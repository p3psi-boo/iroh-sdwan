use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use ipnet::IpNet;
use iroh::endpoint::transports::{FourTuple, PathSelection, PathSelectionContext, PathSelector};

use crate::config::IpFamilyPreference;

/// Keep a proven relay path selected long enough for a new direct mapping to
/// demonstrate stability instead of immediately flapping back to it.
pub const RELAY_HOLD_DOWN: Duration = Duration::from_secs(10);
/// Prefer the configured address family when its RTT is close to the other
/// family. Both paths remain open in the iroh QUIC connection; the selector
/// activates only one of them.
const PREFERRED_FAMILY_MIN_RTT_TOLERANCE: Duration = Duration::from_millis(2);
const DIRECT_SWITCH_MIN_RTT_GAIN: Duration = Duration::from_millis(1);
const MATERIAL_LOSS_DIFFERENCE_PPM: u64 = 10_000;
/// A relay is a fallback for a healthy direct path, but it must be allowed to
/// take over before QUIC declares a badly degraded direct path dead. Requiring
/// both a sizeable absolute and relative RTT gain avoids switching merely due
/// to normal Internet jitter.
const RELAY_FAILOVER_MIN_RTT_GAIN: Duration = Duration::from_millis(50);

#[derive(Debug, Default)]
pub struct WanPathSelector {
    // Key the hold by the actual selected network path. DERP is represented by
    // FourTuple::Custom and therefore has no EndpointId in the tuple; using the
    // complete tuple makes hold-down work for native relay and custom relay
    // transports alike.
    relay_hold_until: Mutex<HashMap<FourTuple, Instant>>,
    forbidden_prefixes: Arc<Vec<IpNet>>,
    prefer: IpFamilyPreference,
}

impl WanPathSelector {
    pub fn new(forbidden_prefixes: Vec<IpNet>, prefer: IpFamilyPreference) -> Self {
        Self {
            relay_hold_until: Mutex::default(),
            forbidden_prefixes: Arc::new(forbidden_prefixes),
            prefer,
        }
    }

    fn path_allowed(&self, path: &FourTuple) -> bool {
        match path {
            FourTuple::Ip { remote, local } => !self.forbidden_prefixes.iter().any(|prefix| {
                prefix.contains(&remote.ip())
                    || local.is_some_and(|address| prefix.contains(&address))
            }),
            FourTuple::Relay { .. } | FourTuple::Custom { .. } => true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportKind {
    Direct,
    Relay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpFamily {
    V4,
    V6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectQuality {
    family: IpFamily,
    rtt: Duration,
    loss_ppm: Option<u64>,
    black_holes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PathQuality {
    rtt: Duration,
    loss_ppm: Option<u64>,
    black_holes: u64,
}

impl DirectQuality {
    fn path(self) -> PathQuality {
        PathQuality {
            rtt: self.rtt,
            loss_ppm: self.loss_ppm,
            black_holes: self.black_holes,
        }
    }
}

fn direct_family(path: &FourTuple) -> Option<IpFamily> {
    match path {
        FourTuple::Ip { remote, .. } if remote.is_ipv6() => Some(IpFamily::V6),
        FourTuple::Ip { .. } => Some(IpFamily::V4),
        FourTuple::Relay { .. } | FourTuple::Custom { .. } => None,
    }
}

fn loss_ppm(sent: u64, lost: u64) -> Option<u64> {
    // lost_packets is part of the transmitted packet population, not an
    // additional population. Dividing by sent + lost systematically hid loss.
    (sent >= 32).then(|| lost.saturating_mul(1_000_000) / sent.max(lost).max(1))
}

fn materially_lower_loss(candidate: DirectQuality, current: DirectQuality) -> Option<bool> {
    let (Some(candidate_loss), Some(current_loss)) = (candidate.loss_ppm, current.loss_ppm) else {
        return None;
    };
    let difference = candidate_loss.abs_diff(current_loss);
    (difference >= MATERIAL_LOSS_DIFFERENCE_PPM).then_some(candidate_loss < current_loss)
}

fn family_is_preferred(family: IpFamily, preference: IpFamilyPreference) -> bool {
    matches!(
        (family, preference),
        (IpFamily::V4, IpFamilyPreference::Ipv4) | (IpFamily::V6, IpFamilyPreference::Ipv6)
    )
}

fn preferred_is_competitive(preferred: DirectQuality, other: DirectQuality) -> bool {
    let tolerance = PREFERRED_FAMILY_MIN_RTT_TOLERANCE.max(other.rtt / 4);
    preferred.rtt <= other.rtt.saturating_add(tolerance)
}

/// Order usable direct paths by health, observed loss and RTT. The configured
/// family is the tie-breaker only while it remains within the other family's
/// quality envelope.
fn better_direct(
    candidate: DirectQuality,
    current: DirectQuality,
    preference: IpFamilyPreference,
) -> bool {
    if candidate.black_holes != current.black_holes {
        return candidate.black_holes < current.black_holes;
    }
    if let Some(candidate_is_better) = materially_lower_loss(candidate, current) {
        return candidate_is_better;
    }
    if candidate.family == current.family {
        return candidate.rtt < current.rtt;
    }
    if family_is_preferred(candidate.family, preference) {
        preferred_is_competitive(candidate, current)
    } else {
        !preferred_is_competitive(current, candidate)
    }
}

fn should_switch_direct(
    candidate: DirectQuality,
    current: DirectQuality,
    preference: IpFamilyPreference,
) -> bool {
    if !better_direct(candidate, current, preference) {
        return false;
    }
    if candidate.family != current.family
        || candidate.black_holes < current.black_holes
        || materially_lower_loss(candidate, current) == Some(true)
    {
        return true;
    }
    let minimum_gain = DIRECT_SWITCH_MIN_RTT_GAIN.max(current.rtt / 10);
    candidate.rtt.saturating_add(minimum_gain) < current.rtt
}

fn better_path(candidate: PathQuality, current: PathQuality) -> bool {
    if candidate.black_holes != current.black_holes {
        return candidate.black_holes < current.black_holes;
    }
    match (candidate.loss_ppm, current.loss_ppm) {
        (Some(candidate), Some(current))
            if candidate.abs_diff(current) >= MATERIAL_LOSS_DIFFERENCE_PPM =>
        {
            candidate < current
        }
        _ => candidate.rtt < current.rtt,
    }
}

fn relay_materially_better(relay: PathQuality, direct: PathQuality) -> bool {
    if relay.black_holes < direct.black_holes {
        return true;
    }
    if let (Some(relay_loss), Some(direct_loss)) = (relay.loss_ppm, direct.loss_ppm)
        && direct_loss.saturating_sub(relay_loss) >= MATERIAL_LOSS_DIFFERENCE_PPM
    {
        return true;
    }
    let minimum_gain = RELAY_FAILOVER_MIN_RTT_GAIN.max(direct.rtt / 3);
    relay.rtt.saturating_add(minimum_gain) < direct.rtt
}

fn transport_kind(path: &FourTuple) -> TransportKind {
    match path {
        FourTuple::Ip { .. } => TransportKind::Direct,
        FourTuple::Relay { .. } | FourTuple::Custom { .. } => TransportKind::Relay,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Choice {
    Keep,
    Direct,
    Relay,
}

impl PathSelector for WanPathSelector {
    fn select(&self, ctx: &PathSelectionContext<'_>) -> PathSelection {
        let current = ctx.current();
        let mut direct = None;
        let mut current_direct = None;
        let mut relay = None;
        let mut current_relay = None;
        let mut current_available = false;

        for candidate in ctx.paths() {
            let Some(stats) = candidate.stats() else {
                continue;
            };
            let path = candidate.network_path();
            if !self.path_allowed(path) {
                continue;
            }
            if current == Some(path) {
                current_available = true;
            }
            match transport_kind(path) {
                TransportKind::Direct => {
                    let quality = DirectQuality {
                        family: direct_family(path).expect("direct path has an IP family"),
                        rtt: stats.rtt,
                        loss_ppm: loss_ppm(stats.udp_tx.datagrams, stats.lost_packets),
                        black_holes: stats.black_holes_detected,
                    };
                    if current == Some(path) {
                        current_direct = Some(quality);
                    }
                    if direct
                        .as_ref()
                        .is_none_or(|(_, best): &(_, DirectQuality)| {
                            better_direct(quality, *best, self.prefer)
                        })
                    {
                        direct = Some((candidate, quality));
                    }
                }
                TransportKind::Relay => {
                    let quality = PathQuality {
                        rtt: stats.rtt,
                        loss_ppm: loss_ppm(stats.udp_tx.datagrams, stats.lost_packets),
                        black_holes: stats.black_holes_detected,
                    };
                    if current == Some(path) {
                        current_relay = Some(quality);
                    }
                    if relay
                        .as_ref()
                        .is_none_or(|(_, best): &(_, PathQuality)| better_path(quality, *best))
                    {
                        relay = Some((candidate, quality));
                    }
                }
            }
        }

        let current_kind = current.map(transport_kind);
        if current_kind == Some(TransportKind::Direct) && current_available {
            let mut selection = PathSelection::none();
            if let (Some(current_quality), Some((candidate, relay_quality))) =
                (current_direct, relay.as_ref())
                && relay_materially_better(*relay_quality, current_quality.path())
            {
                selection.set(candidate);
                let now = Instant::now();
                self.relay_hold_until
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .insert(candidate.network_path().clone(), now + RELAY_HOLD_DOWN);
                return selection;
            }
            if let (Some(current_path), Some(current_quality), Some((candidate, quality))) =
                (current, current_direct, direct.as_ref())
                && candidate.network_path() != current_path
                && should_switch_direct(*quality, current_quality, self.prefer)
            {
                selection.set(candidate);
            }
            return selection;
        }
        let now = Instant::now();
        let mut holds = self
            .relay_hold_until
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        holds.retain(|_, until| *until > now);
        let hold_active = current
            .filter(|path| transport_kind(path) == TransportKind::Relay)
            .and_then(|path| holds.get(path))
            .is_some_and(|until| *until > now);
        let relay_health_preferred = current_kind == Some(TransportKind::Relay)
            && current_available
            && current_relay
                .zip(direct.as_ref().map(|(_, quality)| quality.path()))
                .is_some_and(|(relay, direct)| relay_materially_better(relay, direct));
        let choice = choose_transport(
            current_kind,
            current_available,
            direct.is_some(),
            relay.is_some(),
            hold_active || relay_health_preferred,
        );

        if choice == Choice::Relay
            && current_kind != Some(TransportKind::Relay)
            && let Some((candidate, _)) = relay.as_ref()
        {
            holds.insert(candidate.network_path().clone(), now + RELAY_HOLD_DOWN);
        } else if choice == Choice::Direct
            && let Some(path) = current
        {
            holds.remove(path);
        }
        drop(holds);

        let mut selection = PathSelection::none();
        match choice {
            Choice::Keep => {}
            Choice::Direct => {
                if let Some((candidate, _)) = direct {
                    selection.set(&candidate);
                }
            }
            Choice::Relay => {
                if let Some((candidate, _)) = relay {
                    selection.set(&candidate);
                }
            }
        }
        selection
    }
}

fn choose_transport(
    current: Option<TransportKind>,
    current_available: bool,
    direct_available: bool,
    relay_available: bool,
    relay_hold_active: bool,
) -> Choice {
    match current {
        Some(TransportKind::Direct) if current_available => Choice::Keep,
        Some(TransportKind::Relay) if current_available && relay_hold_active => Choice::Keep,
        Some(TransportKind::Relay) if direct_available => Choice::Direct,
        _ if direct_available => Choice::Direct,
        Some(TransportKind::Relay) if current_available => Choice::Keep,
        _ if relay_available => Choice::Relay,
        _ => Choice::Keep,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;

    #[test]
    fn direct_is_primary_until_it_disappears() {
        assert_eq!(
            choose_transport(Some(TransportKind::Direct), true, true, true, false),
            Choice::Keep
        );
        assert_eq!(
            choose_transport(Some(TransportKind::Direct), false, false, true, false),
            Choice::Relay
        );
    }

    #[test]
    fn relay_hold_prevents_immediate_direct_flapping() {
        assert_eq!(
            choose_transport(Some(TransportKind::Relay), true, true, true, true),
            Choice::Keep
        );
        assert_eq!(
            choose_transport(Some(TransportKind::Relay), true, true, true, false),
            Choice::Direct
        );
    }

    fn quality(family: IpFamily, rtt_ms: u64, loss_ppm: Option<u64>) -> DirectQuality {
        DirectQuality {
            family,
            rtt: Duration::from_millis(rtt_ms),
            loss_ppm,
            black_holes: 0,
        }
    }

    #[test]
    fn ipv6_wins_when_dual_stack_quality_is_close() {
        let ipv4 = quality(IpFamily::V4, 10, Some(0));
        let ipv6 = quality(IpFamily::V6, 12, Some(0));
        assert!(better_direct(ipv6, ipv4, IpFamilyPreference::Ipv6));
        assert!(!better_direct(ipv4, ipv6, IpFamilyPreference::Ipv6));
        assert!(should_switch_direct(ipv6, ipv4, IpFamilyPreference::Ipv6));
    }

    #[test]
    fn ipv4_can_be_configured_as_the_preferred_family() {
        let ipv4 = quality(IpFamily::V4, 12, Some(0));
        let ipv6 = quality(IpFamily::V6, 10, Some(0));
        assert!(better_direct(ipv4, ipv6, IpFamilyPreference::Ipv4));
        assert!(!better_direct(ipv6, ipv4, IpFamilyPreference::Ipv4));
    }

    #[test]
    fn ipv4_wins_when_ipv6_is_materially_worse() {
        let ipv4 = quality(IpFamily::V4, 10, Some(0));
        let ipv6 = quality(IpFamily::V6, 20, Some(0));
        assert!(better_direct(ipv4, ipv6, IpFamilyPreference::Ipv6));
        assert!(!better_direct(ipv6, ipv4, IpFamilyPreference::Ipv6));
    }

    #[test]
    fn lower_loss_overrides_address_family_preference() {
        let ipv4 = quality(IpFamily::V4, 12, Some(0));
        let ipv6 = quality(IpFamily::V6, 10, Some(25_000));
        assert!(better_direct(ipv4, ipv6, IpFamilyPreference::Ipv6));
    }

    #[test]
    fn loss_uses_transmitted_packets_as_denominator() {
        assert_eq!(loss_ppm(100, 5), Some(50_000));
        assert_eq!(loss_ppm(31, 5), None);
    }

    #[test]
    fn materially_better_relay_can_replace_degraded_direct() {
        let relay = PathQuality {
            rtt: Duration::from_millis(40),
            loss_ppm: Some(0),
            black_holes: 0,
        };
        let high_loss_direct = PathQuality {
            rtt: Duration::from_millis(20),
            loss_ppm: Some(30_000),
            black_holes: 0,
        };
        let high_latency_direct = PathQuality {
            rtt: Duration::from_millis(300),
            loss_ppm: Some(0),
            black_holes: 0,
        };
        assert!(relay_materially_better(relay, high_loss_direct));
        assert!(relay_materially_better(relay, high_latency_direct));
    }

    #[test]
    fn healthy_direct_is_not_replaced_by_relay_jitter() {
        let relay = PathQuality {
            rtt: Duration::from_millis(35),
            loss_ppm: Some(0),
            black_holes: 0,
        };
        let direct = PathQuality {
            rtt: Duration::from_millis(20),
            loss_ppm: Some(0),
            black_holes: 0,
        };
        assert!(!relay_materially_better(relay, direct));
    }

    #[test]
    fn same_family_switch_requires_a_meaningful_gain() {
        let current = quality(IpFamily::V6, 10, Some(0));
        assert!(!should_switch_direct(
            quality(IpFamily::V6, 9, Some(0)),
            current,
            IpFamilyPreference::Ipv6
        ));
        assert!(should_switch_direct(
            quality(IpFamily::V6, 7, Some(0)),
            current,
            IpFamilyPreference::Ipv6
        ));
    }

    #[test]
    fn hard_nat_starts_on_relay_then_upgrades_without_replacing_session() {
        // Before coordinated punching there is deliberately no direct path.
        assert_eq!(
            choose_transport(None, false, false, true, false),
            Choice::Relay
        );
        // A CGNAT/hairpin candidate is kept in probation during hold-down.
        assert_eq!(
            choose_transport(Some(TransportKind::Relay), true, true, true, true),
            Choice::Keep
        );
        // Once proven, the same connection selects it.
        assert_eq!(
            choose_transport(Some(TransportKind::Relay), true, true, true, false),
            Choice::Direct
        );
    }

    #[test]
    fn double_nat_and_network_change_fall_back_then_recover() {
        assert_eq!(
            choose_transport(Some(TransportKind::Direct), false, false, true, false),
            Choice::Relay
        );
        assert_eq!(
            choose_transport(Some(TransportKind::Relay), true, false, true, false),
            Choice::Keep
        );
        assert_eq!(
            choose_transport(Some(TransportKind::Relay), true, true, true, false),
            Choice::Direct
        );
    }

    #[test]
    fn overlay_addresses_are_never_eligible_as_underlay_paths() {
        let selector = WanPathSelector::new(
            vec!["10.250.12.0/24".parse().unwrap()],
            IpFamilyPreference::Ipv6,
        );
        assert!(!selector.path_allowed(&FourTuple::Ip {
            remote: SocketAddr::from(([10, 250, 12, 2], 10119)),
            local: None,
        }));
        assert!(!selector.path_allowed(&FourTuple::Ip {
            remote: SocketAddr::from(([111, 62, 241, 102], 10119)),
            local: Some(IpAddr::V4(Ipv4Addr::new(10, 250, 12, 1))),
        }));
        assert!(selector.path_allowed(&FourTuple::Ip {
            remote: SocketAddr::from(([111, 62, 241, 102], 10119)),
            local: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
        }));
    }
}

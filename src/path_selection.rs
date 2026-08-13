use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use ipnet::IpNet;
use iroh::{
    EndpointId,
    endpoint::transports::{FourTuple, PathSelection, PathSelectionContext, PathSelector},
};

/// Keep a proven relay path selected long enough for a new direct mapping to
/// demonstrate stability instead of immediately flapping back to it.
pub const RELAY_HOLD_DOWN: Duration = Duration::from_secs(10);

#[derive(Debug, Default)]
pub struct WanPathSelector {
    relay_hold_until: Mutex<HashMap<EndpointId, Instant>>,
    forbidden_prefixes: Arc<Vec<IpNet>>,
}

impl WanPathSelector {
    pub fn new(forbidden_prefixes: Vec<IpNet>) -> Self {
        Self {
            relay_hold_until: Mutex::default(),
            forbidden_prefixes: Arc::new(forbidden_prefixes),
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
        let mut relay = None;
        let mut endpoint_id = None;
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
            if let FourTuple::Relay {
                endpoint_id: remote,
                ..
            } = path
            {
                endpoint_id = Some(*remote);
            }
            let best = match transport_kind(path) {
                TransportKind::Direct => &mut direct,
                TransportKind::Relay => &mut relay,
            };
            if best
                .as_ref()
                .is_none_or(|(_, best_rtt): &(_, Duration)| stats.rtt < *best_rtt)
            {
                *best = Some((candidate, stats.rtt));
            }
        }

        let current_kind = current.map(transport_kind);
        let now = Instant::now();
        let mut holds = self
            .relay_hold_until
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let hold_active = endpoint_id
            .and_then(|id| holds.get(&id))
            .is_some_and(|until| *until > now);
        let choice = choose_transport(
            current_kind,
            current_available,
            direct.is_some(),
            relay.is_some(),
            hold_active,
        );

        if choice == Choice::Relay
            && current_kind == Some(TransportKind::Direct)
            && !current_available
            && let Some(id) = endpoint_id
        {
            holds.insert(id, now + RELAY_HOLD_DOWN);
        } else if choice == Choice::Direct
            && let Some(id) = endpoint_id
        {
            holds.remove(&id);
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
        let selector = WanPathSelector::new(vec!["10.250.12.0/24".parse().unwrap()]);
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

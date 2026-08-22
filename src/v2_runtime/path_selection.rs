//! Underlay path admission and health-based selection for the V2 runtime.

use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use ipnet::IpNet;
use iroh::endpoint::{
    PathId,
    transports::{AddrKind, FourTuple, PathSelection, PathSelectionContext, PathSelector},
};
use rustc_hash::FxHashMap as HashMap;
use tracing::info;

use crate::config::PathMigrationConfig;

/// Iroh's ordinary path policy, with one additional hard gate: neither the
/// local nor remote IP of a direct path may fall inside an operator-excluded
/// prefix. Applying the gate here also covers NAT candidates learned after
/// startup, including addresses of overlay/Yggdrasil interfaces that did not
/// exist when the static peer locator was validated.
#[derive(Debug, Clone)]
pub(super) struct UnderlayPathSelector {
    excluded: Arc<[IpNet]>,
    tuning: PathMigrationConfig,
    health: Arc<Mutex<HashMap<(usize, PathId), UnderlayPathHealth>>>,
}

#[derive(Debug, Clone, Copy)]
struct UnderlayPathHealth {
    last_acked_packets: u64,
    last_ack_at: Instant,
    last_validated_challenges: u64,
    last_recovery_proof_at: Instant,
    last_seen_at: Instant,
    degraded: bool,
    recovered_at: Option<Instant>,
    recovery_start_validated_challenges: u64,
}

#[derive(Debug, Clone, Copy)]
struct UnderlayPathProgress {
    acked_packets: u64,
    validated_challenges: u64,
    pto_count: u32,
}

impl UnderlayPathProgress {
    const fn new(acked_packets: u64, validated_challenges: u64, pto_count: u32) -> Self {
        Self {
            acked_packets,
            validated_challenges,
            pto_count,
        }
    }
}

impl UnderlayPathHealth {
    fn new(now: Instant, acked_packets: u64, validated_challenges: u64) -> Self {
        Self {
            last_acked_packets: acked_packets,
            last_ack_at: now,
            last_validated_challenges: validated_challenges,
            last_recovery_proof_at: now,
            last_seen_at: now,
            degraded: false,
            recovered_at: None,
            recovery_start_validated_challenges: validated_challenges,
        }
    }

    fn observe(
        &mut self,
        now: Instant,
        progress: UnderlayPathProgress,
        rtt: Duration,
        is_current: bool,
        tuning: &PathMigrationConfig,
    ) -> bool {
        let UnderlayPathProgress {
            acked_packets,
            validated_challenges,
            pto_count,
        } = progress;
        self.last_seen_at = now;
        let ack_progress = acked_packets != self.last_acked_packets;
        if ack_progress {
            self.last_acked_packets = acked_packets;
            self.last_ack_at = now;
        }
        // The selector is polled independently from QUIC receive processing, so
        // several successful responses can legitimately land between two
        // observations. Preserve the whole delta instead of collapsing a burst
        // into one proof.
        let challenge_delta = validated_challenges.saturating_sub(self.last_validated_challenges);
        let challenge_progress = challenge_delta != 0;
        let previous_recovery_proof_at = self.last_recovery_proof_at;
        if challenge_progress {
            self.last_validated_challenges = validated_challenges;
            self.last_recovery_proof_at = now;
            // A successful challenge/response is stronger than a PATH_ACK: it
            // proves bidirectional reachability of this exact four-tuple.
            self.last_ack_at = now;
        }

        let silent_for = now.saturating_duration_since(self.last_ack_at);
        // PTO is an early hint, not proof of continued failure. Once authenticated
        // packets resume, a stale counter must not prevent recovery forever.
        let pto_silence = (rtt * 2).clamp(
            Duration::from_millis(tuning.min_pto_silence_ms),
            Duration::from_millis(tuning.min_silence_ms),
        );
        let silence_timeout = if is_current {
            underlay_silence_timeout(rtt, tuning)
        } else {
            // A warm backup carries exact PATH_CHALLENGE probes rather than
            // application ACK volume. Its lease therefore follows the maximum
            // accepted proof gap, bounded by the general silence guardrails.
            // Using the full outer lease here allowed a path that had just
            // failed to win back on stale RTT before probation was armed.
            Duration::from_millis(tuning.recovery_max_response_gap_ms).clamp(
                Duration::from_millis(tuning.min_silence_ms),
                Duration::from_millis(tuning.max_silence_ms),
            )
        };
        let raw_degraded = silent_for >= silence_timeout
            || pto_count >= tuning.pto_threshold && silent_for >= pto_silence;
        if !self.degraded && raw_degraded {
            self.degraded = true;
            self.recovered_at = None;
            self.recovery_start_validated_challenges = validated_challenges;
        } else if self.degraded {
            if challenge_progress
                && (self.recovered_at.is_none()
                    || now.saturating_duration_since(previous_recovery_proof_at)
                        > Duration::from_millis(tuning.recovery_max_response_gap_ms))
            {
                // Begin (or restart) probation at the first response batch in
                // a contiguous run. The counter baseline precedes the entire
                // batch so three responses processed in one selector interval
                // still count as three independent cryptographic proofs.
                self.recovered_at = Some(now);
                self.recovery_start_validated_challenges =
                    validated_challenges.saturating_sub(challenge_delta);
            }
            let probation_complete = self.recovered_at.is_some_and(|recovered_at| {
                now.saturating_duration_since(recovered_at)
                    >= Duration::from_millis(tuning.recovery_probation_ms)
                    && validated_challenges.saturating_sub(self.recovery_start_validated_challenges)
                        >= tuning.recovery_min_responses
                    // Probation is a hold-down after positive proof, not a
                    // demand for continuous traffic on an idle backup. Any
                    // renewed PTO train vetoes failback.
                    && pto_count < tuning.pto_threshold
                    && silent_for <= Duration::from_millis(tuning.max_silence_ms)
            });
            if probation_complete {
                self.degraded = false;
                self.recovered_at = None;
                // Start the normal RTT-derived health lease at the end of the
                // hold-down. Otherwise the ACK silence accumulated *during*
                // probation would make the path fail again on the very next
                // selector poll, before failback can put traffic on it.
                self.last_ack_at = now;
            } else if now.saturating_duration_since(self.last_recovery_proof_at)
                > Duration::from_millis(tuning.recovery_max_response_gap_ms) * 4
            {
                // A lone delayed packet is not a recovery signal. Forget it so a
                // later real recovery must prove a fresh run of progress.
                self.recovered_at = None;
                self.recovery_start_validated_challenges = validated_challenges;
            }
        }
        self.degraded
    }
}

fn underlay_silence_timeout(rtt: Duration, tuning: &PathMigrationConfig) -> Duration {
    (rtt * 4).clamp(
        Duration::from_millis(tuning.min_silence_ms),
        Duration::from_millis(tuning.max_silence_ms),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum UnderlayTransportTier {
    Primary,
    Backup,
}

impl UnderlayPathSelector {
    pub(super) fn new(excluded: Vec<IpNet>, tuning: PathMigrationConfig) -> Self {
        Self {
            excluded: excluded.into(),
            tuning,
            health: Arc::new(Mutex::new(HashMap::default())),
        }
    }

    fn allows(&self, path: &FourTuple) -> bool {
        let FourTuple::Ip { remote, local } = path else {
            return true;
        };
        self.allows_ip(remote.ip()) && local.is_none_or(|address| self.allows_ip(address))
    }

    fn allows_ip(&self, address: IpAddr) -> bool {
        self.excluded
            .iter()
            .all(|prefix| !prefix.contains(&address))
    }

    fn sort_key(
        path: &FourTuple,
        rtt: Duration,
        degraded: bool,
    ) -> (bool, UnderlayTransportTier, i128) {
        let (tier, rtt_nanos) = match path.addr_kind() {
            AddrKind::Relay => (UnderlayTransportTier::Backup, rtt.as_nanos() as i128),
            _ => (UnderlayTransportTier::Primary, rtt.as_nanos() as i128),
        };
        (degraded, tier, rtt_nanos)
    }
}

impl PathSelector for UnderlayPathSelector {
    fn select(&self, context: &PathSelectionContext<'_>) -> PathSelection {
        let current = context.current();
        let mut best = None;
        let mut current_key = None;
        let now = Instant::now();
        let mut health = self
            .health
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        health.retain(|_, observed| {
            now.saturating_duration_since(observed.last_seen_at)
                <= Duration::from_secs(self.tuning.health_ttl_secs)
        });
        for candidate in context.paths() {
            let path = candidate.network_path();
            if !self.allows(path) {
                continue;
            }
            let Some(stats) = candidate.stats() else {
                continue;
            };
            let is_current = Some(path) == current;
            let degraded = candidate.health_key().map_or(
                stats.pto_count >= self.tuning.pto_threshold,
                |health_key| {
                    let observed = health.entry(health_key).or_insert_with(|| {
                        UnderlayPathHealth::new(
                            now,
                            stats.acked_packets,
                            stats.validated_challenges,
                        )
                    });
                    let was_degraded = observed.degraded;
                    let previous_recovery = observed.recovered_at;
                    let degraded = observed.observe(
                        now,
                        UnderlayPathProgress::new(
                            stats.acked_packets,
                            stats.validated_challenges,
                            stats.pto_count,
                        ),
                        stats.rtt,
                        is_current,
                        &self.tuning,
                    );
                    if degraded != was_degraded {
                        info!(
                            %path,
                            acked_packets = stats.acked_packets,
                            authenticated_rx_packets = stats.authenticated_rx_packets,
                            validated_challenges = stats.validated_challenges,
                            pto_count = stats.pto_count,
                            rtt = ?stats.rtt,
                            degraded,
                            "underlay path health changed"
                        );
                    } else if previous_recovery.is_none() && observed.recovered_at.is_some() {
                        info!(
                            %path,
                            acked_packets = stats.acked_packets,
                            authenticated_rx_packets = stats.authenticated_rx_packets,
                            validated_challenges = stats.validated_challenges,
                            rtt = ?stats.rtt,
                            "underlay path recovery probation started"
                        );
                    }
                    degraded
                },
            );
            let key = Self::sort_key(path, stats.rtt, degraded);
            if Some(path) == current && current_key.is_none_or(|existing| key < existing) {
                current_key = Some(key);
            }
            if best.as_ref().is_none_or(|(_, best_key)| key < *best_key) {
                best = Some((candidate, key));
            }
        }

        let mut selection = PathSelection::none();
        let Some((best_candidate, (best_degraded, best_tier, best_rtt))) = best else {
            return selection;
        };
        let Some((current_degraded, current_tier, current_rtt)) = current_key else {
            info!(
                selected = %best_candidate.network_path(),
                degraded = best_degraded,
                rtt_nanos = best_rtt,
                "selected initial underlay path"
            );
            selection.set(&best_candidate);
            return selection;
        };
        if !best_degraded
            && (current_degraded
                || best_tier != current_tier
                || best_rtt
                    + Duration::from_millis(self.tuning.rtt_switch_margin_ms).as_nanos() as i128
                    <= current_rtt)
        {
            if let Some(previous) = current {
                info!(
                    %previous,
                    selected = %best_candidate.network_path(),
                    previous_degraded = current_degraded,
                    selected_degraded = best_degraded,
                    previous_rtt_nanos = current_rtt,
                    selected_rtt_nanos = best_rtt,
                    "switched selected underlay path"
                );
            }
            selection.set(&best_candidate);
        }
        selection
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn excluded_underlay_gate_covers_both_ends_of_discovered_ip_paths() {
        use iroh::endpoint::{LocalTransportAddr, transports::Addr};

        let selector = UnderlayPathSelector::new(
            vec!["200::/7".parse().unwrap(), "21.0.0.0/8".parse().unwrap()],
            PathMigrationConfig::default(),
        );
        let carrier = FourTuple::new(
            Addr::Ip("[2400:dd01::1]:4000".parse().unwrap()),
            LocalTransportAddr::Ip(Some("2409:8a00::1".parse().unwrap())),
        );
        let forbidden_remote = FourTuple::new(
            Addr::Ip("21.42.0.7:4000".parse().unwrap()),
            LocalTransportAddr::Ip(Some("2409:8a00::1".parse().unwrap())),
        );
        let forbidden_local = FourTuple::new(
            Addr::Ip("[2400:dd01::1]:4000".parse().unwrap()),
            LocalTransportAddr::Ip(Some("200:18cc::1".parse().unwrap())),
        );
        assert!(selector.allows(&carrier));
        assert!(!selector.allows(&forbidden_remote));
        assert!(!selector.allows(&forbidden_local));
    }

    #[test]
    fn underlay_health_detects_ack_silence_not_send_activity() {
        let started = Instant::now();
        let mut health = UnderlayPathHealth::new(started, 7, 0);
        let rtt = Duration::from_millis(20);
        let tuning = PathMigrationConfig::default();

        assert!(!health.observe(
            started + Duration::from_millis(900),
            UnderlayPathProgress::new(7, 0, 0),
            rtt,
            true,
            &tuning
        ));
        assert!(health.observe(
            started + Duration::from_secs(1),
            UnderlayPathProgress::new(7, 0, 0),
            rtt,
            true,
            &tuning
        ));
        assert!(health.degraded);
    }

    #[test]
    fn warm_backup_arms_probation_after_recovery_proof_gap() {
        let started = Instant::now();
        let mut health = UnderlayPathHealth::new(started, 7, 1);
        let tuning = PathMigrationConfig::default();
        let deadline = Duration::from_millis(tuning.recovery_max_response_gap_ms);

        assert!(!health.observe(
            started + deadline - Duration::from_millis(1),
            UnderlayPathProgress::new(7, 1, 0),
            Duration::from_millis(20),
            false,
            &tuning,
        ));
        assert!(health.observe(
            started + deadline,
            UnderlayPathProgress::new(7, 1, 0),
            Duration::from_millis(20),
            false,
            &tuning,
        ));
    }

    #[test]
    fn underlay_health_requires_continuous_recovery_probation() {
        let started = Instant::now();
        let mut health = UnderlayPathHealth::new(started, 7, 0);
        let rtt = Duration::from_millis(20);
        let tuning = PathMigrationConfig::default();
        assert!(health.observe(
            started + Duration::from_secs(1),
            UnderlayPathProgress::new(7, 0, 0),
            rtt,
            true,
            &tuning
        ));

        // A successful on-path challenge starts probation but does not immediately
        // fail back onto a path that may only have recovered for one probe.
        assert!(health.observe(
            started + Duration::from_millis(1100),
            UnderlayPathProgress::new(8, 1, 0),
            rtt,
            true,
            &tuning
        ));
        assert!(health.observe(
            started + Duration::from_millis(1600),
            UnderlayPathProgress::new(9, 1, 0),
            rtt,
            true,
            &tuning
        ));
        assert!(health.observe(
            started + Duration::from_millis(2100),
            UnderlayPathProgress::new(10, 2, 0),
            rtt,
            true,
            &tuning
        ));
        assert!(health.observe(
            started + Duration::from_millis(2600),
            UnderlayPathProgress::new(11, 2, 0),
            rtt,
            true,
            &tuning
        ));
        assert!(!health.observe(
            started + Duration::from_millis(3100),
            UnderlayPathProgress::new(12, 3, 0),
            rtt,
            true,
            &tuning
        ));
        assert!(!health.degraded);
    }

    #[test]
    fn underlay_health_preserves_batched_response_proofs_during_probation() {
        let started = Instant::now();
        let mut health = UnderlayPathHealth::new(started, 7, 0);
        let rtt = Duration::from_millis(20);
        let tuning = PathMigrationConfig::default();
        assert!(health.observe(
            started + Duration::from_secs(1),
            UnderlayPathProgress::new(7, 0, 0),
            rtt,
            true,
            &tuning
        ));

        // QUIC can process multiple NAT/PATH_RESPONSE frames between two
        // selector polls. They remain independent proofs and start the
        // anti-flap hold-down as one observed batch.
        assert!(health.observe(
            started + Duration::from_millis(1100),
            UnderlayPathProgress::new(7, 3, 0),
            rtt,
            true,
            &tuning
        ));
        assert!(health.observe(
            started + Duration::from_millis(2100),
            UnderlayPathProgress::new(7, 3, 0),
            rtt,
            true,
            &tuning
        ));
        assert!(!health.observe(
            started + Duration::from_millis(3100),
            UnderlayPathProgress::new(7, 3, 0),
            rtt,
            true,
            &tuning
        ));
    }

    #[test]
    fn underlay_health_uses_pto_before_silence_deadline() {
        let started = Instant::now();
        let mut health = UnderlayPathHealth::new(started, 7, 0);
        let tuning = PathMigrationConfig::default();
        assert!(!health.observe(
            started + Duration::from_millis(100),
            UnderlayPathProgress::new(7, 0, tuning.pto_threshold),
            Duration::from_millis(20),
            true,
            &tuning,
        ));
        assert!(health.observe(
            started + Duration::from_millis(tuning.min_pto_silence_ms),
            UnderlayPathProgress::new(7, 0, tuning.pto_threshold),
            Duration::from_millis(20),
            true,
            &tuning,
        ));
    }

    #[test]
    fn underlay_silence_deadline_scales_with_rtt_and_is_bounded() {
        let tuning = PathMigrationConfig::default();
        assert_eq!(
            underlay_silence_timeout(Duration::from_millis(5), &tuning),
            Duration::from_secs(1)
        );
        assert_eq!(
            underlay_silence_timeout(Duration::from_millis(400), &tuning),
            Duration::from_millis(1600)
        );
        assert_eq!(
            underlay_silence_timeout(Duration::from_secs(2), &tuning),
            Duration::from_secs(5)
        );
    }
}

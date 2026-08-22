//! Context bucketing of telemetry into a small discrete key.

use ironet_policy_abi::{PathReliabilityV1, PolicyInputV1, PolicyTelemetryV1};
use serde::{Deserialize, Serialize};

use crate::ContextSchemaSpecV1;

/// Discrete context the bandit keeps separate posteriors for. Field order is
/// the sort order used when exporting memory; serde shape is byte-compatible
/// with the host's legacy `ContextKeyV2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ContextKeyV1 {
    pub rtt_class: u8,
    pub rate_class: u8,
    pub loss_class: u8,
    pub reliable: bool,
    /// True only for a genuinely host-local path below 2 ms. The ordinary
    /// `rtt_class == 0` bucket spans up to 10 ms and is too broad for the
    /// low-RTT cwnd-floor preset. The 2 ms bound includes the userspace
    /// QUIC/TUN scheduling floor measured by the netns harness.
    #[serde(default)]
    pub host_rtt: bool,
}

impl ContextKeyV1 {
    /// Classify one input with the spec's thresholds.
    pub fn classify_input(input: &PolicyInputV1, schema: &ContextSchemaSpecV1) -> Self {
        Self::classify(&input.telemetry, input.reliability, schema)
    }

    /// Classify telemetry. Durations are integer microseconds, which is
    /// exactly what the host's microsecond-resolution telemetry carries, so
    /// this reproduces the legacy `Duration`-based classification bit for
    /// bit: `min_rtt.as_millis()` is `min_rtt_micros / 1000`, and
    /// `queue_delay > max(5 ms, min_rtt / 2)` is
    /// `queue_delay_micros > max(5000, min_rtt_micros / 2)` for whole
    /// microseconds.
    pub fn classify(
        t: &PolicyTelemetryV1,
        reliability: PathReliabilityV1,
        schema: &ContextSchemaSpecV1,
    ) -> Self {
        let rtt_millis = u128::from(t.path_min_rtt_micros / 1_000);
        let rtt_class = bucket(rtt_millis, &schema.rtt_millis);
        let rate = t
            .local_tx_wire_rate_bytes_per_second
            .max(t.local_tx_controller_bw_bytes_per_second)
            .saturating_mul(8);
        let rate_class = bucket(u128::from(rate / 1_000_000), &schema.rate_mbps);
        let queue_budget_micros = 5_000_u64.max(t.path_min_rtt_micros / 2);
        let queue_inflated = t.path_queue_delay_micros > queue_budget_micros
            || t.local_tx_controller_guard_transitions_delta > 0;
        let raw_loss_class = bucket(u128::from(t.local_tx_loss_ppm), &schema.loss_ppm);
        let loss_class = if queue_inflated && raw_loss_class != 0 {
            3
        } else if t.local_tx_burst_loss_cells >= 2 || t.remote_expired_stripes_delta > 0 {
            2
        } else {
            raw_loss_class
                .max(u8::from(t.remote_residual_loss_ppm > 0))
                .min(3)
        };
        Self {
            rtt_class,
            rate_class,
            loss_class,
            reliable: reliability == PathReliabilityV1::ReliableRelay,
            host_rtt: t.path_min_rtt_micros < 2_000,
        }
    }

    /// Key used for the spec's `priors` map, e.g. `r2-b1-l2-datagram` or
    /// `r0-b3-l0-datagram-host`.
    pub fn policy_key(self) -> String {
        let base = format!(
            "r{}-b{}-l{}-{}",
            self.rtt_class,
            self.rate_class,
            self.loss_class,
            if self.reliable {
                "reliable"
            } else {
                "datagram"
            }
        );
        if self.host_rtt {
            format!("{base}-host")
        } else {
            base
        }
    }
}

fn bucket(value: u128, thresholds: &[u32]) -> u8 {
    thresholds
        .iter()
        .position(|threshold| value < u128::from(*threshold))
        .unwrap_or(thresholds.len())
        .min(usize::from(u8::MAX)) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    fn telemetry() -> PolicyTelemetryV1 {
        PolicyTelemetryV1 {
            path_rtt_micros: 42_000,
            path_min_rtt_micros: 40_000,
            path_queue_delay_micros: 2_000,
            local_tx_wire_rate_bytes_per_second: 10_000_000,
            local_tx_controller_bw_bytes_per_second: 10_500_000,
            local_tx_loss_ppm: 18_000,
            local_tx_burst_loss_cells: 1,
            remote_residual_loss_ppm: 1_500,
            ..PolicyTelemetryV1::default()
        }
    }

    #[test]
    fn classifies_like_the_legacy_learner() {
        let schema = ContextSchemaSpecV1::builtin();
        let key = ContextKeyV1::classify(&telemetry(), PathReliabilityV1::Datagram, &schema);
        assert_eq!(
            key,
            ContextKeyV1 {
                rtt_class: 2,
                rate_class: 1,
                loss_class: 2,
                reliable: false,
                host_rtt: false,
            }
        );
        assert_eq!(key.policy_key(), "r2-b1-l2-datagram");
    }

    #[test]
    fn context_separates_asymmetric_rate_loss_and_rtt_classes() {
        let schema = ContextSchemaSpecV1::builtin();
        let mut t = telemetry();
        t.path_min_rtt_micros = 150_000;
        t.local_tx_wire_rate_bytes_per_second = 80_000_000;
        t.local_tx_burst_loss_cells = 3;
        let key = ContextKeyV1::classify(&t, PathReliabilityV1::Datagram, &schema);
        assert_eq!(key.rtt_class, 3);
        assert_eq!(key.rate_class, 3);
        assert_eq!(key.loss_class, 2);
    }

    #[test]
    fn host_rtt_requires_sub_two_millisecond_path() {
        let schema = ContextSchemaSpecV1::builtin();
        let mut t = telemetry();
        t.path_min_rtt_micros = 4_000;
        let key = ContextKeyV1::classify(&t, PathReliabilityV1::Datagram, &schema);
        assert_eq!(key.rtt_class, 0);
        assert!(!key.host_rtt);
        t.path_min_rtt_micros = 800;
        assert!(ContextKeyV1::classify(&t, PathReliabilityV1::Datagram, &schema).host_rtt);
        t.path_min_rtt_micros = 1_500;
        let key = ContextKeyV1::classify(&t, PathReliabilityV1::Datagram, &schema);
        assert!(key.host_rtt);
        assert_eq!(key.policy_key(), "r0-b1-l2-datagram-host");
    }

    #[test]
    fn queue_inflation_and_reliability_shape_the_key() {
        let schema = ContextSchemaSpecV1::builtin();
        let mut t = telemetry();
        t.path_queue_delay_micros = 20_001;
        let key = ContextKeyV1::classify(&t, PathReliabilityV1::ReliableRelay, &schema);
        assert_eq!(key.loss_class, 3);
        assert!(key.reliable);
        assert_eq!(key.policy_key(), "r2-b1-l3-reliable");
        t.path_queue_delay_micros = 20_000;
        t.local_tx_burst_loss_cells = 0;
        let key = ContextKeyV1::classify(&t, PathReliabilityV1::Datagram, &schema);
        assert_eq!(key.loss_class, 2);
    }
}

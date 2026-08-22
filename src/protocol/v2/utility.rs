use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use super::tuning::{PathTelemetryV2, TuneDecisionV2};

const GOODPUT_NORMALIZER_BYTES_PER_SECOND: f64 = 1_000_000.0 / 8.0;
const MINIMUM_QUEUE_DELAY_BUDGET_MICROS: f64 = 5_000.0;
const LATENCY_SOJOURN_NORMALIZER_MICROS: f64 = 20_000.0;
const MEMORY_NORMALIZER_BYTES: f64 = 32.0 * 1024.0 * 1024.0;
const GOODPUT_WINDOW: usize = 8;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Objective {
    #[default]
    Balanced,
    Throughput,
    Latency,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UtilityWeights {
    pub throughput: f64,
    pub queue_delay: f64,
    pub latency_sojourn: f64,
    pub residual_loss: f64,
    pub jitter: f64,
    pub cpu: f64,
    pub wire_overhead: f64,
    pub memory: f64,
}

impl Objective {
    pub const fn weights(self) -> UtilityWeights {
        let mut weights = UtilityWeights {
            throughput: 1.0,
            queue_delay: 0.8,
            latency_sojourn: 0.8,
            residual_loss: 1.0,
            jitter: 0.3,
            cpu: 0.3,
            wire_overhead: 0.4,
            memory: 0.1,
        };
        match self {
            Self::Balanced => {}
            Self::Throughput => {
                weights.throughput = 1.5;
                weights.queue_delay = 0.4;
                weights.latency_sojourn = 0.2;
            }
            Self::Latency => {
                weights.throughput = 0.6;
                weights.queue_delay = 1.5;
                weights.latency_sojourn = 1.5;
            }
        }
        weights
    }
}

/// Per-interval application wire ledger used by the utility estimator. The
/// fields deliberately exclude QUIC packet protection and ACK overhead: the
/// application learner can change only these V2 costs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WireCostV2 {
    pub payload_bytes: u64,
    pub parity_bytes: u64,
    pub repair_bytes: u64,
    pub cover_bytes: u64,
    pub cell_envelope_bytes: u64,
}

impl WireCostV2 {
    fn overhead_ratio(self) -> f64 {
        if self.payload_bytes == 0 {
            return 0.0;
        }
        self.parity_bytes
            .saturating_add(self.repair_bytes)
            .saturating_add(self.cover_bytes)
            .saturating_add(self.cell_envelope_bytes) as f64
            / self.payload_bytes as f64
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct UtilitySample {
    pub total: f64,
    /// Weighted signed terms in formula order: throughput, queue delay,
    /// latency sojourn, residual loss, jitter, CPU, wire cost and memory.
    pub components: [f64; 8],
    pub goodput_bytes_per_second: u64,
}

#[derive(Debug, Clone)]
pub struct UtilityEstimator {
    window: VecDeque<u64>,
    weights: UtilityWeights,
}

impl UtilityEstimator {
    pub fn new(objective: Objective) -> Self {
        Self::with_weights(objective.weights())
    }

    pub fn with_weights(weights: UtilityWeights) -> Self {
        Self {
            window: VecDeque::with_capacity(GOODPUT_WINDOW),
            weights,
        }
    }

    pub fn set_weights(&mut self, weights: UtilityWeights) {
        self.weights = weights;
    }

    pub fn observe(
        &mut self,
        telemetry: &PathTelemetryV2,
        decision: &TuneDecisionV2,
        wire: &WireCostV2,
    ) -> UtilitySample {
        let goodput = telemetry.receiver_goodput_bytes_per_second;
        if self.window.len() == GOODPUT_WINDOW {
            self.window.pop_front();
        }
        self.window.push_back(goodput);

        let queue_budget_micros = MINIMUM_QUEUE_DELAY_BUDGET_MICROS
            .max(telemetry.min_rtt.as_micros().min(u128::from(u64::MAX)) as f64 * 0.5);
        let queue_delay_micros = telemetry.queue_delay.as_micros().min(u128::from(u64::MAX)) as f64;
        let queue_penalty = (queue_delay_micros / queue_budget_micros - 1.0).max(0.0);
        let latency_penalty = if telemetry.latency_queue_recently_nonempty {
            telemetry.latency_sojourn_p95_micros as f64 / LATENCY_SOJOURN_NORMALIZER_MICROS
        } else {
            0.0
        };
        let memory_bytes = decision
            .send_buffer_bytes
            .saturating_add(decision.receive_buffer_bytes)
            .saturating_add(decision.repair_cache_bytes);

        let components = [
            self.weights.throughput
                * (1.0 + goodput as f64 / GOODPUT_NORMALIZER_BYTES_PER_SECOND).ln(),
            -self.weights.queue_delay * queue_penalty,
            -self.weights.latency_sojourn * latency_penalty,
            -self.weights.residual_loss * f64::from(telemetry.residual_loss_ppm) / 10_000.0,
            -self.weights.jitter * coefficient_of_variation(&self.window),
            -self.weights.cpu * f64::from(telemetry.cpu_utilization_per_mille) / 1_000.0,
            -self.weights.wire_overhead * wire.overhead_ratio(),
            -self.weights.memory * memory_bytes as f64 / MEMORY_NORMALIZER_BYTES,
        ];
        UtilitySample {
            total: components.iter().sum(),
            components,
            goodput_bytes_per_second: goodput,
        }
    }
}

fn coefficient_of_variation(samples: &VecDeque<u64>) -> f64 {
    if samples.len() < 2 {
        return 0.0;
    }
    let mean = samples.iter().map(|value| *value as f64).sum::<f64>() / samples.len() as f64;
    if mean == 0.0 {
        return 0.0;
    }
    let variance = samples
        .iter()
        .map(|value| {
            let delta = *value as f64 - mean;
            delta * delta
        })
        .sum::<f64>()
        / samples.len() as f64;
    variance.sqrt() / mean
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::protocol::v2::tuning::{AutoTuneBoundsV2, AutoTunerV2, PathReliability};

    fn telemetry() -> PathTelemetryV2 {
        PathTelemetryV2 {
            path_epoch: 1,
            reliability: PathReliability::Datagram,
            rtt: Duration::from_millis(20),
            min_rtt: Duration::from_millis(20),
            queue_delay: Duration::ZERO,
            loss_ppm: 0,
            burst_loss_cells: 0,
            reorder_ppm: 0,
            receiver_goodput_bytes_per_second: 10_000_000,
            residual_loss_ppm: 0,
            latency_sojourn_p95_micros: 0,
            latency_sojourn_p50_micros: 0,
            latency_sojourn_p99_micros: 0,
            latency_queue_recently_nonempty: false,
            delivery_rate_bytes_per_second: 10_000_000,
            controller_pacing_rate_bytes_per_second: 0,
            controller_send_quantum_bytes: 0,
            controller_state: 0,
            controller_bw_bytes_per_second: 0,
            controller_inflight_longterm_bytes: 0,
            controller_guard_transitions_delta: 0,
            controller_app_limited: false,
            controller_tunables_generation: 0,
            controller_params_generation: 0,
            controller_clamped_writes: 0,
            receive_rate_bytes_per_second: 10_000_000,
            packets_per_second: 10_000,
            tun_ingress_bytes_per_second: 10_000_000,
            average_record_bytes: 1_200,
            gso_ingress_ratio_ppm: 0,
            packet_train_queue_bytes: 0,
            latency_queue_bytes: 0,
            reassembly_pressure_evictions: 0,
            remote_expired_stripes_delta: 0,
            train_build_bytes_per_second: 0,
            bulk_preemption_delay_average_micros: 0,
            cpu_utilization_per_mille: 0,
            wasted_parity_per_mille: 0,
            fec_recovery_per_mille: 0,
            repair_hit_per_mille: 0,
            repair_completed_requests: 0,
            repair_response_latency: Duration::ZERO,
            real_traffic_bytes_per_second: 10_000_000,
        }
    }

    fn decision(sample: PathTelemetryV2) -> TuneDecisionV2 {
        AutoTunerV2::new(AutoTuneBoundsV2::default(), 1).observe(sample)
    }

    #[test]
    fn penalties_are_monotonic_and_goodput_is_rewarded() {
        let base = telemetry();
        let decision = decision(base);
        let mut estimator = UtilityEstimator::new(Objective::Balanced);
        let baseline = estimator.observe(&base, &decision, &WireCostV2::default());

        let mut worse = base;
        worse.queue_delay = Duration::from_millis(40);
        worse.latency_queue_bytes = 1;
        worse.latency_queue_recently_nonempty = true;
        worse.latency_sojourn_p95_micros = 40_000;
        worse.residual_loss_ppm = 20_000;
        worse.cpu_utilization_per_mille = 800;
        let costly = WireCostV2 {
            payload_bytes: 1_000,
            parity_bytes: 500,
            repair_bytes: 100,
            cover_bytes: 100,
            cell_envelope_bytes: 100,
        };
        let degraded = estimator.observe(&worse, &decision, &costly);
        assert!(degraded.total < baseline.total);
        assert!(degraded.components[1] < baseline.components[1]);
        assert!(degraded.components[2] < baseline.components[2]);
        assert!(degraded.components[3] < baseline.components[3]);
        assert!(degraded.components[5] < baseline.components[5]);
        assert!(degraded.components[6] < baseline.components[6]);

        let mut faster = base;
        faster.receiver_goodput_bytes_per_second *= 2;
        let rewarded = UtilityEstimator::new(Objective::Balanced).observe(
            &faster,
            &decision,
            &WireCostV2::default(),
        );
        assert!(rewarded.components[0] > baseline.components[0]);
    }

    #[test]
    fn latency_sojourn_is_charged_only_when_latency_work_was_recent() {
        let mut sample = telemetry();
        sample.latency_sojourn_p95_micros = 100_000;
        let decision = decision(sample);
        let idle = UtilityEstimator::new(Objective::Latency).observe(
            &sample,
            &decision,
            &WireCostV2::default(),
        );
        sample.latency_queue_recently_nonempty = true;
        let active = UtilityEstimator::new(Objective::Latency).observe(
            &sample,
            &decision,
            &WireCostV2::default(),
        );
        assert_eq!(idle.components[2], 0.0);
        assert!(active.components[2] < 0.0);
    }

    #[test]
    fn latency_objective_penalizes_queue_more_than_throughput_objective() {
        let mut sample = telemetry();
        sample.queue_delay = Duration::from_millis(30);
        let decision = decision(sample);
        let latency = UtilityEstimator::new(Objective::Latency).observe(
            &sample,
            &decision,
            &WireCostV2::default(),
        );
        let throughput = UtilityEstimator::new(Objective::Throughput).observe(
            &sample,
            &decision,
            &WireCostV2::default(),
        );
        assert!(latency.components[1].abs() > throughput.components[1].abs());
    }

    #[test]
    fn jitter_window_detects_unstable_goodput() {
        let mut estimator = UtilityEstimator::new(Objective::Balanced);
        let mut sample = telemetry();
        let decision = decision(sample);
        for rate in [1_000_000, 10_000_000, 1_000_000, 10_000_000] {
            sample.receiver_goodput_bytes_per_second = rate;
            estimator.observe(&sample, &decision, &WireCostV2::default());
        }
        let result = estimator.observe(&sample, &decision, &WireCostV2::default());
        assert!(result.components[4] < 0.0);
    }

    #[test]
    fn wire_cost_can_outweigh_goodput_gain_and_memory_is_charged() {
        let mut base = telemetry();
        base.receiver_goodput_bytes_per_second = 1_000_000;
        let base_decision = decision(base);
        let baseline = UtilityEstimator::new(Objective::Balanced).observe(
            &base,
            &base_decision,
            &WireCostV2::default(),
        );

        let mut faster = base;
        faster.receiver_goodput_bytes_per_second = 2_000_000;
        let expensive = UtilityEstimator::new(Objective::Balanced).observe(
            &faster,
            &base_decision,
            &WireCostV2 {
                payload_bytes: 1_000,
                parity_bytes: 100_000,
                ..WireCostV2::default()
            },
        );
        assert!(expensive.total < baseline.total);

        let mut larger = base_decision;
        larger.send_buffer_bytes = 32 * 1024 * 1024;
        larger.receive_buffer_bytes = 32 * 1024 * 1024;
        larger.repair_cache_bytes = 32 * 1024 * 1024;
        let memory_heavy = UtilityEstimator::new(Objective::Balanced).observe(
            &base,
            &larger,
            &WireCostV2::default(),
        );
        assert!(memory_heavy.components[7] < baseline.components[7]);
    }
}

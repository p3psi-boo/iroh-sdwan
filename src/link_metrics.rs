use std::time::Duration;

/// Smoothed, directional observation of one active overlay adjacency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkMetrics {
    pub rtt: Duration,
    pub jitter: Duration,
    pub loss_ppm: u32,
}

impl LinkMetrics {
    pub fn startup_latency(self) -> Duration {
        self.rtt.saturating_add(self.jitter)
    }

    /// Convert loss into an ETA term rather than a traffic-class state. The
    /// expected retry factor is p/(1-p), bounded to keep a broken link from
    /// overflowing duration arithmetic.
    pub fn loss_penalty(self) -> Duration {
        let loss = u64::from(self.loss_ppm.min(999_999));
        let retries_ppm = loss.saturating_mul(1_000_000) / (1_000_000 - loss);
        self.rtt
            .mul_f64((retries_ppm.min(10_000_000) as f64) / 1_000_000.0)
    }
}

#[derive(Debug, Clone)]
pub struct LinkEstimator {
    metrics: LinkMetrics,
    last_rtt: Option<Duration>,
    last_lost_packets: u64,
    last_sent_packets: u64,
}

impl Default for LinkEstimator {
    fn default() -> Self {
        Self {
            metrics: LinkMetrics {
                rtt: Duration::from_millis(100),
                jitter: Duration::ZERO,
                loss_ppm: 0,
            },
            last_rtt: None,
            last_lost_packets: 0,
            last_sent_packets: 0,
        }
    }
}

impl LinkEstimator {
    pub fn observe(&mut self, rtt: Duration, lost_packets: u64, sent_packets: u64) -> LinkMetrics {
        if !rtt.is_zero() {
            let jitter_sample = self
                .last_rtt
                .map(|previous| rtt.abs_diff(previous))
                .unwrap_or(Duration::ZERO);
            self.metrics.rtt = duration_ewma(self.metrics.rtt, rtt);
            self.metrics.jitter = duration_ewma(self.metrics.jitter, jitter_sample);
            self.last_rtt = Some(rtt);
        }

        let lost_delta = lost_packets.saturating_sub(self.last_lost_packets);
        let tx_delta = sent_packets.saturating_sub(self.last_sent_packets);
        self.last_lost_packets = lost_packets;
        self.last_sent_packets = sent_packets;
        let sample = lost_delta
            .saturating_mul(1_000_000)
            // QUIC's sent counter already includes packets later declared
            // lost. `max(lost, sent)` also bounds delayed loss reports that
            // arrive in a telemetry interval with few new transmissions.
            .checked_div(lost_delta.max(tx_delta).max(1))
            .unwrap_or(0)
            .min(1_000_000) as u32;
        self.metrics.loss_ppm =
            ((u64::from(self.metrics.loss_ppm) * 7 + u64::from(sample)) / 8) as u32;
        self.metrics
    }

    pub fn snapshot(&self) -> LinkMetrics {
        self.metrics
    }
}

fn duration_ewma(previous: Duration, sample: Duration) -> Duration {
    let micros = previous
        .as_micros()
        .saturating_mul(7)
        .saturating_add(sample.as_micros())
        / 8;
    Duration::from_micros(micros.min(u128::from(u64::MAX)) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimator_smooths_rtt_jitter_and_loss_deltas() {
        let mut estimator = LinkEstimator::default();
        estimator.observe(Duration::from_millis(20), 0, 100);
        let metrics = estimator.observe(Duration::from_millis(28), 10, 190);
        assert!(metrics.rtt > Duration::from_millis(70));
        assert!(metrics.jitter > Duration::ZERO);
        assert!(metrics.loss_ppm > 0);
    }

    #[test]
    fn loss_is_an_eta_penalty_not_a_route_state() {
        let metrics = LinkMetrics {
            rtt: Duration::from_millis(40),
            jitter: Duration::from_millis(2),
            loss_ppm: 100_000,
        };
        assert_eq!(metrics.startup_latency(), Duration::from_millis(42));
        assert!(metrics.loss_penalty() >= Duration::from_millis(4));
    }
}

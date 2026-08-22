use std::time::Duration;

use super::cell::TrafficClass;

#[derive(Debug, Clone, Copy)]
pub struct ClassifierConfig {
    pub promotion_age: Duration,
    pub promotion_window: Duration,
    pub promotion_bytes: u64,
    pub promotion_rate_bytes_per_second: u64,
    pub promotion_queue_bytes: u64,
    pub demotion_idle: Duration,
    pub latency_hold: Duration,
}

impl Default for ClassifierConfig {
    fn default() -> Self {
        Self {
            promotion_age: Duration::from_millis(150),
            promotion_window: Duration::from_millis(250),
            // A shaped 12-Mbit/s path split across eight flows only gives each
            // flow about 187 KiB/s. Requiring a MiB/s made those sustained
            // flows remain in the Latency FIFO forever. Sixteen KiB still
            // protects a short request burst while allowing one ordinary TUN
            // receive batch to prove that a flow is Bulk.
            promotion_bytes: 16 * 1024,
            promotion_rate_bytes_per_second: 128 * 1024,
            promotion_queue_bytes: 64 * 1024,
            demotion_idle: Duration::from_secs(1),
            latency_hold: Duration::from_millis(500),
        }
    }
}

/// Per-flow hysteretic classifier. Packet size is deliberately not an input:
/// a GSO super-packet cannot promote a new flow to Bulk by itself.
#[derive(Debug, Clone)]
pub struct FlowClassifier {
    config: ClassifierConfig,
    class: TrafficClass,
    started: Duration,
    last_seen: Duration,
    window_started: Duration,
    window_bytes: u64,
    window_records: u32,
    latency_hold_until: Duration,
}

impl FlowClassifier {
    pub fn new(config: ClassifierConfig, now: Duration) -> Self {
        Self {
            config,
            class: TrafficClass::Latency,
            started: now,
            last_seen: now,
            window_started: now,
            window_bytes: 0,
            window_records: 0,
            latency_hold_until: now,
        }
    }

    /// Records one flow contribution. `interactive` is derived from protocol
    /// semantics (ACK/control/OAM/handshake), never from packet length.
    pub fn observe(
        &mut self,
        now: Duration,
        bytes: usize,
        queued_flow_bytes: u64,
        interactive: bool,
    ) -> TrafficClass {
        let now = now.max(self.last_seen);
        let idle = now.saturating_sub(self.last_seen);
        self.last_seen = now;

        if interactive || (self.class == TrafficClass::Bulk && idle >= self.config.demotion_idle) {
            self.class = TrafficClass::Latency;
            self.started = now;
            self.window_started = now;
            self.window_bytes = 0;
            self.window_records = 0;
            self.latency_hold_until = now.saturating_add(self.config.latency_hold);
        }

        if now.saturating_sub(self.window_started) > self.config.promotion_window {
            self.window_started = now;
            self.window_bytes = 0;
            self.window_records = 0;
        }
        self.window_bytes = self.window_bytes.saturating_add(bytes as u64);
        self.window_records = self.window_records.saturating_add(1);

        if self.class == TrafficClass::Latency
            && now >= self.latency_hold_until
            // Preserve one-record latency protection for a new GSO flow, but
            // do not require wall-clock ageing after a second record proves a
            // sustained transfer. TUN can deliver several MiB in the first
            // scheduler tick; ageing all of it as Latency creates seconds of
            // inner-TCP queueing and retransmissions on a shaped path.
            && (now.saturating_sub(self.started) >= self.config.promotion_age
                || self.window_records >= 2)
            && self.window_bytes >= self.config.promotion_bytes
        {
            let elapsed_micros = now.saturating_sub(self.window_started).as_micros().max(1);
            let rate = u128::from(self.window_bytes)
                .saturating_mul(1_000_000)
                .checked_div(elapsed_micros)
                .unwrap_or(u128::MAX)
                .min(u128::from(u64::MAX)) as u64;
            if rate >= self.config.promotion_rate_bytes_per_second
                || queued_flow_bytes >= self.config.promotion_queue_bytes
            {
                self.class = TrafficClass::Bulk;
            }
        }
        self.class
    }

    pub fn class(&self) -> TrafficClass {
        self.class
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_large_first_gso_packet_stays_latency_protected() {
        let mut classifier = FlowClassifier::new(ClassifierConfig::default(), Duration::ZERO);
        assert_eq!(
            classifier.observe(Duration::ZERO, 65_535, 65_535, false),
            TrafficClass::Latency
        );
        assert_eq!(
            classifier.observe(Duration::ZERO, 65_535, 0, false),
            TrafficClass::Bulk,
            "a second large record proves sustained Bulk without a timer round trip"
        );
    }

    #[test]
    fn sustained_high_rate_flow_promotes_and_idle_flow_demotes() {
        let config = ClassifierConfig::default();
        let mut classifier = FlowClassifier::new(config, Duration::ZERO);
        for tick in 1..=4 {
            classifier.observe(
                Duration::from_millis(tick * 50),
                32 * 1024,
                80 * 1024,
                false,
            );
        }
        assert_eq!(classifier.class(), TrafficClass::Bulk);
        assert_eq!(
            classifier.observe(Duration::from_secs(2), 100, 0, false),
            TrafficClass::Latency
        );
    }

    #[test]
    fn shaped_small_packet_flow_promotes_within_one_receive_batch() {
        let mut classifier = FlowClassifier::new(ClassifierConfig::default(), Duration::ZERO);
        for _ in 0..13 {
            assert_eq!(
                classifier.observe(Duration::from_millis(10), 1_200, 0, false),
                TrafficClass::Latency
            );
        }
        assert_eq!(
            classifier.observe(Duration::from_millis(10), 1_200, 0, false),
            TrafficClass::Bulk
        );
    }

    #[test]
    fn interactive_signal_demotes_with_a_hysteretic_hold() {
        let config = ClassifierConfig::default();
        let mut classifier = FlowClassifier::new(config, Duration::ZERO);
        classifier.observe(Duration::from_millis(200), 128 * 1024, 128 * 1024, false);
        assert_eq!(classifier.class(), TrafficClass::Bulk);
        classifier.observe(Duration::from_millis(210), 64, 0, true);
        assert_eq!(classifier.class(), TrafficClass::Latency);
        classifier.observe(Duration::from_millis(300), 128 * 1024, 128 * 1024, false);
        assert_eq!(classifier.class(), TrafficClass::Latency);
        classifier.observe(Duration::from_millis(800), 128 * 1024, 128 * 1024, false);
        assert_eq!(classifier.class(), TrafficClass::Bulk);
    }
}

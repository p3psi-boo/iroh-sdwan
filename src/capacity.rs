//! Directional, measurement-driven route capacity estimation.
//!
//! A route is identified by its final owner and the first overlay hop chosen
//! by this node.  Nothing in this module is shared with the reverse direction:
//! every node learns the routes that originate locally.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use iroh::EndpointId;

pub const DEFAULT_ROUTE_ESTIMATE_CAPACITY: usize = 4_096;
pub const CAPACITY_WINDOW: Duration = Duration::from_secs(2);
pub const FRESH_TTL: Duration = Duration::from_secs(60);
pub const STALE_TTL: Duration = Duration::from_secs(180);
pub const BOOTSTRAP_CAPACITY_BPS: u64 = 1_000_000;
pub const ACTIVE_SAMPLE_DISCOUNT_PER_MILLE: u64 = 800;
pub const MIN_HEALTH_PER_MILLE: u16 = 500;
pub const MAX_HEALTH_PER_MILLE: u16 = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RouteKey {
    pub destination: EndpointId,
    pub first_hop: EndpointId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleSource {
    Active,
    Passive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    Unknown,
    Fresh,
    Stale,
}

impl Freshness {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Fresh => "fresh",
            Self::Stale => "stale",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapacitySnapshot {
    pub capacity_bps: u64,
    pub effective_capacity_bps: u64,
    pub measured_capacity_bps: Option<u64>,
    pub min_rtt: Option<Duration>,
    pub rtt_ewma: Option<Duration>,
    pub loss_ppm: u32,
    pub health_per_mille: u16,
    pub sample_age: Option<Duration>,
    pub freshness: Freshness,
    pub last_sample_source: Option<SampleSource>,
    pub active_samples: u64,
    pub passive_samples: u64,
    pub route_switches: u64,
    pub path_epoch: u64,
}

#[derive(Debug, Clone)]
pub struct RouteEstimate {
    pub bw_previous_bps: u64,
    pub bw_current_bps: u64,
    pub min_rtt: Option<Duration>,
    pub rtt_ewma: Option<Duration>,
    pub loss_ppm: u32,
    pub health_per_mille: u16,
    pub sample_updated_at: Option<Instant>,
    pub path_epoch: u64,
    window_started_at: Instant,
    last_used_at: Instant,
    last_queue_bytes: u64,
    queue_growth_intervals: u8,
    healthy_intervals: u8,
    last_sample_source: Option<SampleSource>,
    active_samples: u64,
    passive_samples: u64,
    route_switches: u64,
}

impl RouteEstimate {
    pub fn new(now: Instant) -> Self {
        Self {
            bw_previous_bps: 0,
            bw_current_bps: 0,
            min_rtt: None,
            rtt_ewma: None,
            loss_ppm: 0,
            health_per_mille: MAX_HEALTH_PER_MILLE,
            sample_updated_at: None,
            path_epoch: 0,
            window_started_at: now,
            last_used_at: now,
            last_queue_bytes: 0,
            queue_growth_intervals: 0,
            healthy_intervals: 0,
            last_sample_source: None,
            active_samples: 0,
            passive_samples: 0,
            route_switches: 0,
        }
    }

    pub fn observe_active(&mut self, sample_bps: u64, rtt: Duration, loss_ppm: u32, now: Instant) {
        self.rotate_window(now);
        let accepted = sample_bps.saturating_mul(ACTIVE_SAMPLE_DISCOUNT_PER_MILLE) / 1_000;
        self.accept_capacity_sample(accepted, SampleSource::Active, now);
        self.observe_health(rtt, loss_ppm, self.last_queue_bytes, now);
    }

    /// Observe destination-confirmed delivery. `app_limited` means the route
    /// queue was not continuously occupied for the receiver's sample window.
    /// Such a sample is accepted only when it raises the current estimate.
    pub fn observe_passive(
        &mut self,
        delivered_bytes: u64,
        receiver_interval: Duration,
        app_limited: bool,
        now: Instant,
    ) -> bool {
        self.rotate_window(now);
        let Some(sample_bps) = delivery_rate_bps(delivered_bytes, receiver_interval) else {
            return false;
        };
        let current = self.measured_capacity_bps().unwrap_or(0);
        if app_limited && sample_bps < current {
            return false;
        }
        self.accept_capacity_sample(sample_bps, SampleSource::Passive, now);
        true
    }

    pub fn observe_health(&mut self, rtt: Duration, loss_ppm: u32, queue_bytes: u64, now: Instant) {
        self.last_used_at = now;
        self.min_rtt = Some(self.min_rtt.map_or(rtt, |minimum| minimum.min(rtt)));
        self.rtt_ewma = Some(match self.rtt_ewma {
            None => rtt,
            Some(previous) if rtt > previous => duration_ewma(previous, rtt, 1, 2),
            Some(previous) => duration_ewma(previous, rtt, 7, 8),
        });
        self.loss_ppm = if loss_ppm > self.loss_ppm {
            ((u64::from(self.loss_ppm) + u64::from(loss_ppm)) / 2) as u32
        } else {
            ((u64::from(self.loss_ppm) * 7 + u64::from(loss_ppm)) / 8) as u32
        };

        if queue_bytes > self.last_queue_bytes {
            self.queue_growth_intervals = self.queue_growth_intervals.saturating_add(1);
        } else {
            self.queue_growth_intervals = 0;
        }
        self.last_queue_bytes = queue_bytes;

        let minimum = self.min_rtt.unwrap_or(rtt);
        let queue_delay = self.rtt_ewma.unwrap_or(rtt).saturating_sub(minimum);
        let delay_threshold = Duration::from_millis(10).max(minimum / 4);
        let queue_unhealthy = self.queue_growth_intervals >= 2 && queue_delay > delay_threshold;
        let loss_unhealthy = self.loss_ppm >= 5_000;
        if queue_unhealthy || loss_unhealthy {
            self.decrease_health();
            self.healthy_intervals = 0;
            return;
        }

        let healthy = self.queue_growth_intervals == 0
            && queue_delay <= delay_threshold
            && self.loss_ppm < 1_000;
        if healthy {
            self.healthy_intervals = self.healthy_intervals.saturating_add(1);
            if self.healthy_intervals >= 3 {
                self.health_per_mille = self
                    .health_per_mille
                    .saturating_add(20)
                    .min(MAX_HEALTH_PER_MILLE);
                self.healthy_intervals = 0;
            }
        } else {
            self.healthy_intervals = 0;
        }
    }

    pub fn observe_failure(&mut self, now: Instant) {
        self.last_used_at = now;
        self.decrease_health();
        self.healthy_intervals = 0;
    }

    pub fn observe_route_switch(&mut self, now: Instant) {
        self.route_switches = self.route_switches.saturating_add(1);
        self.last_used_at = now;
    }

    pub fn rotate_window(&mut self, now: Instant) {
        while now.saturating_duration_since(self.window_started_at) >= CAPACITY_WINDOW {
            if self.bw_current_bps > 0 {
                self.bw_previous_bps = if self.bw_previous_bps == 0
                    || self.bw_current_bps >= self.bw_previous_bps / 2
                {
                    self.bw_current_bps
                } else {
                    self.bw_current_bps
                        .max(self.bw_previous_bps.saturating_mul(3) / 4)
                };
            }
            self.bw_current_bps = 0;
            self.window_started_at += CAPACITY_WINDOW;
            if self.freshness_at(self.window_started_at) == Freshness::Stale {
                self.health_per_mille = self
                    .health_per_mille
                    .saturating_sub(2)
                    .max(MIN_HEALTH_PER_MILLE);
            }
        }
        self.last_used_at = now;
    }

    pub fn invalidate_for_path_change(&mut self, new_epoch: u64, now: Instant) {
        if new_epoch == self.path_epoch {
            self.last_used_at = now;
            return;
        }
        self.bw_previous_bps = 0;
        self.bw_current_bps = 0;
        self.min_rtt = None;
        self.rtt_ewma = None;
        self.loss_ppm = 0;
        self.health_per_mille = MAX_HEALTH_PER_MILLE;
        self.sample_updated_at = None;
        self.path_epoch = new_epoch;
        self.window_started_at = now;
        self.last_used_at = now;
        self.last_queue_bytes = 0;
        self.queue_growth_intervals = 0;
        self.healthy_intervals = 0;
        self.last_sample_source = None;
    }

    pub fn snapshot(&self, now: Instant, max_egress_bps: Option<u64>) -> CapacitySnapshot {
        let freshness = self.freshness_at(now);
        let measured = (freshness != Freshness::Unknown)
            .then(|| self.measured_capacity_bps())
            .flatten();
        let capacity_bps = measured.unwrap_or(BOOTSTRAP_CAPACITY_BPS);
        let mut effective_capacity_bps =
            capacity_bps.saturating_mul(u64::from(self.health_per_mille)) / 1_000;
        if let Some(cap) = max_egress_bps {
            effective_capacity_bps = effective_capacity_bps.min(cap);
        }
        CapacitySnapshot {
            capacity_bps,
            effective_capacity_bps: effective_capacity_bps.max(1),
            measured_capacity_bps: measured,
            min_rtt: self.min_rtt,
            rtt_ewma: self.rtt_ewma,
            loss_ppm: self.loss_ppm,
            health_per_mille: self.health_per_mille,
            sample_age: self
                .sample_updated_at
                .map(|updated| now.saturating_duration_since(updated)),
            freshness,
            last_sample_source: self.last_sample_source,
            active_samples: self.active_samples,
            passive_samples: self.passive_samples,
            route_switches: self.route_switches,
            path_epoch: self.path_epoch,
        }
    }

    pub fn freshness_at(&self, now: Instant) -> Freshness {
        let Some(updated) = self.sample_updated_at else {
            return Freshness::Unknown;
        };
        let age = now.saturating_duration_since(updated);
        if age <= FRESH_TTL {
            Freshness::Fresh
        } else if age <= STALE_TTL {
            Freshness::Stale
        } else {
            Freshness::Unknown
        }
    }

    pub fn measured_capacity_bps(&self) -> Option<u64> {
        let value = self.bw_previous_bps.max(self.bw_current_bps);
        (value > 0).then_some(value)
    }

    fn accept_capacity_sample(&mut self, bps: u64, source: SampleSource, now: Instant) {
        if bps == 0 {
            return;
        }
        self.bw_current_bps = self.bw_current_bps.max(bps);
        self.sample_updated_at = Some(now);
        self.last_used_at = now;
        self.last_sample_source = Some(source);
        match source {
            SampleSource::Active => self.active_samples = self.active_samples.saturating_add(1),
            SampleSource::Passive => self.passive_samples = self.passive_samples.saturating_add(1),
        }
    }

    fn decrease_health(&mut self) {
        self.health_per_mille = (u32::from(self.health_per_mille) * 85 / 100)
            .max(u32::from(MIN_HEALTH_PER_MILLE)) as u16;
    }
}

#[derive(Debug)]
pub struct RouteEstimateTable {
    entries: HashMap<RouteKey, RouteEstimate>,
    capacity: usize,
}

impl Default for RouteEstimateTable {
    fn default() -> Self {
        Self::new(DEFAULT_ROUTE_ESTIMATE_CAPACITY)
    }
}

impl RouteEstimateTable {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            capacity: capacity.max(1),
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn get(&self, key: &RouteKey) -> Option<&RouteEstimate> {
        self.entries.get(key)
    }

    /// Read a route estimate without updating LRU bookkeeping. The capacity
    /// manager refreshes every live route independently, so packet forwarding
    /// can stay on a shared read lock and use the identical bootstrap model
    /// during the short interval before a route is registered.
    pub fn snapshot_or_bootstrap(
        &self,
        key: &RouteKey,
        now: Instant,
        max_egress_bps: Option<u64>,
    ) -> CapacitySnapshot {
        self.entries.get(key).map_or_else(
            || RouteEstimate::new(now).snapshot(now, max_egress_bps),
            |estimate| estimate.snapshot(now, max_egress_bps),
        )
    }

    pub fn get_mut(&mut self, key: &RouteKey, now: Instant) -> Option<&mut RouteEstimate> {
        let estimate = self.entries.get_mut(key)?;
        estimate.last_used_at = now;
        Some(estimate)
    }

    pub fn get_or_insert(&mut self, key: RouteKey, now: Instant) -> &mut RouteEstimate {
        if !self.entries.contains_key(&key) {
            self.make_room(now);
            self.entries.insert(key, RouteEstimate::new(now));
        }
        let estimate = self.entries.get_mut(&key).expect("route was inserted");
        estimate.last_used_at = now;
        estimate
    }

    #[cfg(test)]
    fn remove_destination(&mut self, destination: EndpointId) {
        self.entries.retain(|key, _| key.destination != destination);
    }

    pub fn iter(&self) -> impl Iterator<Item = (&RouteKey, &RouteEstimate)> {
        self.entries.iter()
    }

    pub fn snapshot_all(
        &self,
        now: Instant,
        max_egress_bps: Option<u64>,
    ) -> HashMap<RouteKey, CapacitySnapshot> {
        self.entries
            .iter()
            .map(|(key, estimate)| (*key, estimate.snapshot(now, max_egress_bps)))
            .collect()
    }

    pub fn prune_expired(&mut self, now: Instant) {
        self.entries.retain(|_, estimate| {
            estimate.freshness_at(now) != Freshness::Unknown
                || now.saturating_duration_since(estimate.last_used_at) <= STALE_TTL
        });
    }

    fn make_room(&mut self, now: Instant) {
        self.prune_expired(now);
        if self.entries.len() < self.capacity {
            return;
        }
        if let Some(oldest) = self
            .entries
            .iter()
            .min_by_key(|(_, estimate)| estimate.last_used_at)
            .map(|(key, _)| *key)
        {
            self.entries.remove(&oldest);
        }
    }
}

fn delivery_rate_bps(delivered_bytes: u64, interval: Duration) -> Option<u64> {
    if interval.is_zero() {
        return None;
    }
    let bits = u128::from(delivered_bytes).saturating_mul(8);
    let bps = bits.saturating_mul(1_000_000_000) / interval.as_nanos();
    Some(bps.min(u128::from(u64::MAX)) as u64)
}

fn duration_ewma(previous: Duration, sample: Duration, old_weight: u32, total: u32) -> Duration {
    let old = previous.as_nanos().saturating_mul(u128::from(old_weight));
    let new = sample
        .as_nanos()
        .saturating_mul(u128::from(total - old_weight));
    Duration::from_nanos(((old + new) / u128::from(total)).min(u128::from(u64::MAX)) as u64)
}

#[cfg(test)]
mod tests {
    use iroh::SecretKey;

    use super::*;

    fn endpoint(byte: u8) -> EndpointId {
        SecretKey::from_bytes(&[byte; 32]).public()
    }

    #[test]
    fn active_samples_are_discounted_and_window_uses_maximum() {
        let start = Instant::now();
        let mut estimate = RouteEstimate::new(start);
        estimate.observe_active(100_000_000, Duration::from_millis(20), 0, start);
        estimate.observe_active(
            50_000_000,
            Duration::from_millis(20),
            0,
            start + Duration::from_millis(10),
        );
        assert_eq!(estimate.bw_current_bps, 80_000_000);
        assert_eq!(estimate.active_samples, 2);
    }

    #[test]
    fn passive_samples_use_receiver_elapsed_and_app_limited_gate() {
        let start = Instant::now();
        let mut estimate = RouteEstimate::new(start);
        assert!(estimate.observe_passive(1_250_000, Duration::from_millis(100), false, start,));
        assert_eq!(estimate.bw_current_bps, 100_000_000);
        assert!(!estimate.observe_passive(
            125_000,
            Duration::from_millis(100),
            true,
            start + Duration::from_millis(10),
        ));
        assert!(estimate.observe_passive(
            2_500_000,
            Duration::from_millis(100),
            true,
            start + Duration::from_millis(20),
        ));
        assert_eq!(estimate.bw_current_bps, 200_000_000);
        assert_eq!(estimate.passive_samples, 2);
    }

    #[test]
    fn zero_receiver_elapsed_is_rejected() {
        let start = Instant::now();
        let mut estimate = RouteEstimate::new(start);
        assert!(!estimate.observe_passive(1_000, Duration::ZERO, false, start));
        assert_eq!(estimate.passive_samples, 0);
    }

    #[test]
    fn window_rotation_has_collapse_hysteresis_and_keeps_empty_window() {
        let start = Instant::now();
        let mut estimate = RouteEstimate::new(start);
        estimate.observe_passive(12_500_000, Duration::from_secs(1), false, start);
        estimate.rotate_window(start + CAPACITY_WINDOW);
        assert_eq!(estimate.bw_previous_bps, 100_000_000);

        estimate.observe_passive(
            1_250_000,
            Duration::from_secs(1),
            false,
            start + CAPACITY_WINDOW + Duration::from_millis(1),
        );
        estimate.rotate_window(start + CAPACITY_WINDOW * 2);
        assert_eq!(estimate.bw_previous_bps, 75_000_000);

        estimate.rotate_window(start + CAPACITY_WINDOW * 3);
        assert_eq!(estimate.bw_previous_bps, 75_000_000);
    }

    #[test]
    fn freshness_boundaries_and_bootstrap_are_deterministic() {
        let start = Instant::now();
        let mut estimate = RouteEstimate::new(start);
        assert_eq!(estimate.freshness_at(start), Freshness::Unknown);
        assert_eq!(
            estimate.snapshot(start, None).capacity_bps,
            BOOTSTRAP_CAPACITY_BPS
        );
        estimate.observe_passive(1_000_000, Duration::from_secs(1), false, start);
        assert_eq!(estimate.freshness_at(start + FRESH_TTL), Freshness::Fresh);
        assert_eq!(
            estimate.freshness_at(start + FRESH_TTL + Duration::from_nanos(1)),
            Freshness::Stale
        );
        assert_eq!(estimate.freshness_at(start + STALE_TTL), Freshness::Stale);
        assert_eq!(
            estimate.freshness_at(start + STALE_TTL + Duration::from_nanos(1)),
            Freshness::Unknown
        );
    }

    #[test]
    fn health_drops_fast_on_loss_and_recovers_slowly() {
        let start = Instant::now();
        let mut estimate = RouteEstimate::new(start);
        for index in 0..8 {
            estimate.observe_health(
                Duration::from_millis(20),
                50_000,
                0,
                start + Duration::from_millis(index),
            );
        }
        assert_eq!(estimate.health_per_mille, MIN_HEALTH_PER_MILLE);
        for index in 0..3 {
            estimate.observe_health(
                Duration::from_millis(20),
                0,
                0,
                start + Duration::from_secs(1) + Duration::from_millis(index),
            );
        }
        assert_eq!(estimate.health_per_mille, MIN_HEALTH_PER_MILLE);
        for index in 0..40 {
            estimate.observe_health(
                Duration::from_millis(20),
                0,
                0,
                start + Duration::from_secs(2) + Duration::from_millis(index),
            );
        }
        assert!(estimate.health_per_mille > MIN_HEALTH_PER_MILLE);
        assert!(estimate.health_per_mille <= MAX_HEALTH_PER_MILLE);
    }

    #[test]
    fn growing_queue_and_rtt_inflation_reduce_health() {
        let start = Instant::now();
        let mut estimate = RouteEstimate::new(start);
        estimate.observe_health(Duration::from_millis(20), 0, 1_000, start);
        estimate.observe_health(
            Duration::from_millis(60),
            0,
            2_000,
            start + Duration::from_millis(1),
        );
        estimate.observe_health(
            Duration::from_millis(80),
            0,
            3_000,
            start + Duration::from_millis(2),
        );
        assert_eq!(estimate.health_per_mille, 722);
    }

    #[test]
    fn degraded_rtt_and_loss_are_reflected_faster_than_recovery() {
        let start = Instant::now();
        let mut estimate = RouteEstimate::new(start);
        estimate.observe_health(Duration::from_millis(10), 0, 0, start);
        estimate.observe_health(
            Duration::from_millis(150),
            50_000,
            0,
            start + Duration::from_secs(1),
        );
        assert_eq!(estimate.rtt_ewma, Some(Duration::from_millis(80)));
        assert_eq!(estimate.loss_ppm, 25_000);
        assert_eq!(estimate.health_per_mille, 850);

        estimate.observe_health(
            Duration::from_millis(10),
            0,
            0,
            start + Duration::from_secs(2),
        );
        assert!(estimate.rtt_ewma.unwrap() > Duration::from_millis(70));
        assert!(estimate.loss_ppm > 20_000);
    }

    #[test]
    fn path_epoch_change_invalidates_capacity_and_rtt() {
        let start = Instant::now();
        let mut estimate = RouteEstimate::new(start);
        estimate.observe_active(100_000_000, Duration::from_millis(20), 0, start);
        estimate.invalidate_for_path_change(4, start + Duration::from_secs(1));
        assert_eq!(estimate.path_epoch, 4);
        assert_eq!(estimate.measured_capacity_bps(), None);
        assert_eq!(estimate.min_rtt, None);
        assert_eq!(
            estimate.freshness_at(start + Duration::from_secs(1)),
            Freshness::Unknown
        );
        estimate.observe_route_switch(start + Duration::from_secs(2));
        estimate.invalidate_for_path_change(5, start + Duration::from_secs(3));
        assert_eq!(
            estimate
                .snapshot(start + Duration::from_secs(3), None)
                .route_switches,
            1
        );
    }

    #[test]
    fn effective_capacity_combines_health_and_local_cap() {
        let start = Instant::now();
        let mut estimate = RouteEstimate::new(start);
        estimate.observe_passive(12_500_000, Duration::from_secs(1), false, start);
        estimate.health_per_mille = 850;
        let snapshot = estimate.snapshot(start, Some(70_000_000));
        assert_eq!(snapshot.capacity_bps, 100_000_000);
        assert_eq!(snapshot.effective_capacity_bps, 70_000_000);
    }

    #[test]
    fn table_evicts_expired_then_lru_and_can_remove_owner() {
        let start = Instant::now();
        let mut table = RouteEstimateTable::new(2);
        let a = RouteKey {
            destination: endpoint(1),
            first_hop: endpoint(2),
        };
        let b = RouteKey {
            destination: endpoint(1),
            first_hop: endpoint(3),
        };
        let c = RouteKey {
            destination: endpoint(4),
            first_hop: endpoint(3),
        };
        table.get_or_insert(a, start);
        table.get_or_insert(b, start + Duration::from_secs(1));
        table.get_or_insert(c, start + Duration::from_secs(2));
        assert!(table.get(&a).is_none());
        assert!(table.get(&b).is_some());
        assert!(table.get(&c).is_some());
        table.remove_destination(endpoint(1));
        assert_eq!(table.len(), 1);
        assert!(table.get(&c).is_some());
    }

    #[test]
    fn table_never_exceeds_hard_capacity() {
        let start = Instant::now();
        let mut table = RouteEstimateTable::new(4);
        for index in 0..100_u8 {
            table.get_or_insert(
                RouteKey {
                    destination: endpoint(index),
                    first_hop: endpoint(index.wrapping_add(1)),
                },
                start + Duration::from_millis(u64::from(index)),
            );
            assert!(table.len() <= 4);
        }
    }
}

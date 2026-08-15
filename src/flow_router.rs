//! Demand-aware route selection without protocol or business classification.
//!
//! A flow carries only a decaying pressure estimate and a short route lease.

use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use rustc_hash::FxHashMap;

use crate::packet::FlowKey;

const DEFAULT_MAX_FLOWS: usize = 65_536;
const DEFAULT_PRESSURE_DRAIN_BYTES_PER_SECOND: u64 = 256 * 1024;
const DEFAULT_PACKET_ALLOWANCE_BYTES: usize = 256;
const DEFAULT_MAX_PRESSURE_BYTES: u64 = 64 * 1024 * 1024;
// One second is still short relative to a transfer, but gives a newly selected
// path enough time to leave QUIC cold start and produce a receiver-confirmed
// sample before a bulk flow's first re-evaluation.
const DEFAULT_LEASE: Duration = Duration::from_secs(1);
const DEFAULT_IDLE_TTL: Duration = Duration::from_secs(2);
const DEFAULT_SWITCH_PENALTY: Duration = Duration::from_millis(25);
// New flows can arrive at packet rate. Rebuilding the entire table for every
// insertion makes admission O(active_flows), even while comfortably below the
// hard limit. Expiry is housekeeping, so amortize it independently of packets.
const PRUNE_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RouteId(pub u64);

/// One usable next-hop route reduced by the topology layer.
#[derive(Debug)]
pub struct RouteCandidate {
    pub id: RouteId,
    pub startup_latency: Duration,
    /// Directional capacity after path health and local policy caps.
    pub capacity_bps: u64,
    pub queued_bytes: u64,
    pub loss_penalty: Duration,
}

impl RouteCandidate {
    pub fn is_usable(&self) -> bool {
        self.capacity_bps > 0
    }

    pub fn estimated_completion(&self, demand_bytes: u64) -> Duration {
        self.startup_latency
            .saturating_add(transfer_time(
                self.queued_bytes.saturating_add(demand_bytes),
                self.capacity_bps,
            ))
            .saturating_add(self.loss_penalty)
    }
}

#[derive(Debug)]
pub struct FlowDecision {
    pub route_id: RouteId,
    pub demand_bytes: u64,
    /// Previous lease holder, if this flow had already selected a route.
    pub previous_route_id: Option<RouteId>,
    /// Cost components captured at the decision boundary for observability.
    pub estimated_completion: Duration,
    pub switch_penalty: Duration,
}

impl FlowDecision {
    pub fn switched(&self) -> bool {
        self.previous_route_id
            .is_some_and(|previous| previous != self.route_id)
    }
}

#[derive(Debug, Clone, Copy)]
struct RouteLease {
    route_id: RouteId,
    valid_until: Instant,
}

#[derive(Debug)]
struct FlowSlot {
    pressure: u64,
    updated_at: Instant,
    lease: Option<RouteLease>,
}

impl FlowSlot {
    fn new(now: Instant) -> Self {
        Self {
            pressure: 0,
            updated_at: now,
            lease: None,
        }
    }

    fn observe(&mut self, packet_len: usize, now: Instant, config: &FlowRouterConfig) {
        let elapsed = now
            .checked_duration_since(self.updated_at)
            .unwrap_or(Duration::ZERO);
        let drained = bytes_for_duration(config.pressure_drain_bytes_per_second, elapsed);
        self.pressure = self.pressure.saturating_sub(drained);
        self.pressure = self
            .pressure
            .saturating_add(packet_len.saturating_sub(config.packet_allowance_bytes) as u64)
            .min(config.max_pressure_bytes);
        self.updated_at = now;
    }
}

#[derive(Debug, Clone)]
pub struct FlowRouterConfig {
    pub max_flows: usize,
    pub pressure_drain_bytes_per_second: u64,
    pub packet_allowance_bytes: usize,
    pub max_pressure_bytes: u64,
    pub lease_duration: Duration,
    pub idle_ttl: Duration,
    pub switch_penalty: Duration,
}

impl Default for FlowRouterConfig {
    fn default() -> Self {
        Self {
            max_flows: DEFAULT_MAX_FLOWS,
            pressure_drain_bytes_per_second: DEFAULT_PRESSURE_DRAIN_BYTES_PER_SECOND,
            packet_allowance_bytes: DEFAULT_PACKET_ALLOWANCE_BYTES,
            max_pressure_bytes: DEFAULT_MAX_PRESSURE_BYTES,
            lease_duration: DEFAULT_LEASE,
            idle_ttl: DEFAULT_IDLE_TTL,
            switch_penalty: DEFAULT_SWITCH_PENALTY,
        }
    }
}

/// Bounded per-flow demand memory and route lease selector.
#[derive(Debug)]
pub struct FlowRouter {
    config: FlowRouterConfig,
    flows: FxHashMap<FlowKey, FlowSlot>,
    insertion_order: VecDeque<FlowKey>,
    next_prune_at: Option<Instant>,
}

impl Default for FlowRouter {
    fn default() -> Self {
        Self::new(FlowRouterConfig::default())
    }
}

impl FlowRouter {
    pub fn new(config: FlowRouterConfig) -> Self {
        assert!(
            config.max_flows > 0,
            "FlowRouter max_flows must be non-zero"
        );
        assert!(
            config.pressure_drain_bytes_per_second > 0,
            "FlowRouter pressure drain must be non-zero"
        );
        assert!(
            !config.lease_duration.is_zero(),
            "FlowRouter lease duration must be non-zero"
        );
        assert!(
            !config.idle_ttl.is_zero(),
            "FlowRouter idle TTL must be non-zero"
        );
        Self {
            config,
            flows: FxHashMap::default(),
            insertion_order: VecDeque::new(),
            next_prune_at: None,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.flows.len()
    }

    /// Observe one packet and select a route. `flow_queued_bytes` is the
    /// queue occupancy attributable to this flow, not the peer-wide backlog.
    #[cfg(test)]
    fn select(
        &mut self,
        key: FlowKey,
        packet_len: usize,
        flow_queued_bytes: u64,
        candidates: &[RouteCandidate],
        now: Instant,
    ) -> Option<FlowDecision> {
        self.select_projected(
            key,
            packet_len,
            flow_queued_bytes,
            candidates,
            |candidate| candidate,
            now,
        )
    }

    /// Select from caller-owned wrappers without cloning their candidates into
    /// a temporary Vec. Topology metadata can remain beside each candidate.
    pub fn select_projected<'a, T>(
        &mut self,
        key: FlowKey,
        packet_len: usize,
        flow_queued_bytes: u64,
        candidates: &'a [T],
        project: impl Fn(&'a T) -> &'a RouteCandidate,
        now: Instant,
    ) -> Option<FlowDecision> {
        if !self.flows.contains_key(&key) {
            self.make_room(now);
            self.flows.insert(key, FlowSlot::new(now));
            self.insertion_order.push_back(key);
        }

        let slot = self.flows.get_mut(&key).expect("flow was inserted");
        let idle = now
            .checked_duration_since(slot.updated_at)
            .unwrap_or(Duration::ZERO);
        if idle >= self.config.idle_ttl {
            *slot = FlowSlot::new(now);
        }
        slot.observe(packet_len, now, &self.config);
        let demand_bytes = slot.pressure.saturating_add(flow_queued_bytes);

        let leased = slot.lease.and_then(|lease| {
            (lease.valid_until > now)
                .then(|| {
                    candidates
                        .iter()
                        .map(&project)
                        .find(|route| route.id == lease.route_id)
                })
                .flatten()
                .filter(|route| route.is_usable())
                .map(|route| (route, lease))
        });
        let previous_route_id = slot.lease.map(|lease| lease.route_id);
        let (selected, lease, switch_penalty) = match leased {
            Some((route, lease)) => (route, lease, Duration::ZERO),
            None => {
                let selected = candidates
                    .iter()
                    .map(&project)
                    .filter(|route| route.is_usable())
                    .min_by_key(|route| {
                        let switch = if previous_route_id.is_some_and(|id| id != route.id) {
                            self.config.switch_penalty
                        } else {
                            Duration::ZERO
                        };
                        route
                            .estimated_completion(demand_bytes)
                            .saturating_add(switch)
                    })?;
                (
                    selected,
                    RouteLease {
                        route_id: selected.id,
                        valid_until: now + self.config.lease_duration,
                    },
                    if previous_route_id.is_some_and(|id| id != selected.id) {
                        self.config.switch_penalty
                    } else {
                        Duration::ZERO
                    },
                )
            }
        };

        // A busy flow must still be re-evaluated when its lease expires. If
        // each packet renewed the lease, sustained bulk traffic would remain
        // pinned forever to the low-latency route selected at flow startup.
        slot.lease = Some(lease);
        Some(FlowDecision {
            route_id: selected.id,
            demand_bytes,
            previous_route_id,
            estimated_completion: selected
                .estimated_completion(demand_bytes)
                .saturating_add(switch_penalty),
            switch_penalty,
        })
    }

    fn prune(&mut self, now: Instant) {
        let idle_ttl = self.config.idle_ttl;
        self.flows.retain(|_, flow| {
            now.checked_duration_since(flow.updated_at)
                .unwrap_or(Duration::ZERO)
                < idle_ttl
        });
    }

    fn make_room(&mut self, now: Instant) {
        if self.next_prune_at.is_none_or(|deadline| deadline <= now) {
            self.prune(now);
            self.next_prune_at = now.checked_add(PRUNE_INTERVAL);
        }
        if self.flows.len() < self.config.max_flows {
            return;
        }
        while let Some(oldest) = self.insertion_order.pop_front() {
            if self.flows.remove(&oldest).is_some() {
                return;
            }
        }
    }
}

fn bytes_for_duration(bytes_per_second: u64, duration: Duration) -> u64 {
    let bytes =
        u128::from(bytes_per_second).saturating_mul(duration.as_nanos()) / 1_000_000_000_u128;
    bytes.min(u128::from(u64::MAX)) as u64
}

fn transfer_time(bytes: u64, capacity_bps: u64) -> Duration {
    if bytes == 0 {
        return Duration::ZERO;
    }
    if capacity_bps == 0 {
        return Duration::MAX;
    }
    let nanos = u128::from(bytes)
        .saturating_mul(8)
        .saturating_mul(1_000_000_000)
        .div_ceil(u128::from(capacity_bps));
    Duration::from_nanos(nanos.min(u128::from(u64::MAX)) as u64)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    fn key(port: u16) -> FlowKey {
        FlowKey {
            source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            destination: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            protocol: 6,
            source_port: Some(port),
            destination_port: Some(443),
        }
    }

    fn indexed_key(index: u32) -> FlowKey {
        let octets = index.to_be_bytes();
        FlowKey {
            source: IpAddr::V4(Ipv4Addr::new(10, octets[1], octets[2], octets[3])),
            destination: IpAddr::V4(Ipv4Addr::new(10, 255, 255, 254)),
            protocol: 6,
            source_port: Some(index as u16),
            destination_port: Some(443),
        }
    }

    fn candidate(id: u64, latency: Duration, capacity_bps: u64) -> RouteCandidate {
        RouteCandidate {
            id: RouteId(id),
            startup_latency: latency,
            capacity_bps,
            queued_bytes: 0,
            loss_penalty: Duration::ZERO,
        }
    }

    fn test_router() -> FlowRouter {
        FlowRouter::new(FlowRouterConfig {
            lease_duration: Duration::from_millis(100),
            idle_ttl: Duration::from_secs(1),
            switch_penalty: Duration::from_millis(5),
            ..FlowRouterConfig::default()
        })
    }

    #[test]
    fn new_short_flow_chooses_low_latency_route() {
        let now = Instant::now();
        let mut router = test_router();
        let plans = [
            candidate(1, Duration::from_millis(10), 50_000_000),
            candidate(2, Duration::from_millis(50), 500_000_000),
        ];

        let decision = router.select(key(10_001), 100, 0, &plans, now).unwrap();
        assert_eq!(decision.route_id, RouteId(1));
        assert_eq!(decision.demand_bytes, 0);
    }

    #[test]
    fn sustained_large_flow_moves_to_high_capacity_route() {
        let start = Instant::now();
        let mut router = test_router();
        let plans = [
            candidate(1, Duration::from_millis(10), 10_000_000),
            candidate(2, Duration::from_millis(50), 500_000_000),
        ];

        let first = router.select(key(10_002), 1_500, 0, &plans, start).unwrap();
        assert_eq!(first.route_id, RouteId(1));
        assert_eq!(first.previous_route_id, None);
        assert!(!first.switched());

        let mut last = first;
        for index in 1..=200 {
            last = router
                .select(
                    key(10_002),
                    1_500,
                    256 * 1024,
                    &plans,
                    start + Duration::from_millis(index * 2),
                )
                .unwrap();
        }
        assert_eq!(last.route_id, RouteId(2));
        assert_eq!(last.previous_route_id, Some(RouteId(2)));

        let switched = router
            .select(key(10_008), 100, 0, &plans, start + Duration::from_secs(2))
            .unwrap();
        assert!(!switched.switched(), "an initial decision is not a switch");
    }

    #[test]
    fn valid_lease_prevents_packet_by_packet_route_flapping() {
        let start = Instant::now();
        let mut router = test_router();
        let initial = [
            candidate(1, Duration::from_millis(10), 100_000_000),
            candidate(2, Duration::from_millis(50), 500_000_000),
        ];
        assert_eq!(
            router
                .select(key(10_003), 100, 0, &initial, start)
                .unwrap()
                .route_id,
            RouteId(1)
        );

        let changed = [
            candidate(1, Duration::from_millis(100), 1_000_000),
            candidate(2, Duration::from_millis(1), 1_000_000_000),
        ];
        let decision = router
            .select(
                key(10_003),
                1_500,
                1_000_000,
                &changed,
                start + Duration::from_millis(10),
            )
            .unwrap();
        assert_eq!(decision.route_id, RouteId(1));
    }

    #[test]
    fn idle_flow_is_recreated_with_low_pressure() {
        let start = Instant::now();
        let mut router = test_router();
        let plans = [candidate(1, Duration::from_millis(10), 50_000_000)];
        router.select(key(10_005), 1_500, 0, &plans, start).unwrap();
        let second = router
            .select(key(10_005), 100, 0, &plans, start + Duration::from_secs(2))
            .unwrap();
        assert_eq!(second.demand_bytes, 0);
    }

    #[test]
    fn flow_table_is_bounded() {
        let now = Instant::now();
        let mut router = FlowRouter::new(FlowRouterConfig {
            max_flows: 2,
            ..FlowRouterConfig::default()
        });
        let plans = [candidate(1, Duration::from_millis(10), 50_000_000)];
        for port in 1..=3 {
            router.select(key(port), 100, 0, &plans, now).unwrap();
        }
        assert_eq!(router.len(), 2);
    }

    #[test]
    fn flow_table_tracks_one_hundred_and_one_thousand_active_flows() {
        let now = Instant::now();
        let plans = [candidate(1, Duration::from_millis(10), 50_000_000)];
        for expected in [1_u16, 100, 1_000] {
            let mut router = FlowRouter::default();
            for port in 1..=expected {
                router.select(key(port), 100, 0, &plans, now).unwrap();
            }
            assert_eq!(router.len(), usize::from(expected));
        }
    }

    #[test]
    fn flow_table_stays_at_the_hard_limit_under_sixty_five_thousand_flows() {
        let now = Instant::now();
        let plans = [candidate(1, Duration::from_millis(10), 50_000_000)];
        let mut router = FlowRouter::default();
        for index in 0..DEFAULT_MAX_FLOWS as u32 {
            router
                .select(indexed_key(index), 100, 0, &plans, now)
                .unwrap();
        }
        assert_eq!(router.len(), DEFAULT_MAX_FLOWS);

        router
            .select(indexed_key(DEFAULT_MAX_FLOWS as u32), 100, 0, &plans, now)
            .unwrap();
        assert_eq!(router.len(), DEFAULT_MAX_FLOWS);
    }

    #[test]
    fn queue_occupancy_redirects_a_short_flow_after_its_lease() {
        let start = Instant::now();
        let mut router = test_router();
        let clear = [
            candidate(1, Duration::from_millis(5), 10_000_000),
            candidate(2, Duration::from_millis(40), 100_000_000),
        ];
        assert_eq!(
            router
                .select(key(10_006), 100, 0, &clear, start)
                .unwrap()
                .route_id,
            RouteId(1)
        );

        let mut congested = clear;
        congested[0].queued_bytes = 2 * 1024 * 1024;
        let decision = router
            .select(
                key(10_006),
                100,
                0,
                &congested,
                start + Duration::from_millis(101),
            )
            .unwrap();
        assert_eq!(decision.route_id, RouteId(2));
        assert!(decision.switched());
        assert_eq!(decision.previous_route_id, Some(RouteId(1)));
        assert_eq!(decision.switch_penalty, Duration::from_millis(5));
        assert!(decision.estimated_completion >= decision.switch_penalty);
    }

    #[test]
    fn measured_loss_penalty_can_override_raw_rtt() {
        let now = Instant::now();
        let mut router = test_router();
        let mut lossy = candidate(1, Duration::from_millis(5), 100_000_000);
        lossy.loss_penalty = Duration::from_millis(80);
        let clean = candidate(2, Duration::from_millis(30), 100_000_000);
        let decision = router
            .select(key(10_007), 100, 0, &[lossy, clean], now)
            .unwrap();
        assert_eq!(decision.route_id, RouteId(2));
    }

    #[test]
    fn classification_is_protocol_and_port_agnostic() {
        let now = Instant::now();
        let plans = [
            candidate(1, Duration::from_millis(5), 10_000_000),
            candidate(2, Duration::from_millis(50), 500_000_000),
        ];
        for (protocol, source_port, destination_port) in [
            (6, Some(22), Some(60_000)),
            (17, Some(53), Some(9999)),
            (1, None, None),
        ] {
            let mut router = test_router();
            let flow = FlowKey {
                source: "10.0.0.1".parse().unwrap(),
                destination: "10.0.0.2".parse().unwrap(),
                protocol,
                source_port,
                destination_port,
            };
            assert_eq!(
                router.select(flow, 100, 0, &plans, now).unwrap().route_id,
                RouteId(1)
            );
            assert_eq!(
                router
                    .select(
                        flow,
                        1_500,
                        2 * 1024 * 1024,
                        &plans,
                        now + Duration::from_millis(101),
                    )
                    .unwrap()
                    .route_id,
                RouteId(2)
            );
        }
    }
}

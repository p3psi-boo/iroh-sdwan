//! Node egress coordinator (plan section 9).
//!
//! Every peer's policy tick publishes its guarded [`EgressRequestV1`] here
//! and reads back an [`EgressAllocationViewV1`] for the next tick. The
//! coordinator is the only place per-peer demands meet the node-wide budget:
//!
//! ```text
//! peer candidates
//! → minimum guarantee allocation
//! → weighted excess allocation (non-exploring peers)
//! → exploration budget (whatever is left)
//! → total cap enforcement
//! → per-peer assigned rate
//! ```
//!
//! The assigned rate clamps the peer's BBR pacing cap through the guardrail
//! pass ([`ClampReasonV1::EgressArbitration`]). Control and Repair traffic
//! ride a dedicated QUIC stream outside the paced datagram data plane, so
//! arbitration can never starve them (plan section 9.2).
//!
//! Slow peers are never awaited (plan section 9.2): each peer ticks in its
//! own task and merely publishes into shared state. A peer whose demand is
//! older than [`EGRESS_DEMAND_DEADLINE`] reserves its last assigned rate (the
//! conservative reading of its previous constrained demand) instead of a
//! fresh request; a peer with no history at all reads the dynamic fair share
//! of the remaining budget. A faulting guest simply stops publishing, which
//! cannot block the other peers.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::api::{EgressAllocationViewV1, EgressRequestV1};

/// A demand older than this no longer counts as a fresh request (2.5 ticks
/// at the 1 s sample cadence).
pub const EGRESS_DEMAND_DEADLINE: Duration = Duration::from_millis(2_500);
/// Peers silent for this long are forgotten entirely (disconnects).
pub const EGRESS_PEER_PRUNE_AFTER: Duration = Duration::from_secs(30);
/// The BBR3 controller floors any non-zero pacing cap at 64 KiB/s; the
/// coordinator never reports a smaller non-zero assignment, so the effective
/// action stays exactly what the data plane executes.
pub const EGRESS_ASSIGNMENT_FLOOR_BYTES_PER_SECOND: u64 = 64 * 1024;

/// Opaque peer bucket: the BLAKE3 peer hash the policy pipeline already uses.
pub type EgressPeerKey = [u8; 32];

#[derive(Debug, Clone)]
struct PeerDemandV1 {
    request: EgressRequestV1,
    updated_at: Instant,
    /// Rate the coordinator assigned the last time this peer was fresh; a
    /// stale peer reserves this much of the node budget.
    last_assigned: u64,
}

/// Weighted max-min over `excess` demands within `budget`. Every iteration
/// fully satisfies at least one peer, or closes with a final proportional
/// partial grant, so the loop terminates in at most `n + 1` rounds and the
/// total granted never exceeds `budget` (floor division may leave a few
/// bytes undistributed).
fn weighted_max_min(excess: &[u64], weights: &[u64], mut budget: u64) -> Vec<u64> {
    let n = excess.len();
    let mut granted = vec![0_u64; n];
    let mut open: Vec<bool> = excess.iter().map(|&demand| demand > 0).collect();
    loop {
        if budget == 0 {
            break;
        }
        let total_weight: u128 = (0..n)
            .filter(|&index| open[index])
            .map(|index| u128::from(weights[index]))
            .sum();
        if total_weight == 0 {
            break;
        }
        let mut satisfied = false;
        let mut spent = 0_u64;
        for index in 0..n {
            if !open[index] {
                continue;
            }
            let remaining = excess[index] - granted[index];
            let share = (u128::from(budget) * u128::from(weights[index]) / total_weight)
                .min(u128::from(u64::MAX)) as u64;
            if share >= remaining {
                granted[index] = excess[index];
                open[index] = false;
                satisfied = true;
                spent = spent.saturating_add(remaining);
            }
        }
        if !satisfied {
            // Nobody completes this round: everyone takes their proportional
            // share and the budget is exhausted modulo floor division.
            for index in 0..n {
                if !open[index] {
                    continue;
                }
                let share = (u128::from(budget) * u128::from(weights[index]) / total_weight)
                    .min(u128::from(u64::MAX)) as u64;
                granted[index] += share.min(excess[index] - granted[index]);
            }
            break;
        }
        budget = budget.saturating_sub(spent);
    }
    granted
}

/// Two-phase arbitration (plan section 9.1) over the fresh demands of one
/// round. `reserved` is the budget stale peers hold from their last assigned
/// rates. The sum of the returned assignments never exceeds
/// `node_cap - reserved`; every demanding peer's minimum is met whenever the
/// minima fit the available budget, and exploring peers only ever see what
/// the non-exploring excess allocation leaves behind.
pub fn arbitrate(requests: &[EgressRequestV1], reserved: u64, node_cap: u64) -> Vec<u64> {
    let available = node_cap.saturating_sub(reserved);
    let minima: Vec<u64> = requests
        .iter()
        .map(|request| request.minimum_rate_bytes_per_second)
        .collect();
    let sum_minima: u128 = minima.iter().map(|&minimum| u128::from(minimum)).sum();
    if sum_minima > u128::from(available) {
        // Overcommitted minima scale down proportionally; the hard budget is
        // never exceeded.
        return minima
            .iter()
            .map(|&minimum| {
                (u128::from(minimum) * u128::from(available))
                    .checked_div(sum_minima)
                    .unwrap_or(0) as u64
            })
            .collect();
    }
    let mut assigned = minima.clone();
    let mut budget = available - sum_minima as u64;
    let weights: Vec<u64> = requests
        .iter()
        .map(|request| u64::from(request.priority) + 1)
        .collect();
    // Phase 2: weighted excess for the peers that are not exploring. A
    // zero desired rate is no excess demand.
    let excess: Vec<u64> = requests
        .iter()
        .map(|request| {
            if request.exploring || request.desired_rate_bytes_per_second == 0 {
                0
            } else {
                request
                    .desired_rate_bytes_per_second
                    .saturating_sub(request.minimum_rate_bytes_per_second)
            }
        })
        .collect();
    let grants = weighted_max_min(&excess, &weights, budget);
    for (index, grant) in grants.iter().enumerate() {
        assigned[index] += grant;
        budget = budget.saturating_sub(*grant);
    }
    // Phase 3: exploring peers share whatever the excess allocation left;
    // exploration can never eat a minimum or outbid committed demand.
    let exploration: Vec<u64> = requests
        .iter()
        .map(|request| {
            if request.exploring {
                request
                    .desired_rate_bytes_per_second
                    .saturating_sub(request.minimum_rate_bytes_per_second)
            } else {
                0
            }
        })
        .collect();
    let grants = weighted_max_min(&exploration, &weights, budget);
    for (index, grant) in grants.iter().enumerate() {
        assigned[index] += grant;
    }
    assigned
}

/// Shared per-node coordinator state. Cheap to clone into every peer task.
#[derive(Debug)]
pub struct NodeEgressCoordinatorV1 {
    node_cap_bytes_per_second: u64,
    inner: Mutex<CoordinatorInnerV1>,
}

#[derive(Debug, Default)]
struct CoordinatorInnerV1 {
    demands: HashMap<EgressPeerKey, PeerDemandV1>,
    generation: u64,
}

impl NodeEgressCoordinatorV1 {
    /// `node_cap_bytes_per_second == 0` means unconfigured: the coordinator
    /// is a pass-through and every view reports "uncapped".
    pub fn new(node_cap_bytes_per_second: u64) -> Self {
        Self {
            node_cap_bytes_per_second,
            inner: Mutex::default(),
        }
    }

    /// Publish this tick's guarded egress request for `peer`.
    pub fn publish(&self, peer: EgressPeerKey, request: EgressRequestV1, now: Instant) {
        let mut inner = self.inner.lock().expect("egress coordinator poisoned");
        inner.generation = inner.generation.saturating_add(1);
        let last_assigned = inner
            .demands
            .get(&peer)
            .map_or(0, |demand| demand.last_assigned);
        inner.demands.insert(
            peer,
            PeerDemandV1 {
                request,
                updated_at: now,
                last_assigned,
            },
        );
        inner.demands.retain(|_, demand| {
            now.saturating_duration_since(demand.updated_at) <= EGRESS_PEER_PRUNE_AFTER
        });
    }

    /// The coordinator view `peer` sees for the coming tick. Never blocks on
    /// other peers: only demands published within [`EGRESS_DEMAND_DEADLINE`]
    /// count as fresh; stale peers reserve their last assigned rate.
    pub fn view(&self, peer: EgressPeerKey, now: Instant) -> EgressAllocationViewV1 {
        let mut inner = self.inner.lock().expect("egress coordinator poisoned");
        inner.demands.retain(|_, demand| {
            now.saturating_duration_since(demand.updated_at) <= EGRESS_PEER_PRUNE_AFTER
        });
        let active_peers = inner.demands.len() as u32;
        if self.node_cap_bytes_per_second == 0 {
            return EgressAllocationViewV1 {
                active_peers,
                allocation_generation: inner.generation,
                ..EgressAllocationViewV1::default()
            };
        }
        let mut fresh: Vec<(EgressPeerKey, EgressRequestV1)> = Vec::new();
        let mut reserved = 0_u64;
        let mut self_stale_assigned = None;
        for (&key, demand) in &inner.demands {
            if now.saturating_duration_since(demand.updated_at) <= EGRESS_DEMAND_DEADLINE {
                fresh.push((key, demand.request.clone()));
            } else {
                reserved = reserved.saturating_add(demand.last_assigned);
                if key == peer {
                    self_stale_assigned = Some(demand.last_assigned);
                }
            }
        }
        let requests: Vec<EgressRequestV1> =
            fresh.iter().map(|(_, request)| request.clone()).collect();
        let assigned = arbitrate(&requests, reserved, self.node_cap_bytes_per_second);
        let mut self_assigned = self_stale_assigned;
        for ((key, _), rate) in fresh.iter().zip(assigned.iter()) {
            // The controller floor dominates tiny assignments; the
            // coordinator never reports a smaller non-zero rate.
            let rate = if *rate == 0 || *rate >= EGRESS_ASSIGNMENT_FLOOR_BYTES_PER_SECOND {
                *rate
            } else {
                EGRESS_ASSIGNMENT_FLOOR_BYTES_PER_SECOND
            };
            if let Some(demand) = inner.demands.get_mut(key) {
                demand.last_assigned = rate;
            }
            if *key == peer {
                self_assigned = Some(rate);
            }
        }
        let assigned = match self_assigned {
            Some(rate) => rate,
            // No history: the dynamic fair share of the unreserved budget,
            // counting this peer among the competitors.
            None => {
                let available = self.node_cap_bytes_per_second.saturating_sub(reserved);
                let peers = u64::from(active_peers) + 1;
                (available / peers).min(self.node_cap_bytes_per_second)
            }
        };
        let node_demand = fresh
            .iter()
            .map(|(_, request)| request.desired_rate_bytes_per_second)
            .fold(reserved, u64::saturating_add);
        let pressure_per_mille = u16::try_from(
            u128::from(node_demand)
                .saturating_mul(1_000)
                .checked_div(u128::from(self.node_cap_bytes_per_second))
                .unwrap_or(0)
                .min(u128::from(u16::MAX)),
        )
        .unwrap_or(u16::MAX);
        EgressAllocationViewV1 {
            assigned_rate_bytes_per_second: assigned,
            node_cap_bytes_per_second: self.node_cap_bytes_per_second,
            node_demand_bytes_per_second: node_demand,
            pressure_per_mille,
            active_peers,
            allocation_generation: inner.generation,
        }
    }

    #[cfg(test)]
    fn tracked_peers(&self) -> usize {
        self.inner
            .lock()
            .expect("egress coordinator poisoned")
            .demands
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(desired: u64, minimum: u64, priority: u8, exploring: bool) -> EgressRequestV1 {
        EgressRequestV1 {
            desired_rate_bytes_per_second: desired,
            minimum_rate_bytes_per_second: minimum,
            priority,
            exploring,
        }
    }

    fn peer(byte: u8) -> EgressPeerKey {
        [byte; 32]
    }

    /// Small deterministic generator (xorshift64*), same pattern as the
    /// guardrail property tests.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }

        fn below(&mut self, bound: u64) -> u64 {
            self.next() % bound.max(1)
        }
    }

    #[test]
    fn minima_are_guaranteed_before_excess() {
        let requests = [request(800, 400, 0, false), request(800, 400, 0, false)];
        let assigned = arbitrate(&requests, 0, 1_000);
        assert_eq!(assigned, [500, 500]);
    }

    #[test]
    fn weighted_excess_is_max_min_fair() {
        // B's weighted share (666) covers its whole excess, so B completes
        // and the leftover flows to A (weighted max-min, not a single
        // proportional pass).
        let requests = [request(600, 0, 1, false), request(600, 0, 3, false)];
        let assigned = arbitrate(&requests, 0, 1_000);
        assert_eq!(assigned, [400, 600]);
        // When nobody completes, the split is proportional to the weights.
        let requests = [request(2_000, 0, 0, false), request(2_000, 0, 2, false)];
        let assigned = arbitrate(&requests, 0, 1_000);
        assert_eq!(assigned, [250, 750]);
        assert!(assigned.iter().sum::<u64>() <= 1_000);
    }

    #[test]
    fn exploration_only_gets_what_committed_demand_leaves() {
        let requests = [request(900, 100, 0, false), request(900, 100, 0, true)];
        let assigned = arbitrate(&requests, 0, 1_000);
        // The committed peer takes the whole excess; the explorer keeps its
        // minimum and nothing more.
        assert_eq!(assigned, [900, 100]);
        // With spare capacity the explorer receives its excess.
        let assigned = arbitrate(&requests, 0, 2_000);
        assert_eq!(assigned, [900, 900]);
    }

    #[test]
    fn overcommitted_minima_scale_down_within_budget() {
        let requests = [request(400, 400, 0, false), request(400, 400, 0, false)];
        let assigned = arbitrate(&requests, 0, 500);
        assert_eq!(assigned, [250, 250]);
        assert!(assigned.iter().sum::<u64>() <= 500);
    }

    #[test]
    fn equal_demands_split_fairly() {
        let requests: Vec<EgressRequestV1> = std::iter::repeat_with(|| request(600, 0, 0, false))
            .take(3)
            .collect();
        let assigned = arbitrate(&requests, 0, 900);
        assert_eq!(assigned, [300, 300, 300]);
    }

    #[test]
    fn arbitration_property_sum_within_budget_and_minima_met() {
        let mut rng = Rng(0x243f_6a88_85a3_08d3);
        for _ in 0..4_000 {
            let peer_count = 1 + rng.below(8) as usize;
            let requests: Vec<EgressRequestV1> = (0..peer_count)
                .map(|_| {
                    let minimum = rng.below(200_000);
                    let desired = minimum + rng.below(800_000);
                    request(desired, minimum, rng.below(8) as u8, rng.below(2) == 1)
                })
                .collect();
            let cap = 64 * 1024 * (1 + rng.below(64));
            let reserved = rng.below(cap / 2);
            let available = cap - reserved;
            let assigned = arbitrate(&requests, reserved, cap);
            assert_eq!(assigned.len(), peer_count);
            let total: u64 = assigned.iter().sum();
            assert!(total <= available, "total {total} exceeds {available}");
            let sum_minima: u64 = requests
                .iter()
                .map(|request| request.minimum_rate_bytes_per_second)
                .sum();
            if sum_minima <= available {
                for (request, &rate) in requests.iter().zip(&assigned) {
                    assert!(
                        rate >= request.minimum_rate_bytes_per_second,
                        "minimum {} not met by {rate}",
                        request.minimum_rate_bytes_per_second
                    );
                    assert!(rate <= request.desired_rate_bytes_per_second);
                }
            }
        }
    }

    #[test]
    fn fresh_peer_gets_its_demand_within_cap() {
        let coordinator = NodeEgressCoordinatorV1::new(1_000_000);
        let now = Instant::now();
        coordinator.publish(peer(1), request(800_000, 200_000, 0, false), now);
        let view = coordinator.view(peer(1), now);
        assert_eq!(view.assigned_rate_bytes_per_second, 800_000);
        assert_eq!(view.node_cap_bytes_per_second, 1_000_000);
        assert_eq!(view.node_demand_bytes_per_second, 800_000);
        assert_eq!(view.pressure_per_mille, 800);
        assert_eq!(view.active_peers, 1);
        assert!(view.allocation_generation > 0);
    }

    #[test]
    fn stale_peer_reserves_its_last_assigned_rate() {
        let coordinator = NodeEgressCoordinatorV1::new(1_000_000);
        let now = Instant::now();
        coordinator.publish(peer(1), request(800_000, 200_000, 0, false), now);
        coordinator.publish(peer(2), request(1_000_000, 500_000, 0, false), now);
        // First round: minima 200k+500k, excess 300k split evenly.
        let view = coordinator.view(peer(2), now);
        assert_eq!(view.assigned_rate_bytes_per_second, 650_000);
        // Peer 1 goes silent past the deadline: it reserves its last
        // assigned 350k and peer 2 arbitrates over the remaining 650k alone.
        let later = now + EGRESS_DEMAND_DEADLINE + Duration::from_millis(1);
        coordinator.publish(peer(2), request(1_000_000, 500_000, 0, false), later);
        let view = coordinator.view(peer(2), later);
        assert_eq!(view.assigned_rate_bytes_per_second, 650_000);
        assert_eq!(view.node_demand_bytes_per_second, 350_000 + 1_000_000);
    }

    #[test]
    fn a_silent_or_faulting_peer_never_blocks_the_others() {
        let coordinator = NodeEgressCoordinatorV1::new(1_000_000);
        let now = Instant::now();
        // Peer 2 never publishes (its guest trapped before producing a
        // demand); peer 1 still gets a full arbitration.
        coordinator.publish(peer(1), request(900_000, 100_000, 0, false), now);
        let view = coordinator.view(peer(1), now);
        assert_eq!(view.assigned_rate_bytes_per_second, 900_000);
        // A brand-new peer without history reads the dynamic fair share of
        // the budget, counting itself among the competitors.
        let view = coordinator.view(peer(9), now);
        assert_eq!(view.assigned_rate_bytes_per_second, 500_000);
    }

    #[test]
    fn silent_peers_are_pruned() {
        let coordinator = NodeEgressCoordinatorV1::new(1_000);
        let now = Instant::now();
        coordinator.publish(peer(1), request(100, 100, 0, false), now);
        assert_eq!(coordinator.tracked_peers(), 1);
        let much_later = now + EGRESS_PEER_PRUNE_AFTER + Duration::from_millis(1);
        let view = coordinator.view(peer(1), much_later);
        // Pruned: the peer has no history and reads the fair share again.
        assert_eq!(coordinator.tracked_peers(), 0);
        assert_eq!(view.assigned_rate_bytes_per_second, 1_000);
    }

    #[test]
    fn unconfigured_cap_is_a_passthrough() {
        let coordinator = NodeEgressCoordinatorV1::new(0);
        let now = Instant::now();
        coordinator.publish(peer(1), request(900, 100, 0, false), now);
        let view = coordinator.view(peer(1), now);
        assert_eq!(view.assigned_rate_bytes_per_second, 0);
        assert_eq!(view.node_cap_bytes_per_second, 0);
        assert_eq!(view.pressure_per_mille, 0);
        assert_eq!(view.active_peers, 1);
    }

    #[test]
    fn tiny_assignments_are_floored_to_the_controller_minimum() {
        // A pathologically small cap scales minima below the 64 KiB/s
        // controller floor; the view reports the floor so the effective
        // action matches what the data plane executes.
        let coordinator = NodeEgressCoordinatorV1::new(100_000);
        let now = Instant::now();
        coordinator.publish(peer(1), request(60_000, 60_000, 0, false), now);
        coordinator.publish(peer(2), request(60_000, 60_000, 0, false), now);
        let view = coordinator.view(peer(1), now);
        assert_eq!(
            view.assigned_rate_bytes_per_second,
            EGRESS_ASSIGNMENT_FLOOR_BYTES_PER_SECOND
        );
    }
}

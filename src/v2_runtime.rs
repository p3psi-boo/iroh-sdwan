//! Ironet V2 production runtime.
//!
//! V2 is the only daemon dataplane. It intentionally has no legacy decoder,
//! negotiation fallback, or shared mutable state with the removed protocol.

use std::{
    collections::{HashSet as StdHashSet, VecDeque, hash_map::Entry},
    future::Future,
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    pin::Pin,
    process::Command,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use arc_swap::ArcSwap;
use bytes::Bytes;
use ipnet::IpNet;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey, TransportAddr,
    endpoint::{
        Bbr3Tunables, ConnectOptions, Connection, ControllerSnapshot, LocalTransportAddr, PathId,
        QuicTransportConfig, TlsSessionPartition, presets,
        transports::{AddrKind, FourTuple, PathSelection, PathSelectionContext, PathSelector},
    },
};
use ironet_policy_core::{BANDIT_POLICY_ID_V1, LearnerMemoryV1, LearnerStateV1, STATE_SCHEMA_V1};
use rustc_hash::{FxHashMap as HashMap, FxHasher};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, broadcast, mpsc, oneshot, watch},
    task::JoinSet,
};
use tracing::{debug, info, warn};
use tun_rs::{IDEAL_BATCH_SIZE, VIRTIO_NET_HDR_LEN, VirtioNetHdr, gso_split};

use crate::{
    buffer::PacketSlotPool,
    config::{AutotuneConfig, AutotuneMode, AutotuneObjective, PathMigrationConfig},
    derp::{
        DerpAddr, DerpPublicKey, DerpServer, DerpTransport,
        identity::load_or_create as load_or_create_derp_identity, tls_config as derp_tls_config,
    },
    identity,
    packet::{FlowKey, PacketInfo, icmpv4_echo_probe, inspect_ip_packet, ip_hop_limit_validated},
    protocol::v2::{
        cell::TrafficClass,
        classifier::{ClassifierConfig, FlowClassifier},
        cover::CoverPaddingV2,
        dataplane::{
            ForwardAdmissionV2, MAX_REPAIR_REQUESTS_PER_TICK, RepairRequestBatchV2,
            RepairResponseObservationV2, SendProgress, V2ControlRx, V2Rx, V2Tx,
            completed_record_to_tun,
        },
        fec::{FecGeometryV2, LossRunHistogramV2},
        feedback::FecFeedbackV2,
        gso::{GsoObservationV2, encode_train_record_observed},
        learner::{LearnerModeV2, LearnerTraceV2},
        memory::load as load_autotune_memory,
        policy::{
            api::{BbrEffectiveV1, PolicyBackend, PolicyFaultV1},
            runtime::{PolicyEngine, PolicyLoader, WasmPolicyBackend},
            signature::{TrustStoreV1, encode_digest},
            state::PolicyStateStoreV1,
        },
        policy_tick::{
            PolicySlotKindV1, PolicySlotStatusV1, PolicySlotV1, PolicyTickConfigV1, PolicyTickV1,
            ShadowEvaluationV2, ShadowEvaluatorV2, derive_policy_seed,
            peer_hash as policy_peer_hash,
        },
        presence::{
            PresenceBodyV2, PresenceDirectoryV2, PresenceLinkV2, PresenceUpdateV2,
            SignedPresenceV2, adjacency_id,
        },
        reassembly::ReassemblyOutput,
        repair::{RepairControlV2, RepairRequestV2, RepairResponseV2},
        routing::{
            AdjacencyIdV2, DataplaneSnapshotStoreV2, DataplaneSnapshotV2, LabelActionV2,
            LabelRouteV2, OamControlV2, OamPathMtuExceededV2, ResolvedRouteV2,
            RouteAdvertisementV2, RouteLabelV2, TransitDispositionV2,
        },
        scheduler::SchedulerLimits,
        session::{
            ConnectionRole, NegotiatedSessionV2, SessionPolicyV2, WireLimitsV2, capability,
            negotiate_connection_v2,
        },
        train::TrainRecord,
        tuning::{
            AutoTuneBoundsV2, AutoTunerV2, Bbr3PresetV2, Bbr3ProposalV2, CoverTrafficProfileV2,
            ForcedActionV2, PathReliability, PathTelemetryV2, RepairWaitPolicyV2, TuneDecisionV2,
        },
        utility::{Objective, UtilitySample, WireCostV2},
    },
    trace::{OverlayTraceOamEvent, TraceProbeTag, v2_trace_probe_tag},
    tunnel::OverlayTunnel,
};

const ALPN: &[u8] = b"h3";
const COVER_PROFILE_NAME: &str = "LiveMedia";
const QUIC_WIRE_VERSION: u32 = 1;
const RAW_TUN_BYTES: usize = VIRTIO_NET_HDR_LEN + u16::MAX as usize;
const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
const TUN_INPUT_SLOTS: usize = 64;
const TUN_PRIORITY_INPUT_SLOTS: usize = 128;
const TUN_REGULAR_INPUT_BYTES: usize = 512 * 1024;
// Linux gives fq_codel on a TUN a 32 MiB memory limit by default. Once the
// userspace reader applies backpressure that can retain seconds of stale
// inner-TCP data and strand FIN/control payloads behind it. Keep the kernel
// queue close to the userspace window; fq_codel still owns per-flow fairness,
// ECN marking and overload drops.
const TUN_FQ_CODEL_MEMORY_BYTES: usize = TUN_REGULAR_INPUT_BYTES * 2;
const TUN_FQ_CODEL_PACKET_LIMIT: usize = 1024;
const TX_BULK_ADMISSION_HIGH_WATER_BYTES: usize = 512 * 1024;
const TX_LATENCY_ADMISSION_HIGH_WATER_BYTES: usize = 128 * 1024;
// Keep ordinary admission shallow enough that an inner TCP sender observes
// the real path rather than an 8 MiB userspace queue. The hard scheduler
// limits remain larger for control/repair safety; this is the normal producer
// watermark, with a separately driven strict-priority path.
const TX_APPLICATION_ADMISSION_HIGH_WATER_BYTES: usize = 512 * 1024;
const TX_ADMISSION_BATCH_BYTES: usize = 128 * 1024;
const ADAPTIVE_CWND_FLOOR_QUANTUM_BYTES: u64 = 16 * 1024;
const ADAPTIVE_CWND_FLOOR_MAX_BYTES: u64 = 8 * 1024 * 1024;
// Sub-millisecond direct paths are CPU/ACK-scheduling limited rather than
// bandwidth-delay limited. Keep one automatically tuned send-buffer turn in
// flight so a delayed runtime wakeup cannot drain QUIC to zero.
// Four times the BDP of a 1 Gbit/s, 1 ms path and enough for 1 Gbit/s at
// roughly 4 ms, without the ~50 ms queue that a fixed 2 MiB floor created on
// a 300 Mbit/s Wi-Fi path.
const LOW_RTT_CWND_FLOOR_BYTES: u64 = 512 * 1024;
const MAX_CLASSIFIERS: usize = 65_536;
const CLASSIFIER_IDLE: Duration = Duration::from_secs(60);
const LATENCY_SOJOURN_UPPER_MICROS: [u64; 12] = [
    50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 25_000, 50_000, 100_000, 1_000_000,
];
const LATENCY_SOJOURN_BUCKETS: usize = LATENCY_SOJOURN_UPPER_MICROS.len() + 1;
const BULK_FAIRNESS_BUCKETS: usize = 32;
const TRACE_TRAIN_REGISTRATION_TTL: Duration = Duration::from_secs(120);
const MAX_TRACE_TRAIN_REGISTRATIONS: usize = 4_096;
const V2_NAT_INGRESS_CHAINS: [&str; 2] = ["IRONET_V2_NAT_IN_A", "IRONET_V2_NAT_IN_B"];
const V2_NAT_EGRESS_CHAINS: [&str; 2] = ["IRONET_V2_NAT_OUT_A", "IRONET_V2_NAT_OUT_B"];
const LEGACY_V2_NAT_INGRESS_CHAIN: &str = "IRONET_V2_NAT_IN";
const LEGACY_V2_NAT_EGRESS_CHAIN: &str = "IRONET_V2_NAT_OUT";
const V2_NAT_CONNMARK: &str = "0x20000000/0x20000000";
const LIVE_MEDIA_QUIC_MINIMUM_MTU: u16 = 1_200;
const LIVE_MEDIA_QUIC_INITIAL_MTU: u16 = 1_200;
const LIVE_MEDIA_QUIC_BIDI_STREAMS: u32 = 100;
const LIVE_MEDIA_QUIC_UNI_STREAMS: u32 = 16;
const LIVE_MEDIA_QUIC_STREAM_RECEIVE_WINDOW: u32 = 1024 * 1024;
const LIVE_MEDIA_QUIC_RECEIVE_WINDOW: u32 = 16 * 1024 * 1024;
const LIVE_MEDIA_QUIC_SEND_WINDOW: u64 = 16 * 1024 * 1024;
const LIVE_MEDIA_QUIC_DATAGRAM_BUFFER: usize = 32 * 1024 * 1024;
const MAX_PATH_MTU_CONSTRAINTS: usize = 4_096;
const COVER_DNS_SELECTION_TIMEOUT: Duration = Duration::from_millis(250);
// Private route-protocol marker used only for V2 dataplane-owned kernel
// routes.  This mirrors `system.rs`; keeping the marker on every route makes
// crash recovery surgical instead of flushing an operator-owned table.
const V2_ROUTE_PROTOCOL: &str = "100";

/// A raw TUN record plus its byte-budget ownership. Slot-bounded channels are
/// insufficient here because one slot may hold either a 60-byte ACK or a
/// 65-KiB GSO record. The permit remains attached until the dispatcher
/// actually consumes the record, making the admission edge byte-bounded
/// without a mutex or a second queue-length state machine.
struct TunIngressRecordV2 {
    bytes: Bytes,
    info: PacketInfo,
    _permit: Option<OwnedSemaphorePermit>,
}

impl TunIngressRecordV2 {
    fn priority(bytes: Bytes, info: PacketInfo) -> Self {
        Self {
            bytes,
            info,
            _permit: None,
        }
    }

    fn regular(bytes: Bytes, info: PacketInfo, permit: OwnedSemaphorePermit) -> Self {
        Self {
            bytes,
            info,
            _permit: Some(permit),
        }
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }
}

#[derive(Debug, Clone)]
pub struct V2PeerConfig {
    pub endpoint_id: EndpointId,
    pub addresses: Vec<SocketAddr>,
    pub derp_public_key: Option<DerpPublicKey>,
}

/// Iroh's ordinary path policy, with one additional hard gate: neither the
/// local nor remote IP of a direct path may fall inside an operator-excluded
/// prefix. Applying the gate here also covers NAT candidates learned after
/// startup, including addresses of overlay/Yggdrasil interfaces that did not
/// exist when the static peer locator was validated.
#[derive(Debug, Clone)]
struct UnderlayPathSelector {
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
    fn new(excluded: Vec<IpNet>, tuning: PathMigrationConfig) -> Self {
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

#[derive(Debug, Clone)]
pub struct V2RuntimeConfig {
    pub identity_file: PathBuf,
    pub bind: SocketAddr,
    /// IP prefixes that neither side of an automatically discovered direct
    /// underlay path may use. This is enforced by the live path selector, not
    /// only when configured locators are parsed.
    pub excluded_underlay_prefixes: Vec<IpNet>,
    /// A peer with addresses is dialed. A peer without addresses is an
    /// allowlisted listener. `None` accepts the first authenticated peer.
    pub peer_id: Option<EndpointId>,
    /// Standalone lab mode may accept one authenticated but otherwise
    /// unconfigured peer. Product configurations always set this to false so
    /// an empty or fully revoked membership set remains fail-closed.
    pub accept_first_peer: bool,
    pub peer_addresses: Vec<SocketAddr>,
    pub peer_derp_public_key: Option<DerpPublicKey>,
    /// Static authenticated adjacencies for the V2 mesh runtime. Repeating an
    /// EndpointId merges its locators. Dial ownership is derived from the two
    /// EndpointIds so only one side initiates each direct QUIC adjacency.
    pub mesh_peers: Vec<V2PeerConfig>,
    pub derp_servers: Vec<DerpServer>,
    pub derp_identity_file: Option<PathBuf>,
    pub network_id: String,
    /// Network-level LiveMedia SNI pool. The dialer chooses one stable entry
    /// per peer and cover-profile generation; pool order is irrelevant.
    pub cover_sni_pool: Vec<String>,
    pub cover_profile_id: u32,
    pub tun_name: String,
    pub tun_mtu: u16,
    /// Keep every overlay destination in a dedicated policy-routing table.
    /// Disabling this deliberately installs only protocol-tagged routes in
    /// `main`; it is never inferred from the route inventory.
    pub isolate_overlay: bool,
    pub routing_table: u32,
    pub routing_rule_priority: u32,
    /// Stable local overlay host addresses. Product configurations provide
    /// these explicitly; the standalone lab harness derives them.
    pub node_addresses: Vec<IpNet>,
    pub routes: Vec<IpNet>,
    pub advertised_routes: Vec<IpNet>,
    pub allow_default_routes: bool,
    pub subnet_nat: bool,
    pub transit_enabled: bool,
    pub route_label: u32,
    pub autotune: AutotuneConfig,
    pub path_migration: PathMigrationConfig,
    pub max_egress_bytes_per_second: Option<u64>,
}

#[derive(Debug, Clone)]
struct KernelRoutePolicyV2 {
    tun_name: String,
    isolate_overlay: bool,
    table: u32,
    rule_priority: u32,
    underlay_addresses: Vec<IpAddr>,
    ipv4_source: Option<Ipv4Addr>,
    ipv6_source: Option<Ipv6Addr>,
}

impl KernelRoutePolicyV2 {
    fn from_config(config: &V2RuntimeConfig, local_v4: Ipv4Addr, local_v6: Ipv6Addr) -> Self {
        let mut underlay_addresses = config
            .peer_addresses
            .iter()
            .chain(
                config
                    .mesh_peers
                    .iter()
                    .flat_map(|peer| peer.addresses.iter()),
            )
            .map(|address| address.ip())
            .filter(|address| !address.is_unspecified())
            .collect::<Vec<_>>();
        underlay_addresses.sort_unstable();
        underlay_addresses.dedup();
        Self {
            tun_name: config.tun_name.clone(),
            isolate_overlay: config.isolate_overlay,
            table: if config.isolate_overlay {
                config.routing_table
            } else {
                254
            },
            rule_priority: config.routing_rule_priority,
            underlay_addresses,
            ipv4_source: Some(local_v4),
            ipv6_source: Some(local_v6),
        }
    }

    fn install_policy(&self) -> Result<()> {
        if !self.isolate_overlay {
            return Ok(());
        }
        let priority = self.rule_priority.to_string();
        let table = self.table.to_string();
        for family in ["-4", "-6"] {
            remove_ip_rule(family, self.rule_priority, self.table, None)?;
            run_ip([
                family, "rule", "add", "priority", &priority, "lookup", &table, "protocol",
                "static",
            ])?;
        }
        let underlay_priority = self.rule_priority.saturating_sub(1);
        let underlay_priority_text = underlay_priority.to_string();
        for address in &self.underlay_addresses {
            let family = if address.is_ipv4() { "-4" } else { "-6" };
            let prefix = host_prefix_v2(*address);
            remove_ip_rule(family, underlay_priority, 254, Some(&prefix))?;
            run_ip([
                family,
                "rule",
                "add",
                "priority",
                &underlay_priority_text,
                "to",
                &prefix,
                "lookup",
                "main",
                "protocol",
                "static",
            ])?;
        }
        Ok(())
    }

    fn replace_route(&self, prefix: IpNet) -> Result<()> {
        let family = if prefix.addr().is_ipv4() { "-4" } else { "-6" };
        let table = self.table.to_string();
        let prefix = prefix.to_string();
        let source = if family == "-4" {
            self.ipv4_source.map(|address| address.to_string())
        } else {
            self.ipv6_source.map(|address| address.to_string())
        };
        let mut arguments = vec![
            family.to_owned(),
            "route".to_owned(),
            "replace".to_owned(),
            "table".to_owned(),
            table,
            prefix,
            "dev".to_owned(),
            self.tun_name.clone(),
            "proto".to_owned(),
            V2_ROUTE_PROTOCOL.to_owned(),
        ];
        if let Some(source) = source {
            arguments.extend(["src".to_owned(), source]);
        }
        run_ip_vec(&arguments)
    }

    fn delete_route(&self, prefix: IpNet) -> Result<()> {
        let family = if prefix.addr().is_ipv4() { "-4" } else { "-6" };
        let table = self.table.to_string();
        let prefix = prefix.to_string();
        run_ip_allow_failure([
            family,
            "route",
            "del",
            "table",
            &table,
            &prefix,
            "proto",
            V2_ROUTE_PROTOCOL,
        ])
    }

    fn cleanup(&self) -> Result<()> {
        let table = self.table.to_string();
        for family in ["-4", "-6"] {
            run_ip_allow_failure([
                family,
                "route",
                "flush",
                "table",
                &table,
                "proto",
                V2_ROUTE_PROTOCOL,
            ])?;
        }
        if self.isolate_overlay {
            for family in ["-4", "-6"] {
                remove_ip_rule(family, self.rule_priority, self.table, None)?;
            }
            let underlay_priority = self.rule_priority.saturating_sub(1);
            for address in &self.underlay_addresses {
                let family = if address.is_ipv4() { "-4" } else { "-6" };
                let prefix = host_prefix_v2(*address);
                remove_ip_rule(family, underlay_priority, 254, Some(&prefix))?;
            }
        }
        Ok(())
    }
}

/// Synchronous cleanup is intentional: `Drop` also runs on setup errors and
/// aborted Tokio tasks, so no async lifecycle gap can leave a policy rule
/// pointing at a stale overlay table.
struct KernelRouteGuardV2(KernelRoutePolicyV2);

impl Drop for KernelRouteGuardV2 {
    fn drop(&mut self) {
        if let Err(error) = self.0.cleanup() {
            warn!(%error, "failed cleaning V2 kernel route policy");
        }
    }
}

/// Control-plane view owned by the V2 runtime. It deliberately exposes V2
/// protocol identity and connection health without translating through the
/// legacy runtime's counter graph.
#[derive(Debug, Clone, Copy)]
struct PendingTraceTrainV2 {
    request_id: u64,
    target: IpAddr,
    registered_at: Instant,
}

#[derive(Debug, Clone)]
struct TuneStatusSampleV2<'a> {
    decision: TuneDecisionV2,
    utility: UtilitySample,
    learner: LearnerTraceV2,
    policy_id: &'a str,
    policy_source: &'a str,
    shadow_policy_id: Option<&'a str>,
    shadow: Option<ShadowEvaluationV2>,
    live: PolicySlotStatusV1,
    shadow_slot: Option<PolicySlotStatusV1>,
    egress_requested_bytes_per_second: u64,
    egress_assigned_bytes_per_second: u64,
}

#[derive(Debug)]
pub struct V2RuntimeState {
    endpoint_id: EndpointId,
    started_unix: u64,
    started_at: Instant,
    interface: String,
    tun_mtu: u16,
    peers: RwLock<HashMap<EndpointId, crate::status::PeerStatus>>,
    connections: RwLock<HashMap<EndpointId, Connection>>,
    metrics: RwLock<HashMap<EndpointId, Arc<RuntimeMetrics>>>,
    tun_ingress_metrics: Arc<RuntimeMetrics>,
    mesh: RwLock<crate::status::MeshStatus>,
    gateway: crate::status::GatewayStatus,
    routes: RwLock<Vec<crate::status::RouteStatus>>,
    routes_ready: AtomicBool,
    cpu_utilization_per_mille: AtomicU64,
    autotune_state_dir: PathBuf,
    autotune: AutotuneConfig,
    policy_loader: std::sync::OnceLock<Option<PolicyLoader>>,
    max_egress_bytes_per_second: Option<u64>,
    /// Node egress coordinator (plan section 9); pass-through when no
    /// `routing.max_egress_mbps` is configured.
    egress_coordinator: crate::protocol::v2::policy::egress::NodeEgressCoordinatorV1,
    trace_trains: Mutex<HashMap<(u32, u32, u64), PendingTraceTrainV2>>,
    trace_events: broadcast::Sender<OverlayTraceOamEvent>,
}

impl V2RuntimeState {
    pub(crate) fn new(config: &V2RuntimeConfig, endpoint_id: EndpointId) -> Self {
        let (trace_events, _) = broadcast::channel(256);
        let mut peers = HashMap::default();
        for peer in config
            .mesh_peers
            .iter()
            .map(|peer| peer.endpoint_id)
            .chain(config.peer_id)
        {
            peers.insert(
                peer,
                Self::peer_status(&config.tun_name, config.tun_mtu, peer),
            );
        }
        Self {
            endpoint_id,
            started_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            started_at: Instant::now(),
            interface: config.tun_name.clone(),
            tun_mtu: config.tun_mtu,
            peers: RwLock::new(peers),
            connections: RwLock::new(HashMap::default()),
            metrics: RwLock::new(HashMap::default()),
            tun_ingress_metrics: Arc::new(RuntimeMetrics::default()),
            mesh: RwLock::new(crate::status::MeshStatus::default()),
            gateway: crate::status::GatewayStatus {
                transit_enabled: config.transit_enabled,
                subnet_nat_enabled: config.subnet_nat,
                advertised_prefixes: config.advertised_routes.clone(),
            },
            routes: RwLock::new(
                config
                    .routes
                    .iter()
                    .map(|prefix| crate::status::RouteStatus {
                        prefix: prefix.to_string(),
                        present: false,
                    })
                    .collect(),
            ),
            routes_ready: AtomicBool::new(false),
            cpu_utilization_per_mille: AtomicU64::new(0),
            autotune_state_dir: crate::protocol::v2::memory::state_dir(&config.identity_file),
            autotune: config.autotune.clone(),
            policy_loader: std::sync::OnceLock::new(),
            max_egress_bytes_per_second: config.max_egress_bytes_per_second,
            egress_coordinator: crate::protocol::v2::policy::egress::NodeEgressCoordinatorV1::new(
                config.max_egress_bytes_per_second.unwrap_or(0),
            ),
            trace_trains: Mutex::new(HashMap::default()),
            trace_events,
        }
    }

    pub(crate) fn subscribe_trace_events(&self) -> broadcast::Receiver<OverlayTraceOamEvent> {
        self.trace_events.subscribe()
    }

    /// Shared WASM policy loader (engine built lazily on first `.wasm` use,
    /// so deployments without WASM policies never pay for it). `None` means
    /// engine construction failed; callers fall back to the builtin policy.
    fn policy_loader(&self) -> Option<&PolicyLoader> {
        self.policy_loader
            .get_or_init(|| match PolicyEngine::try_new() {
                Ok(engine) => Some(PolicyLoader::new(engine)),
                Err(error) => {
                    warn!(
                        %error,
                        "policy WASM engine unavailable; .wasm policies fall back to builtin"
                    );
                    None
                }
            })
            .as_ref()
    }

    fn register_trace_train(&self, route: ResolvedRouteV2, train_id: u64, tag: TraceProbeTag) {
        let now = Instant::now();
        let mut pending = self
            .trace_trains
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        pending.retain(|_, value| {
            now.saturating_duration_since(value.registered_at) < TRACE_TRAIN_REGISTRATION_TTL
        });
        if pending.len() >= MAX_TRACE_TRAIN_REGISTRATIONS
            && let Some(oldest) = pending
                .iter()
                .min_by_key(|(_, value)| value.registered_at)
                .map(|(key, _)| *key)
        {
            pending.remove(&oldest);
        }
        pending.insert(
            (route.route_epoch, route.route_label.0, train_id),
            PendingTraceTrainV2 {
                request_id: tag.request_id,
                target: tag.target,
                registered_at: now,
            },
        );
    }

    fn publish_ttl_expired(&self, oam: &crate::protocol::v2::routing::OamTtlExpiredV2) {
        let mut trace_trains = self
            .trace_trains
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let pending = trace_trains.remove(&(oam.route_epoch, oam.route_label.0, oam.train_id));
        let Some(pending) = pending else {
            return;
        };
        trace_trains.retain(|_, value| value.request_id != pending.request_id);
        drop(trace_trains);
        if pending.registered_at.elapsed() >= TRACE_TRAIN_REGISTRATION_TTL {
            return;
        }
        let Ok(reporter_id) = EndpointId::from_bytes(&oam.reporter) else {
            return;
        };
        let mesh = self
            .mesh
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(node) = mesh
            .nodes
            .iter()
            .find(|node| node.endpoint_id == reporter_id.to_string())
        else {
            return;
        };
        let Some(reporter_address) = node
            .node_addresses
            .iter()
            .map(IpNet::addr)
            .find(|address| address.is_ipv4() == pending.target.is_ipv4())
        else {
            return;
        };
        let mut metadata = std::collections::BTreeMap::new();
        metadata.insert("endpoint_id".to_owned(), reporter_id.to_string());
        metadata.insert("overlay_hops".to_owned(), oam.traversed_hops.to_string());
        let _ = self.trace_events.send(OverlayTraceOamEvent {
            request_id: pending.request_id,
            reporter_address,
            reporter: crate::config::NodeInfo {
                name: reporter_id.to_string(),
                description: Some("V2 overlay transit node".to_owned()),
                metadata,
            },
        });
    }

    fn publish_routes(&self, prefixes: impl IntoIterator<Item = IpNet>) {
        let mut prefixes = prefixes.into_iter().collect::<Vec<_>>();
        prefixes
            .sort_by_key(|prefix| (prefix.addr().is_ipv6(), prefix.addr(), prefix.prefix_len()));
        prefixes.dedup();
        *self
            .routes
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = prefixes
            .into_iter()
            .map(|prefix| crate::status::RouteStatus {
                prefix: prefix.to_string(),
                present: true,
            })
            .collect();
        self.routes_ready.store(true, Ordering::Release);
    }

    fn peer_status(
        interface: &str,
        tun_mtu: u16,
        endpoint_id: EndpointId,
    ) -> crate::status::PeerStatus {
        crate::status::PeerStatus {
            name: endpoint_id.to_string(),
            endpoint_id: endpoint_id.to_string(),
            interface: interface.to_owned(),
            protocol_major: u64::from(crate::protocol::v2::MAJOR),
            tun_mtu: u64::from(tun_mtu),
            ..crate::status::PeerStatus::default()
        }
    }

    fn mark_connected(&self, connection: &Connection) {
        let remote_id = connection.remote_id();
        let mut peers = self
            .peers
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let peer = peers
            .entry(remote_id)
            .or_insert_with(|| Self::peer_status(&self.interface, self.tun_mtu, remote_id));
        peer.connected = true;
        peer.connection_events = peer.connection_events.saturating_add(1);
        self.connections
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(remote_id, connection.clone());
        Self::refresh_path(peer, connection);
    }

    fn attach_metrics(&self, remote_id: EndpointId, metrics: Arc<RuntimeMetrics>) {
        self.metrics
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(remote_id, metrics);
    }

    fn publish_tune_status(&self, remote_id: EndpointId, sample: TuneStatusSampleV2<'_>) {
        let TuneStatusSampleV2 {
            decision,
            utility,
            learner,
            policy_id,
            policy_source,
            shadow_policy_id,
            shadow,
            live,
            shadow_slot,
            egress_requested_bytes_per_second,
            egress_assigned_bytes_per_second,
        } = sample;
        let mut peers = self
            .peers
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let peer = peers
            .entry(remote_id)
            .or_insert_with(|| Self::peer_status(&self.interface, self.tun_mtu, remote_id));
        peer.tune_reason = format!("{:?}", decision.reason);
        peer.fec_geometry = decision.fec.map_or_else(
            || "off".to_owned(),
            |geometry| format!("{}+{}", geometry.data_cells, geometry.parity_cells),
        );
        peer.train_target_bytes = decision.train_target_bytes as u64;
        peer.bbr_preset = format!("{:?}", decision.bbr.preset);
        peer.utility_total = utility.total;
        peer.learner_mode = format!("{:?}", learner.mode);
        peer.learner_context = format!(
            "r{}-b{}-l{}-{}",
            learner.context.rtt_class,
            learner.context.rate_class,
            learner.context.loss_class,
            if learner.context.reliable {
                "reliable"
            } else {
                "datagram"
            }
        );
        peer.learner_rollbacks = learner.rollbacks;
        peer.policy_id = policy_id.to_owned();
        peer.policy_source = policy_source.to_owned();
        peer.shadow_policy_id = shadow_policy_id.unwrap_or_default().to_owned();
        peer.shadow_preset = shadow.map_or_else(String::new, |candidate| {
            format!("{:?}", candidate.trace.proposed_preset)
        });
        peer.shadow_advantage = shadow.map_or(0.0, |candidate| candidate.trace.predicted_advantage);
        peer.policy_backend = live.backend;
        peer.policy_version = live.policy_version;
        peer.abi_version = live.abi_version;
        peer.policy_module_digest = live.module_digest;
        peer.policy_signer_id = live.signer_id;
        peer.policy_module_generation = live.module_generation;
        peer.policy_health = live.health;
        peer.state_schema = u64::from(live.state_schema);
        peer.state_bytes = live.state_bytes;
        peer.last_call_micros = live.last_call_micros;
        peer.policy_fuel_consumed = live.fuel_consumed;
        peer.faults_total = live.faults_total;
        peer.policy_timeouts_total = live.timeouts_total;
        peer.policy_quarantines_total = live.quarantines_total;
        peer.clamped_fields_total = live.clamped_fields_total;
        peer.last_clamp_reasons = live.last_clamp_reasons;
        peer.egress_requested_bytes_per_second = egress_requested_bytes_per_second;
        peer.egress_assigned_bytes_per_second = egress_assigned_bytes_per_second;
        let shadow_slot = shadow_slot.unwrap_or_default();
        peer.shadow_policy_backend = shadow_slot.backend;
        peer.shadow_policy_version = shadow_slot.policy_version;
        peer.shadow_module_digest = shadow_slot.module_digest;
        peer.shadow_signer_id = shadow_slot.signer_id;
        peer.shadow_module_generation = shadow_slot.module_generation;
        peer.shadow_policy_health = shadow_slot.health;
        peer.shadow_state_schema = u64::from(shadow_slot.state_schema);
        peer.shadow_state_bytes = shadow_slot.state_bytes;
        peer.shadow_last_call_micros = shadow_slot.last_call_micros;
        peer.shadow_fuel_consumed = shadow_slot.fuel_consumed;
        peer.shadow_faults_total = shadow_slot.faults_total;
        peer.shadow_timeouts_total = shadow_slot.timeouts_total;
        peer.shadow_quarantines_total = shadow_slot.quarantines_total;
        peer.shadow_clamped_fields_total = shadow_slot.clamped_fields_total;
        peer.shadow_last_clamp_reasons = shadow_slot.last_clamp_reasons;
    }

    fn publish_presence_directory(&self, directory: &PresenceDirectoryV2, max_total_peers: usize) {
        let mut nodes = directory
            .records()
            .map(|presence| crate::status::MeshNodeStatus {
                endpoint_id: presence.body.owner.to_string(),
                sequence: presence.body.sequence,
                expires_unix_secs: presence.body.expires_unix_secs,
                direct_addresses: presence.body.direct_addresses.clone(),
                node_addresses: presence.body.node_addresses.clone(),
                prefixes: presence.body.prefixes.clone(),
                transit_enabled: presence.body.transit_enabled,
            })
            .collect::<Vec<_>>();
        nodes.sort_by(|left, right| left.endpoint_id.cmp(&right.endpoint_id));
        *self
            .mesh
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = crate::status::MeshStatus {
            enabled: true,
            directory_entries: nodes.len(),
            max_total_peers,
            nodes,
        };
    }

    fn refresh_path(peer: &mut crate::status::PeerStatus, connection: &Connection) {
        let paths = connection.paths();
        peer.open_paths = paths.len() as u64;
        if let Some(path) = paths.iter().find(|path| path.is_selected()) {
            let stats = path.stats();
            peer.path_rtt_micros = stats.rtt.as_micros().min(u128::from(u64::MAX)) as u64;
            peer.path_cwnd_bytes = stats.cwnd;
            peer.path_mtu = u64::from(stats.current_mtu);
            peer.selected_path_remote = path_endpoint_identity(path.remote_addr());
            peer.selected_path_transport = if path.is_relay() {
                "relay".to_owned()
            } else {
                "direct".to_owned()
            };
        }
    }

    fn refresh_metrics(peer: &mut crate::status::PeerStatus, metrics: &RuntimeMetrics) {
        peer.tx_packets = metrics.tun_ingress_records.load(Ordering::Relaxed);
        peer.tx_bytes = metrics.tun_ingress_bytes.load(Ordering::Relaxed);
        peer.rx_packets = metrics.tun_rx_packets.load(Ordering::Relaxed);
        peer.rx_bytes = metrics.tun_rx_bytes.load(Ordering::Relaxed);
        peer.trains_built = metrics.trains_built.load(Ordering::Relaxed);
        peer.cells_built = metrics.cells_built.load(Ordering::Relaxed);
        peer.data_cell_tx_datagrams = metrics.data_cell_tx_datagrams.load(Ordering::Relaxed);
        peer.full_payload_cells_built = metrics.full_payload_cells_built.load(Ordering::Relaxed);
        peer.data_cell_tx_bytes = metrics.data_cell_tx_bytes.load(Ordering::Relaxed);
        peer.cell_payload_tx_bytes = metrics.data_cell_payload_tx_bytes.load(Ordering::Relaxed);
        peer.unused_cell_capacity_bytes =
            metrics.unused_cell_capacity_bytes.load(Ordering::Relaxed);
        peer.split_records_built = metrics.split_records_built.load(Ordering::Relaxed);
        peer.fec_tx_cells = metrics.fec_parity_cells_built.load(Ordering::Relaxed);
        peer.fec_tx_bytes = metrics.fec_tx_bytes.load(Ordering::Relaxed);
        peer.fec_rx_cells = metrics.fec_parity_rx.load(Ordering::Relaxed);
        peer.fec_recovered_cells = metrics.fec_recovered_cells.load(Ordering::Relaxed);
        peer.fec_wasted_cells = metrics.fec_wasted_parity.load(Ordering::Relaxed);
        peer.fec_expired_stripes = metrics.fec_expired_stripes.load(Ordering::Relaxed);
        peer.fec_unprotected_tail_cells =
            metrics.fec_unprotected_tail_cells.load(Ordering::Relaxed);
        peer.fec_encode_copy_bytes = metrics.fec_encode_copy_bytes.load(Ordering::Relaxed);
        peer.fec_decode_copy_bytes = metrics.fec_decode_copy_bytes.load(Ordering::Relaxed);
        peer.repair_requested_cells = metrics.repair_requested_cells.load(Ordering::Relaxed);
        peer.repair_suppressed_stripes = metrics.repair_suppressed_stripes.load(Ordering::Relaxed);
        peer.repair_suppressed_cells = metrics.repair_suppressed_cells.load(Ordering::Relaxed);
        peer.repair_received_cells = metrics.repair_received_cells.load(Ordering::Relaxed);
        peer.repair_completed_requests = metrics.repair_completed_requests.load(Ordering::Relaxed);
        peer.repair_latency_max_micros = metrics.repair_latency_max_micros.load(Ordering::Relaxed);
        peer.repair_stale_responses = metrics.repair_stale_responses.load(Ordering::Relaxed);
        peer.bulk_service_bytes = metrics.bulk_service_bytes.load(Ordering::Relaxed);
        peer.latency_service_bytes = metrics.latency_service_bytes.load(Ordering::Relaxed);
        peer.bulk_preemptions = metrics.bulk_preemptions.load(Ordering::Relaxed);
        peer.packet_train_queue_bytes = metrics.train_queue_bytes.load(Ordering::Relaxed);
        peer.latency_queue_bytes = metrics.latency_queue_bytes.load(Ordering::Relaxed);
        peer.receive_buffer_bytes = metrics.receive_buffer_bytes.load(Ordering::Relaxed);
        peer.cover_tx_bytes = metrics.cover_tx_bytes.load(Ordering::Relaxed);
        peer.cover_rx_bytes = metrics.cover_rx_bytes.load(Ordering::Relaxed);
        peer.control_tx_bytes = metrics.control_record_tx_bytes.load(Ordering::Relaxed);
        peer.control_rx_bytes = metrics.control_record_rx_bytes.load(Ordering::Relaxed);
        peer.protocol_datagram_errors = metrics.protocol_datagram_errors.load(Ordering::Relaxed);
        peer.route_gate_drops = metrics.route_gate_drops.load(Ordering::Relaxed);
        peer.tun_admission_drop_records =
            metrics.tun_admission_drop_records.load(Ordering::Relaxed);
        peer.tun_admission_drop_bytes = metrics.tun_admission_drop_bytes.load(Ordering::Relaxed);
        peer.reassembly_pressure_evictions = metrics
            .reassembly_pressure_evictions
            .load(Ordering::Relaxed);
        peer.pmtu_drop_datagrams = metrics.pmtu_drop_datagrams.load(Ordering::Relaxed);
        peer.pmtu_drop_bytes = metrics.pmtu_drop_bytes.load(Ordering::Relaxed);
        peer.gso_input_bytes = metrics.gso_input_bytes.load(Ordering::Relaxed);
        peer.gso_preserved_bytes = metrics.gso_preserved_bytes.load(Ordering::Relaxed);
        peer.gso_fallback_splits = metrics.gso_fallback_splits.load(Ordering::Relaxed);
    }

    pub async fn live_snapshot(&self) -> Result<crate::status::RuntimeStatus> {
        let mut peers = self
            .peers
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let connections = self
            .connections
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let metrics = self
            .metrics
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for peer in &mut peers {
            let Ok(endpoint_id) = peer.endpoint_id.parse::<EndpointId>() else {
                continue;
            };
            if let Some(connection) = connections.get(&endpoint_id) {
                Self::refresh_path(peer, connection);
            }
            if let Some(peer_metrics) = metrics.get(&endpoint_id) {
                Self::refresh_metrics(peer, peer_metrics);
            }
        }
        peers.sort_by(|left, right| left.endpoint_id.cmp(&right.endpoint_id));
        let routes_ready = self.routes_ready.load(Ordering::Acquire);
        let ready = !peers.is_empty() && peers.iter().all(|peer| peer.connected) && routes_ready;
        let updated_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Ok(crate::status::RuntimeStatus {
            ready,
            endpoint_id: self.endpoint_id.to_string(),
            started_unix: self.started_unix,
            updated_unix,
            uptime_seconds: self.started_at.elapsed().as_secs(),
            routes_ready,
            routes: self
                .routes
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
            peers,
            mesh: self
                .mesh
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
            gateway: self.gateway.clone(),
            tun_admission_drop_records: self
                .tun_ingress_metrics
                .tun_admission_drop_records
                .load(Ordering::Relaxed),
            tun_admission_drop_bytes: self
                .tun_ingress_metrics
                .tun_admission_drop_bytes
                .load(Ordering::Relaxed),
            ..crate::status::RuntimeStatus::default()
        })
    }
}

impl V2RuntimeConfig {
    fn underlay_path_exclusions(&self) -> Vec<IpNet> {
        let mut prefixes = self.excluded_underlay_prefixes.clone();
        prefixes.extend(self.node_addresses.iter().copied());
        prefixes.extend(self.routes.iter().copied());
        prefixes.extend(self.advertised_routes.iter().copied());
        prefixes
            .sort_by_key(|prefix| (prefix.addr().is_ipv6(), prefix.addr(), prefix.prefix_len()));
        prefixes.dedup();
        prefixes
    }

    fn validate(&self) -> Result<()> {
        self.path_migration.validate()?;
        ensure!(!self.network_id.is_empty(), "V2 network ID is empty");
        ensure!(self.network_id.len() <= 128, "V2 network ID is too long");
        ensure!(
            self.cover_profile_id != 0,
            "V2 cover profile generation zero is reserved"
        );
        ensure!(
            !self.cover_sni_pool.is_empty(),
            "V2 cover SNI pool is empty"
        );
        for name in &self.cover_sni_pool {
            validate_cover_sni(name)?;
        }
        let mut cover_names = self.cover_sni_pool.iter().collect::<Vec<_>>();
        cover_names.sort_unstable();
        let count = cover_names.len();
        cover_names.dedup();
        ensure!(cover_names.len() == count, "duplicate V2 cover SNI");
        ensure!(!self.tun_name.is_empty(), "V2 TUN name is empty");
        ensure!(
            (2..32_766).contains(&self.routing_rule_priority),
            "V2 routing rule priority must be between 2 and 32765"
        );
        ensure!(
            !matches!(self.routing_table, 0 | 253 | 254 | 255),
            "V2 routing table must be a non-reserved Linux routing table"
        );
        let mut families = StdHashSet::new();
        for address in &self.node_addresses {
            ensure!(
                address.prefix_len() == if address.addr().is_ipv4() { 32 } else { 128 },
                "V2 node address {address} must be a host prefix"
            );
            ensure!(
                families.insert(address.addr().is_ipv6()),
                "V2 accepts at most one node address per family"
            );
        }
        ensure!(self.route_label != 0, "V2 route label zero is reserved");
        RouteAdvertisementV2 {
            generation: 1,
            prefixes: self.advertised_routes.clone(),
        }
        .validate(self.allow_default_routes)?;
        ensure!(
            self.allow_default_routes || self.routes.iter().all(|route| route.prefix_len() != 0),
            "V2 default route was not explicitly enabled"
        );
        ensure!(
            (self.peer_addresses.is_empty() && self.peer_derp_public_key.is_none())
                || self.peer_id.is_some(),
            "V2 peer locators require a peer ID"
        );
        ensure!(
            !self.accept_first_peer || (self.peer_id.is_none() && self.mesh_peers.is_empty()),
            "V2 accept-first mode cannot be combined with configured peers"
        );
        ensure!(
            self.mesh_peers.is_empty()
                || (self.peer_id.is_none()
                    && self.peer_addresses.is_empty()
                    && self.peer_derp_public_key.is_none()),
            "V2 one-peer and mesh-peer modes are mutually exclusive"
        );
        let mut peers = self
            .mesh_peers
            .iter()
            .map(|peer| peer.endpoint_id)
            .collect::<Vec<_>>();
        peers.sort_unstable();
        let count = peers.len();
        peers.dedup();
        ensure!(peers.len() == count, "duplicate V2 mesh peer EndpointId");
        let underlay_path_exclusions = self.underlay_path_exclusions();
        for peer in &self.mesh_peers {
            // An invite issuer knows the member identity before that member has
            // an address. Keep that peer as an authenticated accept-only
            // adjacency; the joining node owns the bootstrap locator and dials.
            ensure!(
                peer.addresses.iter().all(|address| address.port() != 0),
                "V2 mesh peer address has port zero"
            );
            ensure!(
                peer.addresses.iter().all(|address| underlay_path_exclusions
                    .iter()
                    .all(|prefix| !prefix.contains(&address.ip()))),
                "V2 mesh peer address is inside an excluded underlay prefix"
            );
        }
        let derp_enabled = !self.derp_servers.is_empty();
        let has_derp_peer = self.peer_derp_public_key.is_some()
            || self
                .mesh_peers
                .iter()
                .any(|peer| peer.derp_public_key.is_some());
        ensure!(
            derp_enabled == self.derp_identity_file.is_some(),
            "V2 DERP servers and identity file must be configured together"
        );
        ensure!(
            !has_derp_peer || derp_enabled,
            "V2 DERP peer locator requires configured DERP servers"
        );
        let mut regions = self
            .derp_servers
            .iter()
            .map(|server| server.region_id)
            .collect::<Vec<_>>();
        regions.sort_unstable();
        let region_count = regions.len();
        regions.dedup();
        ensure!(regions.len() == region_count, "duplicate V2 DERP region");
        let mut derp_peers = self
            .peer_derp_public_key
            .into_iter()
            .chain(
                self.mesh_peers
                    .iter()
                    .filter_map(|peer| peer.derp_public_key),
            )
            .collect::<Vec<_>>();
        derp_peers.sort_unstable();
        let derp_peer_count = derp_peers.len();
        derp_peers.dedup();
        ensure!(
            derp_peers.len() == derp_peer_count,
            "duplicate V2 DERP peer public key"
        );
        Ok(())
    }

    fn dialing(&self) -> bool {
        self.peer_id.is_some()
            && (!self.peer_addresses.is_empty() || self.peer_derp_public_key.is_some())
    }

    /// Translate the product configuration into the single V2 dataplane
    /// contract. This conversion is intentionally strict: unsupported V1
    /// transport shapes are rejected instead of silently starting a legacy
    /// runtime or weakening a private-link policy.
    pub fn from_product_config(config: &crate::config::Config) -> Result<Self> {
        let mut bind_addresses = config.endpoint_bind_addresses().collect::<Vec<_>>();
        bind_addresses.sort_unstable();
        bind_addresses.dedup();
        ensure!(
            bind_addresses.len() <= 1,
            "V2 requires one dual-stack bind address; found {}",
            bind_addresses.len()
        );
        let bind = bind_addresses
            .into_iter()
            .next()
            .unwrap_or_else(|| "[::]:4000".parse().expect("static V2 bind address"));

        let derp_servers = config.derp_servers()?;
        let mut invite_authorization = HashMap::<EndpointId, bool>::default();
        for (endpoint, revoked) in crate::product::authority_invites(&config.identity_file)
            .unwrap_or_default()
            .into_values()
        {
            invite_authorization
                .entry(endpoint)
                .and_modify(|active| *active |= !revoked)
                .or_insert(!revoked);
        }
        let revoked_invites = invite_authorization
            .into_iter()
            .filter_map(|(endpoint, active)| (!active).then_some(endpoint))
            .collect::<StdHashSet<_>>();
        let mut mesh_peers = Vec::with_capacity(config.peers.len());
        for peer in &config.peers {
            if revoked_invites.contains(&peer.endpoint_id) {
                continue;
            }
            let mut addresses = peer.direct_addresses.clone();
            for link in config
                .links
                .iter()
                .filter(|link| link.peer_id == peer.endpoint_id)
            {
                ensure!(
                    link.exclusive && !link.fallback,
                    "V2 private link {} must remain exclusive without fallback",
                    link.name
                );
                addresses.extend(link.remote_addresses.iter().copied());
            }
            addresses.sort_unstable();
            addresses.dedup();
            mesh_peers.push(V2PeerConfig {
                endpoint_id: peer.endpoint_id,
                addresses,
                derp_public_key: peer.derp_public_key,
            });
        }

        let mut routes = config
            .route_origins
            .iter()
            .flat_map(|origin| origin.prefixes.iter().copied())
            .collect::<Vec<_>>();
        routes.sort_by_key(|prefix| (prefix.addr().is_ipv6(), prefix.addr(), prefix.prefix_len()));
        routes.dedup();

        let result = Self {
            identity_file: config.identity_file.clone(),
            bind,
            excluded_underlay_prefixes: config.excluded_underlay_prefixes.clone(),
            peer_id: None,
            accept_first_peer: false,
            peer_addresses: Vec::new(),
            peer_derp_public_key: None,
            mesh_peers,
            derp_servers,
            derp_identity_file: config
                .relay
                .derp_enabled()
                .then(|| config.derp_identity_file()),
            network_id: config.network_id.clone(),
            cover_sni_pool: config.cover.sni_pool.clone(),
            cover_profile_id: config.cover.profile_id,
            tun_name: config.node_interface.clone(),
            tun_mtu: config.tun_mtu,
            isolate_overlay: config.routing.isolate_overlay,
            routing_table: config.routing.table,
            routing_rule_priority: config.routing.rule_priority,
            node_addresses: config.node_addresses.clone(),
            routes,
            advertised_routes: config.advertised_prefixes.clone(),
            allow_default_routes: config.routing.allow_default_routes,
            subnet_nat: config.routing.nat_enabled,
            transit_enabled: config.routing.transit_enabled,
            route_label: 1,
            autotune: config.autotune.clone(),
            path_migration: config.path_migration.clone(),
            max_egress_bytes_per_second: config.routing.max_egress_bps().map(|bits| bits / 8),
        };
        result.validate()?;
        Ok(result)
    }
}

fn build_v2_derp_transport(config: &V2RuntimeConfig) -> Result<Option<Arc<DerpTransport>>> {
    if config.derp_servers.is_empty() {
        return Ok(None);
    }
    let identity_file = config
        .derp_identity_file
        .as_deref()
        .context("V2 DERP identity file is missing")?;
    let identity = load_or_create_derp_identity(identity_file)?;
    let public_key = identity.public_key();
    let allowed_peers = config
        .peer_derp_public_key
        .into_iter()
        .chain(
            config
                .mesh_peers
                .iter()
                .filter_map(|peer| peer.derp_public_key),
        )
        .collect::<StdHashSet<_>>();
    info!(
        %public_key,
        identity_file = %identity_file.display(),
        regions = config.derp_servers.len(),
        peers = allowed_peers.len(),
        "V2 DERP transport configured"
    );
    Ok(Some(DerpTransport::new(
        identity,
        config.derp_servers.clone(),
        allowed_peers,
        derp_tls_config()?,
    )))
}

#[derive(Debug, Default)]
struct RuntimeMetrics {
    train_queue_bytes: AtomicU64,
    latency_queue_bytes: AtomicU64,
    real_tx_bytes: AtomicU64,
    cover_tx_bytes: AtomicU64,
    cover_rx_bytes: AtomicU64,
    pmtu_drop_bytes: AtomicU64,
    pmtu_drop_datagrams: AtomicU64,
    tun_tx_packets: AtomicU64,
    tun_rx_packets: AtomicU64,
    tun_rx_bytes: AtomicU64,
    tun_ingress_records: AtomicU64,
    tun_ingress_bytes: AtomicU64,
    tun_admission_drop_records: AtomicU64,
    tun_admission_drop_bytes: AtomicU64,
    data_cell_tx_datagrams: AtomicU64,
    full_payload_cells_built: AtomicU64,
    data_cell_tx_bytes: AtomicU64,
    data_cell_payload_tx_bytes: AtomicU64,
    fec_tx_datagrams: AtomicU64,
    fec_tx_bytes: AtomicU64,
    control_record_tx_bytes: AtomicU64,
    control_record_rx_bytes: AtomicU64,
    repair_request_tx_bytes: AtomicU64,
    repair_request_rx_bytes: AtomicU64,
    repair_response_tx_bytes: AtomicU64,
    repair_response_rx_bytes: AtomicU64,
    trains_built: AtomicU64,
    records_built: AtomicU64,
    record_bytes_built: AtomicU64,
    split_records_built: AtomicU64,
    cells_built: AtomicU64,
    cell_payload_built_bytes: AtomicU64,
    cell_wire_built_bytes: AtomicU64,
    unused_cell_capacity_bytes: AtomicU64,
    fec_stripes_built: AtomicU64,
    fec_protected_data_cells: AtomicU64,
    fec_parity_cells_built: AtomicU64,
    fec_encode_copy_bytes: AtomicU64,
    fec_unprotected_tail_cells: AtomicU64,
    fec_parity_rx: AtomicU64,
    fec_recovered_cells: AtomicU64,
    fec_wasted_parity: AtomicU64,
    fec_expired_stripes: AtomicU64,
    fec_decode_copy_bytes: AtomicU64,
    fec_recovery_latency_micros: AtomicU64,
    repair_requested_cells: AtomicU64,
    repair_suppressed_stripes: AtomicU64,
    repair_suppressed_cells: AtomicU64,
    repair_received_cells: AtomicU64,
    repair_completed_requests: AtomicU64,
    repair_completed_requested_cells: AtomicU64,
    repair_latency_micros: AtomicU64,
    repair_latency_max_micros: AtomicU64,
    repair_stale_responses: AtomicU64,
    repair_minimum_age_micros: AtomicU64,
    /// `RepairWaitPolicyV2` metrics code published by the tuner loop.
    repair_wait_policy: AtomicU8,
    remote_feedback_sequence: AtomicU64,
    remote_fec_parity_rx: AtomicU64,
    remote_fec_recovered_cells: AtomicU64,
    remote_fec_wasted_parity: AtomicU64,
    remote_fec_expired_stripes: AtomicU64,
    remote_repair_requested_cells: AtomicU64,
    remote_repair_received_cells: AtomicU64,
    remote_repair_completed_requests: AtomicU64,
    remote_repair_completed_requested_cells: AtomicU64,
    remote_repair_latency_micros: AtomicU64,
    remote_delivered_payload_bytes: AtomicU64,
    remote_reorder_cells: AtomicU64,
    remote_missing_cells: AtomicU64,
    remote_loss_run_1: AtomicU64,
    remote_loss_run_2: AtomicU64,
    remote_loss_run_3_4: AtomicU64,
    remote_loss_run_5_plus: AtomicU64,
    remote_reassembly_expired_trains: AtomicU64,
    receive_buffer_bytes: AtomicU64,
    /// Policy-driven aggregate reassembly budget (0 = follow the receive
    /// buffer), published by the tuner loop.
    reassembly_budget_bytes: AtomicU64,
    /// Policy-driven active-train budget (0 = negotiated wire limit).
    active_train_budget: AtomicU64,
    reassembly_pressure_evictions: AtomicU64,
    reassembly_expired_trains: AtomicU64,
    reorder_cells: AtomicU64,
    missing_cells: AtomicU64,
    loss_run_1: AtomicU64,
    loss_run_2: AtomicU64,
    loss_run_3_4: AtomicU64,
    loss_run_5_plus: AtomicU64,
    gso_input_bytes: AtomicU64,
    gso_preserved_bytes: AtomicU64,
    gso_fallback_splits: AtomicU64,
    protocol_datagram_errors: AtomicU64,
    route_gate_drops: AtomicU64,
    bulk_service_bytes: AtomicU64,
    latency_service_bytes: AtomicU64,
    bulk_service_quantums: AtomicU64,
    latency_service_quantums: AtomicU64,
    bulk_preemptions: AtomicU64,
    bulk_preemption_delay_micros: AtomicU64,
    bulk_preemption_max_delay_micros: AtomicU64,
    latency_sojourn_buckets: [AtomicU64; LATENCY_SOJOURN_BUCKETS],
    bulk_flow_service: [AtomicU64; BULK_FAIRNESS_BUCKETS],
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct TxByteSnapshotV2 {
    quic_udp_payload_bytes: u64,
    real_record_bytes: u64,
    data_cell_bytes: u64,
    data_cell_payload_bytes: u64,
    fec_bytes: u64,
    control_record_bytes: u64,
    repair_request_bytes: u64,
    repair_response_bytes: u64,
    padding_bytes: u64,
}

impl TxByteSnapshotV2 {
    fn load(metrics: &RuntimeMetrics, quic_udp_payload_bytes: u64) -> Self {
        Self {
            quic_udp_payload_bytes,
            real_record_bytes: metrics.record_bytes_built.load(Ordering::Relaxed),
            data_cell_bytes: metrics.data_cell_tx_bytes.load(Ordering::Relaxed),
            data_cell_payload_bytes: metrics.data_cell_payload_tx_bytes.load(Ordering::Relaxed),
            fec_bytes: metrics.fec_tx_bytes.load(Ordering::Relaxed),
            control_record_bytes: metrics.control_record_tx_bytes.load(Ordering::Relaxed),
            repair_request_bytes: metrics.repair_request_tx_bytes.load(Ordering::Relaxed),
            repair_response_bytes: metrics.repair_response_tx_bytes.load(Ordering::Relaxed),
            padding_bytes: metrics.cover_tx_bytes.load(Ordering::Relaxed),
        }
    }

    fn delta(self, previous: Self) -> Self {
        Self {
            quic_udp_payload_bytes: counter_delta(
                self.quic_udp_payload_bytes,
                previous.quic_udp_payload_bytes,
            ),
            real_record_bytes: self
                .real_record_bytes
                .saturating_sub(previous.real_record_bytes),
            data_cell_bytes: self
                .data_cell_bytes
                .saturating_sub(previous.data_cell_bytes),
            data_cell_payload_bytes: self
                .data_cell_payload_bytes
                .saturating_sub(previous.data_cell_payload_bytes),
            fec_bytes: self.fec_bytes.saturating_sub(previous.fec_bytes),
            control_record_bytes: self
                .control_record_bytes
                .saturating_sub(previous.control_record_bytes),
            repair_request_bytes: self
                .repair_request_bytes
                .saturating_sub(previous.repair_request_bytes),
            repair_response_bytes: self
                .repair_response_bytes
                .saturating_sub(previous.repair_response_bytes),
            padding_bytes: self.padding_bytes.saturating_sub(previous.padding_bytes),
        }
    }

    fn breakdown(self) -> TxByteBreakdownV2 {
        let repair_bytes = self
            .repair_request_bytes
            .saturating_add(self.repair_response_bytes)
            .min(self.control_record_bytes);
        let application_bytes = self
            .data_cell_bytes
            .saturating_add(self.fec_bytes)
            .saturating_add(self.control_record_bytes)
            .saturating_add(self.padding_bytes);
        TxByteBreakdownV2 {
            quic_udp_payload_bytes: self.quic_udp_payload_bytes,
            real_record_bytes: self.real_record_bytes,
            data_cell_bytes: self.data_cell_bytes,
            data_cell_payload_bytes: self.data_cell_payload_bytes,
            packet_train_metadata_bytes: self
                .data_cell_payload_bytes
                .saturating_sub(self.real_record_bytes),
            cell_envelope_bytes: self
                .data_cell_bytes
                .saturating_sub(self.data_cell_payload_bytes),
            fec_bytes: self.fec_bytes,
            repair_request_bytes: self.repair_request_bytes,
            repair_response_bytes: self.repair_response_bytes,
            other_control_record_bytes: self.control_record_bytes.saturating_sub(repair_bytes),
            padding_bytes: self.padding_bytes,
            quic_transport_residual_bytes: self
                .quic_udp_payload_bytes
                .saturating_sub(application_bytes),
            interval_accounting_lag_bytes: application_bytes
                .saturating_sub(self.quic_udp_payload_bytes),
        }
    }
}

/// A status-interval ledger. QUIC's counter includes every byte carried
/// inside UDP datagrams. DATAGRAM payload, reliable control records and cover
/// padding are counted at successful QUIC admission; their positive residual
/// is therefore QUIC packet/frame/AEAD/ACK/retransmission overhead. A positive
/// lag is reported separately instead of pretending that asynchronous QUIC
/// serialization at an interval boundary is protocol overhead.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct TxByteBreakdownV2 {
    quic_udp_payload_bytes: u64,
    real_record_bytes: u64,
    data_cell_bytes: u64,
    data_cell_payload_bytes: u64,
    packet_train_metadata_bytes: u64,
    cell_envelope_bytes: u64,
    fec_bytes: u64,
    repair_request_bytes: u64,
    repair_response_bytes: u64,
    other_control_record_bytes: u64,
    padding_bytes: u64,
    quic_transport_residual_bytes: u64,
    interval_accounting_lag_bytes: u64,
}

impl TxByteBreakdownV2 {
    fn wire_cost(self) -> WireCostV2 {
        WireCostV2 {
            payload_bytes: self.real_record_bytes,
            parity_bytes: self.fec_bytes,
            repair_bytes: self
                .repair_request_bytes
                .saturating_add(self.repair_response_bytes),
            cover_bytes: self.padding_bytes,
            cell_envelope_bytes: self.cell_envelope_bytes,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct TunIngressBatchV2 {
    records: u64,
    bytes: u64,
    gso: GsoObservationV2,
}

impl TunIngressBatchV2 {
    fn observe(&mut self, bytes: usize, gso: GsoObservationV2) {
        self.records = self.records.saturating_add(1);
        self.bytes = self
            .bytes
            .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
        self.gso.input_bytes = self.gso.input_bytes.saturating_add(gso.input_bytes);
        self.gso.preserved_bytes = self.gso.preserved_bytes.saturating_add(gso.preserved_bytes);
        self.gso.fallback_splits = self.gso.fallback_splits.saturating_add(gso.fallback_splits);
    }
}

impl RuntimeMetrics {
    fn record_protocol_datagram_error(&self) -> (u64, bool) {
        increment_sampled_counter(&self.protocol_datagram_errors)
    }

    fn record_route_gate_drop(&self) -> (u64, bool) {
        increment_sampled_counter(&self.route_gate_drops)
    }

    fn observe_tun_ingress_batch(&self, observation: TunIngressBatchV2) {
        if observation.records == 0 {
            return;
        }
        self.tun_ingress_records
            .fetch_add(observation.records, Ordering::Relaxed);
        self.tun_ingress_bytes
            .fetch_add(observation.bytes, Ordering::Relaxed);
        self.gso_input_bytes
            .fetch_add(observation.gso.input_bytes, Ordering::Relaxed);
        self.gso_preserved_bytes
            .fetch_add(observation.gso.preserved_bytes, Ordering::Relaxed);
        self.gso_fallback_splits
            .fetch_add(observation.gso.fallback_splits, Ordering::Relaxed);
    }

    fn observe_send(&self, progress: SendProgress) {
        if let Some(class) = progress.class {
            match class {
                TrafficClass::Latency => {
                    self.latency_service_bytes
                        .fetch_add(progress.bytes as u64, Ordering::Relaxed);
                    self.latency_service_quantums
                        .fetch_add(1, Ordering::Relaxed);
                    let bucket = latency_sojourn_bucket(progress.queue_sojourn_micros);
                    self.latency_sojourn_buckets[bucket].fetch_add(1, Ordering::Relaxed);
                    if progress.bulk_preemption {
                        self.bulk_preemptions.fetch_add(1, Ordering::Relaxed);
                        self.bulk_preemption_delay_micros
                            .fetch_add(progress.queue_sojourn_micros, Ordering::Relaxed);
                        self.bulk_preemption_max_delay_micros
                            .fetch_max(progress.queue_sojourn_micros, Ordering::Relaxed);
                    }
                }
                TrafficClass::Bulk => {
                    self.bulk_service_bytes
                        .fetch_add(progress.bytes as u64, Ordering::Relaxed);
                    self.bulk_service_quantums.fetch_add(1, Ordering::Relaxed);
                    if let Some(flow_id) = progress.flow_id {
                        self.bulk_flow_service[flow_id as usize % BULK_FAIRNESS_BUCKETS]
                            .fetch_add(progress.bytes as u64, Ordering::Relaxed);
                    }
                }
            }
        }
        self.data_cell_tx_datagrams
            .fetch_add(progress.data_cell_datagrams as u64, Ordering::Relaxed);
        self.data_cell_tx_bytes
            .fetch_add(progress.data_cell_bytes as u64, Ordering::Relaxed);
        self.data_cell_payload_tx_bytes
            .fetch_add(progress.data_cell_payload_bytes as u64, Ordering::Relaxed);
        self.fec_tx_datagrams
            .fetch_add(progress.fec_datagrams as u64, Ordering::Relaxed);
        self.fec_tx_bytes
            .fetch_add(progress.fec_bytes as u64, Ordering::Relaxed);
        if let Some(stats) = progress.train_stats {
            self.trains_built.fetch_add(1, Ordering::Relaxed);
            self.records_built
                .fetch_add(stats.records, Ordering::Relaxed);
            self.record_bytes_built
                .fetch_add(stats.record_bytes, Ordering::Relaxed);
            self.split_records_built
                .fetch_add(stats.split_records, Ordering::Relaxed);
            self.cells_built.fetch_add(stats.cells, Ordering::Relaxed);
            self.full_payload_cells_built
                .fetch_add(stats.full_payload_cells, Ordering::Relaxed);
            self.cell_payload_built_bytes
                .fetch_add(stats.cell_payload_bytes, Ordering::Relaxed);
            self.cell_wire_built_bytes
                .fetch_add(stats.cell_wire_bytes, Ordering::Relaxed);
            self.unused_cell_capacity_bytes
                .fetch_add(stats.unused_payload_capacity, Ordering::Relaxed);
            self.fec_stripes_built
                .fetch_add(stats.fec_stripes, Ordering::Relaxed);
            self.fec_protected_data_cells
                .fetch_add(stats.fec_protected_data_cells, Ordering::Relaxed);
            self.fec_parity_cells_built
                .fetch_add(stats.fec_parity_cells, Ordering::Relaxed);
            self.fec_encode_copy_bytes
                .fetch_add(stats.fec_encode_copy_bytes, Ordering::Relaxed);
            self.fec_unprotected_tail_cells
                .fetch_add(stats.fec_unprotected_tail_cells, Ordering::Relaxed);
        }
    }

    fn observe_control_tx(&self, record: &[u8]) {
        self.observe_control_record(
            record,
            &self.control_record_tx_bytes,
            &self.repair_request_tx_bytes,
            &self.repair_response_tx_bytes,
        );
    }

    fn observe_control_rx(&self, record: &[u8]) {
        self.observe_control_record(
            record,
            &self.control_record_rx_bytes,
            &self.repair_request_rx_bytes,
            &self.repair_response_rx_bytes,
        );
    }

    fn observe_control_record(
        &self,
        record: &[u8],
        total: &AtomicU64,
        repair_requests: &AtomicU64,
        repair_responses: &AtomicU64,
    ) {
        let bytes = u64::try_from(record.len()).unwrap_or(u64::MAX);
        total.fetch_add(bytes, Ordering::Relaxed);
        if RepairControlV2::is_request(record) {
            repair_requests.fetch_add(bytes, Ordering::Relaxed);
        } else if RepairControlV2::is_response(record) {
            repair_responses.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    fn observe_receive(&self, output: &ReassemblyOutput) {
        self.reassembly_pressure_evictions
            .fetch_add(output.pressure_evicted_trains, Ordering::Relaxed);
        self.reassembly_expired_trains
            .fetch_add(output.reassembly_expired_trains, Ordering::Relaxed);
        self.reorder_cells
            .fetch_add(output.reorder_cells, Ordering::Relaxed);
        self.missing_cells
            .fetch_add(output.missing_cells, Ordering::Relaxed);
        self.fec_parity_rx
            .fetch_add(output.fec.parity_received, Ordering::Relaxed);
        self.fec_recovered_cells
            .fetch_add(output.fec.recovered_cells, Ordering::Relaxed);
        self.fec_wasted_parity
            .fetch_add(output.fec.wasted_parity, Ordering::Relaxed);
        self.fec_expired_stripes
            .fetch_add(output.fec.expired_stripes, Ordering::Relaxed);
        self.fec_decode_copy_bytes
            .fetch_add(output.fec.decode_copy_bytes, Ordering::Relaxed);
        self.fec_recovery_latency_micros
            .fetch_add(output.fec.recovery_latency_micros, Ordering::Relaxed);
    }

    fn observe_repair_request(&self, request: &RepairRequestV2) {
        self.repair_requested_cells
            .fetch_add(request.missing_sequences.len() as u64, Ordering::Relaxed);
        let runs = LossRunHistogramV2::from_missing_sequences(&request.missing_sequences);
        self.loss_run_1.fetch_add(runs.run_1, Ordering::Relaxed);
        self.loss_run_2.fetch_add(runs.run_2, Ordering::Relaxed);
        self.loss_run_3_4.fetch_add(runs.run_3_4, Ordering::Relaxed);
        self.loss_run_5_plus
            .fetch_add(runs.run_5_plus, Ordering::Relaxed);
    }

    fn observe_repair_suppression(&self, batch: &RepairRequestBatchV2) {
        self.repair_suppressed_stripes
            .fetch_add(batch.suppressed_stripes, Ordering::Relaxed);
        self.repair_suppressed_cells
            .fetch_add(batch.suppressed_cells, Ordering::Relaxed);
    }

    fn observe_local_delivery(&self, output: &ReassemblyOutput) {
        if output.records.is_empty() {
            return;
        }
        let bytes = output.records.iter().fold(0_u64, |total, record| {
            total.saturating_add(u64::try_from(record.total_len).unwrap_or(u64::MAX))
        });
        self.tun_rx_packets.fetch_add(
            u64::try_from(output.records.len()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
        self.tun_rx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    fn observe_repair_response(&self, observation: RepairResponseObservationV2) {
        self.repair_received_cells
            .fetch_add(observation.received_cells, Ordering::Relaxed);
        self.repair_completed_requests
            .fetch_add(1, Ordering::Relaxed);
        self.repair_completed_requested_cells
            .fetch_add(observation.requested_cells, Ordering::Relaxed);
        self.repair_latency_micros
            .fetch_add(observation.latency_micros, Ordering::Relaxed);
        self.repair_latency_max_micros
            .fetch_max(observation.latency_micros, Ordering::Relaxed);
    }

    fn fec_feedback(&self, sequence: u64) -> FecFeedbackV2 {
        FecFeedbackV2 {
            sequence,
            parity_received: self.fec_parity_rx.load(Ordering::Relaxed),
            recovered_cells: self.fec_recovered_cells.load(Ordering::Relaxed),
            wasted_parity: self.fec_wasted_parity.load(Ordering::Relaxed),
            repair_requested_cells: self.repair_requested_cells.load(Ordering::Relaxed),
            repair_received_cells: self.repair_received_cells.load(Ordering::Relaxed),
            repair_completed_requests: self.repair_completed_requests.load(Ordering::Relaxed),
            repair_completed_requested_cells: self
                .repair_completed_requested_cells
                .load(Ordering::Relaxed),
            repair_latency_micros: self.repair_latency_micros.load(Ordering::Relaxed),
            expired_stripes: self.fec_expired_stripes.load(Ordering::Relaxed),
            delivered_payload_bytes: self.tun_rx_bytes.load(Ordering::Relaxed),
            reorder_cells: self.reorder_cells.load(Ordering::Relaxed),
            missing_cells: self.missing_cells.load(Ordering::Relaxed),
            loss_run_1: self.loss_run_1.load(Ordering::Relaxed),
            loss_run_2: self.loss_run_2.load(Ordering::Relaxed),
            loss_run_3_4: self.loss_run_3_4.load(Ordering::Relaxed),
            loss_run_5_plus: self.loss_run_5_plus.load(Ordering::Relaxed),
            reassembly_expired_trains: self.reassembly_expired_trains.load(Ordering::Relaxed),
        }
    }

    fn apply_remote_feedback(&self, feedback: FecFeedbackV2) -> bool {
        if feedback.sequence <= self.remote_feedback_sequence.load(Ordering::Acquire) {
            return false;
        }
        self.remote_fec_parity_rx
            .store(feedback.parity_received, Ordering::Relaxed);
        self.remote_fec_recovered_cells
            .store(feedback.recovered_cells, Ordering::Relaxed);
        self.remote_fec_wasted_parity
            .store(feedback.wasted_parity, Ordering::Relaxed);
        self.remote_fec_expired_stripes
            .store(feedback.expired_stripes, Ordering::Relaxed);
        self.remote_repair_requested_cells
            .store(feedback.repair_requested_cells, Ordering::Relaxed);
        self.remote_repair_received_cells
            .store(feedback.repair_received_cells, Ordering::Relaxed);
        self.remote_repair_completed_requests
            .store(feedback.repair_completed_requests, Ordering::Relaxed);
        self.remote_repair_completed_requested_cells
            .store(feedback.repair_completed_requested_cells, Ordering::Relaxed);
        self.remote_repair_latency_micros
            .store(feedback.repair_latency_micros, Ordering::Relaxed);
        self.remote_delivered_payload_bytes
            .store(feedback.delivered_payload_bytes, Ordering::Relaxed);
        self.remote_reorder_cells
            .store(feedback.reorder_cells, Ordering::Relaxed);
        self.remote_missing_cells
            .store(feedback.missing_cells, Ordering::Relaxed);
        self.remote_loss_run_1
            .store(feedback.loss_run_1, Ordering::Relaxed);
        self.remote_loss_run_2
            .store(feedback.loss_run_2, Ordering::Relaxed);
        self.remote_loss_run_3_4
            .store(feedback.loss_run_3_4, Ordering::Relaxed);
        self.remote_loss_run_5_plus
            .store(feedback.loss_run_5_plus, Ordering::Relaxed);
        self.remote_reassembly_expired_trains
            .store(feedback.reassembly_expired_trains, Ordering::Relaxed);
        self.remote_feedback_sequence
            .store(feedback.sequence, Ordering::Release);
        true
    }
}

/// Increment a cumulative metric while requesting logs only at powers of two.
/// This keeps the first error visible, then bounds a sustained attack to
/// O(log n) messages without hiding the exact cumulative count.
fn increment_sampled_counter(counter: &AtomicU64) -> (u64, bool) {
    let count = counter.fetch_add(1, Ordering::Relaxed).saturating_add(1);
    (count, count.is_power_of_two())
}

fn latency_sojourn_bucket(micros: u64) -> usize {
    LATENCY_SOJOURN_UPPER_MICROS
        .iter()
        .position(|upper| micros <= *upper)
        .unwrap_or(LATENCY_SOJOURN_BUCKETS - 1)
}

fn histogram_percentile_micros(delta: &[u64; LATENCY_SOJOURN_BUCKETS], percentile: u64) -> u64 {
    let total = delta.iter().copied().sum::<u64>();
    if total == 0 {
        return 0;
    }
    let target = total
        .saturating_mul(percentile)
        .saturating_add(99)
        .saturating_div(100)
        .max(1);
    let mut cumulative = 0_u64;
    for (index, count) in delta.iter().copied().enumerate() {
        cumulative = cumulative.saturating_add(count);
        if cumulative >= target {
            return LATENCY_SOJOURN_UPPER_MICROS
                .get(index)
                .copied()
                .unwrap_or(1_000_001);
        }
    }
    1_000_001
}

fn jain_fairness_ppm(service: &[u64; BULK_FAIRNESS_BUCKETS]) -> u64 {
    let active = service.iter().filter(|bytes| **bytes != 0).count() as u128;
    if active <= 1 {
        return if active == 0 { 0 } else { 1_000_000 };
    }
    let sum = service.iter().copied().map(u128::from).sum::<u128>();
    let squares = service
        .iter()
        .copied()
        .map(u128::from)
        .map(|value| value.saturating_mul(value))
        .sum::<u128>();
    sum.saturating_mul(sum)
        .saturating_mul(1_000_000)
        .checked_div(active.saturating_mul(squares))
        .unwrap_or_default()
        .min(1_000_000) as u64
}

fn minimum_receive_buffer_bytes() -> usize {
    AutoTuneBoundsV2::default().minimum_receive_buffer_bytes
}

fn apply_receive_buffer_target(rx: &mut V2Rx, metrics: &RuntimeMetrics) -> Result<usize> {
    let mut evicted = 0;
    // The policy-driven reassembly budget and active-train budget ride the
    // same metrics channel as the receive buffer target.
    let budget = metrics.reassembly_budget_bytes.load(Ordering::Relaxed) as usize;
    let trains = metrics.active_train_budget.load(Ordering::Relaxed) as usize;
    if budget != rx.reassembly_budget_bytes() || trains != rx.active_train_budget() {
        evicted += rx.set_reassembly_budget(budget, trains)?;
    }
    let target = metrics.receive_buffer_bytes.load(Ordering::Relaxed) as usize;
    if target != 0 && target != rx.maximum_buffered_bytes() {
        evicted += rx.set_maximum_buffered_bytes(target)?;
    }
    Ok(evicted)
}

#[derive(Debug)]
struct CoverShaperV2 {
    profile: CoverTrafficProfileV2,
    bytes_per_second: u64,
    tokens: u64,
    updated_at: Instant,
}

impl Default for CoverShaperV2 {
    fn default() -> Self {
        Self {
            profile: CoverTrafficProfileV2::Idle,
            bytes_per_second: 0,
            tokens: 0,
            updated_at: Instant::now(),
        }
    }
}

impl CoverShaperV2 {
    fn update(&mut self, decision: TuneDecisionV2) {
        self.refill();
        self.profile = decision.cover_profile;
        self.bytes_per_second = decision.cover_padding_bytes_per_second;
        if self.bytes_per_second == 0 || self.profile == CoverTrafficProfileV2::Idle {
            self.tokens = 0;
        } else {
            self.tokens = self.tokens.min(self.maximum_tokens());
        }
    }

    fn enqueue_after_real(&mut self, tx: &mut V2Tx) -> Result<usize> {
        if self.bytes_per_second == 0 || self.profile == CoverTrafficProfileV2::Idle {
            return Ok(0);
        }
        self.refill();
        let target = tx.cover_padding_target_size(self.profile)?;
        if self.tokens < target as u64 || !tx.enqueue_cover_padding(self.profile)? {
            return Ok(0);
        }
        self.tokens -= target as u64;
        Ok(target)
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed_nanos = now.saturating_duration_since(self.updated_at).as_nanos();
        self.updated_at = now;
        if self.bytes_per_second == 0 {
            return;
        }
        let added = u128::from(self.bytes_per_second).saturating_mul(elapsed_nanos) / 1_000_000_000;
        self.tokens = self
            .tokens
            .saturating_add(added.min(u64::MAX.into()) as u64)
            .min(self.maximum_tokens());
    }

    fn maximum_tokens(&self) -> u64 {
        // At most 100 ms of the automatically derived budget may accumulate;
        // this prevents a low-rate flow from later emitting a cover burst.
        (self.bytes_per_second / 10).max(2_048)
    }
}

#[derive(Debug)]
struct FlowState {
    classifier: FlowClassifier,
    last_seen: Duration,
}

#[derive(Debug)]
enum TxControl {
    Send(Bytes),
    Respond(RepairRequestV2),
}

#[derive(Debug)]
struct ControlContextV2 {
    tx: mpsc::Sender<TxControl>,
    repaired: mpsc::Sender<RepairResponseV2>,
    routes: mpsc::Sender<RouteAdvertisementV2>,
    presences: mpsc::Sender<SignedPresenceV2>,
    allow_default_routes: bool,
    metrics: Arc<RuntimeMetrics>,
}

#[derive(Debug, Clone)]
struct RxRouteContext {
    snapshot: Arc<DataplaneSnapshotV2>,
    incoming: AdjacencyIdV2,
}

pub async fn run(config: V2RuntimeConfig) -> Result<()> {
    // Register SIGTERM before creating routes/firewall state so systemd can
    // never terminate the process in the setup-to-main-loop race window.
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("installing V2 SIGTERM handler")?;
    let result = run_with_shutdown(
        config,
        async move {
            tokio::select! {
                signal = tokio::signal::ctrl_c() => signal.context("waiting for V2 SIGINT"),
                _ = terminate.recv() => Ok(()),
            }
        },
        None,
    )
    .await;
    let cleanup = cleanup_v2_nat_all();
    result.and(cleanup)
}

type ShutdownFuture = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

/// Run the sole production dataplane under an externally owned lifecycle.
///
/// `ironetd` uses this entry point so reload/stop never requires a second
/// protocol runtime. The standalone signal wrapper above is retained only as
/// a developer harness until the temporary benchmark binary is removed.
pub async fn run_with_shutdown<F>(
    config: V2RuntimeConfig,
    shutdown: F,
    ready: Option<oneshot::Sender<()>>,
) -> Result<()>
where
    F: Future<Output = Result<()>> + Send + 'static,
{
    run_with_shutdown_and_state(config, shutdown, ready, None).await
}

pub async fn run_with_shutdown_and_state<F>(
    config: V2RuntimeConfig,
    shutdown: F,
    ready: Option<oneshot::Sender<()>>,
    state: Option<watch::Sender<Option<Arc<V2RuntimeState>>>>,
) -> Result<()>
where
    F: Future<Output = Result<()>> + Send + 'static,
{
    let mut shutdown: ShutdownFuture = Box::pin(shutdown);
    let result = run_with_shutdown_future(config, &mut shutdown, ready, state.as_ref()).await;
    if let Some(state) = state {
        state.send_replace(None);
    }
    result
}

async fn run_with_shutdown_future(
    config: V2RuntimeConfig,
    shutdown: &mut ShutdownFuture,
    mut ready: Option<oneshot::Sender<()>>,
    state: Option<&watch::Sender<Option<Arc<V2RuntimeState>>>>,
) -> Result<()> {
    config.validate()?;
    let secret_key = identity::load_or_create(&config.identity_file)?;
    let local_id = secret_key.public();
    let runtime_state = Arc::new(V2RuntimeState::new(&config, local_id));
    let derp_transport = build_v2_derp_transport(&config)?;
    let mut congestion = noq_proto::congestion::Bbr3Config::default();
    // At <=5 ms, userspace timer wakeups cost more than a complete send
    // quantum and can collapse LAN/Wi-Fi delivery-rate sampling. BBR still
    // enforces cwnd; if live loss proves a shallow policer, its automatic
    // pacing scale immediately disables this bypass for that path lifetime.
    congestion.pacing_bypass_below_rtt(Some(Duration::from_millis(5)));
    congestion.low_rtt_cwnd_floor(LOW_RTT_CWND_FLOOR_BYTES);
    let transport = QuicTransportConfig::builder()
        // Keep the passive QUIC v1/H3Media surface deterministic across every
        // peer. These are protocol-profile constants, not operator tuning:
        // live bandwidth/RTT/loss adaptation remains inside QUIC BBR3, PMTUD
        // and the bounded V2 admission controller.
        .max_concurrent_bidi_streams(LIVE_MEDIA_QUIC_BIDI_STREAMS.into())
        .max_concurrent_uni_streams(LIVE_MEDIA_QUIC_UNI_STREAMS.into())
        .stream_receive_window(LIVE_MEDIA_QUIC_STREAM_RECEIVE_WINDOW.into())
        .receive_window(LIVE_MEDIA_QUIC_RECEIVE_WINDOW.into())
        .send_window(LIVE_MEDIA_QUIC_SEND_WINDOW)
        .initial_mtu(LIVE_MEDIA_QUIC_INITIAL_MTU)
        .min_mtu(LIVE_MEDIA_QUIC_MINIMUM_MTU)
        .packet_threshold(3)
        .time_threshold(1.125)
        .initial_rtt(Duration::from_millis(333))
        .persistent_congestion_threshold(3)
        .ack_frequency_config(None)
        .allow_spin(false)
        .enable_segmentation_offload(true)
        .keep_alive_interval(Duration::from_secs(1))
        .default_path_keep_alive_interval(Duration::from_millis(
            config.path_migration.keep_alive_ms,
        ))
        .default_path_max_idle_timeout(Duration::from_millis(config.path_migration.idle_timeout_ms))
        // V2 carries a tunnel's long-lived mixed traffic over QUIC DATAGRAMs.
        // Loss-based CUBIC collapses its window on lossy mobile/WAN paths even
        // when receiver feedback proves the path is not queue-congested. BBR3
        // derives pacing and inflight from delivered bandwidth/min-RTT and is
        // therefore the appropriate automatic controller for this dataplane;
        // peers need not expose or coordinate an operator setting.
        // Sub-millisecond host/datacenter paths bypass only the userspace
        // pacing timer after BBR measures min-RTT; its inflight window remains
        // active. WAN paths retain full model-based pacing.
        .congestion_controller_factory(Arc::new(congestion))
        .max_outgoing_bytes_per_second(config.max_egress_bytes_per_second)
        .datagram_send_buffer_size(LIVE_MEDIA_QUIC_DATAGRAM_BUFFER)
        .datagram_receive_buffer_size(Some(LIVE_MEDIA_QUIC_DATAGRAM_BUFFER))
        .send_observed_address_reports(false)
        .receive_observed_address_reports(false)
        .build();
    let mut endpoint_builder = Endpoint::builder(presets::N0)
        .secret_key(secret_key.clone())
        .alpns(vec![ALPN.to_vec()])
        .enable_early_data(false)
        .relay_mode(RelayMode::Disabled)
        .transport_config(transport)
        .path_selector(Arc::new(UnderlayPathSelector::new(
            config.underlay_path_exclusions(),
            config.path_migration.clone(),
        )))
        .path_recovery_interval(Duration::from_millis(config.path_migration.keep_alive_ms))
        .path_recovery_probation(Duration::from_millis(
            config.path_migration.recovery_probation_ms,
        ))
        .clear_address_lookup()
        .clear_ip_transports();
    // `clear_ip_transports` removes iroh's default IPv4 + IPv6 pair. Restore
    // both families when the product configuration uses an unspecified bind;
    // a lone `[::]` socket is IPv6-only in the transport and cannot dial an
    // IPv4 invite locator (and conversely for `0.0.0.0`). Both sockets share
    // the configured QUIC port, preserving one externally visible endpoint.
    for bind in endpoint_bind_addresses(config.bind) {
        endpoint_builder = endpoint_builder.bind_addr(bind)?;
    }
    if let Some(transport) = derp_transport.clone() {
        endpoint_builder = endpoint_builder.add_custom_transport(transport);
    }
    let endpoint = endpoint_builder
        .bind()
        .await
        .context("binding V2 QUIC endpoint")?;
    info!(
        endpoint_id = %local_id,
        bind = %config.bind,
        alpn = "h3",
        cover_profile = COVER_PROFILE_NAME,
        cover_profile_generation = config.cover_profile_id,
        "V2 endpoint ready"
    );
    if let Some(ready) = ready.take() {
        let _ = ready.send(());
    }
    if let Some(state) = state {
        state.send_replace(Some(runtime_state.clone()));
    }

    if !config.mesh_peers.is_empty() {
        return run_mesh(
            config,
            endpoint,
            derp_transport,
            secret_key,
            local_id,
            shutdown,
            runtime_state,
        )
        .await;
    }

    if config.peer_id.is_none() && !config.accept_first_peer {
        info!("V2 product endpoint has no admitted peers; waiting fail-closed");
        shutdown.as_mut().await?;
        endpoint.close().await;
        return Ok(());
    }

    let connection = tokio::select! {
        // A passive endpoint can wait here indefinitely. Keep shutdown live
        // before the dataplane JoinSet exists instead of merely registering
        // the signal and deferring its observation until a peer arrives.
        biased;
        signal = shutdown.as_mut() => {
            signal?;
            info!("received V2 shutdown signal during connection establishment");
            endpoint.close().await;
            return Ok(());
        }
        result = establish_connection(&endpoint, &config, derp_transport.as_deref()) => result?,
    };
    let remote_id = connection.remote_id();
    if let Some(expected) = config.peer_id {
        ensure!(remote_id == expected, "incoming V2 peer is not allowlisted");
    }
    let policy = session_policy(&config, local_id, remote_id);
    let negotiated = tokio::select! {
        biased;
        signal = shutdown.as_mut() => {
            signal?;
            info!("received V2 shutdown signal during session negotiation");
            connection.close(0_u8.into(), b"V2 startup shutdown");
            endpoint.close().await;
            return Ok(());
        }
        result = negotiate_connection_v2(&connection, &policy) => result?,
    };
    info!(
        peer = %remote_id,
        session_epoch = negotiated.session_epoch,
        cover_profile = negotiated.cover_profile_id,
        "V2 authenticated session active"
    );
    runtime_state.mark_connected(&connection);
    let (local_overlay_v4, local_overlay) = local_overlay_addresses(&config, local_id);
    let presence_issued = unix_secs(SystemTime::now())?;
    let local_presence = SignedPresenceV2::sign(
        PresenceBodyV2 {
            owner: local_id,
            sequence: 1,
            issued_unix_secs: presence_issued,
            expires_unix_secs: presence_issued.saturating_add(180),
            direct_addresses: selected_direct_addresses(&connection, config.bind.port()),
            node_addresses: vec![
                IpNet::from(std::net::IpAddr::V4(local_overlay_v4)),
                IpNet::from(std::net::IpAddr::V6(local_overlay)),
            ],
            prefixes: config.advertised_routes.clone(),
            links: vec![PresenceLinkV2 {
                peer: remote_id,
                cost: selected_path_cost(&connection),
                healthy: true,
                maximum_datagram_size: negotiated.limits.max_datagram_size,
            }],
            transit_enabled: config.transit_enabled,
        },
        &secret_key,
        &config.network_id,
    )?;

    let remote_overlay = derived_overlay_address(&config.network_id, remote_id);
    let remote_overlay_v4 = derived_overlay_ipv4_address(&config.network_id, remote_id);
    let tunnel = OverlayTunnel::create(config.tun_name.clone(), config.tun_mtu)?;
    let (route_policy, _kernel_route_guard) = configure_tunnel(
        &config,
        local_overlay_v4,
        remote_overlay_v4,
        local_overlay,
        remote_overlay,
    )?;
    runtime_state.publish_routes(config.routes.iter().copied());
    reconcile_v2_nat(
        &config.tun_name,
        &config.advertised_routes,
        config.subnet_nat,
    )?;
    info!(
        interface = %config.tun_name,
        local_overlay_v4 = %local_overlay_v4,
        remote_overlay_v4 = %remote_overlay_v4,
        local_overlay = %local_overlay,
        remote_overlay = %remote_overlay,
        queues = tunnel.queue_count(),
        "V2 TUN configured"
    );

    let metrics = Arc::new(RuntimeMetrics::default());
    runtime_state.attach_metrics(remote_id, metrics.clone());
    // The one-adjacency runtime still has one adjacency, but it consumes the same
    // immutable label snapshot and local-delivery gate as the multi-peer
    // runtime. This prevents the one-peer path from becoming a second wire
    // semantics while transit is brought up incrementally.
    let ingress_adjacency = AdjacencyIdV2::new(1)?;
    let dataplane_snapshot = Arc::new(DataplaneSnapshotV2::compile(
        1,
        *local_id.as_bytes(),
        Vec::new(),
        vec![LabelRouteV2 {
            route_label: RouteLabelV2::new(config.route_label)?,
            route_epoch: negotiated.session_epoch,
            action: LabelActionV2::Local {
                expected_ingress: ingress_adjacency,
            },
        }],
        Vec::new(),
        false,
    )?);
    let (tun_sender, tun_receiver) = mpsc::channel(TUN_INPUT_SLOTS);
    let (tun_priority_sender, tun_priority_receiver) = mpsc::channel(TUN_PRIORITY_INPUT_SLOTS);
    let tun_regular_budget = Arc::new(Semaphore::new(TUN_REGULAR_INPUT_BYTES));
    let (tune_sender, tune_receiver) = watch::channel(None::<TuneDecisionV2>);
    let (control_sender, control_receiver) = mpsc::channel(256);
    let (repair_sender, repair_receiver) = mpsc::channel(256);
    let (route_sender, route_receiver) = mpsc::channel(8);
    let (presence_sender, presence_receiver) = mpsc::channel(64);
    let mut tasks = JoinSet::new();
    tasks.spawn(cpu_sampler_loop(runtime_state.clone()));
    for device in &tunnel.devices {
        tasks.spawn(prioritized_tun_reader(
            device.clone(),
            tun_sender.clone(),
            tun_priority_sender.clone(),
            tun_regular_budget.clone(),
            metrics.clone(),
        ));
    }
    drop(tun_sender);
    drop(tun_priority_sender);
    tasks.spawn(tx_loop(
        connection.clone(),
        negotiated,
        PrioritizedTunInput {
            regular: tun_receiver,
            priority: tun_priority_receiver,
        },
        tune_receiver,
        control_receiver,
        metrics.clone(),
        config.route_label,
    ));
    tasks.spawn(rx_loop(
        connection.clone(),
        negotiated,
        tunnel.writer(),
        metrics.clone(),
        control_sender.clone(),
        repair_receiver,
        RxRouteContext {
            snapshot: dataplane_snapshot,
            incoming: ingress_adjacency,
        },
    ));
    tasks.spawn(control_loop(
        connection.clone(),
        negotiated,
        ControlContextV2 {
            tx: control_sender.clone(),
            repaired: repair_sender,
            routes: route_sender.clone(),
            presences: presence_sender,
            allow_default_routes: config.allow_default_routes,
            metrics: metrics.clone(),
        },
    ));
    tasks.spawn(presence_loop(
        local_presence.clone(),
        presence_receiver,
        PresenceContextV2 {
            network_id: config.network_id.clone(),
            local_id,
            secret_key: secret_key.clone(),
            routes: route_sender.clone(),
            control: control_sender.clone(),
            allow_default_routes: config.allow_default_routes,
            runtime_state: runtime_state.clone(),
        },
    ));
    tasks.spawn(route_loop(
        route_policy,
        config.routes.clone(),
        route_receiver,
        runtime_state.clone(),
    ));
    tasks.spawn(tuner_loop(
        connection.clone(),
        metrics,
        tune_sender,
        runtime_state.clone(),
        ticket_partition_label(
            &config.network_id,
            config.cover_profile_id,
            QUIC_WIRE_VERSION,
        ),
    ));
    control_sender
        .send(TxControl::Send(local_presence.encode()?))
        .await
        .context("V2 TX task stopped before Presence advertisement")?;

    let outcome = tokio::select! {
        signal = shutdown.as_mut() => {
            signal?;
            info!("received V2 shutdown signal");
            Ok(())
        },
        result = tasks.join_next() => match result {
            Some(Ok(result)) => result.context("V2 dataplane task stopped"),
            Some(Err(error)) => Err(error).context("V2 dataplane task panicked"),
            None => bail!("V2 dataplane has no active tasks"),
        },
    };
    connection.close(0_u8.into(), b"V2 shutdown");
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    endpoint.close().await;
    outcome
}

fn endpoint_bind_addresses(bind: SocketAddr) -> Vec<SocketAddr> {
    match bind.ip() {
        std::net::IpAddr::V4(address) if address.is_unspecified() => vec![
            bind,
            SocketAddr::new(
                std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                bind.port(),
            ),
        ],
        std::net::IpAddr::V6(address) if address.is_unspecified() => vec![
            SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                bind.port(),
            ),
            bind,
        ],
        _ => vec![bind],
    }
}

/// One authenticated logical peer session. Path migration and direct/DERP
/// candidates remain inside this single end-to-end QUIC connection; V2 never
/// creates parallel congestion-control lanes for the same peer.
#[derive(Debug, Clone)]
struct PeerSessionV2 {
    id: AdjacencyIdV2,
    remote_id: EndpointId,
    connection: Connection,
    negotiated: NegotiatedSessionV2,
}

#[derive(Debug)]
enum MeshTxCommandV2 {
    Records {
        flow_id: u64,
        class: TrafficClass,
        priority: bool,
        route: ResolvedRouteV2,
        overlay_hop_limit: u8,
        records: Vec<TrainRecord>,
        trace_probe: Option<TraceProbeTag>,
        ingress_permits: Vec<OwnedSemaphorePermit>,
    },
    Forward {
        flow_id: u64,
        cells: Vec<Bytes>,
    },
    Control(TxControl),
}

#[derive(Debug)]
struct MeshDatagramV2 {
    incoming: AdjacencyIdV2,
    datagrams: Vec<Bytes>,
}

#[derive(Debug)]
struct MeshControlRecordV2 {
    incoming: AdjacencyIdV2,
    bytes: Bytes,
}

#[derive(Debug)]
struct MeshRepairDeliveryV2 {
    incoming: AdjacencyIdV2,
    response: RepairResponseV2,
}

#[derive(Debug)]
struct MeshPathMtuEventV2 {
    incoming: AdjacencyIdV2,
    oam: OamPathMtuExceededV2,
}

#[derive(Debug)]
struct MeshRxMetricsV2 {
    tun: Arc<RuntimeMetrics>,
    adjacencies: HashMap<AdjacencyIdV2, Arc<RuntimeMetrics>>,
}

#[derive(Debug)]
struct MeshFlowStateV2 {
    classifier: FlowClassifier,
    last_seen: Duration,
    lease: crate::protocol::v2::routing::FlowRouteLeaseV2,
    effective_route: ResolvedRouteV2,
    path_mtu_generation: u64,
}

#[derive(Debug, Default)]
struct RoutePmtuConstraintsV2 {
    values: ArcSwap<HashMap<(u32, u32), u16>>,
    generation: AtomicU64,
}

impl RoutePmtuConstraintsV2 {
    fn constrain(&self, route_epoch: u32, route_label: RouteLabelV2, maximum: u16) {
        let current = self.values.load_full();
        let key = (route_epoch, route_label.0);
        if current
            .get(&key)
            .is_some_and(|existing| *existing <= maximum)
        {
            return;
        }
        let mut next = if current.len() >= MAX_PATH_MTU_CONSTRAINTS {
            HashMap::default()
        } else {
            (*current).clone()
        };
        next.entry(key)
            .and_modify(|existing| *existing = (*existing).min(maximum))
            .or_insert(maximum);
        self.values.store(Arc::new(next));
        self.generation.fetch_add(1, Ordering::Release);
    }

    fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    fn apply(&self, mut route: ResolvedRouteV2) -> ResolvedRouteV2 {
        if let Some(maximum) = self
            .values
            .load()
            .get(&(route.route_epoch, route.route_label.0))
        {
            route.maximum_datagram_size = route.maximum_datagram_size.min(*maximum);
        }
        route
    }
}

async fn run_mesh(
    config: V2RuntimeConfig,
    endpoint: Endpoint,
    derp_transport: Option<Arc<DerpTransport>>,
    secret_key: SecretKey,
    local_id: EndpointId,
    shutdown: &mut ShutdownFuture,
    runtime_state: Arc<V2RuntimeState>,
) -> Result<()> {
    ensure!(
        config
            .mesh_peers
            .iter()
            .all(|peer| peer.endpoint_id != local_id),
        "V2 mesh peer list contains the local EndpointId"
    );
    let adjacencies = tokio::select! {
        // Mesh establishment includes dial/accept and SessionHello for every
        // adjacency, so it too must remain cancellable before tasks exist.
        biased;
        signal = shutdown.as_mut() => {
            signal?;
            info!("received V2 mesh shutdown signal during adjacency establishment");
            endpoint.close().await;
            return Ok(());
        }
        result = establish_mesh_adjacencies(&endpoint, &config, local_id, derp_transport) => result?,
    };
    ensure!(!adjacencies.is_empty(), "V2 mesh has no active adjacency");
    for adjacency in &adjacencies {
        runtime_state.mark_connected(&adjacency.connection);
    }
    info!(
        peers = adjacencies.len(),
        "V2 authenticated mesh adjacencies active"
    );

    let (local_overlay_v4, local_overlay_v6) = local_overlay_addresses(&config, local_id);
    let tunnel = OverlayTunnel::create(config.tun_name.clone(), config.tun_mtu)?;
    let (route_policy, _kernel_route_guard) =
        configure_mesh_tunnel(&config, local_overlay_v4, local_overlay_v6)?;
    runtime_state.publish_routes(config.routes.iter().copied());
    reconcile_v2_nat(
        &config.tun_name,
        &config.advertised_routes,
        config.subnet_nat,
    )?;
    info!(
        interface = %config.tun_name,
        local_overlay_v4 = %local_overlay_v4,
        local_overlay_v6 = %local_overlay_v6,
        queues = tunnel.queue_count(),
        "V2 mesh TUN configured"
    );

    let initial = DataplaneSnapshotV2::empty(1, *local_id.as_bytes())?;
    let snapshots = Arc::new(DataplaneSnapshotStoreV2::new(initial));
    let path_mtu_constraints = Arc::new(RoutePmtuConstraintsV2::default());
    let (tun_priority_sender, tun_priority_receiver) = mpsc::channel(TUN_PRIORITY_INPUT_SLOTS);
    // Merge kernel RSS queues before route/class admission. Sharding before
    // the single adjacency scheduler lets a busy hash bucket monopolize the
    // bounded command channel and makes equal flows receive unequal service.
    let (tun_regular_sender, tun_regular_receiver) = mpsc::channel(TUN_INPUT_SLOTS);
    let (datagram_sender, datagram_receiver) = mpsc::channel(2048);
    let (control_record_sender, control_record_receiver) = mpsc::channel(512);
    let (repair_sender, repair_receiver) = mpsc::channel(256);
    let (path_mtu_sender, path_mtu_receiver) = mpsc::channel(64);
    let (route_sender, route_receiver) = mpsc::channel(16);
    let mut commands = HashMap::<AdjacencyIdV2, mpsc::Sender<MeshTxCommandV2>>::default();
    let mut priority_commands = HashMap::<AdjacencyIdV2, mpsc::Sender<MeshTxCommandV2>>::default();
    let mut adjacency_metrics = HashMap::<AdjacencyIdV2, Arc<RuntimeMetrics>>::default();
    let mut tasks = JoinSet::new();
    let shutting_down = Arc::new(AtomicBool::new(false));
    spawn_named_mesh_task(
        &mut tasks,
        "process CPU sampler",
        shutting_down.clone(),
        cpu_sampler_loop(runtime_state.clone()),
    );

    let tun_metrics = runtime_state.tun_ingress_metrics.clone();
    let tun_regular_budget = Arc::new(Semaphore::new(TUN_REGULAR_INPUT_BYTES));
    for (queue, device) in tunnel.devices.iter().enumerate() {
        spawn_named_mesh_task(
            &mut tasks,
            format!("TUN reader queue {queue}"),
            shutting_down.clone(),
            prioritized_tun_reader(
                device.clone(),
                tun_regular_sender.clone(),
                tun_priority_sender.clone(),
                tun_regular_budget.clone(),
                tun_metrics.clone(),
            ),
        );
    }
    drop(tun_regular_sender);
    drop(tun_priority_sender);

    for adjacency in &adjacencies {
        let (command_sender, command_receiver) = mpsc::channel(4);
        let (priority_command_sender, priority_command_receiver) =
            mpsc::channel(TUN_PRIORITY_INPUT_SLOTS);
        let (tune_sender, tune_receiver) = watch::channel(None::<TuneDecisionV2>);
        commands.insert(adjacency.id, command_sender);
        priority_commands.insert(adjacency.id, priority_command_sender);
        let metrics = Arc::new(RuntimeMetrics::default());
        runtime_state.attach_metrics(adjacency.remote_id, metrics.clone());
        adjacency_metrics.insert(adjacency.id, metrics.clone());
        spawn_named_mesh_task(
            &mut tasks,
            format!("adjacency {} TX", adjacency.id.0),
            shutting_down.clone(),
            mesh_tx_loop(
                adjacency.clone(),
                command_receiver,
                priority_command_receiver,
                tune_receiver,
                metrics.clone(),
                path_mtu_sender.clone(),
                local_id,
                snapshots.clone(),
                runtime_state.clone(),
            ),
        );
        spawn_named_mesh_task(
            &mut tasks,
            format!("adjacency {} DATAGRAM reader", adjacency.id.0),
            shutting_down.clone(),
            mesh_datagram_reader(adjacency.clone(), datagram_sender.clone()),
        );
        spawn_named_mesh_task(
            &mut tasks,
            format!("adjacency {} control reader", adjacency.id.0),
            shutting_down.clone(),
            mesh_control_reader(adjacency.clone(), control_record_sender.clone()),
        );
        spawn_named_mesh_task(
            &mut tasks,
            format!("adjacency {} tuner", adjacency.id.0),
            shutting_down.clone(),
            tuner_loop(
                adjacency.connection.clone(),
                metrics,
                tune_sender,
                runtime_state.clone(),
                ticket_partition_label(
                    &config.network_id,
                    config.cover_profile_id,
                    QUIC_WIRE_VERSION,
                ),
            ),
        );
    }
    drop(datagram_sender);
    drop(control_record_sender);
    drop(path_mtu_sender);

    let mut direct_addresses = adjacencies
        .iter()
        .flat_map(|adjacency| selected_direct_addresses(&adjacency.connection, config.bind.port()))
        .collect::<Vec<_>>();
    if config.bind.port() != 0 && !config.bind.ip().is_unspecified() {
        direct_addresses.push(config.bind);
    }
    direct_addresses.sort_unstable();
    direct_addresses.dedup();
    direct_addresses.truncate(crate::protocol::v2::presence::MAX_DIRECT_ADDRESSES);

    let now = unix_secs(SystemTime::now())?;
    let local_presence = SignedPresenceV2::sign(
        PresenceBodyV2 {
            owner: local_id,
            sequence: 1,
            issued_unix_secs: now,
            expires_unix_secs: now.saturating_add(180),
            direct_addresses,
            node_addresses: vec![
                IpNet::from(std::net::IpAddr::V4(local_overlay_v4)),
                IpNet::from(std::net::IpAddr::V6(local_overlay_v6)),
            ],
            prefixes: config.advertised_routes.clone(),
            links: adjacencies
                .iter()
                .map(|adjacency| PresenceLinkV2 {
                    peer: adjacency.remote_id,
                    cost: selected_path_cost(&adjacency.connection),
                    healthy: true,
                    // QUIC frequently exposes its conservative 1,162-byte
                    // floor for a few milliseconds after SessionHello. Start
                    // at the authenticated negotiated ceiling; a real PMTU
                    // reduction is fed back immediately by reliable OAM and
                    // later confirmed by Presence refresh.
                    maximum_datagram_size: adjacency.negotiated.limits.max_datagram_size,
                })
                .collect(),
            transit_enabled: config.transit_enabled,
        },
        &secret_key,
        &config.network_id,
    )?;

    spawn_named_mesh_task(
        &mut tasks,
        "regular TUN dispatcher",
        shutting_down.clone(),
        mesh_tun_loop(
            tun_regular_receiver,
            snapshots.clone(),
            commands.clone(),
            priority_commands.clone(),
            path_mtu_constraints.clone(),
            adjacency_metrics.clone(),
            false,
        ),
    );
    spawn_named_mesh_task(
        &mut tasks,
        "priority TUN dispatcher",
        shutting_down.clone(),
        mesh_tun_loop(
            tun_priority_receiver,
            snapshots.clone(),
            commands.clone(),
            priority_commands,
            path_mtu_constraints.clone(),
            adjacency_metrics.clone(),
            true,
        ),
    );
    spawn_named_mesh_task(
        &mut tasks,
        "DATAGRAM dispatcher",
        shutting_down.clone(),
        mesh_datagram_loop(
            adjacencies.clone(),
            datagram_receiver,
            repair_receiver,
            tunnel.writer(),
            snapshots.clone(),
            commands.clone(),
            MeshRxMetricsV2 {
                tun: tun_metrics,
                adjacencies: adjacency_metrics.clone(),
            },
        ),
    );
    spawn_named_mesh_task(
        &mut tasks,
        "control manager",
        shutting_down.clone(),
        mesh_control_loop(
            config.network_id.clone(),
            local_id,
            local_presence,
            secret_key,
            adjacencies.clone(),
            control_record_receiver,
            path_mtu_receiver,
            repair_sender,
            route_sender.clone(),
            snapshots,
            commands,
            path_mtu_constraints,
            config.allow_default_routes,
            config.bind,
            adjacency_metrics,
            runtime_state.clone(),
            config.mesh_peers.len().saturating_add(1),
        ),
    );
    spawn_named_mesh_task(
        &mut tasks,
        "route manager",
        shutting_down.clone(),
        route_loop(
            route_policy,
            config.routes.clone(),
            route_receiver,
            runtime_state,
        ),
    );

    let outcome = tokio::select! {
        signal = shutdown.as_mut() => {
            signal?;
            shutting_down.store(true, Ordering::Release);
            info!("received V2 mesh shutdown signal");
            Ok(())
        },
        result = tasks.join_next() => match result {
            Some(Ok(result)) => result.context("V2 mesh task stopped"),
            Some(Err(error)) => Err(error).context("V2 mesh task panicked"),
            None => bail!("V2 mesh has no active tasks"),
        },
    };
    for adjacency in &adjacencies {
        adjacency.connection.close(0_u8.into(), b"V2 mesh shutdown");
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    endpoint.close().await;
    outcome
}

fn spawn_named_mesh_task<F>(
    tasks: &mut JoinSet<Result<()>>,
    name: impl Into<String>,
    shutting_down: Arc<AtomicBool>,
    future: F,
) where
    F: Future<Output = Result<()>> + Send + 'static,
{
    let name = name.into();
    tasks.spawn(async move {
        let result = future.await;
        if !shutting_down.load(Ordering::Acquire) {
            match &result {
                Ok(()) => warn!(task = %name, "V2 mesh task returned unexpectedly"),
                Err(error) => {
                    warn!(task = %name, error = %format_args!("{error:#}"), "V2 mesh task failed")
                }
            }
        }
        result.with_context(|| format!("V2 mesh {name} stopped"))
    });
}

async fn establish_mesh_adjacencies(
    endpoint: &Endpoint,
    config: &V2RuntimeConfig,
    local_id: EndpointId,
    derp_transport: Option<Arc<DerpTransport>>,
) -> Result<Vec<PeerSessionV2>> {
    let expected = config
        .mesh_peers
        .iter()
        .map(|peer| (peer.endpoint_id, peer.clone()))
        .collect::<HashMap<_, _>>();
    let mut dials = JoinSet::new();
    for peer in config
        .mesh_peers
        .iter()
        .filter(|peer| peer.is_dialable())
        .cloned()
    {
        let endpoint = endpoint.clone();
        let network_id = config.network_id.clone();
        let cover_sni_pool = config.cover_sni_pool.clone();
        let derp_transport = derp_transport.clone();
        let cover_profile_id = config.cover_profile_id;
        let policy = session_policy(config, local_id, peer.endpoint_id);
        let fallback_delay =
            (!mesh_should_dial(local_id, peer.endpoint_id)).then_some(Duration::from_millis(750));
        dials.spawn(async move {
            // Normally the lower EndpointId owns the dial. A delayed dial from
            // the other side makes asymmetric product bootstrap robust when
            // only that side has a usable locator. If the primary dial arrives
            // first this task is aborted when the adjacency set completes.
            if let Some(delay) = fallback_delay {
                tokio::time::sleep(delay).await;
            }
            let cover_sni = select_cover_sni_for_peer(
                &cover_sni_pool,
                &network_id,
                local_id,
                peer.endpoint_id,
                cover_profile_id,
                &peer.addresses,
            )
            .await?;
            loop {
                let connection = dial_mesh_peer(
                    &endpoint,
                    &peer,
                    &network_id,
                    &cover_sni,
                    cover_profile_id,
                    derp_transport.as_deref(),
                )
                .await?;
                match negotiate_connection_v2(&connection, &policy).await {
                    Ok(negotiated) => {
                        let remote_id = peer.endpoint_id;
                        return Ok::<_, anyhow::Error>((
                            remote_id,
                            PeerSessionV2 {
                                id: adjacency_id(local_id, remote_id),
                                remote_id,
                                connection,
                                negotiated,
                            },
                        ));
                    }
                    Err(error) => {
                        warn!(
                            peer = %peer.endpoint_id,
                            error = %format_args!("{error:#}"),
                            "retrying V2 mesh candidate after SessionHello failure"
                        );
                        connection.close(1_u8.into(), b"V2 SessionHello failed");
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                }
            }
        });
    }

    let mut adjacencies = HashMap::<EndpointId, PeerSessionV2>::default();
    while adjacencies.len() < expected.len() {
        tokio::select! {
            result = dials.join_next(), if !dials.is_empty() => {
                let Some(joined) = result else {
                    continue;
                };
                let output = match joined {
                    Ok(Ok(output)) => output,
                    Ok(Err(error)) => {
                        warn!(
                            error = %format_args!("{error:#}"),
                            "V2 mesh dial attempt stopped before adjacency establishment"
                        );
                        continue;
                    }
                    Err(error) => {
                        warn!(%error, "V2 mesh dial task panicked before adjacency establishment");
                        continue;
                    }
                };
                let (remote, adjacency) = output;
                if let Some(previous) = adjacencies.insert(remote, adjacency) {
                    previous.connection.close(
                        1_u8.into(),
                        b"duplicate outgoing V2 mesh adjacency",
                    );
                    warn!(peer = %remote, "replacing duplicate outgoing V2 mesh adjacency");
                }
            }
            incoming = endpoint.accept() => {
                let incoming = incoming.context("V2 endpoint closed during mesh establishment")?;
                let accepting = match incoming.accept() {
                    Ok(accepting) => accepting,
                    Err(error) => {
                        // A fallback dial can be rejected by the deterministic
                        // primary dialer while its legitimate connection is
                        // still in flight. Retransmits and abandoned Initials
                        // are likewise connection-local events; none may tear
                        // down the endpoint or the whole dataplane generation.
                        warn!(%error, "ignoring rejected incoming V2 mesh Initial");
                        continue;
                    }
                };
                let connection = match accepting.await {
                    Ok(connection) => connection,
                    Err(error) => {
                        warn!(%error, "ignoring failed incoming V2 mesh handshake");
                        continue;
                    }
                };
                let remote = connection.remote_id();
                let local_primary_dial = expected.get(&remote).is_some_and(|peer| {
                    peer.is_dialable() && mesh_should_dial(local_id, remote)
                });
                if !expected.contains_key(&remote) || local_primary_dial {
                    connection.close(1_u8.into(), b"unexpected V2 mesh dialer");
                    continue;
                }
                let policy = session_policy(config, local_id, remote);
                let negotiated = match negotiate_connection_v2(&connection, &policy).await {
                    Ok(negotiated) => negotiated,
                    Err(error) => {
                        warn!(
                            peer = %remote,
                            error = %format_args!("{error:#}"),
                            "ignoring incoming V2 mesh candidate that failed SessionHello"
                        );
                        connection.close(1_u8.into(), b"V2 SessionHello rejected");
                        continue;
                    }
                };
                let adjacency = PeerSessionV2 {
                    id: adjacency_id(local_id, remote),
                    remote_id: remote,
                    connection,
                    negotiated,
                };
                if let Some(previous) = adjacencies.insert(remote, adjacency) {
                    previous.connection.close(
                        1_u8.into(),
                        b"duplicate incoming V2 mesh adjacency",
                    );
                    warn!(peer = %remote, "replacing duplicate incoming V2 mesh adjacency");
                }
            }
        }
    }
    dials.abort_all();
    let mut adjacencies = adjacencies.into_values().collect::<Vec<_>>();
    adjacencies.sort_by_key(|adjacency| adjacency.remote_id);
    Ok(adjacencies)
}

fn mesh_should_dial(local: EndpointId, remote: EndpointId) -> bool {
    local < remote
}

impl V2PeerConfig {
    fn is_dialable(&self) -> bool {
        !self.addresses.is_empty() || self.derp_public_key.is_some()
    }
}

pub(crate) fn validate_cover_sni(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty() && name.len() <= 253 && name.is_ascii(),
        "V2 cover SNI is invalid"
    );
    ensure!(
        !name.starts_with('.') && !name.ends_with('.'),
        "V2 cover SNI is not canonical"
    );
    ensure!(
        name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        }),
        "V2 cover SNI contains an invalid DNS label"
    );
    Ok(())
}

fn select_cover_sni<'a>(
    pool: &'a [String],
    network_id: &str,
    local: EndpointId,
    remote: EndpointId,
    generation: u32,
) -> Result<&'a str> {
    select_cover_sni_with_preference(
        pool,
        &StdHashSet::new(),
        network_id,
        local,
        remote,
        generation,
    )
}

fn select_cover_sni_with_preference<'a>(
    pool: &'a [String],
    preferred: &StdHashSet<String>,
    network_id: &str,
    local: EndpointId,
    remote: EndpointId,
    generation: u32,
) -> Result<&'a str> {
    ensure!(!pool.is_empty(), "V2 cover SNI pool is empty");
    let mut canonical = pool
        .iter()
        .filter(|name| preferred.is_empty() || preferred.contains(*name))
        .map(String::as_str)
        .collect::<Vec<_>>();
    if canonical.is_empty() {
        canonical.extend(pool.iter().map(String::as_str));
    }
    canonical.sort_unstable();
    let (first, second) = if local < remote {
        (local, remote)
    } else {
        (remote, local)
    };
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ironet-v2/live-media-sni\0");
    hasher.update(network_id.as_bytes());
    hasher.update(&[0]);
    hasher.update(first.as_bytes());
    hasher.update(second.as_bytes());
    hasher.update(&generation.to_be_bytes());
    let digest = hasher.finalize();
    let slot =
        u64::from_be_bytes(digest.as_bytes()[..8].try_into().unwrap()) as usize % canonical.len();
    Ok(canonical[slot])
}

async fn select_cover_sni_for_peer(
    pool: &[String],
    network_id: &str,
    local: EndpointId,
    remote: EndpointId,
    generation: u32,
    direct_addresses: &[SocketAddr],
) -> Result<String> {
    let direct_ips = direct_addresses
        .iter()
        .map(SocketAddr::ip)
        .collect::<StdHashSet<_>>();
    if direct_ips.is_empty() {
        return Ok(select_cover_sni(pool, network_id, local, remote, generation)?.to_owned());
    }

    let mut lookups = JoinSet::new();
    for name in pool.iter().cloned() {
        let direct_ips = direct_ips.clone();
        lookups.spawn(async move {
            let Ok(Ok(mut resolved)) = tokio::time::timeout(
                COVER_DNS_SELECTION_TIMEOUT,
                tokio::net::lookup_host((name.as_str(), 0)),
            )
            .await
            else {
                return None;
            };
            let matches = resolved.any(|address| direct_ips.contains(&address.ip()));
            drop(resolved);
            matches.then_some(name)
        });
    }
    let mut preferred = StdHashSet::new();
    while let Some(result) = lookups.join_next().await {
        if let Ok(Some(name)) = result {
            preferred.insert(name);
        }
    }
    Ok(
        select_cover_sni_with_preference(pool, &preferred, network_id, local, remote, generation)?
            .to_owned(),
    )
}

async fn dial_mesh_peer(
    endpoint: &Endpoint,
    peer: &V2PeerConfig,
    network_id: &str,
    cover_sni: &str,
    cover_profile_id: u32,
    derp_transport: Option<&DerpTransport>,
) -> Result<Connection> {
    let mut target = peer.addresses.iter().copied().fold(
        EndpointAddr::new(peer.endpoint_id),
        EndpointAddr::with_ip_addr,
    );
    if let (Some(transport), Some(public_key)) = (derp_transport, peer.derp_public_key) {
        target = target.with_addrs(
            transport
                .remote_addresses(public_key)
                .into_iter()
                .map(TransportAddr::Custom),
        );
    }
    let mut retry_delay = Duration::from_millis(200);
    loop {
        let options = ConnectOptions::new()
            .with_visible_server_name(cover_sni.to_owned())
            .with_tls_session_partition(TlsSessionPartition::new(
                network_id.to_owned(),
                cover_profile_id,
                QUIC_WIRE_VERSION,
            ));
        match endpoint
            .connect_with_opts(target.clone(), ALPN, options)
            .await
        {
            Ok(connecting) => match connecting.await {
                Ok(connection) => return Ok(connection),
                Err(error) => {
                    warn!(peer = %peer.endpoint_id, %error, "retrying V2 mesh handshake");
                }
            },
            Err(error) => {
                warn!(peer = %peer.endpoint_id, %error, "retrying V2 mesh dial");
            }
        }
        tokio::time::sleep(retry_delay).await;
        retry_delay = retry_delay.saturating_mul(2).min(Duration::from_secs(3));
    }
}

#[allow(clippy::too_many_arguments)]
async fn mesh_tx_loop(
    adjacency: PeerSessionV2,
    mut commands: mpsc::Receiver<MeshTxCommandV2>,
    mut priority_commands: mpsc::Receiver<MeshTxCommandV2>,
    mut tuning: watch::Receiver<Option<TuneDecisionV2>>,
    metrics: Arc<RuntimeMetrics>,
    path_mtu_events: mpsc::Sender<MeshPathMtuEventV2>,
    local_id: EndpointId,
    snapshots: Arc<DataplaneSnapshotStoreV2>,
    runtime_state: Arc<V2RuntimeState>,
) -> Result<()> {
    let mut tx = V2Tx::new_for_adjacency(
        adjacency.connection,
        adjacency.negotiated,
        SchedulerLimits::default(),
        adjacency.id,
    )?;
    let mut applied_tuning = None::<TuneDecisionV2>;
    let mut cover_shaper = CoverShaperV2::default();
    loop {
        enum Event {
            Command(Option<MeshTxCommandV2>),
            Tuned,
            Sent(Result<Option<crate::protocol::v2::dataplane::SendProgress>>),
        }
        let event =
            if tx.has_pending() && admission_saturated(tx.depth(), tx_admission_high_water(&tx)) {
                tokio::select! {
                    biased;
                    command = priority_commands.recv() => Event::Command(command),
                    changed = tuning.changed() => {
                        changed.context("V2 mesh tuner stopped")?;
                        Event::Tuned
                    }
                    sent = tx.send_next() => Event::Sent(sent),
                }
            } else if tx.has_pending() {
                tokio::select! {
                    biased;
                    command = priority_commands.recv() => Event::Command(command),
                    changed = tuning.changed() => {
                        changed.context("V2 mesh tuner stopped")?;
                        Event::Tuned
                    }
                    command = commands.recv() => Event::Command(command),
                    sent = tx.send_next() => Event::Sent(sent),
                }
            } else {
                tokio::select! {
                    biased;
                    command = priority_commands.recv() => Event::Command(command),
                    changed = tuning.changed() => {
                        changed.context("V2 mesh tuner stopped")?;
                        Event::Tuned
                    }
                    command = commands.recv() => Event::Command(command),
                }
            };
        match event {
            Event::Command(None) => bail!("V2 mesh adjacency command channel stopped"),
            Event::Command(Some(MeshTxCommandV2::Records {
                flow_id,
                class,
                priority,
                route,
                overlay_hop_limit,
                records,
                trace_probe,
                ingress_permits: _ingress_permits,
            })) => {
                let admitted = tx.enqueue_routed_records_auto_with_priority(
                    flow_id,
                    class,
                    route,
                    overlay_hop_limit,
                    records,
                    priority,
                )?;
                ensure!(!admitted.is_empty(), "V2 mesh rejected PacketTrain");
                if let Some(trace_probe) = trace_probe {
                    // A normal trace hop is one 1 KiB record and one train. If
                    // a crafted/GSO group spans trains, correlate every train;
                    // the first authenticated OAM response retires the group.
                    for train_id in admitted {
                        runtime_state.register_trace_train(route, train_id, trace_probe);
                    }
                }
            }
            Event::Command(Some(MeshTxCommandV2::Forward { flow_id, cells })) => {
                match tx.admit_forwarded_cells(flow_id, cells)? {
                    ForwardAdmissionV2::Admitted => {}
                    ForwardAdmissionV2::QueueFull => {
                        warn!(
                            adjacency = adjacency.id.0,
                            "dropped V2 transit batch at queue limit"
                        );
                    }
                    ForwardAdmissionV2::PathMtuExceeded {
                        header,
                        observed_datagram_size,
                        maximum_datagram_size,
                    } => {
                        let observed_datagram_size = u16::try_from(observed_datagram_size)
                            .context("V2 forwarded Cell exceeds wire range")?;
                        let maximum_datagram_size = u16::try_from(maximum_datagram_size)
                            .context("V2 live adjacency PMTU exceeds wire range")?;
                        let incoming = header_incoming_adjacency(
                            header.route_label,
                            header.session_epoch,
                            adjacency.id,
                            &snapshots,
                        )?;
                        path_mtu_events
                            .send(MeshPathMtuEventV2 {
                                incoming,
                                oam: OamPathMtuExceededV2 {
                                    snapshot_generation: snapshots.load().generation(),
                                    route_epoch: header.session_epoch,
                                    route_label: RouteLabelV2::new(header.route_label)?,
                                    train_id: header.train_id,
                                    cell_sequence: header.cell_sequence,
                                    observed_datagram_size,
                                    maximum_datagram_size,
                                    incoming,
                                    reporter: *local_id.as_bytes(),
                                },
                            })
                            .await
                            .context("V2 mesh path-MTU event manager stopped")?;
                    }
                }
            }
            Event::Command(Some(MeshTxCommandV2::Control(TxControl::Send(record)))) => {
                metrics.observe_control_tx(&record);
                ensure!(tx.enqueue_control(record)?, "V2 mesh control queue is full");
            }
            Event::Command(Some(MeshTxCommandV2::Control(TxControl::Respond(request)))) => {
                let response = tx.repair_response(&request).encode()?;
                metrics.observe_control_tx(&response);
                ensure!(
                    tx.enqueue_control(response)?,
                    "V2 mesh control queue is full"
                );
            }
            Event::Tuned => {
                if let Some(decision) = *tuning.borrow_and_update()
                    && applied_tuning.is_none_or(|current| {
                        effective_tx_tuning(current) != effective_tx_tuning(decision)
                    })
                {
                    tx.apply_tuning(decision)?;
                    cover_shaper.update(decision);
                    info!(
                        adjacency = adjacency.id.0,
                        reason = ?decision.reason,
                        path_epoch = decision.path_epoch,
                        train_bytes = decision.train_target_bytes,
                        quantum_cells = decision.bulk_quantum_cells,
                        fec = ?decision.fec,
                        repair_cache_bytes = decision.repair_cache_bytes,
                        send_buffer_bytes = decision.send_buffer_bytes,
                        datagram_admission_bytes = tx.datagram_send_buffer_limit(),
                        receive_buffer_bytes = decision.receive_buffer_bytes,
                        receive_batch = decision.receive_batch,
                        cover_profile = ?decision.cover_profile,
                        cover_overhead_per_mille = decision.cover_overhead_per_mille,
                        cover_padding_bytes_per_second = decision.cover_padding_bytes_per_second,
                        "applied automatic V2 mesh tuning decision"
                    );
                    applied_tuning = Some(decision);
                }
            }
            Event::Sent(result) => {
                if let Some(progress) = result? {
                    metrics.observe_send(progress);
                    let sent_real = progress.class.is_some();
                    if sent_real {
                        metrics
                            .real_tx_bytes
                            .fetch_add(progress.bytes as u64, Ordering::Relaxed);
                    }
                    metrics
                        .cover_tx_bytes
                        .fetch_add(progress.cover_padding_bytes as u64, Ordering::Relaxed);
                    metrics
                        .pmtu_drop_bytes
                        .fetch_add(progress.dropped_bytes as u64, Ordering::Relaxed);
                    metrics
                        .pmtu_drop_datagrams
                        .fetch_add(progress.dropped_datagrams as u64, Ordering::Relaxed);
                    if sent_real && !tx.has_pending() {
                        let _ = cover_shaper.enqueue_after_real(&mut tx)?;
                    }
                }
            }
        }
        let depth = tx.depth();
        metrics.train_queue_bytes.store(
            (depth.bulk_bytes + depth.latency_bytes) as u64,
            Ordering::Relaxed,
        );
        metrics
            .latency_queue_bytes
            .store(depth.latency_bytes as u64, Ordering::Relaxed);
    }
}

fn header_incoming_adjacency(
    route_label: u32,
    route_epoch: u32,
    outgoing: AdjacencyIdV2,
    snapshots: &DataplaneSnapshotStoreV2,
) -> Result<AdjacencyIdV2> {
    let route_label = RouteLabelV2::new(route_label)?;
    match snapshots.label_action(route_epoch, route_label) {
        Some(LabelActionV2::Forward {
            expected_ingress,
            next_hop,
        }) if next_hop == outgoing => Ok(expected_ingress),
        _ => bail!("V2 path-MTU event has no reverse label action"),
    }
}

async fn mesh_datagram_reader(
    adjacency: PeerSessionV2,
    sender: mpsc::Sender<MeshDatagramV2>,
) -> Result<()> {
    // This is a non-blocking drain of DATAGRAMs that have already arrived;
    // using the negotiated hard batch bound cannot add coalescing latency and
    // strictly reduces channel wakeups compared with a feedback downshift.
    let receive_batch = AutoTuneBoundsV2::default().maximum_receive_batch;
    loop {
        let datagrams = adjacency
            .connection
            .read_datagram_batch(receive_batch)
            .await
            .context("receiving V2 mesh DATAGRAM batch")?;
        sender
            .send(MeshDatagramV2 {
                incoming: adjacency.id,
                datagrams,
            })
            .await
            .context("V2 mesh dispatcher stopped")?;
    }
}

async fn mesh_control_reader(
    adjacency: PeerSessionV2,
    sender: mpsc::Sender<MeshControlRecordV2>,
) -> Result<()> {
    let mut receiver = V2ControlRx::new(adjacency.connection, adjacency.negotiated);
    loop {
        sender
            .send(MeshControlRecordV2 {
                incoming: adjacency.id,
                bytes: receiver.receive().await?,
            })
            .await
            .context("V2 mesh control manager stopped")?;
    }
}

async fn mesh_tun_loop(
    mut input: mpsc::Receiver<TunIngressRecordV2>,
    snapshots: Arc<DataplaneSnapshotStoreV2>,
    commands: HashMap<AdjacencyIdV2, mpsc::Sender<MeshTxCommandV2>>,
    priority_commands: HashMap<AdjacencyIdV2, mpsc::Sender<MeshTxCommandV2>>,
    path_mtu_constraints: Arc<RoutePmtuConstraintsV2>,
    metrics: HashMap<AdjacencyIdV2, Arc<RuntimeMetrics>>,
    priority: bool,
) -> Result<()> {
    let started = Instant::now();
    let mut flows = HashMap::<FlowKey, MeshFlowStateV2>::default();
    let mut pending = VecDeque::<TunIngressRecordV2>::new();
    loop {
        if pending.is_empty() {
            pending.push_back(input.recv().await.context(if priority {
                "all V2 mesh priority TUN readers stopped"
            } else {
                "all V2 mesh TUN readers stopped"
            })?);
            while pending.len() < AutoTuneBoundsV2::default().maximum_receive_batch {
                match input.try_recv() {
                    Ok(record) => pending.push_back(record),
                    Err(mpsc::error::TryRecvError::Empty) => break,
                    Err(mpsc::error::TryRecvError::Disconnected) => break,
                }
            }
        }
        let records = drain_tun_ingress_batch(
            &mut pending,
            AutoTuneBoundsV2::default().maximum_receive_batch,
            if priority {
                TX_LATENCY_ADMISSION_HIGH_WATER_BYTES
            } else {
                TX_ADMISSION_BATCH_BYTES
            },
        );
        enqueue_mesh_tun_batch(
            records,
            &mut flows,
            started.elapsed(),
            &snapshots,
            &commands,
            &priority_commands,
            &path_mtu_constraints,
            &metrics,
            priority,
        )
        .await?;
        if flows.len() > MAX_CLASSIFIERS {
            let now = started.elapsed();
            flows.retain(|_, state| now.saturating_sub(state.last_seen) < CLASSIFIER_IDLE);
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn enqueue_mesh_tun_batch(
    batch: Vec<TunIngressRecordV2>,
    flows: &mut HashMap<FlowKey, MeshFlowStateV2>,
    now: Duration,
    snapshots: &DataplaneSnapshotStoreV2,
    commands: &HashMap<AdjacencyIdV2, mpsc::Sender<MeshTxCommandV2>>,
    priority_commands: &HashMap<AdjacencyIdV2, mpsc::Sender<MeshTxCommandV2>>,
    path_mtu_constraints: &RoutePmtuConstraintsV2,
    metrics: &HashMap<AdjacencyIdV2, Arc<RuntimeMetrics>>,
    priority: bool,
) -> Result<()> {
    #[derive(Default)]
    struct Group {
        records: Vec<(Bytes, Bytes)>,
        trace_probe: Option<TraceProbeTag>,
        permits: Vec<OwnedSemaphorePermit>,
    }

    let mut grouped = HashMap::<(ResolvedRouteV2, u64, TrafficClass, u8), Group>::default();
    let mut ingress = HashMap::<AdjacencyIdV2, TunIngressBatchV2>::default();
    for record in batch {
        let TunIngressRecordV2 {
            bytes: raw,
            info,
            _permit: permit,
        } = record;
        let packet = &raw[VIRTIO_NET_HDR_LEN..];
        let packet_len = packet.len();
        let trace_probe = (info.protocol == 17
            && info.destination_port == Some(crate::trace::TRACE_PORT))
        .then(|| v2_trace_probe_tag(packet))
        .flatten();
        let key = FlowKey::from(info);
        if info.destination.is_multicast() {
            continue;
        }
        let id = flow_id(key);
        let hop_limit = ip_hop_limit_validated(packet);
        if hop_limit == 0 {
            continue;
        }
        let snapshot = snapshots.load();
        if let Some(state) = flows.get_mut(&key)
            && state.lease.snapshot_generation() != snapshot.generation()
        {
            if let Err(error) = state.lease.refresh(snapshot.clone()) {
                warn!(%error, destination = %info.destination, "V2 mesh flow route disappeared");
                flows.remove(&key);
                continue;
            }
            state.effective_route = path_mtu_constraints.apply(state.lease.route());
            state.path_mtu_generation = path_mtu_constraints.generation();
        }
        if let Entry::Vacant(entry) = flows.entry(key) {
            let lease = match crate::protocol::v2::routing::FlowRouteLeaseV2::resolve(
                snapshot,
                info.destination,
            ) {
                Ok(lease) => lease,
                Err(error) => {
                    warn!(%error, destination = %info.destination, "dropped unroutable V2 mesh packet");
                    continue;
                }
            };
            entry.insert(MeshFlowStateV2 {
                classifier: FlowClassifier::new(ClassifierConfig::default(), now),
                last_seen: now,
                effective_route: path_mtu_constraints.apply(lease.route()),
                path_mtu_generation: path_mtu_constraints.generation(),
                lease,
            });
        }
        let state = flows.get_mut(&key).expect("V2 mesh flow was inserted");
        let path_mtu_generation = path_mtu_constraints.generation();
        if state.path_mtu_generation != path_mtu_generation {
            state.effective_route = path_mtu_constraints.apply(state.lease.route());
            state.path_mtu_generation = path_mtu_generation;
        }
        state.last_seen = now;
        let class = state
            .classifier
            .observe(now, packet_len, 0, info.latency_protected);
        let route = state.effective_route;
        let (metadata, data, gso) = match encode_train_record_observed(raw) {
            Ok(record) => record,
            Err(error) => {
                warn!(%error, "dropped invalid V2 mesh GSO metadata");
                continue;
            }
        };
        if !commands.contains_key(&route.adjacency) {
            warn!(
                adjacency = route.adjacency.0,
                "V2 mesh route has no live writer"
            );
            continue;
        }
        ingress
            .entry(route.adjacency)
            .or_default()
            .observe(packet_len, gso);
        let group = grouped.entry((route, id, class, hop_limit)).or_default();
        group.records.push((metadata, data));
        group.trace_probe = group.trace_probe.or(trace_probe);
        if let Some(permit) = permit {
            group.permits.push(permit);
        }
    }
    for ((route, flow_id, class, overlay_hop_limit), group) in grouped {
        let records = group
            .records
            .into_iter()
            .enumerate()
            .map(|(index, (metadata, data))| {
                Ok(TrainRecord {
                    record_id: u16::try_from(index + 1)
                        .context("V2 mesh TUN batch has too many records")?,
                    metadata,
                    data,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let sender = if priority {
            &priority_commands[&route.adjacency]
        } else {
            &commands[&route.adjacency]
        };
        sender
            .send(MeshTxCommandV2::Records {
                flow_id,
                class,
                priority,
                route,
                overlay_hop_limit,
                records,
                trace_probe: group.trace_probe,
                ingress_permits: group.permits,
            })
            .await
            .context("V2 mesh adjacency writer stopped")?;
    }
    for (adjacency, observation) in ingress {
        metrics[&adjacency].observe_tun_ingress_batch(observation);
    }
    Ok(())
}

async fn mesh_datagram_loop(
    adjacencies: Vec<PeerSessionV2>,
    mut datagrams: mpsc::Receiver<MeshDatagramV2>,
    mut repairs: mpsc::Receiver<MeshRepairDeliveryV2>,
    mut writer: crate::tunnel::OverlayTunnelWriter,
    snapshots: Arc<DataplaneSnapshotStoreV2>,
    commands: HashMap<AdjacencyIdV2, mpsc::Sender<MeshTxCommandV2>>,
    metrics: MeshRxMetricsV2,
) -> Result<()> {
    let mut receivers = HashMap::<AdjacencyIdV2, V2Rx>::default();
    for adjacency in adjacencies {
        receivers.insert(
            adjacency.id,
            V2Rx::new(
                adjacency.connection,
                adjacency.negotiated,
                minimum_receive_buffer_bytes(),
            )?,
        );
    }
    let mut repair_tick = tokio::time::interval(Duration::from_millis(10));
    repair_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut feedback_tick = tokio::time::interval(Duration::from_secs(1));
    feedback_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut feedback_sequence = 0_u64;
    loop {
        tokio::select! {
            datagram = datagrams.recv() => {
                let batch = datagram.context("all V2 mesh DATAGRAM readers stopped")?;
                let receiver = receivers
                    .get_mut(&batch.incoming)
                    .context("V2 mesh DATAGRAM has no receiver")?;
                let adjacency_metrics = metrics
                    .adjacencies
                    .get(&batch.incoming)
                    .context("V2 mesh DATAGRAM has no adjacency metrics")?;
                let evicted = apply_receive_buffer_target(receiver, adjacency_metrics)?;
                if evicted != 0 {
                    warn!(
                        incoming = batch.incoming.0,
                        evicted,
                        receive_buffer_bytes = receiver.maximum_buffered_bytes(),
                        "evicted stale V2 mesh RX state while shrinking automatic budget"
                    );
                }
                let mut forwarded = HashMap::<
                    (AdjacencyIdV2, TrafficClass, u32, u32, u64),
                    Vec<Bytes>,
                >::default();
                let mut local = ReassemblyOutput::default();
                for bytes in batch.datagrams {
                    if CoverPaddingV2::is_record(&bytes) {
                        let receiver = receivers
                            .get_mut(&batch.incoming)
                            .context("V2 mesh cover padding has no receiver")?;
                        let length = bytes.len();
                        if let Err(error) = receiver.accept_datagram(bytes) {
                            let (errors, report) =
                                adjacency_metrics.record_protocol_datagram_error();
                            if report {
                                warn!(
                                    incoming = batch.incoming.0,
                                    errors,
                                    stage = "cover",
                                    %error,
                                    "dropped malformed V2 mesh DATAGRAM; further errors are exponentially sampled"
                                );
                            }
                            continue;
                        }
                        metrics
                            .adjacencies
                            .get(&batch.incoming)
                            .context("V2 mesh cover padding has no adjacency metrics")?
                            .cover_rx_bytes
                            .fetch_add(length as u64, Ordering::Relaxed);
                        continue;
                    }
                    let disposition = match snapshots.dispatch_cell(batch.incoming, bytes) {
                        Ok(disposition) => disposition,
                        Err(error) => {
                            let (errors, report) =
                                adjacency_metrics.record_protocol_datagram_error();
                            if report {
                                warn!(
                                    incoming = batch.incoming.0,
                                    errors,
                                    stage = "cell-route",
                                    %error,
                                    "dropped malformed V2 mesh DATAGRAM; further errors are exponentially sampled"
                                );
                            }
                            continue;
                        }
                    };
                    match disposition {
                        TransitDispositionV2::Local { header, cell } => {
                            let receiver = receivers
                                .get_mut(&batch.incoming)
                                .context("V2 mesh local Cell has no receiver")?;
                            if let Err(error) = receiver.activate_route_epoch(header.session_epoch) {
                                let (errors, report) =
                                    adjacency_metrics.record_protocol_datagram_error();
                                if report {
                                    warn!(
                                        incoming = batch.incoming.0,
                                        errors,
                                        stage = "route-epoch",
                                        %error,
                                        "dropped invalid V2 mesh DATAGRAM; further errors are exponentially sampled"
                                    );
                                }
                                continue;
                            }
                            let output = match receiver.accept_routed_datagram(cell, header) {
                                Ok(output) => output,
                                Err(error) => {
                                    let (errors, report) =
                                        adjacency_metrics.record_protocol_datagram_error();
                                    if report {
                                        warn!(
                                            incoming = batch.incoming.0,
                                            errors,
                                            stage = "cell-payload",
                                            %error,
                                            "dropped malformed V2 mesh DATAGRAM; further errors are exponentially sampled"
                                        );
                                    }
                                    continue;
                                }
                            };
                            metrics.adjacencies[&batch.incoming].observe_receive(&output);
                            metrics.adjacencies[&batch.incoming]
                                .observe_local_delivery(&output);
                            local.merge(output);
                        }
                        TransitDispositionV2::Forward { next_hop, cell } => {
                            forwarded
                                .entry((
                                    next_hop,
                                    cell.header.class,
                                    cell.header.session_epoch,
                                    cell.header.route_label,
                                    cell.header.train_id,
                                ))
                                .or_default()
                                .push(cell.bytes);
                        }
                        TransitDispositionV2::TtlExpired(oam) => {
                            let sender = commands
                                .get(&oam.incoming)
                                .context("V2 mesh TTL OAM reverse adjacency is disconnected")?;
                            sender.send(MeshTxCommandV2::Control(TxControl::Send(oam.encode()?)))
                                .await.context("V2 mesh OAM writer stopped")?;
                        }
                        TransitDispositionV2::Drop(reason) => {
                            let (drops, report) = adjacency_metrics.record_route_gate_drop();
                            if report {
                                warn!(
                                    ?reason,
                                    incoming = batch.incoming.0,
                                    drops,
                                    "dropped V2 mesh Cell at route-label gate; further drops are exponentially sampled"
                                );
                            }
                        }
                    }
                }
                for ((next_hop, _class, _epoch, _label, train_id), cells) in forwarded {
                    let sender = commands
                        .get(&next_hop)
                        .context("V2 mesh transit next hop is disconnected")?;
                    sender.send(MeshTxCommandV2::Forward {
                        flow_id: train_id.max(1),
                        cells,
                    }).await.context("V2 mesh transit writer stopped")?;
                }
                write_reassembled(&mut writer, &metrics.tun, local).await?;
            }
            repair = repairs.recv() => {
                let repair = repair.context("V2 mesh control manager stopped")?;
                let receiver = receivers
                    .get_mut(&repair.incoming)
                    .context("V2 mesh Repair response has no receiver")?;
                let adjacency_metrics = metrics
                    .adjacencies
                    .get(&repair.incoming)
                    .context("V2 mesh Repair response has no adjacency metrics")?;
                let evicted = apply_receive_buffer_target(receiver, adjacency_metrics)?;
                if evicted != 0 {
                    warn!(
                        incoming = repair.incoming.0,
                        evicted,
                        receive_buffer_bytes = receiver.maximum_buffered_bytes(),
                        "evicted stale V2 mesh RX state while shrinking automatic budget"
                    );
                }
                let request_id = repair.response.request_id;
                let route_epoch = repair.response.key.session_epoch;
                match receiver.accept_repair_response_at(repair.response, Instant::now())? {
                    Some((output, observation)) => {
                        metrics.adjacencies[&repair.incoming]
                            .observe_repair_response(observation);
                        metrics.adjacencies[&repair.incoming].observe_receive(&output);
                        metrics.adjacencies[&repair.incoming].observe_local_delivery(&output);
                        write_reassembled(&mut writer, &metrics.tun, output).await?;
                    }
                    None => {
                        let (stale, report) = increment_sampled_counter(
                            &metrics.adjacencies[&repair.incoming].repair_stale_responses,
                        );
                        if report {
                            warn!(
                                incoming = repair.incoming.0,
                                request_id,
                                route_epoch,
                                stale,
                                "ignored unmatched or expired V2 mesh Repair response; further events are exponentially sampled"
                            );
                        }
                    }
                }
            }
            _ = repair_tick.tick() => {
                let now = Instant::now();
                for (&incoming, receiver) in &mut receivers {
                    let repair_batch = receiver.repair_requests_bounded(
                        now,
                        adaptive_repair_minimum_age(&metrics.adjacencies[&incoming]),
                        MAX_REPAIR_REQUESTS_PER_TICK,
                    );
                    metrics.adjacencies[&incoming].observe_repair_suppression(&repair_batch);
                    for request in repair_batch.requests {
                        metrics.adjacencies[&incoming].observe_repair_request(&request);
                        commands[&incoming]
                            .send(MeshTxCommandV2::Control(TxControl::Send(request.encode()?)))
                            .await
                            .context("V2 mesh Repair request writer stopped")?;
                    }
                }
            }
            _ = feedback_tick.tick() => {
                feedback_sequence = feedback_sequence.wrapping_add(1).max(1);
                for (&adjacency, adjacency_metrics) in &metrics.adjacencies {
                    commands[&adjacency]
                        .send(MeshTxCommandV2::Control(TxControl::Send(
                            adjacency_metrics.fec_feedback(feedback_sequence).encode()?,
                        )))
                        .await
                        .context("V2 mesh writer stopped before FEC feedback")?;
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn mesh_control_loop(
    network_id: String,
    local_id: EndpointId,
    mut local_presence: SignedPresenceV2,
    secret_key: SecretKey,
    adjacencies: Vec<PeerSessionV2>,
    mut records: mpsc::Receiver<MeshControlRecordV2>,
    mut path_mtu_events: mpsc::Receiver<MeshPathMtuEventV2>,
    repairs: mpsc::Sender<MeshRepairDeliveryV2>,
    routes: mpsc::Sender<RouteAdvertisementV2>,
    snapshots: Arc<DataplaneSnapshotStoreV2>,
    commands: HashMap<AdjacencyIdV2, mpsc::Sender<MeshTxCommandV2>>,
    path_mtu_constraints: Arc<RoutePmtuConstraintsV2>,
    allow_default_routes: bool,
    bind: SocketAddr,
    metrics: HashMap<AdjacencyIdV2, Arc<RuntimeMetrics>>,
    runtime_state: Arc<V2RuntimeState>,
    max_total_peers: usize,
) -> Result<()> {
    let mut directory = PresenceDirectoryV2::new(network_id.clone())?;
    directory.insert(local_presence.clone(), SystemTime::now())?;
    runtime_state.publish_presence_directory(&directory, max_total_peers);
    let encoded_local = local_presence.encode()?;
    for sender in commands.values() {
        sender
            .send(MeshTxCommandV2::Control(TxControl::Send(
                encoded_local.clone(),
            )))
            .await
            .context("V2 mesh writer stopped before local Presence")?;
    }
    let mut generation = 1_u64;
    let mut refresh = tokio::time::interval(Duration::from_secs(60));
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    refresh.tick().await;
    loop {
        enum Event {
            Record(MeshControlRecordV2),
            PathMtu(MeshPathMtuEventV2),
            Refresh,
        }
        let event = tokio::select! {
            record = records.recv() => {
                Event::Record(record.context("all V2 mesh control readers stopped")?)
            }
            event = path_mtu_events.recv() => {
                Event::PathMtu(event.context("all V2 mesh adjacency writers stopped")?)
            }
            _ = refresh.tick() => {
                Event::Refresh
            }
        };
        let record = match event {
            Event::Record(record) => record,
            Event::PathMtu(event) => {
                commands[&event.incoming]
                    .send(MeshTxCommandV2::Control(TxControl::Send(
                        event.oam.encode()?,
                    )))
                    .await
                    .context("V2 mesh local path-MTU OAM writer stopped")?;
                continue;
            }
            Event::Refresh => {
                refresh_local_presence_paths(&mut local_presence.body, &adjacencies, bind);
                refresh_and_publish_local_presence(
                    &network_id,
                    local_id,
                    &mut local_presence,
                    &secret_key,
                    &mut directory,
                    &mut generation,
                    &routes,
                    &snapshots,
                    &commands,
                    allow_default_routes,
                    &runtime_state,
                    max_total_peers,
                )
                .await?;
                continue;
            }
        };
        metrics
            .get(&record.incoming)
            .context("V2 control record has no adjacency metrics")?
            .observe_control_rx(&record.bytes);
        if SignedPresenceV2::is_record(&record.bytes) {
            let presence = SignedPresenceV2::decode(record.bytes)?;
            apply_mesh_presence(
                &mut directory,
                presence,
                Some(record.incoming),
                &mut generation,
                local_id,
                &routes,
                &snapshots,
                &commands,
                allow_default_routes,
                &runtime_state,
                max_total_peers,
            )
            .await?;
            continue;
        }
        if FecFeedbackV2::is_record(&record.bytes) {
            let feedback = FecFeedbackV2::decode(record.bytes)?;
            let adjacency_metrics = metrics
                .get(&record.incoming)
                .context("V2 FEC feedback has no adjacency metrics")?;
            if adjacency_metrics.apply_remote_feedback(feedback) {
                info!(
                    adjacency = record.incoming.0,
                    sequence = feedback.sequence,
                    parity_received = feedback.parity_received,
                    recovered_cells = feedback.recovered_cells,
                    wasted_parity = feedback.wasted_parity,
                    "applied authenticated V2 directional FEC feedback"
                );
            }
            continue;
        }
        if OamControlV2::is_record(&record.bytes) {
            match OamControlV2::decode(record.bytes)? {
                OamControlV2::TtlExpired(oam) => {
                    if relay_oam_reverse(
                        oam.route_epoch,
                        oam.route_label,
                        oam.encode()?,
                        record.incoming,
                        &snapshots,
                        &commands,
                    )
                    .await?
                    {
                        continue;
                    }
                    runtime_state.publish_ttl_expired(&oam);
                    info!(reporter = ?oam.reporter, hops = oam.traversed_hops, "V2 mesh TTL-expired OAM reached route source");
                }
                OamControlV2::PathMtuExceeded(oam) => {
                    if relay_oam_reverse(
                        oam.route_epoch,
                        oam.route_label,
                        oam.encode()?,
                        record.incoming,
                        &snapshots,
                        &commands,
                    )
                    .await?
                    {
                        continue;
                    }
                    path_mtu_constraints.constrain(
                        oam.route_epoch,
                        oam.route_label,
                        oam.maximum_datagram_size,
                    );
                    info!(
                        reporter = ?oam.reporter,
                        route_epoch = oam.route_epoch,
                        route_label = oam.route_label.0,
                        maximum_datagram_size = oam.maximum_datagram_size,
                        "applied V2 end-to-end path-MTU constraint"
                    );
                }
            }
            continue;
        }
        match RepairControlV2::decode(record.bytes)? {
            RepairControlV2::Request(request) => {
                match snapshots.label_action(
                    request.key.session_epoch,
                    RouteLabelV2::new(request.key.route_label)?,
                ) {
                    Some(LabelActionV2::Forward {
                        expected_ingress,
                        next_hop,
                    }) if record.incoming == next_hop => {
                        commands[&expected_ingress]
                            .send(MeshTxCommandV2::Control(TxControl::Send(request.encode()?)))
                            .await
                            .context("V2 mesh Repair request relay stopped")?;
                    }
                    None => {
                        commands[&record.incoming]
                            .send(MeshTxCommandV2::Control(TxControl::Respond(request)))
                            .await
                            .context("V2 mesh Repair source writer stopped")?;
                    }
                    _ => warn!(
                        incoming = record.incoming.0,
                        "dropped misdirected V2 Repair request"
                    ),
                }
            }
            RepairControlV2::Response(response) => {
                match snapshots.label_action(
                    response.key.session_epoch,
                    RouteLabelV2::new(response.key.route_label)?,
                ) {
                    Some(LabelActionV2::Forward {
                        expected_ingress,
                        next_hop,
                    }) if record.incoming == expected_ingress => {
                        commands[&next_hop]
                            .send(MeshTxCommandV2::Control(TxControl::Send(
                                response.encode()?,
                            )))
                            .await
                            .context("V2 mesh Repair response relay stopped")?;
                    }
                    Some(LabelActionV2::Local { expected_ingress })
                        if record.incoming == expected_ingress =>
                    {
                        repairs
                            .send(MeshRepairDeliveryV2 {
                                incoming: record.incoming,
                                response,
                            })
                            .await
                            .context("V2 mesh local Repair receiver stopped")?;
                    }
                    _ => warn!(
                        incoming = record.incoming.0,
                        "dropped misdirected V2 Repair response"
                    ),
                }
            }
        }
    }
}

fn refresh_local_presence_paths(
    body: &mut PresenceBodyV2,
    adjacencies: &[PeerSessionV2],
    bind: SocketAddr,
) -> bool {
    let mut direct_addresses = adjacencies
        .iter()
        .flat_map(|adjacency| selected_direct_addresses(&adjacency.connection, bind.port()))
        .collect::<Vec<_>>();
    if bind.port() != 0 && !bind.ip().is_unspecified() {
        direct_addresses.push(bind);
    }
    direct_addresses.sort_unstable();
    direct_addresses.dedup();
    direct_addresses.truncate(crate::protocol::v2::presence::MAX_DIRECT_ADDRESSES);

    let mut changed = body.direct_addresses != direct_addresses;
    body.direct_addresses = direct_addresses;
    for link in &mut body.links {
        let Some(adjacency) = adjacencies
            .iter()
            .find(|adjacency| adjacency.remote_id == link.peer)
        else {
            continue;
        };
        let maximum_datagram_size = adjacency
            .connection
            .max_datagram_size()
            .map(|maximum| maximum.min(adjacency.negotiated.limits.max_datagram_size.into()) as u16)
            .unwrap_or(adjacency.negotiated.limits.max_datagram_size);
        let next = PresenceLinkV2 {
            peer: link.peer,
            // Per-second transport quality belongs to the directional
            // autotuner, not the route epoch. Rewriting link cost from a
            // noisy RTT sample on every Presence lease renewal invalidated
            // otherwise identical route labels while queued Bulk Cells were
            // still draining. Keep the authenticated route cost stable for
            // the lifetime of this adjacency; health and PMTU changes below
            // still publish a genuine topology replacement.
            cost: link.cost,
            healthy: adjacency.connection.close_reason().is_none(),
            maximum_datagram_size,
        };
        changed |= *link != next;
        *link = next;
    }
    changed
}

#[allow(clippy::too_many_arguments)]
async fn refresh_and_publish_local_presence(
    network_id: &str,
    local_id: EndpointId,
    local_presence: &mut SignedPresenceV2,
    secret_key: &SecretKey,
    directory: &mut PresenceDirectoryV2,
    generation: &mut u64,
    routes: &mpsc::Sender<RouteAdvertisementV2>,
    snapshots: &DataplaneSnapshotStoreV2,
    commands: &HashMap<AdjacencyIdV2, mpsc::Sender<MeshTxCommandV2>>,
    allow_default_routes: bool,
    runtime_state: &V2RuntimeState,
    max_total_peers: usize,
) -> Result<()> {
    let now = unix_secs(SystemTime::now())?;
    local_presence.body.sequence = local_presence
        .body
        .sequence
        .checked_add(1)
        .context("V2 local Presence sequence overflow")?;
    local_presence.body.issued_unix_secs = now;
    local_presence.body.expires_unix_secs = now.saturating_add(180);
    *local_presence = SignedPresenceV2::sign(local_presence.body.clone(), secret_key, network_id)?;
    apply_mesh_presence(
        directory,
        local_presence.clone(),
        None,
        generation,
        local_id,
        routes,
        snapshots,
        commands,
        allow_default_routes,
        runtime_state,
        max_total_peers,
    )
    .await
}

async fn relay_oam_reverse(
    route_epoch: u32,
    route_label: RouteLabelV2,
    encoded: Bytes,
    incoming: AdjacencyIdV2,
    snapshots: &DataplaneSnapshotStoreV2,
    commands: &HashMap<AdjacencyIdV2, mpsc::Sender<MeshTxCommandV2>>,
) -> Result<bool> {
    let Some(LabelActionV2::Forward {
        expected_ingress,
        next_hop,
    }) = snapshots.label_action(route_epoch, route_label)
    else {
        return Ok(false);
    };
    if incoming != next_hop {
        return Ok(false);
    }
    commands[&expected_ingress]
        .send(MeshTxCommandV2::Control(TxControl::Send(encoded)))
        .await
        .context("V2 mesh reverse OAM writer stopped")?;
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
async fn apply_mesh_presence(
    directory: &mut PresenceDirectoryV2,
    presence: SignedPresenceV2,
    incoming: Option<AdjacencyIdV2>,
    generation: &mut u64,
    local_id: EndpointId,
    routes: &mpsc::Sender<RouteAdvertisementV2>,
    snapshots: &DataplaneSnapshotStoreV2,
    commands: &HashMap<AdjacencyIdV2, mpsc::Sender<MeshTxCommandV2>>,
    allow_default_routes: bool,
    runtime_state: &V2RuntimeState,
    max_total_peers: usize,
) -> Result<()> {
    let encoded = presence.encode()?;
    let owner = presence.body.owner;
    let update = directory.insert(presence, SystemTime::now())?;
    if matches!(
        update,
        PresenceUpdateV2::Duplicate | PresenceUpdateV2::Stale
    ) {
        return Ok(());
    }
    for (&adjacency, sender) in commands {
        if incoming != Some(adjacency) {
            sender
                .send(MeshTxCommandV2::Control(TxControl::Send(encoded.clone())))
                .await
                .context("V2 mesh Presence gossip writer stopped")?;
        }
    }
    if update == PresenceUpdateV2::Renewed {
        runtime_state.publish_presence_directory(directory, max_total_peers);
        debug!(%owner, "accepted V2 Presence lease renewal without route epoch churn");
        return Ok(());
    }
    *generation = generation
        .checked_add(1)
        .context("V2 mesh generation overflow")?;
    let route_epoch = u32::try_from(*generation).context("V2 mesh route epoch space exhausted")?;
    let topology = directory.compile_topology(
        *generation,
        route_epoch,
        allow_default_routes,
        SystemTime::now(),
    )?;
    let local = topology
        .snapshot(crate::protocol::v2::routing::NodeIdV2(*local_id.as_bytes()))
        .context("compiled V2 mesh topology omitted local node")?
        .clone();
    let route_count = local.route_count();
    let label_count = local.label_count();
    snapshots.publish(local)?;
    let mut learned_prefixes = directory
        .records()
        .filter(|presence| presence.body.owner != local_id)
        .flat_map(|presence| {
            presence
                .body
                .node_addresses
                .iter()
                .chain(&presence.body.prefixes)
                .copied()
        })
        .collect::<Vec<_>>();
    learned_prefixes
        .sort_by_key(|prefix| (prefix.addr().is_ipv6(), prefix.addr(), prefix.prefix_len()));
    learned_prefixes.dedup();
    routes
        .send(RouteAdvertisementV2 {
            generation: *generation,
            prefixes: learned_prefixes,
        })
        .await
        .context("V2 mesh route manager stopped")?;
    runtime_state.publish_presence_directory(directory, max_total_peers);
    info!(
        %owner,
        ?update,
        generation = *generation,
        route_epoch,
        route_count,
        label_count,
        "published authenticated V2 mesh snapshot"
    );
    Ok(())
}

async fn establish_connection(
    endpoint: &Endpoint,
    config: &V2RuntimeConfig,
    derp_transport: Option<&DerpTransport>,
) -> Result<Connection> {
    if config.dialing() {
        let peer_id = config.peer_id.expect("dialing requires peer ID");
        let mut target = config
            .peer_addresses
            .iter()
            .copied()
            .fold(EndpointAddr::new(peer_id), EndpointAddr::with_ip_addr);
        if let (Some(transport), Some(public_key)) = (derp_transport, config.peer_derp_public_key) {
            target = target.with_addrs(
                transport
                    .remote_addresses(public_key)
                    .into_iter()
                    .map(TransportAddr::Custom),
            );
        }
        let options = ConnectOptions::new()
            .with_visible_server_name(
                select_cover_sni_for_peer(
                    &config.cover_sni_pool,
                    &config.network_id,
                    endpoint.id(),
                    peer_id,
                    config.cover_profile_id,
                    &config.peer_addresses,
                )
                .await?,
            )
            .with_tls_session_partition(TlsSessionPartition::new(
                config.network_id.clone(),
                config.cover_profile_id,
                QUIC_WIRE_VERSION,
            ));
        return endpoint
            .connect_with_opts(target, ALPN, options)
            .await
            .context("starting V2 QUIC connection")?
            .await
            .context("establishing V2 QUIC connection");
    }
    loop {
        let incoming = endpoint
            .accept()
            .await
            .context("V2 QUIC endpoint closed while accepting")?;
        let connection = incoming
            .accept()
            .context("accepting V2 QUIC handshake")?
            .await
            .context("establishing incoming V2 QUIC connection")?;
        if config
            .peer_id
            .is_none_or(|expected| expected == connection.remote_id())
        {
            return Ok(connection);
        }
        connection.close(1_u8.into(), b"unexpected V2 peer");
    }
}

fn session_policy(
    config: &V2RuntimeConfig,
    local_id: EndpointId,
    remote_id: EndpointId,
) -> SessionPolicyV2 {
    SessionPolicyV2 {
        network_id: config.network_id.clone(),
        local_id,
        remote_id,
        role: ConnectionRole::Data,
        expected_remote_role: Some(ConnectionRole::Data),
        capabilities: capability::KNOWN,
        limits: WireLimitsV2 {
            max_datagram_size: 1382,
            max_control_size: 1024 * 1024,
            max_train_size: 64 * 1024,
            max_record_size: u16::MAX as u32,
            max_cells_per_train: 256,
            max_active_trains: 1024,
        },
        cover_profile_id: config.cover_profile_id,
    }
}

/// Read hard latency traffic into a reserved ingress lane. The mesh runtime
/// drives regular and priority dispatchers independently. Ordinary traffic
/// is byte-bounded with backpressure rather than userspace tail-drop: dropping
/// an inner TCP packet here is invisible to QUIC/BBR and previously collapsed
/// throughput long before the real underlay bottleneck was reached.
async fn prioritized_tun_reader(
    device: Arc<tun_rs::AsyncDevice>,
    regular: mpsc::Sender<TunIngressRecordV2>,
    priority: mpsc::Sender<TunIngressRecordV2>,
    regular_budget: Arc<Semaphore>,
    metrics: Arc<RuntimeMetrics>,
) -> Result<()> {
    let mut pool = PacketSlotPool::with_payload_sizes(1, 0, RAW_TUN_BYTES, RAW_TUN_BYTES);
    let mut split_pool = PacketSlotPool::with_payload_sizes(
        IDEAL_BATCH_SIZE,
        0,
        VIRTIO_NET_HDR_LEN + 4 * 1024,
        RAW_TUN_BYTES,
    );
    let mut split_sizes = vec![0_usize; IDEAL_BATCH_SIZE];
    loop {
        let length = device
            .recv(&mut pool.slots_mut()[0])
            .await
            .context("reading raw prioritized V2 TUN record")?;
        if length <= VIRTIO_NET_HDR_LEN {
            pool.recycle_empty(0);
            warn!(length, "dropped truncated raw V2 TUN record");
            continue;
        }
        let info = match inspect_ip_packet(&pool.slots_mut()[0][VIRTIO_NET_HDR_LEN..length]) {
            Ok(info) => info,
            Err(error) => {
                warn!(%error, "dropped invalid V2 IP input at TUN admission");
                continue;
            }
        };
        metrics.tun_tx_packets.fetch_add(1, Ordering::Relaxed);
        if info.latency_protected {
            let record = pool.take(0, length);
            if let Some((kind, sequence)) = icmpv4_echo_probe(&record[VIRTIO_NET_HDR_LEN..]) {
                tracing::trace!(
                    target: "ironet::latency_probe",
                    stage = "tun-read",
                    kind,
                    sequence,
                    "V2 ICMP latency probe"
                );
            }
            priority
                .send(TunIngressRecordV2::priority(record, info))
                .await
                .context("V2 priority TX task stopped")?;
        } else if regular.capacity() > 0 && regular_budget.available_permits() >= length {
            // The uncontended path retains the kernel's GSO aggregate and its
            // zero-copy recycling allocation.
            let record = pool.take(0, length);
            try_admit_regular_tun_record(&regular, &regular_budget, record, info, &metrics)?;
        } else {
            // Admission overload must not stop reading the TUN: doing so moves
            // the queue into the opaque kernel/TUN ring and leaves ICMP, ACKs
            // and FINs behind seconds of stale bulk data. If this is a large
            // TCP/UDP GSO record, split it before controlled tail shedding so
            // one admission miss does not erase up to 64 KiB of inner TCP.
            let header = VirtioNetHdr::decode(&pool.slots_mut()[0][..VIRTIO_NET_HDR_LEN])
                .context("decoding overloaded V2 TUN virtio header")?;
            if header.gso_type == VIRTIO_NET_HDR_GSO_NONE {
                let record = pool.take(0, length);
                try_admit_regular_tun_record(&regular, &regular_budget, record, info, &metrics)?;
                continue;
            }
            split_sizes.fill(0);
            let ip_version = pool.slots_mut()[0][VIRTIO_NET_HDR_LEN] >> 4;
            let segments = gso_split(
                &mut pool.slots_mut()[0][VIRTIO_NET_HDR_LEN..length],
                header,
                split_pool.slots_mut(),
                &mut split_sizes,
                VIRTIO_NET_HDR_LEN,
                ip_version == 6,
            )
            .context("splitting overloaded V2 TUN GSO record")?;
            pool.recycle_empty(0);
            for (index, payload_len) in split_sizes.iter().copied().take(segments).enumerate() {
                split_pool.slots_mut()[index][..VIRTIO_NET_HDR_LEN].fill(0);
                let record = split_pool.take(index, VIRTIO_NET_HDR_LEN + payload_len);
                let info = match inspect_ip_packet(&record[VIRTIO_NET_HDR_LEN..]) {
                    Ok(info) => info,
                    Err(error) => {
                        warn!(%error, "dropped invalid split V2 IP input at TUN admission");
                        continue;
                    }
                };
                metrics.tun_tx_packets.fetch_add(1, Ordering::Relaxed);
                if info.latency_protected {
                    priority
                        .send(TunIngressRecordV2::priority(record, info))
                        .await
                        .context("V2 priority TX task stopped")?;
                } else {
                    try_admit_regular_tun_record(
                        &regular,
                        &regular_budget,
                        record,
                        info,
                        &metrics,
                    )?;
                }
            }
        }
    }
}

fn try_admit_regular_tun_record(
    regular: &mpsc::Sender<TunIngressRecordV2>,
    regular_budget: &Arc<Semaphore>,
    record: Bytes,
    info: crate::packet::PacketInfo,
    metrics: &RuntimeMetrics,
) -> Result<()> {
    let length = record.len();
    let permits = u32::try_from(record.len()).context("V2 TUN record length overflow")?;
    let Ok(permit) = regular_budget.clone().try_acquire_many_owned(permits) else {
        record_tun_admission_drop(metrics, length);
        return Ok(());
    };
    match regular.try_send(TunIngressRecordV2::regular(record, info, permit)) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(record)) => {
            record_tun_admission_drop(metrics, record.len());
            Ok(())
        }
        Err(mpsc::error::TrySendError::Closed(_)) => bail!("V2 TX task stopped"),
    }
}

fn record_tun_admission_drop(metrics: &RuntimeMetrics, bytes: usize) {
    let (records, sampled) = increment_sampled_counter(&metrics.tun_admission_drop_records);
    let total_bytes = metrics
        .tun_admission_drop_bytes
        .fetch_add(bytes as u64, Ordering::Relaxed)
        .saturating_add(bytes as u64);
    if sampled {
        warn!(
            records,
            total_bytes, "shed overloaded V2 regular TUN segment at observable admission edge"
        );
    }
}

struct PrioritizedTunInput {
    regular: mpsc::Receiver<TunIngressRecordV2>,
    priority: mpsc::Receiver<TunIngressRecordV2>,
}

async fn tx_loop(
    connection: Connection,
    negotiated: crate::protocol::v2::session::NegotiatedSessionV2,
    mut input: PrioritizedTunInput,
    mut tuning: watch::Receiver<Option<TuneDecisionV2>>,
    mut control: mpsc::Receiver<TxControl>,
    metrics: Arc<RuntimeMetrics>,
    route_label: u32,
) -> Result<()> {
    enum Event {
        Input(Option<TunIngressRecordV2>),
        PriorityInput(Option<TunIngressRecordV2>),
        Control(Option<TxControl>),
        Tuned,
        Sent(Result<Option<crate::protocol::v2::dataplane::SendProgress>>),
    }

    let mut tx = V2Tx::new(connection, negotiated, SchedulerLimits::default())?;
    let started = Instant::now();
    let mut classifiers = HashMap::<FlowKey, FlowState>::default();
    let mut receive_batch = 8_usize;
    let mut applied_tuning = None::<TuneDecisionV2>;
    let mut cover_shaper = CoverShaperV2::default();
    let mut deferred_input = VecDeque::<TunIngressRecordV2>::new();
    loop {
        // Preserve a bounded receive burst as one aggregation opportunity.
        // The scheduler still owns hard memory admission, while the local
        // byte ceiling prevents a 64-entry GSO burst from overshooting its
        // high-water mark. One-record admission made every PacketTrain too
        // short for a real FEC stripe and defeated train packing entirely.
        let depth = tx.depth();
        let high_water = tx_admission_high_water(&tx);
        if !admission_saturated(depth, high_water) && !deferred_input.is_empty() {
            let available =
                high_water.saturating_sub(depth.bulk_bytes.saturating_add(depth.latency_bytes));
            let batch = drain_tun_ingress_batch(
                &mut deferred_input,
                receive_batch,
                available.min(TX_ADMISSION_BATCH_BYTES),
            );
            enqueue_tun_batch(
                &mut tx,
                &mut classifiers,
                started.elapsed(),
                route_label,
                batch,
                false,
                &metrics,
            )?;
        }
        let depth = tx.depth();
        let event = if tx.has_pending() && admission_saturated(depth, high_water) {
            tokio::select! {
                biased;
                record = input.priority.recv() => Event::PriorityInput(record),
                changed = tuning.changed() => {
                    changed.context("V2 tuner stopped")?;
                    Event::Tuned
                }
                sent = tx.send_next() => Event::Sent(sent),
                command = control.recv() => Event::Control(command),
            }
        } else if tx.has_pending() || !deferred_input.is_empty() {
            tokio::select! {
                biased;
                record = input.priority.recv() => Event::PriorityInput(record),
                changed = tuning.changed() => {
                    changed.context("V2 tuner stopped")?;
                    Event::Tuned
                }
                record = input.regular.recv() => Event::Input(record),
                sent = tx.send_next() => Event::Sent(sent),
                command = control.recv() => Event::Control(command),
            }
        } else {
            tokio::select! {
                biased;
                record = input.priority.recv() => Event::PriorityInput(record),
                changed = tuning.changed() => {
                    changed.context("V2 tuner stopped")?;
                    Event::Tuned
                }
                record = input.regular.recv() => Event::Input(record),
                command = control.recv() => Event::Control(command),
            }
        };
        match event {
            Event::Tuned => {
                if let Some(decision) = *tuning.borrow_and_update() {
                    receive_batch = decision.receive_batch;
                    if applied_tuning.is_none_or(|current| {
                        effective_tx_tuning(current) != effective_tx_tuning(decision)
                    }) {
                        tx.apply_tuning(decision)?;
                        cover_shaper.update(decision);
                        info!(
                            reason = ?decision.reason,
                            train_bytes = decision.train_target_bytes,
                            quantum_cells = decision.bulk_quantum_cells,
                            fec = ?decision.fec,
                            send_buffer_bytes = decision.send_buffer_bytes,
                            datagram_admission_bytes = tx.datagram_send_buffer_limit(),
                            receive_buffer_bytes = decision.receive_buffer_bytes,
                            receive_batch,
                            cover_profile = ?decision.cover_profile,
                            cover_overhead_per_mille = decision.cover_overhead_per_mille,
                            cover_padding_bytes_per_second = decision.cover_padding_bytes_per_second,
                            "applied automatic V2 tuning decision"
                        );
                        applied_tuning = Some(decision);
                    }
                }
            }
            Event::Input(None) => bail!("all V2 TUN readers stopped"),
            Event::PriorityInput(None) => bail!("all V2 priority TUN readers stopped"),
            Event::PriorityInput(Some(first)) => {
                let mut batch = Vec::with_capacity(receive_batch);
                batch.push(first);
                while batch.len() < receive_batch {
                    match input.priority.try_recv() {
                        Ok(record) => batch.push(record),
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => break,
                    }
                }
                enqueue_tun_batch(
                    &mut tx,
                    &mut classifiers,
                    started.elapsed(),
                    route_label,
                    batch,
                    true,
                    &metrics,
                )?;
            }
            Event::Control(None) => bail!("V2 control receiver stopped"),
            Event::Control(Some(TxControl::Send(record))) => {
                metrics.observe_control_tx(&record);
                ensure!(tx.enqueue_control(record)?, "V2 control queue is full");
            }
            Event::Control(Some(TxControl::Respond(request))) => {
                let response = tx.repair_response(&request).encode()?;
                metrics.observe_control_tx(&response);
                ensure!(tx.enqueue_control(response)?, "V2 control queue is full");
            }
            Event::Input(Some(first)) => {
                let mut batch = Vec::with_capacity(receive_batch);
                batch.push(first);
                while batch.len() < receive_batch {
                    match input.regular.try_recv() {
                        Ok(record) => batch.push(record),
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => break,
                    }
                }
                deferred_input.extend(batch);
                if classifiers.len() > MAX_CLASSIFIERS {
                    let now = started.elapsed();
                    classifiers
                        .retain(|_, state| now.saturating_sub(state.last_seen) < CLASSIFIER_IDLE);
                }
            }
            Event::Sent(result) => {
                if let Some(progress) = result? {
                    metrics.observe_send(progress);
                    let sent_real = progress.class.is_some();
                    if sent_real {
                        metrics
                            .real_tx_bytes
                            .fetch_add(progress.bytes as u64, Ordering::Relaxed);
                    }
                    metrics
                        .cover_tx_bytes
                        .fetch_add(progress.cover_padding_bytes as u64, Ordering::Relaxed);
                    metrics
                        .pmtu_drop_bytes
                        .fetch_add(progress.dropped_bytes as u64, Ordering::Relaxed);
                    let previous_pmtu_drops = metrics
                        .pmtu_drop_datagrams
                        .fetch_add(progress.dropped_datagrams as u64, Ordering::Relaxed);
                    if progress.dropped_datagrams != 0 && previous_pmtu_drops == 0 {
                        warn!(
                            datagrams = progress.dropped_datagrams,
                            bytes = progress.dropped_bytes,
                            "retiring stale V2 Cells after live PMTU shrink; further drops are counted without per-quantum logs"
                        );
                    }
                    if sent_real && !tx.has_pending() && deferred_input.is_empty() {
                        let _ = cover_shaper.enqueue_after_real(&mut tx)?;
                    }
                }
            }
        }
        let depth = tx.depth();
        metrics.train_queue_bytes.store(
            (depth.bulk_bytes + depth.latency_bytes) as u64,
            Ordering::Relaxed,
        );
        metrics
            .latency_queue_bytes
            .store(depth.latency_bytes as u64, Ordering::Relaxed);
    }
}

fn tx_admission_high_water(tx: &V2Tx) -> usize {
    tx.datagram_send_buffer_limit().clamp(
        TX_ADMISSION_BATCH_BYTES,
        TX_APPLICATION_ADMISSION_HIGH_WATER_BYTES,
    )
}

fn admission_saturated(
    depth: crate::protocol::v2::scheduler::SchedulerDepth,
    application_high_water: usize,
) -> bool {
    depth.bulk_bytes >= TX_BULK_ADMISSION_HIGH_WATER_BYTES.min(application_high_water)
        || depth.latency_bytes >= TX_LATENCY_ADMISSION_HIGH_WATER_BYTES.min(application_high_water)
        || depth.bulk_bytes.saturating_add(depth.latency_bytes) >= application_high_water
}

fn repair_minimum_age_for_rtt(rtt: Duration) -> Duration {
    // QUIC DATAGRAM delivery, PacketTrain scheduling and a shallow policer can
    // reorder Cells across several scheduler/ACK rounds even on a 3-6 ms path.
    // A 10 ms floor treated that harmless delay as loss and sent reliable
    // responses into the same bottleneck. Eight RTTs with a 50 ms floor still
    // beats the inner TCP RTO, while forward progress restarts this grace
    // period and the ceiling keeps Repair useful after migration.
    rtt.saturating_mul(8)
        .clamp(Duration::from_millis(50), Duration::from_secs(1))
}

fn adaptive_repair_minimum_age(metrics: &RuntimeMetrics) -> Duration {
    let micros = metrics.repair_minimum_age_micros.load(Ordering::Relaxed);
    let base = if micros == 0 {
        Duration::from_millis(100)
    } else {
        Duration::from_micros(micros)
    };
    match RepairWaitPolicyV2::from_metrics_code(metrics.repair_wait_policy.load(Ordering::Relaxed))
    {
        RepairWaitPolicyV2::Eager => base / 2,
        // Doubling the RTT-derived wait adds roughly one RTT of reorder
        // tolerance; the ceiling keeps Repair responsive after migration.
        RepairWaitPolicyV2::Patient => base.saturating_mul(2).min(Duration::from_secs(2)),
        RepairWaitPolicyV2::HostDefault | RepairWaitPolicyV2::AfterFecWindow => base,
    }
}

fn drain_tun_ingress_batch(
    pending: &mut VecDeque<TunIngressRecordV2>,
    maximum_records: usize,
    maximum_bytes: usize,
) -> Vec<TunIngressRecordV2> {
    let mut output = Vec::with_capacity(maximum_records.min(pending.len()));
    let mut bytes = 0_usize;
    while output.len() < maximum_records {
        let Some(next) = pending.front() else {
            break;
        };
        if !output.is_empty() && bytes.saturating_add(next.len()) > maximum_bytes {
            break;
        }
        let next = pending.pop_front().expect("front record remains queued");
        bytes = bytes.saturating_add(next.len());
        output.push(next);
    }
    output
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EffectiveTuneV2 {
    train_target_bytes: usize,
    bulk_quantum_cells: usize,
    fec: Option<crate::protocol::v2::fec::FecGeometryV2>,
    repair_cache_bytes: usize,
    repair_retention_millis: u32,
    send_buffer_bytes: usize,
    receive_batch: usize,
    cover_profile: CoverTrafficProfileV2,
    cover_overhead_per_mille: u16,
    cover_padding_bytes_per_second: u64,
}

fn effective_tx_tuning(decision: TuneDecisionV2) -> EffectiveTuneV2 {
    EffectiveTuneV2 {
        train_target_bytes: decision.train_target_bytes,
        bulk_quantum_cells: decision.bulk_quantum_cells,
        fec: decision.fec,
        repair_cache_bytes: decision.repair_cache_bytes,
        repair_retention_millis: decision.repair_retention_millis,
        send_buffer_bytes: decision.send_buffer_bytes,
        receive_batch: decision.receive_batch,
        cover_profile: decision.cover_profile,
        cover_overhead_per_mille: decision.cover_overhead_per_mille,
        cover_padding_bytes_per_second: decision.cover_padding_bytes_per_second,
    }
}

fn enqueue_tun_batch(
    tx: &mut V2Tx,
    classifiers: &mut HashMap<FlowKey, FlowState>,
    now: Duration,
    route_label: u32,
    records: Vec<TunIngressRecordV2>,
    hard_latency: bool,
    metrics: &RuntimeMetrics,
) -> Result<()> {
    // A Cell has one fixed routing shim. Grouping by ingress IP hop limit
    // makes its overlay budget the exact TTL/Hop-Limit of every contained
    // record instead of weakening it to a train-wide default.
    let mut grouped = HashMap::<(u64, TrafficClass, u8), Vec<(Bytes, Bytes)>>::default();
    let mut ingress = TunIngressBatchV2::default();
    for record in records {
        let TunIngressRecordV2 {
            bytes: raw,
            info,
            _permit: _,
        } = record;
        let packet = &raw[VIRTIO_NET_HDR_LEN..];
        let packet_len = packet.len();
        let key = FlowKey::from(info);
        let flow_id = flow_id(key);
        let overlay_hop_limit = ip_hop_limit_validated(packet);
        if overlay_hop_limit == 0 {
            warn!("dropped V2 IP input with exhausted hop limit");
            continue;
        }
        let state = classifiers.entry(key).or_insert_with(|| FlowState {
            classifier: FlowClassifier::new(ClassifierConfig::default(), now),
            last_seen: now,
        });
        state.last_seen = now;
        let class = state
            .classifier
            .observe(now, packet_len, 0, info.latency_protected);
        let (metadata, data, gso) = match encode_train_record_observed(raw) {
            Ok(record) => record,
            Err(error) => {
                warn!(%error, "dropped invalid V2 GSO metadata");
                continue;
            }
        };
        ingress.observe(packet_len, gso);
        grouped
            .entry((flow_id, class, overlay_hop_limit))
            .or_default()
            .push((metadata, data));
    }
    for ((flow_id, class, overlay_hop_limit), records) in grouped {
        let records = records
            .into_iter()
            .enumerate()
            .map(|(index, (metadata, data))| {
                Ok(crate::protocol::v2::train::TrainRecord {
                    record_id: u16::try_from(index + 1)
                        .context("V2 TUN batch has too many records")?,
                    metadata,
                    data,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if hard_latency {
            tracing::trace!(
                target: "ironet::latency_probe",
                stage = "scheduler-admit",
                flow_id,
                records = records.len(),
                "V2 strict latency batch"
            );
        }
        let admitted = tx.enqueue_records_auto_with_hop_limit_and_priority(
            flow_id,
            class,
            route_label,
            overlay_hop_limit,
            records,
            hard_latency,
        )?;
        ensure!(
            !admitted.is_empty(),
            "V2 scheduler rejected a TUN PacketTrain"
        );
    }
    metrics.observe_tun_ingress_batch(ingress);
    Ok(())
}

async fn rx_loop(
    connection: Connection,
    negotiated: crate::protocol::v2::session::NegotiatedSessionV2,
    mut writer: crate::tunnel::OverlayTunnelWriter,
    metrics: Arc<RuntimeMetrics>,
    control: mpsc::Sender<TxControl>,
    mut repaired: mpsc::Receiver<RepairResponseV2>,
    route: RxRouteContext,
) -> Result<()> {
    let mut rx = V2Rx::new(connection, negotiated, minimum_receive_buffer_bytes())?;
    // This only drains DATAGRAMs already buffered by QUIC, so using the
    // negotiated maximum never waits or adds latency. RX FEC state follows
    // the peer's wire data and must not subscribe to the local TX tuner.
    let receive_batch = AutoTuneBoundsV2::default().maximum_receive_batch;
    let mut repair_tick = tokio::time::interval(Duration::from_millis(10));
    repair_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut feedback_tick = tokio::time::interval(Duration::from_secs(1));
    feedback_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut feedback_sequence = 0_u64;
    loop {
        enum Event {
            Cells(Result<Vec<Bytes>>),
            Repair(Option<RepairResponseV2>),
            Tick,
            Feedback,
        }
        let event = tokio::select! {
            datagrams = rx.receive_datagram_batch(receive_batch) => Event::Cells(datagrams),
            response = repaired.recv() => Event::Repair(response),
            _ = repair_tick.tick() => Event::Tick,
            _ = feedback_tick.tick() => Event::Feedback,
        };
        let output = match event {
            Event::Cells(datagrams) => {
                let evicted = apply_receive_buffer_target(&mut rx, &metrics)?;
                if evicted != 0 {
                    warn!(
                        evicted,
                        receive_buffer_bytes = rx.maximum_buffered_bytes(),
                        "evicted stale V2 RX state while shrinking automatic budget"
                    );
                }
                let mut combined = ReassemblyOutput::default();
                for bytes in datagrams? {
                    if CoverPaddingV2::is_record(&bytes) {
                        let length = bytes.len();
                        if let Err(error) = rx.accept_datagram(bytes) {
                            let (errors, report) = metrics.record_protocol_datagram_error();
                            if report {
                                warn!(
                                    errors,
                                    stage = "cover",
                                    %error,
                                    "dropped malformed V2 DATAGRAM; further errors are exponentially sampled"
                                );
                            }
                            continue;
                        }
                        metrics
                            .cover_rx_bytes
                            .fetch_add(length as u64, Ordering::Relaxed);
                        continue;
                    }
                    let disposition = match route.snapshot.dispatch_cell(route.incoming, bytes) {
                        Ok(disposition) => disposition,
                        Err(error) => {
                            let (errors, report) = metrics.record_protocol_datagram_error();
                            if report {
                                warn!(
                                    errors,
                                    stage = "cell-route",
                                    %error,
                                    "dropped malformed V2 DATAGRAM; further errors are exponentially sampled"
                                );
                            }
                            continue;
                        }
                    };
                    match disposition {
                        TransitDispositionV2::Local { header, cell } => {
                            let output = match rx.accept_routed_datagram(cell, header) {
                                Ok(output) => output,
                                Err(error) => {
                                    let (errors, report) = metrics.record_protocol_datagram_error();
                                    if report {
                                        warn!(
                                            errors,
                                            stage = "cell-payload",
                                            %error,
                                            "dropped malformed V2 DATAGRAM; further errors are exponentially sampled"
                                        );
                                    }
                                    continue;
                                }
                            };
                            metrics.observe_receive(&output);
                            combined.merge(output);
                        }
                        TransitDispositionV2::Drop(reason) => {
                            let (drops, report) = metrics.record_route_gate_drop();
                            if report {
                                warn!(
                                    ?reason,
                                    drops,
                                    "dropped V2 Cell at route-label gate; further drops are exponentially sampled"
                                );
                            }
                        }
                        TransitDispositionV2::Forward { .. } => {
                            bail!("single-peer V2 runtime received a transit Cell")
                        }
                        TransitDispositionV2::TtlExpired(_) => {
                            bail!("single-peer V2 runtime produced transit TTL OAM")
                        }
                    }
                }
                Some(combined)
            }
            Event::Repair(Some(response)) => {
                let evicted = apply_receive_buffer_target(&mut rx, &metrics)?;
                if evicted != 0 {
                    warn!(
                        evicted,
                        receive_buffer_bytes = rx.maximum_buffered_bytes(),
                        "evicted stale V2 RX state while shrinking automatic budget"
                    );
                }
                let request_id = response.request_id;
                let route_epoch = response.key.session_epoch;
                match rx.accept_repair_response_at(response, Instant::now())? {
                    Some((output, observation)) => {
                        metrics.observe_repair_response(observation);
                        metrics.observe_receive(&output);
                        Some(output)
                    }
                    None => {
                        let (stale, report) =
                            increment_sampled_counter(&metrics.repair_stale_responses);
                        if report {
                            warn!(
                                request_id,
                                route_epoch,
                                stale,
                                "ignored unmatched or expired V2 Repair response; further events are exponentially sampled"
                            );
                        }
                        None
                    }
                }
            }
            Event::Repair(None) => bail!("V2 Repair control receiver stopped"),
            Event::Tick => {
                let repair_batch = rx.repair_requests_bounded(
                    Instant::now(),
                    adaptive_repair_minimum_age(&metrics),
                    MAX_REPAIR_REQUESTS_PER_TICK,
                );
                metrics.observe_repair_suppression(&repair_batch);
                for request in repair_batch.requests {
                    metrics.observe_repair_request(&request);
                    control
                        .send(TxControl::Send(request.encode()?))
                        .await
                        .context("V2 TX control task stopped")?;
                }
                None
            }
            Event::Feedback => {
                feedback_sequence = feedback_sequence.wrapping_add(1).max(1);
                control
                    .send(TxControl::Send(
                        metrics.fec_feedback(feedback_sequence).encode()?,
                    ))
                    .await
                    .context("V2 TX control task stopped before FEC feedback")?;
                None
            }
        };
        if let Some(output) = output {
            write_reassembled(&mut writer, &metrics, output).await?;
        }
    }
}

async fn write_reassembled(
    writer: &mut crate::tunnel::OverlayTunnelWriter,
    metrics: &RuntimeMetrics,
    output: ReassemblyOutput,
) -> Result<()> {
    if output.records.is_empty() {
        return Ok(());
    }
    let count = output.records.len();
    let bytes = output.records.iter().fold(0_u64, |total, record| {
        total.saturating_add(u64::try_from(record.total_len).unwrap_or(u64::MAX))
    });
    let mut ordinary = Vec::new();
    let mut offloaded = Vec::new();
    for record in output.records {
        if record.metadata.is_empty() {
            ordinary.push(completed_record_to_tun(record)?);
        } else {
            let header = crate::protocol::v2::gso::virtio_header_for_record_fragments(
                record.metadata,
                record.total_len,
                &record.fragments,
            )?;
            offloaded.push((header, record.fragments));
        }
    }
    if !ordinary.is_empty() {
        for record in &ordinary {
            if let Some((kind, sequence)) = icmpv4_echo_probe(&record[VIRTIO_NET_HDR_LEN..]) {
                tracing::trace!(
                    target: "ironet::latency_probe",
                    stage = "tun-write",
                    kind,
                    sequence,
                    "V2 ICMP latency probe"
                );
            }
        }
        writer
            .send_owned(0, &mut ordinary)
            .await
            .context("batch-writing ordinary V2 TUN records")?;
    }
    if !offloaded.is_empty() {
        for (header, fragments) in offloaded {
            writer
                .send_raw_vectored(0, &header, &fragments)
                .await
                .context("gather-writing restored V2 offload record")?;
        }
    }
    metrics
        .tun_rx_packets
        .fetch_add(count as u64, Ordering::Relaxed);
    metrics.tun_rx_bytes.fetch_add(bytes, Ordering::Relaxed);
    Ok(())
}

async fn control_loop(
    connection: Connection,
    negotiated: crate::protocol::v2::session::NegotiatedSessionV2,
    context: ControlContextV2,
) -> Result<()> {
    let mut receiver = V2ControlRx::new(connection, negotiated);
    loop {
        let record = receiver.receive().await?;
        context.metrics.observe_control_rx(&record);
        if SignedPresenceV2::is_record(&record) {
            context
                .presences
                .send(SignedPresenceV2::decode(record)?)
                .await
                .context("V2 Presence manager stopped")?;
            continue;
        }
        if RouteAdvertisementV2::is_record(&record) {
            context
                .routes
                .send(RouteAdvertisementV2::decode(
                    record,
                    context.allow_default_routes,
                )?)
                .await
                .context("V2 route manager stopped")?;
            continue;
        }
        if FecFeedbackV2::is_record(&record) {
            context
                .metrics
                .apply_remote_feedback(FecFeedbackV2::decode(record)?);
            continue;
        }
        match RepairControlV2::decode(record)? {
            RepairControlV2::Request(request) => context
                .tx
                .send(TxControl::Respond(request))
                .await
                .context("V2 TX control task stopped")?,
            RepairControlV2::Response(response) => context
                .repaired
                .send(response)
                .await
                .context("V2 RX task stopped")?,
        }
    }
}

struct PresenceContextV2 {
    network_id: String,
    local_id: EndpointId,
    secret_key: SecretKey,
    routes: mpsc::Sender<RouteAdvertisementV2>,
    control: mpsc::Sender<TxControl>,
    allow_default_routes: bool,
    runtime_state: Arc<V2RuntimeState>,
}

async fn presence_loop(
    mut local_presence: SignedPresenceV2,
    mut updates: mpsc::Receiver<SignedPresenceV2>,
    context: PresenceContextV2,
) -> Result<()> {
    let PresenceContextV2 {
        network_id,
        local_id,
        secret_key,
        routes,
        control,
        allow_default_routes,
        runtime_state,
    } = context;
    let mut directory = PresenceDirectoryV2::new(network_id.clone())?;
    directory.insert(local_presence.clone(), SystemTime::now())?;
    runtime_state.publish_presence_directory(&directory, 2);
    let mut generation = 1_u64;
    let mut refresh = tokio::time::interval(Duration::from_secs(60));
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    refresh.tick().await;
    loop {
        let update = tokio::select! {
            update = updates.recv() => {
                update.context("V2 Presence update channel stopped")?
            }
            _ = refresh.tick() => {
                let now = unix_secs(SystemTime::now())?;
                local_presence.body.sequence = local_presence
                    .body
                    .sequence
                    .checked_add(1)
                    .context("V2 local Presence sequence overflow")?;
                local_presence.body.issued_unix_secs = now;
                local_presence.body.expires_unix_secs = now.saturating_add(180);
                local_presence = SignedPresenceV2::sign(
                    local_presence.body.clone(),
                    &secret_key,
                    &network_id,
                )?;
                control
                    .send(TxControl::Send(local_presence.encode()?))
                    .await
                    .context("V2 TX task stopped before Presence renewal")?;
                local_presence.clone()
            }
        };
        let owner = update.body.owner;
        let result = directory.insert(update, SystemTime::now())?;
        if matches!(
            result,
            PresenceUpdateV2::Duplicate | PresenceUpdateV2::Stale
        ) {
            continue;
        }
        if result == PresenceUpdateV2::Renewed {
            runtime_state.publish_presence_directory(&directory, 2);
            debug!(%owner, "accepted V2 Presence lease renewal without route epoch churn");
            continue;
        }
        generation = generation.wrapping_add(1).max(2);
        let route_epoch = u32::try_from(generation).unwrap_or_else(|_| (generation as u32).max(1));
        let topology = directory.compile_topology(
            generation,
            route_epoch,
            allow_default_routes,
            SystemTime::now(),
        )?;
        let local = topology
            .snapshot(crate::protocol::v2::routing::NodeIdV2(*local_id.as_bytes()))
            .context("compiled V2 Presence topology omitted the local node")?;
        let mut learned_prefixes = directory
            .records()
            .filter(|presence| presence.body.owner != local_id)
            .flat_map(|presence| {
                presence
                    .body
                    .node_addresses
                    .iter()
                    .chain(&presence.body.prefixes)
                    .copied()
            })
            .collect::<Vec<_>>();
        learned_prefixes
            .sort_by_key(|prefix| (prefix.addr().is_ipv6(), prefix.addr(), prefix.prefix_len()));
        learned_prefixes.dedup();
        routes
            .send(RouteAdvertisementV2 {
                generation,
                prefixes: learned_prefixes,
            })
            .await
            .context("V2 route manager stopped")?;
        runtime_state.publish_presence_directory(&directory, 2);
        info!(
            %owner,
            ?result,
            generation,
            nodes = directory.len(),
            routes = local.route_count(),
            labels = local.label_count(),
            "compiled authenticated V2 Presence topology"
        );
    }
}

async fn route_loop(
    policy: Arc<KernelRoutePolicyV2>,
    static_routes: Vec<IpNet>,
    mut updates: mpsc::Receiver<RouteAdvertisementV2>,
    runtime_state: Arc<V2RuntimeState>,
) -> Result<()> {
    let mut generation = 0_u64;
    let mut installed = Vec::<IpNet>::new();
    while let Some(update) = updates.recv().await {
        if update.generation < generation {
            warn!(
                received = update.generation,
                current = generation,
                "ignored stale V2 route advertisement"
            );
            continue;
        }
        let desired = update
            .prefixes
            .into_iter()
            .filter(|prefix| !static_routes.contains(prefix))
            .collect::<Vec<_>>();
        if update.generation == generation {
            if desired != installed {
                warn!(generation, "ignored conflicting V2 route generation replay");
            }
            continue;
        }
        for prefix in installed.iter().filter(|prefix| !desired.contains(prefix)) {
            policy.delete_route(*prefix)?;
        }
        for prefix in &desired {
            policy.replace_route(*prefix)?;
        }
        generation = update.generation;
        installed = desired;
        runtime_state.publish_routes(static_routes.iter().chain(&installed).copied());
        info!(
            generation,
            routes = installed.len(),
            "applied authenticated V2 routes"
        );
    }
    bail!("V2 route update channel stopped")
}

#[derive(Debug, Clone, Copy)]
struct AutotuneTapSampleV2<'a> {
    sampled_unix_micros: u64,
    sample_elapsed: Duration,
    telemetry: PathTelemetryV2,
    decision: TuneDecisionV2,
    utility: UtilitySample,
    wire_cost: WireCostV2,
    force_applied: bool,
    learner: Option<LearnerTraceV2>,
    policy_id: &'a str,
    policy_source: &'a str,
    shadow_policy_id: Option<&'a str>,
    shadow: Option<ShadowEvaluationV2>,
    path_identity: &'a str,
    controller_cwnd_bytes: u64,
    adaptive_cwnd_floor_bytes: u64,
}

fn autotune_tap_record(
    peer: EndpointId,
    ticket_partition: &str,
    sample: AutotuneTapSampleV2<'_>,
) -> serde_json::Value {
    let AutotuneTapSampleV2 {
        sampled_unix_micros,
        sample_elapsed,
        telemetry,
        decision,
        utility,
        wire_cost,
        force_applied,
        learner,
        policy_id,
        policy_source,
        shadow_policy_id,
        shadow,
        path_identity,
        controller_cwnd_bytes,
        adaptive_cwnd_floor_bytes,
    } = sample;
    serde_json::json!({
        "schema_version": 5,
        "peer": peer.to_string(),
        "tls_ticket_partition": ticket_partition,
        "sampled_unix_micros": sampled_unix_micros,
        "sample_interval_micros": sample_elapsed.as_micros().min(u128::from(u64::MAX)) as u64,
        "force_applied": force_applied,
        "path_identity": path_identity,
        "controller": {
            "congestion_window_bytes": controller_cwnd_bytes,
            "adaptive_cwnd_floor_bytes": adaptive_cwnd_floor_bytes,
        },
        "policy": {
            "id": policy_id,
            "source": policy_source,
            "shadow_id": shadow_policy_id,
        },
        "telemetry": {
            "path_epoch": telemetry.path_epoch,
            "reliability": format!("{:?}", telemetry.reliability),
            "rtt_micros": telemetry.rtt.as_micros().min(u128::from(u64::MAX)) as u64,
            "min_rtt_micros": telemetry.min_rtt.as_micros().min(u128::from(u64::MAX)) as u64,
            "queue_delay_micros": telemetry.queue_delay.as_micros().min(u128::from(u64::MAX)) as u64,
            "loss_ppm": telemetry.loss_ppm,
            "burst_loss_cells": telemetry.burst_loss_cells,
            "reorder_ppm": telemetry.reorder_ppm,
            "receiver_goodput_bytes_per_second": telemetry.receiver_goodput_bytes_per_second,
            "residual_loss_ppm": telemetry.residual_loss_ppm,
            "latency_sojourn_p95_micros": telemetry.latency_sojourn_p95_micros,
            "latency_sojourn_p50_micros": telemetry.latency_sojourn_p50_micros,
            "latency_sojourn_p99_micros": telemetry.latency_sojourn_p99_micros,
            "latency_queue_recently_nonempty": telemetry.latency_queue_recently_nonempty,
            "delivery_rate_bytes_per_second": telemetry.delivery_rate_bytes_per_second,
            "controller_pacing_rate_bytes_per_second": telemetry.controller_pacing_rate_bytes_per_second,
            "controller_send_quantum_bytes": telemetry.controller_send_quantum_bytes,
            "controller_state": telemetry.controller_state,
            "controller_bw_bytes_per_second": telemetry.controller_bw_bytes_per_second,
            "controller_inflight_longterm_bytes": telemetry.controller_inflight_longterm_bytes,
            "controller_guard_transitions_delta": telemetry.controller_guard_transitions_delta,
            "controller_app_limited": telemetry.controller_app_limited,
            "controller_tunables_generation": telemetry.controller_tunables_generation,
            "controller_params_generation": telemetry.controller_params_generation,
            "controller_clamped_writes": telemetry.controller_clamped_writes,
            "receive_rate_bytes_per_second": telemetry.receive_rate_bytes_per_second,
            "packets_per_second": telemetry.packets_per_second,
            "tun_ingress_bytes_per_second": telemetry.tun_ingress_bytes_per_second,
            "average_record_bytes": telemetry.average_record_bytes,
            "gso_ingress_ratio_ppm": telemetry.gso_ingress_ratio_ppm,
            "packet_train_queue_bytes": telemetry.packet_train_queue_bytes,
            "latency_queue_bytes": telemetry.latency_queue_bytes,
            "reassembly_pressure_evictions": telemetry.reassembly_pressure_evictions,
            "remote_expired_stripes_delta": telemetry.remote_expired_stripes_delta,
            "train_build_bytes_per_second": telemetry.train_build_bytes_per_second,
            "bulk_preemption_delay_average_micros": telemetry.bulk_preemption_delay_average_micros,
            "cpu_utilization_per_mille": telemetry.cpu_utilization_per_mille,
            "wasted_parity_per_mille": telemetry.wasted_parity_per_mille,
            "fec_recovery_per_mille": telemetry.fec_recovery_per_mille,
            "repair_hit_per_mille": telemetry.repair_hit_per_mille,
            "repair_completed_requests": telemetry.repair_completed_requests,
            "repair_response_latency_micros": telemetry.repair_response_latency.as_micros().min(u128::from(u64::MAX)) as u64,
            "real_traffic_bytes_per_second": telemetry.real_traffic_bytes_per_second,
        },
        "decision": {
            "reason": format!("{:?}", decision.reason),
            "path_epoch": decision.path_epoch,
            "sample_count": decision.sample_count,
            "train_target_bytes": decision.train_target_bytes,
            "bulk_quantum_cells": decision.bulk_quantum_cells,
            "fec": decision.fec.map(|geometry| serde_json::json!({
                "data_cells": geometry.data_cells,
                "parity_cells": geometry.parity_cells,
            })),
            "repair_cache_bytes": decision.repair_cache_bytes,
            "send_buffer_bytes": decision.send_buffer_bytes,
            "receive_buffer_bytes": decision.receive_buffer_bytes,
            "receive_batch": decision.receive_batch,
            "cover_profile": format!("{:?}", decision.cover_profile),
            "cover_overhead_per_mille": decision.cover_overhead_per_mille,
            "cover_padding_bytes_per_second": decision.cover_padding_bytes_per_second,
            "bbr": {
                "preset": format!("{:?}", decision.bbr.preset),
                "up_gain_milli": decision.bbr.up_gain_milli,
                "headroom_milli": decision.bbr.headroom_milli,
                "cwnd_gain_milli": decision.bbr.cwnd_gain_milli,
                "pacing_cap_bytes_per_second": decision.bbr.pacing_cap_bytes_per_second,
                "loss_is_congestion": decision.bbr.loss_is_congestion,
            },
        },
        "utility": {
            "total": utility.total,
            "components": utility.components,
            "goodput_bytes_per_second": utility.goodput_bytes_per_second,
        },
        "wire_cost": {
            "payload_bytes": wire_cost.payload_bytes,
            "parity_bytes": wire_cost.parity_bytes,
            "repair_bytes": wire_cost.repair_bytes,
            "cover_bytes": wire_cost.cover_bytes,
            "cell_envelope_bytes": wire_cost.cell_envelope_bytes,
        },
        "learner": learner.map(|trace| serde_json::json!({
            "mode": format!("{:?}", trace.mode),
            "context": {
                "rtt_class": trace.context.rtt_class,
                "rate_class": trace.context.rate_class,
                "loss_class": trace.context.loss_class,
                "reliable": trace.context.reliable,
                "host_rtt": trace.context.host_rtt,
            },
            "baseline_preset": format!("{:?}", trace.baseline_preset),
            "proposed_preset": format!("{:?}", trace.proposed_preset),
            "applied_preset": format!("{:?}", trace.applied_preset),
            "predicted_advantage": trace.predicted_advantage,
            "exploring": trace.exploring,
            "rollback": trace.rollback,
            "rollbacks": trace.rollbacks,
            "fine_up_gain_delta_milli": trace.fine_up_gain_delta_milli,
            "fine_headroom_delta_milli": trace.fine_headroom_delta_milli,
            "fine_cwnd_gain_delta_milli": trace.fine_cwnd_gain_delta_milli,
        })),
        "shadow": shadow.map(|candidate| serde_json::json!({
            "policy_id": shadow_policy_id,
            "utility": {
                "total": candidate.utility.total,
                "components": candidate.utility.components,
                "goodput_bytes_per_second": candidate.utility.goodput_bytes_per_second,
            },
            "decision": {
                "train_target_bytes": candidate.decision.train_target_bytes,
                "bulk_quantum_cells": candidate.decision.bulk_quantum_cells,
                "fec": candidate.decision.fec.map(|geometry| serde_json::json!({
                    "data_cells": geometry.data_cells,
                    "parity_cells": geometry.parity_cells,
                })),
                "cover_profile": format!("{:?}", candidate.decision.cover_profile),
                "cover_overhead_per_mille": candidate.decision.cover_overhead_per_mille,
                "bbr": {
                    "preset": format!("{:?}", candidate.decision.bbr.preset),
                    "up_gain_milli": candidate.decision.bbr.up_gain_milli,
                    "headroom_milli": candidate.decision.bbr.headroom_milli,
                    "cwnd_gain_milli": candidate.decision.bbr.cwnd_gain_milli,
                    "pacing_cap_bytes_per_second": candidate.decision.bbr.pacing_cap_bytes_per_second,
                },
            },
            "trace": {
                "context": {
                    "rtt_class": candidate.trace.context.rtt_class,
                    "rate_class": candidate.trace.context.rate_class,
                    "loss_class": candidate.trace.context.loss_class,
                    "reliable": candidate.trace.context.reliable,
                    "host_rtt": candidate.trace.context.host_rtt,
                },
                "baseline_preset": format!("{:?}", candidate.trace.baseline_preset),
                "proposed_preset": format!("{:?}", candidate.trace.proposed_preset),
                "predicted_advantage": candidate.trace.predicted_advantage,
                "exploring": candidate.trace.exploring,
            },
        })),
    })
}

fn adaptive_cwnd_floor(telemetry: PathTelemetryV2, proposal: Bbr3ProposalV2) -> u64 {
    if telemetry.reliability != PathReliability::Datagram
        || proposal.loss_is_congestion
        || telemetry.controller_app_limited
        || telemetry.cpu_utilization_per_mille >= 900
        || telemetry.packet_train_queue_bytes < TX_ADMISSION_BATCH_BYTES as u64
        || telemetry.min_rtt.is_zero()
    {
        return 0;
    }
    let queue_budget = Duration::from_millis(5).max(telemetry.min_rtt / 2);
    if telemetry.queue_delay > queue_budget {
        return 0;
    }
    let demand_rate = telemetry
        .tun_ingress_bytes_per_second
        .max(telemetry.delivery_rate_bytes_per_second)
        .max(telemetry.real_traffic_bytes_per_second);
    if demand_rate == 0 {
        return 0;
    }
    let bdp = u128::from(demand_rate).saturating_mul(telemetry.min_rtt.as_micros()) / 1_000_000;
    let target = bdp
        .saturating_mul(u128::from(proposal.cwnd_gain_milli))
        .div_ceil(1_000)
        .min(u128::from(ADAPTIVE_CWND_FLOOR_MAX_BYTES)) as u64;
    target
        .div_ceil(ADAPTIVE_CWND_FLOOR_QUANTUM_BYTES)
        .saturating_mul(ADAPTIVE_CWND_FLOOR_QUANTUM_BYTES)
}

/// Write the full guarded BBR action onto the shared controller tunables.
/// Every field comes from the effective action (already clamped by the
/// guardrails to the ranges the controller accepts); the host only adds the
/// adaptive cwnd floor derived from live telemetry. The controller re-reads
/// the tunables at the next packet-timed round boundary, so a partially
/// published snapshot never takes effect mid-round. Returns whether any
/// tunable changed (and bumps the generation then).
fn apply_bbr3_effective(
    tunables: &Bbr3Tunables,
    effective: &BbrEffectiveV1,
    adaptive_cwnd_floor: u64,
) -> bool {
    fn update_u32(value: &AtomicU32, next: u32) -> bool {
        value.swap(next, Ordering::Relaxed) != next
    }
    fn update_u64(value: &AtomicU64, next: u64) -> bool {
        value.swap(next, Ordering::Relaxed) != next
    }
    fn update_u8(value: &AtomicU8, next: u8) -> bool {
        value.swap(next, Ordering::Relaxed) != next
    }

    let mut changed = false;
    changed |= update_u32(
        &tunables.probe_bw_up_pacing_gain_milli,
        effective.probe_bw_up_pacing_gain_milli,
    );
    changed |= update_u32(
        &tunables.probe_bw_down_pacing_gain_milli,
        effective.probe_bw_down_pacing_gain_milli,
    );
    changed |= update_u32(
        &tunables.cruise_pacing_gain_milli,
        effective.cruise_pacing_gain_milli,
    );
    changed |= update_u32(
        &tunables.default_cwnd_gain_milli,
        effective.default_cwnd_gain_milli,
    );
    changed |= update_u32(
        &tunables.probe_bw_up_cwnd_gain_milli,
        effective.probe_bw_up_cwnd_gain_milli,
    );
    changed |= update_u32(&tunables.headroom_milli, effective.headroom_milli);
    changed |= update_u32(&tunables.beta_milli, effective.beta_milli);
    changed |= update_u32(&tunables.loss_thresh_milli, effective.loss_threshold_milli);
    changed |= update_u8(
        &tunables.loss_is_congestion,
        u8::from(effective.loss_is_congestion),
    );
    changed |= update_u32(
        &tunables.queue_delay_guard_inflation_milli,
        effective.queue_guard_inflation_milli,
    );
    changed |= update_u64(
        &tunables.queue_delay_guard_slack_micros,
        effective.queue_guard_slack_micros,
    );
    changed |= update_u64(
        &tunables.probe_rtt_interval_millis,
        effective.probe_rtt_interval_millis,
    );
    changed |= update_u64(
        &tunables.probe_rtt_duration_millis,
        effective.probe_rtt_duration_millis,
    );
    changed |= update_u32(
        &tunables.probe_rtt_cwnd_gain_milli,
        effective.probe_rtt_cwnd_gain_milli,
    );
    changed |= update_u64(
        &tunables.min_probe_wait_millis,
        effective.min_probe_wait_millis,
    );
    changed |= update_u64(
        &tunables.max_added_probe_wait_millis,
        effective.max_added_probe_wait_millis,
    );
    changed |= update_u64(
        &tunables.pacing_rate_cap_bytes_per_second,
        effective.pacing_cap_bytes_per_second,
    );
    changed |= update_u64(
        &tunables.cwnd_floor_bytes,
        effective.cwnd_floor_bytes.max(adaptive_cwnd_floor),
    );
    changed |= update_u64(&tunables.cwnd_cap_bytes, effective.cwnd_cap_bytes);
    changed |= update_u64(
        &tunables.startup_bw_hint_bytes_per_second,
        effective.startup_bw_hint_bytes_per_second,
    );
    if changed {
        tunables.generation.fetch_add(1, Ordering::Release);
    }
    changed
}

#[cfg(test)]
fn apply_bbr3_proposal(
    tunables: &Bbr3Tunables,
    proposal: Bbr3ProposalV2,
    adaptive_cwnd_floor: u64,
) -> bool {
    fn update_u32(value: &AtomicU32, next: u32) -> bool {
        value.swap(next, Ordering::Relaxed) != next
    }
    fn update_u64(value: &AtomicU64, next: u64) -> bool {
        value.swap(next, Ordering::Relaxed) != next
    }
    fn update_u8(value: &AtomicU8, next: u8) -> bool {
        value.swap(next, Ordering::Relaxed) != next
    }

    let (cruise, guard, probe_interval, cwnd_floor) = match proposal.preset {
        Bbr3PresetV2::SharedConservative => (1_000, 500, 10_000, 0),
        Bbr3PresetV2::PrivateAggressive => (1_000, 500, 5_000, 0),
        Bbr3PresetV2::LossyRadio => (1_000, 800, 10_000, 0),
        Bbr3PresetV2::Policer => (970, 500, 10_000, 0),
        Bbr3PresetV2::LongFat => (1_000, 800, 20_000, 0),
        Bbr3PresetV2::RelayReliable => (980, 500, 10_000, 0),
        Bbr3PresetV2::LowRttHost => (1_000, 500, 5_000, LOW_RTT_CWND_FLOOR_BYTES),
    };
    let mut changed = false;
    changed |= update_u32(
        &tunables.probe_bw_up_pacing_gain_milli,
        proposal.up_gain_milli,
    );
    changed |= update_u32(&tunables.probe_bw_down_pacing_gain_milli, 900);
    changed |= update_u32(&tunables.cruise_pacing_gain_milli, cruise);
    changed |= update_u32(&tunables.default_cwnd_gain_milli, proposal.cwnd_gain_milli);
    changed |= update_u32(
        &tunables.probe_bw_up_cwnd_gain_milli,
        proposal.cwnd_gain_milli.max(1_500),
    );
    changed |= update_u32(&tunables.headroom_milli, proposal.headroom_milli);
    changed |= update_u32(&tunables.beta_milli, 700);
    changed |= update_u32(&tunables.loss_thresh_milli, 20);
    changed |= update_u8(
        &tunables.loss_is_congestion,
        u8::from(proposal.loss_is_congestion),
    );
    changed |= update_u32(&tunables.queue_delay_guard_inflation_milli, guard);
    changed |= update_u64(&tunables.queue_delay_guard_slack_micros, 5_000);
    changed |= update_u64(&tunables.probe_rtt_interval_millis, probe_interval);
    changed |= update_u64(&tunables.probe_rtt_duration_millis, 200);
    changed |= update_u32(&tunables.probe_rtt_cwnd_gain_milli, 500);
    changed |= update_u64(&tunables.min_probe_wait_millis, 2_000);
    changed |= update_u64(&tunables.max_added_probe_wait_millis, 1_000);
    changed |= update_u64(
        &tunables.pacing_rate_cap_bytes_per_second,
        proposal.pacing_cap_bytes_per_second,
    );
    changed |= update_u64(
        &tunables.cwnd_floor_bytes,
        cwnd_floor.max(adaptive_cwnd_floor),
    );
    changed |= update_u64(&tunables.cwnd_cap_bytes, 0);
    if changed {
        tunables.generation.fetch_add(1, Ordering::Release);
    }
    changed
}

fn parse_forced_usize(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<Option<usize>> {
    object
        .get(field)
        .map(|value| {
            let number = value
                .as_u64()
                .with_context(|| format!("IRONET_AUTOTUNE_FORCE.{field} must be an integer"))?;
            usize::try_from(number)
                .with_context(|| format!("IRONET_AUTOTUNE_FORCE.{field} is too large"))
        })
        .transpose()
}

fn parse_forced_fec(value: &serde_json::Value) -> Result<Option<FecGeometryV2>> {
    if value.is_null() || value.as_str() == Some("off") {
        return Ok(None);
    }
    let geometry = if let Some(text) = value.as_str() {
        let (data, parity) = text
            .split_once('+')
            .context("IRONET_AUTOTUNE_FORCE.fec must be off or DATA+PARITY")?;
        FecGeometryV2 {
            data_cells: data
                .parse()
                .context("IRONET_AUTOTUNE_FORCE.fec data count is invalid")?,
            parity_cells: parity
                .parse()
                .context("IRONET_AUTOTUNE_FORCE.fec parity count is invalid")?,
        }
    } else {
        let object = value
            .as_object()
            .context("IRONET_AUTOTUNE_FORCE.fec must be null, a string, or an object")?;
        ensure!(
            object
                .keys()
                .all(|key| key == "data_cells" || key == "parity_cells"),
            "IRONET_AUTOTUNE_FORCE.fec has an unknown field"
        );
        FecGeometryV2 {
            data_cells: parse_forced_usize(object, "data_cells")?
                .context("IRONET_AUTOTUNE_FORCE.fec.data_cells is required")?,
            parity_cells: parse_forced_usize(object, "parity_cells")?
                .context("IRONET_AUTOTUNE_FORCE.fec.parity_cells is required")?,
        }
    };
    geometry
        .validate()
        .context("IRONET_AUTOTUNE_FORCE.fec is outside V2 geometry bounds")?;
    ensure!(
        geometry.parity_cells.saturating_mul(1_000) <= geometry.data_cells.saturating_mul(500),
        "IRONET_AUTOTUNE_FORCE.fec exceeds the 50% wire-overhead guard"
    );
    Ok(Some(geometry))
}

fn parse_autotune_force(input: &str) -> Result<ForcedActionV2> {
    let value: serde_json::Value =
        serde_json::from_str(input).context("parsing IRONET_AUTOTUNE_FORCE JSON")?;
    let object = value
        .as_object()
        .context("IRONET_AUTOTUNE_FORCE must be a JSON object")?;
    const FIELDS: [&str; 6] = [
        "bbr_preset",
        "fec",
        "train_target_bytes",
        "bulk_quantum_cells",
        "cover_profile",
        "cover_overhead_per_mille",
    ];
    ensure!(
        object.keys().all(|key| FIELDS.contains(&key.as_str())),
        "IRONET_AUTOTUNE_FORCE has an unknown field"
    );
    let cover_profile = object
        .get("cover_profile")
        .map(|value| {
            match value
                .as_str()
                .context("IRONET_AUTOTUNE_FORCE.cover_profile must be a string")?
            {
                "idle" => Ok(CoverTrafficProfileV2::Idle),
                "live-broadcast" => Ok(CoverTrafficProfileV2::LiveBroadcast),
                "interactive-video" => Ok(CoverTrafficProfileV2::InteractiveVideo),
                "generic-h3-bulk" => Ok(CoverTrafficProfileV2::GenericH3Bulk),
                _ => bail!("IRONET_AUTOTUNE_FORCE.cover_profile is unknown"),
            }
        })
        .transpose()?;
    let cover_overhead_per_mille = object
        .get("cover_overhead_per_mille")
        .map(|value| {
            let value = value
                .as_u64()
                .context("IRONET_AUTOTUNE_FORCE.cover_overhead_per_mille must be an integer")?;
            u16::try_from(value)
                .context("IRONET_AUTOTUNE_FORCE.cover_overhead_per_mille is too large")
        })
        .transpose()?;
    let bbr_preset = object
        .get("bbr_preset")
        .filter(|value| !value.is_null())
        .map(|value| {
            serde_json::from_value::<Bbr3PresetV2>(value.clone())
                .context("IRONET_AUTOTUNE_FORCE.bbr_preset is unknown")
        })
        .transpose()?;
    let forced = ForcedActionV2 {
        bbr_preset,
        fec: object.get("fec").map(parse_forced_fec).transpose()?,
        train_target_bytes: parse_forced_usize(object, "train_target_bytes")?,
        bulk_quantum_cells: parse_forced_usize(object, "bulk_quantum_cells")?,
        cover_profile,
        cover_overhead_per_mille,
    };
    ensure!(
        forced != ForcedActionV2::default(),
        "IRONET_AUTOTUNE_FORCE must override at least one action"
    );
    Ok(forced)
}

/// Load the embedded builtin policy component into a live slot (plan Phase 6
/// promotion): the bandit learner runs as `builtin.wasm` through the verified
/// wasmtime pipeline. Trust is anchored to the checked-in digest sidecar; the
/// operator's trust store only governs external components.
fn load_builtin_live_slot(runtime_state: &V2RuntimeState) -> Result<PolicySlotV1> {
    let loader = runtime_state
        .policy_loader()
        .context("policy WASM engine unavailable")?;
    let backend = loader.load_builtin(&runtime_state.autotune.wasm)?;
    let digest = backend
        .identity()
        .digest
        .map(|digest| encode_digest(&digest))
        .unwrap_or_default();
    Ok(PolicySlotV1::new(Box::new(backend), None, digest))
}

fn is_wasm_policy_selection(selection: &str) -> bool {
    std::path::Path::new(selection)
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("wasm"))
}

/// The builtin WASM slot, or — when the WASM engine itself is unavailable —
/// the host-native conservative rules backend (plan Phase 6 fallback chain:
/// configured `.wasm` → `builtin.wasm` → `native`).
fn builtin_or_native_slot(
    runtime_state: &V2RuntimeState,
    policy_source: &mut String,
) -> PolicySlotV1 {
    match load_builtin_live_slot(runtime_state) {
        Ok(slot) => slot,
        Err(error) => {
            warn!(
                error = %format_args!("{error:#}"),
                "builtin WASM autotune policy unavailable; fell back to the native conservative policy"
            );
            *policy_source = crate::config::AUTOTUNE_POLICY_NATIVE.to_owned();
            PolicySlotV1::native_rules()
        }
    }
}

/// Plan section 8.3: a freshly loaded candidate component shadows the live
/// input for this many consecutive fault-free ticks before it is promoted at
/// a sample boundary. Any fault aborts the warmup and the last known-good
/// component stays live.
const WASM_WARMUP_TICKS: u64 = 5;

/// A verified candidate component running shadow warmup (plan section 8.3):
/// it observes the live input without influencing the wire until it has
/// survived [`WASM_WARMUP_TICKS`] fault-free ticks.
struct WasmWarmupV1 {
    evaluator: ShadowEvaluatorV2,
    /// The candidate's `state_schema_accepts` manifest list, applied when it
    /// is promoted (plan section 8.2).
    accepts: Vec<u32>,
    healthy_ticks: u64,
}

/// Read and verified-load a `.wasm` policy component: read into a private
/// buffer, parse/verify against the sealed trust store, compile (cached by
/// package digest), instantiate and self-check. Also returns the whole-file
/// BLAKE3 for reload change detection. Runs synchronously; callers on a tick
/// path must offload it.
fn load_wasm_backend(
    runtime_state: &V2RuntimeState,
    path: &std::path::Path,
) -> Result<(WasmPolicyBackend, [u8; 32])> {
    let loader = runtime_state
        .policy_loader()
        .context("policy WASM engine unavailable")?;
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let file_hash = *blake3::hash(&bytes).as_bytes();
    let trust = TrustStoreV1::from_config(&runtime_state.autotune.wasm)?;
    let backend = loader.load_from_bytes(
        &bytes,
        &runtime_state.autotune.wasm,
        &trust,
        chrono::Utc::now(),
    )?;
    Ok((backend, file_hash))
}

/// Load a `.wasm` policy component into a live slot (see
/// [`load_wasm_backend`]).
fn load_wasm_live_slot(
    runtime_state: &V2RuntimeState,
    path: &std::path::Path,
) -> Result<(PolicySlotV1, [u8; 32])> {
    let (backend, file_hash) = load_wasm_backend(runtime_state, path)?;
    let digest = backend
        .identity()
        .digest
        .map(|digest| encode_digest(&digest))
        .unwrap_or_default();
    Ok((
        PolicySlotV1::new(Box::new(backend), None, digest),
        file_hash,
    ))
}

/// Shadow evaluator around a verified WASM backend: it observes the live
/// input without influencing the wire.
fn shadow_evaluator_for_backend(
    backend: WasmPolicyBackend,
    objective: Objective,
    peer_hash: [u8; 32],
) -> ShadowEvaluatorV2 {
    let identity = backend.identity().clone();
    let digest = identity
        .digest
        .map(|digest| encode_digest(&digest))
        .unwrap_or_default();
    let slot = PolicySlotV1::new(Box::new(backend), None, digest.clone());
    let mut shadow = ShadowEvaluatorV2::from_slot(
        slot,
        objective.weights(),
        objective,
        identity.policy_id,
        digest,
    );
    shadow.set_peer_hash(peer_hash);
    shadow
}

/// Restore the live slot state for `peer`: the new state file when present,
/// otherwise a one-time warm start from the legacy `memory.rs` JSON file
/// (only meaningful for the bandit learner's state schema, whether it ran
/// in-process before Phase 6 or runs as `builtin.wasm` now).
fn restore_policy_state(
    store: &PolicyStateStoreV1,
    slot: &mut PolicySlotV1,
    legacy_dir: &std::path::Path,
    peer: &str,
    peer_hash: [u8; 32],
) {
    let identity = slot.identity().clone();
    if let Some(state) = store.load(&identity.policy_id, identity.state_schema, peer) {
        debug!(
            peer,
            policy_id = %identity.policy_id,
            state_schema = identity.state_schema,
            state_bytes = state.len(),
            "restored V2 policy state"
        );
        slot.set_state(state);
        return;
    }
    if identity.state_schema != STATE_SCHEMA_V1 || identity.policy_id != BANDIT_POLICY_ID_V1 {
        return;
    }
    match load_autotune_memory(legacy_dir, peer, &identity.policy_id) {
        Ok(Some(memory)) => {
            let seed = derive_policy_seed(
                PolicySlotKindV1::Live,
                &identity.policy_id,
                identity.state_schema,
                &peer_hash,
                1,
            );
            match LearnerStateV1::from_memory(&LearnerMemoryV1::from(&memory.learner), seed, 0)
                .encode()
            {
                Ok(state) => {
                    info!(
                        peer,
                        policy_id = %identity.policy_id,
                        contexts = memory.learner.contexts.len(),
                        "warm-started V2 policy state from legacy autotune memory"
                    );
                    slot.set_state(state);
                    slot.mark_dirty();
                }
                Err(error) => warn!(peer, %error, "ignored legacy V2 autotune memory"),
            }
        }
        Ok(None) => {}
        Err(error) => warn!(peer, %error, "ignored invalid V2 autotune memory"),
    }
}

fn flush_policy_state(
    store: &PolicyStateStoreV1,
    slot: &mut PolicySlotV1,
    peer: &str,
) -> Result<()> {
    let identity = slot.identity();
    store.save(
        &identity.policy_id,
        identity.state_schema,
        peer,
        slot.module_digest(),
        slot.state(),
    )?;
    slot.mark_flushed();
    Ok(())
}

fn autotune_force_from_env() -> Result<Option<ForcedActionV2>> {
    match std::env::var("IRONET_AUTOTUNE_FORCE") {
        Ok(value) => parse_autotune_force(&value).map(Some),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            bail!("IRONET_AUTOTUNE_FORCE is not valid UTF-8")
        }
    }
}

/// Compatibility helper for the runtime unit test that exercises the legacy
/// JSON action projection.  Production ticks use `PolicyTickV1` and never
/// pass a `TuneDecisionV2` candidate directly to a data-plane applier.
#[cfg(test)]
fn constrain_learned_policy_action(
    tuner: &AutoTunerV2,
    policy: &crate::protocol::v2::policy::PolicyArtifactV2,
    telemetry: PathTelemetryV2,
    learned: TuneDecisionV2,
    trace: LearnerTraceV2,
) -> TuneDecisionV2 {
    if trace.mode != LearnerModeV2::On {
        return learned;
    }

    use crate::protocol::v2::policy::api::{
        CandidateActionV1, CandidateHostExt, EffectiveActionV1, EffectiveHostExt,
    };

    let mut candidate = CandidateActionV1::from_tune_decision(&learned);
    if let Some(action) = policy.action(trace.applied_preset) {
        let application = action.to_candidate(telemetry.controller_bw_bytes_per_second);
        candidate.scheduler = application.scheduler;
        candidate.fec = application.fec;
        candidate.cover = application.cover;
    }
    let base = EffectiveActionV1::from_tune_decision(&learned);
    tuner
        .constrain_candidate(telemetry, &candidate, &base)
        .0
        .to_tune_decision()
}

async fn tuner_loop(
    connection: Connection,
    metrics: Arc<RuntimeMetrics>,
    sender: watch::Sender<Option<TuneDecisionV2>>,
    runtime_state: Arc<V2RuntimeState>,
    ticket_partition: String,
) -> Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let bounds = AutoTuneBoundsV2::default();
    let tuner = AutoTunerV2::new(bounds, 1);
    let objective = match runtime_state.autotune.objective {
        AutotuneObjective::Balanced => Objective::Balanced,
        AutotuneObjective::Throughput => Objective::Throughput,
        AutotuneObjective::Latency => Objective::Latency,
    };
    let forced_action = autotune_force_from_env()?;
    let learner_mode = if forced_action.is_some() {
        LearnerModeV2::Off
    } else {
        match runtime_state.autotune.mode {
            AutotuneMode::Off => LearnerModeV2::Off,
            AutotuneMode::Shadow => LearnerModeV2::Shadow,
            AutotuneMode::On => LearnerModeV2::On,
        }
    };
    // Plan Phase 6: `native` is the host-side conservative rules backend
    // (no learner); `builtin` and external `.wasm` components run through
    // the verified wasmtime pipeline; external JSON artifacts are gone.
    // Utility is host-computed with the canonical objective weights in all
    // cases — a component carries no weight bag of its own.
    let selection = runtime_state.autotune.policy.as_str();
    let wasm_selection = is_wasm_policy_selection(selection);
    let peer_hash = policy_peer_hash(connection.remote_id().as_bytes());
    let utility_weights = objective.weights();
    let mut policy_source = selection.to_owned();
    // Whole-file digest of the live component, for reload change detection.
    let mut wasm_seen_hash: Option<[u8; 32]> = None;
    let live_slot = if wasm_selection {
        let path = std::path::Path::new(selection);
        match load_wasm_live_slot(&runtime_state, path) {
            Ok((slot, file_hash)) => {
                info!(
                    peer = %connection.remote_id(),
                    policy_id = %slot.identity().policy_id,
                    policy_version = %slot.identity().policy_version,
                    state_schema = slot.identity().state_schema,
                    module_digest = %slot.module_digest(),
                    "loaded WASM autotune policy"
                );
                wasm_seen_hash = Some(file_hash);
                slot
            }
            Err(error) => {
                warn!(
                    configured = %selection,
                    error = %format_args!("{error:#}"),
                    "rejected V2 WASM autotune policy and fell back to builtin"
                );
                policy_source = crate::protocol::v2::policy::BUILTIN_POLICY_SOURCE_V2.to_owned();
                builtin_or_native_slot(&runtime_state, &mut policy_source)
            }
        }
    } else if selection == crate::config::AUTOTUNE_POLICY_BUILTIN {
        builtin_or_native_slot(&runtime_state, &mut policy_source)
    } else {
        PolicySlotV1::native_rules()
    };
    let mut tick_config = PolicyTickConfigV1::new(objective, learner_mode);
    tick_config.forced = forced_action;
    tick_config.max_egress_bytes_per_second = runtime_state.max_egress_bytes_per_second;
    tick_config.state_cap_bytes =
        u32::try_from(runtime_state.autotune.wasm.maximum_state_bytes).unwrap_or(u32::MAX);
    tick_config.peer_hash = peer_hash;
    let mut tick = PolicyTickV1::new(tuner, live_slot, utility_weights, tick_config);
    info!(
        policy_id = %tick.live().identity().policy_id,
        %policy_source,
        backend = %tick.live().status().backend,
        state_schema = tick.live().identity().state_schema,
        ?objective,
        mode = ?runtime_state.autotune.mode,
        memory = runtime_state.autotune.memory,
        "loaded V2 autotune policy"
    );
    // Optional shadow policy (`.wasm` only since Phase 6): observes the live
    // input without influencing the wire. Reloaded on change like the live
    // component, minus the warmup stage — a shadow is already off-wire.
    let shadow_selection = runtime_state
        .autotune
        .shadow_policy
        .as_deref()
        .filter(|path| is_wasm_policy_selection(&path.display().to_string()));
    let mut last_shadow_reload_error: Option<String> = None;
    let mut shadow_seen_hash: Option<[u8; 32]> = None;
    if let Some(shadow_path) = shadow_selection {
        match load_wasm_backend(&runtime_state, shadow_path) {
            Ok((backend, file_hash)) => {
                let shadow = shadow_evaluator_for_backend(backend, objective, peer_hash);
                info!(
                    peer = %connection.remote_id(),
                    shadow_policy_id = %shadow.policy_id(),
                    source = %shadow_path.display(),
                    "loaded V2 WASM shadow autotune policy"
                );
                shadow_seen_hash = Some(file_hash);
                tick.set_shadow(Some(shadow));
            }
            Err(error) => {
                let message = format!("{error:#}");
                warn!(
                    source = %shadow_path.display(),
                    error = %message,
                    "ignored invalid V2 WASM shadow autotune policy"
                );
                last_shadow_reload_error = Some(message);
            }
        }
    }
    let peer_name = connection.remote_id().to_string();
    let state_store = runtime_state.autotune.memory.then(|| {
        PolicyStateStoreV1::new(
            &runtime_state.autotune_state_dir,
            Duration::from_secs(runtime_state.autotune.wasm.state_flush_interval_secs),
            usize::try_from(runtime_state.autotune.wasm.maximum_state_bytes).unwrap_or(usize::MAX),
        )
    });
    if let Some(store) = &state_store {
        restore_policy_state(
            store,
            tick.live_mut(),
            &runtime_state.autotune_state_dir,
            &peer_name,
            peer_hash,
        );
    }
    let mut last_state_flush = Instant::now();
    let mut last_policy_fault: Option<PolicyFaultV1> = None;
    if let Some(forced_action) = forced_action {
        info!(
            peer = %connection.remote_id(),
            ?forced_action,
            "enabled guarded IRONET_AUTOTUNE_FORCE experiment"
        );
    }
    let mut previous = connection.stats();
    let mut status_tx_bytes = TxByteSnapshotV2::load(&metrics, previous.udp_tx.bytes);
    let mut previous_utility_tx_bytes = status_tx_bytes;
    let mut previous_real_bytes = metrics.real_tx_bytes.load(Ordering::Relaxed);
    let mut previous_sample_at = Instant::now();
    let mut previous_tun_ingress_records = metrics.tun_ingress_records.load(Ordering::Relaxed);
    let mut previous_tun_ingress_bytes = metrics.tun_ingress_bytes.load(Ordering::Relaxed);
    let mut previous_gso_input_bytes = metrics.gso_input_bytes.load(Ordering::Relaxed);
    let mut previous_reassembly_pressure_evictions = metrics
        .reassembly_pressure_evictions
        .load(Ordering::Relaxed);
    let mut previous_train_build_bytes = metrics.record_bytes_built.load(Ordering::Relaxed);
    let mut previous_bulk_preemptions = metrics.bulk_preemptions.load(Ordering::Relaxed);
    let mut previous_bulk_preemption_delay_micros =
        metrics.bulk_preemption_delay_micros.load(Ordering::Relaxed);
    let mut status_at = Instant::now();
    let mut status_real_bytes = previous_real_bytes;
    let mut status_tun_ingress_records = metrics.tun_ingress_records.load(Ordering::Relaxed);
    let mut status_tun_ingress_bytes = metrics.tun_ingress_bytes.load(Ordering::Relaxed);
    let mut status_gso_input_bytes = metrics.gso_input_bytes.load(Ordering::Relaxed);
    let mut status_cover_bytes = metrics.cover_tx_bytes.load(Ordering::Relaxed);
    let mut status_data_cell_bytes = metrics.data_cell_tx_bytes.load(Ordering::Relaxed);
    let mut status_data_cell_payload_bytes =
        metrics.data_cell_payload_tx_bytes.load(Ordering::Relaxed);
    let mut status_fec_bytes = metrics.fec_tx_bytes.load(Ordering::Relaxed);
    let mut status_trains_built = metrics.trains_built.load(Ordering::Relaxed);
    let mut status_records_built = metrics.records_built.load(Ordering::Relaxed);
    let mut status_record_bytes_built = metrics.record_bytes_built.load(Ordering::Relaxed);
    let mut status_cells_built = metrics.cells_built.load(Ordering::Relaxed);
    let mut status_cell_payload_built_bytes =
        metrics.cell_payload_built_bytes.load(Ordering::Relaxed);
    let mut status_unused_cell_capacity_bytes =
        metrics.unused_cell_capacity_bytes.load(Ordering::Relaxed);
    let mut status_fec_parity_rx = metrics.fec_parity_rx.load(Ordering::Relaxed);
    let mut status_fec_recovered_cells = metrics.fec_recovered_cells.load(Ordering::Relaxed);
    let mut status_fec_wasted_parity = metrics.fec_wasted_parity.load(Ordering::Relaxed);
    let mut status_repair_received_cells = metrics.repair_received_cells.load(Ordering::Relaxed);
    let mut status_repair_completed_requests =
        metrics.repair_completed_requests.load(Ordering::Relaxed);
    let mut status_repair_completed_requested_cells = metrics
        .repair_completed_requested_cells
        .load(Ordering::Relaxed);
    let mut status_repair_latency_micros = metrics.repair_latency_micros.load(Ordering::Relaxed);
    let mut status_bulk_service_bytes = metrics.bulk_service_bytes.load(Ordering::Relaxed);
    let mut status_latency_service_bytes = metrics.latency_service_bytes.load(Ordering::Relaxed);
    let mut status_bulk_preemptions = metrics.bulk_preemptions.load(Ordering::Relaxed);
    let mut status_bulk_preemption_delay_micros =
        metrics.bulk_preemption_delay_micros.load(Ordering::Relaxed);
    let mut status_latency_sojourn: [u64; LATENCY_SOJOURN_BUCKETS] =
        std::array::from_fn(|index| metrics.latency_sojourn_buckets[index].load(Ordering::Relaxed));
    let mut previous_latency_sojourn = status_latency_sojourn;
    let mut status_bulk_flow_service: [u64; BULK_FAIRNESS_BUCKETS] =
        std::array::from_fn(|index| metrics.bulk_flow_service[index].load(Ordering::Relaxed));
    let mut remote_feedback_sequence = metrics.remote_feedback_sequence.load(Ordering::Acquire);
    let mut previous_remote_fec_parity = metrics.remote_fec_parity_rx.load(Ordering::Relaxed);
    let mut previous_remote_fec_recovered =
        metrics.remote_fec_recovered_cells.load(Ordering::Relaxed);
    let mut previous_remote_fec_wasted = metrics.remote_fec_wasted_parity.load(Ordering::Relaxed);
    let mut previous_remote_repair_received =
        metrics.remote_repair_received_cells.load(Ordering::Relaxed);
    let mut previous_remote_repair_completed = metrics
        .remote_repair_completed_requests
        .load(Ordering::Relaxed);
    let mut previous_remote_repair_completed_requested = metrics
        .remote_repair_completed_requested_cells
        .load(Ordering::Relaxed);
    let mut previous_remote_repair_latency =
        metrics.remote_repair_latency_micros.load(Ordering::Relaxed);
    let mut previous_remote_delivered_payload = metrics
        .remote_delivered_payload_bytes
        .load(Ordering::Relaxed);
    let mut previous_remote_reorder_cells = metrics.remote_reorder_cells.load(Ordering::Relaxed);
    let mut previous_remote_missing_cells = metrics.remote_missing_cells.load(Ordering::Relaxed);
    let mut previous_remote_loss_run_1 = metrics.remote_loss_run_1.load(Ordering::Relaxed);
    let mut previous_remote_loss_run_2 = metrics.remote_loss_run_2.load(Ordering::Relaxed);
    let mut previous_remote_loss_run_3_4 = metrics.remote_loss_run_3_4.load(Ordering::Relaxed);
    let mut previous_remote_loss_run_5_plus =
        metrics.remote_loss_run_5_plus.load(Ordering::Relaxed);
    let mut previous_remote_expired_trains = metrics
        .remote_reassembly_expired_trains
        .load(Ordering::Relaxed);
    let mut previous_sent_data_cells = metrics.data_cell_tx_datagrams.load(Ordering::Relaxed);
    let mut remote_feedback_at = Instant::now();
    let mut remote_wasted_parity_per_mille = 0_u16;
    let mut remote_fec_recovery_per_mille = 0_u16;
    let mut remote_repair_hit_per_mille = 0_u16;
    let mut remote_repair_response_latency = Duration::ZERO;
    let mut remote_receiver_goodput_bytes_per_second = 0_u64;
    let mut remote_reorder_ppm = 0_u32;
    let mut remote_residual_loss_ppm = 0_u32;
    let mut remote_burst_loss_cells = 0_u16;
    let mut path_identity = String::new();
    let mut path_epoch = 1_u64;
    let mut minimum_rtt = Duration::MAX;
    let mut previous_controller_guard_transitions = 0_u64;
    let mut telemetry_failures = 0_u64;
    let mut policy_reload_tick = 0_u8;
    let mut wasm_pending: Option<tokio::task::JoinHandle<Result<WasmPolicyBackend>>> = None;
    let mut wasm_warmup: Option<WasmWarmupV1> = None;
    let mut last_wasm_reload_error: Option<String> = None;
    let mut shadow_pending: Option<tokio::task::JoinHandle<Result<WasmPolicyBackend>>> = None;
    interval.tick().await;
    loop {
        interval.tick().await;
        let sampled_at = Instant::now();
        policy_reload_tick = policy_reload_tick.wrapping_add(1);
        if wasm_selection {
            // Plan section 8.3: the candidate component is read into a
            // private buffer, verified, compiled and self-checked on a
            // blocking worker while the active component keeps deciding. A
            // finished candidate then enters shadow warmup: it observes the
            // live input for `WASM_WARMUP_TICKS` fault-free ticks before it
            // is promoted at a sample boundary. Failures only update the
            // error state — the active (last known-good) component is never
            // replaced by a bad file or an unhealthy candidate.
            if let Some(handle) = wasm_pending.as_mut()
                && handle.is_finished()
            {
                let handle = wasm_pending.take().expect("pending handle checked above");
                match handle.await {
                    Ok(Ok(backend)) => {
                        let accepts = backend.manifest().state_schema_accepts.clone();
                        let new_policy_id = backend.identity().policy_id.clone();
                        let digest = backend
                            .identity()
                            .digest
                            .map(|digest| encode_digest(&digest))
                            .unwrap_or_default();
                        let slot = PolicySlotV1::new(Box::new(backend), None, digest.clone());
                        let mut evaluator = ShadowEvaluatorV2::from_slot(
                            slot,
                            objective.weights(),
                            objective,
                            new_policy_id.clone(),
                            digest,
                        );
                        evaluator.set_peer_hash(peer_hash);
                        wasm_warmup = Some(WasmWarmupV1 {
                            evaluator,
                            accepts,
                            healthy_ticks: 0,
                        });
                        info!(
                            peer = %connection.remote_id(),
                            new_policy_id = %new_policy_id,
                            source = %runtime_state.autotune.policy,
                            warmup_ticks = WASM_WARMUP_TICKS,
                            "V2 WASM autotune policy candidate entered shadow warmup"
                        );
                    }
                    Ok(Err(error)) => {
                        let message = format!("{error:#}");
                        if last_wasm_reload_error.as_deref() != Some(&message) {
                            warn!(
                                peer = %connection.remote_id(),
                                source = %runtime_state.autotune.policy,
                                error = %message,
                                "retained last known-good V2 WASM autotune policy"
                            );
                            last_wasm_reload_error = Some(message);
                        }
                    }
                    Err(error) => {
                        let message = format!("WASM policy load task failed: {error}");
                        if last_wasm_reload_error.as_deref() != Some(&message) {
                            warn!(
                                peer = %connection.remote_id(),
                                source = %runtime_state.autotune.policy,
                                error = %message,
                                "retained last known-good V2 WASM autotune policy"
                            );
                            last_wasm_reload_error = Some(message);
                        }
                    }
                }
            }
            if policy_reload_tick.is_multiple_of(5)
                && wasm_pending.is_none()
                && wasm_warmup.is_none()
                && let Some(loader) = runtime_state.policy_loader().cloned()
            {
                let path = std::path::PathBuf::from(&runtime_state.autotune.policy);
                match std::fs::read(&path) {
                    Ok(bytes) => {
                        let file_hash = *blake3::hash(&bytes).as_bytes();
                        if Some(file_hash) != wasm_seen_hash {
                            // Remember the hash before loading: a bad file is
                            // reported once and not retried until it changes.
                            wasm_seen_hash = Some(file_hash);
                            match TrustStoreV1::from_config(&runtime_state.autotune.wasm) {
                                Ok(trust) => {
                                    let config = runtime_state.autotune.wasm.clone();
                                    wasm_pending = Some(tokio::task::spawn_blocking(move || {
                                        loader.load_from_bytes(
                                            &bytes,
                                            &config,
                                            &trust,
                                            chrono::Utc::now(),
                                        )
                                    }));
                                }
                                Err(error) => {
                                    let message = format!("{error:#}");
                                    if last_wasm_reload_error.as_deref() != Some(&message) {
                                        warn!(
                                            peer = %connection.remote_id(),
                                            source = %runtime_state.autotune.policy,
                                            error = %message,
                                            "invalid WASM trust store; retained last known-good V2 autotune policy"
                                        );
                                        last_wasm_reload_error = Some(message);
                                    }
                                }
                            }
                        }
                    }
                    Err(error) => {
                        let message = format!("reading {}: {error}", path.display());
                        if last_wasm_reload_error.as_deref() != Some(&message) {
                            warn!(
                                peer = %connection.remote_id(),
                                source = %runtime_state.autotune.policy,
                                error = %message,
                                "retained last known-good V2 WASM autotune policy"
                            );
                            last_wasm_reload_error = Some(message);
                        }
                    }
                }
            }
        }
        if let Some(shadow_path) = shadow_selection {
            // Verified background load like the live component, minus the
            // warmup stage — a shadow is already off-wire. Failures only
            // update the error state; the last known-good shadow stays.
            if let Some(handle) = shadow_pending.as_mut()
                && handle.is_finished()
            {
                let handle = shadow_pending.take().expect("pending handle checked above");
                match handle.await {
                    Ok(Ok(backend)) => {
                        let shadow = shadow_evaluator_for_backend(backend, objective, peer_hash);
                        info!(
                            peer = %connection.remote_id(),
                            new_shadow_policy_id = %shadow.policy_id(),
                            source = %shadow_path.display(),
                            "hot-switched V2 WASM shadow autotune policy at sample boundary"
                        );
                        tick.set_shadow(Some(shadow));
                    }
                    Ok(Err(error)) => {
                        let message = format!("{error:#}");
                        if last_shadow_reload_error.as_deref() != Some(&message) {
                            warn!(
                                peer = %connection.remote_id(),
                                source = %shadow_path.display(),
                                error = %message,
                                "retained last known-good V2 WASM shadow autotune policy"
                            );
                            last_shadow_reload_error = Some(message);
                        }
                    }
                    Err(error) => {
                        let message = format!("WASM shadow policy load task failed: {error}");
                        if last_shadow_reload_error.as_deref() != Some(&message) {
                            warn!(
                                peer = %connection.remote_id(),
                                source = %shadow_path.display(),
                                error = %message,
                                "retained last known-good V2 WASM shadow autotune policy"
                            );
                            last_shadow_reload_error = Some(message);
                        }
                    }
                }
            }
            if policy_reload_tick.is_multiple_of(5)
                && shadow_pending.is_none()
                && let Some(loader) = runtime_state.policy_loader().cloned()
            {
                match std::fs::read(shadow_path) {
                    Ok(bytes) => {
                        let file_hash = *blake3::hash(&bytes).as_bytes();
                        if Some(file_hash) != shadow_seen_hash {
                            // Remember the hash before loading: a bad file is
                            // reported once and not retried until it changes.
                            shadow_seen_hash = Some(file_hash);
                            match TrustStoreV1::from_config(&runtime_state.autotune.wasm) {
                                Ok(trust) => {
                                    let config = runtime_state.autotune.wasm.clone();
                                    shadow_pending = Some(tokio::task::spawn_blocking(move || {
                                        loader.load_from_bytes(
                                            &bytes,
                                            &config,
                                            &trust,
                                            chrono::Utc::now(),
                                        )
                                    }));
                                }
                                Err(error) => {
                                    let message = format!("{error:#}");
                                    if last_shadow_reload_error.as_deref() != Some(&message) {
                                        warn!(
                                            peer = %connection.remote_id(),
                                            source = %shadow_path.display(),
                                            error = %message,
                                            "invalid WASM trust store; retained last known-good V2 shadow autotune policy"
                                        );
                                        last_shadow_reload_error = Some(message);
                                    }
                                }
                            }
                        }
                    }
                    Err(error) => {
                        let message = format!("reading {}: {error}", shadow_path.display());
                        if last_shadow_reload_error.as_deref() != Some(&message) {
                            warn!(
                                peer = %connection.remote_id(),
                                source = %shadow_path.display(),
                                error = %message,
                                "retained last known-good V2 WASM shadow autotune policy"
                            );
                            last_shadow_reload_error = Some(message);
                        }
                    }
                }
            }
        }
        let sample_elapsed = sampled_at.saturating_duration_since(previous_sample_at);
        let current = connection.stats();
        let path = match selected_path_sample(&connection) {
            Ok(sample) => {
                if telemetry_failures != 0 {
                    info!(
                        peer = %connection.remote_id(),
                        failures = telemetry_failures,
                        "V2 path telemetry recovered without replacing the logical session"
                    );
                    telemetry_failures = 0;
                }
                sample
            }
            Err(error) => {
                telemetry_failures = telemetry_failures.saturating_add(1);
                let decision = tick.fallback_for_missing_telemetry();
                metrics
                    .receive_buffer_bytes
                    .store(decision.receive_buffer_bytes as u64, Ordering::Relaxed);
                if sender.send(Some(decision)).is_err() {
                    if let Some(store) = &state_store
                        && tick.live().is_dirty()
                    {
                        flush_policy_state(store, tick.live_mut(), &peer_name)?;
                    }
                    return Ok(());
                }
                if telemetry_failures == 1 || telemetry_failures.is_multiple_of(10) {
                    warn!(
                        peer = %connection.remote_id(),
                        failures = telemetry_failures,
                        path_epoch = decision.path_epoch,
                        reason = ?decision.reason,
                        %error,
                        "V2 path telemetry unavailable; applied bounded conservative tuning"
                    );
                }
                let current_udp_tx_bytes = current.udp_tx.bytes;
                previous = current;
                previous_real_bytes = metrics.real_tx_bytes.load(Ordering::Relaxed);
                previous_sample_at = sampled_at;
                previous_tun_ingress_records = metrics.tun_ingress_records.load(Ordering::Relaxed);
                previous_tun_ingress_bytes = metrics.tun_ingress_bytes.load(Ordering::Relaxed);
                previous_gso_input_bytes = metrics.gso_input_bytes.load(Ordering::Relaxed);
                previous_reassembly_pressure_evictions = metrics
                    .reassembly_pressure_evictions
                    .load(Ordering::Relaxed);
                previous_train_build_bytes = metrics.record_bytes_built.load(Ordering::Relaxed);
                previous_bulk_preemptions = metrics.bulk_preemptions.load(Ordering::Relaxed);
                previous_bulk_preemption_delay_micros =
                    metrics.bulk_preemption_delay_micros.load(Ordering::Relaxed);
                previous_utility_tx_bytes = TxByteSnapshotV2::load(&metrics, current_udp_tx_bytes);
                previous_latency_sojourn = std::array::from_fn(|index| {
                    metrics.latency_sojourn_buckets[index].load(Ordering::Relaxed)
                });
                continue;
            }
        };
        let SelectedPathSampleV2 {
            identity,
            reliability,
            rtt,
            congestion_window_bytes,
            current_mtu,
            controller_pacing_rate_bytes_per_second,
            controller_send_quantum_bytes,
            controller_queue_delay_guard_transitions,
            controller_policer_pacing_scale_per_mille,
            controller_policer_pacing_transitions,
            controller_snapshot,
            controller_tunables,
        } = path;
        // PathId is a QUIC controller identity, while `path_identity` below is
        // deliberately a stable network-locator epoch. noq may recycle PathId
        // without changing the locator, so never cache its path-local BBR
        // handle across samples.
        let bbr_tunables = controller_tunables;
        if identity != path_identity {
            let migrated = !path_identity.is_empty();
            let previous_identity = std::mem::replace(&mut path_identity, identity);
            if migrated {
                path_epoch = path_epoch.wrapping_add(1).max(1);
            }
            minimum_rtt = rtt;
            previous_controller_guard_transitions =
                controller_snapshot.map_or(0, |snapshot| snapshot.guard_transitions);
            if migrated {
                info!(
                    path_epoch,
                    ?reliability,
                    previous_path = %previous_identity,
                    selected_path = %path_identity,
                    "V2 QUIC path migrated without replacing the logical session"
                );
            }
        }
        minimum_rtt = minimum_rtt.min(rtt);
        metrics.repair_minimum_age_micros.store(
            repair_minimum_age_for_rtt(rtt)
                .as_micros()
                .min(u128::from(u64::MAX)) as u64,
            Ordering::Relaxed,
        );
        let sent_packets = counter_delta(current.udp_tx.datagrams, previous.udp_tx.datagrams);
        let received_packets = counter_delta(current.udp_rx.datagrams, previous.udp_rx.datagrams);
        let lost_packets = counter_delta(current.lost_packets, previous.lost_packets);
        let loss_ppm = ratio_per_million(lost_packets, sent_packets.saturating_add(lost_packets));
        let sent_bytes = counter_delta(current.udp_tx.bytes, previous.udp_tx.bytes);
        let received_bytes = counter_delta(current.udp_rx.bytes, previous.udp_rx.bytes);
        let sent_bytes_per_second = rate_per_second(sent_bytes, sample_elapsed);
        let received_bytes_per_second = rate_per_second(received_bytes, sample_elapsed);
        let real_bytes = metrics.real_tx_bytes.load(Ordering::Relaxed);
        let real_delta = real_bytes.saturating_sub(previous_real_bytes);
        let current_tun_ingress_records = metrics.tun_ingress_records.load(Ordering::Relaxed);
        let current_tun_ingress_bytes = metrics.tun_ingress_bytes.load(Ordering::Relaxed);
        let current_gso_input_bytes = metrics.gso_input_bytes.load(Ordering::Relaxed);
        let current_reassembly_pressure_evictions = metrics
            .reassembly_pressure_evictions
            .load(Ordering::Relaxed);
        let current_train_build_bytes = metrics.record_bytes_built.load(Ordering::Relaxed);
        let current_bulk_preemptions = metrics.bulk_preemptions.load(Ordering::Relaxed);
        let current_bulk_preemption_delay_micros =
            metrics.bulk_preemption_delay_micros.load(Ordering::Relaxed);
        let tun_ingress_records_delta =
            current_tun_ingress_records.saturating_sub(previous_tun_ingress_records);
        let tun_ingress_bytes_delta =
            current_tun_ingress_bytes.saturating_sub(previous_tun_ingress_bytes);
        let gso_input_bytes_delta =
            current_gso_input_bytes.saturating_sub(previous_gso_input_bytes);
        let reassembly_pressure_evictions_delta = current_reassembly_pressure_evictions
            .saturating_sub(previous_reassembly_pressure_evictions);
        let train_build_bytes_per_second = rate_per_second(
            current_train_build_bytes.saturating_sub(previous_train_build_bytes),
            sample_elapsed,
        );
        let bulk_preemption_delta =
            current_bulk_preemptions.saturating_sub(previous_bulk_preemptions);
        let bulk_preemption_delay_average_micros = current_bulk_preemption_delay_micros
            .saturating_sub(previous_bulk_preemption_delay_micros)
            .checked_div(bulk_preemption_delta)
            .unwrap_or_default();
        let tun_ingress_bytes_per_second = rate_per_second(tun_ingress_bytes_delta, sample_elapsed);
        let average_record_bytes = tun_ingress_bytes_delta
            .checked_div(tun_ingress_records_delta)
            .unwrap_or_default();
        let gso_ingress_ratio_ppm =
            ratio_per_million(gso_input_bytes_delta, tun_ingress_bytes_delta);
        let train_queue_bytes = metrics.train_queue_bytes.load(Ordering::Relaxed);
        let latency_queue_bytes = metrics.latency_queue_bytes.load(Ordering::Relaxed);
        let cpu_utilization_per_mille = runtime_state
            .cpu_utilization_per_mille
            .load(Ordering::Relaxed)
            .min(1_000) as u16;
        let current_remote_feedback_sequence =
            metrics.remote_feedback_sequence.load(Ordering::Acquire);
        let mut remote_expired_stripes_delta = 0;
        if current_remote_feedback_sequence != remote_feedback_sequence {
            let parity = metrics.remote_fec_parity_rx.load(Ordering::Relaxed);
            let recovered = metrics.remote_fec_recovered_cells.load(Ordering::Relaxed);
            let wasted = metrics.remote_fec_wasted_parity.load(Ordering::Relaxed);
            let repair_received = metrics.remote_repair_received_cells.load(Ordering::Relaxed);
            let repair_completed = metrics
                .remote_repair_completed_requests
                .load(Ordering::Relaxed);
            let repair_completed_requested = metrics
                .remote_repair_completed_requested_cells
                .load(Ordering::Relaxed);
            let repair_latency = metrics.remote_repair_latency_micros.load(Ordering::Relaxed);
            let delivered_payload = metrics
                .remote_delivered_payload_bytes
                .load(Ordering::Relaxed);
            let reorder_cells = metrics.remote_reorder_cells.load(Ordering::Relaxed);
            let missing_cells = metrics.remote_missing_cells.load(Ordering::Relaxed);
            let loss_run_1 = metrics.remote_loss_run_1.load(Ordering::Relaxed);
            let loss_run_2 = metrics.remote_loss_run_2.load(Ordering::Relaxed);
            let loss_run_3_4 = metrics.remote_loss_run_3_4.load(Ordering::Relaxed);
            let loss_run_5_plus = metrics.remote_loss_run_5_plus.load(Ordering::Relaxed);
            let expired_trains = metrics
                .remote_reassembly_expired_trains
                .load(Ordering::Relaxed);
            let sent_data_cells = metrics.data_cell_tx_datagrams.load(Ordering::Relaxed);
            let feedback_elapsed = sampled_at.saturating_duration_since(remote_feedback_at);
            let sent_data_cells_delta = counter_delta(sent_data_cells, previous_sent_data_cells);
            let reorder_delta = counter_delta(reorder_cells, previous_remote_reorder_cells);
            let missing_delta = counter_delta(missing_cells, previous_remote_missing_cells);
            let run_1_delta = counter_delta(loss_run_1, previous_remote_loss_run_1);
            let run_2_delta = counter_delta(loss_run_2, previous_remote_loss_run_2);
            let run_3_4_delta = counter_delta(loss_run_3_4, previous_remote_loss_run_3_4);
            let run_5_plus_delta = counter_delta(loss_run_5_plus, previous_remote_loss_run_5_plus);
            remote_expired_stripes_delta =
                counter_delta(expired_trains, previous_remote_expired_trains);
            remote_receiver_goodput_bytes_per_second = rate_per_second(
                counter_delta(delivered_payload, previous_remote_delivered_payload),
                feedback_elapsed,
            );
            remote_reorder_ppm = ratio_per_million(reorder_delta, sent_data_cells_delta);
            remote_residual_loss_ppm = ratio_per_million(missing_delta, sent_data_cells_delta);
            let loss_runs = run_1_delta
                .saturating_add(run_2_delta)
                .saturating_add(run_3_4_delta)
                .saturating_add(run_5_plus_delta);
            let weighted_loss_cells = run_1_delta
                .saturating_add(run_2_delta.saturating_mul(2))
                .saturating_add(run_3_4_delta.saturating_mul(4))
                .saturating_add(run_5_plus_delta.saturating_mul(5));
            remote_burst_loss_cells = weighted_loss_cells
                .checked_div(loss_runs)
                .unwrap_or_default()
                .min(u64::from(u16::MAX)) as u16;
            let parity_delta = counter_delta(parity, previous_remote_fec_parity);
            if parity_delta != 0 {
                remote_wasted_parity_per_mille = ratio_per_thousand(
                    counter_delta(wasted, previous_remote_fec_wasted),
                    parity_delta,
                );
                remote_fec_recovery_per_mille = ratio_per_thousand(
                    counter_delta(recovered, previous_remote_fec_recovered),
                    parity_delta,
                );
            }
            let repair_completed_requested_delta = counter_delta(
                repair_completed_requested,
                previous_remote_repair_completed_requested,
            );
            if repair_completed_requested_delta != 0 {
                remote_repair_hit_per_mille = ratio_per_thousand(
                    counter_delta(repair_received, previous_remote_repair_received),
                    repair_completed_requested_delta,
                );
            }
            let repair_completed_delta =
                counter_delta(repair_completed, previous_remote_repair_completed);
            if repair_completed_delta != 0 {
                remote_repair_response_latency = Duration::from_micros(
                    counter_delta(repair_latency, previous_remote_repair_latency)
                        .checked_div(repair_completed_delta)
                        .unwrap_or_default(),
                );
            }
            previous_remote_fec_parity = parity;
            previous_remote_fec_recovered = recovered;
            previous_remote_fec_wasted = wasted;
            previous_remote_repair_received = repair_received;
            previous_remote_repair_completed = repair_completed;
            previous_remote_repair_completed_requested = repair_completed_requested;
            previous_remote_repair_latency = repair_latency;
            previous_remote_delivered_payload = delivered_payload;
            previous_remote_reorder_cells = reorder_cells;
            previous_remote_missing_cells = missing_cells;
            previous_remote_loss_run_1 = loss_run_1;
            previous_remote_loss_run_2 = loss_run_2;
            previous_remote_loss_run_3_4 = loss_run_3_4;
            previous_remote_loss_run_5_plus = loss_run_5_plus;
            previous_remote_expired_trains = expired_trains;
            previous_sent_data_cells = sent_data_cells;
            remote_feedback_at = sampled_at;
            remote_feedback_sequence = current_remote_feedback_sequence;
        }
        let latency_sojourn: [u64; LATENCY_SOJOURN_BUCKETS] = std::array::from_fn(|index| {
            metrics.latency_sojourn_buckets[index].load(Ordering::Relaxed)
        });
        let latency_sojourn_delta = std::array::from_fn(|index| {
            latency_sojourn[index].saturating_sub(previous_latency_sojourn[index])
        });
        let latency_sojourn_p50_micros = histogram_percentile_micros(&latency_sojourn_delta, 50);
        let latency_sojourn_p95_micros = histogram_percentile_micros(&latency_sojourn_delta, 95);
        let latency_sojourn_p99_micros = histogram_percentile_micros(&latency_sojourn_delta, 99);
        let latency_queue_recently_nonempty =
            latency_queue_bytes != 0 || latency_sojourn_delta.iter().any(|count| *count != 0);
        previous_latency_sojourn = latency_sojourn;
        let controller_guard_transitions =
            controller_snapshot.map_or(0, |snapshot| snapshot.guard_transitions);
        let controller_guard_transitions_delta =
            controller_guard_transitions.saturating_sub(previous_controller_guard_transitions);
        previous_controller_guard_transitions = controller_guard_transitions;
        let controller_tunables_generation = bbr_tunables
            .as_ref()
            .map_or(0, |tunables| tunables.generation.load(Ordering::Relaxed));
        let controller_clamped_writes = bbr_tunables.as_ref().map_or(0, |tunables| {
            tunables.clamped_writes.load(Ordering::Relaxed)
        });
        let telemetry = PathTelemetryV2 {
            path_epoch,
            reliability,
            rtt,
            min_rtt: minimum_rtt,
            queue_delay: rtt.saturating_sub(minimum_rtt),
            loss_ppm,
            burst_loss_cells: remote_burst_loss_cells,
            reorder_ppm: remote_reorder_ppm,
            receiver_goodput_bytes_per_second: remote_receiver_goodput_bytes_per_second,
            residual_loss_ppm: remote_residual_loss_ppm,
            latency_sojourn_p95_micros,
            latency_sojourn_p50_micros,
            latency_sojourn_p99_micros,
            latency_queue_recently_nonempty,
            delivery_rate_bytes_per_second: sent_bytes_per_second,
            controller_pacing_rate_bytes_per_second: controller_pacing_rate_bytes_per_second
                .unwrap_or_default(),
            controller_send_quantum_bytes: controller_send_quantum_bytes.unwrap_or_default(),
            controller_state: controller_snapshot.map_or(0, |snapshot| snapshot.state),
            controller_bw_bytes_per_second: controller_snapshot.map_or(0, |snapshot| snapshot.bw),
            controller_inflight_longterm_bytes: controller_snapshot
                .map_or(0, |snapshot| snapshot.inflight_longterm),
            controller_guard_transitions_delta,
            controller_app_limited: controller_snapshot
                .is_some_and(|snapshot| snapshot.app_limited_in_round),
            controller_tunables_generation,
            controller_params_generation: controller_snapshot
                .map_or(0, |snapshot| snapshot.params_generation),
            controller_clamped_writes,
            receive_rate_bytes_per_second: received_bytes_per_second,
            // Receive coalescing is driven by the busier direction. This is
            // essential for asymmetric paths: a gateway receiving a Bulk
            // stream may transmit little more than QUIC ACKs itself.
            packets_per_second: sent_packets.max(received_packets),
            tun_ingress_bytes_per_second,
            average_record_bytes,
            gso_ingress_ratio_ppm,
            packet_train_queue_bytes: train_queue_bytes,
            latency_queue_bytes,
            reassembly_pressure_evictions: reassembly_pressure_evictions_delta,
            remote_expired_stripes_delta,
            train_build_bytes_per_second,
            bulk_preemption_delay_average_micros,
            cpu_utilization_per_mille,
            wasted_parity_per_mille: remote_wasted_parity_per_mille,
            fec_recovery_per_mille: remote_fec_recovery_per_mille,
            repair_hit_per_mille: remote_repair_hit_per_mille,
            repair_completed_requests: previous_remote_repair_completed,
            repair_response_latency: remote_repair_response_latency,
            real_traffic_bytes_per_second: rate_per_second(real_delta, sample_elapsed),
        };
        let current_utility_tx_bytes = TxByteSnapshotV2::load(&metrics, current.udp_tx.bytes);
        let wire_cost = current_utility_tx_bytes
            .delta(previous_utility_tx_bytes)
            .breakdown()
            .wire_cost();
        previous_utility_tx_bytes = current_utility_tx_bytes;
        // Baseline -> PolicyInputV1 -> backend decide -> guardrails ->
        // EffectiveActionV1 -> TuneDecisionV2 (and the shadow evaluation),
        // see `protocol::v2::policy_tick`.
        // Plan section 9: read the node egress view for this tick before the
        // pipeline runs; publish the guarded request afterwards. Both are
        // lock-protected shared state, so a slow or faulting guest on
        // another peer can never block this tick.
        let egress_peer_key = tick.config().peer_hash;
        tick.set_egress_view(
            runtime_state
                .egress_coordinator
                .view(egress_peer_key, sampled_at),
        );
        let outcome = tick.run(telemetry, &wire_cost, sampled_at);
        let egress_requested_bytes_per_second =
            outcome.effective.egress.desired_rate_bytes_per_second;
        runtime_state.egress_coordinator.publish(
            egress_peer_key,
            outcome.effective.egress,
            sampled_at,
        );
        // Plan section 8.3 shadow warmup: the candidate observes this tick's
        // live input without influencing the wire; any fault aborts it and
        // `WASM_WARMUP_TICKS` consecutive healthy ticks promote it to live.
        if let Some(warmup) = wasm_warmup.as_mut() {
            let evaluation = warmup.evaluator.observe(
                sampled_at,
                tick.tuner(),
                &telemetry,
                &wire_cost,
                outcome.baseline,
            );
            if let Some(fault) = evaluation.fault {
                warn!(
                    peer = %connection.remote_id(),
                    policy_id = %warmup.evaluator.policy_id(),
                    healthy_ticks = warmup.healthy_ticks,
                    %fault,
                    "aborted V2 WASM policy warmup; retained last known-good"
                );
                wasm_warmup = None;
            } else {
                warmup.healthy_ticks = warmup.healthy_ticks.saturating_add(1);
                if warmup.healthy_ticks >= WASM_WARMUP_TICKS {
                    let warmup = wasm_warmup.take().expect("warmup checked above");
                    let policy_id = warmup.evaluator.policy_id().to_owned();
                    let (backend, probe, digest) = warmup.evaluator.into_slot().into_backend();
                    if let Some(store) = &state_store
                        && tick.live().is_dirty()
                        && let Err(error) = flush_policy_state(store, tick.live_mut(), &peer_name)
                    {
                        warn!(
                            peer = %connection.remote_id(),
                            %error,
                            "failed persisting V2 policy state before hot switch"
                        );
                    }
                    let kept_state = tick.replace_live(
                        backend,
                        probe,
                        digest,
                        objective.weights(),
                        &warmup.accepts,
                    );
                    if !kept_state && let Some(store) = &state_store {
                        let identity = tick.live().identity().clone();
                        if let Some(state) =
                            store.load(&identity.policy_id, identity.state_schema, &peer_name)
                        {
                            tick.live_mut().set_state(state);
                        }
                    }
                    last_wasm_reload_error = None;
                    info!(
                        peer = %connection.remote_id(),
                        new_policy_id = %policy_id,
                        source = %runtime_state.autotune.policy,
                        kept_state,
                        warmup_ticks = WASM_WARMUP_TICKS,
                        "promoted V2 WASM autotune policy after shadow warmup"
                    );
                }
            }
        }
        let decision = outcome.decision;
        if outcome.fault != last_policy_fault {
            match outcome.fault {
                Some(fault) => {
                    let health = tick.live().health();
                    warn!(
                        peer = %connection.remote_id(),
                        %fault,
                        health = ?health.state,
                        faults_total = health.faults_total,
                        "V2 policy backend fault; applied the host baseline"
                    );
                }
                None => info!(
                    peer = %connection.remote_id(),
                    "V2 policy backend recovered"
                ),
            }
            last_policy_fault = outcome.fault;
        }
        let adaptive_cwnd_floor_bytes = adaptive_cwnd_floor(telemetry, decision.bbr);
        if let Some(tunables) = bbr_tunables.as_deref() {
            apply_bbr3_effective(tunables, &outcome.effective.bbr, adaptive_cwnd_floor_bytes);
        }
        let utility = outcome.utility;
        let learner_trace = outcome.trace;
        let shadow_evaluation = outcome.shadow;
        let shadow_policy_id = tick.shadow().map(|shadow| shadow.policy_id().to_owned());
        let live_policy_id = tick.live().identity().policy_id.clone();
        let egress_assigned_bytes_per_second = tick.egress_view().assigned_rate_bytes_per_second;
        runtime_state.publish_tune_status(
            connection.remote_id(),
            TuneStatusSampleV2 {
                decision,
                utility,
                learner: learner_trace,
                policy_id: &live_policy_id,
                policy_source: &policy_source,
                shadow_policy_id: shadow_policy_id.as_deref(),
                shadow: shadow_evaluation,
                live: tick.live().status(),
                shadow_slot: tick.shadow().map(|shadow| shadow.slot().status()),
                egress_requested_bytes_per_second,
                egress_assigned_bytes_per_second,
            },
        );
        if tracing::enabled!(target: "ironet::autotune", tracing::Level::DEBUG) {
            let sampled_unix_micros = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_micros()
                .min(u128::from(u64::MAX)) as u64;
            let record = autotune_tap_record(
                connection.remote_id(),
                &ticket_partition,
                AutotuneTapSampleV2 {
                    sampled_unix_micros,
                    sample_elapsed,
                    telemetry,
                    decision,
                    utility,
                    wire_cost,
                    force_applied: forced_action.is_some(),
                    learner: Some(learner_trace),
                    policy_id: &live_policy_id,
                    policy_source: &policy_source,
                    shadow_policy_id: shadow_policy_id.as_deref(),
                    shadow: shadow_evaluation,
                    path_identity: &path_identity,
                    controller_cwnd_bytes: congestion_window_bytes,
                    adaptive_cwnd_floor_bytes,
                },
            );
            debug!(
                target: "ironet::autotune",
                record = %record,
                "V2 autotune tap"
            );
        }
        metrics
            .receive_buffer_bytes
            .store(decision.receive_buffer_bytes as u64, Ordering::Relaxed);
        metrics
            .reassembly_budget_bytes
            .store(decision.reassembly_budget_bytes as u64, Ordering::Relaxed);
        metrics
            .active_train_budget
            .store(u64::from(decision.active_train_budget), Ordering::Relaxed);
        metrics.repair_wait_policy.store(
            decision.repair_wait_policy.to_metrics_code(),
            Ordering::Relaxed,
        );
        if sender.send(Some(decision)).is_err() {
            if let Some(store) = &state_store
                && tick.live().is_dirty()
            {
                flush_policy_state(store, tick.live_mut(), &peer_name)?;
            }
            return Ok(());
        }
        if let Some(store) = &state_store
            && tick.live().is_dirty()
            && sampled_at.saturating_duration_since(last_state_flush) >= store.flush_interval()
        {
            match flush_policy_state(store, tick.live_mut(), &peer_name) {
                Ok(()) => last_state_flush = sampled_at,
                Err(error) => warn!(
                    peer = %connection.remote_id(),
                    %error,
                    "failed persisting V2 policy state"
                ),
            }
        }
        if decision.sample_count.is_multiple_of(10) {
            let now = Instant::now();
            let status_elapsed = now.saturating_duration_since(status_at);
            let current_tx_bytes = TxByteSnapshotV2::load(&metrics, current.udp_tx.bytes);
            let tx_bytes = current_tx_bytes.delta(status_tx_bytes).breakdown();
            let repair_tx_bytes = tx_bytes
                .repair_request_bytes
                .saturating_add(tx_bytes.repair_response_bytes);
            let quic_transport_residual_per_mille = ratio_per_thousand(
                tx_bytes.quic_transport_residual_bytes,
                tx_bytes.quic_udp_payload_bytes,
            );
            let cell_envelope_overhead_per_mille =
                ratio_per_thousand(tx_bytes.cell_envelope_bytes, tx_bytes.data_cell_bytes);
            let tun_ingress_records = metrics.tun_ingress_records.load(Ordering::Relaxed);
            let tun_ingress_bytes = metrics.tun_ingress_bytes.load(Ordering::Relaxed);
            let gso_input_bytes = metrics.gso_input_bytes.load(Ordering::Relaxed);
            let tun_ingress_records_delta =
                tun_ingress_records.saturating_sub(status_tun_ingress_records);
            let tun_ingress_bytes_delta =
                tun_ingress_bytes.saturating_sub(status_tun_ingress_bytes);
            let gso_input_bytes_delta = gso_input_bytes.saturating_sub(status_gso_input_bytes);
            let tun_ingress_bytes_per_second =
                rate_per_second(tun_ingress_bytes_delta, status_elapsed);
            let gso_ingress_ratio_ppm =
                ratio_per_million(gso_input_bytes_delta, tun_ingress_bytes_delta);
            let average_record_bytes = tun_ingress_bytes_delta
                .checked_div(tun_ingress_records_delta)
                .unwrap_or_default();
            let cover_bytes = metrics.cover_tx_bytes.load(Ordering::Relaxed);
            let cover_delta = cover_bytes.saturating_sub(status_cover_bytes);
            let status_real_delta = real_bytes.saturating_sub(status_real_bytes);
            let actual_cover_overhead_per_mille =
                ratio_per_thousand(cover_delta, status_real_delta);
            let actual_cover_overhead_ppm = ratio_per_million(cover_delta, status_real_delta);
            let data_cell_bytes = metrics.data_cell_tx_bytes.load(Ordering::Relaxed);
            let data_cell_payload_bytes =
                metrics.data_cell_payload_tx_bytes.load(Ordering::Relaxed);
            let fec_bytes = metrics.fec_tx_bytes.load(Ordering::Relaxed);
            let data_cell_delta = data_cell_bytes.saturating_sub(status_data_cell_bytes);
            let data_cell_payload_delta =
                data_cell_payload_bytes.saturating_sub(status_data_cell_payload_bytes);
            let fec_delta = fec_bytes.saturating_sub(status_fec_bytes);
            let actual_cell_wire_utilization_per_mille =
                ratio_per_thousand(data_cell_payload_delta, data_cell_delta);
            let actual_fec_wire_overhead_per_mille = ratio_per_thousand(fec_delta, data_cell_delta);
            let trains_built = metrics.trains_built.load(Ordering::Relaxed);
            let records_built = metrics.records_built.load(Ordering::Relaxed);
            let record_bytes_built = metrics.record_bytes_built.load(Ordering::Relaxed);
            let cells_built = metrics.cells_built.load(Ordering::Relaxed);
            let cell_payload_built_bytes = metrics.cell_payload_built_bytes.load(Ordering::Relaxed);
            let unused_cell_capacity_bytes =
                metrics.unused_cell_capacity_bytes.load(Ordering::Relaxed);
            let trains_delta = trains_built.saturating_sub(status_trains_built);
            let records_delta = records_built.saturating_sub(status_records_built);
            let record_bytes_delta = record_bytes_built.saturating_sub(status_record_bytes_built);
            let cells_delta = cells_built.saturating_sub(status_cells_built);
            let cell_payload_built_delta =
                cell_payload_built_bytes.saturating_sub(status_cell_payload_built_bytes);
            let unused_cell_capacity_delta =
                unused_cell_capacity_bytes.saturating_sub(status_unused_cell_capacity_bytes);
            let cell_payload_utilization_per_mille = ratio_per_thousand(
                record_bytes_delta,
                cell_payload_built_delta.saturating_add(unused_cell_capacity_delta),
            );
            let cells_per_megabyte = ratio_scaled_u64(cells_delta, record_bytes_delta, 1_000_000);
            let records_per_train_milli = ratio_scaled_u64(records_delta, trains_delta, 1_000);
            let fec_parity_rx = metrics.fec_parity_rx.load(Ordering::Relaxed);
            let fec_recovered_cells = metrics.fec_recovered_cells.load(Ordering::Relaxed);
            let fec_wasted_parity = metrics.fec_wasted_parity.load(Ordering::Relaxed);
            let repair_requested_cells = metrics.repair_requested_cells.load(Ordering::Relaxed);
            let repair_received_cells = metrics.repair_received_cells.load(Ordering::Relaxed);
            let repair_completed_requests =
                metrics.repair_completed_requests.load(Ordering::Relaxed);
            let repair_completed_requested_cells = metrics
                .repair_completed_requested_cells
                .load(Ordering::Relaxed);
            let repair_latency_micros = metrics.repair_latency_micros.load(Ordering::Relaxed);
            let incoming_parity_delta = fec_parity_rx.saturating_sub(status_fec_parity_rx);
            let incoming_recovered_delta =
                fec_recovered_cells.saturating_sub(status_fec_recovered_cells);
            let incoming_wasted_delta = fec_wasted_parity.saturating_sub(status_fec_wasted_parity);
            let repair_received_delta =
                repair_received_cells.saturating_sub(status_repair_received_cells);
            let repair_completed_delta =
                repair_completed_requests.saturating_sub(status_repair_completed_requests);
            let repair_completed_requested_delta = repair_completed_requested_cells
                .saturating_sub(status_repair_completed_requested_cells);
            let repair_latency_delta =
                repair_latency_micros.saturating_sub(status_repair_latency_micros);
            let incoming_repair_response_latency_average_micros = repair_latency_delta
                .checked_div(repair_completed_delta)
                .unwrap_or_default();
            let incoming_fec_recovery_per_mille =
                ratio_per_thousand(incoming_recovered_delta, incoming_parity_delta);
            let incoming_wasted_parity_per_mille =
                ratio_per_thousand(incoming_wasted_delta, incoming_parity_delta);
            let incoming_repair_hit_per_mille =
                ratio_per_thousand(repair_received_delta, repair_completed_requested_delta);
            let bulk_service_bytes = metrics.bulk_service_bytes.load(Ordering::Relaxed);
            let latency_service_bytes = metrics.latency_service_bytes.load(Ordering::Relaxed);
            let bulk_service_delta = bulk_service_bytes.saturating_sub(status_bulk_service_bytes);
            let latency_service_delta =
                latency_service_bytes.saturating_sub(status_latency_service_bytes);
            let bulk_service_share_ppm = ratio_per_million(
                bulk_service_delta,
                bulk_service_delta.saturating_add(latency_service_delta),
            );
            let latency_sojourn: [u64; LATENCY_SOJOURN_BUCKETS] = std::array::from_fn(|index| {
                metrics.latency_sojourn_buckets[index].load(Ordering::Relaxed)
            });
            let latency_sojourn_delta = std::array::from_fn(|index| {
                latency_sojourn[index].saturating_sub(status_latency_sojourn[index])
            });
            let latency_queue_sojourn_p50_micros =
                histogram_percentile_micros(&latency_sojourn_delta, 50);
            let latency_queue_sojourn_p95_micros =
                histogram_percentile_micros(&latency_sojourn_delta, 95);
            let latency_queue_sojourn_p99_micros =
                histogram_percentile_micros(&latency_sojourn_delta, 99);
            let bulk_flow_service: [u64; BULK_FAIRNESS_BUCKETS] = std::array::from_fn(|index| {
                metrics.bulk_flow_service[index].load(Ordering::Relaxed)
            });
            let bulk_flow_service_delta = std::array::from_fn(|index| {
                bulk_flow_service[index].saturating_sub(status_bulk_flow_service[index])
            });
            let bulk_fairness_ppm = jain_fairness_ppm(&bulk_flow_service_delta);
            let bulk_preemptions = metrics.bulk_preemptions.load(Ordering::Relaxed);
            let bulk_preemption_delay_micros =
                metrics.bulk_preemption_delay_micros.load(Ordering::Relaxed);
            let bulk_preemption_delta = bulk_preemptions.saturating_sub(status_bulk_preemptions);
            let bulk_preemption_delay_delta =
                bulk_preemption_delay_micros.saturating_sub(status_bulk_preemption_delay_micros);
            let bulk_preemption_delay_average_micros = bulk_preemption_delay_delta
                .checked_div(bulk_preemption_delta)
                .unwrap_or_default();
            info!(
                peer = %connection.remote_id(),
                controller_queue_delay_guard_transitions,
                controller_policer_pacing_scale_per_mille,
                controller_policer_pacing_transitions,
                "V2 automatic controller guard status"
            );
            info!(
                peer = %connection.remote_id(),
                reason = ?decision.reason,
                path_epoch = decision.path_epoch,
                samples = decision.sample_count,
                sample_age_millis = 0,
                rtt_micros = rtt.as_micros(),
                minimum_rtt_micros = minimum_rtt.as_micros(),
                congestion_window_bytes,
                current_path_mtu_bytes = current_mtu,
                controller_pacing_rate_bytes_per_second =
                    controller_pacing_rate_bytes_per_second.unwrap_or(0),
                controller_send_quantum_bytes = controller_send_quantum_bytes.unwrap_or(0),
                loss_ppm,
                tx_bytes_per_second = sent_bytes_per_second,
                rx_bytes_per_second = received_bytes_per_second,
                packets_per_second = sent_packets.max(received_packets),
                tun_ingress_bytes_per_second,
                tun_ingress_records,
                tun_ingress_bytes,
                tun_admission_drop_records = metrics
                    .tun_admission_drop_records
                    .load(Ordering::Relaxed),
                tun_admission_drop_bytes = metrics
                    .tun_admission_drop_bytes
                    .load(Ordering::Relaxed),
                average_record_bytes,
                gso_ingress_ratio_ppm,
                train_queue_bytes,
                latency_queue_bytes,
                bulk_service_share_ppm,
                bulk_fairness_ppm,
                bulk_service_quantums = metrics.bulk_service_quantums.load(Ordering::Relaxed),
                latency_service_quantums = metrics
                    .latency_service_quantums
                    .load(Ordering::Relaxed),
                bulk_preemptions,
                bulk_preemption_delay_average_micros,
                bulk_preemption_max_delay_micros = metrics
                    .bulk_preemption_max_delay_micros
                    .load(Ordering::Relaxed),
                latency_queue_sojourn_p50_micros,
                latency_queue_sojourn_p95_micros,
                latency_queue_sojourn_p99_micros,
                cpu_utilization_per_mille,
                train_target_bytes = decision.train_target_bytes,
                train_minimum_bytes = bounds.minimum_train_bytes,
                train_maximum_bytes = bounds.maximum_train_bytes,
                bulk_quantum_cells = decision.bulk_quantum_cells,
                fec = ?decision.fec,
                repair_cache_bytes = decision.repair_cache_bytes,
                send_buffer_bytes = decision.send_buffer_bytes,
                datagram_admission_bytes = connection.datagram_send_buffer_limit(),
                receive_buffer_bytes = decision.receive_buffer_bytes,
                receive_buffer_target_bytes = metrics.receive_buffer_bytes.load(Ordering::Relaxed),
                reassembly_pressure_evictions = metrics
                    .reassembly_pressure_evictions
                    .load(Ordering::Relaxed),
                receive_batch = decision.receive_batch,
                receive_batch_maximum = bounds.maximum_receive_batch,
                cover_profile = ?decision.cover_profile,
                cover_budget_per_mille = decision.cover_overhead_per_mille,
                cover_padding_bytes_per_second = decision.cover_padding_bytes_per_second,
                cover_tx_bytes = cover_bytes,
                cover_rx_bytes = metrics.cover_rx_bytes.load(Ordering::Relaxed),
                actual_cover_overhead_per_mille,
                actual_cover_overhead_ppm,
                interval_quic_udp_payload_tx_bytes = tx_bytes.quic_udp_payload_bytes,
                interval_real_record_tx_bytes = tx_bytes.real_record_bytes,
                interval_packet_train_metadata_tx_bytes = tx_bytes.packet_train_metadata_bytes,
                interval_cell_envelope_tx_bytes = tx_bytes.cell_envelope_bytes,
                interval_fec_tx_bytes = tx_bytes.fec_bytes,
                interval_repair_tx_bytes = repair_tx_bytes,
                interval_repair_request_tx_bytes = tx_bytes.repair_request_bytes,
                interval_repair_response_tx_bytes = tx_bytes.repair_response_bytes,
                interval_other_control_record_tx_bytes = tx_bytes.other_control_record_bytes,
                interval_padding_tx_bytes = tx_bytes.padding_bytes,
                interval_quic_transport_residual_tx_bytes =
                    tx_bytes.quic_transport_residual_bytes,
                interval_accounting_lag_bytes = tx_bytes.interval_accounting_lag_bytes,
                quic_transport_residual_per_mille,
                cell_envelope_overhead_per_mille,
                control_record_tx_bytes = metrics
                    .control_record_tx_bytes
                    .load(Ordering::Relaxed),
                control_record_rx_bytes = metrics
                    .control_record_rx_bytes
                    .load(Ordering::Relaxed),
                repair_request_tx_bytes = metrics
                    .repair_request_tx_bytes
                    .load(Ordering::Relaxed),
                repair_request_rx_bytes = metrics
                    .repair_request_rx_bytes
                    .load(Ordering::Relaxed),
                repair_response_tx_bytes = metrics
                    .repair_response_tx_bytes
                    .load(Ordering::Relaxed),
                repair_response_rx_bytes = metrics
                    .repair_response_rx_bytes
                    .load(Ordering::Relaxed),
                data_cell_tx_bytes = data_cell_bytes,
                data_cell_payload_tx_bytes = data_cell_payload_bytes,
                actual_cell_wire_utilization_per_mille,
                cell_payload_utilization_per_mille,
                cells_per_megabyte,
                records_per_train_milli,
                fec_tx_bytes = fec_bytes,
                fec_stripes_built = metrics.fec_stripes_built.load(Ordering::Relaxed),
                fec_protected_data_cells = metrics
                    .fec_protected_data_cells
                    .load(Ordering::Relaxed),
                fec_parity_cells_built = metrics
                    .fec_parity_cells_built
                    .load(Ordering::Relaxed),
                fec_encode_copy_bytes = metrics.fec_encode_copy_bytes.load(Ordering::Relaxed),
                fec_unprotected_tail_cells = metrics
                    .fec_unprotected_tail_cells
                    .load(Ordering::Relaxed),
                actual_fec_wire_overhead_per_mille,
                incoming_fec_parity_cells = fec_parity_rx,
                incoming_fec_recovered_cells = fec_recovered_cells,
                incoming_fec_wasted_parity = fec_wasted_parity,
                incoming_fec_recovery_per_mille,
                incoming_wasted_parity_per_mille,
                incoming_repair_requested_cells = repair_requested_cells,
                incoming_repair_received_cells = repair_received_cells,
                incoming_repair_hit_per_mille,
                incoming_repair_completed_requests = repair_completed_requests,
                incoming_repair_completed_requested_cells = repair_completed_requested_cells,
                incoming_repair_response_latency_average_micros,
                incoming_repair_response_latency_max_micros = metrics
                    .repair_latency_max_micros
                    .load(Ordering::Relaxed),
                incoming_repair_stale_responses = metrics
                    .repair_stale_responses
                    .load(Ordering::Relaxed),
                incoming_fec_decode_copy_bytes = metrics
                    .fec_decode_copy_bytes
                    .load(Ordering::Relaxed),
                incoming_fec_expired_stripes = metrics
                    .fec_expired_stripes
                    .load(Ordering::Relaxed),
                gso_input_bytes,
                gso_preserved_bytes = metrics.gso_preserved_bytes.load(Ordering::Relaxed),
                gso_fallback_splits = metrics.gso_fallback_splits.load(Ordering::Relaxed),
                protocol_datagram_errors = metrics
                    .protocol_datagram_errors
                    .load(Ordering::Relaxed),
                route_gate_drops = metrics.route_gate_drops.load(Ordering::Relaxed),
                tls_ticket_partition = %ticket_partition,
                zero_rtt_policy = "disabled",
                zero_rtt_accepted = 0_u64,
                zero_rtt_rejected = 0_u64,
                remote_feedback_sequence,
                outgoing_fec_remote_wasted_parity_per_mille =
                    remote_wasted_parity_per_mille,
                outgoing_fec_remote_recovery_per_mille = remote_fec_recovery_per_mille,
                outgoing_repair_remote_hit_per_mille = remote_repair_hit_per_mille,
                outgoing_repair_remote_completed_requests =
                    previous_remote_repair_completed,
                outgoing_repair_remote_response_latency_micros =
                    remote_repair_response_latency.as_micros(),
                outgoing_fec_remote_expired_stripes = metrics
                    .remote_fec_expired_stripes
                    .load(Ordering::Relaxed),
                "V2 automatic tuning status"
            );
            status_at = now;
            status_real_bytes = real_bytes;
            status_tun_ingress_records = tun_ingress_records;
            status_tun_ingress_bytes = tun_ingress_bytes;
            status_gso_input_bytes = gso_input_bytes;
            status_cover_bytes = cover_bytes;
            status_data_cell_bytes = data_cell_bytes;
            status_data_cell_payload_bytes = data_cell_payload_bytes;
            status_fec_bytes = fec_bytes;
            status_trains_built = trains_built;
            status_records_built = records_built;
            status_record_bytes_built = record_bytes_built;
            status_cells_built = cells_built;
            status_cell_payload_built_bytes = cell_payload_built_bytes;
            status_unused_cell_capacity_bytes = unused_cell_capacity_bytes;
            status_fec_parity_rx = fec_parity_rx;
            status_fec_recovered_cells = fec_recovered_cells;
            status_fec_wasted_parity = fec_wasted_parity;
            status_repair_received_cells = repair_received_cells;
            status_repair_completed_requests = repair_completed_requests;
            status_repair_completed_requested_cells = repair_completed_requested_cells;
            status_repair_latency_micros = repair_latency_micros;
            status_bulk_service_bytes = bulk_service_bytes;
            status_latency_service_bytes = latency_service_bytes;
            status_bulk_preemptions = bulk_preemptions;
            status_bulk_preemption_delay_micros = bulk_preemption_delay_micros;
            status_latency_sojourn = latency_sojourn;
            status_bulk_flow_service = bulk_flow_service;
            status_tx_bytes = current_tx_bytes;
        }
        previous = current;
        previous_real_bytes = real_bytes;
        previous_sample_at = sampled_at;
        previous_tun_ingress_records = current_tun_ingress_records;
        previous_tun_ingress_bytes = current_tun_ingress_bytes;
        previous_gso_input_bytes = current_gso_input_bytes;
        previous_reassembly_pressure_evictions = current_reassembly_pressure_evictions;
        previous_train_build_bytes = current_train_build_bytes;
        previous_bulk_preemptions = current_bulk_preemptions;
        previous_bulk_preemption_delay_micros = current_bulk_preemption_delay_micros;
    }
}

#[derive(Debug)]
struct SelectedPathSampleV2 {
    identity: String,
    reliability: PathReliability,
    rtt: Duration,
    congestion_window_bytes: u64,
    current_mtu: u16,
    controller_pacing_rate_bytes_per_second: Option<u64>,
    controller_send_quantum_bytes: Option<u64>,
    controller_queue_delay_guard_transitions: u64,
    controller_policer_pacing_scale_per_mille: u16,
    controller_policer_pacing_transitions: u64,
    controller_snapshot: Option<ControllerSnapshot>,
    controller_tunables: Option<Arc<Bbr3Tunables>>,
}

fn selected_path_sample(connection: &Connection) -> Result<SelectedPathSampleV2> {
    let paths = connection.paths();
    let path = paths
        .iter()
        .find(|path| path.is_selected())
        .context("V2 connection has no selected path")?;
    let reliability = path_reliability(path.is_relay(), path.remote_addr());
    let stats = path.stats();
    let controller = connection
        .congestion_state(path.id())
        .map(|controller| controller.metrics());
    let controller_tunables = connection
        .congestion_tunables(path.id())
        .and_then(|handle| handle.downcast::<Bbr3Tunables>().ok());
    Ok(SelectedPathSampleV2 {
        identity: path_endpoint_identity(path.remote_addr()),
        reliability,
        rtt: stats.rtt,
        congestion_window_bytes: stats.cwnd,
        current_mtu: stats.current_mtu,
        controller_pacing_rate_bytes_per_second: controller
            .as_ref()
            .and_then(|metrics| metrics.pacing_rate),
        controller_send_quantum_bytes: controller.as_ref().and_then(|metrics| metrics.send_quantum),
        controller_queue_delay_guard_transitions: controller
            .as_ref()
            .map_or(0, |metrics| metrics.queue_delay_guard_transitions),
        controller_policer_pacing_scale_per_mille: controller
            .as_ref()
            .map_or(1_000, |metrics| metrics.policer_pacing_scale_per_mille),
        controller_policer_pacing_transitions: controller
            .as_ref()
            .map_or(0, |metrics| metrics.policer_pacing_transitions),
        controller_snapshot: controller.as_ref().and_then(|metrics| metrics.snapshot),
        controller_tunables,
    })
}

fn ticket_partition_label(network_id: &str, cover_profile: u32, quic_version: u32) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ironet-v2/ticket-partition\0");
    hasher.update(network_id.as_bytes());
    let digest = hasher.finalize();
    format!(
        "{}:{cover_profile}:{quic_version}",
        hex::encode(&digest.as_bytes()[..8])
    )
}

fn path_endpoint_identity(remote: &TransportAddr) -> String {
    // noq can recycle its internal PathId during validation/maintenance even
    // when the underlying network path is unchanged, and its local address
    // can move between unresolved/resolved representations during that same
    // maintenance cycle. The authenticated peer's selected remote locator is
    // the stable path identity: it still distinguishes IPv4, IPv6, DERP
    // region/key and address-family/network changes without manufacturing
    // five-second epochs for harmless QUIC/NAT source-port rebinding.
    match remote {
        TransportAddr::Ip(address) => format!("ip:{}", address.ip()),
        TransportAddr::Custom(address) => format!("custom:{address:?}"),
        _ => format!("other:{remote:?}"),
    }
}

fn path_reliability(is_iroh_relay: bool, remote: &TransportAddr) -> PathReliability {
    if is_iroh_relay
        || matches!(
            remote,
            TransportAddr::Custom(address) if DerpAddr::from_custom(address).is_ok()
        )
    {
        PathReliability::ReliableRelay
    } else {
        PathReliability::Datagram
    }
}

fn selected_direct_addresses(connection: &Connection, port: u16) -> Vec<SocketAddr> {
    if port == 0 {
        return Vec::new();
    }
    connection
        .paths()
        .iter()
        .filter(|path| path.is_selected())
        .filter_map(|path| match path.local_addr() {
            LocalTransportAddr::Ip(Some(address))
                if !address.is_unspecified() && !address.is_multicast() =>
            {
                Some(SocketAddr::new(*address, port))
            }
            _ => None,
        })
        .collect()
}

fn selected_path_cost(connection: &Connection) -> u32 {
    connection
        .paths()
        .iter()
        .find(|path| path.is_selected())
        .map(|path| path.rtt().as_micros().clamp(1, u128::from(u32::MAX)) as u32)
        .unwrap_or(1)
}

fn unix_secs(now: SystemTime) -> Result<u64> {
    now.duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")
        .map(|duration| duration.as_secs())
}

fn ratio_per_million(numerator: u64, denominator: u64) -> u32 {
    if denominator == 0 {
        return 0;
    }
    numerator
        .saturating_mul(1_000_000)
        .checked_div(denominator)
        .unwrap_or(u64::MAX)
        .min(1_000_000) as u32
}

fn ratio_per_thousand(numerator: u64, denominator: u64) -> u16 {
    if denominator == 0 {
        return 0;
    }
    numerator
        .saturating_mul(1_000)
        .checked_div(denominator)
        .unwrap_or(u64::MAX)
        .min(1_000) as u16
}

fn ratio_scaled_u64(numerator: u64, denominator: u64, scale: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    (u128::from(numerator) * u128::from(scale) / u128::from(denominator)).min(u128::from(u64::MAX))
        as u64
}

fn rate_per_second(value: u64, elapsed: Duration) -> u64 {
    if elapsed.is_zero() {
        return 0;
    }
    (u128::from(value) * 1_000_000_000 / elapsed.as_nanos()).min(u128::from(u64::MAX)) as u64
}

fn counter_delta(current: u64, previous: u64) -> u64 {
    // Per-path QUIC counters can restart when noq refreshes a path object even
    // though the semantic remote locator and logical session are unchanged.
    // Treat the new counter as the first sample of that replacement instead
    // of manufacturing a zero-rate interval through saturating subtraction.
    current.checked_sub(previous).unwrap_or(current)
}

fn flow_id(key: FlowKey) -> u64 {
    let mut hasher = FxHasher::default();
    key.hash(&mut hasher);
    hasher.finish().max(1)
}

pub fn derived_overlay_address(network_id: &str, endpoint_id: EndpointId) -> Ipv6Addr {
    let mut input = Vec::with_capacity(network_id.len() + endpoint_id.as_bytes().len());
    input.extend_from_slice(network_id.as_bytes());
    input.extend_from_slice(endpoint_id.as_bytes());
    let digest = blake3::hash(&input);
    let mut octets = [0_u8; 16];
    octets.copy_from_slice(&digest.as_bytes()[..16]);
    octets[0] = 0xfd;
    Ipv6Addr::from(octets)
}

/// Derives a stable per-network endpoint address from the RFC 6598 shared
/// address space. A /32 is installed, so no L2/broadcast semantics apply.
pub fn derived_overlay_ipv4_address(network_id: &str, endpoint_id: EndpointId) -> Ipv4Addr {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ironet-v2-overlay-ipv4");
    hasher.update(&(network_id.len() as u64).to_be_bytes());
    hasher.update(network_id.as_bytes());
    hasher.update(endpoint_id.as_bytes());
    let digest = hasher.finalize();
    let host = u32::from_be_bytes(digest.as_bytes()[..4].try_into().unwrap()) & 0x003f_ffff;
    Ipv4Addr::from(0x6440_0000 | host)
}

fn local_overlay_addresses(
    config: &V2RuntimeConfig,
    endpoint_id: EndpointId,
) -> (Ipv4Addr, Ipv6Addr) {
    let ipv4 = config
        .node_addresses
        .iter()
        .find_map(|address| match address.addr() {
            std::net::IpAddr::V4(address) => Some(address),
            std::net::IpAddr::V6(_) => None,
        })
        .unwrap_or_else(|| derived_overlay_ipv4_address(&config.network_id, endpoint_id));
    let ipv6 = config
        .node_addresses
        .iter()
        .find_map(|address| match address.addr() {
            std::net::IpAddr::V6(address) => Some(address),
            std::net::IpAddr::V4(_) => None,
        })
        .unwrap_or_else(|| derived_overlay_address(&config.network_id, endpoint_id));
    (ipv4, ipv6)
}

fn configure_tunnel(
    config: &V2RuntimeConfig,
    local_v4: Ipv4Addr,
    remote_v4: Ipv4Addr,
    local_v6: Ipv6Addr,
    remote_v6: Ipv6Addr,
) -> Result<(Arc<KernelRoutePolicyV2>, KernelRouteGuardV2)> {
    let policy = KernelRoutePolicyV2::from_config(config, local_v4, local_v6);
    policy.cleanup()?;
    let guard = KernelRouteGuardV2(policy.clone());
    run_ip(["link", "set", "dev", &config.tun_name, "up"])?;
    configure_tun_egress_aqm(&config.tun_name)?;
    let local_v4_prefix = format!("{local_v4}/32");
    run_ip([
        "-4",
        "address",
        "replace",
        &local_v4_prefix,
        "dev",
        &config.tun_name,
    ])?;
    policy.install_policy()?;
    policy.replace_route(IpNet::from(IpAddr::V4(remote_v4)))?;
    let local_prefix = format!("{local_v6}/128");
    run_ip([
        "-6",
        "address",
        "replace",
        &local_prefix,
        "dev",
        &config.tun_name,
    ])?;
    policy.replace_route(IpNet::from(IpAddr::V6(remote_v6)))?;
    for route in &config.routes {
        policy.replace_route(*route)?;
    }
    let policy = Arc::new(policy);
    Ok((policy, guard))
}

fn configure_mesh_tunnel(
    config: &V2RuntimeConfig,
    local_v4: Ipv4Addr,
    local_v6: Ipv6Addr,
) -> Result<(Arc<KernelRoutePolicyV2>, KernelRouteGuardV2)> {
    let policy = KernelRoutePolicyV2::from_config(config, local_v4, local_v6);
    policy.cleanup()?;
    let guard = KernelRouteGuardV2(policy.clone());
    run_ip(["link", "set", "dev", &config.tun_name, "up"])?;
    configure_tun_egress_aqm(&config.tun_name)?;
    run_ip([
        "-4",
        "address",
        "replace",
        &format!("{local_v4}/32"),
        "dev",
        &config.tun_name,
    ])?;
    run_ip([
        "-6",
        "address",
        "replace",
        &format!("{local_v6}/128"),
        "dev",
        &config.tun_name,
    ])?;
    policy.install_policy()?;
    for route in &config.routes {
        policy.replace_route(*route)?;
    }
    let policy = Arc::new(policy);
    Ok((policy, guard))
}

fn reconcile_v2_nat(tun_name: &str, prefixes: &[IpNet], enabled: bool) -> Result<()> {
    let ipv4 = prefixes.iter().any(|prefix| prefix.addr().is_ipv4());
    let ipv6 = prefixes.iter().any(|prefix| prefix.addr().is_ipv6());
    if ipv4 {
        set_forwarding("net.ipv4.ip_forward")?;
    }
    if ipv6 {
        set_forwarding("net.ipv6.conf.all.forwarding")?;
    }
    if !enabled || prefixes.is_empty() {
        // Pure-routing nodes must not require firewall tooling. Only touch a
        // family when a previous NAT generation actually left owned state;
        // this still makes NAT -> routing reloads remove the old generation.
        for command in ["iptables", "ip6tables"] {
            if v2_nat_family_has_owned_state(command)? {
                cleanup_v2_nat_family(command)?;
            }
        }
        if !prefixes.is_empty() {
            info!(prefixes = prefixes.len(), "V2 subnet uses pure routing");
        }
        return Ok(());
    }

    for (command, family_v4) in [("iptables", true), ("ip6tables", false)] {
        let family = prefixes
            .iter()
            .filter(|prefix| prefix.addr().is_ipv4() == family_v4)
            .copied()
            .collect::<Vec<_>>();
        if family.is_empty() {
            cleanup_v2_nat_family(command)?;
        } else {
            install_v2_nat_family(command, tun_name, &family)?;
        }
    }
    info!(
        interface = tun_name,
        prefixes = prefixes.len(),
        "enabled V2 subnet NAT"
    );
    Ok(())
}

/// Remove every V2-owned NAT generation. The daemon calls this only when its
/// supervisor exits; ordinary peer loss and data-plane generation rebuilds
/// intentionally leave the active kernel/conntrack topology in place.
pub(crate) fn cleanup_v2_nat_all() -> Result<()> {
    cleanup_v2_nat_family("iptables")?;
    cleanup_v2_nat_family("ip6tables")
}

fn set_forwarding(key: &str) -> Result<()> {
    let output = Command::new("sysctl")
        .args(["-q", "-w", &format!("{key}=1")])
        .output()
        .context("enabling V2 kernel forwarding")?;
    ensure!(
        output.status.success(),
        "enabling V2 kernel forwarding failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

fn install_v2_nat_family(command: &str, tun_name: &str, prefixes: &[IpNet]) -> Result<()> {
    ensure!(!prefixes.is_empty(), "V2 NAT generation has no prefixes");
    let active_slot = V2_NAT_INGRESS_CHAINS
        .iter()
        .position(|chain| firewall_rule_exists(command, "mangle", "PREROUTING", chain));
    let next_slot = active_slot.map_or(0, |slot| 1 - slot);
    let ingress = V2_NAT_INGRESS_CHAINS[next_slot];
    let egress = V2_NAT_EGRESS_CHAINS[next_slot];

    // Recover a partially installed inactive slot before constructing the new
    // generation. The active slot remains untouched until both replacement
    // chains are fully populated.
    cleanup_v2_nat_chain(command, "mangle", "PREROUTING", ingress)?;
    cleanup_v2_nat_chain(command, "nat", "POSTROUTING", egress)?;
    run_firewall(command, &["-t", "mangle", "-N", ingress])?;
    run_firewall(
        command,
        &[
            "-t",
            "mangle",
            "-A",
            ingress,
            "-i",
            tun_name,
            "-j",
            "CONNMARK",
            "--set-xmark",
            V2_NAT_CONNMARK,
        ],
    )?;
    run_firewall(command, &["-t", "nat", "-N", egress])?;
    for prefix in prefixes {
        run_firewall(
            command,
            &[
                "-t",
                "nat",
                "-A",
                egress,
                "-m",
                "connmark",
                "--mark",
                V2_NAT_CONNMARK,
                "-d",
                &prefix.to_string(),
                "-j",
                "MASQUERADE",
            ],
        )?;
    }

    // Install the egress decision before admitting newly marked ingress
    // connections. During the overlap both generations are valid and the
    // CONNMARK operation is idempotent, so there is no rule-free interval.
    run_firewall(
        command,
        &["-t", "nat", "-I", "POSTROUTING", "1", "-j", egress],
    )?;
    run_firewall(
        command,
        &["-t", "mangle", "-I", "PREROUTING", "1", "-j", ingress],
    )?;

    for slot in 0..V2_NAT_INGRESS_CHAINS.len() {
        if slot != next_slot {
            cleanup_v2_nat_chain(command, "mangle", "PREROUTING", V2_NAT_INGRESS_CHAINS[slot])?;
            cleanup_v2_nat_chain(command, "nat", "POSTROUTING", V2_NAT_EGRESS_CHAINS[slot])?;
        }
    }
    cleanup_v2_nat_chain(command, "mangle", "PREROUTING", LEGACY_V2_NAT_INGRESS_CHAIN)?;
    cleanup_v2_nat_chain(command, "nat", "POSTROUTING", LEGACY_V2_NAT_EGRESS_CHAIN)
}

fn firewall_rule_exists(command: &str, table: &str, hook: &str, chain: &str) -> bool {
    Command::new(command)
        .args(["-t", table, "-C", hook, "-j", chain])
        .output()
        .is_ok_and(|output| output.status.success())
}

fn cleanup_v2_nat_chain(command: &str, table: &str, hook: &str, chain: &str) -> Result<()> {
    loop {
        let output = Command::new(command)
            .args(["-t", table, "-D", hook, "-j", chain])
            .output()
            .with_context(|| format!("removing V2 NAT jump with {command}"))?;
        if !output.status.success() {
            break;
        }
    }
    for action in ["-F", "-X"] {
        Command::new(command)
            .args(["-t", table, action, chain])
            .output()
            .with_context(|| format!("cleaning V2 NAT chain with {command}"))?;
    }
    Ok(())
}

fn cleanup_v2_nat_family(command: &str) -> Result<()> {
    if !firewall_command_available(command)? {
        return Ok(());
    }
    for chain in V2_NAT_INGRESS_CHAINS
        .iter()
        .copied()
        .chain(std::iter::once(LEGACY_V2_NAT_INGRESS_CHAIN))
    {
        cleanup_v2_nat_chain(command, "mangle", "PREROUTING", chain)?;
    }
    for chain in V2_NAT_EGRESS_CHAINS
        .iter()
        .copied()
        .chain(std::iter::once(LEGACY_V2_NAT_EGRESS_CHAIN))
    {
        cleanup_v2_nat_chain(command, "nat", "POSTROUTING", chain)?;
    }
    Ok(())
}

fn firewall_command_available(command: &str) -> Result<bool> {
    match Command::new(command).arg("--version").output() {
        Ok(output) => {
            ensure!(
                output.status.success(),
                "checking {command} availability failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("checking {command} availability")),
    }
}

fn v2_nat_family_has_owned_state(command: &str) -> Result<bool> {
    if !firewall_command_available(command)? {
        return Ok(false);
    }
    for table in ["mangle", "nat"] {
        let output = Command::new(command)
            .args(["-t", table, "-S"])
            .output()
            .with_context(|| format!("inspecting {command} V2 NAT state"))?;
        ensure!(
            output.status.success(),
            "inspecting {command} V2 NAT state failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        let rules = String::from_utf8_lossy(&output.stdout);
        if V2_NAT_INGRESS_CHAINS
            .iter()
            .chain(V2_NAT_EGRESS_CHAINS.iter())
            .copied()
            .chain([LEGACY_V2_NAT_INGRESS_CHAIN, LEGACY_V2_NAT_EGRESS_CHAIN])
            .any(|chain| rules.contains(chain))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn run_firewall(command: &str, arguments: &[&str]) -> Result<()> {
    let output = Command::new(command)
        .args(arguments)
        .output()
        .with_context(|| format!("executing {command} for V2 subnet NAT"))?;
    ensure!(
        output.status.success(),
        "{command} failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

fn run_ip<const N: usize>(arguments: [&str; N]) -> Result<()> {
    let output = Command::new("ip")
        .args(arguments)
        .output()
        .context("executing iproute2 for V2 TUN")?;
    if !output.status.success() {
        bail!(
            "iproute2 failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn configure_tun_egress_aqm(tun_name: &str) -> Result<()> {
    let packet_limit = TUN_FQ_CODEL_PACKET_LIMIT.to_string();
    let memory_limit = TUN_FQ_CODEL_MEMORY_BYTES.to_string();
    let output = Command::new("tc")
        .args([
            "qdisc",
            "replace",
            "dev",
            tun_name,
            "root",
            "fq_codel",
            "limit",
            &packet_limit,
            "memory_limit",
            &memory_limit,
            "ecn",
        ])
        .output()
        .context("executing tc for V2 TUN egress AQM")?;
    ensure!(
        output.status.success(),
        "tc fq_codel setup failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    info!(
        interface = tun_name,
        packet_limit = TUN_FQ_CODEL_PACKET_LIMIT,
        memory_limit_bytes = TUN_FQ_CODEL_MEMORY_BYTES,
        "configured V2 TUN fq_codel backpressure boundary"
    );
    Ok(())
}

fn run_ip_vec(arguments: &[String]) -> Result<()> {
    let output = Command::new("ip")
        .args(arguments)
        .output()
        .context("executing iproute2 for V2 policy route")?;
    ensure!(
        output.status.success(),
        "iproute2 failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(())
}

fn host_prefix_v2(address: IpAddr) -> String {
    format!("{address}/{}", if address.is_ipv4() { 32 } else { 128 })
}

fn remove_ip_rule(
    family: &str,
    priority: u32,
    table: u32,
    destination: Option<&str>,
) -> Result<()> {
    let priority = priority.to_string();
    let table = table.to_string();
    // Repeatedly delete to recover duplicates left by a killed older build.
    // The first non-zero status means the owned key no longer exists.
    for _ in 0..32 {
        let mut arguments = vec![family, "rule", "del", "priority", &priority];
        if let Some(destination) = destination {
            arguments.extend(["to", destination]);
        }
        arguments.extend(["lookup", if table == "254" { "main" } else { &table }]);
        let output = Command::new("ip")
            .args(arguments)
            .output()
            .context("removing stale V2 policy-routing rule")?;
        if !output.status.success() {
            break;
        }
    }
    Ok(())
}

fn run_ip_allow_failure<const N: usize>(arguments: [&str; N]) -> Result<()> {
    Command::new("ip")
        .args(arguments)
        .output()
        .context("executing idempotent iproute2 cleanup")?;
    Ok(())
}

#[derive(Debug)]
struct CpuSampler {
    previous_ticks: Option<u64>,
    previous_at: Instant,
    ticks_per_second: u64,
}

async fn cpu_sampler_loop(runtime_state: Arc<V2RuntimeState>) -> Result<()> {
    let mut sampler = CpuSampler::new();
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        runtime_state
            .cpu_utilization_per_mille
            .store(u64::from(sampler.sample()), Ordering::Relaxed);
    }
}

impl CpuSampler {
    fn new() -> Self {
        let ticks_per_second = Command::new("getconf")
            .arg("CLK_TCK")
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(100);
        Self {
            previous_ticks: process_cpu_ticks(),
            previous_at: Instant::now(),
            ticks_per_second,
        }
    }

    fn sample(&mut self) -> u16 {
        let now = Instant::now();
        let current = process_cpu_ticks();
        let value = match (self.previous_ticks, current) {
            (Some(previous), Some(current)) => {
                let elapsed = now
                    .saturating_duration_since(self.previous_at)
                    .as_micros()
                    .max(1);
                u128::from(current.saturating_sub(previous))
                    .saturating_mul(1_000_000)
                    .saturating_mul(1_000)
                    .checked_div(u128::from(self.ticks_per_second).saturating_mul(elapsed))
                    .unwrap_or(u128::MAX)
                    .min(1_000) as u16
            }
            _ => 0,
        };
        self.previous_ticks = current;
        self.previous_at = now;
        value
    }
}

fn process_cpu_ticks() -> Option<u64> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let tail = stat.rsplit_once(") ")?.1;
    let fields = tail.split_ascii_whitespace().collect::<Vec<_>>();
    let user: u64 = fields.get(11)?.parse().ok()?;
    let system: u64 = fields.get(12)?.parse().ok()?;
    Some(user.saturating_add(system))
}

#[cfg(test)]
mod tests {
    use iroh::SecretKey;

    use super::*;

    fn test_packet_info() -> PacketInfo {
        PacketInfo {
            source: "192.0.2.1".parse().unwrap(),
            destination: "198.51.100.2".parse().unwrap(),
            protocol: 6,
            source_port: Some(40_000),
            destination_port: Some(5201),
            length: 90,
            latency_protected: false,
        }
    }

    fn product_config() -> crate::config::Config {
        toml::from_str(include_str!("../config/example.toml")).unwrap()
    }

    #[test]
    fn autotune_tap_is_versioned_complete_and_json_roundtrips() {
        let peer = SecretKey::from_bytes(&[63; 32]).public();
        let telemetry = PathTelemetryV2 {
            path_epoch: 7,
            reliability: PathReliability::Datagram,
            rtt: Duration::from_millis(85),
            min_rtt: Duration::from_millis(80),
            queue_delay: Duration::from_millis(5),
            loss_ppm: 12_000,
            burst_loss_cells: 2,
            reorder_ppm: 300,
            receiver_goodput_bytes_per_second: 4_700_000,
            residual_loss_ppm: 1_200,
            latency_sojourn_p95_micros: 8_000,
            latency_sojourn_p50_micros: 4_000,
            latency_sojourn_p99_micros: 12_000,
            latency_queue_recently_nonempty: true,
            delivery_rate_bytes_per_second: 6_000_000,
            controller_pacing_rate_bytes_per_second: 5_500_000,
            controller_send_quantum_bytes: 64_000,
            controller_state: 5,
            controller_bw_bytes_per_second: 5_000_000,
            controller_inflight_longterm_bytes: 512_000,
            controller_guard_transitions_delta: 1,
            controller_app_limited: false,
            controller_tunables_generation: 9,
            controller_params_generation: 9,
            controller_clamped_writes: 2,
            receive_rate_bytes_per_second: 50_000_000,
            packets_per_second: 4_000,
            tun_ingress_bytes_per_second: 5_000_000,
            average_record_bytes: 1_400,
            gso_ingress_ratio_ppm: 500_000,
            packet_train_queue_bytes: 32_000,
            latency_queue_bytes: 64,
            reassembly_pressure_evictions: 1,
            remote_expired_stripes_delta: 2,
            train_build_bytes_per_second: 4_900_000,
            bulk_preemption_delay_average_micros: 750,
            cpu_utilization_per_mille: 420,
            wasted_parity_per_mille: 900,
            fec_recovery_per_mille: 80,
            repair_hit_per_mille: 950,
            repair_completed_requests: 11,
            repair_response_latency: Duration::from_millis(90),
            real_traffic_bytes_per_second: 4_800_000,
        };
        let decision = AutoTunerV2::new(AutoTuneBoundsV2::default(), 7).observe(telemetry);
        let record = autotune_tap_record(
            peer,
            "partition",
            AutotuneTapSampleV2 {
                sampled_unix_micros: 1_234_567,
                sample_elapsed: Duration::from_secs(1),
                telemetry,
                decision,
                utility: UtilitySample {
                    total: 1.25,
                    components: [2.0, -0.1, -0.2, -0.1, -0.1, -0.1, -0.1, -0.05],
                    goodput_bytes_per_second: 4_700_000,
                },
                wire_cost: WireCostV2 {
                    payload_bytes: 4_700_000,
                    parity_bytes: 120_000,
                    repair_bytes: 8_000,
                    cover_bytes: 0,
                    cell_envelope_bytes: 40_000,
                },
                force_applied: false,
                learner: None,
                policy_id: "bandit-vivace@1",
                policy_source: "builtin",
                shadow_policy_id: None,
                shadow: None,
                path_identity: "ip:2001:db8::1",
                controller_cwnd_bytes: 512_000,
                adaptive_cwnd_floor_bytes: 256_000,
            },
        );
        let encoded = serde_json::to_string(&record).unwrap();
        let decoded: serde_json::Value = serde_json::from_str(&encoded).unwrap();

        assert_eq!(decoded["schema_version"], 5);
        assert_eq!(decoded["force_applied"], false);
        assert_eq!(decoded["path_identity"], "ip:2001:db8::1");
        assert_eq!(decoded["policy"]["id"], "bandit-vivace@1");
        assert_eq!(decoded["sample_interval_micros"], 1_000_000);
        assert_eq!(decoded["telemetry"]["reorder_ppm"], 300);
        assert_eq!(decoded["utility"]["goodput_bytes_per_second"], 4_700_000);
        assert_eq!(decoded["wire_cost"]["parity_bytes"], 120_000);
        assert_eq!(
            decoded["telemetry"]["real_traffic_bytes_per_second"],
            4_800_000
        );
        assert_eq!(decoded["decision"]["path_epoch"], 7);
        assert!(decoded["decision"].get("fec").is_some());
        assert_eq!(decoded["decision"]["bbr"]["preset"], "LossyRadio");
        assert_eq!(decoded["controller"]["congestion_window_bytes"], 512_000);
        assert_eq!(decoded["controller"]["adaptive_cwnd_floor_bytes"], 256_000);
        assert!(decoded.get("shadow").is_some());
    }

    #[test]
    fn shadow_evaluator_runs_independent_policy_without_changing_wire_action() {
        let telemetry = crate::protocol::v2::tuning::tests_fixture::sample(1);
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let mut baseline = tuner.observe(telemetry);
        baseline.sample_count = 8;
        let mut policy = crate::protocol::v2::policy::builtin().unwrap();
        let context =
            crate::protocol::v2::learner::ContextKeyV2::classify_with(&telemetry, &policy.contexts);
        policy.priors.insert(
            format!(
                "r{}-b{}-l{}-{}",
                context.rtt_class,
                context.rate_class,
                context.loss_class,
                if context.reliable {
                    "reliable"
                } else {
                    "datagram"
                }
            ),
            std::collections::BTreeMap::from([(
                "private-aggressive".to_owned(),
                crate::protocol::v2::policy::PosteriorSpecV2 {
                    observations: 100,
                    mean: 100.0,
                },
            )]),
        );
        policy.digest = policy.calculated_digest().unwrap();
        let mut shadow = ShadowEvaluatorV2::new(policy, Objective::Balanced, 17);
        let start = Instant::now();
        shadow.observe(start, &tuner, &telemetry, &WireCostV2::default(), baseline);
        let evaluation = shadow.observe(
            start + Duration::from_secs(20),
            &tuner,
            &telemetry,
            &WireCostV2::default(),
            baseline,
        );
        assert_eq!(evaluation.trace.mode, LearnerModeV2::Shadow);
        assert_eq!(evaluation.trace.applied_preset, baseline.bbr.preset);
        assert_eq!(
            evaluation.trace.proposed_preset,
            Bbr3PresetV2::PrivateAggressive
        );
        assert_eq!(
            evaluation.decision.bbr.preset,
            Bbr3PresetV2::PrivateAggressive
        );
        assert_eq!(evaluation.decision.train_target_bytes, 64 * 1024);
        assert_eq!(evaluation.decision.bulk_quantum_cells, 4);
        assert_ne!(evaluation.decision, baseline);
        assert!(evaluation.utility.total.is_finite());
    }

    #[test]
    fn bbr_proposal_publish_is_atomic_idempotent_and_preset_complete() {
        let tunables = Bbr3Tunables::default();
        let proposal = Bbr3ProposalV2::for_preset(Bbr3PresetV2::LossyRadio, 0);
        assert!(apply_bbr3_proposal(&tunables, proposal, 0));
        assert_eq!(tunables.generation.load(Ordering::Acquire), 1);
        assert_eq!(
            tunables
                .probe_bw_up_pacing_gain_milli
                .load(Ordering::Relaxed),
            1_250
        );
        assert_eq!(
            tunables
                .queue_delay_guard_inflation_milli
                .load(Ordering::Relaxed),
            800
        );
        assert!(!apply_bbr3_proposal(&tunables, proposal, 0));
        assert_eq!(tunables.generation.load(Ordering::Acquire), 1);

        let policer = Bbr3ProposalV2::for_preset(Bbr3PresetV2::Policer, 1_000_000);
        assert!(apply_bbr3_proposal(&tunables, policer, 0));
        assert_eq!(
            tunables
                .pacing_rate_cap_bytes_per_second
                .load(Ordering::Relaxed),
            970_000
        );
        assert_eq!(tunables.loss_is_congestion.load(Ordering::Relaxed), 1);
    }

    /// Raw snapshot of every shared tunable, for cross-path comparison.
    fn tunables_snapshot(tunables: &Bbr3Tunables) -> [u64; 20] {
        [
            u64::from(
                tunables
                    .probe_bw_up_pacing_gain_milli
                    .load(Ordering::Relaxed),
            ),
            u64::from(
                tunables
                    .probe_bw_down_pacing_gain_milli
                    .load(Ordering::Relaxed),
            ),
            u64::from(tunables.cruise_pacing_gain_milli.load(Ordering::Relaxed)),
            u64::from(tunables.default_cwnd_gain_milli.load(Ordering::Relaxed)),
            u64::from(tunables.probe_bw_up_cwnd_gain_milli.load(Ordering::Relaxed)),
            u64::from(tunables.headroom_milli.load(Ordering::Relaxed)),
            u64::from(tunables.beta_milli.load(Ordering::Relaxed)),
            u64::from(tunables.loss_thresh_milli.load(Ordering::Relaxed)),
            u64::from(tunables.loss_is_congestion.load(Ordering::Relaxed)),
            u64::from(
                tunables
                    .queue_delay_guard_inflation_milli
                    .load(Ordering::Relaxed),
            ),
            tunables
                .queue_delay_guard_slack_micros
                .load(Ordering::Relaxed),
            tunables.probe_rtt_interval_millis.load(Ordering::Relaxed),
            tunables.probe_rtt_duration_millis.load(Ordering::Relaxed),
            u64::from(tunables.probe_rtt_cwnd_gain_milli.load(Ordering::Relaxed)),
            tunables.min_probe_wait_millis.load(Ordering::Relaxed),
            tunables.max_added_probe_wait_millis.load(Ordering::Relaxed),
            tunables
                .pacing_rate_cap_bytes_per_second
                .load(Ordering::Relaxed),
            tunables.cwnd_floor_bytes.load(Ordering::Relaxed),
            tunables.cwnd_cap_bytes.load(Ordering::Relaxed),
            tunables
                .startup_bw_hint_bytes_per_second
                .load(Ordering::Relaxed),
        ]
    }

    #[test]
    fn bbr_effective_publish_matches_the_legacy_proposal_path() {
        use crate::protocol::v2::policy::api::BbrHostExt;

        const PRESETS: [Bbr3PresetV2; 7] = [
            Bbr3PresetV2::SharedConservative,
            Bbr3PresetV2::PrivateAggressive,
            Bbr3PresetV2::LossyRadio,
            Bbr3PresetV2::Policer,
            Bbr3PresetV2::LongFat,
            Bbr3PresetV2::RelayReliable,
            Bbr3PresetV2::LowRttHost,
        ];
        for preset in PRESETS {
            for (cap, floor) in [(0, 0), (970_000, 208 * 1024)] {
                let proposal = Bbr3ProposalV2::for_preset(preset, cap);
                let legacy = Bbr3Tunables::default();
                assert!(apply_bbr3_proposal(&legacy, proposal, floor));
                let effective = BbrEffectiveV1::from_proposal(&proposal);
                let full = Bbr3Tunables::default();
                assert!(apply_bbr3_effective(&full, &effective, floor));
                assert_eq!(
                    tunables_snapshot(&legacy),
                    tunables_snapshot(&full),
                    "preset {preset:?} cap {cap} floor {floor}"
                );
                // Both paths are idempotent.
                assert!(!apply_bbr3_proposal(&legacy, proposal, floor));
                assert!(!apply_bbr3_effective(&full, &effective, floor));
            }
        }
    }

    #[test]
    fn repair_wait_policy_scales_the_adaptive_minimum_age() {
        let metrics = RuntimeMetrics::default();
        metrics
            .repair_minimum_age_micros
            .store(200_000, Ordering::Relaxed);
        assert_eq!(
            adaptive_repair_minimum_age(&metrics),
            Duration::from_millis(200)
        );
        metrics.repair_wait_policy.store(
            RepairWaitPolicyV2::Eager.to_metrics_code(),
            Ordering::Relaxed,
        );
        assert_eq!(
            adaptive_repair_minimum_age(&metrics),
            Duration::from_millis(100)
        );
        metrics.repair_wait_policy.store(
            RepairWaitPolicyV2::AfterFecWindow.to_metrics_code(),
            Ordering::Relaxed,
        );
        assert_eq!(
            adaptive_repair_minimum_age(&metrics),
            Duration::from_millis(200)
        );
        metrics.repair_wait_policy.store(
            RepairWaitPolicyV2::Patient.to_metrics_code(),
            Ordering::Relaxed,
        );
        assert_eq!(
            adaptive_repair_minimum_age(&metrics),
            Duration::from_millis(400)
        );
        // Patient is capped so Repair stays responsive after migration.
        metrics
            .repair_minimum_age_micros
            .store(1_000_000, Ordering::Relaxed);
        assert_eq!(
            adaptive_repair_minimum_age(&metrics),
            Duration::from_secs(2)
        );
        // Unknown codes degrade to the host default.
        metrics.repair_wait_policy.store(99, Ordering::Relaxed);
        assert_eq!(
            adaptive_repair_minimum_age(&metrics),
            Duration::from_secs(1)
        );
    }

    #[test]
    fn queued_demand_sets_a_quantized_bdp_cwnd_floor_without_operator_input() {
        let mut telemetry = crate::protocol::v2::tuning::tests_fixture::sample(1);
        telemetry.controller_app_limited = false;
        telemetry.min_rtt = Duration::from_millis(20);
        telemetry.rtt = Duration::from_millis(22);
        telemetry.queue_delay = Duration::from_millis(2);
        telemetry.packet_train_queue_bytes = 256 * 1024;
        telemetry.tun_ingress_bytes_per_second = 4_000_000;
        telemetry.delivery_rate_bytes_per_second = 4_200_000;
        telemetry.real_traffic_bytes_per_second = 3_800_000;
        let proposal = Bbr3ProposalV2::for_preset(Bbr3PresetV2::LossyRadio, 0);

        let floor = adaptive_cwnd_floor(telemetry, proposal);
        assert_eq!(floor, 208 * 1024);
        let tunables = Bbr3Tunables::default();
        assert!(apply_bbr3_proposal(&tunables, proposal, floor));
        assert_eq!(
            tunables.cwnd_floor_bytes.load(Ordering::Relaxed),
            208 * 1024
        );

        telemetry.queue_delay = Duration::from_millis(11);
        assert_eq!(adaptive_cwnd_floor(telemetry, proposal), 0);
        telemetry.queue_delay = Duration::from_millis(2);
        telemetry.packet_train_queue_bytes = 0;
        assert_eq!(adaptive_cwnd_floor(telemetry, proposal), 0);
    }

    #[test]
    fn learner_on_applies_complete_policy_action_while_shadow_keeps_baseline() {
        let telemetry = crate::protocol::v2::tuning::tests_fixture::sample(1);
        let mut tuner = AutoTunerV2::new(AutoTuneBoundsV2::default(), 1);
        let baseline = tuner.observe(telemetry);
        let policy = crate::protocol::v2::policy::builtin().unwrap();
        let trace = LearnerTraceV2 {
            mode: LearnerModeV2::On,
            context: crate::protocol::v2::learner::ContextKeyV2::classify(&telemetry),
            baseline_preset: baseline.bbr.preset,
            proposed_preset: Bbr3PresetV2::LossyRadio,
            applied_preset: Bbr3PresetV2::LossyRadio,
            predicted_advantage: 0.1,
            exploring: true,
            rollback: false,
            rollbacks: 0,
            fine_up_gain_delta_milli: 0,
            fine_headroom_delta_milli: 0,
            fine_cwnd_gain_delta_milli: 0,
        };
        let mut learned = baseline;
        learned.bbr = Bbr3ProposalV2::for_preset(Bbr3PresetV2::LossyRadio, 0);
        let applied = constrain_learned_policy_action(&tuner, &policy, telemetry, learned, trace);
        assert_eq!(applied.fec.unwrap().parity_cells, 2);
        assert_eq!(applied.train_target_bytes, 32 * 1024);
        assert_eq!(applied.bulk_quantum_cells, 2);

        let shadow = LearnerTraceV2 {
            mode: LearnerModeV2::Shadow,
            ..trace
        };
        assert_eq!(
            constrain_learned_policy_action(&tuner, &policy, telemetry, baseline, shadow),
            baseline
        );
    }

    #[test]
    fn autotune_force_parser_is_strict_and_distinguishes_fec_off() {
        let forced = parse_autotune_force(
            r#"{"bbr_preset":"lossy-radio","fec":"8+1","train_target_bytes":32768,"bulk_quantum_cells":2,"cover_profile":"live-broadcast","cover_overhead_per_mille":30}"#,
        )
        .unwrap();
        assert_eq!(forced.bbr_preset, Some(Bbr3PresetV2::LossyRadio));
        assert_eq!(
            forced.fec,
            Some(Some(FecGeometryV2 {
                data_cells: 8,
                parity_cells: 1,
            }))
        );
        assert_eq!(forced.train_target_bytes, Some(32 * 1024));
        assert_eq!(forced.bulk_quantum_cells, Some(2));
        assert_eq!(
            forced.cover_profile,
            Some(CoverTrafficProfileV2::LiveBroadcast)
        );
        assert_eq!(forced.cover_overhead_per_mille, Some(30));

        assert_eq!(
            parse_autotune_force(r#"{"fec":null}"#).unwrap().fec,
            Some(None)
        );
        assert!(parse_autotune_force("{}").is_err());
        assert!(parse_autotune_force(r#"{"unknown":1}"#).is_err());
        assert!(parse_autotune_force(r#"{"fec":"2+2"}"#).is_err());
        assert!(parse_autotune_force(r#"{"bbr_preset":"unknown"}"#).is_err());
    }

    #[test]
    fn product_configuration_has_one_strict_v2_runtime_translation() {
        let mut config = product_config();
        config.routing.max_egress_mbps = Some(80);
        config.autotune.mode = AutotuneMode::On;
        let runtime = V2RuntimeConfig::from_product_config(&config).unwrap();
        assert_eq!(runtime.bind, "[::]:4000".parse().unwrap());
        assert_eq!(runtime.tun_name, config.node_interface);
        assert_eq!(runtime.isolate_overlay, config.routing.isolate_overlay);
        assert_eq!(runtime.routing_table, config.routing.table);
        assert_eq!(runtime.routing_rule_priority, config.routing.rule_priority);
        assert_eq!(runtime.node_addresses, config.node_addresses);
        assert_eq!(runtime.advertised_routes, config.advertised_prefixes);
        assert_eq!(
            runtime.excluded_underlay_prefixes,
            config.excluded_underlay_prefixes
        );
        let path_exclusions = runtime.underlay_path_exclusions();
        assert!(
            config
                .node_addresses
                .iter()
                .chain(&config.advertised_prefixes)
                .all(|prefix| path_exclusions.contains(prefix))
        );
        assert_eq!(runtime.cover_sni_pool, ["media.example"]);
        assert!(runtime.peer_id.is_none());
        assert!(!runtime.accept_first_peer);
        assert!(runtime.peer_addresses.is_empty());
        assert_eq!(runtime.autotune.mode, AutotuneMode::On);
        assert_eq!(runtime.path_migration, config.path_migration);
        assert_eq!(runtime.max_egress_bytes_per_second, Some(10_000_000));
    }

    #[test]
    fn excluded_underlay_gate_covers_both_ends_of_discovered_ip_paths() {
        use iroh::endpoint::transports::Addr;

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

    #[tokio::test]
    async fn live_snapshot_publishes_gateway_and_signed_presence_directory() {
        let mut config = product_config();
        config.routing.transit_enabled = true;
        config.routing.nat_enabled = true;
        config.advertised_prefixes = vec!["11.6.1.0/24".parse().unwrap()];
        let runtime = V2RuntimeConfig::from_product_config(&config).unwrap();
        let local_key = SecretKey::from_bytes(&[51; 32]);
        let remote_key = SecretKey::from_bytes(&[52; 32]);
        let state = V2RuntimeState::new(&runtime, local_key.public());
        let now = SystemTime::now();
        let now_secs = now.duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut directory = PresenceDirectoryV2::new(runtime.network_id.clone()).unwrap();
        for (key, sequence, node_address, prefix) in [
            (&local_key, 1, "21.0.0.1/32", "11.6.1.0/24"),
            (&remote_key, 2, "21.0.0.2/32", "10.52.0.0/16"),
        ] {
            let presence = SignedPresenceV2::sign(
                PresenceBodyV2 {
                    owner: key.public(),
                    sequence,
                    issued_unix_secs: now_secs,
                    expires_unix_secs: now_secs + 180,
                    direct_addresses: vec!["[2001:db8::1]:4000".parse().unwrap()],
                    node_addresses: vec![node_address.parse().unwrap()],
                    prefixes: vec![prefix.parse().unwrap()],
                    links: Vec::new(),
                    transit_enabled: key.public() == local_key.public(),
                },
                key,
                &runtime.network_id,
            )
            .unwrap();
            directory.insert(presence, now).unwrap();
        }
        state.publish_presence_directory(&directory, 32);
        state.publish_routes([
            "21.0.0.2/32".parse().unwrap(),
            "10.52.0.0/16".parse().unwrap(),
        ]);

        let snapshot = state.live_snapshot().await.unwrap();
        assert!(snapshot.routes_ready);
        assert_eq!(snapshot.routes.len(), 2);
        assert!(snapshot.routes.iter().all(|route| route.present));
        assert!(snapshot.gateway.transit_enabled);
        assert!(snapshot.gateway.subnet_nat_enabled);
        assert_eq!(
            snapshot.gateway.advertised_prefixes,
            config.advertised_prefixes
        );
        assert!(snapshot.mesh.enabled);
        assert_eq!(snapshot.mesh.directory_entries, 2);
        assert_eq!(snapshot.mesh.max_total_peers, 32);
        assert_eq!(snapshot.mesh.nodes.len(), 2);
        assert!(snapshot.mesh.nodes.iter().any(|node| {
            node.endpoint_id == remote_key.public().to_string()
                && node.node_addresses == ["21.0.0.2/32".parse().unwrap()]
                && node.prefixes == ["10.52.0.0/16".parse().unwrap()]
        }));
    }

    #[tokio::test]
    async fn ttl_oam_is_correlated_to_the_originating_trace_train() {
        let runtime = V2RuntimeConfig::from_product_config(&product_config()).unwrap();
        let local_key = SecretKey::from_bytes(&[61; 32]);
        let reporter_key = SecretKey::from_bytes(&[62; 32]);
        let state = V2RuntimeState::new(&runtime, local_key.public());
        state
            .mesh
            .write()
            .unwrap()
            .nodes
            .push(crate::status::MeshNodeStatus {
                endpoint_id: reporter_key.public().to_string(),
                sequence: 1,
                expires_unix_secs: u64::MAX,
                direct_addresses: Vec::new(),
                node_addresses: vec!["21.0.0.7/32".parse().unwrap()],
                prefixes: Vec::new(),
                transit_enabled: true,
            });
        let route = ResolvedRouteV2 {
            adjacency: AdjacencyIdV2::new(1).unwrap(),
            route_label: RouteLabelV2::new(7).unwrap(),
            route_epoch: 9,
            maximum_datagram_size: 1_382,
        };
        let mut events = state.subscribe_trace_events();
        state.register_trace_train(
            route,
            11,
            TraceProbeTag {
                request_id: 17,
                target: "21.0.0.9".parse().unwrap(),
            },
        );
        state.publish_ttl_expired(&crate::protocol::v2::routing::OamTtlExpiredV2 {
            snapshot_generation: 1,
            route_epoch: route.route_epoch,
            route_label: route.route_label,
            train_id: 11,
            cell_sequence: 0,
            ingress_hop_limit: 1,
            traversed_hops: 1,
            incoming: AdjacencyIdV2::new(1).unwrap(),
            reporter: *reporter_key.public().as_bytes(),
        });

        let event = events.recv().await.unwrap();
        assert_eq!(event.request_id, 17);
        assert_eq!(
            event.reporter_address,
            "21.0.0.7".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            event.reporter.metadata["endpoint_id"],
            reporter_key.public().to_string()
        );
        assert!(
            state.trace_trains.lock().unwrap().is_empty(),
            "completed trace correlation must not leak pending state"
        );
    }

    #[test]
    fn unspecified_product_bind_expands_to_a_dual_stack_socket_pair() {
        assert_eq!(
            endpoint_bind_addresses("[::]:4000".parse().unwrap()),
            [
                "0.0.0.0:4000".parse().unwrap(),
                "[::]:4000".parse().unwrap(),
            ]
        );
        assert_eq!(
            endpoint_bind_addresses("0.0.0.0:4001".parse().unwrap()),
            [
                "0.0.0.0:4001".parse().unwrap(),
                "[::]:4001".parse().unwrap(),
            ]
        );
        assert_eq!(
            endpoint_bind_addresses("192.0.2.7:4002".parse().unwrap()),
            ["192.0.2.7:4002".parse().unwrap()]
        );
    }

    #[test]
    fn product_translation_rejects_multiple_bind_addresses() {
        let mut config = product_config();
        config.bind_addresses = vec![
            "0.0.0.0:4000".parse().unwrap(),
            "[::]:4000".parse().unwrap(),
        ];
        let error = V2RuntimeConfig::from_product_config(&config)
            .unwrap_err()
            .to_string();
        assert!(error.contains("one dual-stack bind address"));
    }

    #[test]
    fn product_translation_accepts_invited_accept_only_peer() {
        let mut config = product_config();
        config.peers.push(crate::config::PeerConfig {
            name: "invited-peer".into(),
            endpoint_id: SecretKey::from_bytes(&[9; 32]).public(),
            direct_addresses: Vec::new(),
            derp_public_key: None,
        });
        let runtime = V2RuntimeConfig::from_product_config(&config).unwrap();
        assert_eq!(runtime.mesh_peers.len(), 1);
        assert!(!runtime.mesh_peers[0].is_dialable());
    }

    #[test]
    fn derived_addresses_are_stable_network_and_endpoint_scoped() {
        let one = SecretKey::from_bytes(&[1; 32]).public();
        let two = SecretKey::from_bytes(&[2; 32]).public();
        let first = derived_overlay_address("network-a", one);
        assert_eq!(first, derived_overlay_address("network-a", one));
        assert_ne!(first, derived_overlay_address("network-a", two));
        assert_ne!(first, derived_overlay_address("network-b", one));
        assert_eq!(first.octets()[0], 0xfd);

        let first_v4 = derived_overlay_ipv4_address("network-a", one);
        assert_eq!(first_v4, derived_overlay_ipv4_address("network-a", one));
        assert_ne!(first_v4, derived_overlay_ipv4_address("network-a", two));
        assert_ne!(first_v4, derived_overlay_ipv4_address("network-b", one));
        assert!(
            ipnet::Ipv4Net::new(Ipv4Addr::new(100, 64, 0, 0), 10)
                .unwrap()
                .contains(&first_v4)
        );
    }

    #[test]
    fn product_node_addresses_override_lab_derivation() {
        let runtime = V2RuntimeConfig::from_product_config(&product_config()).unwrap();
        let endpoint = SecretKey::from_bytes(&[3; 32]).public();
        let (ipv4, ipv6) = local_overlay_addresses(&runtime, endpoint);
        assert_eq!(ipv4, "21.0.0.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(ipv6, "21::1".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn ticket_partition_status_is_stable_and_hides_network_name() {
        let first = ticket_partition_label("private-network-name", 7, QUIC_WIRE_VERSION);
        assert_eq!(first, ticket_partition_label("private-network-name", 7, 1));
        assert_ne!(first, ticket_partition_label("other-network", 7, 1));
        assert_ne!(first, ticket_partition_label("private-network-name", 8, 1));
        assert!(!first.contains("private-network-name"));
        assert!(first.ends_with(":7:1"));
    }

    #[test]
    fn loss_ratio_is_bounded_and_handles_no_sample() {
        assert_eq!(ratio_per_million(0, 0), 0);
        assert_eq!(ratio_per_million(1, 100), 10_000);
        assert_eq!(ratio_per_million(u64::MAX, 1), 1_000_000);
        assert_eq!(ratio_per_thousand(3, 100), 30);
        assert_eq!(ratio_per_thousand(1, 0), 0);
        assert_eq!(ratio_scaled_u64(17, 4, 1_000), 4_250);
        assert_eq!(ratio_scaled_u64(1, 0, 1_000_000), 0);
        assert_eq!(ratio_scaled_u64(u64::MAX, 1, u64::MAX), u64::MAX);
        assert_eq!(rate_per_second(1_000, Duration::from_millis(500)), 2_000);
        assert_eq!(rate_per_second(1, Duration::ZERO), 0);
        assert_eq!(counter_delta(120, 100), 20);
        assert_eq!(counter_delta(7, 100), 7);
    }

    #[test]
    fn control_byte_metrics_partition_repair_without_double_counting() {
        let metrics = RuntimeMetrics::default();
        metrics.observe_control_tx(b"FRQ2-request");
        metrics.observe_control_tx(b"FRS2-response-data");
        metrics.observe_control_tx(b"PRES-presence");
        metrics.observe_control_rx(b"FRQ2-rx");
        metrics.observe_control_rx(b"FRS2-rx-data");

        assert_eq!(
            metrics.control_record_tx_bytes.load(Ordering::Relaxed),
            12 + 18 + 13
        );
        assert_eq!(metrics.repair_request_tx_bytes.load(Ordering::Relaxed), 12);
        assert_eq!(metrics.repair_response_tx_bytes.load(Ordering::Relaxed), 18);
        assert_eq!(
            metrics.control_record_rx_bytes.load(Ordering::Relaxed),
            7 + 12
        );
        assert_eq!(metrics.repair_request_rx_bytes.load(Ordering::Relaxed), 7);
        assert_eq!(metrics.repair_response_rx_bytes.load(Ordering::Relaxed), 12);
    }

    #[test]
    fn runtime_metrics_refreshes_only_v2_native_peer_telemetry() {
        let metrics = RuntimeMetrics::default();
        metrics.tun_ingress_records.store(11, Ordering::Relaxed);
        metrics.tun_ingress_bytes.store(12_000, Ordering::Relaxed);
        metrics.tun_rx_packets.store(7, Ordering::Relaxed);
        metrics.tun_rx_bytes.store(8_000, Ordering::Relaxed);
        metrics.trains_built.store(3, Ordering::Relaxed);
        metrics.cells_built.store(9, Ordering::Relaxed);
        metrics.fec_recovered_cells.store(2, Ordering::Relaxed);
        metrics
            .repair_completed_requests
            .store(1, Ordering::Relaxed);
        metrics.train_queue_bytes.store(4_096, Ordering::Relaxed);

        let mut peer = crate::status::PeerStatus::default();
        V2RuntimeState::refresh_metrics(&mut peer, &metrics);
        assert_eq!(peer.protocol_major, 0);
        assert_eq!(peer.tx_packets, 11);
        assert_eq!(peer.tx_bytes, 12_000);
        assert_eq!(peer.rx_packets, 7);
        assert_eq!(peer.rx_bytes, 8_000);
        assert_eq!(peer.trains_built, 3);
        assert_eq!(peer.cells_built, 9);
        assert_eq!(peer.fec_recovered_cells, 2);
        assert_eq!(peer.repair_completed_requests, 1);
        assert_eq!(peer.packet_train_queue_bytes, 4_096);

        let json = serde_json::to_value(peer).unwrap();
        let object = json.as_object().unwrap();
        for removed in [
            "delivery_tagged_packets",
            "tx_fragments",
            "fec_tx_recovery_shards",
            "capacity_probe_attempts",
        ] {
            assert!(!object.contains_key(removed), "stale V1 field {removed}");
        }
    }

    #[test]
    fn tx_byte_ledger_separates_protocol_layers_and_boundary_lag() {
        let bytes = TxByteSnapshotV2 {
            quic_udp_payload_bytes: 2_000,
            real_record_bytes: 700,
            data_cell_bytes: 1_000,
            data_cell_payload_bytes: 800,
            fec_bytes: 200,
            control_record_bytes: 100,
            repair_request_bytes: 30,
            repair_response_bytes: 40,
            padding_bytes: 50,
        }
        .breakdown();
        assert_eq!(bytes.real_record_bytes, 700);
        assert_eq!(bytes.packet_train_metadata_bytes, 100);
        assert_eq!(bytes.cell_envelope_bytes, 200);
        assert_eq!(bytes.other_control_record_bytes, 30);
        assert_eq!(bytes.quic_transport_residual_bytes, 650);
        assert_eq!(bytes.interval_accounting_lag_bytes, 0);

        let lagged = TxByteSnapshotV2 {
            quic_udp_payload_bytes: 1_000,
            data_cell_bytes: 900,
            fec_bytes: 100,
            control_record_bytes: 50,
            padding_bytes: 25,
            ..TxByteSnapshotV2::default()
        }
        .breakdown();
        assert_eq!(lagged.quic_transport_residual_bytes, 0);
        assert_eq!(lagged.interval_accounting_lag_bytes, 75);
    }

    #[test]
    fn sustained_datagram_errors_are_counted_but_exponentially_sampled() {
        let metrics = RuntimeMetrics::default();
        let mut reported = Vec::new();
        for _ in 0..10 {
            let (count, report) = metrics.record_protocol_datagram_error();
            if report {
                reported.push(count);
            }
        }
        assert_eq!(reported, [1, 2, 4, 8]);
        assert_eq!(metrics.protocol_datagram_errors.load(Ordering::Relaxed), 10);
    }

    #[test]
    fn tun_ingress_metrics_are_folded_once_per_admission_batch() {
        let metrics = RuntimeMetrics::default();
        let mut batch = TunIngressBatchV2::default();
        batch.observe(
            1_500,
            GsoObservationV2 {
                input_bytes: 0,
                preserved_bytes: 0,
                fallback_splits: 0,
            },
        );
        batch.observe(
            60_000,
            GsoObservationV2 {
                input_bytes: 60_000,
                preserved_bytes: 60_000,
                fallback_splits: 0,
            },
        );
        metrics.observe_tun_ingress_batch(batch);

        assert_eq!(metrics.tun_ingress_records.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.tun_ingress_bytes.load(Ordering::Relaxed), 61_500);
        assert_eq!(metrics.gso_input_bytes.load(Ordering::Relaxed), 60_000);
        assert_eq!(metrics.gso_preserved_bytes.load(Ordering::Relaxed), 60_000);
        assert_eq!(metrics.gso_fallback_splits.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn fec_feedback_is_monotonic_and_directional() {
        let metrics = RuntimeMetrics::default();
        let first = FecFeedbackV2 {
            sequence: 2,
            parity_received: 10,
            recovered_cells: 3,
            wasted_parity: 6,
            repair_requested_cells: 4,
            repair_received_cells: 3,
            repair_completed_requests: 2,
            repair_completed_requested_cells: 4,
            repair_latency_micros: 40_000,
            expired_stripes: 1,
            delivered_payload_bytes: 8_000_000,
            reorder_cells: 2,
            missing_cells: 3,
            loss_run_1: 1,
            loss_run_2: 1,
            loss_run_3_4: 0,
            loss_run_5_plus: 0,
            reassembly_expired_trains: 1,
        };
        assert!(metrics.apply_remote_feedback(first));
        assert!(!metrics.apply_remote_feedback(FecFeedbackV2 {
            sequence: 1,
            parity_received: 99,
            ..first
        }));
        assert_eq!(metrics.remote_feedback_sequence.load(Ordering::Acquire), 2);
        assert_eq!(metrics.remote_fec_parity_rx.load(Ordering::Relaxed), 10);
        assert_eq!(
            metrics.remote_fec_recovered_cells.load(Ordering::Relaxed),
            3
        );
        assert_eq!(metrics.fec_parity_rx.load(Ordering::Relaxed), 0);
        assert_eq!(
            metrics
                .remote_delivered_payload_bytes
                .load(Ordering::Relaxed),
            8_000_000
        );
        assert_eq!(metrics.remote_reorder_cells.load(Ordering::Relaxed), 2);
        assert_eq!(metrics.remote_missing_cells.load(Ordering::Relaxed), 3);
        assert_eq!(metrics.remote_loss_run_1.load(Ordering::Relaxed), 1);
        assert_eq!(
            metrics
                .remote_reassembly_expired_trains
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics
                .remote_repair_completed_requests
                .load(Ordering::Relaxed),
            2
        );
        assert_eq!(
            metrics.remote_repair_latency_micros.load(Ordering::Relaxed),
            40_000
        );
        assert_eq!(
            metrics
                .remote_repair_completed_requested_cells
                .load(Ordering::Relaxed),
            4
        );
    }

    #[test]
    fn admission_batch_preserves_records_and_obeys_both_bounds() {
        let mut pending = VecDeque::from([
            TunIngressRecordV2::priority(Bytes::from(vec![1; 100]), test_packet_info()),
            TunIngressRecordV2::priority(Bytes::from(vec![2; 100]), test_packet_info()),
            TunIngressRecordV2::priority(Bytes::from(vec![3; 100]), test_packet_info()),
        ]);
        let first = drain_tun_ingress_batch(&mut pending, 8, 210);
        assert_eq!(first.len(), 2);
        assert_eq!(
            first.iter().map(TunIngressRecordV2::len).sum::<usize>(),
            200
        );
        assert_eq!(pending.len(), 1);

        let second = drain_tun_ingress_batch(&mut pending, 1, 0);
        assert_eq!(second.len(), 1, "the head record must always make progress");
        assert!(pending.is_empty());
    }

    #[test]
    fn tun_ingress_byte_budget_is_held_until_dispatch_consumes_records() {
        let budget = Arc::new(Semaphore::new(200));
        let mut pending = VecDeque::from([
            TunIngressRecordV2::regular(
                Bytes::from(vec![1; 100]),
                test_packet_info(),
                budget.clone().try_acquire_many_owned(100).unwrap(),
            ),
            TunIngressRecordV2::regular(
                Bytes::from(vec![2; 100]),
                test_packet_info(),
                budget.clone().try_acquire_many_owned(100).unwrap(),
            ),
        ]);
        assert_eq!(budget.available_permits(), 0);
        assert!(budget.clone().try_acquire_owned().is_err());

        let first = drain_tun_ingress_batch(&mut pending, 1, 100);
        assert_eq!(first.len(), 1);
        assert_eq!(budget.available_permits(), 0);
        assert_eq!(pending.len(), 1);

        drop(first);
        assert_eq!(budget.available_permits(), 100);
        let second = drain_tun_ingress_batch(&mut pending, 1, 100);
        assert_eq!(second.len(), 1);
        assert_eq!(budget.available_permits(), 100);
        drop(second);
        assert_eq!(budget.available_permits(), 200);
    }

    #[test]
    fn regular_tun_admission_sheds_overload_without_blocking_priority_reads() {
        let budget = Arc::new(Semaphore::new(100));
        let held = budget.clone().try_acquire_many_owned(100).unwrap();
        let (sender, mut receiver) = mpsc::channel(1);
        let metrics = RuntimeMetrics::default();
        try_admit_regular_tun_record(
            &sender,
            &budget,
            Bytes::from(vec![1; 100]),
            test_packet_info(),
            &metrics,
        )
        .unwrap();
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        assert_eq!(
            metrics.tun_admission_drop_records.load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            metrics.tun_admission_drop_bytes.load(Ordering::Relaxed),
            100
        );

        drop(held);
        try_admit_regular_tun_record(
            &sender,
            &budget,
            Bytes::from(vec![2; 100]),
            test_packet_info(),
            &metrics,
        )
        .unwrap();
        let admitted = receiver.try_recv().unwrap();
        assert_eq!(budget.available_permits(), 0);
        drop(admitted);
        assert_eq!(budget.available_permits(), 100);
    }

    #[test]
    fn repair_grace_tracks_rtt_with_conservative_bounds() {
        assert_eq!(
            repair_minimum_age_for_rtt(Duration::from_millis(1)),
            Duration::from_millis(50)
        );
        assert_eq!(
            repair_minimum_age_for_rtt(Duration::from_millis(13)),
            Duration::from_millis(104)
        );
        assert_eq!(
            repair_minimum_age_for_rtt(Duration::from_secs(1)),
            Duration::from_secs(1)
        );
    }

    #[test]
    fn mixed_scheduler_depth_respects_the_shared_application_watermark() {
        use crate::protocol::v2::scheduler::{SchedulerDepth, SchedulerLimits};

        let application_headroom = SchedulerLimits::default()
            .application_bytes
            .saturating_sub(TX_APPLICATION_ADMISSION_HIGH_WATER_BYTES);
        let maximum_fec_expanded_batch = TX_ADMISSION_BATCH_BYTES
            .saturating_add(RAW_TUN_BYTES)
            .saturating_mul(3)
            / 2;
        assert!(
            application_headroom >= maximum_fec_expanded_batch.saturating_add(64 * 1024),
            "shared headroom must cover one overshooting GSO record, strongest automatic FEC, and Cell envelopes"
        );

        let mixed = SchedulerDepth {
            bulk_bytes: TX_BULK_ADMISSION_HIGH_WATER_BYTES - 64 * 1024,
            latency_bytes: 96 * 1024,
            ..SchedulerDepth::default()
        };
        assert!(
            mixed.bulk_bytes < TX_BULK_ADMISSION_HIGH_WATER_BYTES
                && mixed.latency_bytes < TX_LATENCY_ADMISSION_HIGH_WATER_BYTES
        );
        assert!(
            admission_saturated(mixed, TX_APPLICATION_ADMISSION_HIGH_WATER_BYTES),
            "the shared queue must retain room for one complete TUN admission burst"
        );

        let latency_watermark = SchedulerDepth {
            bulk_bytes: TX_APPLICATION_ADMISSION_HIGH_WATER_BYTES
                - TX_LATENCY_ADMISSION_HIGH_WATER_BYTES
                - 1,
            latency_bytes: TX_LATENCY_ADMISSION_HIGH_WATER_BYTES,
            ..SchedulerDepth::default()
        };
        assert!(admission_saturated(
            latency_watermark,
            TX_APPLICATION_ADMISSION_HIGH_WATER_BYTES
        ));

        let below_all_watermarks = SchedulerDepth {
            bulk_bytes: 256 * 1024,
            latency_bytes: 64 * 1024,
            ..SchedulerDepth::default()
        };
        assert!(!admission_saturated(
            below_all_watermarks,
            TX_APPLICATION_ADMISSION_HIGH_WATER_BYTES
        ));
        assert!(admission_saturated(below_all_watermarks, 256 * 1024));
    }

    #[test]
    fn live_media_sni_pool_selection_is_stable_symmetric_and_order_independent() {
        let one = SecretKey::from_bytes(&[1; 32]).public();
        let two = SecretKey::from_bytes(&[2; 32]).public();
        let pool = vec![
            "video-c.example".to_owned(),
            "video-a.example".to_owned(),
            "video-b.example".to_owned(),
        ];
        let selected = select_cover_sni(&pool, "network-a", one, two, 7).unwrap();
        assert!(pool.iter().any(|candidate| candidate == selected));
        assert_eq!(
            selected,
            select_cover_sni(&pool, "network-a", two, one, 7).unwrap()
        );
        let mut reversed = pool.clone();
        reversed.reverse();
        assert_eq!(
            selected,
            select_cover_sni(&reversed, "network-a", one, two, 7).unwrap()
        );
        assert!(validate_cover_sni("live-edge.example").is_ok());
        assert!(validate_cover_sni("-invalid.example").is_err());
        assert!(validate_cover_sni("invalid..example").is_err());
    }

    #[test]
    fn live_media_sni_prefers_names_matching_peer_direct_addresses() {
        let one = SecretKey::from_bytes(&[1; 32]).public();
        let two = SecretKey::from_bytes(&[2; 32]).public();
        let pool = vec![
            "video-c.example".to_owned(),
            "video-a.example".to_owned(),
            "video-b.example".to_owned(),
        ];
        let preferred =
            StdHashSet::from(["video-a.example".to_owned(), "video-b.example".to_owned()]);
        let selected =
            select_cover_sni_with_preference(&pool, &preferred, "network-a", one, two, 7).unwrap();
        assert!(preferred.contains(selected));
        assert_eq!(
            selected,
            select_cover_sni_with_preference(&pool, &preferred, "network-a", two, one, 7,).unwrap()
        );

        let unmatched = StdHashSet::from(["not-in-pool.example".to_owned()]);
        assert_eq!(
            select_cover_sni_with_preference(&pool, &unmatched, "network-a", one, two, 7,).unwrap(),
            select_cover_sni(&pool, "network-a", one, two, 7).unwrap()
        );
    }

    #[tokio::test]
    async fn live_media_sni_dns_ranking_is_bounded_and_uses_direct_ip() {
        let one = SecretKey::from_bytes(&[1; 32]).public();
        let two = SecretKey::from_bytes(&[2; 32]).public();
        let selected = select_cover_sni_for_peer(
            &["not-a-real-name.invalid".to_owned(), "localhost".to_owned()],
            "network-a",
            one,
            two,
            7,
            &[SocketAddr::from(([127, 0, 0, 1], 443))],
        )
        .await
        .unwrap();
        assert_eq!(selected, "localhost");
    }

    #[test]
    fn path_mtu_constraints_only_reduce_the_matching_compiled_route() {
        let constraints = RoutePmtuConstraintsV2::default();
        let route = ResolvedRouteV2 {
            adjacency: AdjacencyIdV2::new(1).unwrap(),
            route_label: RouteLabelV2::new(7).unwrap(),
            route_epoch: 9,
            maximum_datagram_size: 1_382,
        };
        constraints.constrain(9, route.route_label, 1_200);
        constraints.constrain(9, route.route_label, 1_300);
        assert_eq!(constraints.apply(route).maximum_datagram_size, 1_200);

        let mut next_epoch = route;
        next_epoch.route_epoch = 10;
        assert_eq!(constraints.apply(next_epoch).maximum_datagram_size, 1_382);
    }

    #[test]
    fn derp_and_iroh_relay_paths_are_reliable_for_fec_tuning() {
        let derp = TransportAddr::Custom(
            DerpAddr {
                region_id: crate::derp::RegionId(7),
                public_key: DerpPublicKey::from_bytes([9; 32]),
            }
            .to_custom(),
        );
        assert_eq!(
            path_reliability(false, &derp),
            PathReliability::ReliableRelay
        );
        assert_eq!(
            path_reliability(false, &TransportAddr::Ip("192.0.2.1:443".parse().unwrap())),
            PathReliability::Datagram
        );
        assert_eq!(
            path_reliability(true, &TransportAddr::Ip("192.0.2.1:443".parse().unwrap())),
            PathReliability::ReliableRelay
        );
        assert_eq!(
            path_endpoint_identity(&TransportAddr::Ip("192.0.2.1:443".parse().unwrap())),
            path_endpoint_identity(&TransportAddr::Ip("192.0.2.1:5443".parse().unwrap()))
        );
        assert_ne!(
            path_endpoint_identity(&TransportAddr::Ip("192.0.2.1:443".parse().unwrap())),
            path_endpoint_identity(&derp)
        );
    }

    #[test]
    fn scheduler_observability_histogram_and_fairness_are_bounded() {
        assert_eq!(latency_sojourn_bucket(0), 0);
        assert_eq!(latency_sojourn_bucket(51), 1);
        assert_eq!(
            latency_sojourn_bucket(u64::MAX),
            LATENCY_SOJOURN_BUCKETS - 1
        );

        let mut histogram = [0_u64; LATENCY_SOJOURN_BUCKETS];
        histogram[0] = 50;
        histogram[5] = 45;
        histogram[LATENCY_SOJOURN_BUCKETS - 1] = 5;
        assert_eq!(histogram_percentile_micros(&histogram, 50), 50);
        assert_eq!(histogram_percentile_micros(&histogram, 95), 2_500);
        assert_eq!(histogram_percentile_micros(&histogram, 99), 1_000_001);

        let mut service = [0_u64; BULK_FAIRNESS_BUCKETS];
        service[0] = 100;
        service[1] = 50;
        assert_eq!(jain_fairness_ppm(&service), 900_000);
        service[1] = 100;
        assert_eq!(jain_fairness_ppm(&service), 1_000_000);
    }

    #[tokio::test]
    async fn path_oam_uses_the_compiled_reverse_label_action() {
        let incoming = AdjacencyIdV2::new(1).unwrap();
        let outgoing = AdjacencyIdV2::new(2).unwrap();
        let route_label = RouteLabelV2::new(7).unwrap();
        let snapshot = DataplaneSnapshotV2::compile(
            1,
            [3; 32],
            Vec::new(),
            vec![LabelRouteV2 {
                route_label,
                route_epoch: 9,
                action: LabelActionV2::Forward {
                    expected_ingress: incoming,
                    next_hop: outgoing,
                },
            }],
            Vec::new(),
            false,
        )
        .unwrap();
        let snapshots = DataplaneSnapshotStoreV2::new(snapshot);
        let (sender, mut receiver) = mpsc::channel(1);
        let commands = HashMap::from_iter([(incoming, sender)]);
        let encoded = Bytes::from_static(b"oam");
        assert!(
            relay_oam_reverse(
                9,
                route_label,
                encoded.clone(),
                outgoing,
                &snapshots,
                &commands,
            )
            .await
            .unwrap()
        );
        let MeshTxCommandV2::Control(TxControl::Send(delivered)) = receiver.recv().await.unwrap()
        else {
            panic!("expected reverse OAM control record");
        };
        assert_eq!(delivered, encoded);
    }

    #[test]
    fn cpu_stat_parser_is_available_on_linux() {
        assert!(process_cpu_ticks().is_some());
    }

    #[test]
    fn missing_optional_firewall_tools_mean_no_owned_nat_state() {
        let missing = "ironet-v2-test-firewall-command-that-does-not-exist";
        assert!(!firewall_command_available(missing).unwrap());
        assert!(!v2_nat_family_has_owned_state(missing).unwrap());
        cleanup_v2_nat_family(missing).unwrap();
    }
}

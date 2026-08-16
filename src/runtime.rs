use std::{
    borrow::Cow,
    collections::{HashMap, HashSet, VecDeque},
    future::{Future, pending},
    net::IpAddr,
    sync::{
        Arc, Mutex as StdMutex, RwLock as StdRwLock,
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
use arc_swap::ArcSwapOption;
use bytes::Bytes;
use futures_util::StreamExt;
use ipnet::IpNet;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMode, RelayUrl, SecretKey, TransportAddr,
    address_lookup::AddrFilter,
    endpoint::{
        Connection, IncomingAddr, LocalTransportAddr, QuicTransportConfig, SendDatagramError, Side,
        presets,
    },
};
use n0_watcher::Watcher as _;
use noq_proto::congestion::CubicConfig;
use rustc_hash::FxHashMap;
use rustls::{CipherSuite, crypto::CryptoProvider};
use tokio::{
    sync::{Mutex, Notify, RwLock, Semaphore, mpsc, oneshot},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};
use tun_rs::AsyncDevice;

use crate::{
    address::{
        Nat64Prefix, discover_nat64_prefix, network_alpn, network_discovery_status,
        network_probe_alpn,
    },
    buffer::{
        BufferBudget, DEFAULT_FEC_DECODE_BYTES, DEFAULT_QUEUE_BYTES, DEFAULT_REASSEMBLY_BYTES,
        DEFAULT_REPAIR_BYTES, DataplaneBuf, PROCESS_PAYLOAD_BUDGET_BYTES,
    },
    capacity::{CapacitySnapshot, RouteEstimateTable, RouteKey},
    capacity_probe::{
        ActiveProbeScheduler, CapacityProbeMessage, CapacityProbePacket, CapacityProbeReady,
        CapacityProbeStart, ProbeReceiver, ProbeRequest, ProbeStatusSnapshot, append_probe_hop,
        encode_probe, forward_next_hop, reverse_next_hop,
    },
    config::{AttachmentMode, Config, DialRole, PeerConfig, RelayConfig},
    delivery::{
        DELIVERY_ROUTE_TEMPLATE_TTL, DELIVERY_SESSION_TTL, DELIVERY_TAG_WIRE_BYTES,
        DeliveryMessage, DeliveryReceiver, DeliveryReport, DeliverySessionRegister, DeliverySource,
        DeliveryTag, MAX_DELIVERY_SESSIONS, encode_delivery,
    },
    derp::{DerpAddr, DerpTransport, identity::load_or_create, tls_config},
    fec::{EncodedDatagram, FecDecoder, FecEncoder},
    flow_router::{FlowRouter, FlowRouterConfig, RouteCandidate, RouteId},
    link_metrics::{LinkEstimator, LinkMetrics},
    mesh::{
        EVALUATION_INTERVAL, MeshPlanner, MeshRuntime, PathKind, ProbeObservation, SignedPresence,
    },
    observability::{
        CapacityObservability, FlowRouterCounters, PeerCounters, RuntimeState, log_runtime_started,
        publish_status, run_reporter, should_log,
    },
    packet::{FlowKey, PacketInfo, decrement_hop_limit_validated, inspect_ip_packet},
    path_selection::WanPathSelector,
    protocol::{
        feature,
        session::{LinkAuthentication, NegotiatedSession, SessionPolicy, negotiate_connection},
    },
    system::{
        cleanup_node_interface, cleanup_routing, prepare_node_interface, prepare_routing,
        routing_table, sync_overlay_routes,
    },
    trace::TraceResponder,
    transport::{
        AdaptiveFrameSizer, OUTBOUND_QUEUE_BYTES, OutboundConsumer, OutboundItem, OutboundPacket,
        OutboundQueue, RepairCache, adaptive_queue_max_age, store_duration_micros,
    },
    tunnel::{
        OverlayTunnel, OverlayTunnelQueueWriter, attach_virtio, data_plane_parallelism,
        tun_read_pool,
    },
    wire::{
        MAX_PACKET_FRAME_HEADER_LEN, Reassembler, WireDatagram, decode_datagram,
        encode_address_candidates, encode_batch, encode_heartbeat, encode_packet_from_buf,
        encode_repair_request,
    },
};

mod dispatch;
mod prefix;
#[cfg(test)]
use dispatch::flow_shard;
use dispatch::{InboundDispatcher, RouteDispatcher};
use prefix::{IpPrefixSet, PrefixOwnerTable};

// Keep noq's non-preemptible FIFO smaller than a short interactive burst.
// Large TUN super-packets remain in the application scheduler between wire
// datagrams, where control/latency work can preempt them, instead of hiding a
// whole 64 KiB packet behind bulk traffic inside QUIC.
const QUIC_SEND_BUFFER_BYTES: usize = 8 * 1024;
// Keep 8 MiB receive so FEC/repair can absorb a BDP of loss. Shrinking it
// without a measured loss/FEC regression would trade recoverability for RSS.
const QUIC_RECEIVE_BUFFER_BYTES: usize = 8 * 1024 * 1024;
const SMALL_PACKET_LIMIT: usize = 512;
const OVERLAY_HEARTBEAT_INTERVAL: Duration = Duration::from_millis(500);
// Retire a silent direct path quickly enough to use an already-open relay
// backup, but leave enough startup time for discovery to establish that
// backup before the first idle decision.
const QUIC_PATH_IDLE_TIMEOUT: Duration = Duration::from_secs(5);
// A DERP custom path is a reliable stream-backed transport, not a raw UDP
// path. noq's five-second path-idle retirement can race its keepalive/ACK
// bookkeeping and intermittently retire the only custom path even while
// overlay traffic is flowing. Overlay liveness below still replaces a dead
// connection after seven seconds, so a longer transport-level guard does not
// slow failure recovery.
const DERP_PATH_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
// QUIC gets the first chance to migrate paths without replacing the
// connection. This guard repairs the connection if no usable backup exists.
const OVERLAY_LIVENESS_TIMEOUT: Duration = Duration::from_secs(7);
const INITIAL_OVERLAY_LIVENESS_TIMEOUT: Duration = Duration::from_secs(15);
const BOOTSTRAP_FALLBACK_DELAY: Duration = Duration::from_secs(5);
const NAT64_REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);
const UNKNOWN_ADMISSION_CONCURRENCY: usize = 16;
// This queue sits before FlowRouter classifies packets.  Keep it shallow so a
// burst of jumbo TUN packets cannot hide hundreds of milliseconds of work in
// a classless FIFO. Backpressure is preferable to moving that backlog out of
// sight of the class-aware outbound queues.
const FLOW_DISPATCH_QUEUE: usize = 64;
const CAPACITY_EVENT_QUEUE: usize = 4_096;
const ROUTE_SNAPSHOT_REFRESH: Duration = Duration::from_millis(100);
const INBOUND_ROUTER_BATCH: usize = 128;
const LATENCY_PRESSURE_LIMIT: u64 = 64 * 1024;
// A merely connected owner must not suppress every transit path. Above these
// thresholds the direct adjacency remains a candidate, but FlowRouter is also
// given healthy transit alternatives so loss or queue collapse can move work.
const DIRECT_OWNER_MAX_LOSS_PPM: u32 = 50_000;
const DIRECT_OWNER_MIN_HEALTH_PER_MILLE: u16 = 700;
// A low-pressure flow normally receives latency service, but one large TUN
// super-packet must never monopolize that class while it is fragmented into
// dozens of wire datagrams. Flow demand still controls route selection; this
// limit only controls the local per-peer scheduler.
const PRIORITY_PACKET_LIMIT: usize = 4 * 1024;
const CAPACITY_PROBE_TICK: Duration = Duration::from_millis(50);
const PROBE_STATUS_REFRESH: Duration = Duration::from_secs(1);
const CAPACITY_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const CAPACITY_PROBE_RECEIVER_TIMEOUT: Duration = Duration::from_millis(300);
const CAPACITY_PROBE_PACKET_COUNT: u16 = 64;
const CAPACITY_PROBE_PAYLOAD_SIZE: u16 = 1_000;

fn latency_service(demand_bytes: u64, packet_len: usize) -> bool {
    demand_bytes < LATENCY_PRESSURE_LIMIT && packet_len <= PRIORITY_PACKET_LIMIT
}

fn delivery_tracking_required(
    destination_owner: EndpointId,
    selected_endpoint: EndpointId,
    candidate_count: usize,
    selected_path_transport: u64,
) -> bool {
    candidate_count > 1 || selected_endpoint != destination_owner || selected_path_transport != 1
}

struct InboundPacket {
    peer_id: EndpointId,
    packet: DataplaneBuf,
    packet_info: PacketInfo,
    delivery_tag: Option<DeliveryTag>,
}

struct RouteRequest {
    packet: DataplaneBuf,
    packet_info: PacketInfo,
    previous_peer: Option<EndpointId>,
    delivery_tag: Option<DeliveryTag>,
}

/// One encoded application transmission that may be suspended between wire
/// datagrams while urgent traffic runs.  This is deliberately sender-local:
/// FlowRouter keeps no persistent Bulk/Interactive mode, and a suspended bulk
/// packet is the only additional scheduling state.
struct TransmissionJob {
    packets: Vec<OutboundPacket>,
    datagrams: VecDeque<EncodedDatagram>,
    packet_count: u64,
    packet_bytes: u64,
    fragment_count: u64,
    latency_sensitive: bool,
}

enum TransmissionWork {
    Item(OutboundItem),
    Job(TransmissionJob),
}

enum TransmissionOutcome {
    Complete,
    Preempted(OutboundItem),
    Reframe,
    Failed,
}

fn data_committed_before_recovery_failure(
    failed_recovery: bool,
    queued: &VecDeque<EncodedDatagram>,
) -> bool {
    failed_recovery && queued.iter().all(|datagram| datagram.recovery)
}

#[derive(Debug)]
enum CapacityEvent {
    Message {
        from: EndpointId,
        message: CapacityProbeMessage,
    },
    DeliveryMessage {
        from: EndpointId,
        message: DeliveryMessage,
    },
    Delivered {
        report: DeliveryReport,
    },
}

#[derive(Debug, Clone, Copy)]
struct PendingOriginProbe {
    request: ProbeRequest,
    started_at: Instant,
    path_epoch: u64,
    route_rtt: Option<Duration>,
}

#[derive(Debug)]
struct ReceivingProbe {
    receiver: ProbeReceiver,
    origin: EndpointId,
    destination: EndpointId,
    traversed_hops: Vec<EndpointId>,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
struct DeliveryBinding {
    registration: crate::delivery::DeliverySessionRegister,
    last_used: Instant,
}

#[derive(Debug, Default)]
struct DeliveryTagState {
    tag: Option<DeliveryTag>,
    registration: Option<DeliverySessionRegister>,
}

#[derive(Debug, Default)]
struct DeliveryCoordinator {
    source: DeliverySource,
    receiver: DeliveryReceiver,
    source_routes: HashMap<RouteKey, DeliveryBinding>,
    forwarding: HashMap<u64, DeliveryBinding>,
}

#[derive(Debug)]
struct FastDeliveryBinding {
    registration: DeliverySessionRegister,
    next_sequence: AtomicU32,
    last_used_micros: AtomicU64,
    queue_nonempty_since_micros: AtomicU64,
}

#[derive(Debug, Clone, Copy)]
struct FastSourceLiveness {
    route: RouteKey,
    session_id: u64,
    queue_nonempty_since: Option<Instant>,
}

/// Read-mostly delivery-session index. Control-plane registration and report
/// application remain serialized, while tagged data packets only perform an
/// ArcSwap lookup plus relaxed atomics. This removes DeliveryCoordinator from
/// the per-packet transit/multipath hot path.
#[derive(Debug)]
struct DeliveryFastPath {
    started: Instant,
    source_routes: arc_swap::ArcSwap<HashMap<RouteKey, Arc<FastDeliveryBinding>>>,
    forwarding: arc_swap::ArcSwap<HashMap<u64, Arc<FastDeliveryBinding>>>,
}

impl Default for DeliveryFastPath {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            source_routes: arc_swap::ArcSwap::from_pointee(HashMap::new()),
            forwarding: arc_swap::ArcSwap::from_pointee(HashMap::new()),
        }
    }
}

impl DeliveryFastPath {
    fn duration_micros(duration: Duration) -> u64 {
        duration.as_micros().min(u128::from(u64::MAX)) as u64
    }

    fn now_micros(&self) -> u64 {
        Self::duration_micros(self.started.elapsed()).max(1)
    }

    fn install_source(&self, registration: DeliverySessionRegister, next_sequence: u32) {
        let route = RouteKey {
            destination: registration.destination,
            first_hop: registration.first_hop,
        };
        let binding = Arc::new(FastDeliveryBinding {
            registration,
            next_sequence: AtomicU32::new(next_sequence),
            last_used_micros: AtomicU64::new(self.now_micros()),
            queue_nonempty_since_micros: AtomicU64::new(0),
        });
        self.source_routes.rcu(|current| {
            let mut updated = (**current).clone();
            updated.insert(route, binding.clone());
            Arc::new(updated)
        });
    }

    fn install_forwarding(&self, registration: DeliverySessionRegister) {
        let session_id = registration.session_id;
        let binding = Arc::new(FastDeliveryBinding {
            registration,
            next_sequence: AtomicU32::new(0),
            last_used_micros: AtomicU64::new(self.now_micros()),
            queue_nonempty_since_micros: AtomicU64::new(0),
        });
        self.forwarding.rcu(|current| {
            let mut updated = (**current).clone();
            updated.insert(session_id, binding.clone());
            Arc::new(updated)
        });
    }

    fn next_source_tag(
        &self,
        route: RouteKey,
        path_epoch: u64,
        queue_nonempty: bool,
    ) -> Option<DeliveryTag> {
        let now = self.now_micros();
        let routes = self.source_routes.load();
        let binding = routes.get(&route)?;
        if binding.registration.path_epoch != path_epoch
            || now.saturating_sub(binding.last_used_micros.load(Ordering::Relaxed))
                > Self::duration_micros(DELIVERY_SESSION_TTL)
        {
            return None;
        }
        binding.last_used_micros.store(now, Ordering::Relaxed);
        if queue_nonempty {
            let _ = binding.queue_nonempty_since_micros.compare_exchange(
                0,
                now,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        } else {
            binding
                .queue_nonempty_since_micros
                .store(0, Ordering::Relaxed);
        }
        Some(DeliveryTag {
            session_id: binding.registration.session_id,
            sequence: binding.next_sequence.fetch_add(1, Ordering::Relaxed),
        })
    }

    fn remove_source_session(&self, session_id: u64) {
        self.source_routes.rcu(|current| {
            let mut updated = (**current).clone();
            updated.retain(|_, binding| binding.registration.session_id != session_id);
            Arc::new(updated)
        });
    }

    fn source_queue_nonempty_since(&self, session_id: u64) -> Option<Instant> {
        let routes = self.source_routes.load();
        let binding = routes
            .values()
            .find(|binding| binding.registration.session_id == session_id)?;
        let micros = binding.queue_nonempty_since_micros.load(Ordering::Relaxed);
        (micros != 0).then(|| self.started + Duration::from_micros(micros))
    }

    fn source_liveness(&self) -> Vec<FastSourceLiveness> {
        let now = self.now_micros();
        let ttl = Self::duration_micros(DELIVERY_SESSION_TTL);
        self.source_routes
            .load()
            .iter()
            .filter(|(_, binding)| {
                now.saturating_sub(binding.last_used_micros.load(Ordering::Relaxed)) <= ttl
            })
            .map(|(route, binding)| {
                let queue_micros = binding.queue_nonempty_since_micros.load(Ordering::Relaxed);
                FastSourceLiveness {
                    route: *route,
                    session_id: binding.registration.session_id,
                    queue_nonempty_since: (queue_micros != 0)
                        .then(|| self.started + Duration::from_micros(queue_micros)),
                }
            })
            .collect()
    }

    fn touch_forwarding(&self, session_id: u64) -> bool {
        let forwarding = self.forwarding.load();
        let Some(binding) = forwarding.get(&session_id) else {
            return false;
        };
        binding
            .last_used_micros
            .store(self.now_micros(), Ordering::Relaxed);
        true
    }

    fn forwarding_registration(&self, session_id: u64) -> Option<DeliverySessionRegister> {
        self.forwarding
            .load()
            .get(&session_id)
            .map(|binding| binding.registration.clone())
    }

    /// Resolve report routing from the lock-free session generation. Sources
    /// live in `source_routes`; transit and destination nodes live in
    /// `forwarding`. Reports are cold, so the bounded source scan is preferable
    /// to putting another shared mutable index on every tagged data packet.
    fn session_registration(&self, session_id: u64) -> Option<DeliverySessionRegister> {
        if let Some(binding) = self.forwarding.load().get(&session_id) {
            binding
                .last_used_micros
                .store(self.now_micros(), Ordering::Relaxed);
            return Some(binding.registration.clone());
        }
        let routes = self.source_routes.load();
        let binding = routes
            .values()
            .find(|binding| binding.registration.session_id == session_id)?;
        binding
            .last_used_micros
            .store(self.now_micros(), Ordering::Relaxed);
        Some(binding.registration.clone())
    }

    fn prune(&self) {
        let now = self.now_micros();
        let ttl = Self::duration_micros(DELIVERY_SESSION_TTL);
        self.source_routes.rcu(|current| {
            let mut updated = (**current).clone();
            updated.retain(|_, binding| {
                now.saturating_sub(binding.last_used_micros.load(Ordering::Relaxed)) <= ttl
            });
            Arc::new(updated)
        });
        self.forwarding.rcu(|current| {
            let mut updated = (**current).clone();
            updated.retain(|_, binding| {
                now.saturating_sub(binding.last_used_micros.load(Ordering::Relaxed)) <= ttl
            });
            Arc::new(updated)
        });
    }
}

#[derive(Clone)]
struct CapacityManagerState {
    estimates: Arc<StdRwLock<RouteEstimateTable>>,
    probe_status: Arc<StdRwLock<ProbeStatusSnapshot>>,
    delivery: Arc<StdMutex<DeliveryCoordinator>>,
    delivery_fast: Arc<DeliveryFastPath>,
}

impl DeliveryCoordinator {
    fn install_source_route(
        &mut self,
        origin: EndpointId,
        route: RouteKey,
        path_epoch: u64,
        forward_hops: Vec<EndpointId>,
        now: Instant,
    ) -> Result<crate::delivery::DeliverySessionRegister> {
        self.source.invalidate_route(route);
        let registration = self
            .source
            .register(origin, route, path_epoch, forward_hops, now)?;
        self.source_routes.insert(
            route,
            DeliveryBinding {
                registration: registration.clone(),
                last_used: now,
            },
        );
        self.forwarding.insert(
            registration.session_id,
            DeliveryBinding {
                registration: registration.clone(),
                last_used: now,
            },
        );
        self.make_room(now);
        Ok(registration)
    }

    fn next_tag(
        &mut self,
        route: RouteKey,
        path_epoch: u64,
        queue_nonempty: bool,
        now: Instant,
    ) -> DeliveryTagState {
        let Some(template) = self.source_routes.get(&route) else {
            return DeliveryTagState::default();
        };
        if template.registration.path_epoch != path_epoch {
            return DeliveryTagState::default();
        }
        let mut registration = None;
        if now.saturating_duration_since(template.last_used) > DELIVERY_SESSION_TTL {
            let template = template.registration.clone();
            let Ok(renewed) = self.install_source_route(
                template.origin,
                route,
                path_epoch,
                template.forward_hops,
                now,
            ) else {
                return DeliveryTagState::default();
            };
            registration = Some(renewed);
        }
        let Some(binding) = self.source_routes.get_mut(&route) else {
            return DeliveryTagState::default();
        };
        binding.last_used = now;
        let session_id = binding.registration.session_id;
        if let Some(forwarding) = self.forwarding.get_mut(&session_id) {
            forwarding.last_used = now;
        }
        self.source.observe_queue(session_id, queue_nonempty, now);
        DeliveryTagState {
            tag: self.source.next_tag(session_id, route, path_epoch, now),
            registration,
        }
    }

    fn source_registration(&self, route: RouteKey) -> Option<DeliverySessionRegister> {
        self.source_routes
            .get(&route)
            .map(|binding| binding.registration.clone())
    }

    fn install_forwarding(
        &mut self,
        registration: crate::delivery::DeliverySessionRegister,
        local_id: EndpointId,
        now: Instant,
    ) -> Result<()> {
        if registration.destination == local_id {
            self.receiver.register(registration.clone(), now)?;
        }
        self.forwarding.insert(
            registration.session_id,
            DeliveryBinding {
                registration,
                last_used: now,
            },
        );
        self.make_room(now);
        Ok(())
    }

    fn registration_failed(&mut self, session_id: u64, now: Instant) {
        let Some(forwarding) = self.forwarding.get(&session_id) else {
            return;
        };
        let route = RouteKey {
            destination: forwarding.registration.destination,
            first_hop: forwarding.registration.first_hop,
        };
        let Some(binding) = self.source_routes.get_mut(&route) else {
            return;
        };
        if binding.registration.session_id != session_id {
            return;
        }
        binding.last_used = now
            .checked_sub(DELIVERY_SESSION_TTL + Duration::from_nanos(1))
            .unwrap_or(now);
        self.source.invalidate_route(route);
    }

    fn synchronize_source_liveness(&mut self, liveness: FastSourceLiveness, now: Instant) {
        let Some(binding) = self.source_routes.get_mut(&liveness.route) else {
            return;
        };
        if binding.registration.session_id != liveness.session_id {
            return;
        }
        binding.last_used = now;
        if let Some(forwarding) = self.forwarding.get_mut(&liveness.session_id) {
            forwarding.last_used = now;
        }
        self.source
            .observe_queue_since(liveness.session_id, liveness.queue_nonempty_since, now);
    }

    #[cfg(test)]
    fn observe_delivery(
        &mut self,
        tag: DeliveryTag,
        bytes: usize,
        now: Instant,
    ) -> Option<DeliveryReport> {
        if let Some(binding) = self.forwarding.get_mut(&tag.session_id) {
            binding.last_used = now;
        }
        self.receiver.observe(tag, bytes, now)
    }

    #[cfg(test)]
    fn touch_forwarding(&mut self, session_id: u64, now: Instant) {
        if let Some(binding) = self.forwarding.get_mut(&session_id) {
            binding.last_used = now;
        }
    }

    #[cfg(test)]
    fn forwarding_hops(
        &mut self,
        origin: EndpointId,
        session_id: u64,
        now: Instant,
    ) -> Option<Vec<EndpointId>> {
        let binding = self.forwarding.get_mut(&session_id)?;
        if binding.registration.origin != origin {
            return None;
        }
        binding.last_used = now;
        Some(binding.registration.forward_hops.clone())
    }

    fn apply_report(
        &mut self,
        report: &DeliveryReport,
        now: Instant,
    ) -> Option<crate::delivery::PassiveObservation> {
        let Some(forwarding) = self.forwarding.get(&report.session_id) else {
            debug!(
                session_id = report.session_id,
                "delivery report source session has no mutable forwarding binding"
            );
            return None;
        };
        let route = RouteKey {
            destination: forwarding.registration.destination,
            first_hop: forwarding.registration.first_hop,
        };
        let Some(binding) = self.source_routes.get_mut(&route) else {
            debug!(
                session_id = report.session_id,
                destination = %route.destination,
                first_hop = %route.first_hop,
                "delivery report source session has no route template"
            );
            return None;
        };
        if binding.registration.session_id != report.session_id {
            debug!(
                report_session_id = report.session_id,
                active_session_id = binding.registration.session_id,
                destination = %route.destination,
                first_hop = %route.first_hop,
                "delivery report belongs to a superseded source session"
            );
            return None;
        }
        binding.last_used = now;
        let epoch = binding.registration.path_epoch;
        let observation = self.source.apply_report(report, route, epoch, now);
        if observation.is_none() {
            debug!(
                session_id = report.session_id,
                path_epoch = report.path_epoch,
                destination = %route.destination,
                first_hop = %route.first_hop,
                "delivery source rejected cumulative report state"
            );
        }
        observation
    }

    fn prune(&mut self, now: Instant) {
        self.source.prune(now);
        self.receiver.prune(now);
        self.source_routes.retain(|_, binding| {
            now.saturating_duration_since(binding.last_used) <= DELIVERY_ROUTE_TEMPLATE_TTL
        });
        self.forwarding.retain(|_, binding| {
            now.saturating_duration_since(binding.last_used) <= DELIVERY_SESSION_TTL
        });
    }

    fn make_room(&mut self, now: Instant) {
        self.prune(now);
        while self.forwarding.len() > MAX_DELIVERY_SESSIONS {
            let Some(oldest) = self
                .forwarding
                .iter()
                .min_by_key(|(_, binding)| binding.last_used)
                .map(|(key, _)| *key)
            else {
                break;
            };
            self.forwarding.remove(&oldest);
        }
        while self.source_routes.len() > MAX_DELIVERY_SESSIONS {
            let Some(oldest) = self
                .source_routes
                .iter()
                .min_by_key(|(_, binding)| binding.last_used)
                .map(|(key, _)| *key)
            else {
                break;
            };
            self.source_routes.remove(&oldest);
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct AdjacencyRouteInput {
    endpoint_id: EndpointId,
    route_id: RouteId,
    connected: bool,
    transit_enabled: bool,
    metrics: LinkMetrics,
    queued_bytes: u64,
}

#[derive(Debug)]
struct RouteChoice {
    endpoint_id: EndpointId,
    adjacency_index: usize,
    candidate: RouteCandidate,
    capacity: CapacitySnapshot,
}

struct RouteAdjacencySnapshot {
    input: AdjacencyRouteInput,
    direct_capacity: CapacitySnapshot,
    peer: Arc<Peer>,
}

struct DataPlaneRouteSnapshot {
    owners: PrefixOwnerTable,
    mesh_owners: PrefixOwnerTable,
    overlay_prefixes: IpPrefixSet,
    local_prefixes: IpPrefixSet,
    remote_prefixes: IpPrefixSet,
    adjacencies: Vec<RouteAdjacencySnapshot>,
    adjacency_by_owner: FxHashMap<EndpointId, usize>,
    capacities: FxHashMap<RouteKey, CapacitySnapshot>,
    max_egress_bps: Option<u64>,
}

pub async fn run(config: Config, secret_key: SecretKey) -> Result<()> {
    run_with_shutdown(config, secret_key, shutdown_signal()).await
}

/// Run the data plane until the supplied shutdown future resolves.
///
/// The standalone daemon uses this entry point so it can perform a graceful
/// cleanup before reloading configuration while the compatibility runner uses
/// the process signal wrapper above.
pub async fn run_with_shutdown<F>(config: Config, secret_key: SecretKey, shutdown: F) -> Result<()>
where
    F: Future<Output = Result<()>>,
{
    run_with_shutdown_and_ready(config, secret_key, shutdown, None).await
}

/// Run the data plane and notify a supervisor after all startup resources and
/// long-running tasks have been created successfully.
pub async fn run_with_shutdown_and_ready<F>(
    config: Config,
    secret_key: SecretKey,
    shutdown: F,
    ready: Option<oneshot::Sender<()>>,
) -> Result<()>
where
    F: Future<Output = Result<()>>,
{
    run_with_shutdown_ready_and_state(config, secret_key, shutdown, ready, None).await
}

/// Daemon entry point that also publishes the active in-memory observability
/// state to the local control server. The watch channel is generation-aware:
/// reload replaces the state and shutdown clears it.
pub async fn run_with_shutdown_ready_and_state<F>(
    config: Config,
    secret_key: SecretKey,
    shutdown: F,
    ready: Option<oneshot::Sender<()>>,
    runtime_state: Option<tokio::sync::watch::Sender<Option<Arc<RuntimeState>>>>,
) -> Result<()>
where
    F: Future<Output = Result<()>>,
{
    if !cfg!(target_os = "linux") {
        bail!("ironet runtime is supported only on Linux");
    }

    let local_id = secret_key.public();
    config.validate_local_id(local_id)?;
    let tunnel = if config.attachment == AttachmentMode::Tun {
        let tunnel = Arc::new(OverlayTunnel::create(
            config.node_interface.clone(),
            config.tun_mtu,
        )?);
        prepare_node_interface(&config).await?;
        if let Err(error) = prepare_routing(&config).await {
            let _ = cleanup_routing(&config).await;
            let _ = cleanup_node_interface(&config).await;
            return Err(error);
        }
        Some(tunnel)
    } else {
        info!("starting userspace-only transit node without a TUN attachment");
        None
    };
    let result = run_data_plane(
        &config,
        secret_key,
        local_id,
        tunnel,
        shutdown,
        ready,
        runtime_state.clone(),
    )
    .await;
    if let Some(runtime_state) = runtime_state {
        runtime_state.send_replace(None);
    }
    let (routing_cleanup, interface_cleanup) = if config.attachment == AttachmentMode::Tun {
        (
            cleanup_routing(&config).await,
            cleanup_node_interface(&config).await,
        )
    } else {
        (Ok(()), Ok(()))
    };
    match (result, routing_cleanup, interface_cleanup) {
        (Err(error), _, _) => Err(error),
        (Ok(()), Err(error), _) => Err(error.context("failed cleaning overlay routing state")),
        (Ok(()), Ok(()), Err(error)) => Err(error.context("failed cleaning node interface")),
        (Ok(()), Ok(()), Ok(())) => Ok(()),
    }
}

async fn run_data_plane(
    config: &Config,
    secret_key: SecretKey,
    local_id: EndpointId,
    tunnel: Option<Arc<OverlayTunnel>>,
    shutdown: impl Future<Output = Result<()>>,
    ready: Option<oneshot::Sender<()>>,
    runtime_state_tx: Option<tokio::sync::watch::Sender<Option<Arc<RuntimeState>>>>,
) -> Result<()> {
    let trace_responder = TraceResponder::bind(config).await?;

    let alpn = Arc::new(network_alpn(&config.network_id));
    let probe_alpn = Arc::new(network_probe_alpn(&config.network_id));
    let derp_transport = build_derp_transport(config)?;
    let endpoint = build_endpoint(
        config,
        secret_key.clone(),
        &alpn,
        &probe_alpn,
        derp_transport.clone(),
    )
    .await?;
    info!(endpoint_id = %local_id, alpn = %String::from_utf8_lossy(&alpn), "iroh endpoint ready");

    let mesh_runtime = config
        .mesh
        .enabled
        .then(|| {
            MeshRuntime::new(
                config,
                secret_key,
                endpoint.clone(),
                derp_transport
                    .as_ref()
                    .map(|transport| transport.local_public_key()),
            )
        })
        .transpose()?;

    let inherited_relays = config.inherited_peer_relays()?;
    let nat64_prefix = Arc::new(StdRwLock::new(None::<Nat64Prefix>));
    let router_shards = tunnel
        .as_ref()
        .map_or_else(data_plane_parallelism, |tunnel| tunnel.queue_count());
    let mut inbound_senders = Vec::with_capacity(router_shards);
    let mut inbound_receivers = Vec::with_capacity(router_shards);
    for _ in 0..router_shards {
        let (sender, receiver) = mpsc::channel(FLOW_DISPATCH_QUEUE);
        inbound_senders.push(sender);
        inbound_receivers.push(receiver);
    }
    let inbound_dispatcher = InboundDispatcher::new(inbound_senders);
    let mut route_senders = Vec::with_capacity(router_shards);
    let mut route_receivers = Vec::with_capacity(router_shards);
    for _ in 0..router_shards {
        let (sender, receiver) = mpsc::channel(FLOW_DISPATCH_QUEUE);
        route_senders.push(sender);
        route_receivers.push(receiver);
    }
    let route_dispatcher = RouteDispatcher::new(route_senders);
    let (capacity_tx, capacity_rx) = mpsc::channel(CAPACITY_EVENT_QUEUE);
    let route_estimates = Arc::new(StdRwLock::new(RouteEstimateTable::default()));
    let probe_status = Arc::new(StdRwLock::new(ProbeStatusSnapshot::default()));
    let delivery = Arc::new(StdMutex::new(DeliveryCoordinator::default()));
    let delivery_fast = Arc::new(DeliveryFastPath::default());
    let flow_router_counters = Arc::new(FlowRouterCounters::default());
    let mut peers = HashMap::new();
    for peer_config in &config.peers {
        let peer = Peer::create(
            config,
            peer_config,
            local_id,
            endpoint.clone(),
            alpn.clone(),
            PeerServices {
                inherited_relays: &inherited_relays,
                trace_responder: trace_responder.clone(),
                derp_transport: derp_transport.as_ref(),
                mesh_runtime: mesh_runtime.clone(),
                nat64_prefix: nat64_prefix.clone(),
                inbound_packets: inbound_dispatcher.clone(),
                capacity_events: capacity_tx.clone(),
            },
        )?;
        info!(
            peer = %peer.name,
            endpoint_id = %peer.endpoint_id,
            attachment = %tunnel.as_ref().map_or("none", |tunnel| tunnel.name.as_str()),
            "peer transport ready"
        );
        peers.insert(peer.endpoint_id, Arc::new(peer));
    }
    let peers = Arc::new(RwLock::new(peers));
    let initial_peers = peers.read().await.values().cloned().collect::<Vec<_>>();
    let peer_counters = Arc::new(StdRwLock::new(
        initial_peers
            .iter()
            .map(|peer| (peer.endpoint_id, peer.counters.clone()))
            .collect::<HashMap<_, _>>(),
    ));
    let dynamic_manager = match mesh_runtime.clone() {
        Some(mesh) => Some(DynamicMeshManager::new(
            config,
            local_id,
            endpoint.clone(),
            alpn.clone(),
            inherited_relays.clone(),
            trace_responder.clone(),
            derp_transport.clone(),
            nat64_prefix.clone(),
            mesh,
            peers.clone(),
            peer_counters.clone(),
            inbound_dispatcher.clone(),
            capacity_tx.clone(),
        )?),
        None => None,
    };
    let initial_route_snapshot = Arc::new(
        build_route_snapshot(config, &peers, mesh_runtime.as_deref(), &route_estimates).await,
    );
    let (route_snapshot_tx, route_snapshot_rx) =
        tokio::sync::watch::channel(initial_route_snapshot);
    let runtime_state = Arc::new(RuntimeState::new(
        local_id,
        routing_table(config),
        if tunnel.is_some() {
            config.all_remote_prefixes().collect()
        } else {
            Vec::new()
        },
        peer_counters,
        mesh_runtime.clone(),
        CapacityObservability::new(
            route_estimates.clone(),
            probe_status.clone(),
            config.routing.max_egress_bps(),
        ),
        flow_router_counters.clone(),
    ));
    if let Some(runtime_state_tx) = runtime_state_tx {
        runtime_state_tx.send_replace(Some(runtime_state.clone()));
    }

    let mut tasks = JoinSet::new();
    {
        let config = config.clone();
        let peers = peers.clone();
        let mesh = mesh_runtime.clone();
        let route_estimates = route_estimates.clone();
        tasks.spawn(async move {
            maintain_route_snapshots(config, peers, mesh, route_estimates, route_snapshot_tx).await
        });
    }
    for peer in &initial_peers {
        let sender = peer.clone();
        tasks.spawn(async move { sender.queue_to_network().await });
        let connector = peer.clone();
        tasks.spawn(async move { connector.maintain_connection().await });
    }
    if let Some(tunnel) = tunnel.clone() {
        for (shard, device) in tunnel.devices.iter().cloned().enumerate() {
            let name = tunnel.name.clone();
            let mtu = tunnel.mtu;
            let dispatcher = route_dispatcher.clone();
            tasks
                .spawn(async move { tunnel_to_router(name, device, mtu, shard, dispatcher).await });
        }
    }
    for (shard, inbound_rx) in inbound_receivers.into_iter().enumerate() {
        let config = config.clone();
        let tunnel_writer = tunnel.as_ref().map(|tunnel| tunnel.queue_writer(shard));
        let route_dispatcher = route_dispatcher.clone();
        let capacity_tx = capacity_tx.clone();
        let delivery_fast = delivery_fast.clone();
        let route_snapshot_rx = route_snapshot_rx.clone();
        tasks.spawn(async move {
            inbound_to_router_shard(
                config,
                tunnel_writer,
                inbound_rx,
                route_dispatcher,
                capacity_tx,
                delivery_fast,
                route_snapshot_rx,
            )
            .await
        });
    }
    for (router_shard, route_rx) in route_receivers.into_iter().enumerate() {
        let route_snapshot_rx = route_snapshot_rx.clone();
        let route_estimates = route_estimates.clone();
        let delivery = delivery.clone();
        let delivery_fast = delivery_fast.clone();
        let flow_router_counters = flow_router_counters.clone();
        tasks.spawn(async move {
            run_flow_router(
                FlowRouterConfig::default().max_flows / router_shards
                    + usize::from(
                        router_shard < FlowRouterConfig::default().max_flows % router_shards,
                    ),
                route_snapshot_rx,
                route_estimates,
                delivery,
                delivery_fast,
                flow_router_counters,
                route_rx,
            )
            .await
        });
    }
    {
        let config = config.clone();
        let peers = peers.clone();
        let mesh = mesh_runtime.clone();
        let route_estimates = route_estimates.clone();
        let probe_status = probe_status.clone();
        let delivery = delivery.clone();
        let delivery_fast = delivery_fast.clone();
        tasks.spawn(async move {
            run_capacity_manager(
                config,
                local_id,
                peers,
                mesh,
                CapacityManagerState {
                    estimates: route_estimates,
                    probe_status,
                    delivery,
                    delivery_fast,
                },
                capacity_rx,
            )
            .await
        });
    }

    {
        let endpoint = endpoint.clone();
        let peers = peers.clone();
        let alpn = alpn.clone();
        let probe_alpn = probe_alpn.clone();
        let forbidden_underlay_prefixes = Arc::new(underlay_exclusion_prefixes(config));
        let dynamic_manager = dynamic_manager.clone();
        tasks.spawn(async move {
            accept_loop(
                endpoint,
                peers,
                alpn,
                probe_alpn,
                forbidden_underlay_prefixes,
                dynamic_manager,
            )
            .await
        });
    }
    {
        log_runtime_started(&config.observability);
        let observability = config.observability.clone();
        let runtime_state = runtime_state.clone();
        tasks.spawn(async move { run_reporter(observability, runtime_state).await });
    }
    {
        let endpoint = endpoint.clone();
        let runtime_state = runtime_state.clone();
        let nat64_prefix = nat64_prefix.clone();
        tasks.spawn(async move {
            monitor_network_discovery(endpoint, runtime_state, nat64_prefix).await
        });
    }
    if let Some(mesh_runtime) = mesh_runtime.clone() {
        let route_config = config.clone();
        let route_mesh = mesh_runtime.clone();
        tasks.spawn(async move { maintain_presence_routes(route_config, route_mesh).await });
        tasks.spawn(async move { mesh_runtime.run_maintenance().await });
    }
    if let Some(dynamic_manager) = dynamic_manager {
        tasks.spawn(async move { dynamic_manager.run().await });
    }

    if let Some(ready) = ready {
        let _ = ready.send(());
    }

    tokio::pin!(shutdown);
    let runtime_error = tokio::select! {
        signal = &mut shutdown => {
            signal?;
            info!("shutdown requested");
            None
        }
        task = tasks.join_next() => {
            Some(match task {
                Some(Ok(Ok(()))) => anyhow!("a runtime task stopped unexpectedly"),
                Some(Ok(Err(error))) => error,
                Some(Err(error)) => error.into(),
                None => anyhow!("all runtime tasks stopped unexpectedly"),
            })
        }
    };

    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    let all_peers = peers.read().await.values().cloned().collect::<Vec<_>>();
    for peer in all_peers {
        peer.close().await;
    }
    let status_result = publish_status(&config.observability, &runtime_state).await;
    endpoint.close().await;
    match runtime_error {
        Some(error) => Err(error),
        None => {
            status_result.context("failed publishing final runtime status")?;
            Ok(())
        }
    }
}

async fn tunnel_to_router(
    name: String,
    device: Arc<AsyncDevice>,
    mtu: u16,
    read_shard: usize,
    dispatcher: RouteDispatcher,
) -> Result<()> {
    let mut original = vec![0_u8; tun_rs::VIRTIO_NET_HDR_LEN + usize::from(u16::MAX)];
    let mut pool = tun_read_pool(mtu);
    let mut sizes = vec![0_usize; pool.slot_count()];
    let mut route_batch = Vec::with_capacity(pool.slot_count());
    let mut dispatch_scratch = (0..dispatcher.shard_count())
        .map(|_| Vec::new())
        .collect::<Vec<_>>();
    loop {
        let headroom = pool.headroom();
        let count = device
            .recv_multiple(&mut original, pool.slots_mut(), &mut sizes, headroom)
            .await
            .with_context(|| format!("failed reading {name} queue {read_shard}"))?;
        for (index, payload_len) in sizes.iter().copied().enumerate().take(count) {
            let packet = pool.take(index, payload_len);
            let packet_info = match inspect_ip_packet(packet.as_slice()) {
                Ok(info) => info,
                Err(error) => {
                    debug!(%error, read_shard, "dropping invalid packet read from FlowRouter TUN");
                    continue;
                }
            };
            route_batch.push(RouteRequest {
                packet,
                packet_info,
                previous_peer: None,
                delivery_tag: None,
            });
        }
        dispatcher
            .send_batch_with_scratch(&mut route_batch, &mut dispatch_scratch)
            .await?;
    }
}

async fn inbound_to_router_shard(
    config: Config,
    mut tunnel_writer: Option<OverlayTunnelQueueWriter>,
    mut inbound_rx: mpsc::Receiver<InboundPacket>,
    route_dispatcher: RouteDispatcher,
    capacity_tx: mpsc::Sender<CapacityEvent>,
    delivery_fast: Arc<DeliveryFastPath>,
    mut route_snapshots: tokio::sync::watch::Receiver<Arc<DataPlaneRouteSnapshot>>,
) -> Result<()> {
    let mut inbound_batch = Vec::with_capacity(INBOUND_ROUTER_BATCH);
    let mut local = Vec::with_capacity(INBOUND_ROUTER_BATCH);
    let mut tun_buffers = Vec::with_capacity(INBOUND_ROUTER_BATCH);
    let mut local_delivery = Vec::with_capacity(INBOUND_ROUTER_BATCH);
    let mut transit = Vec::with_capacity(INBOUND_ROUTER_BATCH);
    let mut dispatch_scratch = (0..route_dispatcher.shard_count())
        .map(|_| Vec::new())
        .collect::<Vec<_>>();
    let mut active_snapshot = route_snapshots.borrow_and_update().clone();
    let mut delivery_receiver = DeliveryReceiver::default();
    let mut registered_delivery_sessions = HashSet::new();
    loop {
        inbound_batch.clear();
        if inbound_rx
            .recv_many(&mut inbound_batch, INBOUND_ROUTER_BATCH)
            .await
            == 0
        {
            break;
        }
        if route_snapshots.has_changed().unwrap_or(false) {
            active_snapshot = route_snapshots.borrow_and_update().clone();
        }
        let batch_now = Instant::now();
        for mut inbound in inbound_batch.drain(..) {
            let info = inbound.packet_info;
            let snapshot = active_snapshot.as_ref();
            let Some(adjacency_index) = snapshot.adjacency_by_owner.get(&inbound.peer_id) else {
                debug!(peer = %inbound.peer_id, "dropping packet from expired adjacency generation");
                continue;
            };
            let Some(adjacency) = snapshot.adjacencies.get(*adjacency_index) else {
                continue;
            };
            let peer = &adjacency.peer;
            if !peer.packet_allowed(
                snapshot,
                adjacency.input.transit_enabled,
                info.source,
                info.destination,
                true,
            ) {
                if should_log(&peer.counters.policy_drops) {
                    warn!(
                        peer = %peer.name,
                        source = %info.source,
                        destination = %info.destination,
                        policy_drops = peer.counters.policy_drops.load(Ordering::Relaxed),
                        "dropping inbound packet rejected by immutable overlay policy"
                    );
                }
                continue;
            }
            peer.counters.rx_packets.fetch_add(1, Ordering::Relaxed);
            peer.counters
                .rx_bytes
                .fetch_add(inbound.packet.len() as u64, Ordering::Relaxed);
            if snapshot.local_prefixes.contains(info.destination) {
                if tunnel_writer.is_none() {
                    debug!(destination = %info.destination, "dropping local packet without an attachment");
                    continue;
                }
                local.push(inbound);
                continue;
            }
            if !config.routing.transit_enabled {
                continue;
            }
            if let Err(error) = inbound
                .packet
                .try_map_payload(decrement_hop_limit_validated)
            {
                debug!(peer = %inbound.peer_id, %error, "dropping packet at overlay hop limit");
                continue;
            }
            transit.push(RouteRequest {
                packet: inbound.packet,
                packet_info: info,
                previous_peer: Some(inbound.peer_id),
                delivery_tag: inbound.delivery_tag,
            });
        }

        if let Some(writer) = tunnel_writer.as_mut()
            && !local.is_empty()
        {
            tun_buffers.clear();
            local_delivery.clear();
            for inbound in local.drain(..) {
                local_delivery.push((inbound.delivery_tag, inbound.packet.len()));
                tun_buffers.push(attach_virtio(inbound.packet));
            }
            writer
                .send_owned(&mut tun_buffers)
                .await
                .context("failed injecting inbound packet batch into FlowRouter TUN")?;
            for (delivery_tag, packet_len) in local_delivery.drain(..) {
                let Some(tag) = delivery_tag else {
                    continue;
                };
                if !registered_delivery_sessions.contains(&tag.session_id) {
                    let Some(registration) = delivery_fast.forwarding_registration(tag.session_id)
                    else {
                        continue;
                    };
                    if delivery_receiver.register(registration, batch_now).is_err() {
                        continue;
                    }
                    if registered_delivery_sessions.len() >= MAX_DELIVERY_SESSIONS {
                        registered_delivery_sessions.clear();
                    }
                    registered_delivery_sessions.insert(tag.session_id);
                }
                delivery_fast.touch_forwarding(tag.session_id);
                let report = delivery_receiver.observe(tag, packet_len, batch_now);
                if let Some(report) = report {
                    let _ = capacity_tx.try_send(CapacityEvent::Delivered { report });
                }
            }
        }
        route_dispatcher
            .send_batch_with_scratch(&mut transit, &mut dispatch_scratch)
            .await?;
    }
    bail!("inbound packet queue closed")
}

async fn build_route_snapshot(
    config: &Config,
    peers: &RwLock<HashMap<EndpointId, Arc<Peer>>>,
    mesh: Option<&MeshRuntime>,
    route_estimates: &StdRwLock<RouteEstimateTable>,
) -> DataPlaneRouteSnapshot {
    let (mesh_origins, transit_by_owner) = mesh
        .map(MeshRuntime::routing_policy_snapshot)
        .unwrap_or_default();
    let mesh_owners = PrefixOwnerTable::from_origins(mesh_origins.iter().copied());
    let mut origins = mesh_origins.clone();
    // Pinned configuration is authoritative for an identical prefix. Insert
    // it after Presence-derived policy so exact duplicates replace the dynamic
    // entry while longest-prefix matching still governs overlaps.
    origins.extend(config.route_origins.iter().flat_map(|origin| {
        origin
            .prefixes
            .iter()
            .copied()
            .map(|prefix| (origin.endpoint_id, prefix))
    }));
    let owners = PrefixOwnerTable::from_origins(origins.iter().copied());
    let overlay_prefixes = IpPrefixSet::from_prefixes(
        config
            .all_overlay_prefixes()
            .chain(mesh_origins.iter().map(|(_, prefix)| *prefix)),
    );
    let local_prefixes = IpPrefixSet::from_prefixes(config.all_advertised_prefixes());
    let remote_prefixes = IpPrefixSet::from_prefixes(
        config
            .all_remote_prefixes()
            .chain(mesh_origins.iter().map(|(_, prefix)| *prefix)),
    );
    let peers = peers.read().await.values().cloned().collect::<Vec<_>>();
    let now = Instant::now();
    let estimates = route_estimates
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut adjacencies = Vec::with_capacity(peers.len());
    let mut adjacency_by_owner = FxHashMap::default();
    adjacency_by_owner.reserve(peers.len());
    for peer in peers {
        let metrics = peer
            .link_estimator
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .snapshot();
        let index = adjacencies.len();
        adjacency_by_owner.insert(peer.endpoint_id, index);
        adjacencies.push(RouteAdjacencySnapshot {
            input: AdjacencyRouteInput {
                endpoint_id: peer.endpoint_id,
                route_id: peer.route_id,
                connected: peer.counters.connected.load(Ordering::Relaxed),
                transit_enabled: transit_by_owner
                    .get(&peer.endpoint_id)
                    .copied()
                    .unwrap_or(peer.declared_transit_enabled),
                metrics,
                queued_bytes: peer.outbound.queued_bytes(),
            },
            direct_capacity: estimates.snapshot_or_bootstrap(
                &RouteKey {
                    destination: peer.endpoint_id,
                    first_hop: peer.endpoint_id,
                },
                now,
                config.routing.max_egress_bps(),
            ),
            peer,
        });
    }
    DataPlaneRouteSnapshot {
        owners,
        mesh_owners,
        overlay_prefixes,
        local_prefixes,
        remote_prefixes,
        adjacencies,
        adjacency_by_owner,
        capacities: estimates
            .snapshot_all(now, config.routing.max_egress_bps())
            .into_iter()
            .collect(),
        max_egress_bps: config.routing.max_egress_bps(),
    }
}

async fn maintain_route_snapshots(
    config: Config,
    peers: Arc<RwLock<HashMap<EndpointId, Arc<Peer>>>>,
    mesh: Option<Arc<MeshRuntime>>,
    route_estimates: Arc<StdRwLock<RouteEstimateTable>>,
    snapshots: tokio::sync::watch::Sender<Arc<DataPlaneRouteSnapshot>>,
) -> Result<()> {
    let mut refresh = tokio::time::interval(ROUTE_SNAPSHOT_REFRESH);
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    refresh.tick().await;
    loop {
        refresh.tick().await;
        snapshots.send_replace(Arc::new(
            build_route_snapshot(&config, &peers, mesh.as_deref(), &route_estimates).await,
        ));
    }
}

fn direct_route_choice(
    snapshot: &DataPlaneRouteSnapshot,
    owner: EndpointId,
    previous_peer: Option<EndpointId>,
) -> Option<RouteChoice> {
    if previous_peer == Some(owner) {
        return None;
    }
    let adjacency_index = *snapshot.adjacency_by_owner.get(&owner)?;
    let adjacency = snapshot.adjacencies.get(adjacency_index)?;
    // Connected/queue state changes faster than the immutable topology
    // generation. Refresh those two atomics on the fast path while keeping
    // policy, prefix ownership and link metrics snapshot-owned.
    if !adjacency.peer.counters.connected.load(Ordering::Relaxed) {
        return None;
    }
    let capacity = adjacency.direct_capacity;
    if adjacency.input.metrics.loss_ppm >= DIRECT_OWNER_MAX_LOSS_PPM
        || capacity.health_per_mille < DIRECT_OWNER_MIN_HEALTH_PER_MILLE
    {
        return None;
    }
    Some(RouteChoice {
        endpoint_id: owner,
        adjacency_index,
        candidate: RouteCandidate {
            id: adjacency.input.route_id,
            startup_latency: capacity
                .rtt_ewma
                .unwrap_or_else(|| adjacency.input.metrics.startup_latency()),
            capacity_bps: capacity.effective_capacity_bps,
            queued_bytes: adjacency.peer.outbound.queued_bytes(),
            loss_penalty: adjacency.input.metrics.loss_penalty(),
        },
        capacity,
    })
}

async fn run_flow_router(
    max_flows: usize,
    mut route_snapshots: tokio::sync::watch::Receiver<Arc<DataPlaneRouteSnapshot>>,
    route_estimates: Arc<StdRwLock<RouteEstimateTable>>,
    delivery: Arc<StdMutex<DeliveryCoordinator>>,
    delivery_fast: Arc<DeliveryFastPath>,
    counters: Arc<FlowRouterCounters>,
    mut requests: mpsc::Receiver<RouteRequest>,
) -> Result<()> {
    let mut router = FlowRouter::new(FlowRouterConfig {
        max_flows,
        ..FlowRouterConfig::default()
    });
    let mut published_active_flows = 0_usize;
    let mut active_snapshot = route_snapshots.borrow_and_update().clone();
    let route_switch_log_events = AtomicU64::new(0);
    let mut inputs = Vec::new();
    let mut choices = Vec::new();
    let mut request_batch = Vec::with_capacity(INBOUND_ROUTER_BATCH);
    loop {
        request_batch.clear();
        if requests
            .recv_many(&mut request_batch, INBOUND_ROUTER_BATCH)
            .await
            == 0
        {
            break;
        }
        if route_snapshots.has_changed().unwrap_or(false) {
            active_snapshot = route_snapshots.borrow_and_update().clone();
        }
        let batch_now = Instant::now();
        router.maintain(batch_now);
        for request in request_batch.drain(..) {
            let packet_info = request.packet_info;
            let snapshot = active_snapshot.as_ref();
            let owner = snapshot.owners.owner(packet_info.destination);
            choices.clear();
            if let Some(owner) = owner
                && let Some(direct) = direct_route_choice(snapshot, owner, request.previous_peer)
            {
                choices.push(direct);
            } else {
                inputs.clear();
                inputs.reserve(snapshot.adjacencies.len().saturating_sub(inputs.capacity()));
                inputs.extend(
                    snapshot
                        .adjacencies
                        .iter()
                        .map(|adjacency| AdjacencyRouteInput {
                            connected: adjacency.peer.counters.connected.load(Ordering::Relaxed),
                            queued_bytes: adjacency.peer.outbound.queued_bytes(),
                            ..adjacency.input
                        }),
                );
                fill_route_candidates_from_snapshot(
                    &mut choices,
                    owner,
                    request.previous_peer,
                    &inputs,
                    snapshot,
                    batch_now,
                );
            }
            let flow_key = FlowKey::from(packet_info);
            let Some(decision) = router.select_projected(
                flow_key,
                packet_info.length,
                0,
                &choices,
                |choice| &choice.candidate,
                batch_now,
            ) else {
                publish_shard_flow_count(&counters, &mut published_active_flows, router.len());
                counters.no_route_drops.fetch_add(1, Ordering::Relaxed);
                debug!(destination = %packet_info.destination, "no usable FlowRouter route");
                continue;
            };
            publish_shard_flow_count(&counters, &mut published_active_flows, router.len());
            counters.decisions.fetch_add(1, Ordering::Relaxed);
            let Some(selected_choice) = choices
                .iter()
                .find(|choice| choice.candidate.id == decision.route_id)
            else {
                continue;
            };
            let selected_endpoint = selected_choice.endpoint_id;
            if decision.switched() {
                counters.route_switches.fetch_add(1, Ordering::Relaxed);
                let now = Instant::now();
                let route = RouteKey {
                    destination: owner.expect("a route decision requires a destination owner"),
                    first_hop: selected_endpoint,
                };
                route_estimates
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get_or_insert(route, now)
                    .observe_route_switch(now);
                if should_log(&route_switch_log_events) {
                    let old_first_hop = decision
                        .previous_route_id
                        .and_then(|old| {
                            choices
                                .iter()
                                .find(|choice| choice.candidate.id == old)
                                .map(|choice| choice.endpoint_id.to_string())
                        })
                        .unwrap_or_else(|| {
                            decision.previous_route_id.map_or_else(
                                || "none".into(),
                                |old| format!("unavailable-route-{}", old.0),
                            )
                        });
                    info!(
                        ?flow_key,
                        destination = %route.destination,
                        old_first_hop = %old_first_hop,
                        new_first_hop = %selected_endpoint,
                        demand_bytes = decision.demand_bytes,
                        rtt_micros = selected_choice
                            .candidate
                            .startup_latency
                            .as_micros()
                            .min(u128::from(u64::MAX)) as u64,
                        capacity_bps = selected_choice.capacity.capacity_bps,
                        effective_capacity_bps = selected_choice.capacity.effective_capacity_bps,
                        health_per_mille = selected_choice.capacity.health_per_mille,
                        queue_bytes = selected_choice.candidate.queued_bytes,
                        loss_penalty_micros = selected_choice
                            .candidate
                            .loss_penalty
                            .as_micros()
                            .min(u128::from(u64::MAX)) as u64,
                        switch_penalty_micros = decision
                            .switch_penalty
                            .as_micros()
                            .min(u128::from(u64::MAX)) as u64,
                        estimated_completion_micros = decision
                            .estimated_completion
                            .as_micros()
                            .min(u128::from(u64::MAX)) as u64,
                        "FlowRouter switched route"
                    );
                }
            }
            let Some(adjacency) = snapshot.adjacencies.get(selected_choice.adjacency_index) else {
                continue;
            };
            let peer = adjacency.peer.as_ref();
            if !peer.packet_allowed(
                snapshot,
                adjacency.input.transit_enabled,
                packet_info.source,
                packet_info.destination,
                false,
            ) {
                if should_log(&peer.counters.policy_drops) {
                    warn!(
                        peer = %peer.name,
                        source = %packet_info.source,
                        destination = %packet_info.destination,
                        "dropping FlowRouter packet outside overlay policy"
                    );
                }
                continue;
            }
            let latency_sensitive = latency_service(decision.demand_bytes, packet_info.length);
            if latency_sensitive {
                peer.counters
                    .flow_latency_packets
                    .fetch_add(1, Ordering::Relaxed);
            } else {
                peer.counters
                    .flow_bulk_packets
                    .fetch_add(1, Ordering::Relaxed);
            }
            peer.counters
                .flow_selected_bytes
                .fetch_add(packet_info.length as u64, Ordering::Relaxed);
            let mut delivery_state = if let Some(tag) = request.delivery_tag {
                delivery_fast.touch_forwarding(tag.session_id);
                DeliveryTagState {
                    tag: Some(tag),
                    registration: None,
                }
            } else if let Some(owner) = owner
                && delivery_tracking_required(
                    owner,
                    selected_endpoint,
                    choices.len(),
                    peer.counters
                        .selected_path_transport
                        .load(Ordering::Relaxed),
                )
            {
                // Receiver-confirmed capacity exists to discriminate between
                // competing routes and to learn a transit route before an
                // alternate reconnects. Only the common healthy direct-owner
                // path can omit the 12-byte header; all tracked paths use the
                // lock-free session index in steady state.
                let route = RouteKey {
                    destination: owner,
                    first_hop: selected_endpoint,
                };
                let path_epoch = peer.path_epoch.load(Ordering::Relaxed);
                let queue_nonempty = !latency_sensitive || peer.outbound.queued_bytes() > 0;
                if let Some(tag) = delivery_fast.next_source_tag(route, path_epoch, queue_nonempty)
                {
                    DeliveryTagState {
                        tag: Some(tag),
                        registration: None,
                    }
                } else {
                    // Expiry/registration is a once-per-session cold path.
                    {
                        let mut coordinator = delivery
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        let state =
                            coordinator.next_tag(route, path_epoch, queue_nonempty, batch_now);
                        if let (Some(tag), Some(registration)) =
                            (state.tag, coordinator.source_registration(route))
                        {
                            // Publish the mutable and read-mostly generations
                            // under one cold-path serialization point. Without
                            // this, two Router shards (or a probe renewal) can
                            // publish an older session after a newer session.
                            delivery_fast
                                .install_source(registration, tag.sequence.wrapping_add(1));
                        }
                        state
                    }
                }
            } else {
                DeliveryTagState::default()
            };
            if let Some(registration) = delivery_state.registration.take() {
                // Control is queued before the first tagged application packet. If
                // the bounded control queue is full, leave this packet untagged and
                // retry session renewal on later data.
                let session_id = registration.session_id;
                let registered =
                    queue_delivery_message(peer, DeliveryMessage::Register(registration)).await;
                if !registered {
                    delivery_state.tag = None;
                    delivery_fast.remove_source_session(session_id);
                    delivery
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .registration_failed(session_id, Instant::now());
                }
            }
            if delivery_state.tag.is_some() {
                peer.counters
                    .delivery_tagged_packets
                    .fetch_add(1, Ordering::Relaxed);
                peer.counters
                    .delivery_header_bytes
                    .fetch_add(DELIVERY_TAG_WIRE_BYTES as u64, Ordering::Relaxed);
            }
            peer.outbound.push(
                OutboundPacket::new(request.packet, latency_sensitive)
                    .with_delivery_tag(delivery_state.tag),
            );
        }
    }
    counters
        .active_flows
        .fetch_sub(published_active_flows as u64, Ordering::Relaxed);
    bail!("FlowRouter request queue closed")
}

fn publish_shard_flow_count(counters: &FlowRouterCounters, published: &mut usize, current: usize) {
    if current > *published {
        counters
            .active_flows
            .fetch_add((current - *published) as u64, Ordering::Relaxed);
    } else if current < *published {
        counters
            .active_flows
            .fetch_sub((*published - current) as u64, Ordering::Relaxed);
    }
    *published = current;
}

async fn run_capacity_manager(
    config: Config,
    local_id: EndpointId,
    peers: Arc<RwLock<HashMap<EndpointId, Arc<Peer>>>>,
    mesh: Option<Arc<MeshRuntime>>,
    state: CapacityManagerState,
    mut events: mpsc::Receiver<CapacityEvent>,
) -> Result<()> {
    let CapacityManagerState {
        estimates,
        probe_status,
        delivery,
        delivery_fast,
    } = state;
    let mut scheduler = ActiveProbeScheduler::default();
    let mut pending = HashMap::<u64, PendingOriginProbe>::new();
    let mut receiving = HashMap::<(EndpointId, u64), ReceivingProbe>::new();
    let mut last_health_refresh = None;
    let mut last_probe_status_publish = None;
    let mut tick = tokio::time::interval(CAPACITY_PROBE_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            event = events.recv() => {
                let Some(event) = event else {
                    bail!("capacity event queue closed");
                };
                let result = match event {
                    CapacityEvent::Message { from, message } => {
                        handle_capacity_message(
                            local_id,
                            from,
                            message,
                            &peers,
                            mesh.as_ref(),
                            &estimates,
                            &delivery,
                            &delivery_fast,
                            &mut scheduler,
                            &mut pending,
                            &mut receiving,
                        ).await.map_err(|error| (from, error))
                    }
                    CapacityEvent::DeliveryMessage { from, message } => {
                        handle_delivery_message(
                            local_id,
                            from,
                            message,
                            &peers,
                            &estimates,
                            &delivery,
                            &delivery_fast,
                            &mut scheduler,
                        ).await.map_err(|error| (from, error))
                    }
                    CapacityEvent::Delivered { report } => {
                        handle_delivery_report(local_id, report, &peers, &delivery_fast)
                            .await
                            .map_err(|error| (local_id, error))
                    }
                };
                if let Err((from, error)) = result {
                    debug!(%from, %error, "dropping invalid capacity or delivery message");
                }
                publish_probe_status_if_due(
                    &probe_status,
                    &scheduler,
                    Instant::now(),
                    &mut last_probe_status_publish,
                );
            }
            _ = tick.tick() => {
                let now = Instant::now();
                let observe_health = last_health_refresh.is_none_or(|last| {
                    now.saturating_duration_since(last) >= Duration::from_secs(1)
                });
                if observe_health {
                    refresh_capacity_routes(
                        &config,
                        local_id,
                        &peers,
                        mesh.as_ref(),
                        &estimates,
                        &mut scheduler,
                        now,
                    ).await;
                    last_health_refresh = Some(now);
                }
                let source_liveness = delivery_fast.source_liveness();
                {
                    let mut coordinator = delivery
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    // The packet path owns session liveness in atomics. Fold
                    // it into the mutable report accumulator at control-tick
                    // cadence so low-rate tagged traffic cannot keep the fast
                    // session alive while its report state expires.
                    for liveness in source_liveness {
                        coordinator.synchronize_source_liveness(liveness, now);
                    }
                    coordinator.prune(now);
                }
                delivery_fast.prune();

                let expired = pending
                    .iter()
                    .filter(|(_, state)| now.saturating_duration_since(state.started_at) >= CAPACITY_PROBE_TIMEOUT)
                    .map(|(probe_id, _)| *probe_id)
                    .collect::<Vec<_>>();
                for probe_id in expired {
                    if let Some(state) = pending.remove(&probe_id) {
                        scheduler.failed(state.request, now);
                        if let Some(estimate) = estimates
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .get_mut(&state.request.route, now)
                        {
                            estimate.observe_failure(now);
                        }
                    }
                }

                let expired_receivers = receiving
                    .iter()
                    .filter(|(_, state)| state.expires_at <= now)
                    .map(|(key, _)| *key)
                    .collect::<Vec<_>>();
                for key in expired_receivers {
                    if let Some(state) = receiving.remove(&key) {
                        let report = state.receiver.report(
                            key.1,
                            state.origin,
                            state.destination,
                            state.traversed_hops,
                        );
                        if let Some(previous) = reverse_next_hop(&report.traversed_hops, local_id) {
                            let _ = send_capacity_message(
                                &peers,
                                previous,
                                CapacityProbeMessage::Report(report),
                                false,
                            ).await;
                        }
                    }
                }

                let inventory = peers.read().await.values().cloned().collect::<Vec<_>>();
                let any_application_busy = inventory.iter().any(|peer| {
                    peer.counters.queue_bytes.load(Ordering::Relaxed) > 0
                });
                let queue_by_hop = inventory
                    .iter()
                    .map(|peer| (
                        peer.endpoint_id,
                        peer.counters.queue_bytes.load(Ordering::Relaxed),
                    ))
                    .collect::<HashMap<_, _>>();
                if let Some(request) = scheduler.next(
                    now,
                    |route| queue_by_hop.get(&route.first_hop).copied().unwrap_or(1) > 0,
                    any_application_busy,
                    any_application_busy,
                ) {
                    let path_epoch = inventory
                        .iter()
                        .find(|peer| peer.endpoint_id == request.route.first_hop)
                        .map(|peer| peer.path_epoch.load(Ordering::Relaxed))
                        .unwrap_or(0);
                    let start = CapacityProbeStart {
                        probe_id: request.probe_id,
                        origin: local_id,
                        destination: request.route.destination,
                        packet_count: CAPACITY_PROBE_PACKET_COUNT,
                        payload_size: CAPACITY_PROBE_PAYLOAD_SIZE,
                        hop_limit: crate::capacity_probe::MAX_PROBE_HOPS as u8,
                        traversed_hops: vec![local_id],
                    };
                    if send_capacity_message(
                        &peers,
                        request.route.first_hop,
                        CapacityProbeMessage::Start(start),
                        false,
                    ).await {
                        pending.insert(request.probe_id, PendingOriginProbe {
                            request,
                            started_at: now,
                            path_epoch,
                            route_rtt: None,
                        });
                    } else {
                        scheduler.failed(request, now);
                    }
                }
                publish_probe_status_if_due(
                    &probe_status,
                    &scheduler,
                    now,
                    &mut last_probe_status_publish,
                );
            }
        }
    }
}

fn publish_probe_status(
    shared: &StdRwLock<ProbeStatusSnapshot>,
    scheduler: &ActiveProbeScheduler,
    now: Instant,
) {
    *shared
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = scheduler.snapshot(now);
}

fn publish_probe_status_if_due(
    shared: &StdRwLock<ProbeStatusSnapshot>,
    scheduler: &ActiveProbeScheduler,
    now: Instant,
    last_publish: &mut Option<Instant>,
) {
    if last_publish.is_some_and(|last| now.saturating_duration_since(last) < PROBE_STATUS_REFRESH) {
        return;
    }
    publish_probe_status(shared, scheduler, now);
    *last_publish = Some(now);
}

#[allow(clippy::too_many_arguments)]
async fn handle_capacity_message(
    local_id: EndpointId,
    from: EndpointId,
    message: CapacityProbeMessage,
    peers: &Arc<RwLock<HashMap<EndpointId, Arc<Peer>>>>,
    mesh: Option<&Arc<MeshRuntime>>,
    estimates: &Arc<StdRwLock<RouteEstimateTable>>,
    delivery: &Arc<StdMutex<DeliveryCoordinator>>,
    delivery_fast: &Arc<DeliveryFastPath>,
    scheduler: &mut ActiveProbeScheduler,
    pending: &mut HashMap<u64, PendingOriginProbe>,
    receiving: &mut HashMap<(EndpointId, u64), ReceivingProbe>,
) -> Result<()> {
    match message {
        CapacityProbeMessage::Start(mut start) => {
            ensure!(
                start.traversed_hops.last() == Some(&from),
                "probe start arrived from an unexpected hop"
            );
            append_probe_hop(&mut start, local_id)?;
            if start.destination == local_id {
                let previous = reverse_next_hop(&start.traversed_hops, local_id)
                    .context("probe route has no reverse hop")?;
                let ready = CapacityProbeReady {
                    probe_id: start.probe_id,
                    origin: start.origin,
                    destination: start.destination,
                    traversed_hops: start.traversed_hops,
                };
                ensure!(
                    send_capacity_message(
                        peers,
                        previous,
                        CapacityProbeMessage::Ready(ready),
                        false
                    )
                    .await,
                    "probe ready next hop is unavailable"
                );
            } else {
                let next = capacity_forward_peer(start.destination, Some(from), peers, mesh)
                    .await
                    .context("no capacity probe route to destination")?;
                ensure!(
                    send_capacity_message(peers, next, CapacityProbeMessage::Start(start), false)
                        .await,
                    "probe start next hop is unavailable"
                );
            }
        }
        CapacityProbeMessage::Ready(ready) => {
            ensure!(
                forward_next_hop(&ready.traversed_hops, local_id) == Some(from),
                "probe ready arrived outside its fixed reverse route"
            );
            if ready.origin != local_id {
                let previous = reverse_next_hop(&ready.traversed_hops, local_id)
                    .context("probe ready has no reverse hop")?;
                ensure!(
                    send_capacity_message(
                        peers,
                        previous,
                        CapacityProbeMessage::Ready(ready),
                        false
                    )
                    .await,
                    "probe ready reverse hop is unavailable"
                );
                return Ok(());
            }
            let state = pending
                .get_mut(&ready.probe_id)
                .context("unknown local capacity probe")?;
            ensure!(
                state.request.route.destination == ready.destination,
                "probe destination changed"
            );
            ensure!(
                ready.traversed_hops.get(1) == Some(&state.request.route.first_hop),
                "probe first hop changed"
            );
            let current_epoch = peers
                .read()
                .await
                .get(&state.request.route.first_hop)
                .map(|peer| peer.path_epoch.load(Ordering::Relaxed))
                .context("probe first hop disappeared")?;
            ensure!(
                current_epoch == state.path_epoch,
                "probe first-hop path changed"
            );
            state.route_rtt = Some(Instant::now().saturating_duration_since(state.started_at));
            let registration = {
                let mut coordinator = delivery
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let registration = coordinator.install_source_route(
                    local_id,
                    state.request.route,
                    state.path_epoch,
                    ready.traversed_hops.clone(),
                    Instant::now(),
                )?;
                // Use the same serialization boundary as FlowRouter renewal so
                // the fast map cannot be rolled back to a stale session.
                delivery_fast.install_source(registration.clone(), 0);
                registration
            };
            let session_id = registration.session_id;
            if !send_delivery_message(
                peers,
                state.request.route.first_hop,
                DeliveryMessage::Register(registration),
            )
            .await
            {
                delivery_fast.remove_source_session(session_id);
                delivery
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .registration_failed(session_id, Instant::now());
                bail!("delivery registration first hop is unavailable");
            }
            let active_samples = scheduler
                .bookkeeping(&state.request.route)
                .map_or(0, |bookkeeping| bookkeeping.active_samples)
                .min(2);
            let target_bps = 10_000_000_u64.saturating_mul(1_u64 << (active_samples * 2));
            scheduler.record_bytes(
                state.request,
                u64::from(CAPACITY_PROBE_PACKET_COUNT)
                    .saturating_mul(u64::from(CAPACITY_PROBE_PAYLOAD_SIZE)),
            );
            let gap_micros = (u64::from(CAPACITY_PROBE_PAYLOAD_SIZE) * 8 * 1_000_000)
                .div_ceil(target_bps)
                .max(1) as u32;
            let first_hop = state.request.route.first_hop;
            let probe_id = ready.probe_id;
            let origin = ready.origin;
            let destination = ready.destination;
            let forward_hops = ready.traversed_hops;
            let peer = peers
                .read()
                .await
                .get(&first_hop)
                .cloned()
                .context("probe first hop is unavailable")?;
            tokio::spawn(async move {
                let start = tokio::time::Instant::now();
                let mut message = CapacityProbeMessage::Packet(CapacityProbePacket {
                    probe_id,
                    origin,
                    destination,
                    sequence: 0,
                    packet_count: CAPACITY_PROBE_PACKET_COUNT,
                    planned_gap_micros: gap_micros,
                    forward_hops,
                    payload: Bytes::from(vec![0_u8; usize::from(CAPACITY_PROBE_PAYLOAD_SIZE)]),
                });
                for sequence in 0..CAPACITY_PROBE_PACKET_COUNT {
                    let CapacityProbeMessage::Packet(packet) = &mut message else {
                        unreachable!("capacity probe train message changed variant");
                    };
                    packet.sequence = sequence;
                    let Ok(datagram) = encode_probe(&message) else {
                        break;
                    };
                    if !peer.outbound.push_probe(datagram) {
                        break;
                    }
                    tokio::time::sleep_until(
                        start
                            + Duration::from_micros(
                                u64::from(gap_micros) * u64::from(sequence + 1),
                            ),
                    )
                    .await;
                }
            });
        }
        CapacityProbeMessage::Packet(packet) => {
            ensure!(
                reverse_next_hop(&packet.forward_hops, local_id) == Some(from),
                "probe packet arrived outside its fixed route"
            );
            if packet.destination != local_id {
                let next = forward_next_hop(&packet.forward_hops, local_id)
                    .context("probe packet has no forward hop")?;
                ensure!(
                    send_capacity_message(peers, next, CapacityProbeMessage::Packet(packet), true)
                        .await,
                    "probe packet next hop is unavailable"
                );
                return Ok(());
            }
            const MAX_RECEIVING_PROBES: usize = 64;
            let key = (packet.origin, packet.probe_id);
            if !receiving.contains_key(&key) {
                if receiving.len() >= MAX_RECEIVING_PROBES {
                    let oldest = receiving
                        .iter()
                        .min_by_key(|(_, state)| state.expires_at)
                        .map(|(key, _)| *key);
                    if let Some(oldest) = oldest {
                        receiving.remove(&oldest);
                    }
                }
                receiving.insert(
                    key,
                    ReceivingProbe {
                        receiver: ProbeReceiver::new(
                            packet.packet_count,
                            packet.payload.len() as u16,
                            Duration::from_micros(u64::from(packet.planned_gap_micros)),
                        )?,
                        origin: packet.origin,
                        destination: packet.destination,
                        traversed_hops: packet.forward_hops.clone(),
                        expires_at: Instant::now() + CAPACITY_PROBE_RECEIVER_TIMEOUT,
                    },
                );
            }
            let complete = {
                let state = receiving
                    .get_mut(&key)
                    .expect("probe receiver was inserted");
                ensure!(
                    state.traversed_hops == packet.forward_hops,
                    "probe packet route changed"
                );
                state
                    .receiver
                    .observe(packet.sequence, packet.payload.len(), Instant::now())?;
                state.receiver.is_complete()
            };
            if complete {
                let state = receiving.remove(&key).expect("complete receiver exists");
                let report = state.receiver.report(
                    packet.probe_id,
                    state.origin,
                    state.destination,
                    state.traversed_hops,
                );
                let previous = reverse_next_hop(&report.traversed_hops, local_id)
                    .context("probe report has no reverse hop")?;
                ensure!(
                    send_capacity_message(
                        peers,
                        previous,
                        CapacityProbeMessage::Report(report),
                        false
                    )
                    .await,
                    "probe report reverse hop is unavailable"
                );
            }
        }
        CapacityProbeMessage::Report(report) => {
            ensure!(
                forward_next_hop(&report.traversed_hops, local_id) == Some(from),
                "probe report arrived outside its fixed reverse route"
            );
            if report.origin != local_id {
                let previous = reverse_next_hop(&report.traversed_hops, local_id)
                    .context("probe report has no reverse hop")?;
                ensure!(
                    send_capacity_message(
                        peers,
                        previous,
                        CapacityProbeMessage::Report(report),
                        false
                    )
                    .await,
                    "probe report reverse hop is unavailable"
                );
                return Ok(());
            }
            let state = pending
                .get(&report.probe_id)
                .copied()
                .context("unknown local probe report")?;
            ensure!(
                state.request.route.destination == report.destination,
                "probe report destination changed"
            );
            ensure!(
                report.traversed_hops.get(1) == Some(&state.request.route.first_hop),
                "probe report first hop changed"
            );
            let current_epoch = peers
                .read()
                .await
                .get(&state.request.route.first_hop)
                .map(|peer| peer.path_epoch.load(Ordering::Relaxed))
                .context("probe first hop disappeared")?;
            ensure!(
                current_epoch == state.path_epoch,
                "probe result belongs to an old path epoch"
            );
            let interval = Duration::from_micros(u64::from(report.first_to_last_arrival_micros));
            ensure!(
                !interval.is_zero() && report.received_bytes > 0,
                "probe report has no rate sample"
            );
            let sample_bps = (u128::from(report.received_bytes) * 8 * 1_000_000
                / interval.as_micros())
            .min(u128::from(u64::MAX)) as u64;
            pending.remove(&report.probe_id);
            let now = Instant::now();
            estimates
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .get_or_insert(state.request.route, now)
                .observe_active(
                    sample_bps,
                    state
                        .route_rtt
                        .unwrap_or_else(|| now.saturating_duration_since(state.started_at)),
                    report.loss_ppm,
                    now,
                );
            scheduler.active_succeeded(state.request, now);
        }
    }
    Ok(())
}

async fn refresh_capacity_routes(
    config: &Config,
    local_id: EndpointId,
    peers: &Arc<RwLock<HashMap<EndpointId, Arc<Peer>>>>,
    mesh: Option<&Arc<MeshRuntime>>,
    estimates: &Arc<StdRwLock<RouteEstimateTable>>,
    scheduler: &mut ActiveProbeScheduler,
    now: Instant,
) {
    let inventory = peers.read().await.values().cloned().collect::<Vec<_>>();
    let mut owners = config
        .route_origins
        .iter()
        .map(|origin| origin.endpoint_id)
        .filter(|owner| *owner != local_id)
        .collect::<HashSet<_>>();
    if let Some(mesh) = mesh {
        owners.extend(
            mesh.eligible_owners()
                .into_iter()
                .filter(|owner| *owner != local_id),
        );
    }

    for owner in owners {
        let direct = inventory.iter().any(|peer| {
            peer.endpoint_id == owner && peer.counters.connected.load(Ordering::Relaxed)
        });
        for peer in &inventory {
            if !peer.counters.connected.load(Ordering::Relaxed) {
                continue;
            }
            let transit = mesh
                .and_then(|mesh| mesh.transit_enabled_for(peer.endpoint_id))
                .unwrap_or(peer.declared_transit_enabled);
            if peer.endpoint_id != owner && (direct || !transit) {
                continue;
            }
            let key = RouteKey {
                destination: owner,
                first_hop: peer.endpoint_id,
            };
            if !scheduler.register(key, now) {
                continue;
            }
            let epoch = peer.path_epoch.load(Ordering::Relaxed);
            let mut table = estimates
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let estimate = table.get_or_insert(key, now);
            if estimate.path_epoch != epoch {
                estimate.invalidate_for_path_change(epoch, now);
                scheduler.invalidate(key, now);
            }
            let metrics = peer
                .link_estimator
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .snapshot();
            if !metrics.rtt.is_zero() {
                estimate.observe_health(
                    metrics.rtt,
                    metrics.loss_ppm,
                    peer.counters.queue_bytes.load(Ordering::Relaxed),
                    now,
                );
            }
        }
    }
    estimates
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .prune_expired(now);
}

async fn capacity_forward_peer(
    destination: EndpointId,
    previous: Option<EndpointId>,
    peers: &Arc<RwLock<HashMap<EndpointId, Arc<Peer>>>>,
    mesh: Option<&Arc<MeshRuntime>>,
) -> Option<EndpointId> {
    let inventory = peers.read().await.values().cloned().collect::<Vec<_>>();
    if inventory.iter().any(|peer| {
        peer.endpoint_id == destination
            && previous != Some(peer.endpoint_id)
            && peer.counters.connected.load(Ordering::Relaxed)
    }) {
        return Some(destination);
    }
    let mut candidates = Vec::new();
    for peer in inventory {
        if previous == Some(peer.endpoint_id) || !peer.counters.connected.load(Ordering::Relaxed) {
            continue;
        }
        let transit = mesh
            .and_then(|mesh| mesh.transit_enabled_for(peer.endpoint_id))
            .unwrap_or(peer.declared_transit_enabled);
        if transit {
            candidates.push((
                peer.counters.path_rtt_micros.load(Ordering::Relaxed),
                peer.endpoint_id,
            ));
        }
    }
    candidates.into_iter().min().map(|(_, endpoint)| endpoint)
}

async fn send_capacity_message(
    peers: &Arc<RwLock<HashMap<EndpointId, Arc<Peer>>>>,
    next_hop: EndpointId,
    message: CapacityProbeMessage,
    probe_priority: bool,
) -> bool {
    let Ok(datagram) = encode_probe(&message) else {
        return false;
    };
    let Some(peer) = peers.read().await.get(&next_hop).cloned() else {
        return false;
    };
    if !peer.counters.connected.load(Ordering::Relaxed) {
        return false;
    }
    if probe_priority {
        peer.outbound.push_probe(datagram)
    } else {
        peer.outbound.push_control(datagram)
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_delivery_message(
    local_id: EndpointId,
    from: EndpointId,
    message: DeliveryMessage,
    peers: &Arc<RwLock<HashMap<EndpointId, Arc<Peer>>>>,
    estimates: &Arc<StdRwLock<RouteEstimateTable>>,
    delivery: &Arc<StdMutex<DeliveryCoordinator>>,
    delivery_fast: &Arc<DeliveryFastPath>,
    scheduler: &mut ActiveProbeScheduler,
) -> Result<()> {
    let now = Instant::now();
    match message {
        DeliveryMessage::Register(registration) => {
            ensure!(
                reverse_next_hop(&registration.forward_hops, local_id) == Some(from),
                "delivery registration arrived outside its fixed route"
            );
            delivery
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .install_forwarding(registration.clone(), local_id, now)?;
            delivery_fast.install_forwarding(registration.clone());
            if registration.destination != local_id {
                let next = forward_next_hop(&registration.forward_hops, local_id)
                    .context("delivery registration has no forward hop")?;
                ensure!(
                    send_delivery_message(peers, next, DeliveryMessage::Register(registration),)
                        .await,
                    "delivery registration next hop is unavailable"
                );
            }
        }
        DeliveryMessage::Report(report) => {
            let registration = delivery_fast
                .session_registration(report.session_id)
                .context("unknown delivery report session")?;
            ensure!(
                registration.origin == report.origin,
                "delivery report origin does not match its session"
            );
            let hops = registration.forward_hops;
            ensure!(
                forward_next_hop(&hops, local_id) == Some(from),
                "delivery report arrived outside its fixed reverse route"
            );
            if report.origin == local_id {
                let queue_nonempty_since =
                    delivery_fast.source_queue_nonempty_since(report.session_id);
                let observation = {
                    let mut coordinator = delivery
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    coordinator.source.observe_queue_since(
                        report.session_id,
                        queue_nonempty_since,
                        now,
                    );
                    coordinator
                        .apply_report(&report, now)
                        .context("delivery report does not match the active source route")?
                };
                let accepted = estimates
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get_or_insert(observation.route, now)
                    .observe_passive(
                        observation.delivered_bytes,
                        observation.receiver_interval,
                        observation.app_limited,
                        now,
                    );
                if accepted {
                    scheduler.observe_passive(observation.route, now);
                }
            } else {
                let previous = reverse_next_hop(&hops, local_id)
                    .context("delivery report has no reverse hop")?;
                ensure!(
                    send_delivery_message(peers, previous, DeliveryMessage::Report(report)).await,
                    "delivery report reverse hop is unavailable"
                );
            }
        }
    }
    Ok(())
}

async fn handle_delivery_report(
    local_id: EndpointId,
    report: DeliveryReport,
    peers: &Arc<RwLock<HashMap<EndpointId, Arc<Peer>>>>,
    delivery_fast: &Arc<DeliveryFastPath>,
) -> Result<()> {
    let registration = delivery_fast
        .session_registration(report.session_id)
        .context("delivered packet has no registered route")?;
    ensure!(
        registration.origin == report.origin,
        "delivered packet origin does not match its session"
    );
    let hops = registration.forward_hops;
    ensure!(
        hops.last() == Some(&local_id),
        "delivery session does not terminate locally"
    );
    let previous =
        reverse_next_hop(&hops, local_id).context("delivery report has no reverse hop")?;
    ensure!(
        send_delivery_message(peers, previous, DeliveryMessage::Report(report)).await,
        "delivery report reverse hop is unavailable"
    );
    Ok(())
}

async fn send_delivery_message(
    peers: &Arc<RwLock<HashMap<EndpointId, Arc<Peer>>>>,
    next_hop: EndpointId,
    message: DeliveryMessage,
) -> bool {
    let Some(peer) = peers.read().await.get(&next_hop).cloned() else {
        return false;
    };
    if !peer.counters.connected.load(Ordering::Relaxed) {
        return false;
    }
    queue_delivery_message(&peer, message).await
}

async fn queue_delivery_message(peer: &Peer, message: DeliveryMessage) -> bool {
    let register = matches!(&message, DeliveryMessage::Register(_));
    let report = matches!(&message, DeliveryMessage::Report(_));
    let Ok(datagram) = encode_delivery(&message) else {
        return false;
    };
    let bytes = datagram.len() as u64;
    if !peer.outbound.push_control(datagram) {
        return false;
    }
    if register {
        peer.counters
            .delivery_registers_sent
            .fetch_add(1, Ordering::Relaxed);
    }
    if report {
        peer.counters
            .delivery_reports_sent
            .fetch_add(1, Ordering::Relaxed);
    }
    peer.counters
        .delivery_control_bytes
        .fetch_add(bytes, Ordering::Relaxed);
    true
}

/// Reduce topology inventory to usable single-next-hop routes. A direct
/// owner suppresses transit alternatives only while that adjacency is live
/// and healthy. A degraded direct route remains eligible but no longer hides
/// transit alternatives.
/// Capacity is directional and comes only from the locally measured complete
/// route `(destination owner, first hop)`.
#[cfg(test)]
fn route_candidates(
    owner: Option<EndpointId>,
    previous_peer: Option<EndpointId>,
    adjacencies: &[AdjacencyRouteInput],
    estimates: &RouteEstimateTable,
    max_egress_bps: Option<u64>,
    now: Instant,
) -> Vec<RouteChoice> {
    let mut choices = Vec::with_capacity(adjacencies.len());
    fill_route_candidates(
        &mut choices,
        owner,
        previous_peer,
        adjacencies,
        estimates,
        max_egress_bps,
        now,
    );
    choices
}

fn snapshot_route_capacity(
    snapshot: &DataPlaneRouteSnapshot,
    key: RouteKey,
    now: Instant,
) -> CapacitySnapshot {
    snapshot.capacities.get(&key).copied().unwrap_or_else(|| {
        crate::capacity::RouteEstimate::new(now).snapshot(now, snapshot.max_egress_bps)
    })
}

fn fill_route_candidates_from_snapshot(
    choices: &mut Vec<RouteChoice>,
    owner: Option<EndpointId>,
    previous_peer: Option<EndpointId>,
    adjacencies: &[AdjacencyRouteInput],
    snapshot: &DataPlaneRouteSnapshot,
    now: Instant,
) {
    choices.clear();
    let Some(owner) = owner else {
        return;
    };
    let direct_owner_active = previous_peer != Some(owner)
        && adjacencies.iter().any(|link| {
            if link.endpoint_id != owner || !link.connected {
                return false;
            }
            let capacity = snapshot_route_capacity(
                snapshot,
                RouteKey {
                    destination: owner,
                    first_hop: owner,
                },
                now,
            );
            link.metrics.loss_ppm < DIRECT_OWNER_MAX_LOSS_PPM
                && capacity.health_per_mille >= DIRECT_OWNER_MIN_HEALTH_PER_MILLE
        });

    choices.reserve(adjacencies.len().saturating_sub(choices.capacity()));
    for (adjacency_index, link) in adjacencies.iter().enumerate() {
        if !link.connected || previous_peer == Some(link.endpoint_id) {
            continue;
        }
        let direct_owner = owner == link.endpoint_id;
        if !direct_owner && (direct_owner_active || !link.transit_enabled) {
            continue;
        }
        let capacity = snapshot_route_capacity(
            snapshot,
            RouteKey {
                destination: owner,
                first_hop: link.endpoint_id,
            },
            now,
        );
        choices.push(RouteChoice {
            endpoint_id: link.endpoint_id,
            adjacency_index,
            candidate: RouteCandidate {
                id: link.route_id,
                startup_latency: capacity
                    .rtt_ewma
                    .unwrap_or_else(|| link.metrics.startup_latency()),
                capacity_bps: capacity.effective_capacity_bps,
                queued_bytes: link.queued_bytes,
                loss_penalty: link.metrics.loss_penalty(),
            },
            capacity,
        });
    }
}

#[cfg(test)]
fn fill_route_candidates(
    choices: &mut Vec<RouteChoice>,
    owner: Option<EndpointId>,
    previous_peer: Option<EndpointId>,
    adjacencies: &[AdjacencyRouteInput],
    estimates: &RouteEstimateTable,
    max_egress_bps: Option<u64>,
    now: Instant,
) {
    choices.clear();
    let Some(owner) = owner else {
        return;
    };
    let direct_owner_active = previous_peer != Some(owner)
        && adjacencies.iter().any(|link| {
            if link.endpoint_id != owner || !link.connected {
                return false;
            }
            let capacity = estimates.snapshot_or_bootstrap(
                &RouteKey {
                    destination: owner,
                    first_hop: owner,
                },
                now,
                max_egress_bps,
            );
            link.metrics.loss_ppm < DIRECT_OWNER_MAX_LOSS_PPM
                && capacity.health_per_mille >= DIRECT_OWNER_MIN_HEALTH_PER_MILLE
        });

    choices.reserve(adjacencies.len().saturating_sub(choices.capacity()));
    for (adjacency_index, link) in adjacencies.iter().enumerate() {
        if !link.connected || previous_peer == Some(link.endpoint_id) {
            continue;
        }
        let direct_owner = owner == link.endpoint_id;
        if !direct_owner && (direct_owner_active || !link.transit_enabled) {
            continue;
        }
        let snapshot = estimates.snapshot_or_bootstrap(
            &RouteKey {
                destination: owner,
                first_hop: link.endpoint_id,
            },
            now,
            max_egress_bps,
        );
        choices.push(RouteChoice {
            endpoint_id: link.endpoint_id,
            adjacency_index,
            candidate: RouteCandidate {
                id: link.route_id,
                startup_latency: snapshot
                    .rtt_ewma
                    .unwrap_or_else(|| link.metrics.startup_latency()),
                capacity_bps: snapshot.effective_capacity_bps,
                queued_bytes: link.queued_bytes,
                loss_penalty: link.metrics.loss_penalty(),
            },
            capacity: snapshot,
        });
    }
}

async fn maintain_presence_routes(config: Config, mesh: Arc<MeshRuntime>) -> Result<()> {
    let mut previous = HashSet::new();
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        let mut current = config.all_remote_prefixes().collect::<HashSet<_>>();
        current.extend(mesh.remote_prefixes());
        if current == previous {
            continue;
        }
        if let Err(error) = sync_overlay_routes(&config, current.iter().copied()).await {
            warn!(%error, "failed reconciling Presence-driven FlowRouter routes");
            continue;
        }
        previous = current;
    }
}

fn route_id(endpoint_id: EndpointId) -> RouteId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ironet-flow-route-v1\0");
    hasher.update(endpoint_id.as_bytes());
    let bytes = hasher.finalize();
    RouteId(u64::from_be_bytes(
        bytes.as_bytes()[..8].try_into().unwrap(),
    ))
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("failed installing SIGTERM handler")?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.context("failed waiting for SIGINT"),
            signal = terminate.recv() => {
                signal.context("SIGTERM handler stopped unexpectedly")?;
                Ok(())
            }
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c()
        .await
        .context("failed waiting for shutdown signal")
}

fn build_derp_transport(config: &Config) -> Result<Option<Arc<DerpTransport>>> {
    if !config.relay.derp_enabled() {
        return Ok(None);
    }
    let identity_path = config.derp_identity_file();
    let identity = load_or_create(&identity_path)?;
    let public_key = identity.public_key();
    let servers = config.derp_servers()?;
    let allowed_peers = config
        .peers
        .iter()
        .filter_map(|peer| peer.derp_public_key)
        .collect();
    info!(%public_key, identity_file = %identity_path.display(), regions = servers.len(), "DERP transport configured");
    Ok(Some(DerpTransport::new(
        identity,
        servers,
        allowed_peers,
        tls_config()?,
    )))
}

fn underlay_exclusion_prefixes(config: &Config) -> Vec<IpNet> {
    config
        .forbidden_underlay_prefixes
        .iter()
        .copied()
        .chain(config.all_overlay_prefixes())
        .collect()
}

fn underlay_publish_exclusion_prefixes(config: &Config) -> Vec<IpNet> {
    underlay_exclusion_prefixes(config)
        .into_iter()
        .chain(config.private_locator_prefixes())
        .collect()
}

async fn build_endpoint(
    config: &Config,
    secret_key: SecretKey,
    alpn: &[u8],
    probe_alpn: &[u8],
    derp_transport: Option<Arc<DerpTransport>>,
) -> Result<Endpoint> {
    let configured_relays = config.inherited_peer_relays()?;
    let relay_mode = iroh_relay_mode(config, configured_relays);
    // Keep CUBIC's MTU-scaled initial window until a path has a measured BDP.
    // A fixed 512 KiB startup burst represents more than four seconds of data
    // on a 1 Mbit/s WAN and makes loss recovery dominate initial convergence.
    // noq's BBR3 currently leaves a long-lived, low-RTT QUIC path at a reduced
    // window after a short UDP loss burst; repeated saturation then decays even
    // though the underlay has recovered. CUBIC recovered between runs in the
    // same profile and raised stable throughput without enlarging startup.
    let cubic = CubicConfig::default();
    let path_idle_timeout = quic_path_idle_timeout(&config.relay);
    let transport = QuicTransportConfig::builder()
        .congestion_controller_factory(Arc::new(cubic))
        .initial_rtt(Duration::from_millis(100))
        // noq's periodic DPLPMTUD probe currently tears down the only direct
        // path on some symmetric-NAT/GSO combinations. Start at the proven
        // 1400-byte UDP payload instead and keep black-hole detection active;
        // noq will still fall back to 1200 when the live path requires it.
        .initial_mtu(1_400)
        .mtu_discovery_config(None)
        // A five-second heartbeat leaves only three attempts before iroh's
        // fixed 15-second per-path idle guard fires. Symmetric and carrier NAT
        // paths can lose several consecutive small UDP packets while rotating
        // mappings, so use one-second connection and per-path heartbeats.
        .keep_alive_interval(Duration::from_secs(1))
        .default_path_keep_alive_interval(Duration::from_secs(1))
        .default_path_max_idle_timeout(path_idle_timeout)
        // Several cloud/NAT virtual NICs accept UDP_SEGMENT at socket setup
        // but return EIO on the first real GSO batch. noq then disables GSO,
        // yet the loss burst can close the only direct path. Userspace batching
        // plus the large virtual TUN MTU keep
        // syscall cost low without that WAN-visible one-time outage.
        .enable_segmentation_offload(config.udp_segmentation_offload)
        .datagram_send_buffer_size(QUIC_SEND_BUFFER_BYTES)
        .datagram_receive_buffer_size(Some(QUIC_RECEIVE_BUFFER_BYTES))
        // Peer-observed socket addresses are endpoint-wide and can therefore
        // be the address of our own overlay TUN on a multi-homed router. That
        // creates recursive "direct" paths which work briefly and then
        // black-hole. Net-report discovery plus the filtered address lookup
        // below still advertise safe host/NAT candidates; keep the unfiltered
        // peer-observation extension off in every mode.
        .send_observed_address_reports(false)
        .receive_observed_address_reports(false)
        .build();
    let path_exclusions = underlay_exclusion_prefixes(config);
    let hidden_prefixes = Arc::new(underlay_publish_exclusion_prefixes(config));
    let path_selector = WanPathSelector::new(path_exclusions, config.path_selection.prefer);
    let address_filter = if config.discovery_enabled {
        AddrFilter::new(move |addresses| {
            Cow::Owned(
                addresses
                    .iter()
                    .filter(|address| publishable_address(address, &hidden_prefixes))
                    .cloned()
                    .collect(),
            )
        })
    } else {
        AddrFilter::relay_only()
    };
    let alpns = if config.mesh.enabled {
        vec![alpn.to_vec(), probe_alpn.to_vec()]
    } else {
        vec![alpn.to_vec()]
    };
    let mut builder = Endpoint::builder(presets::N0)
        .crypto_provider(dataplane_crypto_provider())
        .secret_key(secret_key)
        .alpns(alpns)
        .relay_mode(relay_mode)
        .path_selector(Arc::new(path_selector))
        .transport_config(transport)
        .addr_filter(address_filter);
    let bind_addresses = config.endpoint_bind_addresses().collect::<Vec<_>>();
    if !bind_addresses.is_empty() {
        builder = builder.clear_ip_transports();
        for address in bind_addresses {
            builder = builder.bind_addr(address)?;
        }
    }
    if !config.discovery_enabled {
        builder = builder.clear_address_lookup();
    }
    if let Some(transport) = derp_transport {
        builder = builder.add_custom_transport(transport);
    }
    builder.bind().await.context("failed to bind iroh endpoint")
}

/// Prefer ChaCha20 for QUIC payload protection while retaining AES-GCM for
/// QUIC initial packets and interoperability.
///
/// A peer may expose AES-NI without PCLMULQDQ (notably older/default QEMU CPU
/// models). ring then combines AES assembly with its scalar GHASH fallback;
/// production profiles showed that pair consuming roughly 30% of all sender
/// CPU and capping one direct overlay near 370 Mbit/s. rustls servers honor the
/// client's suite order by default, so every endpoint must advertise ChaCha20
/// first rather than trying to make a local CPU-only choice. On modern x86 and
/// ARM, ring's vectorized ChaCha20 remains comfortably above the WAN rates this
/// dataplane targets.
fn dataplane_crypto_provider() -> Arc<CryptoProvider> {
    let mut provider = rustls::crypto::ring::default_provider();
    provider
        .cipher_suites
        .sort_by_key(|suite| match suite.suite() {
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => 0,
            CipherSuite::TLS13_AES_128_GCM_SHA256 => 1,
            CipherSuite::TLS13_AES_256_GCM_SHA384 => 2,
            _ => 3,
        });
    Arc::new(provider)
}

fn iroh_relay_mode(config: &Config, configured_relays: Vec<RelayUrl>) -> RelayMode {
    if !config.relay.iroh_relay_enabled {
        RelayMode::Disabled
    } else if configured_relays.is_empty() {
        if config.discovery_enabled {
            // Net-report needs multiple independent QAD observers to detect
            // endpoint-dependent mappings. The N0 preset also makes these
            // observers usable as relay paths when explicitly enabled.
            RelayMode::Default
        } else {
            RelayMode::Disabled
        }
    } else {
        RelayMode::custom(configured_relays)
    }
}

async fn monitor_network_discovery(
    endpoint: Endpoint,
    runtime_state: Arc<RuntimeState>,
    nat64_prefix: Arc<StdRwLock<Option<Nat64Prefix>>>,
) -> Result<()> {
    let mut address_updates = endpoint.watch_addr().stream();
    let mut report_updates = endpoint.net_report().stream();
    let mut endpoint_addr = endpoint.addr();
    let mut report = None;
    let mut refresh = tokio::time::interval(NAT64_REFRESH_INTERVAL);
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_status = None;

    loop {
        let refresh_nat64 = tokio::select! {
            update = address_updates.next() => {
                endpoint_addr = update.context("endpoint address watcher stopped")?;
                true
            }
            update = report_updates.next() => {
                report = update.context("network report watcher stopped")?;
                false
            }
            _ = refresh.tick() => true,
        };
        if refresh_nat64 {
            let detected = tokio::time::timeout(Duration::from_secs(3), detect_nat64_prefix())
                .await
                .ok()
                .flatten();
            *nat64_prefix
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = detected;
        }
        let nat64 = *nat64_prefix
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let status = network_discovery_status(&endpoint_addr, report.as_ref(), nat64);
        if last_status.as_ref() != Some(&status) {
            if status.mapping_varies_by_destination_ipv4 == Some(true)
                || status.mapping_varies_by_destination_ipv6 == Some(true)
            {
                warn!(
                    ipv4 = ?status.mapping_varies_by_destination_ipv4,
                    ipv6 = ?status.mapping_varies_by_destination_ipv6,
                    "NAT mapping varies by destination; direct UDP success may require relay or port prediction"
                );
            }
            info!(
                udp_ipv4 = status.udp_ipv4,
                udp_ipv6 = status.udp_ipv6,
                global_ipv4 = ?status.global_ipv4,
                global_ipv6 = ?status.global_ipv6,
                nat64_prefix = ?status.nat64_prefix,
                candidates = status.candidates.len(),
                "network discovery state changed"
            );
            runtime_state.update_network_discovery(status.clone());
            last_status = Some(status);
        }
    }
}

async fn detect_nat64_prefix() -> Option<Nat64Prefix> {
    let addresses = tokio::net::lookup_host(("ipv4only.arpa", 0))
        .await
        .ok()?
        .filter_map(|address| match address.ip() {
            IpAddr::V6(address) => Some(address),
            IpAddr::V4(_) => None,
        })
        .collect::<Vec<_>>();
    discover_nat64_prefix(addresses)
}

struct DynamicPeerTasks {
    peer: Arc<Peer>,
    tasks: Vec<tokio::task::JoinHandle<Result<()>>>,
    derp_public_key: Option<crate::derp::DerpPublicKey>,
    last_lost_packets: u64,
    last_tx_datagrams: u64,
    disconnected_evaluations: u8,
}

impl Drop for DynamicPeerTasks {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

struct DynamicMeshManager {
    config: Config,
    removed_nodes: HashSet<EndpointId>,
    local_id: EndpointId,
    endpoint: Endpoint,
    alpn: Arc<Vec<u8>>,
    inherited_relays: Vec<RelayUrl>,
    trace_responder: Option<Arc<TraceResponder>>,
    derp_transport: Option<Arc<DerpTransport>>,
    nat64_prefix: Arc<StdRwLock<Option<Nat64Prefix>>>,
    mesh: Arc<MeshRuntime>,
    peers: Arc<RwLock<HashMap<EndpointId, Arc<Peer>>>>,
    peer_counters: Arc<StdRwLock<HashMap<EndpointId, Arc<PeerCounters>>>>,
    inbound_packets: InboundDispatcher,
    capacity_events: mpsc::Sender<CapacityEvent>,
    planner: Mutex<MeshPlanner>,
    admission_lock: Mutex<()>,
    dynamic: Mutex<HashMap<EndpointId, DynamicPeerTasks>>,
}

impl DynamicMeshManager {
    #[allow(clippy::too_many_arguments)]
    fn new(
        config: &Config,
        local_id: EndpointId,
        endpoint: Endpoint,
        alpn: Arc<Vec<u8>>,
        inherited_relays: Vec<RelayUrl>,
        trace_responder: Option<Arc<TraceResponder>>,
        derp_transport: Option<Arc<DerpTransport>>,
        nat64_prefix: Arc<StdRwLock<Option<Nat64Prefix>>>,
        mesh: Arc<MeshRuntime>,
        peers: Arc<RwLock<HashMap<EndpointId, Arc<Peer>>>>,
        peer_counters: Arc<StdRwLock<HashMap<EndpointId, Arc<PeerCounters>>>>,
        inbound_packets: InboundDispatcher,
        capacity_events: mpsc::Sender<CapacityEvent>,
    ) -> Result<Arc<Self>> {
        let planner = MeshPlanner::new(
            config.mesh.max_peers,
            config.peers.iter().map(|peer| peer.endpoint_id),
        )?;
        Ok(Arc::new(Self {
            config: config.clone(),
            removed_nodes: crate::product::removed_node_ids(&config.identity_file),
            local_id,
            endpoint,
            alpn,
            inherited_relays,
            trace_responder,
            derp_transport,
            nat64_prefix,
            mesh,
            peers,
            peer_counters,
            inbound_packets,
            capacity_events,
            planner: Mutex::new(planner),
            admission_lock: Mutex::new(()),
            dynamic: Mutex::new(HashMap::new()),
        }))
    }

    async fn run(self: Arc<Self>) -> Result<()> {
        let mut interval = tokio::time::interval(EVALUATION_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = self.mesh.candidate_update_notified() => {}
            }
            if let Err(error) = self.evaluate().await {
                warn!(%error, "bounded mesh evaluation failed");
            }
        }
    }

    async fn evaluate(&self) -> Result<()> {
        let mut presences = self.mesh.eligible_presences().await;
        // Peer-observed NAT mappings are deliberately kept outside the
        // owner-signed Presence. Merge them only into this local planner view;
        // the original signed records remain unchanged when gossiped.
        for presence in &mut presences {
            presence.body.direct_addresses = self.mesh.direct_candidates(presence).await;
        }
        let now = Instant::now();
        let (active_observations, unhealthy_ids) = {
            let mut dynamic = self.dynamic.lock().await;
            let mut unhealthy = HashSet::new();
            let observations = dynamic
                .values_mut()
                .filter_map(|active| {
                    if active
                        .tasks
                        .iter()
                        .any(tokio::task::JoinHandle::is_finished)
                    {
                        unhealthy.insert(active.peer.endpoint_id);
                        return None;
                    }
                    if !active.peer.counters.connected.load(Ordering::Relaxed) {
                        active.disconnected_evaluations =
                            active.disconnected_evaluations.saturating_add(1);
                        if active.disconnected_evaluations >= 3 {
                            unhealthy.insert(active.peer.endpoint_id);
                        }
                        return None;
                    }
                    active.disconnected_evaluations = 0;
                    let presence = presences
                        .iter()
                        .find(|presence| presence.body.owner == active.peer.endpoint_id)?;
                    let direct_hint = presence_direct_path(presence).unwrap_or((
                        PathKind::DirectIpv4,
                        Duration::from_millis(100),
                        "qnt-direct".into(),
                    ));
                    let (path, diversity_key) = match active
                        .peer
                        .counters
                        .selected_path_transport
                        .load(Ordering::Relaxed)
                    {
                        1 => (direct_hint.0, direct_hint.2),
                        2..=4 => (PathKind::Relay, "relay".into()),
                        _ => return None,
                    };
                    let rtt = Duration::from_micros(
                        active.peer.counters.path_rtt_micros.load(Ordering::Relaxed),
                    );
                    if rtt.is_zero() {
                        return None;
                    }
                    let lost = active
                        .peer
                        .counters
                        .path_lost_packets
                        .load(Ordering::Relaxed);
                    let tx = active
                        .peer
                        .counters
                        .path_tx_datagrams
                        .load(Ordering::Relaxed);
                    let lost_delta = lost.saturating_sub(active.last_lost_packets);
                    let tx_delta = tx.saturating_sub(active.last_tx_datagrams);
                    active.last_lost_packets = lost;
                    active.last_tx_datagrams = tx;
                    let loss_ppm = lost_delta
                        .saturating_mul(1_000_000)
                        .checked_div(lost_delta.max(tx_delta).max(1))
                        .unwrap_or(0)
                        .min(1_000_000) as u32;
                    Some(ProbeObservation {
                        endpoint_id: presence.body.owner,
                        path,
                        rtt,
                        loss_ppm,
                        diversity_key,
                        transit_enabled: presence.body.transit_enabled,
                        observed_at: now,
                    })
                })
                .collect::<Vec<_>>();
            (observations, unhealthy)
        };

        let dynamic_ids = self
            .dynamic
            .lock()
            .await
            .keys()
            .copied()
            .collect::<HashSet<_>>();
        let pinned = self
            .config
            .peers
            .iter()
            .map(|peer| peer.endpoint_id)
            .collect::<HashSet<_>>();
        let mut candidates = presences
            .iter()
            .filter(|presence| !dynamic_ids.contains(&presence.body.owner))
            .filter(|presence| !pinned.contains(&presence.body.owner))
            .filter(|presence| !self.removed_nodes.contains(&presence.body.owner))
            .filter(|presence| {
                presence_path(presence, self.config.relay.iroh_relay_enabled).is_some()
            })
            .cloned()
            .collect::<Vec<_>>();
        candidates.sort_by_key(|presence| presence.body.owner);
        // Presence is the side channel: once any relay or direct locator is
        // known, create the durable connection immediately.  The formal iroh
        // connection starts on the first reachable path (normally relay) and
        // performs QNT hole punching on that same connection.  A disposable
        // direct-only QUIC probe would prevent two hard-NAT peers from ever
        // reaching the coordinated punching phase.
        let candidate_observations = candidates.iter().filter_map(|presence| {
            let (path, rtt, diversity_key) =
                presence_path(presence, self.config.relay.iroh_relay_enabled)?;
            Some(ProbeObservation {
                endpoint_id: presence.body.owner,
                path,
                rtt,
                loss_ppm: 0,
                diversity_key,
                transit_enabled: presence.body.transit_enabled,
                observed_at: now,
            })
        });

        let mut planner = self.planner.lock().await;
        for observation in active_observations
            .into_iter()
            .chain(candidate_observations)
        {
            planner.observe(observation);
        }
        let eligible = presences
            .iter()
            .filter(|presence| !unhealthy_ids.contains(&presence.body.owner))
            .filter(|presence| !self.removed_nodes.contains(&presence.body.owner))
            // Only the lower EndpointId initiates the canonical connection.
            // The other side creates its bounded adjacency in accept_unknown.
            .filter(|presence| {
                self.local_id < presence.body.owner || dynamic_ids.contains(&presence.body.owner)
            })
            .filter(|presence| {
                presence_path(presence, self.config.relay.iroh_relay_enabled).is_some()
            })
            .map(|presence| presence.body.owner)
            .collect::<Vec<_>>();
        let decision = planner.evaluate(eligible, now);
        drop(planner);

        for endpoint_id in decision.drain {
            self.remove_dynamic(endpoint_id).await;
        }
        for endpoint_id in decision.activate {
            let Some(presence) = presences
                .iter()
                .find(|presence| presence.body.owner == endpoint_id)
            else {
                continue;
            };
            let _admission = self.admission_lock.lock().await;
            if let Err(error) = self.create_dynamic(presence.clone(), None, None).await {
                self.planner.lock().await.activation_failed(endpoint_id);
                warn!(%endpoint_id, %error, "failed activating dynamic mesh peer");
            } else {
                info!(%endpoint_id, reason = decision.reason.unwrap_or("planner decision"), "activated bounded dynamic mesh peer");
            }
        }
        Ok(())
    }

    async fn accept_unknown(&self, connection: Connection) -> Result<()> {
        let endpoint_id = connection.remote_id();
        ensure!(
            !self.removed_nodes.contains(&endpoint_id),
            "node membership has been removed"
        );
        let session = negotiate_connection(
            &connection,
            &SessionPolicy {
                network_id: self.config.network_id.clone(),
                local_id: self.local_id,
                remote_id: endpoint_id,
                max_datagram_size: u32::from(self.config.max_frame_size),
                max_control_size: 32 * 1024,
                features: feature::core_offers(
                    self.config.routing.transit_enabled,
                    self.config.fec.enabled,
                    self.config.mesh.enabled,
                    false,
                ),
                link: None,
                local_invite_id: crate::product::local_invite_id(&self.config.identity_file),
                authority_invites: crate::product::authority_invites(&self.config.identity_file),
            },
        )
        .await
        .context("dynamic peer V1 admission handshake failed")?;
        if let Some(address) = connection.paths().iter().find_map(|path| {
            if let TransportAddr::Ip(address) = path.remote_addr() {
                Some(*address)
            } else {
                None
            }
        }) {
            self.mesh
                .add_connection_observation(endpoint_id, address)
                .await;
        }
        let presence = match self.mesh.presence(endpoint_id).await {
            Some(presence) => presence,
            None => {
                self.mesh
                    .admit_connection_presence(&connection, endpoint_id)
                    .await?
            }
        };
        let mut presence = presence;
        presence.body.direct_addresses = self.mesh.direct_candidates(&presence).await;
        ensure!(
            presence_path(&presence, self.config.relay.iroh_relay_enabled).is_some(),
            "dynamic endpoint has no usable direct, DERP or enabled iroh relay candidate"
        );
        let _admission = self.admission_lock.lock().await;
        ensure!(
            self.peers.read().await.len() < self.config.mesh.max_peers,
            "bounded mesh peer limit reached"
        );
        self.create_dynamic(presence, Some(connection), Some(session))
            .await?;
        self.planner
            .lock()
            .await
            .admit_inbound(endpoint_id, Instant::now());
        info!(%endpoint_id, "accepted bounded inbound dynamic mesh peer");
        Ok(())
    }

    async fn create_dynamic(
        &self,
        presence: SignedPresence,
        connection: Option<Connection>,
        negotiated: Option<NegotiatedSession>,
    ) -> Result<()> {
        let endpoint_id = presence.body.owner;
        ensure!(
            !self.removed_nodes.contains(&endpoint_id),
            "node membership has been removed"
        );
        if let Some(peer) = self.peers.read().await.get(&endpoint_id).cloned() {
            if let Some(connection) = connection {
                peer.install_connection_with_session(connection, negotiated)
                    .await?;
            }
            return Ok(());
        }
        ensure!(
            self.peers.read().await.len() < self.config.mesh.max_peers,
            "bounded mesh peer limit reached"
        );
        let peer_config = presence_peer_config(&presence, self.config.relay.iroh_relay_enabled);
        let connection_mode = if connection.is_some() {
            ConnectionMode::Inbound
        } else {
            ConnectionMode::Outbound
        };
        if let (Some(transport), Some(key)) = (&self.derp_transport, peer_config.derp_public_key) {
            transport.allow_peer(key);
        }
        let peer = Arc::new(Peer::create_with_mode(
            &self.config,
            &peer_config,
            self.local_id,
            self.endpoint.clone(),
            self.alpn.clone(),
            PeerServices {
                inherited_relays: &self.inherited_relays,
                trace_responder: self.trace_responder.clone(),
                derp_transport: self.derp_transport.as_ref(),
                mesh_runtime: Some(self.mesh.clone()),
                nat64_prefix: self.nat64_prefix.clone(),
                inbound_packets: self.inbound_packets.clone(),
                capacity_events: self.capacity_events.clone(),
            },
            connection_mode,
        )?);
        let tasks = vec![
            tokio::spawn(peer.clone().queue_to_network()),
            tokio::spawn(peer.clone().maintain_connection()),
        ];
        self.peers.write().await.insert(endpoint_id, peer.clone());
        self.peer_counters
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(endpoint_id, peer.counters.clone());
        self.dynamic.lock().await.insert(
            endpoint_id,
            DynamicPeerTasks {
                peer: peer.clone(),
                tasks,
                derp_public_key: peer_config.derp_public_key,
                last_lost_packets: 0,
                last_tx_datagrams: 0,
                disconnected_evaluations: 0,
            },
        );
        if let Some(connection) = connection
            && let Err(error) = peer
                .install_connection_with_session(connection, negotiated)
                .await
        {
            self.remove_dynamic(endpoint_id).await;
            return Err(error);
        }
        Ok(())
    }

    async fn remove_dynamic(&self, endpoint_id: EndpointId) {
        let handle = self.dynamic.lock().await.remove(&endpoint_id);
        self.peers.write().await.remove(&endpoint_id);
        self.peer_counters
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&endpoint_id);
        if let Some(handle) = handle {
            handle.peer.close().await;
            if let (Some(transport), Some(key)) = (&self.derp_transport, handle.derp_public_key) {
                transport.remove_peer(key);
            }
            info!(%endpoint_id, "drained dynamic mesh peer");
        }
    }
}

fn presence_peer_config(presence: &SignedPresence, allow_iroh_relay: bool) -> PeerConfig {
    PeerConfig {
        name: presence
            .body
            .node_info
            .as_ref()
            .map(|info| info.name.clone())
            .unwrap_or_else(|| format!("mesh-{}", presence.body.owner.fmt_short())),
        endpoint_id: presence.body.owner,
        transit_enabled: presence.body.transit_enabled,
        direct_addresses: presence.body.direct_addresses.clone(),
        relay_urls: if allow_iroh_relay {
            presence.body.relay_urls.clone()
        } else {
            Vec::new()
        },
        derp_public_key: presence.body.derp_public_key,
        allowed_source_prefixes: presence.body.prefixes.clone(),
    }
}

fn presence_path(
    presence: &SignedPresence,
    allow_iroh_relay: bool,
) -> Option<(PathKind, Duration, String)> {
    if let Some(direct) = presence_direct_path(presence) {
        return Some(direct);
    }
    ((allow_iroh_relay && !presence.body.relay_urls.is_empty())
        || presence.body.derp_public_key.is_some())
    .then(|| {
        (
            PathKind::Relay,
            Duration::from_millis(400),
            presence
                .body
                .relay_urls
                .first()
                .filter(|_| allow_iroh_relay)
                .cloned()
                .unwrap_or_else(|| "derp".into()),
        )
    })
}

fn presence_direct_path(presence: &SignedPresence) -> Option<(PathKind, Duration, String)> {
    if let Some(address) = presence
        .body
        .direct_addresses
        .iter()
        .find(|address| address.is_ipv6())
    {
        return Some((
            PathKind::DirectIpv6,
            Duration::from_millis(80),
            diversity_key(*address),
        ));
    }
    presence
        .body
        .direct_addresses
        .first()
        .copied()
        .map(|address| {
            (
                PathKind::DirectIpv4,
                Duration::from_millis(100),
                diversity_key(address),
            )
        })
}

fn diversity_key(address: std::net::SocketAddr) -> String {
    match address.ip() {
        std::net::IpAddr::V4(ip) => {
            let octets = ip.octets();
            format!("v4-{}.{}.{}", octets[0], octets[1], octets[2])
        }
        std::net::IpAddr::V6(ip) => {
            let segments = ip.segments();
            format!(
                "v6-{:#x}:{:#x}:{:#x}",
                segments[0], segments[1], segments[2]
            )
        }
    }
}

struct Peer {
    name: String,
    endpoint_id: EndpointId,
    route_id: RouteId,
    declared_transit_enabled: bool,
    endpoint_addr: EndpointAddr,
    endpoint: Endpoint,
    alpn: Arc<Vec<u8>>,
    session_policy: SessionPolicy,
    inbound_packets: InboundDispatcher,
    capacity_events: mpsc::Sender<CapacityEvent>,
    connection: ArcSwapOption<Connection>,
    connection_updates: tokio::sync::watch::Sender<u64>,
    /// Serializes rare install/clear transitions. Packet transmission reads
    /// the active Arc through ArcSwap without a mutex or watch-channel guard.
    connection_update: StdMutex<()>,
    /// Cancellation scope for every task belonging to the published
    /// connection generation. Replacing the ArcSwap value retires the old
    /// generation synchronously instead of waiting for each watcher to notice.
    connection_tasks: StdMutex<ConnectionTaskGeneration>,
    dial_lock: Mutex<()>,
    reconnect_needed: Notify,
    shutdown_ready: Notify,
    shutting_down: AtomicBool,
    refresh_requested: AtomicBool,
    relay_bootstrap_started: AtomicBool,
    discovered_direct_addresses: Mutex<HashSet<std::net::SocketAddr>>,
    dial_outbound: bool,
    connection_mode: ConnectionMode,
    relay_bootstrap_enabled: bool,
    candidate_exchange_enabled: bool,
    trace_responder: Option<Arc<TraceResponder>>,
    enforce_overlay_prefixes: bool,
    transit_enabled: bool,
    allowed_source_prefixes: Arc<IpPrefixSet>,
    forbidden_underlay_prefixes: Arc<Vec<IpNet>>,
    allowed_local_underlay_prefixes: Arc<Vec<IpNet>>,
    allowed_remote_underlay_prefixes: Arc<Vec<IpNet>>,
    private_remote_addresses: Arc<Vec<std::net::SocketAddr>>,
    private_link_exclusive: bool,
    next_packet_id: AtomicU64,
    buffer_budget: Arc<BufferBudget>,
    repair_cache: StdMutex<RepairCache>,
    reassembly_buffer_limit: usize,
    repair_buffer_limit: usize,
    outbound: Arc<OutboundQueue>,
    counters: Arc<PeerCounters>,
    link_estimator: StdRwLock<LinkEstimator>,
    path_epoch: AtomicU64,
    selected_path_fingerprint: StdRwLock<String>,
    frame_size_ceiling: usize,
    effective_frame_size: AtomicU64,
    /// Taken once by `queue_to_network`; encoder mutation is single-writer.
    fec_encoder: StdMutex<Option<FecEncoder>>,
    fec_reset_epoch: AtomicU64,
    fec_decoder_ttl: Duration,
    fec_buffer_limit: usize,
    derp_transport: Option<Arc<DerpTransport>>,
    mesh_runtime: Option<Arc<MeshRuntime>>,
    nat64_prefix: Arc<StdRwLock<Option<Nat64Prefix>>>,
}

#[derive(Debug, Default)]
struct ConnectionTaskGeneration {
    active: Option<(usize, CancellationToken)>,
}

impl ConnectionTaskGeneration {
    fn replace(&mut self, stable_id: usize) -> CancellationToken {
        if let Some((_, previous)) = self.active.take() {
            previous.cancel();
        }
        let cancel = CancellationToken::new();
        self.active = Some((stable_id, cancel.clone()));
        cancel
    }

    fn cancel(&mut self, stable_id: Option<usize>) -> bool {
        let matches = self
            .active
            .as_ref()
            .is_some_and(|(active, _)| stable_id.is_none_or(|expected| *active == expected));
        if !matches {
            return false;
        }
        if let Some((_, cancel)) = self.active.take() {
            cancel.cancel();
        }
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionMode {
    /// Prefer the EndpointId-derived direction, but dial after a short wait so
    /// adding a bootstrap peer works without a reciprocal peer entry.
    Canonical,
    /// Planner-selected side of a dynamic adjacency.
    Outbound,
    /// Dynamically admitted side; the remote owns reconnection.
    Inbound,
}

struct PeerServices<'a> {
    inherited_relays: &'a [RelayUrl],
    trace_responder: Option<Arc<TraceResponder>>,
    derp_transport: Option<&'a Arc<DerpTransport>>,
    mesh_runtime: Option<Arc<MeshRuntime>>,
    nat64_prefix: Arc<StdRwLock<Option<Nat64Prefix>>>,
    inbound_packets: InboundDispatcher,
    capacity_events: mpsc::Sender<CapacityEvent>,
}

impl Peer {
    fn can_dial(&self) -> bool {
        self.connection_mode != ConnectionMode::Inbound
    }

    fn current_connection(&self) -> Option<Connection> {
        self.connection
            .load_full()
            .map(|connection| connection.as_ref().clone())
    }

    fn create(
        config: &Config,
        peer: &PeerConfig,
        local_id: EndpointId,
        endpoint: Endpoint,
        alpn: Arc<Vec<u8>>,
        services: PeerServices<'_>,
    ) -> Result<Self> {
        Self::create_with_mode(
            config,
            peer,
            local_id,
            endpoint,
            alpn,
            services,
            ConnectionMode::Canonical,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn create_with_mode(
        config: &Config,
        peer: &PeerConfig,
        local_id: EndpointId,
        endpoint: Endpoint,
        alpn: Arc<Vec<u8>>,
        services: PeerServices<'_>,
        connection_mode: ConnectionMode,
    ) -> Result<Self> {
        let dial_outbound = local_id < peer.endpoint_id;
        let link = config.link_for_peer(peer.endpoint_id);
        let connection_mode = match link.map(|link| link.dial) {
            Some(DialRole::Active) => ConnectionMode::Outbound,
            Some(DialRole::Passive) => ConnectionMode::Inbound,
            _ => connection_mode,
        };

        let mut endpoint_addr = EndpointAddr::new(peer.endpoint_id);
        let configured_addresses = link.map_or(peer.direct_addresses.as_slice(), |link| {
            link.remote_addresses.as_slice()
        });
        for addr in configured_addresses {
            endpoint_addr = endpoint_addr.with_ip_addr(*addr);
        }
        if link.is_some() {
            // A pairwise locator contract is deliberately not augmented with
            // endpoint discovery, relay or DERP addresses.
        } else if peer.relay_urls.is_empty() {
            for relay in services.inherited_relays {
                endpoint_addr = endpoint_addr.with_relay_url(relay.clone());
            }
        } else {
            for relay in &peer.relay_urls {
                endpoint_addr = endpoint_addr.with_relay_url(relay.parse()?);
            }
        }
        if link.is_none()
            && let (Some(transport), Some(public_key)) =
                (services.derp_transport, peer.derp_public_key)
        {
            endpoint_addr = endpoint_addr.with_addrs(
                transport
                    .remote_addresses(public_key)
                    .into_iter()
                    .map(TransportAddr::Custom),
            );
        }

        let counters = Arc::new(PeerCounters::new(
            peer.name.clone(),
            peer.endpoint_id,
            if config.attachment == AttachmentMode::Tun {
                config.node_interface.clone()
            } else {
                "none".into()
            },
        ));
        let frame_size_ceiling = usize::from(config.max_frame_size);
        let effective_frame_size = frame_size_ceiling.min(1_200);
        let fec_encoder = config
            .fec
            .enabled
            .then(|| {
                FecEncoder::new(
                    usize::from(config.fec.data_shards),
                    usize::from(config.fec.recovery_shards),
                    Duration::from_millis(config.fec.block_timeout_millis),
                )
            })
            .transpose()?;
        counters
            .effective_frame_size
            .store(effective_frame_size as u64, Ordering::Relaxed);
        counters
            .tun_mtu
            .store(u64::from(config.tun_mtu), Ordering::Relaxed);
        let mesh_pool_per_peer = config
            .mesh
            .enabled
            .then(|| PROCESS_PAYLOAD_BUDGET_BYTES / config.mesh.max_peers.max(1));
        // One process-wide payload budget is shared by queue/reassembly/repair/FEC.
        // Mesh-off peers keep the 8 MiB BDP queue default instead of stacking
        // independent 32/16/32 MiB tables.
        let buffer_budget = BufferBudget::process_wide();
        let outbound = Arc::new(if let Some(per_peer) = mesh_pool_per_peer {
            OutboundQueue::with_max_bytes_and_budget(
                counters.clone(),
                DEFAULT_QUEUE_BYTES.min(per_peer).min(OUTBOUND_QUEUE_BYTES),
                Some(buffer_budget.clone()),
            )
        } else {
            OutboundQueue::with_max_bytes_and_budget(
                counters.clone(),
                DEFAULT_QUEUE_BYTES,
                Some(buffer_budget.clone()),
            )
        });
        let reassembly_buffer_limit = mesh_pool_per_peer
            .map_or(DEFAULT_REASSEMBLY_BYTES, |limit| {
                limit.min(DEFAULT_REASSEMBLY_BYTES)
            });
        let repair_buffer_limit = mesh_pool_per_peer.map_or(DEFAULT_REPAIR_BYTES, |limit| {
            limit.min(DEFAULT_REPAIR_BYTES)
        });
        let fec_buffer_limit = mesh_pool_per_peer.map_or(DEFAULT_FEC_DECODE_BYTES, |limit| {
            limit.min(DEFAULT_FEC_DECODE_BYTES)
        });
        Ok(Self {
            name: peer.name.clone(),
            endpoint_id: peer.endpoint_id,
            route_id: route_id(peer.endpoint_id),
            declared_transit_enabled: peer.transit_enabled,
            endpoint_addr,
            endpoint,
            alpn,
            session_policy: SessionPolicy {
                network_id: config.network_id.clone(),
                local_id,
                remote_id: peer.endpoint_id,
                max_datagram_size: u32::from(config.max_frame_size),
                max_control_size: 32 * 1024,
                features: feature::core_offers(
                    config.routing.transit_enabled,
                    config.fec.enabled,
                    config.mesh.enabled && link.is_none(),
                    link.is_some(),
                ),
                link: link.map(|link| {
                    let decoded = hex::decode(&link.auth_key).expect("validated pairwise auth key");
                    let mut secret = [0_u8; 32];
                    secret.copy_from_slice(&decoded);
                    LinkAuthentication {
                        link_id: link.id.clone(),
                        secret,
                    }
                }),
                local_invite_id: crate::product::local_invite_id(&config.identity_file),
                authority_invites: crate::product::authority_invites(&config.identity_file),
            },
            inbound_packets: services.inbound_packets,
            capacity_events: services.capacity_events,
            connection: ArcSwapOption::from(None),
            connection_updates: tokio::sync::watch::channel(0).0,
            connection_update: StdMutex::new(()),
            connection_tasks: StdMutex::new(ConnectionTaskGeneration::default()),
            dial_lock: Mutex::new(()),
            reconnect_needed: Notify::new(),
            shutdown_ready: Notify::new(),
            shutting_down: AtomicBool::new(false),
            refresh_requested: AtomicBool::new(false),
            relay_bootstrap_started: AtomicBool::new(false),
            discovered_direct_addresses: Mutex::new(HashSet::new()),
            dial_outbound,
            connection_mode,
            relay_bootstrap_enabled: link.is_none()
                && config.discovery_enabled
                && (config.relay.iroh_urls().next().is_some() || !peer.relay_urls.is_empty()),
            candidate_exchange_enabled: link.is_none() && config.discovery_enabled,
            trace_responder: services.trace_responder,
            enforce_overlay_prefixes: config.packet_policy.enforce_overlay_prefixes,
            transit_enabled: config.routing.transit_enabled,
            allowed_source_prefixes: Arc::new(IpPrefixSet::from_prefixes(
                peer.allowed_source_prefixes.iter().copied(),
            )),
            forbidden_underlay_prefixes: Arc::new(underlay_exclusion_prefixes(config)),
            allowed_local_underlay_prefixes: Arc::new(
                link.map_or_else(Vec::new, |link| link.allowed_local_prefixes.clone()),
            ),
            allowed_remote_underlay_prefixes: Arc::new(
                link.map_or_else(Vec::new, |link| link.allowed_remote_prefixes.clone()),
            ),
            private_remote_addresses: Arc::new(
                link.map_or_else(Vec::new, |link| link.remote_addresses.clone()),
            ),
            private_link_exclusive: link.is_some(),
            next_packet_id: AtomicU64::new(1),
            buffer_budget: buffer_budget.clone(),
            repair_cache: StdMutex::new(RepairCache::with_max_bytes_and_budget(
                repair_buffer_limit,
                Some(buffer_budget),
            )),
            reassembly_buffer_limit,
            repair_buffer_limit,
            outbound,
            counters,
            link_estimator: StdRwLock::new(LinkEstimator::default()),
            path_epoch: AtomicU64::new(0),
            selected_path_fingerprint: StdRwLock::new(String::new()),
            frame_size_ceiling,
            effective_frame_size: AtomicU64::new(effective_frame_size as u64),
            fec_encoder: StdMutex::new(fec_encoder),
            fec_reset_epoch: AtomicU64::new(0),
            fec_decoder_ttl: Duration::from_millis(config.fec.decoder_ttl_millis),
            fec_buffer_limit,
            derp_transport: services.derp_transport.cloned(),
            mesh_runtime: services.mesh_runtime,
            nat64_prefix: services.nat64_prefix,
        })
    }

    async fn queue_to_network(self: Arc<Self>) -> Result<()> {
        let mut outbound = self
            .outbound
            .take_consumer()
            .context("peer outbound consumer was already started")?;
        let mut fec_encoder = self
            .fec_encoder
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let mut observed_fec_reset = self.fec_reset_epoch.load(Ordering::Acquire);
        let mut suspended_bulk = None::<TransmissionJob>;
        let mut next_item = None::<OutboundItem>;
        let mut cached_connection = None::<Connection>;
        let mut cached_epoch = 0_u64;

        loop {
            let reset_epoch = self.fec_reset_epoch.load(Ordering::Acquire);
            if reset_epoch != observed_fec_reset {
                if let Some(encoder) = fec_encoder.as_mut() {
                    let unprotected = encoder.reset();
                    self.counters
                        .fec_unprotected_shards
                        .fetch_add(unprotected, Ordering::Relaxed);
                }
                observed_fec_reset = reset_epoch;
            }
            let rtt = Duration::from_micros(self.counters.path_rtt_micros.load(Ordering::Relaxed));
            let queue_max_age = adaptive_queue_max_age(rtt);
            self.counters.queue_max_age_micros.store(
                queue_max_age.as_micros().min(u128::from(u64::MAX)) as u64,
                Ordering::Relaxed,
            );

            // A fragmented bulk packet is retained locally between wire
            // datagrams. Before resuming it, give newly queued control or
            // latency traffic a chance to run. Probe traffic remains last.
            let work = if let Some(item) = next_item.take() {
                TransmissionWork::Item(item)
            } else if let Some(job) = suspended_bulk.take() {
                if let Some(urgent) = outbound.try_pop_urgent(queue_max_age) {
                    suspended_bulk = Some(job);
                    TransmissionWork::Item(urgent)
                } else {
                    TransmissionWork::Job(job)
                }
            } else {
                TransmissionWork::Item(outbound.pop_for_network(queue_max_age).await)
            };

            self.outbound.publish_depth();
            let epoch = *self.connection_updates.borrow();
            if cached_connection.is_none() || epoch != cached_epoch {
                cached_connection = None;
                cached_epoch = epoch;
            }
            let connection = match cached_connection.clone() {
                Some(connection) => connection,
                None => match self.connection().await {
                    Ok(connection) => {
                        cached_epoch = *self.connection_updates.borrow();
                        cached_connection = Some(connection.clone());
                        connection
                    }
                    Err(error) => {
                        cached_connection = None;
                        if should_log(&self.counters.connection_errors) {
                            warn!(
                                peer = %self.name,
                                connection_errors = self.counters.connection_errors.load(Ordering::Relaxed),
                                %error,
                                "cannot connect; retrying queued transmission"
                            );
                        }
                        self.requeue_work(work).await;
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                },
            };
            let mut job = match work {
                TransmissionWork::Job(job) => job,
                TransmissionWork::Item(item) => {
                    let first = match item {
                        OutboundItem::Packet(packet) => packet,
                        OutboundItem::Control(datagram) => {
                            let too_large = connection
                                .max_datagram_size()
                                .is_none_or(|maximum| datagram.len() > maximum);
                            if too_large
                                || connection
                                    .send_datagram_wait(datagram.clone())
                                    .await
                                    .is_err()
                            {
                                self.outbound.push_control(datagram);
                            }
                            continue;
                        }
                        OutboundItem::Probe(datagram) => {
                            let too_large = connection
                                .max_datagram_size()
                                .is_none_or(|maximum| datagram.len() > maximum);
                            if too_large
                                || connection
                                    .send_datagram_wait(datagram.clone())
                                    .await
                                    .is_err()
                            {
                                self.outbound.push_probe(datagram);
                            }
                            continue;
                        }
                    };
                    let Some(path_maximum) = connection.max_datagram_size() else {
                        warn!(peer = %self.name, "peer does not support QUIC datagrams");
                        self.outbound.push(first);
                        self.clear_connection(connection.stable_id()).await;
                        continue;
                    };
                    let automatic = self.effective_frame_size.load(Ordering::Relaxed) as usize;
                    let maximum = path_maximum
                        .min(self.frame_size_ceiling)
                        .min(automatic.max(256));
                    let Some(job) = self
                        .encode_transmission(
                            first,
                            maximum,
                            queue_max_age,
                            &mut outbound,
                            &mut fec_encoder,
                        )
                        .await?
                    else {
                        continue;
                    };
                    job
                }
            };
            match self
                .send_transmission(&connection, &mut job, queue_max_age, &mut outbound)
                .await
            {
                TransmissionOutcome::Complete => self.complete_transmission(job),
                TransmissionOutcome::Preempted(urgent) => {
                    self.counters
                        .bulk_preemptions
                        .fetch_add(1, Ordering::Relaxed);
                    suspended_bulk = Some(job);
                    next_item = Some(urgent);
                }
                TransmissionOutcome::Reframe => {
                    if let Some(encoder) = fec_encoder.as_mut() {
                        let unprotected = encoder.reset();
                        self.counters
                            .fec_unprotected_shards
                            .fetch_add(unprotected, Ordering::Relaxed);
                    }
                    self.counters.mtu_reframes.fetch_add(1, Ordering::Relaxed);
                    self.requeue_transmission(job).await;
                }
                TransmissionOutcome::Failed => {
                    self.requeue_transmission(job).await;
                    self.clear_connection(connection.stable_id()).await;
                }
            }
        }
    }

    async fn encode_transmission(
        &self,
        first: OutboundPacket,
        maximum: usize,
        queue_max_age: Duration,
        outbound: &mut OutboundConsumer,
        fec_encoder: &mut Option<FecEncoder>,
    ) -> Result<Option<TransmissionJob>> {
        // DERP already carries every QUIC packet over an ordered, reliable
        // TCP/TLS byte stream. Adding recovery shards there cannot repair
        // underlay loss; it only consumes the QUIC congestion window and can
        // head-of-line-block newer systematic datagrams.
        // 4 = DERP custom transport, published by the telemetry task.
        let selected_is_derp = self
            .counters
            .selected_path_transport
            .load(Ordering::Relaxed)
            == 4;
        let fec_active = fec_encoder.is_some()
            && !selected_is_derp
            && (self
                .counters
                .selected_path_transport
                .load(Ordering::Relaxed)
                != 0
                || self.derp_transport.is_none());
        if !fec_active && let Some(encoder) = fec_encoder.as_mut() {
            let unprotected = encoder.reset();
            self.counters
                .fec_unprotected_shards
                .fetch_add(unprotected, Ordering::Relaxed);
        }
        let inner_maximum = if fec_active {
            match FecEncoder::inner_frame_limit(maximum) {
                Ok(value) => value,
                Err(error) => {
                    warn!(peer = %self.name, maximum, %error, "FEC leaves no overlay frame capacity");
                    self.outbound.push(first);
                    return Ok(None);
                }
            }
        } else {
            maximum
        };

        let packet_id = self.next_packet_id.fetch_add(1, Ordering::Relaxed);
        let mut first = first;
        let (frames, _stats) = match encode_packet_from_buf(
            &mut first.data,
            inner_maximum,
            packet_id,
            first.delivery_tag,
        ) {
            Ok(frames) => frames,
            Err(error) => {
                warn!(peer = %self.name, len = first.data.len(), maximum = inner_maximum, %error, "failed framing overlay packet");
                return Ok(None);
            }
        };
        if frames.len() > 1 {
            debug!(peer = %self.name, len = first.data.len(), fragments = frames.len(), maximum, "fragmenting overlay packet");
            self.repair_cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(packet_id, &frames);
        }

        let latency_sensitive = first.latency_sensitive;
        let mut packets = vec![first];
        let mut packet_count = 1_u64;
        let mut packet_bytes = packets[0].data.len() as u64;
        let mut wire_frames = frames;
        if wire_frames.len() == 1 && packets[0].data.len() <= SMALL_PACKET_LIMIT {
            self.counters
                .aggregation_delay_micros
                .store(0, Ordering::Relaxed);
            let wire_budget = inner_maximum.saturating_sub(16 + wire_frames[0].len());
            let additional = outbound.try_pop_small_batch_class(
                latency_sensitive,
                SMALL_PACKET_LIMIT,
                wire_budget,
                2 + MAX_PACKET_FRAME_HEADER_LEN,
                64,
                queue_max_age,
            );
            for mut packet in additional {
                let packet_id = self.next_packet_id.fetch_add(1, Ordering::Relaxed);
                let (frame, _) = encode_packet_from_buf(
                    &mut packet.data,
                    inner_maximum,
                    packet_id,
                    packet.delivery_tag,
                )?;
                debug_assert_eq!(frame.len(), 1);
                packet_count += 1;
                packet_bytes = packet_bytes.saturating_add(packet.data.len() as u64);
                packets.push(packet);
                wire_frames.push(frame.into_iter().next().expect("one small-packet frame"));
            }
        }

        let fragment_count = wire_frames.len() as u64;
        let datagrams = if packet_count > 1 {
            vec![encode_batch(&wire_frames, inner_maximum)?]
        } else {
            wire_frames
        };
        let mut encoded_datagrams = VecDeque::new();
        if fec_active {
            let encoder = fec_encoder.as_mut().expect("active FEC has an encoder");
            for datagram in datagrams {
                let batch = encoder.push(datagram, maximum)?;
                self.counters
                    .fec_unprotected_shards
                    .fetch_add(batch.unprotected_shards, Ordering::Relaxed);
                self.counters
                    .fec_overhead_bytes
                    .fetch_add(batch.overhead_bytes, Ordering::Relaxed);
                encoded_datagrams.extend(batch.datagrams);
            }
        } else {
            encoded_datagrams.extend(datagrams.into_iter().map(|bytes| EncodedDatagram {
                bytes,
                recovery: false,
            }));
        }
        self.counters
            .active_tx_bytes
            .fetch_add(packet_bytes, Ordering::Relaxed);
        Ok(Some(TransmissionJob {
            packets,
            datagrams: encoded_datagrams,
            packet_count,
            packet_bytes,
            fragment_count,
            latency_sensitive,
        }))
    }

    async fn send_transmission(
        &self,
        connection: &Connection,
        job: &mut TransmissionJob,
        queue_max_age: Duration,
        outbound: &mut OutboundConsumer,
    ) -> TransmissionOutcome {
        while let Some(datagram) = job.datagrams.pop_front() {
            let recovery = datagram.recovery;
            let frame = datagram.bytes;
            if connection
                .max_datagram_size()
                .is_some_and(|maximum| frame.len() > maximum)
            {
                if recovery {
                    self.counters
                        .fec_unprotected_shards
                        .fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                return TransmissionOutcome::Reframe;
            }
            self.counters.quic_send_buffer_used_bytes.store(
                QUIC_SEND_BUFFER_BYTES.saturating_sub(connection.datagram_send_buffer_space())
                    as u64,
                Ordering::Relaxed,
            );
            if let Err(error) = connection.send_datagram_wait(frame).await {
                if error == SendDatagramError::TooLarge {
                    if recovery {
                        self.counters
                            .fec_unprotected_shards
                            .fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    return TransmissionOutcome::Reframe;
                }
                if should_log(&self.counters.send_errors) {
                    warn!(
                        peer = %self.name,
                        send_errors = self.counters.send_errors.load(Ordering::Relaxed),
                        %error,
                        "failed sending datagram"
                    );
                }
                // Systematic data in this job has already committed when only
                // parity remains. Requeueing it would create a new packet id
                // and deliver the same IP packet twice merely because optional
                // recovery traffic hit a closing/congested connection.
                if data_committed_before_recovery_failure(recovery, &job.datagrams) {
                    let skipped = 1 + job.datagrams.len() as u64;
                    self.counters
                        .fec_unprotected_shards
                        .fetch_add(skipped, Ordering::Relaxed);
                    job.datagrams.clear();
                    return TransmissionOutcome::Complete;
                }
                return TransmissionOutcome::Failed;
            }
            if recovery {
                self.counters
                    .fec_tx_recovery_shards
                    .fetch_add(1, Ordering::Relaxed);
            }
            if !job.latency_sensitive
                && !job.datagrams.is_empty()
                && let Some(urgent) = outbound.try_pop_urgent(queue_max_age)
            {
                return TransmissionOutcome::Preempted(urgent);
            }
        }
        self.counters.quic_send_buffer_used_bytes.store(
            QUIC_SEND_BUFFER_BYTES.saturating_sub(connection.datagram_send_buffer_space()) as u64,
            Ordering::Relaxed,
        );
        TransmissionOutcome::Complete
    }

    fn complete_transmission(&self, job: TransmissionJob) {
        self.counters
            .active_tx_bytes
            .fetch_sub(job.packet_bytes, Ordering::Relaxed);
        self.counters
            .tx_packets
            .fetch_add(job.packet_count, Ordering::Relaxed);
        self.counters
            .tx_bytes
            .fetch_add(job.packet_bytes, Ordering::Relaxed);
        self.counters
            .tx_fragments
            .fetch_add(job.fragment_count, Ordering::Relaxed);
        if job.packet_count > 1 {
            self.counters.tx_batches.fetch_add(1, Ordering::Relaxed);
            self.counters
                .tx_batched_packets
                .fetch_add(job.packet_count, Ordering::Relaxed);
        }
    }

    async fn requeue_transmission(&self, job: TransmissionJob) {
        self.counters
            .active_tx_bytes
            .fetch_sub(job.packet_bytes, Ordering::Relaxed);
        for packet in job.packets {
            self.outbound.push(packet);
        }
    }

    async fn requeue_work(&self, work: TransmissionWork) {
        match work {
            TransmissionWork::Item(item) => self.outbound.requeue(item),
            TransmissionWork::Job(job) => self.requeue_transmission(job).await,
        }
    }

    async fn maintain_connection(self: Arc<Self>) -> Result<()> {
        if !self.can_dial() {
            pending::<()>().await;
            return Ok(());
        }
        loop {
            if self.current_connection().is_none()
                && let Err(error) = self.connection().await
            {
                if should_log(&self.counters.connection_errors) {
                    warn!(peer = %self.name, %error, "background peer connection failed");
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
            if self.refresh_requested.swap(false, Ordering::Relaxed) {
                if let Err(error) = self.refresh_connection().await {
                    warn!(peer = %self.name, %error, "requested peer connection refresh failed");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                continue;
            }
            self.reconnect_needed.notified().await;
        }
    }

    async fn refresh_connection(self: &Arc<Self>) -> Result<()> {
        let _dial_guard = self.dial_lock.lock().await;
        let endpoint_addr = self.dial_addr().await;
        let connection = self
            .connect_best_available(endpoint_addr)
            .await
            .with_context(|| format!("failed refreshing peer {}", self.name))?;
        self.install_connection(connection).await
    }

    async fn bootstrap_relay_path(self: Arc<Self>) {
        if !self.can_dial() || !self.relay_bootstrap_enabled {
            return;
        }
        for _ in 0..12 {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                _ = self.shutdown_ready.notified() => return,
            }
            if self.shutting_down.load(Ordering::Acquire) {
                return;
            }
            let already_open = self
                .current_connection()
                .is_some_and(|connection| connection.paths().iter().any(|path| path.is_relay()));
            if already_open {
                return;
            }
            let endpoint_addr = self.dial_addr().await;
            if endpoint_addr.relay_urls().next().is_none() {
                continue;
            }
            info!(peer = %self.name, "refreshing initial connection to add relay standby path");
            self.refresh_requested.store(true, Ordering::Relaxed);
            self.reconnect_needed.notify_one();
            return;
        }
        debug!(peer = %self.name, "relay standby address was not discovered during bootstrap window");
    }

    async fn dial_addr(&self) -> EndpointAddr {
        let mut endpoint_addr = self.endpoint_addr.clone();
        if self.private_link_exclusive {
            return endpoint_addr;
        }
        endpoint_addr = endpoint_addr.with_addrs(
            self.discovered_direct_addresses
                .lock()
                .await
                .iter()
                .copied()
                .map(TransportAddr::Ip),
        );
        if let Some(remote) = self.endpoint.remote_info(self.endpoint_id).await {
            endpoint_addr = endpoint_addr.with_addrs(
                remote
                    .into_addrs()
                    .map(|address| address.into_addr())
                    .filter(|address| {
                        dial_address_allowed(address, &self.forbidden_underlay_prefixes)
                    }),
            );
        }
        let needs_direct = endpoint_addr.ip_addrs().next().is_none();
        let needs_relay = endpoint_addr.relay_urls().next().is_none();
        if (needs_direct || needs_relay)
            && let Ok(lookup) = self.endpoint.address_lookup()
        {
            let mut results = lookup.resolve(self.endpoint_id);
            let _ = tokio::time::timeout(Duration::from_secs(2), async {
                while let Some(result) = results.next().await {
                    let Ok(Ok(item)) = result else {
                        continue;
                    };
                    endpoint_addr = endpoint_addr.clone().with_addrs(
                        item.into_endpoint_addr()
                            .addrs
                            .into_iter()
                            .filter(|address| {
                                dial_address_allowed(address, &self.forbidden_underlay_prefixes)
                            }),
                    );
                    if endpoint_addr.ip_addrs().next().is_some()
                        && endpoint_addr.relay_urls().next().is_some()
                    {
                        break;
                    }
                }
            })
            .await;
        }
        if let Some(prefix) = *self
            .nat64_prefix
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            let synthesized = nat64_candidates(prefix, &endpoint_addr)
                .into_iter()
                .filter(|address| {
                    dial_address_allowed(
                        &TransportAddr::Ip(*address),
                        &self.forbidden_underlay_prefixes,
                    )
                })
                .collect::<Vec<_>>();
            endpoint_addr =
                endpoint_addr.with_addrs(synthesized.into_iter().map(TransportAddr::Ip));
        }
        endpoint_addr
    }

    async fn connect_best_available(&self, endpoint_addr: EndpointAddr) -> Result<Connection> {
        // Keep every IPv4, IPv6 and relay candidate in the first connection
        // attempt. iroh can probe them within one QUIC session and the WAN path
        // selector applies family preference after observing path quality. A
        // preferred-only first attempt serialized fallback behind the complete
        // connection timeout when an advertised IPv6 route was black-holed.
        self.endpoint
            .connect(endpoint_addr, self.alpn.as_slice())
            .await
            .map_err(Into::into)
    }

    fn local_address_candidates(&self) -> Vec<std::net::SocketAddr> {
        if !self.candidate_exchange_enabled {
            return Vec::new();
        }
        self.endpoint
            .addr()
            .ip_addrs()
            .copied()
            .filter(|address| {
                publishable_address(
                    &TransportAddr::Ip(*address),
                    &self.forbidden_underlay_prefixes,
                )
            })
            .take(32)
            .collect()
    }

    async fn learn_address_candidates(self: &Arc<Self>, addresses: Vec<std::net::SocketAddr>) {
        if !self.candidate_exchange_enabled {
            return;
        }
        let mut discovered = self.discovered_direct_addresses.lock().await;
        let mut added_addresses = Vec::new();
        for address in addresses {
            let transport = TransportAddr::Ip(address);
            if publishable_address(&transport, &self.forbidden_underlay_prefixes)
                && dial_address_allowed(&transport, &self.forbidden_underlay_prefixes)
                && discovered.insert(address)
            {
                added_addresses.push(address);
            }
        }
        drop(discovered);
        if added_addresses.is_empty() {
            return;
        }
        info!(peer = %self.name, addresses = ?added_addresses, "learned authenticated direct underlay candidates");
    }

    async fn connection(self: &Arc<Self>) -> Result<Connection> {
        let mut updates = self.connection_updates.subscribe();
        loop {
            if let Some(connection) = self.current_connection() {
                return Ok(connection);
            }
            if self.can_dial()
                && (self.dial_outbound || self.connection_mode == ConnectionMode::Outbound)
            {
                break;
            }
            if self.connection_mode == ConnectionMode::Canonical {
                if tokio::time::timeout(BOOTSTRAP_FALLBACK_DELAY, updates.changed())
                    .await
                    .is_err()
                {
                    info!(peer = %self.name, "no reciprocal bootstrap entry observed; dialing configured peer");
                    break;
                }
            } else {
                tokio::time::timeout(Duration::from_secs(15), updates.changed())
                    .await
                    .with_context(|| {
                        format!("timed out waiting for inbound peer {}", self.name)
                    })??;
            }
        }
        let _dial_guard = self.dial_lock.lock().await;
        if let Some(connection) = self.current_connection() {
            return Ok(connection);
        }
        let endpoint_addr = self.dial_addr().await;
        let connection = self
            .connect_best_available(endpoint_addr)
            .await
            .with_context(|| format!("failed connecting to peer {}", self.name))?;
        self.install_connection(connection.clone()).await?;
        Ok(connection)
    }

    async fn install_connection(self: &Arc<Self>, connection: Connection) -> Result<()> {
        self.install_connection_with_session(connection, None).await
    }

    async fn install_connection_with_session(
        self: &Arc<Self>,
        connection: Connection,
        negotiated_session: Option<NegotiatedSession>,
    ) -> Result<()> {
        if self.shutting_down.load(Ordering::Acquire) {
            connection.close(0_u8.into(), b"peer shutting down");
            bail!("peer {} is shutting down", self.name);
        }
        let canonical_side = if self.dial_outbound {
            Side::Client
        } else {
            Side::Server
        };
        let accepted_side = match self.connection_mode {
            ConnectionMode::Canonical => {
                connection.side() == canonical_side || connection.side() == Side::Client
            }
            ConnectionMode::Outbound => connection.side() == Side::Client,
            ConnectionMode::Inbound => connection.side() == Side::Server,
        };
        if !accepted_side {
            connection.close(4_u8.into(), b"non-canonical connection direction");
            bail!(
                "invalid connection direction for peer {} in {:?} mode",
                self.name,
                self.connection_mode,
            );
        }
        if let Some((address, prefix)) =
            forbidden_selected_path(&connection, &self.forbidden_underlay_prefixes)
        {
            connection.close(2_u8.into(), b"forbidden underlay path");
            bail!(
                "peer {} selected forbidden underlay address {address} in {prefix}",
                self.name
            );
        }
        if self.private_link_exclusive
            && let Some(reason) = private_link_path_violation(
                &connection,
                &self.allowed_local_underlay_prefixes,
                &self.allowed_remote_underlay_prefixes,
                &self.private_remote_addresses,
            )
        {
            connection.close(8_u8.into(), b"private link path violation");
            bail!(
                "peer {} violated private link path contract: {reason}",
                self.name
            );
        }
        let negotiated = match negotiated_session {
            Some(session) => session,
            None => match negotiate_connection(&connection, &self.session_policy).await {
                Ok(session) => session,
                Err(error) => {
                    connection.close(9_u8.into(), b"V1 session negotiation failed");
                    return Err(error).with_context(|| {
                        format!("V1 session negotiation with {} failed", self.name)
                    });
                }
            },
        };
        let transition = self
            .connection_update
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let current = self.current_connection();
        if self.connection_mode == ConnectionMode::Canonical
            && connection.side() != canonical_side
            && current
                .as_ref()
                .is_some_and(|current| current.side() == canonical_side)
        {
            connection.close(0_u8.into(), b"canonical connection already active");
            return Ok(());
        }
        let generation_cancel = self
            .connection_tasks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .replace(connection.stable_id());
        self.counters
            .protocol_major
            .store(u64::from(crate::protocol::MAJOR), Ordering::Relaxed);
        self.counters
            .protocol_minor
            .store(u64::from(negotiated.minor), Ordering::Relaxed);
        self.counters
            .negotiated_features
            .store(negotiated.features.len() as u64, Ordering::Relaxed);
        self.counters
            .private_link
            .store(negotiated.link_id.is_some(), Ordering::Relaxed);
        self.fec_reset_epoch.fetch_add(1, Ordering::Release);
        *self
            .repair_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            RepairCache::with_max_bytes_and_budget(
                self.repair_buffer_limit,
                Some(self.buffer_budget.clone()),
            );
        let old = self
            .connection
            .swap(Some(Arc::new(connection.clone())))
            .map(|connection| connection.as_ref().clone());
        self.connection_updates.send_modify(|epoch| *epoch += 1);
        self.counters.connected.store(true, Ordering::Relaxed);
        self.counters
            .connection_events
            .fetch_add(1, Ordering::Relaxed);
        drop(transition);
        if let Some(old) = old
            && old.stable_id() != connection.stable_id()
        {
            old.close(0_u8.into(), b"replaced");
        }
        info!(
            peer = %self.name,
            protocol_major = crate::protocol::MAJOR,
            protocol_minor = negotiated.minor,
            features = negotiated.features.len(),
            link_id = negotiated.link_id.as_deref().unwrap_or("public"),
            "peer connection active"
        );
        if let Some(mesh_runtime) = self.mesh_runtime.clone() {
            let control_connection = connection.clone();
            let endpoint_id = self.endpoint_id;
            let control_cancel = generation_cancel.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = control_cancel.cancelled() => {}
                    result = mesh_runtime.run_connection(control_connection, endpoint_id) => {
                        if let Err(error) = result {
                            debug!(peer = %endpoint_id, %error, "mesh control loop ended");
                        }
                    }
                }
            });
        }
        if !self.relay_bootstrap_started.swap(true, Ordering::Relaxed) {
            tokio::spawn(self.clone().bootstrap_relay_path());
        }
        let receive_started = Instant::now();
        let last_overlay_receive_millis = Arc::new(AtomicU64::new(0));
        let overlay_receive_confirmed = Arc::new(AtomicBool::new(false));
        let peer = self.clone();
        let receive_connection = connection.clone();
        let receive_activity = last_overlay_receive_millis.clone();
        let receive_confirmed = overlay_receive_confirmed.clone();
        let receive_cancel = generation_cancel.clone();
        tokio::spawn(async move {
            let stable_id = receive_connection.stable_id();
            let mut fec_decoder = FecDecoder::with_max_buffered_bytes_and_budget(
                peer.fec_decoder_ttl,
                peer.fec_buffer_limit,
                Some(peer.buffer_budget.clone()),
            )
            .expect("validated FEC decoder configuration");
            let mut reassembler = Reassembler::with_max_buffered_bytes_and_budget(
                peer.reassembly_buffer_limit,
                Some(peer.buffer_budget.clone()),
            );
            let mut repair_tick = tokio::time::interval(Duration::from_millis(10));
            repair_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut repair_budget = 64_usize;
            let mut repair_refill = Instant::now() + Duration::from_secs(1);
            loop {
                tokio::select! {
                    _ = receive_cancel.cancelled() => break,
                    result = receive_connection.read_datagram() => match result {
                    Ok(datagram) => {
                        let decoded = match fec_decoder.push(datagram) {
                            Ok(decoded) => decoded,
                            Err(error) => {
                                if should_log(&peer.counters.frame_drops) {
                                    warn!(peer = %peer.name, %error, "dropping invalid FEC datagram");
                                }
                                continue;
                            }
                        };
                        peer.counters.fec_rx_recovery_shards.fetch_add(decoded.recovery_shards, Ordering::Relaxed);
                        peer.counters.fec_recovered_shards.fetch_add(decoded.recovered_shards, Ordering::Relaxed);
                        peer.counters.fec_expired_blocks.fetch_add(decoded.expired_blocks, Ordering::Relaxed);
                        for overlay_datagram in decoded.frames {
                            let wire = match decode_datagram(overlay_datagram) {
                                Ok(wire) => wire,
                                Err(error) => {
                                    if should_log(&peer.counters.frame_drops) {
                                        warn!(peer = %peer.name, %error, "dropping invalid overlay datagram");
                                    }
                                    continue;
                                }
                            };
                            receive_activity.store(
                                receive_started
                                    .elapsed()
                                    .as_millis()
                                    .min(u128::from(u64::MAX)) as u64,
                                Ordering::Relaxed,
                            );
                            receive_confirmed.store(true, Ordering::Relaxed);
                            match wire {
                            WireDatagram::Frames(frames) => {
                                peer.counters
                                    .rx_fragments
                                    .fetch_add(frames.len() as u64, Ordering::Relaxed);
                                for frame in frames {
                                    let result = reassembler.push_tagged(frame);
                                    let evictions = reassembler.take_evictions();
                                    peer.counters
                                        .reassembly_evictions
                                        .fetch_add(evictions, Ordering::Relaxed);
                                    let packet = match result {
                                        Ok(Some(packet)) => packet,
                                        Ok(None) => continue,
                                        Err(error) => {
                                            if should_log(&peer.counters.frame_drops) {
                                                warn!(peer = %peer.name, %error, "dropping invalid overlay frame");
                                            }
                                            continue;
                                        }
                                    };
                                    if let Err(error) = peer
                                        .deliver_packet(packet.data, packet.delivery_tag)
                                        .await
                                    {
                                        warn!(peer = %peer.name, %error, "failed delivering peer packet");
                                        receive_connection.close(3_u8.into(), b"TUN write failed");
                                        break;
                                    }
                                }
                            }
                            WireDatagram::RepairRequest(request) => {
                                peer.counters
                                    .repair_requests_received
                                    .fetch_add(1, Ordering::Relaxed);
                                let frames = peer
                                    .repair_cache
                                    .lock()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .get(&request);
                                if let Some(frames) = frames {
                                    for frame in frames {
                                        if let Err(error) = receive_connection.send_datagram_wait(frame).await {
                                            debug!(peer = %peer.name, packet_id = request.packet_id, %error, "failed retransmitting repair frame");
                                            break;
                                        }
                                        peer.counters
                                            .repair_fragments_sent
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                            WireDatagram::Heartbeat => {
                                peer.counters
                                    .heartbeats_received
                                    .fetch_add(1, Ordering::Relaxed);
                            }
                            WireDatagram::ConnectionRefresh => {
                                if peer.can_dial() {
                                    peer.refresh_requested.store(true, Ordering::Relaxed);
                                    peer.reconnect_needed.notify_one();
                                }
                            }
                            WireDatagram::AddressCandidates(addresses) => {
                                peer.learn_address_candidates(addresses).await;
                            }
                            WireDatagram::CapacityProbe(message) => {
                                if peer.capacity_events.try_send(CapacityEvent::Message {
                                    from: peer.endpoint_id,
                                    message,
                                }).is_err() && should_log(&peer.counters.frame_drops) {
                                    warn!(peer = %peer.name, "dropping capacity probe because the bounded event queue is full");
                                }
                            }
                            WireDatagram::Delivery(message) => {
                                if peer.capacity_events.try_send(CapacityEvent::DeliveryMessage {
                                    from: peer.endpoint_id,
                                    message,
                                }).is_err() && should_log(&peer.counters.frame_drops) {
                                    warn!(peer = %peer.name, "dropping delivery message because the bounded event queue is full");
                                }
                            }
                            }
                        }
                    }
                    Err(error) => {
                        debug!(peer = %peer.name, %error, "peer receive loop ended");
                        break;
                    }
                    },
                    _ = repair_tick.tick() => {
                        let now = Instant::now();
                        if now >= repair_refill {
                            repair_budget = 64;
                            repair_refill = now + Duration::from_secs(1);
                        }
                        if repair_budget == 0 {
                            continue;
                        }
                        let rtt_micros = peer.counters.path_rtt_micros.load(Ordering::Relaxed);
                        let delay = Duration::from_micros(rtt_micros)
                            .mul_f32(1.25)
                            .clamp(Duration::from_millis(15), Duration::from_millis(200));
                        let requests = reassembler.repair_requests(delay, repair_budget);
                        repair_budget = repair_budget.saturating_sub(requests.len());
                        for request in requests {
                            let packet_id = request.packet_id;
                            let request = match encode_repair_request(&request) {
                                Ok(request) => request,
                                Err(error) => {
                                    debug!(peer = %peer.name, packet_id, %error, "failed encoding repair request");
                                    continue;
                                }
                            };
                            if let Err(error) = receive_connection
                                .send_datagram_wait(request)
                                .await
                            {
                                debug!(peer = %peer.name, packet_id, %error, "failed sending repair request");
                                break;
                            }
                            peer.counters
                                .repair_requests_sent
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
            peer.clear_connection(stable_id).await;
        });
        if self.candidate_exchange_enabled {
            let peer = self.clone();
            let candidate_connection = connection.clone();
            let candidate_cancel = generation_cancel.clone();
            tokio::spawn(async move {
                let stable_id = candidate_connection.stable_id();
                let mut address_updates = peer.endpoint.watch_addr().stream();
                loop {
                    let update = tokio::select! {
                        _ = candidate_cancel.cancelled() => break,
                        update = address_updates.next() => update,
                    };
                    if update.is_none() {
                        break;
                    }
                    let is_current = !peer.shutting_down.load(Ordering::Acquire)
                        && peer
                            .current_connection()
                            .is_some_and(|current| current.stable_id() == stable_id);
                    if !is_current {
                        break;
                    }
                    let addresses = peer.local_address_candidates();
                    if addresses.is_empty() {
                        continue;
                    }
                    let Ok(datagram) = encode_address_candidates(&addresses) else {
                        continue;
                    };
                    // The iroh QNT update on this same formal connection is the
                    // primary, reliable path trigger.  This authenticated
                    // overlay hint supplements it with Ironet's filtered
                    // candidate view; bounded retries cover DATAGRAM loss
                    // without falling back to periodic gossip.
                    for attempt in 0..3 {
                        let sent = tokio::select! {
                            _ = candidate_cancel.cancelled() => return,
                            result = candidate_connection.send_datagram_wait(datagram.clone()) => result.is_ok(),
                        };
                        if sent {
                            break;
                        }
                        tokio::select! {
                            _ = candidate_cancel.cancelled() => return,
                            _ = tokio::time::sleep(Duration::from_millis(100 * (attempt + 1))) => {}
                        }
                    }
                }
            });
        }
        let peer = self.clone();
        let heartbeat_connection = connection.clone();
        let heartbeat_cancel = generation_cancel.clone();
        tokio::spawn(async move {
            let stable_id = heartbeat_connection.stable_id();
            let mut heartbeat = tokio::time::interval(OVERLAY_HEARTBEAT_INTERVAL);
            heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut last_udp_rx = heartbeat_connection.stats().udp_rx.datagrams;
            let mut last_transport_receive = Instant::now();
            heartbeat.tick().await;
            loop {
                tokio::select! {
                    _ = heartbeat_cancel.cancelled() => break,
                    _ = heartbeat.tick() => {}
                }
                let is_current = !peer.shutting_down.load(Ordering::Acquire)
                    && peer
                        .current_connection()
                        .is_some_and(|current| current.stable_id() == stable_id);
                if !is_current {
                    break;
                }
                let udp_rx = heartbeat_connection.stats().udp_rx.datagrams;
                if udp_rx != last_udp_rx {
                    last_udp_rx = udp_rx;
                    last_transport_receive = Instant::now();
                }
                let elapsed_millis = receive_started
                    .elapsed()
                    .as_millis()
                    .min(u128::from(u64::MAX)) as u64;
                let overlay_silence = Duration::from_millis(
                    elapsed_millis
                        .saturating_sub(last_overlay_receive_millis.load(Ordering::Relaxed)),
                );
                let transport_silence = last_transport_receive.elapsed();
                let liveness_timeout = if overlay_receive_confirmed.load(Ordering::Relaxed)
                    || peer.counters.connection_events.load(Ordering::Relaxed) > 1
                {
                    OVERLAY_LIVENESS_TIMEOUT
                } else {
                    INITIAL_OVERLAY_LIVENESS_TIMEOUT
                };
                // QUIC DATAGRAM is intentionally unreliable, so short overlay
                // silence still requires transport silence. A hard overlay
                // deadline is nevertheless necessary: ACKs or path probes can
                // keep a broken application path transport-alive forever.
                if liveness_expired(overlay_silence, transport_silence, liveness_timeout) {
                    let is_current = peer
                        .current_connection()
                        .is_some_and(|current| current.stable_id() == stable_id);
                    if !is_current {
                        break;
                    }
                    peer.counters
                        .liveness_reconnects
                        .fetch_add(1, Ordering::Relaxed);
                    warn!(
                        peer = %peer.name,
                        overlay_silence_millis = overlay_silence.as_millis(),
                        transport_silence_millis = transport_silence.as_millis(),
                        "peer receive path timed out; reconnecting"
                    );
                    heartbeat_connection.close(5_u8.into(), b"overlay heartbeat timeout");
                    peer.clear_connection(stable_id).await;
                    peer.reconnect_needed.notify_one();
                    break;
                }
                match tokio::time::timeout(
                    Duration::from_secs(1),
                    heartbeat_connection.send_datagram_wait(encode_heartbeat()),
                )
                .await
                {
                    Ok(Ok(())) => {
                        peer.counters
                            .heartbeats_sent
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(Err(error)) => {
                        debug!(peer = %peer.name, %error, "failed sending overlay heartbeat");
                    }
                    Err(_) => {
                        debug!(peer = %peer.name, "timed out queueing overlay heartbeat");
                    }
                }
            }
        });
        let peer = self.clone();
        let telemetry_cancel = generation_cancel;
        tokio::spawn(async move {
            let stable_id = connection.stable_id();
            let mut paths = connection.paths_stream();
            let mut telemetry = tokio::time::interval(Duration::from_secs(1));
            telemetry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut frame_sizer = AdaptiveFrameSizer::new(peer.frame_size_ceiling);
            loop {
                tokio::select! {
                    _ = telemetry_cancel.cancelled() => break,
                    snapshot = paths.next() => {
                        let Some(paths) = snapshot else {
                            break;
                        };
                        peer.counters
                            .open_paths
                            .store(paths.len() as u64, Ordering::Relaxed);
                        if let Some(path) = paths.iter().find(|path| path.is_selected()) {
                            let transport = path_transport_code(path.remote_addr());
                            let remote = describe_transport_addr(
                                path.remote_addr(),
                                peer.derp_transport.as_deref(),
                            );
                            *peer
                                .counters
                                .selected_path_remote
                                .write()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) = remote.clone();
                            let previous = peer
                                .counters
                                .selected_path_transport
                                .swap(transport, Ordering::Relaxed);
                            let fingerprint = format!("{transport}:{remote}");
                            let changed = {
                                let mut selected = peer
                                    .selected_path_fingerprint
                                    .write()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                                if *selected == fingerprint {
                                    false
                                } else {
                                    *selected = fingerprint;
                                    true
                                }
                            };
                            if changed {
                                peer.path_epoch.fetch_add(1, Ordering::Relaxed);
                            }
                            if changed && previous != 0 {
                                peer.counters.path_switches.fetch_add(1, Ordering::Relaxed);
                                info!(
                                    peer = %peer.name,
                                    transport = path_transport_name(transport),
                                    remote = %path.remote_addr(),
                                    "selected underlay path changed"
                                );
                            }
                        }
                        let forbidden = paths
                            .iter()
                            .filter(|path| path.is_selected())
                            .find_map(|path| {
                                forbidden_transport_path(
                                    path.remote_addr(),
                                    path.local_addr(),
                                    &peer.forbidden_underlay_prefixes,
                                )
                            });
                        if let Some((address, prefix)) = forbidden {
                            warn!(peer = %peer.name, %address, %prefix, "closing connection after migration to forbidden underlay path");
                            connection.close(2_u8.into(), b"forbidden underlay path");
                            peer.clear_connection(stable_id).await;
                            break;
                        }
                        if peer.private_link_exclusive
                            && let Some(reason) = private_link_path_violation(
                                &connection,
                                &peer.allowed_local_underlay_prefixes,
                                &peer.allowed_remote_underlay_prefixes,
                                &peer.private_remote_addresses,
                            )
                        {
                            warn!(peer = %peer.name, %reason, "closing connection after private link path migration");
                            connection.close(8_u8.into(), b"private link path migration");
                            peer.clear_connection(stable_id).await;
                            break;
                        }
                    }
                    _ = telemetry.tick() => {
                        let snapshot = connection.paths();
                        let Some(path) = snapshot.iter().find(|path| path.is_selected()) else {
                            continue;
                        };
                        let stats = path.stats();
                        store_duration_micros(&peer.counters.path_rtt_micros, stats.rtt);
                        peer.counters.path_mtu.store(u64::from(stats.current_mtu), Ordering::Relaxed);
                        peer.counters.path_cwnd_bytes.store(stats.cwnd, Ordering::Relaxed);
                        peer.counters.quic_send_buffer_used_bytes.store(
                            QUIC_SEND_BUFFER_BYTES
                                .saturating_sub(connection.datagram_send_buffer_space())
                                as u64,
                            Ordering::Relaxed,
                        );
                        peer.counters
                            .path_tx_datagrams
                            .store(stats.udp_tx.datagrams, Ordering::Relaxed);
                        peer.counters.path_lost_packets.store(stats.lost_packets, Ordering::Relaxed);
                        let metrics = peer.link_estimator
                            .write()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .observe(
                                stats.rtt,
                                stats.lost_packets,
                                stats.udp_tx.datagrams,
                            );
                        store_duration_micros(
                            &peer.counters.path_jitter_micros,
                            metrics.jitter,
                        );
                        peer.counters
                            .path_loss_ppm
                            .store(u64::from(metrics.loss_ppm), Ordering::Relaxed);
                        let path_limit = connection
                            .max_datagram_size()
                            .unwrap_or(peer.frame_size_ceiling);
                        let previous = frame_sizer.current();
                        let current = frame_sizer.update(path_limit);
                        peer.effective_frame_size.store(current as u64, Ordering::Relaxed);
                        peer.counters.effective_frame_size.store(current as u64, Ordering::Relaxed);
                        if current != previous {
                            info!(peer = %peer.name, previous, current, path_limit, "adapted overlay frame size");
                        }
                    }
                }
            }
        });
        Ok(())
    }

    async fn deliver_packet(
        &self,
        packet: DataplaneBuf,
        delivery_tag: Option<DeliveryTag>,
    ) -> Result<()> {
        let packet_info = match inspect_ip_packet(packet.as_slice()) {
            Ok(info) => info,
            Err(error) => {
                if should_log(&self.counters.invalid_packets) {
                    warn!(
                        peer = %self.name,
                        invalid_packets = self.counters.invalid_packets.load(Ordering::Relaxed),
                        %error,
                        "dropping invalid peer datagram"
                    );
                }
                return Ok(());
            }
        };
        if let Some(responder) = &self.trace_responder {
            match responder.handle_packet(packet.as_slice()).await {
                Ok(true) => return Ok(()),
                Ok(false) => {}
                Err(error) => {
                    if should_log(&self.counters.trace_errors) {
                        warn!(
                            peer = %self.name,
                            trace_errors = self.counters.trace_errors.load(Ordering::Relaxed),
                            %error,
                            "failed handling trace probe"
                        );
                    }
                    return Ok(());
                }
            }
        }
        self.inbound_packets
            .send(InboundPacket {
                peer_id: self.endpoint_id,
                packet,
                packet_info,
                delivery_tag,
            })
            .await
            .context("inbound FlowRouter queue closed")?;
        Ok(())
    }

    async fn clear_connection(&self, stable_id: usize) {
        let transition = self
            .connection_update
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self
            .current_connection()
            .as_ref()
            .is_some_and(|current| current.stable_id() == stable_id)
        {
            self.connection.store(None);
            self.connection_tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .cancel(Some(stable_id));
            self.connection_updates.send_modify(|epoch| *epoch += 1);
            self.mark_disconnected();
            if !self.shutting_down.load(Ordering::Acquire) {
                self.reconnect_needed.notify_one();
            }
        }
        drop(transition);
    }

    fn mark_disconnected(&self) {
        self.counters.connected.store(false, Ordering::Relaxed);
        self.counters
            .selected_path_transport
            .store(0, Ordering::Relaxed);
        self.counters
            .selected_path_remote
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        let had_path = {
            let mut selected = self
                .selected_path_fingerprint
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let had_path = !selected.is_empty();
            selected.clear();
            had_path
        };
        if had_path {
            self.path_epoch.fetch_add(1, Ordering::Relaxed);
        }
        self.counters.open_paths.store(0, Ordering::Relaxed);
    }

    fn packet_allowed(
        &self,
        snapshot: &DataPlaneRouteSnapshot,
        peer_transit_enabled: bool,
        source: std::net::IpAddr,
        destination: std::net::IpAddr,
        inbound: bool,
    ) -> bool {
        packet_allowed(
            PacketPolicy {
                enforce_overlay_prefixes: self.enforce_overlay_prefixes,
                transit_enabled: self.transit_enabled,
                peer_transit_enabled,
                overlay_prefixes: &snapshot.overlay_prefixes,
                local_prefixes: &snapshot.local_prefixes,
                remote_prefixes: &snapshot.remote_prefixes,
                allowed_source_prefixes: &self.allowed_source_prefixes,
                mesh_owners: &snapshot.mesh_owners,
                peer_id: self.endpoint_id,
            },
            source,
            destination,
            inbound,
        )
    }

    async fn close(&self) {
        self.shutting_down.store(true, Ordering::Release);
        let connection = {
            let _transition = self
                .connection_update
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let connection = self.connection.swap(None);
            self.connection_tasks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .cancel(None);
            self.connection_updates.send_modify(|epoch| *epoch += 1);
            connection
        };
        if let Some(connection) = connection {
            connection.close(0_u8.into(), b"shutdown");
        }
        self.mark_disconnected();
        self.reconnect_needed.notify_waiters();
        self.shutdown_ready.notify_waiters();
    }
}

fn nat64_candidates(
    prefix: Nat64Prefix,
    endpoint_addr: &EndpointAddr,
) -> Vec<std::net::SocketAddr> {
    endpoint_addr
        .ip_addrs()
        .filter_map(|address| match address {
            std::net::SocketAddr::V4(address) => Some(std::net::SocketAddr::new(
                IpAddr::V6(prefix.synthesize(*address.ip())),
                address.port(),
            )),
            std::net::SocketAddr::V6(_) => None,
        })
        .collect()
}

fn path_transport_code(address: &TransportAddr) -> u64 {
    match address {
        TransportAddr::Ip(_) => 1,
        TransportAddr::Relay(_) => 2,
        TransportAddr::Custom(address) if DerpAddr::from_custom(address).is_ok() => 4,
        TransportAddr::Custom(_) => 3,
        _ => 0,
    }
}

#[cfg(test)]
fn is_relay_transport(address: &TransportAddr) -> bool {
    match address {
        TransportAddr::Relay(_) => true,
        TransportAddr::Custom(custom) => DerpAddr::from_custom(custom).is_ok(),
        _ => false,
    }
}

fn quic_path_idle_timeout(relay: &RelayConfig) -> Duration {
    if relay.derp_enabled() {
        DERP_PATH_IDLE_TIMEOUT
    } else {
        QUIC_PATH_IDLE_TIMEOUT
    }
}

fn path_transport_name(value: u64) -> &'static str {
    match value {
        1 => "direct",
        2 => "relay",
        3 => "custom",
        4 => "derp",
        _ => "unknown",
    }
}

fn describe_transport_addr(address: &TransportAddr, derp: Option<&DerpTransport>) -> String {
    match address {
        TransportAddr::Custom(custom) => match DerpAddr::from_custom(custom) {
            Ok(address) => format!(
                "region={} server={}",
                address.region_id,
                derp.and_then(|transport| transport.server_name(address.region_id))
                    .unwrap_or("unknown")
            ),
            Err(_) => address.to_string(),
        },
        _ => address.to_string(),
    }
}

fn liveness_expired(
    overlay_silence: Duration,
    transport_silence: Duration,
    timeout: Duration,
) -> bool {
    (overlay_silence >= timeout && transport_silence >= timeout)
        || overlay_silence >= timeout.saturating_mul(3)
}

#[derive(Clone, Copy)]
struct PacketPolicy<'a> {
    enforce_overlay_prefixes: bool,
    transit_enabled: bool,
    peer_transit_enabled: bool,
    overlay_prefixes: &'a IpPrefixSet,
    local_prefixes: &'a IpPrefixSet,
    remote_prefixes: &'a IpPrefixSet,
    allowed_source_prefixes: &'a IpPrefixSet,
    mesh_owners: &'a PrefixOwnerTable,
    peer_id: EndpointId,
}

fn packet_allowed(
    policy: PacketPolicy<'_>,
    source: std::net::IpAddr,
    destination: std::net::IpAddr,
    inbound: bool,
) -> bool {
    let remote_destination = policy.remote_prefixes.contains(destination);
    if inbound
        && !policy.transit_enabled
        && !policy.local_prefixes.contains(destination)
        && remote_destination
    {
        return false;
    }
    if !policy.enforce_overlay_prefixes {
        return true;
    }
    let contains = |address| policy.overlay_prefixes.contains(address);
    contains(source)
        && contains(destination)
        && (!inbound
            || policy.allowed_source_prefixes.contains(source)
            || policy
                .mesh_owners
                .owner(source)
                .is_some_and(|owner| policy.peer_transit_enabled || owner == policy.peer_id))
}

async fn accept_loop(
    endpoint: Endpoint,
    peers: Arc<RwLock<HashMap<EndpointId, Arc<Peer>>>>,
    expected_alpn: Arc<Vec<u8>>,
    probe_alpn: Arc<Vec<u8>>,
    forbidden_underlay_prefixes: Arc<Vec<IpNet>>,
    dynamic_manager: Option<Arc<DynamicMeshManager>>,
) -> Result<()> {
    let admissions = Arc::new(Semaphore::new(UNKNOWN_ADMISSION_CONCURRENCY));
    while let Some(incoming) = endpoint.accept().await {
        if let Some((address, prefix)) =
            forbidden_incoming_path(&incoming, &forbidden_underlay_prefixes)
        {
            warn!(%address, %prefix, "ignoring incoming connection on forbidden underlay path");
            incoming.ignore();
            continue;
        }
        let mut accepting = match incoming.accept() {
            Ok(accepting) => accepting,
            Err(error) => {
                debug!(%error, "rejected malformed incoming attempt");
                continue;
            }
        };
        let alpn = match accepting.alpn().await {
            Ok(alpn) => alpn,
            Err(error) => {
                debug!(%error, "failed negotiating incoming ALPN");
                continue;
            }
        };
        let is_probe = alpn == *probe_alpn;
        if alpn != *expected_alpn && !is_probe {
            warn!(alpn = %String::from_utf8_lossy(&alpn), "rejecting unexpected ALPN");
            continue;
        }
        let connection = match accepting.await {
            Ok(connection) => connection,
            Err(error) => {
                debug!(%error, "incoming connection failed");
                continue;
            }
        };
        if is_probe {
            let Some(manager) = dynamic_manager.clone() else {
                connection.close(1_u8.into(), b"mesh disabled");
                continue;
            };
            let Ok(permit) = admissions.clone().try_acquire_owned() else {
                connection.close(1_u8.into(), b"admission busy");
                continue;
            };
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(error) = manager.mesh.answer_probe(&connection).await {
                    connection.close(1_u8.into(), b"invalid mesh probe");
                    debug!(endpoint_id = %connection.remote_id(), %error, "rejected mesh probe");
                } else {
                    connection.close(0_u8.into(), b"probe complete");
                }
            });
            continue;
        }
        let remote_id = connection.remote_id();
        let Some(peer) = peers.read().await.get(&remote_id).cloned() else {
            if let Some(manager) = dynamic_manager.clone() {
                let Ok(permit) = admissions.clone().try_acquire_owned() else {
                    connection.close(1_u8.into(), b"admission busy");
                    continue;
                };
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(error) = manager.accept_unknown(connection.clone()).await {
                        connection.close(1_u8.into(), b"unauthorized dynamic peer");
                        warn!(endpoint_id = %remote_id, %error, "rejected dynamic peer");
                    }
                });
                continue;
            }
            connection.close(1_u8.into(), b"unauthorized peer");
            warn!(endpoint_id = %remote_id, "rejected unauthorized peer");
            continue;
        };
        if let Err(error) = peer.install_connection(connection).await {
            warn!(peer = %peer.name, %error, "rejected incoming connection");
        }
    }
    Err(anyhow!("iroh endpoint accept loop stopped"))
}

fn forbidden_incoming_path(
    incoming: &iroh::endpoint::Incoming,
    prefixes: &[IpNet],
) -> Option<(std::net::IpAddr, IpNet)> {
    if let IncomingAddr::Ip(address) = incoming.remote_addr()
        && let Some(prefix) = forbidden_prefix(prefixes, address.ip())
    {
        return Some((address.ip(), prefix));
    }
    if let LocalTransportAddr::Ip(Some(address)) = incoming.local_addr()
        && let Some(prefix) = forbidden_prefix(prefixes, address)
    {
        return Some((address, prefix));
    }
    None
}

fn forbidden_selected_path(
    connection: &Connection,
    prefixes: &[IpNet],
) -> Option<(std::net::IpAddr, IpNet)> {
    let paths = connection.paths();
    for path in paths.iter().filter(|path| path.is_selected()) {
        if let Some(forbidden) =
            forbidden_transport_path(path.remote_addr(), path.local_addr(), prefixes)
        {
            return Some(forbidden);
        }
    }
    None
}

fn private_link_path_violation(
    connection: &Connection,
    allowed_local: &[IpNet],
    allowed_remote: &[IpNet],
    exact_remote: &[std::net::SocketAddr],
) -> Option<String> {
    let paths = connection.paths();
    let selected = paths.iter().find(|path| path.is_selected())?;
    let TransportAddr::Ip(remote) = selected.remote_addr() else {
        return Some("selected a relay or custom transport".into());
    };
    if !exact_remote.contains(remote) {
        return Some(format!("selected unconfigured remote locator {remote}"));
    }
    if !allowed_remote
        .iter()
        .any(|prefix| prefix.contains(&remote.ip()))
    {
        return Some(format!("remote locator {remote} is outside its allowlist"));
    }
    let LocalTransportAddr::Ip(Some(local)) = selected.local_addr() else {
        return Some("selected a non-IP or unknown local locator".into());
    };
    if !allowed_local.is_empty() && !allowed_local.iter().any(|prefix| prefix.contains(local)) {
        return Some(format!("local locator {local} is outside its allowlist"));
    }
    None
}

fn forbidden_transport_path(
    remote_addr: &TransportAddr,
    local_addr: &LocalTransportAddr,
    prefixes: &[IpNet],
) -> Option<(std::net::IpAddr, IpNet)> {
    if let TransportAddr::Ip(address) = remote_addr
        && let Some(prefix) = forbidden_prefix(prefixes, address.ip())
    {
        return Some((address.ip(), prefix));
    }
    if let LocalTransportAddr::Ip(Some(address)) = local_addr
        && let Some(prefix) = forbidden_prefix(prefixes, *address)
    {
        return Some((*address, prefix));
    }
    None
}

fn forbidden_prefix(prefixes: &[IpNet], address: std::net::IpAddr) -> Option<IpNet> {
    prefixes
        .iter()
        .copied()
        .find(|prefix| prefix.contains(&address))
}

fn publishable_address(address: &TransportAddr, hidden_prefixes: &[IpNet]) -> bool {
    let TransportAddr::Ip(address) = address else {
        return true;
    };
    let ip = address.ip();
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    match ip {
        std::net::IpAddr::V4(ip) if ip.is_link_local() => return false,
        std::net::IpAddr::V6(ip) if ip.is_unicast_link_local() => return false,
        _ => {}
    }
    !hidden_prefixes.iter().any(|prefix| prefix.contains(&ip))
}

fn dial_address_allowed(address: &TransportAddr, forbidden_prefixes: &[IpNet]) -> bool {
    match address {
        TransportAddr::Ip(address) => forbidden_prefix(forbidden_prefixes, address.ip()).is_none(),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::PresenceBody;

    fn endpoint(byte: u8) -> EndpointId {
        SecretKey::from_bytes(&[byte; 32]).public()
    }

    #[test]
    fn parity_failure_never_requeues_already_committed_data() {
        let recovery = || EncodedDatagram {
            bytes: Bytes::from_static(b"recovery"),
            recovery: true,
        };
        let systematic = EncodedDatagram {
            bytes: Bytes::from_static(b"systematic"),
            recovery: false,
        };
        assert!(data_committed_before_recovery_failure(
            true,
            &VecDeque::from([recovery(), recovery()])
        ));
        assert!(!data_committed_before_recovery_failure(
            false,
            &VecDeque::from([recovery()])
        ));
        assert!(!data_committed_before_recovery_failure(
            true,
            &VecDeque::from([recovery(), systematic])
        ));
    }

    #[test]
    fn connection_generation_replacement_retires_only_the_matching_tasks() {
        let mut generation = ConnectionTaskGeneration::default();
        let first = generation.replace(10);
        assert!(!first.is_cancelled());
        let second = generation.replace(11);
        assert!(first.is_cancelled());
        assert!(!second.is_cancelled());
        assert!(!generation.cancel(Some(10)));
        assert!(!second.is_cancelled());
        assert!(generation.cancel(Some(11)));
        assert!(second.is_cancelled());
    }

    #[test]
    fn initial_dial_keeps_all_families_and_relay_in_one_attempt() {
        let relay: RelayUrl = "https://relay.example.com".parse().unwrap();
        let address = EndpointAddr::new(endpoint(60))
            .with_ip_addr("198.51.100.60:4000".parse().unwrap())
            .with_ip_addr("[2001:db8::60]:4000".parse().unwrap())
            .with_relay_url(relay.clone());

        assert_eq!(
            address.ip_addrs().copied().collect::<HashSet<_>>(),
            HashSet::from([
                "198.51.100.60:4000".parse().unwrap(),
                "[2001:db8::60]:4000".parse().unwrap(),
            ])
        );
        assert_eq!(
            address.relay_urls().cloned().collect::<Vec<_>>(),
            vec![relay]
        );
    }

    fn presence_with_paths(
        key_byte: u8,
        direct_addresses: Vec<std::net::SocketAddr>,
        relay_urls: Vec<String>,
    ) -> SignedPresence {
        let key = SecretKey::from_bytes(&[key_byte; 32]);
        let config: Config = toml::from_str(include_str!("../config/example.toml")).unwrap();
        let body = PresenceBody::from_config(
            &config,
            key.public(),
            1,
            std::time::SystemTime::now(),
            direct_addresses,
            relay_urls,
            None,
        )
        .unwrap();
        SignedPresence::sign(body, &key, &config.network_id).unwrap()
    }

    #[test]
    fn relay_only_presence_is_eligible_for_formal_connection() {
        let presence =
            presence_with_paths(61, Vec::new(), vec!["https://relay.example.com".into()]);
        assert!(presence_path(&presence, false).is_none());
        let (path, _, diversity) = presence_path(&presence, true).unwrap();
        assert_eq!(path, PathKind::Relay);
        assert_eq!(diversity, "https://relay.example.com");
    }

    #[test]
    fn direct_path_is_preferred_over_relay_hint() {
        let presence = presence_with_paths(
            62,
            vec!["203.0.113.62:10119".parse().unwrap()],
            vec!["https://relay.example.com".into()],
        );
        assert_eq!(
            presence_path(&presence, false).unwrap().0,
            PathKind::DirectIpv4
        );
    }

    #[test]
    fn nat64_candidate_preserves_ipv4_port() {
        let endpoint_addr =
            EndpointAddr::new(endpoint(63)).with_ip_addr("203.0.113.63:45119".parse().unwrap());
        let candidates = nat64_candidates(
            Nat64Prefix {
                network: "64:ff9b::".parse().unwrap(),
                prefix_len: 96,
            },
            &endpoint_addr,
        );
        assert_eq!(
            candidates,
            vec!["[64:ff9b::cb00:713f]:45119".parse().unwrap()]
        );
    }

    fn route_input(
        endpoint_id: EndpointId,
        connected: bool,
        transit_enabled: bool,
    ) -> AdjacencyRouteInput {
        AdjacencyRouteInput {
            endpoint_id,
            route_id: route_id(endpoint_id),
            connected,
            transit_enabled,
            metrics: LinkMetrics {
                rtt: Duration::from_millis(20),
                jitter: Duration::from_millis(2),
                loss_ppm: 0,
            },
            queued_bytes: 0,
        }
    }

    #[test]
    fn immutable_prefix_table_uses_longest_prefix_for_both_families() {
        let broad = endpoint(38);
        let narrow = endpoint(39);
        let table = PrefixOwnerTable::from_origins([
            (broad, "10.0.0.0/8".parse().unwrap()),
            (narrow, "10.20.0.0/16".parse().unwrap()),
            (broad, "2001:db8::/32".parse().unwrap()),
            (narrow, "2001:db8:20::/48".parse().unwrap()),
        ]);

        assert_eq!(table.owner("10.20.3.4".parse().unwrap()), Some(narrow));
        assert_eq!(table.owner("10.30.3.4".parse().unwrap()), Some(broad));
        assert_eq!(table.owner("2001:db8:20::1".parse().unwrap()), Some(narrow));
        assert_eq!(table.owner("2001:db8:30::1".parse().unwrap()), Some(broad));
        assert_eq!(table.owner("192.0.2.1".parse().unwrap()), None);
    }

    #[test]
    fn flow_sharding_is_stable_and_uses_multiple_router_owners() {
        let base = PacketInfo {
            source: "10.0.0.1".parse().unwrap(),
            destination: "10.0.0.2".parse().unwrap(),
            protocol: 6,
            source_port: Some(40_000),
            destination_port: Some(443),
            length: 1_500,
        };
        assert_eq!(flow_shard(base, 8), flow_shard(base, 8));
        let occupied = (40_000..40_128)
            .map(|source_port| {
                flow_shard(
                    PacketInfo {
                        source_port: Some(source_port),
                        ..base
                    },
                    8,
                )
            })
            .collect::<HashSet<_>>();
        assert!(occupied.len() > 1);
    }

    fn measured_table(
        destination: EndpointId,
        routes: &[(EndpointId, u64)],
        now: Instant,
    ) -> RouteEstimateTable {
        let mut table = RouteEstimateTable::default();
        for (first_hop, capacity_bps) in routes {
            assert!(
                table
                    .get_or_insert(
                        RouteKey {
                            destination,
                            first_hop: *first_hop,
                        },
                        now,
                    )
                    .observe_passive(capacity_bps / 8, Duration::from_secs(1), false, now,)
            );
        }
        table
    }

    #[test]
    fn live_direct_owner_suppresses_transit_routes() {
        let owner = endpoint(41);
        let transit = endpoint(42);
        let links = [
            route_input(owner, true, false),
            route_input(transit, true, true),
        ];
        let now = Instant::now();
        let estimates = measured_table(owner, &[(owner, 300_000_000)], now);
        let choices =
            route_candidates(Some(owner), None, &links, &estimates, Some(80_000_000), now);

        assert_eq!(choices.len(), 1);
        assert_eq!(choices[0].endpoint_id, owner);
        assert_eq!(choices[0].candidate.capacity_bps, 80_000_000);
    }

    #[test]
    fn disconnected_owner_falls_back_to_live_transit() {
        let owner = endpoint(43);
        let transit = endpoint(44);
        let links = [
            route_input(owner, false, false),
            route_input(transit, true, true),
        ];
        let now = Instant::now();
        let estimates = measured_table(owner, &[(transit, 25_000_000)], now);
        let choices = route_candidates(Some(owner), None, &links, &estimates, None, now);

        assert_eq!(choices.len(), 1);
        assert_eq!(choices[0].endpoint_id, transit);
        assert_eq!(choices[0].candidate.capacity_bps, 25_000_000);
    }

    #[test]
    fn degraded_connected_owner_no_longer_hides_transit() {
        let owner = endpoint(43);
        let transit = endpoint(44);
        let mut direct = route_input(owner, true, false);
        direct.metrics.loss_ppm = DIRECT_OWNER_MAX_LOSS_PPM;
        let links = [direct, route_input(transit, true, true)];
        let now = Instant::now();
        let estimates = measured_table(owner, &[(owner, 25_000_000), (transit, 25_000_000)], now);
        let choices = route_candidates(Some(owner), None, &links, &estimates, None, now);

        assert_eq!(
            choices
                .iter()
                .map(|choice| choice.endpoint_id)
                .collect::<HashSet<_>>(),
            HashSet::from([owner, transit])
        );
    }

    #[test]
    fn multiple_transit_hops_share_the_same_single_path_candidate_model() {
        let previous = endpoint(45);
        let b = endpoint(46);
        let d = endpoint(47);
        let unknown_capacity = endpoint(48);
        let links = vec![
            route_input(previous, true, true),
            route_input(b, true, true),
            route_input(d, true, true),
            route_input(unknown_capacity, true, true),
        ];
        let owner = endpoint(49);
        let now = Instant::now();
        let estimates = measured_table(owner, &[(b, 40_000_000), (d, 30_000_000)], now);
        let choices = route_candidates(Some(owner), Some(previous), &links, &estimates, None, now);

        assert_eq!(
            choices
                .iter()
                .map(|choice| choice.endpoint_id)
                .collect::<HashSet<_>>(),
            HashSet::from([b, d, unknown_capacity])
        );
        let b_capacity = choices
            .iter()
            .find(|choice| choice.endpoint_id == b)
            .unwrap()
            .candidate
            .capacity_bps;
        let d_capacity = choices
            .iter()
            .find(|choice| choice.endpoint_id == d)
            .unwrap()
            .candidate
            .capacity_bps;
        assert_eq!(b_capacity, 40_000_000);
        assert_eq!(d_capacity, 30_000_000);
        assert_eq!(
            choices
                .iter()
                .find(|choice| choice.endpoint_id == unknown_capacity)
                .unwrap()
                .candidate
                .capacity_bps,
            crate::capacity::BOOTSTRAP_CAPACITY_BPS
        );
    }

    #[test]
    fn runtime_candidate_model_defaults_to_latency_then_moves_bulk_to_capacity() {
        let b = endpoint(50);
        let d = endpoint(51);
        let mut b_link = route_input(b, true, true);
        b_link.metrics = LinkMetrics {
            rtt: Duration::from_millis(5),
            jitter: Duration::ZERO,
            loss_ppm: 0,
        };
        let mut d_link = route_input(d, true, true);
        d_link.metrics = LinkMetrics {
            rtt: Duration::from_millis(50),
            jitter: Duration::ZERO,
            loss_ppm: 0,
        };
        let owner = endpoint(52);
        let start = Instant::now();
        let estimates = measured_table(owner, &[(b, 10_000_000), (d, 500_000_000)], start);
        let choices = route_candidates(
            Some(owner),
            None,
            &[b_link, d_link],
            &estimates,
            None,
            start,
        );
        let key = FlowKey {
            source: "10.0.0.1".parse().unwrap(),
            destination: "10.0.0.2".parse().unwrap(),
            protocol: 6,
            source_port: Some(50_000),
            destination_port: Some(22),
        };
        let mut router = FlowRouter::new(crate::flow_router::FlowRouterConfig {
            pressure_drain_bytes_per_second: 1,
            packet_allowance_bytes: 0,
            lease_duration: Duration::from_millis(10),
            switch_penalty: Duration::ZERO,
            ..crate::flow_router::FlowRouterConfig::default()
        });

        let first = router
            .select_projected(key, 100, 0, &choices, |choice| &choice.candidate, start)
            .unwrap();
        assert_eq!(
            choices
                .iter()
                .find(|choice| choice.candidate.id == first.route_id)
                .unwrap()
                .endpoint_id,
            b
        );

        let mut last = first;
        for millisecond in 1..=60 {
            last = router
                .select_projected(
                    key,
                    1_500,
                    0,
                    &choices,
                    |choice| &choice.candidate,
                    start + Duration::from_millis(millisecond),
                )
                .unwrap();
        }
        assert_eq!(
            choices
                .iter()
                .find(|choice| choice.candidate.id == last.route_id)
                .unwrap()
                .endpoint_id,
            d
        );
    }

    #[test]
    fn delivery_coordinator_attributes_receiver_rate_to_the_source_route() {
        let origin = endpoint(53);
        let first_hop = endpoint(54);
        let destination = endpoint(55);
        let route = RouteKey {
            destination,
            first_hop,
        };
        let now = Instant::now();
        let mut source = DeliveryCoordinator::default();
        let registration = source
            .install_source_route(origin, route, 7, vec![origin, first_hop, destination], now)
            .unwrap();
        let mut receiver = DeliveryCoordinator::default();
        receiver
            .install_forwarding(registration, destination, now)
            .unwrap();

        let first = source.next_tag(route, 7, true, now).tag.unwrap();
        assert!(
            receiver
                .observe_delivery(first, 200_000, now + Duration::from_millis(1))
                .is_none()
        );
        let second = source
            .next_tag(route, 7, true, now + Duration::from_millis(60))
            .tag
            .unwrap();
        let report = receiver
            .observe_delivery(second, 200_000, now + Duration::from_millis(61))
            .unwrap();
        let observation = source
            .apply_report(&report, now + Duration::from_millis(61))
            .unwrap();
        assert_eq!(observation.route, route);
        assert_eq!(observation.path_epoch, 7);
        assert_eq!(observation.delivered_bytes, 400_000);
        assert_eq!(observation.receiver_interval, Duration::from_millis(60));
        assert!(!observation.app_limited);
        let renew_at = now + DELIVERY_SESSION_TTL + Duration::from_secs(1);
        source.prune(renew_at);
        let renewed = source.next_tag(route, 7, true, renew_at);
        assert!(renewed.tag.is_some());
        assert!(renewed.registration.is_some());
        assert_ne!(
            renewed.registration.unwrap().session_id,
            report.session_id,
            "an expired session is renewed from the bounded route template"
        );
        assert!(
            source
                .next_tag(route, 8, true, renew_at + Duration::from_millis(1))
                .tag
                .is_none()
        );
    }

    #[test]
    fn delivery_fast_path_allocates_unique_tags_and_tracks_queue_state() {
        let origin = endpoint(56);
        let first_hop = endpoint(57);
        let destination = endpoint(58);
        let route = RouteKey {
            destination,
            first_hop,
        };
        let registration = DeliverySessionRegister {
            session_id: 99,
            origin,
            destination,
            first_hop,
            path_epoch: 7,
            forward_hops: vec![origin, first_hop, destination],
        };
        let fast = Arc::new(DeliveryFastPath::default());
        fast.install_source(registration.clone(), 41);
        fast.install_forwarding(registration.clone());

        let workers = 8;
        let tags_per_worker = 512;
        let mut joins = Vec::new();
        for _ in 0..workers {
            let fast = fast.clone();
            joins.push(std::thread::spawn(move || {
                (0..tags_per_worker)
                    .map(|_| fast.next_source_tag(route, 7, true).unwrap().sequence)
                    .collect::<Vec<_>>()
            }));
        }
        let mut sequences = joins
            .into_iter()
            .flat_map(|join| join.join().unwrap())
            .collect::<Vec<_>>();
        sequences.sort_unstable();
        assert_eq!(sequences.first(), Some(&41));
        assert_eq!(sequences.len(), workers * tags_per_worker);
        assert!(sequences.windows(2).all(|pair| pair[1] == pair[0] + 1));
        assert!(
            fast.source_queue_nonempty_since(registration.session_id)
                .is_some()
        );
        assert!(fast.touch_forwarding(registration.session_id));
        assert_eq!(
            fast.forwarding_registration(registration.session_id),
            Some(registration.clone())
        );

        fast.next_source_tag(route, 7, false).unwrap();
        assert!(
            fast.source_queue_nonempty_since(registration.session_id)
                .is_none()
        );
        assert!(fast.next_source_tag(route, 8, true).is_none());
        fast.remove_source_session(registration.session_id);
        assert!(fast.next_source_tag(route, 7, true).is_none());
    }

    #[test]
    fn periodic_fast_liveness_keeps_cold_report_state_alive() {
        let origin = endpoint(59);
        let first_hop = endpoint(60);
        let destination = endpoint(61);
        let route = RouteKey {
            destination,
            first_hop,
        };
        let started = Instant::now();
        let mut coordinator = DeliveryCoordinator::default();
        let registration = coordinator
            .install_source_route(
                origin,
                route,
                3,
                vec![origin, first_hop, destination],
                started,
            )
            .unwrap();
        let fast = DeliveryFastPath::default();
        fast.install_source(registration.clone(), 0);
        fast.next_source_tag(route, 3, true).unwrap();

        let refresh_at = started + DELIVERY_SESSION_TTL - Duration::from_millis(1);
        for liveness in fast.source_liveness() {
            coordinator.synchronize_source_liveness(liveness, refresh_at);
        }
        let after_original_ttl = started + DELIVERY_SESSION_TTL + Duration::from_millis(1);
        coordinator.prune(after_original_ttl);

        assert!(
            coordinator
                .next_tag(route, 3, true, after_original_ttl)
                .tag
                .is_some()
        );
        assert_eq!(
            coordinator.forwarding_hops(origin, registration.session_id, after_original_ttl,),
            Some(vec![origin, first_hop, destination])
        );
    }

    #[test]
    fn transit_delivery_binding_is_kept_alive_by_tagged_data() {
        let origin = endpoint(62);
        let transit = endpoint(63);
        let destination = endpoint(64);
        let route = RouteKey {
            destination,
            first_hop: transit,
        };
        let now = Instant::now();
        let mut source = DeliveryCoordinator::default();
        let registration = source
            .install_source_route(origin, route, 3, vec![origin, transit, destination], now)
            .unwrap();
        let session_id = registration.session_id;
        let mut forwarding = DeliveryCoordinator::default();
        forwarding
            .install_forwarding(registration, transit, now)
            .unwrap();

        forwarding.touch_forwarding(
            session_id,
            now + DELIVERY_SESSION_TTL - Duration::from_millis(1),
        );
        forwarding.prune(now + DELIVERY_SESSION_TTL + Duration::from_millis(1));
        assert_eq!(
            forwarding.forwarding_hops(
                origin,
                session_id,
                now + DELIVERY_SESSION_TTL + Duration::from_millis(2),
            ),
            Some(vec![origin, transit, destination])
        );
    }

    #[test]
    fn derp_custom_address_is_classified_as_relay() {
        let address = DerpAddr {
            region_id: crate::derp::RegionId(7),
            public_key: crate::derp::DerpPublicKey::from_bytes([8; 32]),
        };
        let transport = TransportAddr::Custom(address.to_custom());
        assert!(is_relay_transport(&transport));
        assert_eq!(path_transport_code(&transport), 4);
    }

    #[test]
    fn derp_uses_stream_tolerant_path_idle_timeout() {
        let derp = RelayConfig {
            iroh_relay_enabled: false,
            urls: Vec::new(),
            discovery_urls: Vec::new(),
            servers: vec!["https://derp.example.com".into()],
        };
        assert_eq!(quic_path_idle_timeout(&derp), DERP_PATH_IDLE_TIMEOUT);
        assert_eq!(
            quic_path_idle_timeout(&RelayConfig::default()),
            QUIC_PATH_IDLE_TIMEOUT
        );
    }

    #[test]
    fn opt_in_qad_observation_set_has_multiple_vantage_points() {
        assert!(RelayMode::Default.relay_map().len() >= 2);
    }

    #[test]
    fn iroh_relay_is_disabled_by_default() {
        let mut config: Config = toml::from_str(include_str!("../config/example.toml")).unwrap();
        assert!(matches!(
            iroh_relay_mode(&config, Vec::new()),
            RelayMode::Disabled
        ));

        config.relay.iroh_relay_enabled = true;
        assert!(matches!(
            iroh_relay_mode(&config, Vec::new()),
            RelayMode::Default
        ));
    }

    #[test]
    fn discovered_overlay_addresses_are_not_dialed_as_underlay() {
        let forbidden = vec!["10.250.12.0/24".parse().unwrap()];
        assert!(!dial_address_allowed(
            &TransportAddr::Ip("10.250.12.2:10119".parse().unwrap()),
            &forbidden,
        ));
        assert!(dial_address_allowed(
            &TransportAddr::Ip("111.62.241.102:10119".parse().unwrap()),
            &forbidden,
        ));
    }

    #[test]
    fn inbound_sources_are_restricted_per_adjacency() {
        let local = vec!["10.200.0.1/32".parse().unwrap()];
        let remote = vec![
            "10.200.0.2/32".parse().unwrap(),
            "10.200.0.3/32".parse().unwrap(),
        ];
        let overlay = IpPrefixSet::from_prefixes(local.iter().chain(&remote).copied());
        let local = IpPrefixSet::from_prefixes(local);
        let remote = IpPrefixSet::from_prefixes(remote);
        let allowed = vec!["10.200.0.2/32".parse().unwrap()];
        let allowed = IpPrefixSet::from_prefixes(allowed);
        let mesh_owners = PrefixOwnerTable::default();
        let policy = PacketPolicy {
            enforce_overlay_prefixes: true,
            transit_enabled: true,
            peer_transit_enabled: false,
            overlay_prefixes: &overlay,
            local_prefixes: &local,
            remote_prefixes: &remote,
            allowed_source_prefixes: &allowed,
            mesh_owners: &mesh_owners,
            peer_id: SecretKey::from_bytes(&[30; 32]).public(),
        };
        assert!(packet_allowed(
            policy,
            "10.200.0.2".parse().unwrap(),
            "10.200.0.1".parse().unwrap(),
            true,
        ));
        assert!(!packet_allowed(
            policy,
            "10.200.0.3".parse().unwrap(),
            "10.200.0.1".parse().unwrap(),
            true,
        ));
        assert!(packet_allowed(
            policy,
            "10.200.0.3".parse().unwrap(),
            "10.200.0.1".parse().unwrap(),
            false,
        ));
    }

    #[test]
    fn immutable_mesh_policy_allows_owned_or_transit_sources_without_locking() {
        let peer = SecretKey::from_bytes(&[32; 32]).public();
        let other = SecretKey::from_bytes(&[33; 32]).public();
        let local = IpPrefixSet::from_prefixes(["10.200.0.1/32".parse().unwrap()]);
        let remote = IpPrefixSet::from_prefixes([
            "10.200.0.2/32".parse().unwrap(),
            "10.200.0.3/32".parse().unwrap(),
        ]);
        let overlay = IpPrefixSet::from_prefixes([
            "10.200.0.1/32".parse().unwrap(),
            "10.200.0.2/32".parse().unwrap(),
            "10.200.0.3/32".parse().unwrap(),
        ]);
        let allowed = IpPrefixSet::default();
        let mesh_owners = PrefixOwnerTable::from_origins([
            (peer, "10.200.0.2/32".parse().unwrap()),
            (other, "10.200.0.3/32".parse().unwrap()),
        ]);
        let base = PacketPolicy {
            enforce_overlay_prefixes: true,
            transit_enabled: true,
            peer_transit_enabled: false,
            overlay_prefixes: &overlay,
            local_prefixes: &local,
            remote_prefixes: &remote,
            allowed_source_prefixes: &allowed,
            mesh_owners: &mesh_owners,
            peer_id: peer,
        };
        assert!(packet_allowed(
            base,
            "10.200.0.2".parse().unwrap(),
            "10.200.0.1".parse().unwrap(),
            true,
        ));
        assert!(!packet_allowed(
            base,
            "10.200.0.3".parse().unwrap(),
            "10.200.0.1".parse().unwrap(),
            true,
        ));
        assert!(packet_allowed(
            PacketPolicy {
                peer_transit_enabled: true,
                ..base
            },
            "10.200.0.3".parse().unwrap(),
            "10.200.0.1".parse().unwrap(),
            true,
        ));
    }

    #[test]
    fn non_transit_node_rejects_only_inbound_remote_destinations() {
        let local = vec![
            "10.200.0.2/32".parse().unwrap(),
            "192.168.20.0/24".parse().unwrap(),
        ];
        let remote = vec![
            "10.200.0.1/32".parse().unwrap(),
            "10.200.0.3/32".parse().unwrap(),
        ];
        let overlay = IpPrefixSet::from_prefixes(local.iter().chain(&remote).copied());
        let local = IpPrefixSet::from_prefixes(local);
        let remote = IpPrefixSet::from_prefixes(remote);
        let allowed = vec!["10.200.0.1/32".parse().unwrap()];
        let allowed = IpPrefixSet::from_prefixes(allowed);
        let mesh_owners = PrefixOwnerTable::default();
        let non_transit_policy = PacketPolicy {
            enforce_overlay_prefixes: true,
            transit_enabled: false,
            peer_transit_enabled: false,
            overlay_prefixes: &overlay,
            local_prefixes: &local,
            remote_prefixes: &remote,
            allowed_source_prefixes: &allowed,
            mesh_owners: &mesh_owners,
            peer_id: SecretKey::from_bytes(&[31; 32]).public(),
        };

        // Peer A cannot send through this node to remote Peer C, even when
        // general Overlay-prefix enforcement is disabled.
        assert!(!packet_allowed(
            PacketPolicy {
                enforce_overlay_prefixes: false,
                ..non_transit_policy
            },
            "10.200.0.1".parse().unwrap(),
            "10.200.0.3".parse().unwrap(),
            true,
        ));
        // This node and its locally advertised LAN remain reachable.
        for destination in ["10.200.0.2", "192.168.20.10"] {
            assert!(packet_allowed(
                non_transit_policy,
                "10.200.0.1".parse().unwrap(),
                destination.parse().unwrap(),
                true,
            ));
        }
        // The same remote destination is legal on a transit node, and local
        // traffic may use any learned route on a non-transit node.
        assert!(packet_allowed(
            PacketPolicy {
                transit_enabled: true,
                ..non_transit_policy
            },
            "10.200.0.1".parse().unwrap(),
            "10.200.0.3".parse().unwrap(),
            true,
        ));
        assert!(packet_allowed(
            non_transit_policy,
            "10.200.0.2".parse().unwrap(),
            "10.200.0.3".parse().unwrap(),
            false,
        ));
    }

    #[test]
    fn forbidden_prefix_matches_yggdrasil_range() {
        let prefixes = vec!["200::/7".parse().unwrap()];
        assert_eq!(
            forbidden_prefix(&prefixes, "200:1234::1".parse().unwrap()),
            Some(prefixes[0])
        );
        assert_eq!(
            forbidden_prefix(&prefixes, "fd00::1".parse().unwrap()),
            None
        );

        let remote_ygg = TransportAddr::Ip("[201:1234::1]:4000".parse().unwrap());
        let local_regular = LocalTransportAddr::Ip(Some("fd00::1".parse().unwrap()));
        assert_eq!(
            forbidden_transport_path(&remote_ygg, &local_regular, &prefixes),
            Some(("201:1234::1".parse().unwrap(), prefixes[0]))
        );

        let remote_regular = TransportAddr::Ip("[fd00::2]:4000".parse().unwrap());
        let local_ygg = LocalTransportAddr::Ip(Some("202:1234::1".parse().unwrap()));
        assert_eq!(
            forbidden_transport_path(&remote_regular, &local_ygg, &prefixes),
            Some(("202:1234::1".parse().unwrap(), prefixes[0]))
        );
    }

    #[test]
    fn discovery_filter_hides_overlay_and_non_routable_addresses() {
        let hidden = vec!["10.200.0.0/16".parse().unwrap(), "200::/7".parse().unwrap()];
        assert!(!publishable_address(
            &TransportAddr::Ip("10.200.0.1:4000".parse().unwrap()),
            &hidden,
        ));
        assert!(!publishable_address(
            &TransportAddr::Ip("[201:1234::1]:4000".parse().unwrap()),
            &hidden,
        ));
        assert!(!publishable_address(
            &TransportAddr::Ip("127.0.0.1:4000".parse().unwrap()),
            &hidden,
        ));
        assert!(publishable_address(
            &TransportAddr::Ip("192.168.10.2:4000".parse().unwrap()),
            &hidden,
        ));
    }

    #[test]
    fn dataplane_prefers_chacha_without_removing_quic_initial_aes() {
        let suites = dataplane_crypto_provider()
            .cipher_suites
            .iter()
            .map(|suite| suite.suite())
            .collect::<Vec<_>>();
        assert_eq!(
            suites.first(),
            Some(&CipherSuite::TLS13_CHACHA20_POLY1305_SHA256)
        );
        assert!(suites.contains(&CipherSuite::TLS13_AES_128_GCM_SHA256));
    }

    #[test]
    fn liveness_uses_transport_grace_but_has_a_hard_overlay_deadline() {
        let timeout = Duration::from_secs(2);
        assert!(!liveness_expired(
            Duration::from_secs(3),
            Duration::from_millis(100),
            timeout,
        ));
        assert!(!liveness_expired(
            Duration::from_millis(100),
            Duration::from_secs(3),
            timeout,
        ));
        assert!(liveness_expired(
            Duration::from_secs(2),
            Duration::from_secs(2),
            timeout,
        ));
        assert!(liveness_expired(
            Duration::from_secs(6),
            Duration::from_millis(100),
            timeout,
        ));
    }

    #[test]
    fn jumbo_packets_never_enter_latency_service() {
        assert!(latency_service(0, 64));
        assert!(latency_service(
            LATENCY_PRESSURE_LIMIT - 1,
            PRIORITY_PACKET_LIMIT
        ));
        assert!(!latency_service(
            LATENCY_PRESSURE_LIMIT,
            PRIORITY_PACKET_LIMIT
        ));
        // A 65,535-byte TUN packet previously accumulated only 65,279 bytes
        // of pressure and therefore slipped just below the 64 KiB class
        // boundary. Packet size now independently keeps it in Bulk service.
        assert!(!latency_service(65_279, 65_535));
    }

    #[test]
    fn only_single_healthy_direct_route_omits_delivery_tracking() {
        let owner = endpoint(90);
        let transit = endpoint(91);
        assert!(!delivery_tracking_required(owner, owner, 1, 1));
        assert!(delivery_tracking_required(owner, transit, 1, 1));
        assert!(delivery_tracking_required(owner, owner, 2, 1));
        assert!(delivery_tracking_required(owner, owner, 1, 0));
        assert!(delivery_tracking_required(owner, owner, 1, 2));
        assert!(delivery_tracking_required(owner, owner, 1, 4));
    }
}

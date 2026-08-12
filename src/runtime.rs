use std::{
    borrow::Cow,
    collections::{HashMap, HashSet, VecDeque},
    future::{Future, pending},
    sync::{
        Arc, Mutex as StdMutex, RwLock as StdRwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail, ensure};
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
use noq_proto::congestion::Bbr3Config;
use tokio::{
    sync::{Mutex, Notify, RwLock, Semaphore, mpsc, oneshot},
    task::JoinSet,
};
use tracing::{debug, info, warn};

use crate::{
    address::{network_alpn, network_probe_alpn},
    capacity::{CapacitySnapshot, RouteEstimateTable, RouteKey},
    capacity_probe::{
        ActiveProbeScheduler, CapacityProbeMessage, CapacityProbePacket, CapacityProbeReady,
        CapacityProbeStart, ProbeReceiver, ProbeRequest, ProbeStatusSnapshot, append_probe_hop,
        encode_probe, forward_next_hop, reverse_next_hop,
    },
    config::{Config, PeerConfig, RelayConfig},
    delivery::{
        DELIVERY_ROUTE_TEMPLATE_TTL, DELIVERY_SESSION_TTL, DELIVERY_TAG_WIRE_BYTES,
        DeliveryMessage, DeliveryReceiver, DeliveryReport, DeliverySessionRegister, DeliverySource,
        DeliveryTag, MAX_DELIVERY_SESSIONS, encode_delivery,
    },
    derp::{DerpAddr, DerpTransport, identity::load_or_create, tls_config},
    fec::{EncodedDatagram, FecDecoder, FecEncoder},
    flow_router::{FlowRouter, RouteCandidate, RouteId},
    link_metrics::{LinkEstimator, LinkMetrics},
    mesh::{
        CANDIDATES_PER_ROUND, EVALUATION_INTERVAL, MESH_BUFFER_POOL_BUDGET_BYTES, MeshPlanner,
        MeshRuntime, PROBE_CONCURRENCY, PathKind, ProbeObservation, SignedPresence,
    },
    observability::{
        CapacityObservability, FlowRouterCounters, PeerCounters, RuntimeState, log_runtime_started,
        publish_status, run_reporter, should_log,
    },
    packet::{FlowKey, PacketInfo, decrement_hop_limit_validated, inspect_ip_packet},
    path_selection::{RELAY_HOLD_DOWN, WanPathSelector},
    system::{
        cleanup_node_interface, cleanup_routing, prepare_node_interface, prepare_routing,
        routing_table, sync_overlay_routes,
    },
    trace::TraceResponder,
    transport::{
        AdaptiveFrameSizer, OUTBOUND_QUEUE_BYTES, OutboundItem, OutboundPacket, OutboundQueue,
        RepairCache, adaptive_queue_max_age, store_duration_micros,
    },
    tunnel::OverlayTunnel,
    wire::{
        MAX_PACKET_FRAME_HEADER_LEN, Reassembler, WireDatagram, decode_datagram,
        encode_address_candidates, encode_batch, encode_heartbeat, encode_packet_tagged,
        encode_repair_request,
    },
};

// Keep noq's FIFO datagram buffer shallower than one interactive RTT.  The
// application scheduler cannot preempt datagrams after they enter this
// buffer, so a large value turns otherwise-prioritized traffic into hidden
// head-of-line blocking under bulk load.
const QUIC_SEND_BUFFER_BYTES: usize = 8 * 1024;
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
const DISCOVERED_DIRECT_PROBE_COOLDOWN: Duration = Duration::from_secs(60);
const BOOTSTRAP_FALLBACK_DELAY: Duration = Duration::from_secs(5);
const UNKNOWN_ADMISSION_CONCURRENCY: usize = 16;
// This queue sits before FlowRouter classifies packets.  Keep it shallow so a
// burst of jumbo TUN packets cannot hide hundreds of milliseconds of work in
// a classless FIFO. Backpressure is preferable to moving that backlog out of
// sight of the class-aware outbound queues.
const FLOW_DISPATCH_QUEUE: usize = 64;
const CAPACITY_EVENT_QUEUE: usize = 4_096;
const LATENCY_PRESSURE_LIMIT: u64 = 64 * 1024;
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

struct InboundPacket {
    peer_id: EndpointId,
    packet: Vec<u8>,
    delivery_tag: Option<DeliveryTag>,
}

struct RouteRequest {
    packet: Vec<u8>,
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

#[derive(Clone)]
struct CapacityManagerState {
    estimates: Arc<StdRwLock<RouteEstimateTable>>,
    probe_status: Arc<StdRwLock<ProbeStatusSnapshot>>,
    delivery: Arc<StdMutex<DeliveryCoordinator>>,
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

    fn touch_forwarding(&mut self, session_id: u64, now: Instant) {
        if let Some(binding) = self.forwarding.get_mut(&session_id) {
            binding.last_used = now;
        }
    }

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
        let forwarding = self.forwarding.get(&report.session_id)?;
        let route = RouteKey {
            destination: forwarding.registration.destination,
            first_hop: forwarding.registration.first_hop,
        };
        let binding = self.source_routes.get_mut(&route)?;
        if binding.registration.session_id != report.session_id {
            return None;
        }
        binding.last_used = now;
        let epoch = binding.registration.path_epoch;
        self.source.apply_report(report, route, epoch, now)
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
        bail!("iroh-sdwan runtime is supported only on Linux");
    }

    let local_id = secret_key.public();
    config.validate_local_id(local_id)?;
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
    let routing_cleanup = cleanup_routing(&config).await;
    let interface_cleanup = cleanup_node_interface(&config).await;
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
    tunnel: Arc<OverlayTunnel>,
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
    let (inbound_tx, inbound_rx) = mpsc::channel(FLOW_DISPATCH_QUEUE);
    let (route_tx, route_rx) = mpsc::channel(FLOW_DISPATCH_QUEUE);
    let (capacity_tx, capacity_rx) = mpsc::channel(CAPACITY_EVENT_QUEUE);
    let route_estimates = Arc::new(StdRwLock::new(RouteEstimateTable::default()));
    let probe_status = Arc::new(StdRwLock::new(ProbeStatusSnapshot::default()));
    let delivery = Arc::new(StdMutex::new(DeliveryCoordinator::default()));
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
                inbound_packets: inbound_tx.clone(),
                capacity_events: capacity_tx.clone(),
            },
        )?;
        info!(
            peer = %peer.name,
            endpoint_id = %peer.endpoint_id,
            interface = %tunnel.name,
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
            probe_alpn.clone(),
            inherited_relays.clone(),
            trace_responder.clone(),
            derp_transport.clone(),
            mesh,
            peers.clone(),
            peer_counters.clone(),
            inbound_tx.clone(),
            capacity_tx.clone(),
        )?),
        None => None,
    };
    let runtime_state = Arc::new(RuntimeState::new(
        local_id,
        routing_table(config),
        config.all_remote_prefixes().collect(),
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
    for peer in &initial_peers {
        let sender = peer.clone();
        tasks.spawn(async move { sender.queue_to_network().await });
        let connector = peer.clone();
        tasks.spawn(async move { connector.maintain_connection().await });
    }
    {
        let tunnel = tunnel.clone();
        let route_tx = route_tx.clone();
        tasks.spawn(async move { tunnel_to_router(tunnel, route_tx).await });
    }
    {
        let config = config.clone();
        let tunnel = tunnel.clone();
        let route_tx = route_tx.clone();
        let capacity_tx = capacity_tx.clone();
        let delivery = delivery.clone();
        tasks.spawn(async move {
            inbound_to_router(config, tunnel, inbound_rx, route_tx, capacity_tx, delivery).await
        });
    }
    {
        let config = config.clone();
        let peers = peers.clone();
        let mesh = mesh_runtime.clone();
        let route_estimates = route_estimates.clone();
        let delivery = delivery.clone();
        let flow_router_counters = flow_router_counters.clone();
        tasks.spawn(async move {
            run_flow_router(
                config,
                peers,
                mesh,
                route_estimates,
                delivery,
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
    tunnel: Arc<OverlayTunnel>,
    route_tx: mpsc::Sender<RouteRequest>,
) -> Result<()> {
    let mut packet = vec![0_u8; 65_535];
    loop {
        let len = tunnel
            .device
            .recv(&mut packet)
            .await
            .with_context(|| format!("failed reading {}", tunnel.name))?;
        let packet_info = match inspect_ip_packet(&packet[..len]) {
            Ok(info) => info,
            Err(error) => {
                debug!(%error, "dropping invalid packet read from FlowRouter TUN");
                continue;
            }
        };
        route_tx
            .send(RouteRequest {
                packet: packet[..len].to_vec(),
                packet_info,
                previous_peer: None,
                delivery_tag: None,
            })
            .await
            .context("FlowRouter request queue closed")?;
    }
}

async fn inbound_to_router(
    config: Config,
    tunnel: Arc<OverlayTunnel>,
    mut inbound_rx: mpsc::Receiver<InboundPacket>,
    route_tx: mpsc::Sender<RouteRequest>,
    capacity_tx: mpsc::Sender<CapacityEvent>,
    delivery: Arc<StdMutex<DeliveryCoordinator>>,
) -> Result<()> {
    while let Some(mut inbound) = inbound_rx.recv().await {
        let info = match inspect_ip_packet(&inbound.packet) {
            Ok(info) => info,
            Err(error) => {
                debug!(peer = %inbound.peer_id, %error, "dropping invalid inbound packet");
                continue;
            }
        };
        let local_destination = config
            .all_advertised_prefixes()
            .any(|prefix| prefix.contains(&info.destination));
        if local_destination {
            tunnel
                .device
                .send(&inbound.packet)
                .await
                .context("failed injecting inbound packet into FlowRouter TUN")?;
            if let Some(tag) = inbound.delivery_tag {
                // Aggregate at the receiver before entering the bounded
                // capacity-event queue. Enqueuing one event per data packet
                // would shed a biased subset under high throughput and turn
                // receiver-confirmed capacity into a severe underestimate.
                let report = delivery
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .observe_delivery(tag, inbound.packet.len(), Instant::now());
                if let Some(report) = report {
                    let _ = capacity_tx.try_send(CapacityEvent::Delivered { report });
                }
            }
            continue;
        }
        if !config.routing.transit_enabled {
            continue;
        }
        if let Err(error) = decrement_hop_limit_validated(&mut inbound.packet) {
            debug!(peer = %inbound.peer_id, %error, "dropping packet at overlay hop limit");
            continue;
        }
        route_tx
            .send(RouteRequest {
                packet: inbound.packet,
                packet_info: info,
                previous_peer: Some(inbound.peer_id),
                delivery_tag: inbound.delivery_tag,
            })
            .await
            .context("FlowRouter request queue closed")?;
    }
    bail!("inbound packet queue closed")
}

async fn run_flow_router(
    config: Config,
    peers: Arc<RwLock<HashMap<EndpointId, Arc<Peer>>>>,
    mesh: Option<Arc<MeshRuntime>>,
    route_estimates: Arc<StdRwLock<RouteEstimateTable>>,
    delivery: Arc<StdMutex<DeliveryCoordinator>>,
    counters: Arc<FlowRouterCounters>,
    mut requests: mpsc::Receiver<RouteRequest>,
) -> Result<()> {
    let mut router = FlowRouter::default();
    let route_switch_log_events = AtomicU64::new(0);
    let mut peer_inventory = Vec::new();
    let mut inputs = Vec::new();
    let mut choices = Vec::new();
    while let Some(request) = requests.recv().await {
        let packet_info = request.packet_info;
        let owner = configured_destination_owner(&config, packet_info.destination).or_else(|| {
            mesh.as_ref()
                .and_then(|mesh| mesh.destination_owner(packet_info.destination))
        });
        peer_inventory.clear();
        {
            let peers = peers.read().await;
            peer_inventory.extend(peers.values().cloned());
        }
        inputs.clear();
        inputs.reserve(peer_inventory.len().saturating_sub(inputs.capacity()));
        for peer in &peer_inventory {
            let transit_enabled = mesh
                .as_ref()
                .and_then(|mesh| mesh.transit_enabled_for(peer.endpoint_id))
                .unwrap_or(peer.declared_transit_enabled);
            let metrics = peer
                .link_estimator
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .snapshot();
            inputs.push(AdjacencyRouteInput {
                endpoint_id: peer.endpoint_id,
                route_id: peer.route_id,
                connected: peer.counters.connected.load(Ordering::Relaxed),
                transit_enabled,
                metrics,
                queued_bytes: peer.counters.queue_bytes.load(Ordering::Relaxed),
            });
        }
        {
            let estimates = route_estimates
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            fill_route_candidates(
                &mut choices,
                owner,
                request.previous_peer,
                &inputs,
                &estimates,
                config.routing.max_egress_bps(),
                Instant::now(),
            );
        }
        let flow_key = FlowKey::from(packet_info);
        let Some(decision) = router.select_projected(
            flow_key,
            packet_info.length,
            0,
            &choices,
            |choice| &choice.candidate,
            Instant::now(),
        ) else {
            counters
                .active_flows
                .store(router.len() as u64, Ordering::Relaxed);
            counters.no_route_drops.fetch_add(1, Ordering::Relaxed);
            debug!(destination = %packet_info.destination, "no usable FlowRouter route");
            continue;
        };
        counters
            .active_flows
            .store(router.len() as u64, Ordering::Relaxed);
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
        let Some(peer) = peer_inventory.get(selected_choice.adjacency_index).cloned() else {
            continue;
        };
        if !peer.packet_allowed(packet_info.source, packet_info.destination, false) {
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
            delivery
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .touch_forwarding(tag.session_id, Instant::now());
            DeliveryTagState {
                tag: Some(tag),
                registration: None,
            }
        } else if let Some(owner) = owner {
            delivery
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .next_tag(
                    RouteKey {
                        destination: owner,
                        first_hop: selected_endpoint,
                    },
                    peer.path_epoch.load(Ordering::Relaxed),
                    !latency_sensitive || peer.counters.queue_bytes.load(Ordering::Relaxed) > 0,
                    Instant::now(),
                )
        } else {
            DeliveryTagState::default()
        };
        if let Some(registration) = delivery_state.registration.take() {
            // Control is queued before the first tagged application packet. If
            // the bounded control queue is full, leave this packet untagged and
            // retry session renewal on later data.
            let session_id = registration.session_id;
            let registered =
                queue_delivery_message(&peer, DeliveryMessage::Register(registration)).await;
            if !registered {
                delivery_state.tag = None;
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
        peer.outbound
            .push(
                OutboundPacket::new(Bytes::from(request.packet), latency_sensitive)
                    .with_delivery_tag(delivery_state.tag),
            )
            .await;
    }
    bail!("FlowRouter request queue closed")
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
                            &mut scheduler,
                        ).await.map_err(|error| (from, error))
                    }
                    CapacityEvent::Delivered { report } => {
                        handle_delivery_report(local_id, report, &peers, &delivery)
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
                delivery
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .prune(now);

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
            let registration = delivery
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .install_source_route(
                    local_id,
                    state.request.route,
                    state.path_epoch,
                    ready.traversed_hops.clone(),
                    Instant::now(),
                )?;
            ensure!(
                send_delivery_message(
                    peers,
                    state.request.route.first_hop,
                    DeliveryMessage::Register(registration),
                )
                .await,
                "delivery registration first hop is unavailable"
            );
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
                    if !peer.outbound.push_probe(datagram).await {
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
        peer.outbound.push_probe(datagram).await
    } else {
        peer.outbound.push_control(datagram).await
    }
}

async fn handle_delivery_message(
    local_id: EndpointId,
    from: EndpointId,
    message: DeliveryMessage,
    peers: &Arc<RwLock<HashMap<EndpointId, Arc<Peer>>>>,
    estimates: &Arc<StdRwLock<RouteEstimateTable>>,
    delivery: &Arc<StdMutex<DeliveryCoordinator>>,
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
            let hops = delivery
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .forwarding_hops(report.origin, report.session_id, now)
                .context("unknown delivery report session")?;
            ensure!(
                forward_next_hop(&hops, local_id) == Some(from),
                "delivery report arrived outside its fixed reverse route"
            );
            if report.origin == local_id {
                let observation = delivery
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .apply_report(&report, now)
                    .context("delivery report does not match the active source route")?;
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
    delivery: &Arc<StdMutex<DeliveryCoordinator>>,
) -> Result<()> {
    let now = Instant::now();
    let hops = delivery
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .forwarding_hops(report.origin, report.session_id, now)
        .context("delivered packet has no registered route")?;
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
    if !peer.outbound.push_control(datagram).await {
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
/// owner suppresses transit alternatives only while that adjacency is live.
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
        && adjacencies
            .iter()
            .any(|link| link.endpoint_id == owner && link.connected);

    choices.reserve(adjacencies.len().saturating_sub(choices.capacity()));
    for (adjacency_index, link) in adjacencies.iter().enumerate() {
        if !link.connected || previous_peer == Some(link.endpoint_id) {
            continue;
        }
        let direct_owner = owner == link.endpoint_id;
        if (direct_owner_active && !direct_owner) || (!direct_owner_active && !link.transit_enabled)
        {
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

fn configured_destination_owner(
    config: &Config,
    destination: std::net::IpAddr,
) -> Option<EndpointId> {
    config.route_origins.iter().find_map(|origin| {
        origin
            .prefixes
            .iter()
            .any(|prefix| prefix.contains(&destination))
            .then_some(origin.endpoint_id)
    })
}

fn route_id(endpoint_id: EndpointId) -> RouteId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"iroh-sdwan-flow-route-v1\0");
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

async fn build_endpoint(
    config: &Config,
    secret_key: SecretKey,
    alpn: &[u8],
    probe_alpn: &[u8],
    derp_transport: Option<Arc<DerpTransport>>,
) -> Result<Endpoint> {
    let relay_mode = if config.relay.urls.is_empty() {
        RelayMode::Disabled
    } else {
        RelayMode::custom(
            config
                .relay
                .urls
                .iter()
                .map(|url| url.parse::<RelayUrl>())
                .collect::<std::result::Result<Vec<_>, _>>()?,
        )
    };
    // Retain BBR3's conservative, MTU-scaled initial window.  A fixed 64 KiB
    // window can inject roughly half a second of data on a 1 Mbit/s path
    // before the first useful bandwidth/RTT sample exists.
    let bbr3 = Bbr3Config::default();
    let path_idle_timeout = quic_path_idle_timeout(&config.relay);
    let transport = QuicTransportConfig::builder()
        .congestion_controller_factory(Arc::new(bbr3))
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
        .enable_segmentation_offload(false)
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
    let hidden_prefixes = Arc::new(underlay_exclusion_prefixes(config));
    let path_selector = WanPathSelector::new(hidden_prefixes.as_ref().clone());
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
        .secret_key(secret_key)
        .alpns(alpns)
        .relay_mode(relay_mode)
        .path_selector(Arc::new(path_selector))
        .transport_config(transport)
        .addr_filter(address_filter);
    if !config.bind_addresses.is_empty() {
        builder = builder.clear_ip_transports();
        for address in &config.bind_addresses {
            builder = builder.bind_addr(*address)?;
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
    local_id: EndpointId,
    endpoint: Endpoint,
    alpn: Arc<Vec<u8>>,
    probe_alpn: Arc<Vec<u8>>,
    inherited_relays: Vec<RelayUrl>,
    trace_responder: Option<Arc<TraceResponder>>,
    derp_transport: Option<Arc<DerpTransport>>,
    mesh: Arc<MeshRuntime>,
    peers: Arc<RwLock<HashMap<EndpointId, Arc<Peer>>>>,
    peer_counters: Arc<StdRwLock<HashMap<EndpointId, Arc<PeerCounters>>>>,
    inbound_packets: mpsc::Sender<InboundPacket>,
    capacity_events: mpsc::Sender<CapacityEvent>,
    planner: Mutex<MeshPlanner>,
    probe_cursor: Mutex<usize>,
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
        probe_alpn: Arc<Vec<u8>>,
        inherited_relays: Vec<RelayUrl>,
        trace_responder: Option<Arc<TraceResponder>>,
        derp_transport: Option<Arc<DerpTransport>>,
        mesh: Arc<MeshRuntime>,
        peers: Arc<RwLock<HashMap<EndpointId, Arc<Peer>>>>,
        peer_counters: Arc<StdRwLock<HashMap<EndpointId, Arc<PeerCounters>>>>,
        inbound_packets: mpsc::Sender<InboundPacket>,
        capacity_events: mpsc::Sender<CapacityEvent>,
    ) -> Result<Arc<Self>> {
        let planner = MeshPlanner::new(
            config.mesh.max_peers,
            config.peers.iter().map(|peer| peer.endpoint_id),
        )?;
        Ok(Arc::new(Self {
            config: config.clone(),
            local_id,
            endpoint,
            alpn,
            probe_alpn,
            inherited_relays,
            trace_responder,
            derp_transport,
            mesh,
            peers,
            peer_counters,
            inbound_packets,
            capacity_events,
            planner: Mutex::new(planner),
            probe_cursor: Mutex::new(0),
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
                    let (direct_path, _, direct_diversity) = presence_path(presence)?;
                    let (path, diversity_key) = match active
                        .peer
                        .counters
                        .selected_path_transport
                        .load(Ordering::Relaxed)
                    {
                        1 => (direct_path, direct_diversity),
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
            // Both endpoints probe. Coordinated outbound traffic is required
            // to open two NAT mappings; only the canonical lower EndpointId
            // will later activate the durable adjacency.
            .filter(|presence| !dynamic_ids.contains(&presence.body.owner))
            .filter(|presence| !pinned.contains(&presence.body.owner))
            .filter(|presence| presence_path(presence).is_some())
            .cloned()
            .collect::<Vec<_>>();
        candidates.sort_by_key(|presence| presence.body.owner);
        let probe_batch = if candidates.is_empty() {
            Vec::new()
        } else {
            let mut cursor = self.probe_cursor.lock().await;
            *cursor %= candidates.len();
            let batch = (0..candidates.len().min(CANDIDATES_PER_ROUND))
                .map(|offset| candidates[(*cursor + offset) % candidates.len()].clone())
                .collect::<Vec<_>>();
            *cursor = (*cursor + batch.len()) % candidates.len();
            batch
        };
        let probe_observations = futures_util::stream::iter(probe_batch)
            .map(|presence| async move {
                let endpoint_id = presence.body.owner;
                let transit_enabled = presence.body.transit_enabled;
                match self
                    .mesh
                    .probe_candidate(&presence, self.probe_alpn.as_slice())
                    .await
                {
                    Ok((rtt, address)) => ProbeObservation {
                        endpoint_id,
                        path: if address.is_ipv6() {
                            PathKind::DirectIpv6
                        } else {
                            PathKind::DirectIpv4
                        },
                        rtt,
                        loss_ppm: 0,
                        diversity_key: diversity_key(address),
                        transit_enabled,
                        observed_at: Instant::now(),
                    },
                    Err(error) => {
                        debug!(%endpoint_id, %error, "mesh candidate probe failed");
                        ProbeObservation {
                            endpoint_id,
                            path: PathKind::Unreachable,
                            rtt: Duration::from_secs(3),
                            loss_ppm: 1_000_000,
                            diversity_key: presence
                                .body
                                .direct_addresses
                                .first()
                                .copied()
                                .map(diversity_key)
                                .unwrap_or_default(),
                            transit_enabled,
                            observed_at: Instant::now(),
                        }
                    }
                }
            })
            .buffer_unordered(PROBE_CONCURRENCY)
            .collect::<Vec<_>>()
            .await;

        let mut planner = self.planner.lock().await;
        for observation in active_observations.into_iter().chain(probe_observations) {
            planner.observe(observation);
        }
        let eligible = presences
            .iter()
            .filter(|presence| !unhealthy_ids.contains(&presence.body.owner))
            // Only the lower EndpointId initiates the canonical connection.
            // The other side creates its bounded adjacency in accept_unknown.
            .filter(|presence| {
                self.local_id < presence.body.owner || dynamic_ids.contains(&presence.body.owner)
            })
            .filter(|presence| presence_path(presence).is_some())
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
            if let Err(error) = self.create_dynamic(presence.clone(), None).await {
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
            presence_path(&presence).is_some(),
            "dynamic endpoint has no usable direct candidate"
        );
        let _admission = self.admission_lock.lock().await;
        ensure!(
            self.peers.read().await.len() < self.config.mesh.max_peers,
            "bounded mesh peer limit reached"
        );
        self.create_dynamic(presence, Some(connection)).await?;
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
    ) -> Result<()> {
        let endpoint_id = presence.body.owner;
        if let Some(peer) = self.peers.read().await.get(&endpoint_id).cloned() {
            if let Some(connection) = connection {
                peer.install_connection(connection).await?;
            }
            return Ok(());
        }
        ensure!(
            self.peers.read().await.len() < self.config.mesh.max_peers,
            "bounded mesh peer limit reached"
        );
        let peer_config = presence_peer_config(&presence);
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
            && let Err(error) = peer.install_connection(connection).await
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

fn presence_peer_config(presence: &SignedPresence) -> PeerConfig {
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
        relay_urls: presence.body.relay_urls.clone(),
        derp_public_key: presence.body.derp_public_key,
        allowed_source_prefixes: presence.body.prefixes.clone(),
    }
}

fn presence_path(presence: &SignedPresence) -> Option<(PathKind, Duration, String)> {
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
    inbound_packets: mpsc::Sender<InboundPacket>,
    capacity_events: mpsc::Sender<CapacityEvent>,
    connection: Mutex<Option<Connection>>,
    dial_lock: Mutex<()>,
    connection_ready: Notify,
    reconnect_needed: Notify,
    shutdown_ready: Notify,
    shutting_down: AtomicBool,
    refresh_requested: AtomicBool,
    direct_probe_requested: AtomicBool,
    relay_bootstrap_started: AtomicBool,
    last_direct_probe: Mutex<Option<Instant>>,
    discovered_direct_addresses: Mutex<HashSet<std::net::SocketAddr>>,
    dial_outbound: bool,
    connection_mode: ConnectionMode,
    relay_bootstrap_enabled: bool,
    candidate_exchange_enabled: bool,
    trace_responder: Option<Arc<TraceResponder>>,
    enforce_overlay_prefixes: bool,
    transit_enabled: bool,
    overlay_prefixes: Arc<Vec<IpNet>>,
    local_prefixes: Arc<Vec<IpNet>>,
    remote_prefixes: Arc<Vec<IpNet>>,
    allowed_source_prefixes: Arc<Vec<IpNet>>,
    forbidden_underlay_prefixes: Arc<Vec<IpNet>>,
    next_packet_id: AtomicU64,
    reassembler: Mutex<Reassembler>,
    repair_cache: Mutex<RepairCache>,
    reassembly_buffer_limit: usize,
    repair_buffer_limit: usize,
    outbound: Arc<OutboundQueue>,
    counters: Arc<PeerCounters>,
    link_estimator: StdRwLock<LinkEstimator>,
    path_epoch: AtomicU64,
    selected_path_fingerprint: StdRwLock<String>,
    frame_size_ceiling: usize,
    effective_frame_size: AtomicU64,
    fec_encoder: Option<Mutex<FecEncoder>>,
    fec_decoder: Mutex<FecDecoder>,
    derp_transport: Option<Arc<DerpTransport>>,
    mesh_runtime: Option<Arc<MeshRuntime>>,
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
    inbound_packets: mpsc::Sender<InboundPacket>,
    capacity_events: mpsc::Sender<CapacityEvent>,
}

impl Peer {
    fn can_dial(&self) -> bool {
        self.connection_mode != ConnectionMode::Inbound
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

        let mut endpoint_addr = EndpointAddr::new(peer.endpoint_id);
        for addr in &peer.direct_addresses {
            endpoint_addr = endpoint_addr.with_ip_addr(*addr);
        }
        if peer.relay_urls.is_empty() {
            for relay in services.inherited_relays {
                endpoint_addr = endpoint_addr.with_relay_url(relay.clone());
            }
        } else {
            for relay in &peer.relay_urls {
                endpoint_addr = endpoint_addr.with_relay_url(relay.parse()?);
            }
        }
        if let (Some(transport), Some(public_key)) = (services.derp_transport, peer.derp_public_key)
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
            config.node_interface.clone(),
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
                .map(Mutex::new)
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
            .then(|| MESH_BUFFER_POOL_BUDGET_BYTES / config.mesh.max_peers.max(1));
        let outbound = Arc::new(if let Some(per_peer) = mesh_pool_per_peer {
            // Reserve the global queue budget against the configured worst
            // case. Pinned and automatic adjacencies count against the same
            // ceiling, so growing the mesh cannot grow queue memory beyond
            // the process-wide bound.
            OutboundQueue::with_max_bytes(counters.clone(), OUTBOUND_QUEUE_BYTES.min(per_peer))
        } else {
            OutboundQueue::new(counters.clone())
        });
        let reassembly_buffer_limit =
            mesh_pool_per_peer.map_or(32 * 1024 * 1024, |limit| limit.min(32 * 1024 * 1024));
        let repair_buffer_limit =
            mesh_pool_per_peer.map_or(16 * 1024 * 1024, |limit| limit.min(16 * 1024 * 1024));
        let fec_buffer_limit =
            mesh_pool_per_peer.map_or(32 * 1024 * 1024, |limit| limit.min(32 * 1024 * 1024));
        Ok(Self {
            name: peer.name.clone(),
            endpoint_id: peer.endpoint_id,
            route_id: route_id(peer.endpoint_id),
            declared_transit_enabled: peer.transit_enabled,
            endpoint_addr,
            endpoint,
            alpn,
            inbound_packets: services.inbound_packets,
            capacity_events: services.capacity_events,
            connection: Mutex::new(None),
            dial_lock: Mutex::new(()),
            connection_ready: Notify::new(),
            reconnect_needed: Notify::new(),
            shutdown_ready: Notify::new(),
            shutting_down: AtomicBool::new(false),
            refresh_requested: AtomicBool::new(false),
            direct_probe_requested: AtomicBool::new(false),
            relay_bootstrap_started: AtomicBool::new(false),
            last_direct_probe: Mutex::new(None),
            discovered_direct_addresses: Mutex::new(HashSet::new()),
            dial_outbound,
            connection_mode,
            relay_bootstrap_enabled: config.discovery_enabled
                && (!config.relay.urls.is_empty() || !peer.relay_urls.is_empty()),
            candidate_exchange_enabled: config.discovery_enabled,
            trace_responder: services.trace_responder,
            enforce_overlay_prefixes: config.packet_policy.enforce_overlay_prefixes,
            transit_enabled: config.routing.transit_enabled,
            overlay_prefixes: Arc::new(config.all_overlay_prefixes().collect()),
            local_prefixes: Arc::new(config.all_advertised_prefixes().collect()),
            remote_prefixes: Arc::new(config.all_remote_prefixes().collect()),
            allowed_source_prefixes: Arc::new(peer.allowed_source_prefixes.clone()),
            forbidden_underlay_prefixes: Arc::new(underlay_exclusion_prefixes(config)),
            next_packet_id: AtomicU64::new(1),
            reassembler: Mutex::new(Reassembler::with_max_buffered_bytes(
                reassembly_buffer_limit,
            )),
            repair_cache: Mutex::new(RepairCache::with_max_bytes(repair_buffer_limit)),
            reassembly_buffer_limit,
            repair_buffer_limit,
            outbound,
            counters,
            link_estimator: StdRwLock::new(LinkEstimator::default()),
            path_epoch: AtomicU64::new(0),
            selected_path_fingerprint: StdRwLock::new(String::new()),
            frame_size_ceiling,
            effective_frame_size: AtomicU64::new(effective_frame_size as u64),
            fec_encoder,
            fec_decoder: Mutex::new(FecDecoder::with_max_buffered_bytes(
                Duration::from_millis(config.fec.decoder_ttl_millis),
                fec_buffer_limit,
            )?),
            derp_transport: services.derp_transport.cloned(),
            mesh_runtime: services.mesh_runtime,
        })
    }

    async fn queue_to_network(self: Arc<Self>) -> Result<()> {
        let mut suspended_bulk = None::<TransmissionJob>;
        let mut next_item = None::<OutboundItem>;

        loop {
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
                if let Some(urgent) = self.outbound.try_pop_urgent(queue_max_age).await {
                    suspended_bulk = Some(job);
                    TransmissionWork::Item(urgent)
                } else {
                    TransmissionWork::Job(job)
                }
            } else {
                TransmissionWork::Item(self.outbound.pop_for_network(queue_max_age).await)
            };

            let connection = match self.connection().await {
                Ok(connection) => connection,
                Err(error) => {
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
            };
            if let Some((address, prefix)) =
                forbidden_selected_path(&connection, &self.forbidden_underlay_prefixes)
            {
                warn!(peer = %self.name, %address, %prefix, "closing connection on forbidden underlay path");
                connection.close(2_u8.into(), b"forbidden underlay path");
                self.requeue_work(work).await;
                self.clear_connection(connection.stable_id()).await;
                continue;
            }

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
                                self.outbound.push_control(datagram).await;
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
                                self.outbound.push_probe(datagram).await;
                            }
                            continue;
                        }
                    };
                    let Some(path_maximum) = connection.max_datagram_size() else {
                        warn!(peer = %self.name, "peer does not support QUIC datagrams");
                        self.outbound.push(first).await;
                        self.clear_connection(connection.stable_id()).await;
                        continue;
                    };
                    let automatic = self.effective_frame_size.load(Ordering::Relaxed) as usize;
                    let maximum = path_maximum
                        .min(self.frame_size_ceiling)
                        .min(automatic.max(256));
                    let Some(job) = self
                        .encode_transmission(first, &connection, maximum, queue_max_age)
                        .await?
                    else {
                        continue;
                    };
                    job
                }
            };
            match self
                .send_transmission(&connection, &mut job, queue_max_age)
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
                    if let Some(encoder) = &self.fec_encoder {
                        let unprotected = encoder.lock().await.reset();
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
        connection: &Connection,
        maximum: usize,
        queue_max_age: Duration,
    ) -> Result<Option<TransmissionJob>> {
        // DERP already carries every QUIC packet over an ordered, reliable
        // TCP/TLS byte stream. Adding recovery shards there cannot repair
        // underlay loss; it only consumes the QUIC congestion window and can
        // head-of-line-block newer systematic datagrams.
        let selected_is_derp = connection
            .paths()
            .iter()
            .find(|path| path.is_selected())
            .map(|path| is_derp_transport(path.remote_addr()));
        let fec_active = self.fec_encoder.is_some()
            && selected_is_derp
                .map(|is_derp| !is_derp)
                .unwrap_or(self.derp_transport.is_none());
        if !fec_active && let Some(encoder) = &self.fec_encoder {
            let unprotected = encoder.lock().await.reset();
            self.counters
                .fec_unprotected_shards
                .fetch_add(unprotected, Ordering::Relaxed);
        }
        let inner_maximum = if fec_active {
            match FecEncoder::inner_frame_limit(maximum) {
                Ok(value) => value,
                Err(error) => {
                    warn!(peer = %self.name, maximum, %error, "FEC leaves no overlay frame capacity");
                    self.outbound.push(first).await;
                    return Ok(None);
                }
            }
        } else {
            maximum
        };

        let packet_id = self.next_packet_id.fetch_add(1, Ordering::Relaxed);
        let frames = match encode_packet_tagged(
            &first.data,
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
        }
        self.repair_cache.lock().await.insert(packet_id, &frames);

        let latency_sensitive = first.latency_sensitive;
        let mut packets = vec![first];
        let mut packet_count = 1_u64;
        let mut packet_bytes = packets[0].data.len() as u64;
        let mut wire_frames = frames;
        if wire_frames.len() == 1 && packets[0].data.len() <= SMALL_PACKET_LIMIT {
            let aggregation_delay = self.outbound.aggregation_delay().await;
            self.counters.aggregation_delay_micros.store(
                aggregation_delay.as_micros().min(u128::from(u64::MAX)) as u64,
                Ordering::Relaxed,
            );
            if !aggregation_delay.is_zero() {
                tokio::time::sleep(aggregation_delay).await;
            }
            let mut batch_len = 10 + 2 + wire_frames[0].len();
            while let Some(remaining) =
                inner_maximum.checked_sub(batch_len + 2 + MAX_PACKET_FRAME_HEADER_LEN)
            {
                let Some(packet) = self
                    .outbound
                    .try_pop_small_class(
                        latency_sensitive,
                        remaining.min(SMALL_PACKET_LIMIT),
                        queue_max_age,
                    )
                    .await
                else {
                    break;
                };
                let packet_id = self.next_packet_id.fetch_add(1, Ordering::Relaxed);
                let frame = encode_packet_tagged(
                    &packet.data,
                    inner_maximum,
                    packet_id,
                    packet.delivery_tag,
                )?;
                debug_assert_eq!(frame.len(), 1);
                batch_len += 2 + frame[0].len();
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
            let encoder = self
                .fec_encoder
                .as_ref()
                .expect("active FEC has an encoder");
            let mut encoder = encoder.lock().await;
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
    ) -> TransmissionOutcome {
        while let Some(datagram) = job.datagrams.pop_front() {
            let frame = datagram.bytes;
            if connection
                .max_datagram_size()
                .is_some_and(|maximum| frame.len() > maximum)
            {
                return TransmissionOutcome::Reframe;
            }
            self.counters.quic_send_buffer_used_bytes.store(
                QUIC_SEND_BUFFER_BYTES.saturating_sub(connection.datagram_send_buffer_space())
                    as u64,
                Ordering::Relaxed,
            );
            if let Err(error) = connection.send_datagram_wait(frame).await {
                if error == SendDatagramError::TooLarge {
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
                return TransmissionOutcome::Failed;
            }
            if datagram.recovery {
                self.counters
                    .fec_tx_recovery_shards
                    .fetch_add(1, Ordering::Relaxed);
            }
            if !job.latency_sensitive
                && !job.datagrams.is_empty()
                && let Some(urgent) = self.outbound.try_pop_urgent(queue_max_age).await
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
            self.outbound.push(packet).await;
        }
    }

    async fn requeue_work(&self, work: TransmissionWork) {
        match work {
            TransmissionWork::Item(item) => self.outbound.requeue(item).await,
            TransmissionWork::Job(job) => self.requeue_transmission(job).await,
        }
    }

    async fn maintain_connection(self: Arc<Self>) -> Result<()> {
        if !self.can_dial() {
            pending::<()>().await;
            return Ok(());
        }
        loop {
            if self.connection.lock().await.is_none()
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
            if self.direct_probe_requested.swap(false, Ordering::Relaxed) {
                if let Err(error) = self.refresh_direct_connection().await {
                    debug!(peer = %self.name, %error, "direct underlay probe did not establish a connection");
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
            .endpoint
            .connect(endpoint_addr, self.alpn.as_slice())
            .await
            .with_context(|| format!("failed refreshing peer {}", self.name))?;
        self.install_connection(connection).await
    }

    async fn request_direct_probe(self: &Arc<Self>) {
        // Only the deterministic dialer creates the replacement connection.
        // If both sides refresh simultaneously they can install different
        // selected paths during the hold-down boundary and briefly black-hole
        // the otherwise healthy relay connection.
        if !self.can_dial() {
            return;
        }
        // A relay-only peer has nowhere direct to probe. In particular, a
        // custom DERP address in iroh's remote-info cache is not a direct
        // candidate. Asking iroh to refresh with it can disturb the only open
        // path and cause a needless liveness reconnect.
        let has_configured_direct = self.endpoint_addr.ip_addrs().next().is_some();
        let has_discovered_direct = !self.discovered_direct_addresses.lock().await.is_empty();
        if !has_configured_direct && !has_discovered_direct {
            return;
        }
        let cooldown = if self.endpoint_addr.ip_addrs().next().is_some() {
            RELAY_HOLD_DOWN
        } else {
            DISCOVERED_DIRECT_PROBE_COOLDOWN
        };
        let mut last = self.last_direct_probe.lock().await;
        if last.is_some_and(|instant| instant.elapsed() < cooldown) {
            return;
        }
        *last = Some(Instant::now());
        drop(last);
        info!(peer = %self.name, "probing direct underlay after relay hold-down");
        self.direct_probe_requested.store(true, Ordering::Relaxed);
        self.reconnect_needed.notify_one();
    }

    async fn refresh_direct_connection(self: &Arc<Self>) -> Result<()> {
        let resolved = self.dial_addr().await;
        let direct_addresses = resolved.ip_addrs().copied().collect::<Vec<_>>();
        if direct_addresses.is_empty() {
            bail!("no safe direct address was discovered");
        }
        let mut endpoint_addr = EndpointAddr::new(self.endpoint_id);
        for address in &direct_addresses {
            endpoint_addr = endpoint_addr.with_ip_addr(*address);
        }
        let result = tokio::time::timeout(
            Duration::from_secs(4),
            self.endpoint.connect(endpoint_addr, self.alpn.as_slice()),
        )
        .await;
        let connection = result
            .context("direct underlay probe timed out")?
            .context("direct underlay probe failed")?;
        let selected_configured_direct = connection.paths().iter().any(|path| {
            path.is_selected()
                && matches!(
                    path.remote_addr(),
                    TransportAddr::Ip(address) if direct_addresses.contains(address)
                )
        });
        if !selected_configured_direct {
            connection.close(7_u8.into(), b"direct probe did not use configured address");
            bail!("direct underlay probe resolved through a non-configured path");
        }
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
                .connection
                .lock()
                .await
                .as_ref()
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
        endpoint_addr
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
        let selected_relay = self
            .connection
            .lock()
            .await
            .as_ref()
            .is_some_and(|connection| {
                connection
                    .paths()
                    .iter()
                    .any(|path| path.is_selected() && is_relay_transport(path.remote_addr()))
            });
        if selected_relay {
            self.request_direct_probe().await;
        }
    }

    async fn connection(self: &Arc<Self>) -> Result<Connection> {
        loop {
            // Register the waiter before checking the slot so an inbound
            // install cannot race between the check and the await.
            let notified = self.connection_ready.notified();
            if let Some(connection) = self.connection.lock().await.as_ref().cloned() {
                if let Some((address, prefix)) =
                    forbidden_selected_path(&connection, &self.forbidden_underlay_prefixes)
                {
                    connection.close(2_u8.into(), b"forbidden underlay path");
                    self.clear_connection(connection.stable_id()).await;
                    bail!(
                        "peer {} selected forbidden underlay address {address} in {prefix}",
                        self.name
                    );
                }
                return Ok(connection);
            }
            if self.can_dial()
                && (self.dial_outbound || self.connection_mode == ConnectionMode::Outbound)
            {
                break;
            }
            if self.connection_mode == ConnectionMode::Canonical {
                if tokio::time::timeout(BOOTSTRAP_FALLBACK_DELAY, notified)
                    .await
                    .is_err()
                {
                    info!(peer = %self.name, "no reciprocal bootstrap entry observed; dialing configured peer");
                    break;
                }
            } else {
                tokio::time::timeout(Duration::from_secs(15), notified)
                    .await
                    .with_context(|| format!("timed out waiting for inbound peer {}", self.name))?;
            }
        }
        let _dial_guard = self.dial_lock.lock().await;
        if let Some(connection) = self.connection.lock().await.as_ref().cloned() {
            return Ok(connection);
        }
        let endpoint_addr = self.dial_addr().await;
        let connection = self
            .endpoint
            .connect(endpoint_addr, self.alpn.as_slice())
            .await
            .with_context(|| format!("failed connecting to peer {}", self.name))?;
        self.install_connection(connection.clone()).await?;
        Ok(connection)
    }

    async fn install_connection(self: &Arc<Self>, connection: Connection) -> Result<()> {
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
        let mut slot = self.connection.lock().await;
        if self.connection_mode == ConnectionMode::Canonical
            && connection.side() != canonical_side
            && slot
                .as_ref()
                .is_some_and(|current| current.side() == canonical_side)
        {
            connection.close(0_u8.into(), b"canonical connection already active");
            return Ok(());
        }
        let old = slot.replace(connection.clone());
        drop(slot);
        if let Some(encoder) = &self.fec_encoder {
            let unprotected = encoder.lock().await.reset();
            self.counters
                .fec_unprotected_shards
                .fetch_add(unprotected, Ordering::Relaxed);
        }
        self.fec_decoder.lock().await.reset();
        *self.reassembler.lock().await =
            Reassembler::with_max_buffered_bytes(self.reassembly_buffer_limit);
        *self.repair_cache.lock().await = RepairCache::with_max_bytes(self.repair_buffer_limit);
        if let Some(old) = old
            && old.stable_id() != connection.stable_id()
        {
            old.close(0_u8.into(), b"replaced");
        }
        info!(peer = %self.name, "peer connection active");
        self.counters.connected.store(true, Ordering::Relaxed);
        self.counters
            .connection_events
            .fetch_add(1, Ordering::Relaxed);
        self.connection_ready.notify_waiters();
        if let Some(mesh_runtime) = self.mesh_runtime.clone() {
            let control_connection = connection.clone();
            let endpoint_id = self.endpoint_id;
            tokio::spawn(async move {
                if let Err(error) = mesh_runtime
                    .run_connection(control_connection, endpoint_id)
                    .await
                {
                    debug!(peer = %endpoint_id, %error, "mesh control loop ended");
                }
            });
        }
        if !self.relay_bootstrap_started.swap(true, Ordering::Relaxed) {
            tokio::spawn(self.clone().bootstrap_relay_path());
        }
        let last_overlay_receive = Arc::new(Mutex::new(Instant::now()));
        let overlay_receive_confirmed = Arc::new(AtomicBool::new(false));
        let peer = self.clone();
        let receive_connection = connection.clone();
        let receive_activity = last_overlay_receive.clone();
        let receive_confirmed = overlay_receive_confirmed.clone();
        tokio::spawn(async move {
            let stable_id = receive_connection.stable_id();
            let mut repair_tick = tokio::time::interval(Duration::from_millis(10));
            repair_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut repair_budget = 64_usize;
            let mut repair_refill = Instant::now() + Duration::from_secs(1);
            loop {
                tokio::select! {
                    result = receive_connection.read_datagram() => match result {
                    Ok(datagram) => {
                        if let Some((address, prefix)) = forbidden_selected_path(
                            &receive_connection,
                            &peer.forbidden_underlay_prefixes,
                        ) {
                            warn!(peer = %peer.name, %address, %prefix, "closing connection on forbidden underlay path");
                            receive_connection.close(2_u8.into(), b"forbidden underlay path");
                            break;
                        }
                        let decoded = match peer.fec_decoder.lock().await.push(datagram) {
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
                            *receive_activity.lock().await = Instant::now();
                            receive_confirmed.store(true, Ordering::Relaxed);
                            match wire {
                            WireDatagram::Frames(frames) => {
                                peer.counters
                                    .rx_fragments
                                    .fetch_add(frames.len() as u64, Ordering::Relaxed);
                                for frame in frames {
                                    let (result, evictions) = {
                                        let mut reassembler = peer.reassembler.lock().await;
                                        let result = reassembler.push_tagged(&frame);
                                        let evictions = reassembler.take_evictions();
                                        (result, evictions)
                                    };
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
                                let frames = peer.repair_cache.lock().await.get(&request);
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
                        let requests = peer
                            .reassembler
                            .lock()
                            .await
                            .repair_requests(delay, repair_budget);
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
        let peer = self.clone();
        let heartbeat_connection = connection.clone();
        tokio::spawn(async move {
            let stable_id = heartbeat_connection.stable_id();
            let mut heartbeat = tokio::time::interval(OVERLAY_HEARTBEAT_INTERVAL);
            heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut last_udp_rx = heartbeat_connection.stats().udp_rx.datagrams;
            let mut last_transport_receive = Instant::now();
            let mut next_address_advertisement = Instant::now();
            heartbeat.tick().await;
            loop {
                heartbeat.tick().await;
                let is_current = !peer.shutting_down.load(Ordering::Acquire)
                    && peer
                        .connection
                        .lock()
                        .await
                        .as_ref()
                        .is_some_and(|current| current.stable_id() == stable_id);
                if !is_current {
                    break;
                }
                let udp_rx = heartbeat_connection.stats().udp_rx.datagrams;
                if udp_rx != last_udp_rx {
                    last_udp_rx = udp_rx;
                    last_transport_receive = Instant::now();
                }
                let overlay_silence = last_overlay_receive.lock().await.elapsed();
                let transport_silence = last_transport_receive.elapsed();
                let liveness_timeout = if overlay_receive_confirmed.load(Ordering::Relaxed)
                    || peer.counters.connection_events.load(Ordering::Relaxed) > 1
                {
                    OVERLAY_LIVENESS_TIMEOUT
                } else {
                    INITIAL_OVERLAY_LIVENESS_TIMEOUT
                };
                // QUIC DATAGRAM is intentionally unreliable. Do not replace a
                // healthy connection just because several application
                // heartbeats were discarded while ACKs and path probes were
                // still arriving. A genuine one-way NAT black hole stops both
                // application frames and all UDP/QUIC transport activity.
                if liveness_expired(overlay_silence, transport_silence, liveness_timeout) {
                    let is_current = peer
                        .connection
                        .lock()
                        .await
                        .as_ref()
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
                if Instant::now() >= next_address_advertisement {
                    next_address_advertisement = Instant::now() + Duration::from_secs(5);
                    let addresses = peer.local_address_candidates();
                    if !addresses.is_empty()
                        && let Ok(datagram) = encode_address_candidates(&addresses)
                    {
                        let _ = tokio::time::timeout(
                            Duration::from_secs(1),
                            heartbeat_connection.send_datagram_wait(datagram),
                        )
                        .await;
                    }
                }
            }
        });
        let peer = self.clone();
        tokio::spawn(async move {
            let stable_id = connection.stable_id();
            let mut paths = connection.paths_stream();
            let mut telemetry = tokio::time::interval(Duration::from_secs(1));
            telemetry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let mut frame_sizer = AdaptiveFrameSizer::new(peer.frame_size_ceiling);
            let mut relay_selected_since = None;
            loop {
                tokio::select! {
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
                    }
                    _ = telemetry.tick() => {
                        let snapshot = connection.paths();
                        let Some(path) = snapshot.iter().find(|path| path.is_selected()) else {
                            continue;
                        };
                        let stats = path.stats();
                        if is_relay_transport(path.remote_addr()) {
                            let selected_since = relay_selected_since.get_or_insert_with(Instant::now);
                            if selected_since.elapsed() >= RELAY_HOLD_DOWN {
                                peer.request_direct_probe().await;
                                relay_selected_since = Some(Instant::now());
                            }
                        } else {
                            relay_selected_since = None;
                        }
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
        packet: Vec<u8>,
        delivery_tag: Option<DeliveryTag>,
    ) -> Result<()> {
        let packet_info = match inspect_ip_packet(&packet) {
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
        if !self.packet_allowed(packet_info.source, packet_info.destination, true) {
            if should_log(&self.counters.policy_drops) {
                warn!(
                    peer = %self.name,
                    source = %packet_info.source,
                    destination = %packet_info.destination,
                    policy_drops = self.counters.policy_drops.load(Ordering::Relaxed),
                    "dropping inbound packet rejected by overlay or adjacency source policy"
                );
            }
            return Ok(());
        }
        if let Some(responder) = &self.trace_responder {
            match responder.handle_packet(&packet).await {
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
        self.counters.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.counters
            .rx_bytes
            .fetch_add(packet.len() as u64, Ordering::Relaxed);
        self.inbound_packets
            .send(InboundPacket {
                peer_id: self.endpoint_id,
                packet,
                delivery_tag,
            })
            .await
            .context("inbound FlowRouter queue closed")?;
        Ok(())
    }

    async fn clear_connection(&self, stable_id: usize) {
        let mut connection = self.connection.lock().await;
        if connection
            .as_ref()
            .is_some_and(|current| current.stable_id() == stable_id)
        {
            connection.take();
            self.mark_disconnected();
            if !self.shutting_down.load(Ordering::Acquire) {
                self.reconnect_needed.notify_one();
            }
        }
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
        source: std::net::IpAddr,
        destination: std::net::IpAddr,
        inbound: bool,
    ) -> bool {
        packet_allowed(
            PacketPolicy {
                enforce_overlay_prefixes: self.enforce_overlay_prefixes,
                transit_enabled: self.transit_enabled,
                overlay_prefixes: &self.overlay_prefixes,
                local_prefixes: &self.local_prefixes,
                remote_prefixes: &self.remote_prefixes,
                allowed_source_prefixes: &self.allowed_source_prefixes,
                mesh_runtime: self.mesh_runtime.as_deref(),
                peer_id: self.endpoint_id,
            },
            source,
            destination,
            inbound,
        )
    }

    async fn close(&self) {
        self.shutting_down.store(true, Ordering::Release);
        if let Some(connection) = self.connection.lock().await.take() {
            connection.close(0_u8.into(), b"shutdown");
        }
        self.mark_disconnected();
        self.connection_ready.notify_waiters();
        self.reconnect_needed.notify_waiters();
        self.shutdown_ready.notify_waiters();
    }
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

fn is_relay_transport(address: &TransportAddr) -> bool {
    match address {
        TransportAddr::Relay(_) => true,
        TransportAddr::Custom(custom) => DerpAddr::from_custom(custom).is_ok(),
        _ => false,
    }
}

fn is_derp_transport(address: &TransportAddr) -> bool {
    matches!(address, TransportAddr::Custom(custom) if DerpAddr::from_custom(custom).is_ok())
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
    overlay_silence >= timeout && transport_silence >= timeout
}

#[derive(Clone, Copy)]
struct PacketPolicy<'a> {
    enforce_overlay_prefixes: bool,
    transit_enabled: bool,
    overlay_prefixes: &'a [IpNet],
    local_prefixes: &'a [IpNet],
    remote_prefixes: &'a [IpNet],
    allowed_source_prefixes: &'a [IpNet],
    mesh_runtime: Option<&'a MeshRuntime>,
    peer_id: EndpointId,
}

fn packet_allowed(
    policy: PacketPolicy<'_>,
    source: std::net::IpAddr,
    destination: std::net::IpAddr,
    inbound: bool,
) -> bool {
    let remote_destination = policy
        .remote_prefixes
        .iter()
        .any(|prefix| prefix.contains(&destination))
        || policy
            .mesh_runtime
            .is_some_and(|mesh| mesh.remote_overlay_address_known(destination));
    if inbound
        && !policy.transit_enabled
        && !policy
            .local_prefixes
            .iter()
            .any(|prefix| prefix.contains(&destination))
        && remote_destination
    {
        return false;
    }
    if !policy.enforce_overlay_prefixes {
        return true;
    }
    let contains = |address| {
        policy
            .overlay_prefixes
            .iter()
            .any(|prefix| prefix.contains(&address))
            || policy
                .mesh_runtime
                .is_some_and(|mesh| mesh.overlay_address_known(address))
    };
    contains(source)
        && contains(destination)
        && (!inbound
            || policy
                .allowed_source_prefixes
                .iter()
                .any(|prefix| prefix.contains(&source))
            || policy
                .mesh_runtime
                .is_some_and(|mesh| mesh.source_allowed_from(policy.peer_id, source)))
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

    fn endpoint(byte: u8) -> EndpointId {
        SecretKey::from_bytes(&[byte; 32]).public()
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
    fn transit_delivery_binding_is_kept_alive_by_tagged_data() {
        let origin = endpoint(56);
        let transit = endpoint(57);
        let destination = endpoint(58);
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
            urls: Vec::new(),
            servers: vec!["https://derp.example.com".into()],
        };
        assert_eq!(quic_path_idle_timeout(&derp), DERP_PATH_IDLE_TIMEOUT);
        assert_eq!(
            quic_path_idle_timeout(&RelayConfig::default()),
            QUIC_PATH_IDLE_TIMEOUT
        );
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
        let overlay = local.iter().chain(&remote).copied().collect::<Vec<_>>();
        let allowed = vec!["10.200.0.2/32".parse().unwrap()];
        let policy = PacketPolicy {
            enforce_overlay_prefixes: true,
            transit_enabled: true,
            overlay_prefixes: &overlay,
            local_prefixes: &local,
            remote_prefixes: &remote,
            allowed_source_prefixes: &allowed,
            mesh_runtime: None,
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
    fn non_transit_node_rejects_only_inbound_remote_destinations() {
        let local = vec![
            "10.200.0.2/32".parse().unwrap(),
            "192.168.20.0/24".parse().unwrap(),
        ];
        let remote = vec![
            "10.200.0.1/32".parse().unwrap(),
            "10.200.0.3/32".parse().unwrap(),
        ];
        let overlay = local.iter().chain(&remote).copied().collect::<Vec<_>>();
        let allowed = vec!["10.200.0.1/32".parse().unwrap()];
        let non_transit_policy = PacketPolicy {
            enforce_overlay_prefixes: true,
            transit_enabled: false,
            overlay_prefixes: &overlay,
            local_prefixes: &local,
            remote_prefixes: &remote,
            allowed_source_prefixes: &allowed,
            mesh_runtime: None,
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
    fn liveness_requires_both_application_and_transport_silence() {
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
}

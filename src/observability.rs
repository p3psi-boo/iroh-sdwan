use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use ipnet::IpNet;
use iroh::EndpointId;
use serde::{Deserialize, Serialize};
use tokio::time;
use tracing::{debug, info, warn};

use crate::{
    capacity::{DEFAULT_ROUTE_ESTIMATE_CAPACITY, RouteEstimateTable, SampleSource},
    capacity_probe::{MAX_PROBE_BYTES, ProbeStatusSnapshot},
    config::ObservabilityConfig,
    mesh::{MeshRuntime, MeshStatus},
};

#[derive(Debug)]
pub struct PeerCounters {
    pub name: String,
    pub endpoint_id: EndpointId,
    pub interface: String,
    pub protocol_major: AtomicU64,
    pub protocol_minor: AtomicU64,
    pub negotiated_features: AtomicU64,
    pub private_link: AtomicBool,
    pub connected: AtomicBool,
    pub connection_events: AtomicU64,
    pub connection_errors: AtomicU64,
    pub tx_packets: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub flow_latency_packets: AtomicU64,
    pub flow_bulk_packets: AtomicU64,
    pub flow_selected_bytes: AtomicU64,
    pub delivery_tagged_packets: AtomicU64,
    pub delivery_header_bytes: AtomicU64,
    pub delivery_registers_sent: AtomicU64,
    pub delivery_reports_sent: AtomicU64,
    pub delivery_control_bytes: AtomicU64,
    pub rx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_fragments: AtomicU64,
    pub rx_fragments: AtomicU64,
    pub fec_tx_recovery_shards: AtomicU64,
    pub fec_rx_recovery_shards: AtomicU64,
    pub fec_recovered_shards: AtomicU64,
    pub fec_unprotected_shards: AtomicU64,
    pub fec_expired_blocks: AtomicU64,
    pub fec_overhead_bytes: AtomicU64,
    pub invalid_packets: AtomicU64,
    pub policy_drops: AtomicU64,
    pub frame_drops: AtomicU64,
    pub send_errors: AtomicU64,
    pub mtu_reframes: AtomicU64,
    pub heartbeats_sent: AtomicU64,
    pub heartbeats_received: AtomicU64,
    pub liveness_reconnects: AtomicU64,
    pub trace_errors: AtomicU64,
    pub queue_packets: AtomicU64,
    pub queue_bytes: AtomicU64,
    pub priority_queue_packets: AtomicU64,
    pub priority_queue_bytes: AtomicU64,
    pub bulk_queue_packets: AtomicU64,
    pub bulk_queue_bytes: AtomicU64,
    pub active_tx_bytes: AtomicU64,
    pub quic_send_buffer_used_bytes: AtomicU64,
    pub bulk_preemptions: AtomicU64,
    pub queue_peak_bytes: AtomicU64,
    pub queue_max_age_micros: AtomicU64,
    pub aggregation_delay_micros: AtomicU64,
    pub tun_mtu: AtomicU64,
    pub queue_drops: AtomicU64,
    pub queue_expired_drops: AtomicU64,
    pub tx_batches: AtomicU64,
    pub tx_batched_packets: AtomicU64,
    pub repair_requests_sent: AtomicU64,
    pub repair_requests_received: AtomicU64,
    pub repair_fragments_sent: AtomicU64,
    pub reassembly_evictions: AtomicU64,
    pub effective_frame_size: AtomicU64,
    pub path_rtt_micros: AtomicU64,
    pub path_jitter_micros: AtomicU64,
    pub path_loss_ppm: AtomicU64,
    pub path_mtu: AtomicU64,
    pub path_cwnd_bytes: AtomicU64,
    pub path_tx_datagrams: AtomicU64,
    pub path_lost_packets: AtomicU64,
    pub selected_path_transport: AtomicU64,
    pub selected_path_remote: RwLock<String>,
    pub open_paths: AtomicU64,
    pub path_switches: AtomicU64,
}

#[derive(Debug, Default)]
pub struct FlowRouterCounters {
    pub active_flows: AtomicU64,
    pub decisions: AtomicU64,
    pub route_switches: AtomicU64,
    pub no_route_drops: AtomicU64,
}

impl PeerCounters {
    pub fn new(name: String, endpoint_id: EndpointId, interface: String) -> Self {
        Self {
            name,
            endpoint_id,
            interface,
            protocol_major: AtomicU64::new(0),
            protocol_minor: AtomicU64::new(0),
            negotiated_features: AtomicU64::new(0),
            private_link: AtomicBool::new(false),
            connected: AtomicBool::new(false),
            connection_events: AtomicU64::new(0),
            connection_errors: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            flow_latency_packets: AtomicU64::new(0),
            flow_bulk_packets: AtomicU64::new(0),
            flow_selected_bytes: AtomicU64::new(0),
            delivery_tagged_packets: AtomicU64::new(0),
            delivery_header_bytes: AtomicU64::new(0),
            delivery_registers_sent: AtomicU64::new(0),
            delivery_reports_sent: AtomicU64::new(0),
            delivery_control_bytes: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_fragments: AtomicU64::new(0),
            rx_fragments: AtomicU64::new(0),
            fec_tx_recovery_shards: AtomicU64::new(0),
            fec_rx_recovery_shards: AtomicU64::new(0),
            fec_recovered_shards: AtomicU64::new(0),
            fec_unprotected_shards: AtomicU64::new(0),
            fec_expired_blocks: AtomicU64::new(0),
            fec_overhead_bytes: AtomicU64::new(0),
            invalid_packets: AtomicU64::new(0),
            policy_drops: AtomicU64::new(0),
            frame_drops: AtomicU64::new(0),
            send_errors: AtomicU64::new(0),
            mtu_reframes: AtomicU64::new(0),
            heartbeats_sent: AtomicU64::new(0),
            heartbeats_received: AtomicU64::new(0),
            liveness_reconnects: AtomicU64::new(0),
            trace_errors: AtomicU64::new(0),
            queue_packets: AtomicU64::new(0),
            queue_bytes: AtomicU64::new(0),
            priority_queue_packets: AtomicU64::new(0),
            priority_queue_bytes: AtomicU64::new(0),
            bulk_queue_packets: AtomicU64::new(0),
            bulk_queue_bytes: AtomicU64::new(0),
            active_tx_bytes: AtomicU64::new(0),
            quic_send_buffer_used_bytes: AtomicU64::new(0),
            bulk_preemptions: AtomicU64::new(0),
            queue_peak_bytes: AtomicU64::new(0),
            queue_max_age_micros: AtomicU64::new(0),
            aggregation_delay_micros: AtomicU64::new(0),
            tun_mtu: AtomicU64::new(0),
            queue_drops: AtomicU64::new(0),
            queue_expired_drops: AtomicU64::new(0),
            tx_batches: AtomicU64::new(0),
            tx_batched_packets: AtomicU64::new(0),
            repair_requests_sent: AtomicU64::new(0),
            repair_requests_received: AtomicU64::new(0),
            repair_fragments_sent: AtomicU64::new(0),
            reassembly_evictions: AtomicU64::new(0),
            effective_frame_size: AtomicU64::new(0),
            path_rtt_micros: AtomicU64::new(0),
            path_jitter_micros: AtomicU64::new(0),
            path_loss_ppm: AtomicU64::new(0),
            path_mtu: AtomicU64::new(0),
            path_cwnd_bytes: AtomicU64::new(0),
            path_tx_datagrams: AtomicU64::new(0),
            path_lost_packets: AtomicU64::new(0),
            selected_path_transport: AtomicU64::new(0),
            selected_path_remote: RwLock::new(String::new()),
            open_paths: AtomicU64::new(0),
            path_switches: AtomicU64::new(0),
        }
    }
}

pub struct RuntimeState {
    endpoint_id: EndpointId,
    started_unix: u64,
    started: time::Instant,
    routing_table: u32,
    required_routes: Vec<IpNet>,
    route_cache: RwLock<Vec<RouteStatus>>,
    routes_ready: AtomicBool,
    peers: Arc<RwLock<HashMap<EndpointId, Arc<PeerCounters>>>>,
    mesh: Option<Arc<MeshRuntime>>,
    capacity: CapacityObservability,
    flow_router: Arc<FlowRouterCounters>,
}

#[derive(Clone)]
pub struct CapacityObservability {
    route_estimates: Arc<RwLock<RouteEstimateTable>>,
    probe_status: Arc<RwLock<ProbeStatusSnapshot>>,
    max_egress_bps: Option<u64>,
}

impl CapacityObservability {
    pub fn new(
        route_estimates: Arc<RwLock<RouteEstimateTable>>,
        probe_status: Arc<RwLock<ProbeStatusSnapshot>>,
        max_egress_bps: Option<u64>,
    ) -> Self {
        Self {
            route_estimates,
            probe_status,
            max_egress_bps,
        }
    }
}

impl RuntimeState {
    pub fn new(
        endpoint_id: EndpointId,
        routing_table: u32,
        required_routes: Vec<IpNet>,
        peers: Arc<RwLock<HashMap<EndpointId, Arc<PeerCounters>>>>,
        mesh: Option<Arc<MeshRuntime>>,
        capacity: CapacityObservability,
        flow_router: Arc<FlowRouterCounters>,
    ) -> Self {
        let routes_ready = required_routes.is_empty();
        let route_cache = required_routes
            .iter()
            .map(|prefix| RouteStatus {
                prefix: prefix.to_string(),
                present: false,
            })
            .collect();
        Self {
            endpoint_id,
            started_unix: unix_now(),
            started: time::Instant::now(),
            routing_table,
            required_routes,
            route_cache: RwLock::new(route_cache),
            routes_ready: AtomicBool::new(routes_ready),
            peers,
            mesh,
            capacity,
            flow_router,
        }
    }

    pub async fn snapshot(&self) -> Result<RuntimeStatus> {
        self.snapshot_inner(true).await
    }

    #[cfg(test)]
    pub(crate) fn flow_router_for_test(&self) -> &Arc<FlowRouterCounters> {
        &self.flow_router
    }

    /// Return current in-memory counters without spawning iproute2. The
    /// reporter owns route-table inspection and refreshes this cached portion.
    pub async fn live_snapshot(&self) -> Result<RuntimeStatus> {
        self.snapshot_inner(false).await
    }

    async fn snapshot_inner(&self, inspect_kernel_routes: bool) -> Result<RuntimeStatus> {
        let mut required_routes = self.required_routes.iter().copied().collect::<HashSet<_>>();
        if let Some(mesh) = &self.mesh {
            required_routes.extend(mesh.remote_prefixes());
        }
        let mut required_routes = required_routes.into_iter().collect::<Vec<_>>();
        required_routes.sort();
        let (routes, routes_ready) = if inspect_kernel_routes {
            let routes = inspect_routes(self.routing_table, &required_routes).await?;
            let routes_ready = routes.iter().all(|route| route.present);
            *self
                .route_cache
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = routes.clone();
            self.routes_ready.store(routes_ready, Ordering::Relaxed);
            (routes, routes_ready)
        } else {
            (
                self.route_cache
                    .read()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone(),
                self.routes_ready.load(Ordering::Relaxed),
            )
        };
        let mesh = match &self.mesh {
            Some(mesh) => mesh.snapshot().await,
            None => MeshStatus::default(),
        };
        let peers = self
            .peers
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let now = Instant::now();
        let (
            mut capacities,
            capacity_probe_in_flight,
            capacity_probe_attempts,
            capacity_probe_failures,
            capacity_probe_bytes,
        ) = {
            let probe_status = self
                .capacity
                .probe_status
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let estimates = self
                .capacity
                .route_estimates
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let capacities = estimates
                .iter()
                .map(|(key, estimate)| {
                    let snapshot = estimate.snapshot(now, self.capacity.max_egress_bps);
                    let probe = probe_status.routes.get(key);
                    RouteCapacityStatus {
                        destination: key.destination.to_string(),
                        first_hop: key.first_hop.to_string(),
                        capacity_bps: snapshot.capacity_bps,
                        effective_capacity_bps: snapshot.effective_capacity_bps,
                        measured_capacity_bps: snapshot.measured_capacity_bps,
                        min_rtt_micros: snapshot.min_rtt.map(duration_micros),
                        rtt_ewma_micros: snapshot.rtt_ewma.map(duration_micros),
                        loss_ppm: snapshot.loss_ppm,
                        health_per_mille: snapshot.health_per_mille,
                        sample_age_millis: snapshot.sample_age.map(duration_millis),
                        freshness: snapshot.freshness.as_str().into(),
                        sample_source: snapshot.last_sample_source.map(|source| match source {
                            SampleSource::Active => "active".into(),
                            SampleSource::Passive => "passive".into(),
                        }),
                        active_samples: snapshot.active_samples,
                        passive_samples: snapshot.passive_samples,
                        route_switches: snapshot.route_switches,
                        path_epoch: snapshot.path_epoch,
                        probe_in_flight: probe.is_some_and(|probe| probe.in_flight),
                        probe_next_due_millis: probe
                            .map(|probe| duration_millis(probe.next_due_in)),
                        probe_failure_count: probe.map_or(0, |probe| probe.failure_count),
                        probe_attempts: probe.map_or(0, |probe| probe.attempts_total),
                        probe_failures: probe.map_or(0, |probe| probe.failures_total),
                        probe_bytes: probe.map_or(0, |probe| probe.bytes_total),
                    }
                })
                .collect::<Vec<_>>();
            (
                capacities,
                probe_status.global_in_flight,
                probe_status.attempts_total,
                probe_status.failures_total,
                probe_status.bytes_total,
            )
        };
        capacities.sort_by(|left, right| {
            (&left.destination, &left.first_hop).cmp(&(&right.destination, &right.first_hop))
        });
        let mut peer_statuses = peers
            .iter()
            .map(|peer| peer_snapshot(peer))
            .collect::<Vec<_>>();
        for peer in &mut peer_statuses {
            peer.capacities = capacities
                .iter()
                .filter(|capacity| capacity.first_hop == peer.endpoint_id)
                .cloned()
                .collect();
        }
        Ok(RuntimeStatus {
            ready: routes_ready
                && peers
                    .iter()
                    .all(|peer| peer.connected.load(Ordering::Relaxed)),
            endpoint_id: self.endpoint_id.to_string(),
            started_unix: self.started_unix,
            updated_unix: unix_now(),
            uptime_seconds: self.started.elapsed().as_secs(),
            routes_ready,
            routes,
            peers: peer_statuses,
            mesh,
            capacities,
            capacity_table_entries: self
                .capacity
                .route_estimates
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            capacity_table_limit: DEFAULT_ROUTE_ESTIMATE_CAPACITY,
            capacity_probe_in_flight,
            capacity_probe_budget_bytes: MAX_PROBE_BYTES,
            capacity_probe_attempts,
            capacity_probe_failures,
            capacity_probe_bytes,
            flow_router: FlowRouterStatus {
                active_flows: self.flow_router.active_flows.load(Ordering::Relaxed),
                max_flows: crate::flow_router::FlowRouterConfig::default().max_flows as u64,
                decisions: self.flow_router.decisions.load(Ordering::Relaxed),
                route_switches: self.flow_router.route_switches.load(Ordering::Relaxed),
                no_route_drops: self.flow_router.no_route_drops.load(Ordering::Relaxed),
            },
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeStatus {
    pub ready: bool,
    pub endpoint_id: String,
    pub started_unix: u64,
    pub updated_unix: u64,
    pub uptime_seconds: u64,
    #[serde(default = "default_true")]
    pub routes_ready: bool,
    #[serde(default)]
    pub routes: Vec<RouteStatus>,
    pub peers: Vec<PeerStatus>,
    #[serde(default)]
    pub mesh: MeshStatus,
    #[serde(default)]
    pub capacities: Vec<RouteCapacityStatus>,
    #[serde(default)]
    pub capacity_table_entries: usize,
    #[serde(default)]
    pub capacity_table_limit: usize,
    #[serde(default)]
    pub capacity_probe_in_flight: bool,
    #[serde(default)]
    pub capacity_probe_budget_bytes: usize,
    #[serde(default)]
    pub capacity_probe_attempts: u64,
    #[serde(default)]
    pub capacity_probe_failures: u64,
    #[serde(default)]
    pub capacity_probe_bytes: u64,
    #[serde(default)]
    pub flow_router: FlowRouterStatus,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlowRouterStatus {
    pub active_flows: u64,
    pub max_flows: u64,
    pub decisions: u64,
    pub route_switches: u64,
    pub no_route_drops: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteCapacityStatus {
    pub destination: String,
    pub first_hop: String,
    pub capacity_bps: u64,
    pub effective_capacity_bps: u64,
    pub measured_capacity_bps: Option<u64>,
    pub min_rtt_micros: Option<u64>,
    pub rtt_ewma_micros: Option<u64>,
    pub loss_ppm: u32,
    pub health_per_mille: u16,
    pub sample_age_millis: Option<u64>,
    pub freshness: String,
    pub sample_source: Option<String>,
    pub active_samples: u64,
    pub passive_samples: u64,
    #[serde(default)]
    pub route_switches: u64,
    pub path_epoch: u64,
    #[serde(default)]
    pub probe_in_flight: bool,
    #[serde(default)]
    pub probe_next_due_millis: Option<u64>,
    #[serde(default)]
    pub probe_failure_count: u8,
    #[serde(default)]
    pub probe_attempts: u64,
    #[serde(default)]
    pub probe_failures: u64,
    #[serde(default)]
    pub probe_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteStatus {
    pub prefix: String,
    pub present: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerStatus {
    pub name: String,
    pub endpoint_id: String,
    pub interface: String,
    #[serde(default)]
    pub protocol_major: u64,
    #[serde(default)]
    pub protocol_minor: u64,
    #[serde(default)]
    pub negotiated_features: u64,
    #[serde(default)]
    pub private_link: bool,
    pub connected: bool,
    pub connection_events: u64,
    #[serde(default)]
    pub connection_errors: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    #[serde(default)]
    pub flow_latency_packets: u64,
    #[serde(default)]
    pub flow_bulk_packets: u64,
    #[serde(default)]
    pub flow_selected_bytes: u64,
    #[serde(default)]
    pub delivery_tagged_packets: u64,
    #[serde(default)]
    pub delivery_header_bytes: u64,
    #[serde(default)]
    pub delivery_registers_sent: u64,
    #[serde(default)]
    pub delivery_reports_sent: u64,
    #[serde(default)]
    pub delivery_control_bytes: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub tx_fragments: u64,
    pub rx_fragments: u64,
    #[serde(default)]
    pub fec_tx_recovery_shards: u64,
    #[serde(default)]
    pub fec_rx_recovery_shards: u64,
    #[serde(default)]
    pub fec_recovered_shards: u64,
    #[serde(default)]
    pub fec_unprotected_shards: u64,
    #[serde(default)]
    pub fec_expired_blocks: u64,
    #[serde(default)]
    pub fec_overhead_bytes: u64,
    pub invalid_packets: u64,
    pub policy_drops: u64,
    pub frame_drops: u64,
    pub send_errors: u64,
    #[serde(default)]
    pub mtu_reframes: u64,
    #[serde(default)]
    pub heartbeats_sent: u64,
    #[serde(default)]
    pub heartbeats_received: u64,
    #[serde(default)]
    pub liveness_reconnects: u64,
    #[serde(default)]
    pub trace_errors: u64,
    #[serde(default)]
    pub queue_packets: u64,
    #[serde(default)]
    pub queue_bytes: u64,
    #[serde(default)]
    pub priority_queue_packets: u64,
    #[serde(default)]
    pub priority_queue_bytes: u64,
    #[serde(default)]
    pub bulk_queue_packets: u64,
    #[serde(default)]
    pub bulk_queue_bytes: u64,
    #[serde(default)]
    pub active_tx_bytes: u64,
    #[serde(default)]
    pub quic_send_buffer_used_bytes: u64,
    #[serde(default)]
    pub bulk_preemptions: u64,
    #[serde(default)]
    pub queue_peak_bytes: u64,
    #[serde(default)]
    pub queue_max_age_micros: u64,
    #[serde(default)]
    pub aggregation_delay_micros: u64,
    #[serde(default)]
    pub tun_mtu: u64,
    #[serde(default)]
    pub queue_drops: u64,
    #[serde(default)]
    pub queue_expired_drops: u64,
    #[serde(default)]
    pub tx_batches: u64,
    #[serde(default)]
    pub tx_batched_packets: u64,
    #[serde(default)]
    pub repair_requests_sent: u64,
    #[serde(default)]
    pub repair_requests_received: u64,
    #[serde(default)]
    pub repair_fragments_sent: u64,
    #[serde(default)]
    pub reassembly_evictions: u64,
    #[serde(default)]
    pub effective_frame_size: u64,
    #[serde(default)]
    pub path_rtt_micros: u64,
    #[serde(default)]
    pub path_jitter_micros: u64,
    #[serde(default)]
    pub path_loss_ppm: u64,
    #[serde(default)]
    pub path_mtu: u64,
    #[serde(default)]
    pub path_cwnd_bytes: u64,
    #[serde(default)]
    pub path_tx_datagrams: u64,
    #[serde(default)]
    pub path_lost_packets: u64,
    #[serde(default)]
    pub selected_path_transport: String,
    #[serde(default)]
    pub selected_path_remote: String,
    #[serde(default)]
    pub open_paths: u64,
    #[serde(default)]
    pub path_switches: u64,
    #[serde(default)]
    pub capacities: Vec<RouteCapacityStatus>,
}

pub async fn run_reporter(config: ObservabilityConfig, state: Arc<RuntimeState>) -> Result<()> {
    let mut interval = time::interval(Duration::from_secs(config.report_interval_secs));
    interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
    let mut previous_ready = None;
    loop {
        interval.tick().await;
        let status = state.snapshot().await?;
        if previous_ready != Some(status.ready) {
            let missing_routes = status
                .routes
                .iter()
                .filter(|route| !route.present)
                .take(10)
                .map(|route| route.prefix.as_str())
                .collect::<Vec<_>>()
                .join(",");
            if status.ready {
                info!("runtime transitioned to ready");
            } else {
                warn!(
                    connected_peers = status.peers.iter().filter(|peer| peer.connected).count(),
                    peers = status.peers.len(),
                    missing_routes = status.routes.iter().filter(|route| !route.present).count(),
                    missing_route_sample = %missing_routes,
                    "runtime is not ready"
                );
            }
            previous_ready = Some(status.ready);
        }
        write_status_files(&config, &status).await?;
        debug!(
            ready = status.ready,
            connected_peers = status.peers.iter().filter(|peer| peer.connected).count(),
            peers = status.peers.len(),
            "runtime status updated"
        );
    }
}

pub async fn publish_status(config: &ObservabilityConfig, state: &RuntimeState) -> Result<()> {
    let status = state.snapshot().await?;
    write_status_files(config, &status).await
}

async fn write_status_files(config: &ObservabilityConfig, status: &RuntimeStatus) -> Result<()> {
    let json = serde_json::to_vec_pretty(&status).context("failed encoding runtime status")?;
    atomic_write(&config.status_file, &json).await?;
    atomic_write(&config.metrics_file, render_prometheus(status).as_bytes()).await
}

pub async fn read_status(path: &Path) -> Result<RuntimeStatus> {
    let data = tokio::fs::read(path)
        .await
        .with_context(|| format!("failed reading status file {}", path.display()))?;
    serde_json::from_slice(&data)
        .with_context(|| format!("failed parsing status file {}", path.display()))
}

pub fn should_log(counter: &AtomicU64) -> bool {
    let count = counter.fetch_add(1, Ordering::Relaxed) + 1;
    count <= 3 || count.is_power_of_two()
}

pub fn log_runtime_started(config: &ObservabilityConfig) {
    info!(
        status_file = %config.status_file.display(),
        metrics_file = %config.metrics_file.display(),
        interval_seconds = config.report_interval_secs,
        "observability reporter configured"
    );
}

fn peer_snapshot(peer: &PeerCounters) -> PeerStatus {
    PeerStatus {
        name: peer.name.clone(),
        endpoint_id: peer.endpoint_id.to_string(),
        interface: peer.interface.clone(),
        protocol_major: peer.protocol_major.load(Ordering::Relaxed),
        protocol_minor: peer.protocol_minor.load(Ordering::Relaxed),
        negotiated_features: peer.negotiated_features.load(Ordering::Relaxed),
        private_link: peer.private_link.load(Ordering::Relaxed),
        connected: peer.connected.load(Ordering::Relaxed),
        connection_events: peer.connection_events.load(Ordering::Relaxed),
        connection_errors: peer.connection_errors.load(Ordering::Relaxed),
        tx_packets: peer.tx_packets.load(Ordering::Relaxed),
        tx_bytes: peer.tx_bytes.load(Ordering::Relaxed),
        flow_latency_packets: peer.flow_latency_packets.load(Ordering::Relaxed),
        flow_bulk_packets: peer.flow_bulk_packets.load(Ordering::Relaxed),
        flow_selected_bytes: peer.flow_selected_bytes.load(Ordering::Relaxed),
        delivery_tagged_packets: peer.delivery_tagged_packets.load(Ordering::Relaxed),
        delivery_header_bytes: peer.delivery_header_bytes.load(Ordering::Relaxed),
        delivery_registers_sent: peer.delivery_registers_sent.load(Ordering::Relaxed),
        delivery_reports_sent: peer.delivery_reports_sent.load(Ordering::Relaxed),
        delivery_control_bytes: peer.delivery_control_bytes.load(Ordering::Relaxed),
        rx_packets: peer.rx_packets.load(Ordering::Relaxed),
        rx_bytes: peer.rx_bytes.load(Ordering::Relaxed),
        tx_fragments: peer.tx_fragments.load(Ordering::Relaxed),
        rx_fragments: peer.rx_fragments.load(Ordering::Relaxed),
        fec_tx_recovery_shards: peer.fec_tx_recovery_shards.load(Ordering::Relaxed),
        fec_rx_recovery_shards: peer.fec_rx_recovery_shards.load(Ordering::Relaxed),
        fec_recovered_shards: peer.fec_recovered_shards.load(Ordering::Relaxed),
        fec_unprotected_shards: peer.fec_unprotected_shards.load(Ordering::Relaxed),
        fec_expired_blocks: peer.fec_expired_blocks.load(Ordering::Relaxed),
        fec_overhead_bytes: peer.fec_overhead_bytes.load(Ordering::Relaxed),
        invalid_packets: peer.invalid_packets.load(Ordering::Relaxed),
        policy_drops: peer.policy_drops.load(Ordering::Relaxed),
        frame_drops: peer.frame_drops.load(Ordering::Relaxed),
        send_errors: peer.send_errors.load(Ordering::Relaxed),
        mtu_reframes: peer.mtu_reframes.load(Ordering::Relaxed),
        heartbeats_sent: peer.heartbeats_sent.load(Ordering::Relaxed),
        heartbeats_received: peer.heartbeats_received.load(Ordering::Relaxed),
        liveness_reconnects: peer.liveness_reconnects.load(Ordering::Relaxed),
        trace_errors: peer.trace_errors.load(Ordering::Relaxed),
        queue_packets: peer.queue_packets.load(Ordering::Relaxed),
        queue_bytes: peer.queue_bytes.load(Ordering::Relaxed),
        priority_queue_packets: peer.priority_queue_packets.load(Ordering::Relaxed),
        priority_queue_bytes: peer.priority_queue_bytes.load(Ordering::Relaxed),
        bulk_queue_packets: peer.bulk_queue_packets.load(Ordering::Relaxed),
        bulk_queue_bytes: peer.bulk_queue_bytes.load(Ordering::Relaxed),
        active_tx_bytes: peer.active_tx_bytes.load(Ordering::Relaxed),
        quic_send_buffer_used_bytes: peer.quic_send_buffer_used_bytes.load(Ordering::Relaxed),
        bulk_preemptions: peer.bulk_preemptions.load(Ordering::Relaxed),
        queue_peak_bytes: peer.queue_peak_bytes.load(Ordering::Relaxed),
        queue_max_age_micros: peer.queue_max_age_micros.load(Ordering::Relaxed),
        aggregation_delay_micros: peer.aggregation_delay_micros.load(Ordering::Relaxed),
        tun_mtu: peer.tun_mtu.load(Ordering::Relaxed),
        queue_drops: peer.queue_drops.load(Ordering::Relaxed),
        queue_expired_drops: peer.queue_expired_drops.load(Ordering::Relaxed),
        tx_batches: peer.tx_batches.load(Ordering::Relaxed),
        tx_batched_packets: peer.tx_batched_packets.load(Ordering::Relaxed),
        repair_requests_sent: peer.repair_requests_sent.load(Ordering::Relaxed),
        repair_requests_received: peer.repair_requests_received.load(Ordering::Relaxed),
        repair_fragments_sent: peer.repair_fragments_sent.load(Ordering::Relaxed),
        reassembly_evictions: peer.reassembly_evictions.load(Ordering::Relaxed),
        effective_frame_size: peer.effective_frame_size.load(Ordering::Relaxed),
        path_rtt_micros: peer.path_rtt_micros.load(Ordering::Relaxed),
        path_jitter_micros: peer.path_jitter_micros.load(Ordering::Relaxed),
        path_loss_ppm: peer.path_loss_ppm.load(Ordering::Relaxed),
        path_mtu: peer.path_mtu.load(Ordering::Relaxed),
        path_cwnd_bytes: peer.path_cwnd_bytes.load(Ordering::Relaxed),
        path_tx_datagrams: peer.path_tx_datagrams.load(Ordering::Relaxed),
        path_lost_packets: peer.path_lost_packets.load(Ordering::Relaxed),
        selected_path_transport: path_transport_name(
            peer.selected_path_transport.load(Ordering::Relaxed),
        )
        .into(),
        selected_path_remote: peer
            .selected_path_remote
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone(),
        open_paths: peer.open_paths.load(Ordering::Relaxed),
        path_switches: peer.path_switches.load(Ordering::Relaxed),
        capacities: Vec::new(),
    }
}

fn render_prometheus(status: &RuntimeStatus) -> String {
    let mut output = String::new();
    output.push_str("# TYPE iroh_sdwan_ready gauge\n");
    output.push_str(&format!("iroh_sdwan_ready {}\n", u8::from(status.ready)));
    output.push_str("# TYPE iroh_sdwan_routes_ready gauge\n");
    output.push_str(&format!(
        "iroh_sdwan_routes_ready {}\n",
        u8::from(status.routes_ready)
    ));
    output.push_str("# TYPE iroh_sdwan_capacity_table_entries gauge\n");
    output.push_str(&format!(
        "iroh_sdwan_capacity_table_entries {}\n",
        status.capacity_table_entries
    ));
    output.push_str("# TYPE iroh_sdwan_capacity_table_limit gauge\n");
    output.push_str(&format!(
        "iroh_sdwan_capacity_table_limit {}\n",
        status.capacity_table_limit
    ));
    output.push_str("# TYPE iroh_sdwan_capacity_probe_inflight gauge\n");
    output.push_str(&format!(
        "iroh_sdwan_capacity_probe_inflight {}\n",
        u8::from(status.capacity_probe_in_flight)
    ));
    for (name, value) in [
        ("attempts_total", status.capacity_probe_attempts),
        ("failures_total", status.capacity_probe_failures),
        ("bytes_total", status.capacity_probe_bytes),
    ] {
        output.push_str(&format!("iroh_sdwan_capacity_probe_{name} {value}\n"));
    }
    output.push_str("# TYPE iroh_sdwan_capacity_probe_budget_bytes gauge\n");
    output.push_str(&format!(
        "iroh_sdwan_capacity_probe_budget_bytes {}\n",
        status.capacity_probe_budget_bytes
    ));
    for (name, value) in [
        ("active_flows", status.flow_router.active_flows),
        ("max_flows", status.flow_router.max_flows),
        ("decisions_total", status.flow_router.decisions),
        ("route_switches_total", status.flow_router.route_switches),
        ("no_route_drops_total", status.flow_router.no_route_drops),
    ] {
        output.push_str(&format!("iroh_sdwan_flow_router_{name} {value}\n"));
    }
    output.push_str("# TYPE iroh_sdwan_route_present gauge\n");
    for route in &status.routes {
        output.push_str(&format!(
            "iroh_sdwan_route_present{{prefix=\"{}\"}} {}\n",
            prometheus_escape(&route.prefix),
            u8::from(route.present)
        ));
    }
    output.push_str("# TYPE iroh_sdwan_peer_connected gauge\n");
    output.push_str("# TYPE iroh_sdwan_mesh_directory_entries gauge\n");
    output.push_str(&format!(
        "iroh_sdwan_mesh_directory_entries {}\n",
        status.mesh.directory_entries
    ));
    output.push_str("# TYPE iroh_sdwan_mesh_quarantined_entries gauge\n");
    output.push_str(&format!(
        "iroh_sdwan_mesh_quarantined_entries {}\n",
        status.mesh.quarantined_entries
    ));
    for route in &status.capacities {
        let labels = format!(
            "destination=\"{}\",first_hop=\"{}\"",
            prometheus_escape(&route.destination),
            prometheus_escape(&route.first_hop),
        );
        for (name, value) in [
            ("capacity_bits_per_second", route.capacity_bps),
            (
                "effective_capacity_bits_per_second",
                route.effective_capacity_bps,
            ),
            (
                "measured_capacity_bits_per_second",
                route.measured_capacity_bps.unwrap_or(0),
            ),
            ("min_rtt_microseconds", route.min_rtt_micros.unwrap_or(0)),
            ("rtt_ewma_microseconds", route.rtt_ewma_micros.unwrap_or(0)),
            ("loss_parts_per_million", u64::from(route.loss_ppm)),
            ("health_per_mille", u64::from(route.health_per_mille)),
            (
                "sample_age_milliseconds",
                route.sample_age_millis.unwrap_or(0),
            ),
            ("active_samples_total", route.active_samples),
            ("passive_samples_total", route.passive_samples),
            ("switches_total", route.route_switches),
            ("path_epoch", route.path_epoch),
            ("probe_inflight", u64::from(route.probe_in_flight)),
            (
                "probe_next_due_milliseconds",
                route.probe_next_due_millis.unwrap_or(0),
            ),
            ("probe_failure_count", u64::from(route.probe_failure_count)),
            ("probe_attempts_total", route.probe_attempts),
            ("probe_failures_total", route.probe_failures),
            ("probe_bytes_total", route.probe_bytes),
        ] {
            output.push_str(&format!("iroh_sdwan_route_{name}{{{labels}}} {value}\n"));
        }
        output.push_str(&format!(
            "iroh_sdwan_route_capacity_info{{{labels},freshness=\"{}\",source=\"{}\"}} 1\n",
            prometheus_escape(&route.freshness),
            prometheus_escape(route.sample_source.as_deref().unwrap_or("none")),
        ));
    }
    for peer in &status.peers {
        let labels = format!(
            "peer=\"{}\",endpoint_id=\"{}\",interface=\"{}\"",
            prometheus_escape(&peer.name),
            prometheus_escape(&peer.endpoint_id),
            prometheus_escape(&peer.interface)
        );
        output.push_str(&format!(
            "iroh_sdwan_peer_connected{{{labels}}} {}\n",
            u8::from(peer.connected)
        ));
        output.push_str(&format!(
            "iroh_sdwan_peer_protocol_info{{{labels},major=\"{}\",minor=\"{}\",private_link=\"{}\"}} 1\n",
            peer.protocol_major,
            peer.protocol_minor,
            peer.private_link,
        ));
        output.push_str(&format!(
            "iroh_sdwan_peer_negotiated_features{{{labels}}} {}\n",
            peer.negotiated_features
        ));
        for (name, value) in [
            ("connection_events_total", peer.connection_events),
            ("connection_errors_total", peer.connection_errors),
            ("tx_packets_total", peer.tx_packets),
            ("tx_bytes_total", peer.tx_bytes),
            ("flow_latency_packets_total", peer.flow_latency_packets),
            ("flow_bulk_packets_total", peer.flow_bulk_packets),
            ("flow_selected_bytes_total", peer.flow_selected_bytes),
            (
                "delivery_tagged_packets_total",
                peer.delivery_tagged_packets,
            ),
            ("delivery_header_bytes_total", peer.delivery_header_bytes),
            (
                "delivery_registers_sent_total",
                peer.delivery_registers_sent,
            ),
            ("delivery_reports_sent_total", peer.delivery_reports_sent),
            ("delivery_control_bytes_total", peer.delivery_control_bytes),
            ("rx_packets_total", peer.rx_packets),
            ("rx_bytes_total", peer.rx_bytes),
            ("tx_fragments_total", peer.tx_fragments),
            ("rx_fragments_total", peer.rx_fragments),
            ("fec_tx_recovery_shards_total", peer.fec_tx_recovery_shards),
            ("fec_rx_recovery_shards_total", peer.fec_rx_recovery_shards),
            ("fec_recovered_shards_total", peer.fec_recovered_shards),
            ("fec_unprotected_shards_total", peer.fec_unprotected_shards),
            ("fec_expired_blocks_total", peer.fec_expired_blocks),
            ("fec_overhead_bytes_total", peer.fec_overhead_bytes),
            ("invalid_packets_total", peer.invalid_packets),
            ("policy_drops_total", peer.policy_drops),
            ("frame_drops_total", peer.frame_drops),
            ("send_errors_total", peer.send_errors),
            ("mtu_reframes_total", peer.mtu_reframes),
            ("heartbeats_sent_total", peer.heartbeats_sent),
            ("heartbeats_received_total", peer.heartbeats_received),
            ("liveness_reconnects_total", peer.liveness_reconnects),
            ("trace_errors_total", peer.trace_errors),
            ("queue_drops_total", peer.queue_drops),
            ("queue_expired_drops_total", peer.queue_expired_drops),
            ("bulk_preemptions_total", peer.bulk_preemptions),
            ("tx_batches_total", peer.tx_batches),
            ("tx_batched_packets_total", peer.tx_batched_packets),
            ("repair_requests_sent_total", peer.repair_requests_sent),
            (
                "repair_requests_received_total",
                peer.repair_requests_received,
            ),
            ("repair_fragments_sent_total", peer.repair_fragments_sent),
            ("reassembly_evictions_total", peer.reassembly_evictions),
            ("path_switches_total", peer.path_switches),
        ] {
            output.push_str(&format!("iroh_sdwan_peer_{name}{{{labels}}} {value}\n"));
        }
        for (name, value) in [
            ("queue_packets", peer.queue_packets),
            ("queue_bytes", peer.queue_bytes),
            ("priority_queue_packets", peer.priority_queue_packets),
            ("priority_queue_bytes", peer.priority_queue_bytes),
            ("bulk_queue_packets", peer.bulk_queue_packets),
            ("bulk_queue_bytes", peer.bulk_queue_bytes),
            ("active_tx_bytes", peer.active_tx_bytes),
            (
                "quic_send_buffer_used_bytes",
                peer.quic_send_buffer_used_bytes,
            ),
            ("queue_peak_bytes", peer.queue_peak_bytes),
            ("queue_max_age_microseconds", peer.queue_max_age_micros),
            (
                "aggregation_delay_microseconds",
                peer.aggregation_delay_micros,
            ),
            ("tun_mtu_bytes", peer.tun_mtu),
            ("effective_frame_size_bytes", peer.effective_frame_size),
            ("path_rtt_microseconds", peer.path_rtt_micros),
            ("path_jitter_microseconds", peer.path_jitter_micros),
            ("path_loss_parts_per_million", peer.path_loss_ppm),
            ("path_mtu_bytes", peer.path_mtu),
            ("path_cwnd_bytes", peer.path_cwnd_bytes),
            ("path_tx_datagrams", peer.path_tx_datagrams),
            ("path_lost_packets", peer.path_lost_packets),
            ("open_paths", peer.open_paths),
        ] {
            output.push_str(&format!("iroh_sdwan_peer_{name}{{{labels}}} {value}\n"));
        }
        output.push_str(&format!(
            "iroh_sdwan_peer_selected_path_info{{{labels},transport=\"{}\",remote=\"{}\"}} 1\n",
            prometheus_escape(&peer.selected_path_transport),
            prometheus_escape(&peer.selected_path_remote)
        ));
    }
    output
}

async fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed creating {}", parent.display()))?;
    }
    let temporary = temporary_path(path);
    tokio::fs::write(&temporary, data)
        .await
        .with_context(|| format!("failed writing {}", temporary.display()))?;
    tokio::fs::rename(&temporary, path)
        .await
        .with_context(|| format!("failed replacing {}", path.display()))
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".tmp-{}", std::process::id()));
    PathBuf::from(name)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn duration_micros(duration: Duration) -> u64 {
    duration.as_micros().min(u128::from(u64::MAX)) as u64
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

async fn inspect_routes(table: u32, required: &[IpNet]) -> Result<Vec<RouteStatus>> {
    if required.is_empty() {
        return Ok(Vec::new());
    }
    let mut present: HashSet<IpNet> = HashSet::new();
    let table = table.to_string();
    for family in ["-4", "-6"] {
        let output = tokio::process::Command::new("ip")
            .args([family, "-j", "route", "show", "table", &table])
            .output()
            .await
            .context("failed executing iproute2 route health check")?;
        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr);
            if error.contains("FIB table does not exist") {
                continue;
            }
            anyhow::bail!("route health check failed: {}", error.trim());
        }
        let routes: serde_json::Value = serde_json::from_slice(&output.stdout)
            .context("failed parsing iproute2 route health output")?;
        for destination in routes
            .as_array()
            .into_iter()
            .flatten()
            .filter(|route| {
                route
                    .get("type")
                    .and_then(serde_json::Value::as_str)
                    .is_none_or(|kind| kind == "unicast")
            })
            .filter_map(|route| route.get("dst").and_then(serde_json::Value::as_str))
        {
            if let Some(parsed) = parse_route_destination(family, destination) {
                present.insert(parsed);
            }
        }
    }
    Ok(required
        .iter()
        .map(|prefix| RouteStatus {
            prefix: prefix.to_string(),
            present: present.contains(prefix),
        })
        .collect())
}

fn parse_route_destination(family: &str, destination: &str) -> Option<IpNet> {
    if destination == "default" {
        return if family == "-4" {
            "0.0.0.0/0".parse().ok()
        } else {
            "::/0".parse().ok()
        };
    }
    destination.parse::<IpNet>().ok().or_else(|| {
        destination
            .parse::<IpAddr>()
            .ok()
            .and_then(|address| IpNet::new(address, if address.is_ipv4() { 32 } else { 128 }).ok())
    })
}

fn default_true() -> bool {
    true
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

fn prometheus_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use iroh::SecretKey;

    use super::*;

    #[tokio::test]
    async fn prometheus_output_contains_peer_counters() {
        let peer = Arc::new(PeerCounters::new(
            "branch-a".into(),
            SecretKey::from_bytes(&[1; 32]).public(),
            "isw-a".into(),
        ));
        peer.connected.store(true, Ordering::Relaxed);
        peer.tx_packets.store(4, Ordering::Relaxed);
        peer.priority_queue_packets.store(2, Ordering::Relaxed);
        peer.priority_queue_bytes.store(512, Ordering::Relaxed);
        peer.bulk_queue_packets.store(3, Ordering::Relaxed);
        peer.bulk_queue_bytes.store(4_096, Ordering::Relaxed);
        peer.active_tx_bytes.store(1_200, Ordering::Relaxed);
        peer.quic_send_buffer_used_bytes
            .store(2_400, Ordering::Relaxed);
        peer.bulk_preemptions.store(7, Ordering::Relaxed);
        let state = RuntimeState::new(
            SecretKey::from_bytes(&[2; 32]).public(),
            100,
            Vec::new(),
            Arc::new(RwLock::new(HashMap::from([(peer.endpoint_id, peer)]))),
            None,
            CapacityObservability::new(
                Arc::new(RwLock::new(RouteEstimateTable::default())),
                Arc::new(RwLock::new(ProbeStatusSnapshot::default())),
                None,
            ),
            Arc::new(FlowRouterCounters::default()),
        );
        let status = state.snapshot().await.unwrap();
        let peer = &status.peers[0];
        assert_eq!(peer.priority_queue_packets, 2);
        assert_eq!(peer.priority_queue_bytes, 512);
        assert_eq!(peer.bulk_queue_packets, 3);
        assert_eq!(peer.bulk_queue_bytes, 4_096);
        assert_eq!(peer.active_tx_bytes, 1_200);
        assert_eq!(peer.quic_send_buffer_used_bytes, 2_400);
        assert_eq!(peer.bulk_preemptions, 7);
        let output = render_prometheus(&status);
        assert!(output.contains("iroh_sdwan_peer_connected"));
        assert!(output.contains("iroh_sdwan_peer_tx_packets_total"));
        assert!(output.contains("iroh_sdwan_capacity_table_entries"));
        assert!(output.contains("iroh_sdwan_capacity_probe_inflight"));
        assert!(output.contains("iroh_sdwan_flow_router_active_flows"));
        assert!(output.contains("iroh_sdwan_peer_priority_queue_packets"));
        assert!(output.contains("iroh_sdwan_peer_priority_queue_bytes"));
        assert!(output.contains("iroh_sdwan_peer_bulk_queue_packets"));
        assert!(output.contains("iroh_sdwan_peer_bulk_queue_bytes"));
        assert!(output.contains("iroh_sdwan_peer_active_tx_bytes"));
        assert!(output.contains("iroh_sdwan_peer_quic_send_buffer_used_bytes"));
        assert!(output.contains("iroh_sdwan_peer_bulk_preemptions_total"));
    }

    #[tokio::test]
    async fn status_and_prometheus_expose_route_probe_state() {
        let now = Instant::now();
        let destination = SecretKey::from_bytes(&[3; 32]).public();
        let first_hop = SecretKey::from_bytes(&[4; 32]).public();
        let route = crate::capacity::RouteKey {
            destination,
            first_hop,
        };
        let mut estimates = RouteEstimateTable::default();
        estimates.get_or_insert(route, now).observe_active(
            100_000_000,
            Duration::from_millis(20),
            1_000,
            now,
        );
        let probes = ProbeStatusSnapshot {
            routes: HashMap::from([(
                route,
                crate::capacity_probe::ProbeRouteSnapshot {
                    in_flight: true,
                    next_due_in: Duration::ZERO,
                    failure_count: 2,
                    attempts_total: 3,
                    failures_total: 2,
                    bytes_total: 64_000,
                },
            )]),
            global_in_flight: true,
            attempts_total: 3,
            failures_total: 2,
            bytes_total: 64_000,
        };
        let state = RuntimeState::new(
            SecretKey::from_bytes(&[5; 32]).public(),
            100,
            Vec::new(),
            Arc::new(RwLock::new(HashMap::new())),
            None,
            CapacityObservability::new(
                Arc::new(RwLock::new(estimates)),
                Arc::new(RwLock::new(probes)),
                None,
            ),
            Arc::new(FlowRouterCounters::default()),
        );
        let status = state.snapshot().await.unwrap();
        assert!(status.capacity_probe_in_flight);
        assert_eq!(status.capacity_probe_attempts, 3);
        assert_eq!(status.capacities.len(), 1);
        assert!(status.capacities[0].probe_in_flight);
        assert_eq!(status.capacities[0].probe_failures, 2);
        let output = render_prometheus(&status);
        assert!(output.contains("iroh_sdwan_route_probe_attempts_total"));
        assert!(output.contains("iroh_sdwan_route_probe_bytes_total"));
        assert!(output.contains("iroh_sdwan_route_switches_total"));
    }

    #[test]
    fn parses_iproute_host_and_default_destinations() {
        assert_eq!(
            parse_route_destination("-4", "10.200.0.3"),
            Some("10.200.0.3/32".parse().unwrap())
        );
        assert_eq!(
            parse_route_destination("-6", "fd73:9db8:4200::3"),
            Some("fd73:9db8:4200::3/128".parse().unwrap())
        );
        assert_eq!(
            parse_route_destination("-4", "default"),
            Some("0.0.0.0/0".parse().unwrap())
        );
    }
}

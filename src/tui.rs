use std::{
    collections::{HashMap, HashSet, VecDeque},
    io::IsTerminal,
    net::IpAddr,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use ipnet::IpNet;
use iroh::EndpointId;
use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap},
};

use crate::{
    config::{Config, RouteOriginConfig},
    control, display,
    routes::{self, RouteRegistry},
    status::MeshNodeStatus,
    status::{PeerStatus, RuntimeStatus},
    trace::{PingResult, TraceResult},
};

const HISTORY_LEN: usize = 60;
const EVENT_LIMIT: usize = 32;
const REMOVE_CONFIRM_TTL: Duration = Duration::from_secs(4);
const RELOAD_CONFIRM_TTL: Duration = Duration::from_secs(4);
const DIAGNOSTIC_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum TuiView {
    #[default]
    Peers,
    Routes,
    Diagnostics,
}

impl TuiView {
    fn next(self) -> Self {
        match self {
            Self::Peers => Self::Routes,
            Self::Routes => Self::Diagnostics,
            Self::Diagnostics => Self::Peers,
        }
    }

    fn previous(self) -> Self {
        match self {
            Self::Peers => Self::Diagnostics,
            Self::Routes => Self::Peers,
            Self::Diagnostics => Self::Routes,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Peers => "Peers",
            Self::Routes => "Routes",
            Self::Diagnostics => "Diagnostics",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeclaredRoute {
    owner: EndpointId,
    owner_name: String,
    prefix: IpNet,
    declared: bool,
    accepted: bool,
    ownership_conflict: bool,
    expires_unix_secs: Option<u64>,
}

impl DeclaredRoute {
    fn key(&self) -> (EndpointId, IpNet) {
        (self.owner, self.prefix)
    }

    fn state(&self) -> &'static str {
        if self.ownership_conflict {
            "CONFLICT"
        } else if self.accepted && self.declared {
            "ACCEPTED"
        } else if self.accepted {
            "OFFLINE"
        } else {
            "DECLARED"
        }
    }
}

#[derive(Debug, Clone)]
struct PendingRouteRemoval {
    key: (EndpointId, IpNet),
    requested_at: Instant,
}

#[derive(Debug, Default)]
struct DiagnosticReport {
    title: String,
    lines: Vec<String>,
    failed: bool,
}

#[derive(Debug)]
enum DiagnosticOutcome {
    Ping {
        name: String,
        target: IpAddr,
        result: std::result::Result<PingResult, String>,
    },
    Trace {
        name: String,
        target: IpAddr,
        result: std::result::Result<TraceResult, String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortMode {
    Name,
    Traffic,
    Rtt,
    Queue,
    Drops,
}

impl SortMode {
    fn next(self) -> Self {
        match self {
            Self::Name => Self::Traffic,
            Self::Traffic => Self::Rtt,
            Self::Rtt => Self::Queue,
            Self::Queue => Self::Drops,
            Self::Drops => Self::Name,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Traffic => "traffic",
            Self::Rtt => "rtt",
            Self::Queue => "queue",
            Self::Drops => "drops",
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct PeerRate {
    tx_bps: u64,
    rx_bps: u64,
    latency_bps: u64,
    bulk_bps: u64,
    drop_ps: u64,
    error_ps: u64,
}

#[derive(Debug, Clone)]
struct PreviousPeer {
    sampled_at: Instant,
    tx_bytes: u64,
    rx_bytes: u64,
    latency_service_bytes: u64,
    bulk_service_bytes: u64,
    drops: u64,
    errors: u64,
    connected: bool,
    selected_path_transport: String,
    selected_path_remote: String,
}

impl PreviousPeer {
    fn from_peer(peer: &PeerStatus, sampled_at: Instant) -> Self {
        Self {
            sampled_at,
            tx_bytes: peer.traffic.tx_bytes,
            rx_bytes: peer.traffic.rx_bytes,
            latency_service_bytes: peer.traffic.latency_service_bytes,
            bulk_service_bytes: peer.traffic.bulk_service_bytes,
            drops: total_drops(peer),
            errors: total_errors(peer),
            connected: peer.connected,
            selected_path_transport: peer.selected_path_transport.clone(),
            selected_path_remote: peer.selected_path_remote.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct TuiEvent {
    when_unix: u64,
    severity: Color,
    message: String,
}

#[derive(Debug, Default)]
struct Dashboard {
    status: Option<RuntimeStatus>,
    route_registry: RouteRegistry,
    previous_peers: HashMap<String, PreviousPeer>,
    rates: HashMap<String, PeerRate>,
    total_history: VecDeque<u64>,
    events: VecDeque<TuiEvent>,
    selected: usize,
    selected_route: usize,
    selected_node: usize,
    view: TuiView,
    sort: Option<SortMode>,
    filter_connected: bool,
    paused: bool,
    show_help: bool,
    detail_expanded: bool,
    last_error: Option<String>,
    last_refresh: Option<Instant>,
    operation_message: Option<String>,
    pending_route_removal: Option<PendingRouteRemoval>,
    pending_reload: Option<Instant>,
    diagnostic_report: DiagnosticReport,
    diagnostic_running: bool,
}

impl Dashboard {
    fn update(&mut self, status: RuntimeStatus, sampled_at: Instant) {
        self.record_global_events(&status);
        let mut current = HashMap::with_capacity(status.peers.len());
        let mut rates = HashMap::with_capacity(status.peers.len());
        for peer in &status.peers {
            let key = peer.endpoint_id.clone();
            let rate = self
                .previous_peers
                .get(&key)
                .map(|previous| peer_rate(peer, previous, sampled_at))
                .unwrap_or_default();
            if let Some(previous) = self.previous_peers.get(&key).cloned() {
                self.record_peer_events(peer, &previous);
            } else {
                self.push_event(Color::Cyan, format!("peer {} discovered", peer.name));
            }
            rates.insert(key.clone(), rate);
            current.insert(key, PreviousPeer::from_peer(peer, sampled_at));
        }
        let disappeared = self
            .previous_peers
            .keys()
            .filter(|endpoint| !current.contains_key(*endpoint))
            .cloned()
            .collect::<Vec<_>>();
        for endpoint in disappeared {
            self.push_event(
                Color::Yellow,
                format!("peer {} disappeared", short(&endpoint, 12)),
            );
        }
        let total_rate = rates
            .values()
            .map(|rate| rate.tx_bps.saturating_add(rate.rx_bps))
            .sum();
        self.total_history.push_back(total_rate);
        if self.total_history.len() > HISTORY_LEN {
            self.total_history.pop_front();
        }
        self.status = Some(status);
        self.previous_peers = current;
        self.rates = rates;
        self.last_error = None;
        self.last_refresh = Some(sampled_at);
        self.clamp_selection();
    }

    fn update_route_registry(&mut self, registry: RouteRegistry) {
        self.route_registry = registry;
        self.clamp_selection();
    }

    fn record_global_events(&mut self, status: &RuntimeStatus) {
        let Some(previous) = &self.status else {
            self.push_event(
                if status.ready {
                    Color::Green
                } else {
                    Color::Yellow
                },
                format!("runtime ready={}", status.ready),
            );
            return;
        };
        let previous_ready = previous.ready;
        if previous_ready != status.ready {
            self.push_event(
                if status.ready {
                    Color::Green
                } else {
                    Color::Red
                },
                format!("runtime ready {} -> {}", previous_ready, status.ready),
            );
        }
    }

    fn record_peer_events(&mut self, peer: &PeerStatus, previous: &PreviousPeer) {
        if previous.connected != peer.connected {
            self.push_event(
                if peer.connected {
                    Color::Green
                } else {
                    Color::Red
                },
                format!("peer {} connected={}", peer.name, peer.connected),
            );
        }
        if previous.selected_path_transport != peer.selected_path_transport
            || previous.selected_path_remote != peer.selected_path_remote
        {
            self.push_event(
                Color::Cyan,
                format!(
                    "peer {} path -> {}:{}",
                    peer.name,
                    nonempty(&peer.selected_path_transport, "unknown"),
                    nonempty(&peer.selected_path_remote, "unknown")
                ),
            );
        }
        let drops = total_drops(peer);
        if drops > previous.drops {
            self.push_event(
                Color::Yellow,
                format!("peer {} drops +{}", peer.name, drops - previous.drops),
            );
        }
        let errors = total_errors(peer);
        if errors > previous.errors {
            self.push_event(
                Color::Red,
                format!("peer {} errors +{}", peer.name, errors - previous.errors),
            );
        }
    }

    fn push_event(&mut self, severity: Color, message: String) {
        self.events.push_front(TuiEvent {
            when_unix: unix_now(),
            severity,
            message,
        });
        self.events.truncate(EVENT_LIMIT);
    }

    fn visible_peers(&self) -> Vec<&PeerStatus> {
        let mut peers = self
            .status
            .as_ref()
            .map(|status| status.peers.iter().collect::<Vec<_>>())
            .unwrap_or_default();
        if self.filter_connected {
            peers.retain(|peer| peer.connected);
        }
        if let Some(sort) = self.sort {
            peers.sort_by(|left, right| match sort {
                SortMode::Name => left.name.cmp(&right.name),
                SortMode::Traffic => self
                    .total_rate(right)
                    .cmp(&self.total_rate(left))
                    .then_with(|| left.name.cmp(&right.name)),
                SortMode::Rtt => right
                    .path_rtt_micros
                    .cmp(&left.path_rtt_micros)
                    .then_with(|| left.name.cmp(&right.name)),
                SortMode::Queue => right
                    .traffic
                    .packet_train_queue_bytes
                    .saturating_add(right.traffic.latency_queue_bytes)
                    .cmp(
                        &left
                            .traffic
                            .packet_train_queue_bytes
                            .saturating_add(left.traffic.latency_queue_bytes),
                    )
                    .then_with(|| left.name.cmp(&right.name)),
                SortMode::Drops => total_drops(right)
                    .cmp(&total_drops(left))
                    .then_with(|| left.name.cmp(&right.name)),
            });
        }
        peers
    }

    fn total_rate(&self, peer: &PeerStatus) -> u64 {
        self.rates
            .get(&peer.endpoint_id)
            .map_or(0, |rate| rate.tx_bps.saturating_add(rate.rx_bps))
    }

    fn selected_peer(&self) -> Option<&PeerStatus> {
        self.visible_peers().get(self.selected).copied()
    }

    fn declared_routes(&self) -> Vec<DeclaredRoute> {
        let Some(status) = &self.status else {
            return Vec::new();
        };
        let accepted_by_prefix = self
            .route_registry
            .flattened()
            .into_iter()
            .collect::<HashMap<_, _>>();
        let mut declaration_owners = HashMap::<IpNet, HashSet<EndpointId>>::new();
        for node in &status.mesh.nodes {
            let Ok(owner) = node.endpoint_id.parse::<EndpointId>() else {
                continue;
            };
            for prefix in &node.prefixes {
                declaration_owners.entry(*prefix).or_default().insert(owner);
            }
        }
        let mut seen = HashSet::new();
        let mut routes = Vec::new();

        for node in &status.mesh.nodes {
            let Ok(owner) = node.endpoint_id.parse::<EndpointId>() else {
                continue;
            };
            let owner_name = peer_name(status, owner)
                .map(str::to_owned)
                .unwrap_or_else(|| short(&node.endpoint_id, 16));
            for prefix in &node.prefixes {
                let accepted_owner = accepted_by_prefix.get(prefix).copied();
                routes.push(DeclaredRoute {
                    owner,
                    owner_name: owner_name.clone(),
                    prefix: *prefix,
                    declared: true,
                    accepted: accepted_owner == Some(owner),
                    ownership_conflict: accepted_owner.is_some_and(|accepted| accepted != owner)
                        || declaration_owners
                            .get(prefix)
                            .is_some_and(|owners| owners.len() > 1),
                    expires_unix_secs: Some(node.expires_unix_secs),
                });
                seen.insert((owner, *prefix));
            }
        }

        for (prefix, owner) in self.route_registry.flattened() {
            if seen.contains(&(owner, prefix)) {
                continue;
            }
            routes.push(DeclaredRoute {
                owner,
                owner_name: peer_name(status, owner)
                    .map(str::to_owned)
                    .unwrap_or_else(|| short(&owner.to_string(), 16)),
                prefix,
                declared: false,
                accepted: true,
                ownership_conflict: false,
                expires_unix_secs: None,
            });
        }

        routes.sort_by(|left, right| {
            route_review_rank(left)
                .cmp(&route_review_rank(right))
                .then_with(|| left.owner_name.cmp(&right.owner_name))
                .then_with(|| left.prefix.to_string().cmp(&right.prefix.to_string()))
        });
        routes
    }

    fn selected_route(&self) -> Option<DeclaredRoute> {
        self.declared_routes().get(self.selected_route).cloned()
    }

    fn diagnostic_nodes(&self) -> Vec<&MeshNodeStatus> {
        let mut nodes = self
            .status
            .as_ref()
            .map(|status| status.mesh.nodes.iter().collect::<Vec<_>>())
            .unwrap_or_default();
        nodes.sort_by(|left, right| {
            node_name(left)
                .cmp(node_name(right))
                .then_with(|| left.endpoint_id.cmp(&right.endpoint_id))
        });
        nodes
    }

    fn selected_node(&self) -> Option<&MeshNodeStatus> {
        self.diagnostic_nodes().get(self.selected_node).copied()
    }

    fn move_selection(&mut self, delta: isize) {
        match self.view {
            TuiView::Peers => {
                let len = self.visible_peers().len();
                self.selected = if len == 0 {
                    0
                } else {
                    self.selected
                        .saturating_add_signed(delta)
                        .min(len.saturating_sub(1))
                };
            }
            TuiView::Routes => {
                let len = self.declared_routes().len();
                self.selected_route = if len == 0 {
                    0
                } else {
                    self.selected_route
                        .saturating_add_signed(delta)
                        .min(len.saturating_sub(1))
                };
            }
            TuiView::Diagnostics => {
                let len = self.diagnostic_nodes().len();
                self.selected_node = if len == 0 {
                    0
                } else {
                    self.selected_node
                        .saturating_add_signed(delta)
                        .min(len.saturating_sub(1))
                };
            }
        }
    }

    fn clamp_selection(&mut self) {
        self.selected = self
            .selected
            .min(self.visible_peers().len().saturating_sub(1));
        self.selected_route = self
            .selected_route
            .min(self.declared_routes().len().saturating_sub(1));
        self.selected_node = self
            .selected_node
            .min(self.diagnostic_nodes().len().saturating_sub(1));
        if self.pending_route_removal.as_ref().is_some_and(|pending| {
            pending.requested_at.elapsed() > REMOVE_CONFIRM_TTL
                || !self
                    .declared_routes()
                    .iter()
                    .any(|route| route.key() == pending.key)
        }) {
            self.pending_route_removal = None;
        }
        if self
            .pending_reload
            .is_some_and(|requested| requested.elapsed() > RELOAD_CONFIRM_TTL)
        {
            self.pending_reload = None;
        }
    }

    fn change_view(&mut self, backwards: bool) {
        self.view = if backwards {
            self.view.previous()
        } else {
            self.view.next()
        };
        self.pending_route_removal = None;
        self.operation_message = None;
        self.clamp_selection();
    }

    fn attention_active(&self) -> bool {
        self.last_error.is_some()
            || self.status.as_ref().is_some_and(|status| !status.ready)
            || self
                .rates
                .values()
                .any(|rate| rate.drop_ps > 0 || rate.error_ps > 0)
            || self.events.iter().any(|event| {
                event.when_unix.saturating_add(30) >= unix_now()
                    && matches!(event.severity, Color::Red | Color::Yellow)
            })
    }
}

struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> Self {
        Self
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        ratatui::restore();
    }
}

pub async fn run(config_path: &Path, socket: &Path, interval: Duration) -> Result<()> {
    ensure!(
        interval >= Duration::from_millis(200) && interval <= Duration::from_secs(60),
        "tui interval must be between 200 ms and 60 s"
    );
    ensure!(
        std::io::stdout().is_terminal() && std::io::stdin().is_terminal(),
        "tui requires an interactive terminal"
    );

    let mut dashboard = Dashboard::default();
    let route_registry_path = Config::route_registry_path_for(config_path).await?;
    dashboard.update_route_registry(RouteRegistry::load(&route_registry_path).await?);
    let initial = control::snapshot(socket).await?;
    dashboard.update(initial, Instant::now());

    let mut terminal = ratatui::init();
    let _guard = TerminalGuard::enter();
    run_loop(
        &mut terminal,
        config_path,
        socket,
        &route_registry_path,
        interval,
        &mut dashboard,
    )
    .await
}

async fn run_loop(
    terminal: &mut DefaultTerminal,
    config_path: &Path,
    socket: &Path,
    route_registry_path: &Path,
    interval: Duration,
    dashboard: &mut Dashboard,
) -> Result<()> {
    let mut next_refresh = Instant::now() + interval;
    let (diagnostic_tx, mut diagnostic_rx) = tokio::sync::mpsc::unbounded_channel();
    loop {
        while let Ok(outcome) = diagnostic_rx.try_recv() {
            finish_diagnostic(dashboard, outcome);
        }
        terminal.draw(|frame| render(frame, dashboard, interval))?;
        let timeout = next_refresh.saturating_duration_since(Instant::now());
        if event::poll(timeout.min(Duration::from_millis(100)))? {
            if let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                match key.code {
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return Ok(());
                    }
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Char('?') => dashboard.show_help = !dashboard.show_help,
                    KeyCode::Tab if !dashboard.show_help => dashboard.change_view(false),
                    KeyCode::BackTab if !dashboard.show_help => dashboard.change_view(true),
                    KeyCode::Char(' ') => dashboard.paused = !dashboard.paused,
                    KeyCode::Char('p') if dashboard.view != TuiView::Diagnostics => {
                        dashboard.paused = !dashboard.paused;
                    }
                    KeyCode::Char('c') if dashboard.view == TuiView::Peers => {
                        dashboard.filter_connected = !dashboard.filter_connected;
                        dashboard.clamp_selection();
                    }
                    KeyCode::Char('s') if dashboard.view == TuiView::Peers => {
                        dashboard.sort =
                            Some(dashboard.sort.map_or(SortMode::Traffic, SortMode::next));
                        dashboard.clamp_selection();
                    }
                    KeyCode::Char('r') => next_refresh = Instant::now(),
                    KeyCode::Char('R') if !dashboard.show_help => {
                        reload_daemon(terminal, socket, dashboard, interval).await;
                        next_refresh = Instant::now();
                    }
                    KeyCode::Enter | KeyCode::Char('d') if dashboard.view == TuiView::Peers => {
                        dashboard.detail_expanded = !dashboard.detail_expanded;
                    }
                    KeyCode::Char('a')
                        if dashboard.view == TuiView::Routes && !dashboard.show_help =>
                    {
                        accept_selected_route(
                            terminal,
                            config_path,
                            socket,
                            route_registry_path,
                            dashboard,
                            interval,
                        )
                        .await;
                        next_refresh = Instant::now() + interval;
                    }
                    KeyCode::Char('x')
                        if dashboard.view == TuiView::Routes && !dashboard.show_help =>
                    {
                        remove_selected_route(
                            terminal,
                            config_path,
                            socket,
                            route_registry_path,
                            dashboard,
                            interval,
                        )
                        .await;
                        next_refresh = Instant::now() + interval;
                    }
                    KeyCode::Char('p')
                        if dashboard.view == TuiView::Diagnostics && !dashboard.show_help =>
                    {
                        start_selected_ping(socket, dashboard, diagnostic_tx.clone());
                        next_refresh = Instant::now() + interval;
                    }
                    KeyCode::Char('t')
                        if dashboard.view == TuiView::Diagnostics && !dashboard.show_help =>
                    {
                        start_selected_trace(socket, dashboard, diagnostic_tx.clone());
                        next_refresh = Instant::now() + interval;
                    }
                    KeyCode::Down | KeyCode::Char('j') => dashboard.move_selection(1),
                    KeyCode::Up | KeyCode::Char('k') => dashboard.move_selection(-1),
                    _ => {}
                }
            }
        } else if Instant::now() >= next_refresh && !dashboard.paused {
            match control::snapshot(socket).await {
                Ok(status) => {
                    dashboard.update(status, Instant::now());
                    match RouteRegistry::load(route_registry_path).await {
                        Ok(registry) => dashboard.update_route_registry(registry),
                        Err(error) => {
                            let message = format!("route registry refresh failed: {error}");
                            if dashboard.last_error.as_deref() != Some(&message) {
                                dashboard.push_event(Color::Red, message.clone());
                            }
                            dashboard.last_error = Some(message);
                        }
                    }
                }
                Err(error) => {
                    let message = error.to_string();
                    if dashboard.last_error.as_deref() != Some(&message) {
                        dashboard.push_event(Color::Red, format!("snapshot failed: {message}"));
                    }
                    dashboard.last_error = Some(message);
                }
            }
            next_refresh = Instant::now() + interval;
        } else if Instant::now() >= next_refresh {
            next_refresh = Instant::now() + interval;
        }
    }
}

async fn reload_daemon(
    terminal: &mut DefaultTerminal,
    socket: &Path,
    dashboard: &mut Dashboard,
    interval: Duration,
) {
    let confirmed = dashboard
        .pending_reload
        .is_some_and(|requested| requested.elapsed() <= RELOAD_CONFIRM_TTL);
    if !confirmed {
        dashboard.pending_reload = Some(Instant::now());
        dashboard.operation_message = Some(format!(
            "Press R again within {}s to validate and reload the daemon.",
            RELOAD_CONFIRM_TTL.as_secs()
        ));
        return;
    }

    dashboard.pending_reload = None;
    dashboard.operation_message = Some("Validating and reloading daemon…".into());
    let _ = terminal.draw(|frame| render(frame, dashboard, interval));
    match control::reload(socket).await {
        Ok(ack) => {
            let message = format!("Daemon reloaded; generation {}.", ack.generation);
            dashboard.operation_message = Some(message.clone());
            dashboard.push_event(Color::Green, message);
        }
        Err(error) => {
            let message = format!("Daemon reload failed: {error}");
            dashboard.operation_message = Some(message.clone());
            dashboard.push_event(Color::Red, message);
        }
    }
}

fn start_selected_ping(
    socket: &Path,
    dashboard: &mut Dashboard,
    diagnostic_tx: tokio::sync::mpsc::UnboundedSender<DiagnosticOutcome>,
) {
    if dashboard.diagnostic_running {
        return;
    }
    let Some(node) = dashboard.selected_node() else {
        dashboard.diagnostic_report = DiagnosticReport {
            title: "Ping".into(),
            lines: vec!["No mesh node selected.".into()],
            failed: true,
        };
        return;
    };
    let Some(target) = diagnostic_target(node) else {
        dashboard.diagnostic_report = DiagnosticReport {
            title: format!("Ping · {}", node_name(node)),
            lines: vec!["The node did not declare a host overlay address (/32 or /128).".into()],
            failed: true,
        };
        return;
    };
    let name = node_name(node).to_owned();
    dashboard.diagnostic_report = DiagnosticReport {
        title: format!("Ping · {name} · {target}"),
        lines: vec!["Running 4 probes…".into()],
        failed: false,
    };
    dashboard.diagnostic_running = true;
    let socket = socket.to_owned();
    tokio::spawn(async move {
        let result = control::ping(&socket, target, 4, DIAGNOSTIC_TIMEOUT)
            .await
            .map_err(|error| error.to_string());
        let _ = diagnostic_tx.send(DiagnosticOutcome::Ping {
            name,
            target,
            result,
        });
    });
}

fn start_selected_trace(
    socket: &Path,
    dashboard: &mut Dashboard,
    diagnostic_tx: tokio::sync::mpsc::UnboundedSender<DiagnosticOutcome>,
) {
    if dashboard.diagnostic_running {
        return;
    }
    let Some(node) = dashboard.selected_node() else {
        dashboard.diagnostic_report = DiagnosticReport {
            title: "Trace".into(),
            lines: vec!["No mesh node selected.".into()],
            failed: true,
        };
        return;
    };
    let Some(target) = diagnostic_target(node) else {
        dashboard.diagnostic_report = DiagnosticReport {
            title: format!("Trace · {}", node_name(node)),
            lines: vec!["The node did not declare a host overlay address (/32 or /128).".into()],
            failed: true,
        };
        return;
    };
    let name = node_name(node).to_owned();
    dashboard.diagnostic_report = DiagnosticReport {
        title: format!("Trace · {name} · {target}"),
        lines: vec!["Tracing up to 8 overlay hops…".into()],
        failed: false,
    };
    dashboard.diagnostic_running = true;
    let socket = socket.to_owned();
    tokio::spawn(async move {
        let result = control::trace(&socket, target, 8, DIAGNOSTIC_TIMEOUT)
            .await
            .map_err(|error| error.to_string());
        let _ = diagnostic_tx.send(DiagnosticOutcome::Trace {
            name,
            target,
            result,
        });
    });
}

fn finish_diagnostic(dashboard: &mut Dashboard, outcome: DiagnosticOutcome) {
    dashboard.diagnostic_running = false;
    match outcome {
        DiagnosticOutcome::Ping {
            name,
            target,
            result: Ok(result),
        } => {
            let mut lines = vec![format!(
                "{} transmitted, {} received, {:.2}% loss · min/avg/max {}/{}/{}",
                result.transmitted,
                result.received,
                f64::from(result.loss_ppm) / 10_000.0,
                format_optional_ms(result.min_ms),
                format_optional_ms(result.avg_ms),
                format_optional_ms(result.max_ms),
            )];
            lines.extend(result.samples.iter().map(|sample| {
                if sample.reached {
                    format!(
                        "seq={} from={} time={}",
                        sample.sequence,
                        sample
                            .address
                            .map_or_else(|| "?".into(), |address| address.to_string()),
                        format_optional_ms(sample.elapsed_ms),
                    )
                } else {
                    format!("seq={} timeout", sample.sequence)
                }
            }));
            dashboard.diagnostic_report = DiagnosticReport {
                title: format!("Ping · {name} · {target}"),
                failed: result.received == 0,
                lines,
            };
            dashboard.push_event(
                if result.received == 0 {
                    Color::Yellow
                } else {
                    Color::Green
                },
                format!(
                    "ping {name}: {}/{} replies",
                    result.received, result.transmitted
                ),
            );
        }
        DiagnosticOutcome::Trace {
            name,
            target,
            result: Ok(result),
        } => {
            let lines = result
                .hops
                .iter()
                .map(|hop| {
                    format!(
                        "{:>2}  {:<39} {:>9}  {}",
                        hop.hop,
                        hop.address
                            .map_or_else(|| "*".into(), |address| address.to_string()),
                        format_optional_ms(hop.elapsed_ms),
                        hop.node_info.as_ref().map_or("", |info| info.name.as_str()),
                    )
                })
                .collect();
            dashboard.diagnostic_report = DiagnosticReport {
                title: format!("Trace · {name} · {target}"),
                failed: !result.reached,
                lines,
            };
            dashboard.push_event(
                if result.reached {
                    Color::Green
                } else {
                    Color::Yellow
                },
                format!(
                    "trace {name}: {} after {} hops",
                    if result.reached {
                        "reached"
                    } else {
                        "not reached"
                    },
                    result.hops.len()
                ),
            );
        }
        DiagnosticOutcome::Ping {
            name,
            target,
            result: Err(error),
        } => record_diagnostic_error(dashboard, format!("Ping · {name} · {target}"), error),
        DiagnosticOutcome::Trace {
            name,
            target,
            result: Err(error),
        } => record_diagnostic_error(dashboard, format!("Trace · {name} · {target}"), error),
    }
}

fn record_diagnostic_error(dashboard: &mut Dashboard, title: String, error: String) {
    dashboard.diagnostic_report = DiagnosticReport {
        title,
        lines: vec![error.clone()],
        failed: true,
    };
    dashboard.push_event(Color::Red, format!("diagnostic failed: {error}"));
}

async fn accept_selected_route(
    terminal: &mut DefaultTerminal,
    config_path: &Path,
    socket: &Path,
    registry_path: &Path,
    dashboard: &mut Dashboard,
    interval: Duration,
) {
    let Some(route) = dashboard.selected_route() else {
        dashboard.operation_message = Some("No route selected.".into());
        return;
    };
    if route.accepted {
        dashboard.operation_message = Some(format!("{} is already accepted.", route.prefix));
        return;
    }
    if route.ownership_conflict {
        dashboard.operation_message = Some(format!(
            "{} is already accepted from a different owner.",
            route.prefix
        ));
        return;
    }

    dashboard.operation_message = Some(format!(
        "Accepting {} from {}…",
        route.prefix, route.owner_name
    ));
    let _ = terminal.draw(|frame| render(frame, dashboard, interval));
    let result = mutate_route_registry(config_path, socket, registry_path, |registry| {
        registry.merge(RouteRegistry {
            version: 1,
            routes: vec![RouteOriginConfig {
                endpoint_id: route.owner,
                prefixes: vec![route.prefix],
            }],
        })
    })
    .await;
    finish_route_action(
        dashboard,
        registry_path,
        result,
        format!("accepted {} from {}", route.prefix, route.owner_name),
    )
    .await;
}

async fn remove_selected_route(
    terminal: &mut DefaultTerminal,
    config_path: &Path,
    socket: &Path,
    registry_path: &Path,
    dashboard: &mut Dashboard,
    interval: Duration,
) {
    let Some(route) = dashboard.selected_route() else {
        dashboard.operation_message = Some("No route selected.".into());
        return;
    };
    if !route.accepted {
        dashboard.operation_message = Some(format!(
            "{} is only declared, not accepted; nothing to remove.",
            route.prefix
        ));
        dashboard.pending_route_removal = None;
        return;
    }
    let confirmed = dashboard
        .pending_route_removal
        .as_ref()
        .is_some_and(|pending| {
            pending.key == route.key() && pending.requested_at.elapsed() <= REMOVE_CONFIRM_TTL
        });
    if !confirmed {
        dashboard.pending_route_removal = Some(PendingRouteRemoval {
            key: route.key(),
            requested_at: Instant::now(),
        });
        dashboard.operation_message = Some(format!(
            "Press x again within {}s to remove {} from accepted routes.",
            REMOVE_CONFIRM_TTL.as_secs(),
            route.prefix
        ));
        return;
    }

    dashboard.pending_route_removal = None;
    dashboard.operation_message = Some(format!("Removing {}…", route.prefix));
    let _ = terminal.draw(|frame| render(frame, dashboard, interval));
    let result = mutate_route_registry(config_path, socket, registry_path, |registry| {
        let removed = registry.remove(&route.prefix.to_string())?;
        ensure!(
            removed > 0,
            "accepted route {} no longer exists",
            route.prefix
        );
        Ok(())
    })
    .await;
    finish_route_action(
        dashboard,
        registry_path,
        result,
        format!("removed accepted route {}", route.prefix),
    )
    .await;
}

async fn mutate_route_registry(
    config_path: &Path,
    socket: &Path,
    registry_path: &Path,
    mutate: impl FnOnce(&mut RouteRegistry) -> Result<()>,
) -> Result<u64> {
    let previous = RouteRegistry::load(registry_path).await?;
    let mut candidate = previous.clone();
    mutate(&mut candidate)?;
    routes::validate_for_config(config_path, &candidate).await?;
    candidate.write(registry_path)?;
    match control::reload(socket).await {
        Ok(ack) => Ok(ack.generation),
        Err(error) => {
            previous
                .write(registry_path)
                .context("failed restoring the previous route registry")?;
            Err(error.context("daemon rejected the route change; previous routes restored"))
        }
    }
}

async fn finish_route_action(
    dashboard: &mut Dashboard,
    registry_path: &Path,
    result: Result<u64>,
    success: String,
) {
    match result {
        Ok(generation) => {
            match RouteRegistry::load(registry_path).await {
                Ok(registry) => dashboard.update_route_registry(registry),
                Err(error) => dashboard.last_error = Some(error.to_string()),
            }
            dashboard.operation_message =
                Some(format!("Route {success}; daemon generation {generation}."));
            dashboard.push_event(Color::Green, format!("route {success}"));
        }
        Err(error) => {
            dashboard.operation_message = Some(format!("Route change failed: {error}"));
            dashboard.push_event(Color::Red, format!("route change failed: {error}"));
        }
    }
    dashboard.clamp_selection();
}

fn render(frame: &mut Frame<'_>, dashboard: &Dashboard, interval: Duration) {
    let area = frame.area();
    if area.width < 80 || area.height < 22 {
        frame.render_widget(
            Paragraph::new("Terminal too small for ironet tui (minimum 80x22)")
                .block(Block::bordered().title(" ironet tui "))
                .wrap(Wrap { trim: true }),
            area,
        );
        return;
    }
    let main = match dashboard.view {
        TuiView::Peers => Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(if dashboard.detail_expanded { 9 } else { 5 }),
            Constraint::Length(1),
        ])
        .split(area),
        TuiView::Routes => Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(5),
            Constraint::Length(1),
        ])
        .split(area),
        TuiView::Diagnostics => Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Percentage(52),
            Constraint::Min(7),
            Constraint::Length(1),
        ])
        .split(area),
    };
    render_header(frame, main[0], dashboard, interval);
    render_summary(frame, main[1], dashboard);
    match dashboard.view {
        TuiView::Peers => {
            render_peers(frame, main[2], dashboard);
            render_bottom(frame, main[3], dashboard);
        }
        TuiView::Routes => {
            render_routes(frame, main[2], dashboard);
            render_route_detail(frame, main[3], dashboard);
        }
        TuiView::Diagnostics => {
            render_diagnostic_nodes(frame, main[2], dashboard);
            render_diagnostic_report(frame, main[3], dashboard);
        }
    }
    render_footer(frame, main[4], dashboard);
    if dashboard.show_help {
        render_help(frame, centered(area, 70, 19));
    }
}

fn render_diagnostic_nodes(frame: &mut Frame<'_>, area: Rect, dashboard: &Dashboard) {
    let nodes = dashboard.diagnostic_nodes();
    let rows = nodes.iter().enumerate().map(|(index, node)| {
        let target =
            diagnostic_target(node).map_or_else(|| "-".into(), |address| address.to_string());
        let state = if node.expires_unix_secs <= unix_now() {
            "EXPIRED"
        } else {
            "READY"
        };
        let state_style = match state {
            "READY" => Style::new().fg(Color::Green),
            "EXPIRED" => Style::new().fg(Color::Yellow),
            _ => Style::new().fg(Color::Red).bold(),
        };
        let row_style = if index == dashboard.selected_node {
            Style::new().bg(Color::DarkGray).bold()
        } else {
            Style::default()
        };
        Row::new([
            Cell::from(if index == dashboard.selected_node {
                ">"
            } else {
                " "
            }),
            Cell::from(short(node_name(node), 20)),
            Cell::from(short(&node.endpoint_id, 18)),
            Cell::from(target),
            Cell::from(node.prefixes.len().to_string()),
            Cell::from(if node.transit_enabled { "yes" } else { "no" }),
            Cell::from(Span::styled(state, state_style)),
            Cell::from(if node.expires_unix_secs <= unix_now() {
                "expired".into()
            } else {
                format!("in {}", human_duration(node.expires_unix_secs - unix_now()))
            }),
        ])
        .style(row_style)
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(1),
            Constraint::Length(20),
            Constraint::Length(18),
            Constraint::Length(39),
            Constraint::Length(8),
            Constraint::Length(7),
            Constraint::Length(12),
            Constraint::Min(10),
        ],
    )
    .header(
        Row::new([
            "", "NODE", "ENDPOINT", "TARGET", "PREFIXES", "TRANSIT", "STATE", "PRESENCE",
        ])
        .style(Style::new().fg(Color::Cyan).bold()),
    )
    .block(Block::bordered().title(format!(" mesh nodes {} · p ping · t trace ", nodes.len())))
    .column_spacing(1);
    frame.render_widget(table, area);
}

fn render_diagnostic_report(frame: &mut Frame<'_>, area: Rect, dashboard: &Dashboard) {
    let report = &dashboard.diagnostic_report;
    let lines = if report.lines.is_empty() {
        vec![Line::from(
            "Select a node with j/k, then press p for ping or t for trace.",
        )]
    } else {
        report
            .lines
            .iter()
            .take(area.height.saturating_sub(2) as usize)
            .map(|line| Line::from(line.as_str()))
            .collect()
    };
    let title = if report.title.is_empty() {
        " diagnostics ".into()
    } else {
        format!(" {} ", report.title)
    };
    frame.render_widget(
        Paragraph::new(lines)
            .style(Style::new().fg(if report.failed {
                Color::Red
            } else {
                Color::White
            }))
            .block(Block::bordered().title(title))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_routes(frame: &mut Frame<'_>, area: Rect, dashboard: &Dashboard) {
    let routes = dashboard.declared_routes();
    let rows = routes.iter().enumerate().map(|(index, route)| {
        let state_style = match route.state() {
            "ACCEPTED" => Style::new().fg(Color::Green),
            "DECLARED" => Style::new().fg(Color::Yellow).bold(),
            "CONFLICT" => Style::new().fg(Color::Red).bold(),
            _ => Style::new().fg(Color::DarkGray),
        };
        let row_style = if index == dashboard.selected_route {
            Style::new().bg(Color::DarkGray).bold()
        } else {
            Style::default()
        };
        let expires = route.expires_unix_secs.map_or_else(
            || "-".into(),
            |expires| {
                if expires <= unix_now() {
                    "expired".into()
                } else {
                    format!("in {}", human_duration(expires - unix_now()))
                }
            },
        );
        Row::new([
            Cell::from(if index == dashboard.selected_route {
                ">"
            } else {
                " "
            }),
            Cell::from(route.prefix.to_string()),
            Cell::from(short(&route.owner_name, 20)),
            Cell::from(short(&route.owner.to_string(), 18)),
            Cell::from(Span::styled(route.state(), state_style)),
            Cell::from(expires),
        ])
        .style(row_style)
    });
    let pending = routes
        .iter()
        .filter(|route| route.declared && !route.accepted && !route.ownership_conflict)
        .count();
    let accepted = routes.iter().filter(|route| route.accepted).count();
    let conflicts = routes
        .iter()
        .filter(|route| route.ownership_conflict)
        .count();
    let table = Table::new(
        rows,
        [
            Constraint::Length(1),
            Constraint::Length(24),
            Constraint::Length(20),
            Constraint::Length(18),
            Constraint::Length(10),
            Constraint::Min(10),
        ],
    )
    .header(
        Row::new(["", "PREFIX", "NODE", "ENDPOINT", "STATE", "PRESENCE"])
            .style(Style::new().fg(Color::Cyan).bold()),
    )
    .block(Block::bordered().title(format!(
        " declared routes {}  pending={} accepted={} conflicts={} ",
        routes.len(),
        pending,
        accepted,
        conflicts
    )))
    .column_spacing(1);
    frame.render_widget(table, area);
}

fn render_route_detail(frame: &mut Frame<'_>, area: Rect, dashboard: &Dashboard) {
    let Some(route) = dashboard.selected_route() else {
        frame.render_widget(
            Paragraph::new("No routes declared or accepted.")
                .block(Block::bordered().title(" route review ")),
            area,
        );
        return;
    };
    let action = if route.accepted {
        "[x] remove accepted route (press twice)"
    } else if route.ownership_conflict {
        "Conflict blocks acceptance. Resolve the ownership conflict first."
    } else {
        "[a] accept declared route"
    };
    let message = dashboard
        .operation_message
        .as_deref()
        .unwrap_or("Select a route with j/k, then accept or remove it.");
    let lines = vec![
        Line::from(format!(
            "{} from {} ({}) · state={} · declared={} accepted={}",
            route.prefix,
            route.owner_name,
            short(&route.owner.to_string(), 20),
            route.state(),
            route.declared,
            route.accepted,
        )),
        Line::from(Span::styled(action, Style::new().fg(Color::Cyan).bold())),
        Line::from(Span::styled(
            short(message, area.width.saturating_sub(4) as usize),
            Style::new().fg(if dashboard.last_error.is_some() {
                Color::Red
            } else {
                Color::Yellow
            }),
        )),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::bordered().title(" route review "))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_header(frame: &mut Frame<'_>, area: Rect, dashboard: &Dashboard, interval: Duration) {
    let Some(status) = &dashboard.status else {
        frame.render_widget(
            Paragraph::new("waiting for snapshot").block(Block::bordered()),
            area,
        );
        return;
    };
    let state = if status.ready {
        Span::styled(
            "READY",
            Style::new().fg(Color::Black).bg(Color::Green).bold(),
        )
    } else {
        Span::styled(
            "DEGRADED",
            Style::new().fg(Color::White).bg(Color::Red).bold(),
        )
    };
    let paused = dashboard
        .paused
        .then(|| Span::styled(" PAUSED", Style::new().fg(Color::Yellow).bold()));
    let age = unix_now().saturating_sub(status.updated_unix);
    let mut line = vec![
        Span::styled(
            " ironet ",
            Style::new().fg(Color::Black).bg(Color::Cyan).bold(),
        ),
        Span::raw("  "),
        state,
        Span::raw(format!(
            "  up {}  peers {}/{}  snapshot {} ago  interval {}",
            human_duration(status.uptime_seconds),
            status.peers.iter().filter(|peer| peer.connected).count(),
            status.peers.len(),
            human_duration(age),
            display::duration(interval),
        )),
    ];
    if let Some(paused) = paused {
        line.push(paused);
    }
    if let Some(error) = &dashboard.last_error {
        line.push(Span::styled(
            format!("  ERROR {}", short(error, 48)),
            Style::new().fg(Color::Red).bold(),
        ));
    } else if let Some(message) = &dashboard.operation_message {
        line.push(Span::styled(
            format!("  {}", short(message, 48)),
            Style::new().fg(Color::Yellow),
        ));
    }
    frame.render_widget(
        Paragraph::new(Line::from(line)).block(Block::new().borders(Borders::ALL).title(format!(
            " [Peers] [Routes] [Diagnostics] · {} · endpoint {} ",
            dashboard.view.as_str(),
            short(&status.endpoint_id, 16)
        ))),
        area,
    );
}

fn render_summary(frame: &mut Frame<'_>, area: Rect, dashboard: &Dashboard) {
    let Some(status) = &dashboard.status else {
        return;
    };
    let total = dashboard.total_history.back().copied().unwrap_or(0);
    let queues: u64 = status
        .peers
        .iter()
        .map(|peer| {
            peer.traffic
                .packet_train_queue_bytes
                .saturating_add(peer.traffic.latency_queue_bytes)
        })
        .sum();
    let drops: u64 = dashboard.rates.values().map(|rate| rate.drop_ps).sum();
    let errors: u64 = dashboard.rates.values().map(|rate| rate.error_ps).sum();
    let missing = status.routes.iter().filter(|route| !route.present).count();
    let text = Line::from(vec![
        Span::styled("RATE ", Style::new().fg(Color::DarkGray)),
        Span::styled(human_rate(total), Style::new().fg(Color::Cyan).bold()),
        Span::raw("   QUEUE "),
        Span::styled(human_bytes(queues), pressure_style(queues)),
        Span::raw("   DROP/s "),
        Span::styled(drops.to_string(), alert_style(drops)),
        Span::raw("   ERROR/s "),
        Span::styled(errors.to_string(), alert_style(errors)),
        Span::raw("   ROUTES "),
        Span::styled(
            format!("{} missing", missing),
            if missing == 0 {
                Style::new().fg(Color::Green)
            } else {
                Style::new().fg(Color::Red).bold()
            },
        ),
        Span::raw("   GW "),
        Span::styled(
            format!(
                "nat={} transit={} prefixes={}",
                if status.gateway.subnet_nat_enabled {
                    "on"
                } else {
                    "off"
                },
                if status.gateway.transit_enabled {
                    "on"
                } else {
                    "off"
                },
                status.gateway.advertised_prefixes.len()
            ),
            Style::new().fg(Color::Cyan),
        ),
    ]);
    frame.render_widget(Paragraph::new(text).block(Block::bordered()), area);
}

fn render_peers(frame: &mut Frame<'_>, area: Rect, dashboard: &Dashboard) {
    let peers = dashboard.visible_peers();
    let rows = peers.iter().enumerate().map(|(index, peer)| {
        let rate = dashboard
            .rates
            .get(&peer.endpoint_id)
            .copied()
            .unwrap_or_default();
        let style = if index == dashboard.selected {
            Style::new()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD)
        } else if !peer.connected {
            Style::new().fg(Color::Red)
        } else {
            Style::default()
        };
        Row::new([
            Cell::from(if index == dashboard.selected {
                ">"
            } else {
                " "
            }),
            Cell::from(short(&peer.name, 15)),
            Cell::from(if peer.connected { "up" } else { "DOWN" }),
            Cell::from(short(nonempty(&peer.selected_path_transport, "unknown"), 7)),
            Cell::from(format_micros(peer.path_rtt_micros)),
            Cell::from(human_bytes(
                peer.traffic
                    .packet_train_queue_bytes
                    .saturating_add(peer.traffic.latency_queue_bytes),
            )),
            Cell::from(human_rate(rate.tx_bps)),
            Cell::from(human_rate(rate.rx_bps)),
            Cell::from(format!(
                "{}/{}",
                human_rate(rate.latency_bps),
                human_rate(rate.bulk_bps)
            )),
            Cell::from(format!("{:.2}", peer.utility_total)),
            Cell::from(short(nonempty(&peer.bbr_preset, "-"), 10)),
            Cell::from(rate.drop_ps.to_string()),
        ])
        .style(style)
    });
    let widths = [
        Constraint::Length(1),
        Constraint::Length(15),
        Constraint::Length(5),
        Constraint::Length(7),
        Constraint::Length(8),
        Constraint::Length(9),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(19),
        Constraint::Length(7),
        Constraint::Length(10),
        Constraint::Length(7),
    ];
    let title = format!(
        " peers {}  filter={} sort={} ",
        peers.len(),
        if dashboard.filter_connected {
            "connected"
        } else {
            "all"
        },
        dashboard.sort.map_or("runtime", SortMode::as_str)
    );
    let table = Table::new(rows, widths)
        .header(
            Row::new([
                "", "PEER", "STATE", "PATH", "RTT", "QUEUE", "TX/s", "RX/s", "LAT/BULK", "U",
                "BBR", "DROP/s",
            ])
            .style(Style::new().fg(Color::Cyan).bold()),
        )
        .block(Block::bordered().title(title))
        .column_spacing(1);
    frame.render_widget(table, area);
}

fn render_bottom(frame: &mut Frame<'_>, area: Rect, dashboard: &Dashboard) {
    let detail_width = if dashboard.attention_active() { 50 } else { 65 };
    let columns = Layout::horizontal([
        Constraint::Percentage(detail_width),
        Constraint::Percentage(100 - detail_width),
    ])
    .split(area);
    render_detail(frame, columns[0], dashboard);
    render_events(frame, columns[1], dashboard);
}

fn render_detail(frame: &mut Frame<'_>, area: Rect, dashboard: &Dashboard) {
    let Some(peer) = dashboard.selected_peer() else {
        frame.render_widget(
            Paragraph::new("no peer selected").block(Block::bordered().title(" detail ")),
            area,
        );
        return;
    };
    let rate = dashboard
        .rates
        .get(&peer.endpoint_id)
        .copied()
        .unwrap_or_default();
    let title = format!(
        " {} · {} · {} {}",
        short(&peer.name, 18),
        short(nonempty(&peer.selected_path_transport, "unknown"), 10),
        if peer.connected { "UP" } else { "DOWN" },
        if dashboard.detail_expanded {
            "[d close]"
        } else {
            "[Enter details]"
        },
    );
    if !dashboard.detail_expanded {
        render_compact_detail(frame, area, peer, rate, &title);
        return;
    }

    let policy = &peer.policy;
    let shadow = policy.shadow.as_ref();
    let text = vec![
        Line::from(format!(
            "endpoint={}  remote={}",
            short(&peer.endpoint_id, 16),
            nonempty(&peer.selected_path_remote, "unknown")
        )),
        Line::from(format!(
            "tx={} rx={}  latency={} bulk={}  queue={}",
            human_rate(rate.tx_bps),
            human_rate(rate.rx_bps),
            human_rate(rate.latency_bps),
            human_rate(rate.bulk_bps),
            human_bytes(peer_queue_bytes(peer)),
        )),
        Line::from(format!(
            "queue split: latency={} train={} rx_budget={} preemptions={}",
            human_bytes(peer.traffic.latency_queue_bytes),
            human_bytes(peer.traffic.packet_train_queue_bytes),
            human_bytes(peer.traffic.receive_buffer_bytes),
            peer.traffic.bulk_preemptions,
        )),
        Line::from(format!(
            "mtu={} cwnd={} open_paths={} pmtu_drops={}/{}",
            peer.path_mtu,
            human_bytes(peer.path_cwnd_bytes),
            peer.open_paths,
            peer.traffic.pmtu_drop_datagrams,
            human_bytes(peer.traffic.pmtu_drop_bytes),
        )),
        Line::from(format!("drops/errors: {}", error_detail(peer))),
        Line::from(format!(
            "autotune: mode={} policy={} source={} U={:.3} reason={} bbr={} fec={} train={} rollbacks={}",
            nonempty(&peer.learner_mode, "unknown"),
            nonempty(&policy.live.policy_id, "unknown"),
            nonempty(&policy.policy_source, "unknown"),
            peer.utility_total,
            nonempty(&peer.tune_reason, "unknown"),
            nonempty(&peer.bbr_preset, "unknown"),
            nonempty(&peer.fec_geometry, "unknown"),
            human_bytes(peer.train_target_bytes),
            peer.learner_rollbacks,
        )),
        Line::from(format!(
            "shadow: policy={} preset={} predicted_advantage={:.3}",
            shadow.map_or("off", |slot| nonempty(&slot.policy_id, "off")),
            nonempty(&policy.shadow_preset, "-"),
            policy.shadow_advantage,
        )),
        Line::from(format!(
            "backend: {} {} abi={} health={} state={}B call={}us faults={} clamps={} [{}]",
            nonempty(&policy.live.backend, "-"),
            nonempty(&policy.live.policy_version, "-"),
            nonempty(&policy.live.abi_version, "-"),
            nonempty(&policy.live.health, "-"),
            policy.live.state_bytes,
            policy.live.last_call_micros,
            policy.live.faults_total,
            policy.live.clamped_fields_total,
            nonempty(&policy.live.last_clamp_reasons, "-"),
        )),
        Line::from(format!(
            "module: digest={} signer={} gen={} fuel={} timeouts={} quarantines={}",
            nonempty(&short(&policy.live.module_digest, 18), "-"),
            nonempty(&policy.live.signer_id, "-"),
            policy.live.module_generation,
            policy.live.fuel_consumed,
            policy.live.timeouts_total,
            policy.live.quarantines_total,
        )),
        Line::from(format!(
            "egress: requested={}/s assigned={}/s",
            human_bytes(peer.egress_requested_bytes_per_second),
            human_bytes(peer.egress_assigned_bytes_per_second),
        )),
        Line::from(format!("fec: {}", fec_detail(peer))),
        Line::from(format!(
            "wire: trains={} cells={} payload={} wire={} cover={}/{} control={}/{}",
            peer.traffic.trains_built,
            peer.traffic.cells_built,
            human_bytes(peer.traffic.cell_payload_tx_bytes),
            human_bytes(peer.traffic.data_cell_tx_bytes),
            human_bytes(peer.traffic.cover_tx_bytes),
            human_bytes(peer.traffic.cover_rx_bytes),
            human_bytes(peer.traffic.control_tx_bytes),
            human_bytes(peer.traffic.control_rx_bytes),
        )),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .block(Block::bordered().title(title))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn render_compact_detail(
    frame: &mut Frame<'_>,
    area: Rect,
    peer: &PeerStatus,
    rate: PeerRate,
    title: &str,
) {
    let (health_text, health_style) = peer_health(peer, rate);
    let text = vec![
        Line::from(vec![
            Span::styled("TX ", Style::new().fg(Color::DarkGray)),
            Span::styled(human_rate(rate.tx_bps), Style::new().fg(Color::Cyan).bold()),
            Span::raw("   RX "),
            Span::styled(human_rate(rate.rx_bps), Style::new().fg(Color::Cyan).bold()),
            Span::raw("   Queue "),
            Span::styled(
                format!(
                    "{} / {} pkt",
                    human_bytes(peer_queue_bytes(peer)),
                    peer.traffic.trains_built
                ),
                pressure_style(peer_queue_bytes(peer)),
            ),
        ]),
        Line::from(format!(
            "RTT {}   PMTU {}   cwnd {}",
            format_micros(peer.path_rtt_micros),
            peer.path_mtu,
            human_bytes(peer.path_cwnd_bytes),
        )),
        Line::from(format!(
            "U {:.2}   BBR {}   FEC {}",
            peer.utility_total,
            nonempty(&peer.bbr_preset, "-"),
            nonempty(&peer.fec_geometry, "-")
        )),
        Line::from(Span::styled(health_text, health_style)),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .block(Block::bordered().title(title))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn peer_health(peer: &PeerStatus, rate: PeerRate) -> (String, Style) {
    let mut messages = Vec::new();
    let mut style = Style::new().fg(Color::Green);
    if !peer.connected {
        messages.push("DOWN".to_string());
        style = Style::new().fg(Color::Red).bold();
    }
    if rate.error_ps > 0 {
        messages.push(format!("errors {}/s", rate.error_ps));
        style = Style::new().fg(Color::Red).bold();
    }
    if rate.drop_ps > 0 {
        messages.push(format!("drops {}/s", rate.drop_ps));
        if rate.error_ps == 0 {
            style = Style::new().fg(Color::Yellow).bold();
        }
    }
    if peer_queue_bytes(peer) >= 4 * 1024 * 1024 {
        messages.push(format!("queue {}", human_bytes(peer_queue_bytes(peer))));
        if rate.error_ps == 0 {
            style = Style::new().fg(Color::Yellow).bold();
        }
    }
    if messages.is_empty() {
        let fec = if peer.traffic.fec_recovered_cells > 0 {
            format!(" · FEC recovered {}", peer.traffic.fec_recovered_cells)
        } else {
            String::new()
        };
        (format!("✓ healthy{fec}"), style)
    } else {
        (format!("! {}", messages.join(" · ")), style)
    }
}

fn error_detail(peer: &PeerStatus) -> String {
    let mut errors = Vec::new();
    for (label, count) in [
        ("conn", peer.connection_errors),
        ("protocol", peer.traffic.protocol_datagram_errors),
        ("route", peer.traffic.route_gate_drops),
        ("admission", peer.traffic.tun_admission_drop_records),
        ("reassembly", peer.traffic.reassembly_pressure_evictions),
        ("pmtu", peer.traffic.pmtu_drop_datagrams),
        ("repair-stale", peer.traffic.repair_stale_responses),
    ] {
        if count > 0 {
            errors.push(format!("{label}={count}"));
        }
    }
    if errors.is_empty() {
        "none".into()
    } else {
        errors.join(" ")
    }
}

fn fec_detail(peer: &PeerStatus) -> String {
    let mut fields = Vec::new();
    for (label, count) in [
        ("tx", peer.traffic.fec_tx_cells),
        ("rx", peer.traffic.fec_rx_cells),
        ("recovered", peer.traffic.fec_recovered_cells),
        ("wasted", peer.traffic.fec_wasted_cells),
        ("unprotected", peer.traffic.fec_unprotected_tail_cells),
        ("expired", peer.traffic.fec_expired_stripes),
    ] {
        if count > 0 {
            fields.push(format!("{label}={count}"));
        }
    }
    if peer.traffic.fec_tx_bytes > 0 {
        fields.push(format!("wire={}", human_bytes(peer.traffic.fec_tx_bytes)));
    }
    if peer.traffic.repair_completed_requests > 0 {
        fields.push(format!(
            "repair={}/{} max={}",
            peer.traffic.repair_received_cells,
            peer.traffic.repair_requested_cells,
            format_micros(peer.traffic.repair_latency_max_micros)
        ));
    }
    if fields.is_empty() {
        "none".into()
    } else {
        fields.join(" ")
    }
}

fn render_events(frame: &mut Frame<'_>, area: Rect, dashboard: &Dashboard) {
    let lines = dashboard
        .events
        .iter()
        .take(area.height.saturating_sub(2) as usize)
        .map(|event| {
            Line::from(vec![
                Span::styled(
                    format!("{} ", short_time(event.when_unix)),
                    Style::new().fg(Color::DarkGray),
                ),
                Span::styled(
                    short(&event.message, area.width.saturating_sub(12) as usize),
                    Style::new().fg(event.severity),
                ),
            ])
        })
        .collect::<Vec<_>>();
    frame.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(" recent changes ")),
        area,
    );
}

fn render_footer(frame: &mut Frame<'_>, area: Rect, dashboard: &Dashboard) {
    let text = if dashboard.pending_reload.is_some() {
        format!(
            " Press R again to reload · Esc cancels/quit                                      traffic:{}",
            tiny_history(&dashboard.total_history)
        )
    } else {
        match dashboard.view {
            TuiView::Peers => format!(
                " q quit  Tab views  j/k select  Enter/d details  s sort  c connected  p pause  r refresh  R reload×2  ? help   traffic:{}",
                tiny_history(&dashboard.total_history)
            ),
            TuiView::Routes => format!(
                " q quit  Tab views  j/k select  a accept  x remove×2  Space pause  r refresh  R reload×2  ? help   traffic:{}",
                tiny_history(&dashboard.total_history)
            ),
            TuiView::Diagnostics => format!(
                " q quit  Tab views  j/k select  p ping  t trace  Space pause  r refresh  R reload×2  ? help   traffic:{}",
                tiny_history(&dashboard.total_history)
            ),
        }
    };
    frame.render_widget(
        Paragraph::new(text).style(Style::new().fg(Color::DarkGray)),
        area,
    );
}

fn render_help(frame: &mut Frame<'_>, area: Rect) {
    let text = vec![
        Line::from(Span::styled(
            "ironet tui",
            Style::new().fg(Color::Cyan).bold(),
        )),
        Line::from(""),
        Line::from("j / Down    select next item"),
        Line::from("k / Up      select previous item"),
        Line::from("Tab         next view: peers / routes / diagnostics"),
        Line::from("Shift+Tab   previous view"),
        Line::from("a           accept selected declared route"),
        Line::from("x x         remove selected accepted route"),
        Line::from("p           ping selected node (diagnostics) / pause"),
        Line::from("t           trace selected node (diagnostics)"),
        Line::from("R R         validate and reload daemon"),
        Line::from("s           cycle sort: traffic/rtt/queue/loss/name"),
        Line::from("c           show all / connected peers"),
        Line::from("Space       pause snapshots"),
        Line::from("r           refresh immediately"),
        Line::from("Enter / d   show / hide selected-peer details"),
        Line::from("?           close this help"),
        Line::from("q / Esc     quit"),
        Line::from(""),
        Line::from("Route changes validate, write atomically, and reload the daemon."),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .block(
                Block::bordered()
                    .title(" help ")
                    .style(Style::new().bg(Color::Black)),
            )
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn peer_rate(peer: &PeerStatus, previous: &PreviousPeer, now: Instant) -> PeerRate {
    let elapsed = now.saturating_duration_since(previous.sampled_at);
    PeerRate {
        tx_bps: per_second(
            peer.traffic.tx_bytes.saturating_sub(previous.tx_bytes),
            elapsed,
        ),
        rx_bps: per_second(
            peer.traffic.rx_bytes.saturating_sub(previous.rx_bytes),
            elapsed,
        ),
        latency_bps: per_second(
            peer.traffic
                .latency_service_bytes
                .saturating_sub(previous.latency_service_bytes),
            elapsed,
        ),
        bulk_bps: per_second(
            peer.traffic
                .bulk_service_bytes
                .saturating_sub(previous.bulk_service_bytes),
            elapsed,
        ),
        drop_ps: per_second(total_drops(peer).saturating_sub(previous.drops), elapsed),
        error_ps: per_second(total_errors(peer).saturating_sub(previous.errors), elapsed),
    }
}

fn per_second(delta: u64, elapsed: Duration) -> u64 {
    if elapsed.is_zero() {
        return 0;
    }
    (u128::from(delta) * 1_000_000_000 / elapsed.as_nanos()).min(u128::from(u64::MAX)) as u64
}

fn total_drops(peer: &PeerStatus) -> u64 {
    peer.traffic
        .route_gate_drops
        .saturating_add(peer.traffic.tun_admission_drop_records)
        .saturating_add(peer.traffic.reassembly_pressure_evictions)
        .saturating_add(peer.traffic.pmtu_drop_datagrams)
}

fn total_errors(peer: &PeerStatus) -> u64 {
    peer.connection_errors
        .saturating_add(peer.traffic.protocol_datagram_errors)
        .saturating_add(peer.traffic.repair_stale_responses)
}

fn peer_queue_bytes(peer: &PeerStatus) -> u64 {
    peer.traffic
        .packet_train_queue_bytes
        .saturating_add(peer.traffic.latency_queue_bytes)
}

fn peer_name(status: &RuntimeStatus, endpoint_id: EndpointId) -> Option<&str> {
    let endpoint_id = endpoint_id.to_string();
    status
        .peers
        .iter()
        .find(|peer| peer.endpoint_id == endpoint_id)
        .map(|peer| peer.name.as_str())
}

fn node_name(node: &MeshNodeStatus) -> &str {
    node.endpoint_id.as_str()
}

fn diagnostic_target(node: &MeshNodeStatus) -> Option<IpAddr> {
    node.node_addresses.first().map(IpNet::addr)
}

fn route_review_rank(route: &DeclaredRoute) -> u8 {
    if route.ownership_conflict {
        0
    } else if route.declared && !route.accepted {
        1
    } else if route.accepted && route.declared {
        2
    } else {
        3
    }
}

fn nonempty<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() { fallback } else { value }
}

fn short(value: &str, width: usize) -> String {
    let value = value.replace(['\n', '\r', '\t'], " ");
    if value.chars().count() <= width {
        return value;
    }
    if width <= 1 {
        return "…".chars().take(width).collect();
    }
    let mut result = value.chars().take(width - 1).collect::<String>();
    result.push('…');
    result
}

fn human_bytes(bytes: u64) -> String {
    display::bytes(bytes)
}

fn human_rate(bytes_per_second: u64) -> String {
    display::bytes_per_second(bytes_per_second)
}

fn format_micros(micros: u64) -> String {
    if micros == 0 {
        "?".into()
    } else {
        display::micros(micros)
    }
}

fn format_optional_ms(milliseconds: Option<f64>) -> String {
    milliseconds.map_or_else(|| "?".into(), |value| format!("{value:.2}ms"))
}

fn human_duration(seconds: u64) -> String {
    display::duration(Duration::from_secs(seconds))
}

fn pressure_style(bytes: u64) -> Style {
    if bytes >= 4 * 1024 * 1024 {
        Style::new().fg(Color::Red).bold()
    } else if bytes >= 512 * 1024 {
        Style::new().fg(Color::Yellow)
    } else {
        Style::new().fg(Color::Green)
    }
}

fn alert_style(value: u64) -> Style {
    if value == 0 {
        Style::new().fg(Color::Green)
    } else {
        Style::new().fg(Color::Red).bold()
    }
}

fn tiny_history(history: &VecDeque<u64>) -> String {
    const LEVELS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    let max = history.iter().copied().max().unwrap_or(0).max(1);
    history
        .iter()
        .rev()
        .take(24)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .map(|value| {
            let index = ((*value as u128 * (LEVELS.len() - 1) as u128) / max as u128) as usize;
            LEVELS[index]
        })
        .collect()
}

fn short_time(unix: u64) -> String {
    let seconds = unix % 86_400;
    format!(
        "{:02}:{:02}:{:02}",
        seconds / 3_600,
        seconds % 3_600 / 60,
        seconds % 60
    )
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width.saturating_sub(2));
    let height = height.min(area.height.saturating_sub(2));
    Rect::new(
        area.x + area.width.saturating_sub(width) / 2,
        area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    )
}

#[cfg(test)]
mod tests {
    use crate::status::{MeshNodeStatus, MeshStatus};
    use iroh::SecretKey;

    use super::*;

    fn peer(tx_bytes: u64, bulk: u64) -> PeerStatus {
        PeerStatus {
            name: "peer-a".into(),
            endpoint_id: "endpoint-a".into(),
            interface: "ironet0".into(),
            protocol_major: 2,
            connected: true,
            connection_events: 1,
            traffic: crate::status::PeerTrafficStatus {
                tx_packets: 10,
                tx_bytes,
                bulk_service_bytes: bulk,
                latency_queue_bytes: 512,
                packet_train_queue_bytes: 4_096,
                receive_buffer_bytes: 2_400,
                bulk_preemptions: 7,
                rx_packets: 4,
                rx_bytes: 500,
                ..crate::status::PeerTrafficStatus::default()
            },
            ..PeerStatus::default()
        }
    }

    #[test]
    fn rates_use_saturating_counter_deltas() {
        let start = Instant::now();
        let previous = PreviousPeer::from_peer(&peer(1_000, 1), start);
        let rate = peer_rate(&peer(3_000, 5), &previous, start + Duration::from_secs(2));
        assert_eq!(rate.tx_bps, 1_000);
        assert_eq!(rate.bulk_bps, 2);

        let reset = peer_rate(&peer(5, 0), &previous, start + Duration::from_secs(2));
        assert_eq!(reset.tx_bps, 0);
        assert_eq!(reset.bulk_bps, 0);
    }

    #[test]
    fn peer_fixture_exposes_v2_queue_isolation_detail() {
        let peer = peer(1_000, 1);
        assert_eq!(peer.traffic.latency_queue_bytes, 512);
        assert_eq!(peer.traffic.packet_train_queue_bytes, 4_096);
        assert_eq!(peer.traffic.receive_buffer_bytes, 2_400);
        assert_eq!(peer.traffic.bulk_preemptions, 7);
    }

    #[test]
    fn formatting_is_bounded_and_readable() {
        assert_eq!(short("abcdef", 4), "abc…");
        assert_eq!(human_bytes(1_500), "1.5KB");
        assert_eq!(human_rate(2_000_000), "2.0MB/s");
        assert_eq!(format_micros(12_500), "12.5ms");
    }

    #[test]
    fn views_cycle_in_both_directions() {
        let mut dashboard = Dashboard::default();
        assert_eq!(dashboard.view, TuiView::Peers);
        dashboard.change_view(false);
        assert_eq!(dashboard.view, TuiView::Routes);
        dashboard.change_view(false);
        assert_eq!(dashboard.view, TuiView::Diagnostics);
        dashboard.change_view(false);
        assert_eq!(dashboard.view, TuiView::Peers);
        dashboard.change_view(true);
        assert_eq!(dashboard.view, TuiView::Diagnostics);
    }

    #[test]
    fn diagnostic_target_uses_only_declared_host_addresses() {
        let mut node = MeshNodeStatus {
            endpoint_id: SecretKey::from_bytes(&[40; 32]).public().to_string(),
            sequence: 1,
            expires_unix_secs: unix_now() + 60,
            direct_addresses: Vec::new(),
            node_addresses: vec!["21.0.0.40/32".parse().unwrap()],
            prefixes: vec![
                "10.40.0.0/16".parse().unwrap(),
                "21.0.0.40/32".parse().unwrap(),
            ],
            transit_enabled: false,
        };
        assert_eq!(diagnostic_target(&node), Some("21.0.0.40".parse().unwrap()));
        node.node_addresses.clear();
        assert_eq!(diagnostic_target(&node), None);
    }

    #[test]
    fn compact_detail_prioritizes_health_and_hides_zero_counters() {
        let healthy = peer(1_000, 1);
        let (summary, style) = peer_health(&healthy, PeerRate::default());
        assert_eq!(summary, "✓ healthy");
        assert_eq!(style.fg, Some(Color::Green));
        assert_eq!(error_detail(&healthy), "none");
        assert_eq!(fec_detail(&healthy), "none");

        let mut impaired = peer(1_000, 1);
        impaired.connection_errors = 3;
        impaired.traffic.tun_admission_drop_records = 4;
        impaired.traffic.fec_recovered_cells = 5;
        impaired.traffic.fec_tx_bytes = 1_500;
        let (summary, style) = peer_health(
            &impaired,
            PeerRate {
                error_ps: 2,
                ..PeerRate::default()
            },
        );
        assert_eq!(summary, "! errors 2/s");
        assert_eq!(style.fg, Some(Color::Red));
        assert_eq!(error_detail(&impaired), "conn=3 admission=4");
        assert_eq!(fec_detail(&impaired), "recovered=5 wire=1.5KB");
    }

    #[test]
    fn declared_routes_distinguish_pending_accepted_offline_and_conflicts() {
        let first = SecretKey::from_bytes(&[41; 32]).public();
        let second = SecretKey::from_bytes(&[42; 32]).public();
        let accepted: IpNet = "10.41.0.0/16".parse().unwrap();
        let pending: IpNet = "10.42.0.0/16".parse().unwrap();
        let offline: IpNet = "10.43.0.0/16".parse().unwrap();
        let conflicting: IpNet = "10.44.0.0/16".parse().unwrap();
        let status: RuntimeStatus = serde_json::from_value(serde_json::json!({
            "ready": true,
            "endpoint_id": "local",
            "started_unix": 1,
            "updated_unix": 1,
            "uptime_seconds": 1,
            "peers": []
        }))
        .unwrap();
        let mut dashboard = Dashboard {
            status: Some(RuntimeStatus {
                mesh: MeshStatus {
                    enabled: true,
                    directory_entries: 2,
                    max_total_peers: 12,
                    nodes: vec![
                        MeshNodeStatus {
                            endpoint_id: first.to_string(),
                            sequence: 1,
                            expires_unix_secs: unix_now() + 60,
                            direct_addresses: Vec::new(),
                            node_addresses: Vec::new(),
                            prefixes: vec![accepted, pending, conflicting],
                            transit_enabled: false,
                        },
                        MeshNodeStatus {
                            endpoint_id: second.to_string(),
                            sequence: 1,
                            expires_unix_secs: unix_now() + 60,
                            direct_addresses: Vec::new(),
                            node_addresses: Vec::new(),
                            prefixes: vec![conflicting],
                            transit_enabled: false,
                        },
                    ],
                },
                ..status
            }),
            route_registry: RouteRegistry {
                version: 1,
                routes: vec![RouteOriginConfig {
                    endpoint_id: first,
                    prefixes: vec![accepted, offline],
                }],
            },
            ..Dashboard::default()
        };

        let routes = dashboard.declared_routes();
        assert_eq!(routes.len(), 5);
        assert_eq!(
            routes
                .iter()
                .find(|route| route.prefix == accepted)
                .unwrap()
                .state(),
            "ACCEPTED"
        );
        assert_eq!(
            routes
                .iter()
                .find(|route| route.prefix == pending)
                .unwrap()
                .state(),
            "DECLARED"
        );
        assert_eq!(
            routes
                .iter()
                .find(|route| route.prefix == offline)
                .unwrap()
                .state(),
            "OFFLINE"
        );
        assert_eq!(
            routes
                .iter()
                .find(|route| route.prefix == conflicting && route.owner == second)
                .unwrap()
                .state(),
            "CONFLICT"
        );

        dashboard.view = TuiView::Routes;
        dashboard.selected_route = routes
            .iter()
            .position(|route| route.prefix == pending)
            .unwrap();
        assert_eq!(dashboard.selected_route().unwrap().prefix, pending);
    }
}

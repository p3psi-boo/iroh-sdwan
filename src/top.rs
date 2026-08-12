use std::{
    collections::{HashMap, VecDeque},
    io::IsTerminal,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Result, ensure};
use ratatui::{
    DefaultTerminal, Frame,
    crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap},
};

use crate::{
    control,
    observability::{PeerStatus, RouteCapacityStatus, RuntimeStatus},
};

const HISTORY_LEN: usize = 60;
const EVENT_LIMIT: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SortMode {
    Name,
    Traffic,
    Rtt,
    Queue,
    Loss,
}

impl SortMode {
    fn next(self) -> Self {
        match self {
            Self::Name => Self::Traffic,
            Self::Traffic => Self::Rtt,
            Self::Rtt => Self::Queue,
            Self::Queue => Self::Loss,
            Self::Loss => Self::Name,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Traffic => "traffic",
            Self::Rtt => "rtt",
            Self::Queue => "queue",
            Self::Loss => "loss",
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct PeerRate {
    tx_bps: u64,
    rx_bps: u64,
    latency_pps: u64,
    bulk_pps: u64,
    drop_ps: u64,
    error_ps: u64,
}

#[derive(Debug, Clone)]
struct PreviousPeer {
    sampled_at: Instant,
    tx_bytes: u64,
    rx_bytes: u64,
    flow_latency_packets: u64,
    flow_bulk_packets: u64,
    drops: u64,
    errors: u64,
    connected: bool,
    selected_path_transport: String,
    selected_path_remote: String,
    path_switches: u64,
}

impl PreviousPeer {
    fn from_peer(peer: &PeerStatus, sampled_at: Instant) -> Self {
        Self {
            sampled_at,
            tx_bytes: peer.tx_bytes,
            rx_bytes: peer.rx_bytes,
            flow_latency_packets: peer.flow_latency_packets,
            flow_bulk_packets: peer.flow_bulk_packets,
            drops: total_drops(peer),
            errors: total_errors(peer),
            connected: peer.connected,
            selected_path_transport: peer.selected_path_transport.clone(),
            selected_path_remote: peer.selected_path_remote.clone(),
            path_switches: peer.path_switches,
        }
    }
}

#[derive(Debug, Clone)]
struct TopEvent {
    when_unix: u64,
    severity: Color,
    message: String,
}

#[derive(Debug, Default)]
struct Dashboard {
    status: Option<RuntimeStatus>,
    previous_peers: HashMap<String, PreviousPeer>,
    rates: HashMap<String, PeerRate>,
    total_history: VecDeque<u64>,
    events: VecDeque<TopEvent>,
    selected: usize,
    sort: Option<SortMode>,
    filter_connected: bool,
    paused: bool,
    show_help: bool,
    detail_expanded: bool,
    last_error: Option<String>,
    last_refresh: Option<Instant>,
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
        let previous_quarantined = previous.mesh.quarantined_entries;
        let previous_probe_failures = previous.capacity_probe_failures;
        let previous_flow_switches = previous.flow_router.route_switches;
        let previous_no_route_drops = previous.flow_router.no_route_drops;
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
        if status.mesh.quarantined_entries > previous_quarantined {
            self.push_event(
                Color::Red,
                format!(
                    "mesh quarantine {} -> {}",
                    previous_quarantined, status.mesh.quarantined_entries
                ),
            );
        }
        if status.capacity_probe_failures > previous_probe_failures {
            self.push_event(
                Color::Yellow,
                format!(
                    "capacity probe failures +{}",
                    status
                        .capacity_probe_failures
                        .saturating_sub(previous_probe_failures)
                ),
            );
        }
        if status.flow_router.route_switches > previous_flow_switches {
            self.push_event(
                Color::Cyan,
                format!(
                    "FlowRouter route switches +{}",
                    status
                        .flow_router
                        .route_switches
                        .saturating_sub(previous_flow_switches)
                ),
            );
        }
        if status.flow_router.no_route_drops > previous_no_route_drops {
            self.push_event(
                Color::Red,
                format!(
                    "FlowRouter no-route drops +{}",
                    status
                        .flow_router
                        .no_route_drops
                        .saturating_sub(previous_no_route_drops)
                ),
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
        if previous.path_switches != peer.path_switches
            || previous.selected_path_transport != peer.selected_path_transport
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
        self.events.push_front(TopEvent {
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
                    .queue_bytes
                    .cmp(&left.queue_bytes)
                    .then_with(|| left.name.cmp(&right.name)),
                SortMode::Loss => right
                    .path_loss_ppm
                    .cmp(&left.path_loss_ppm)
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

    fn move_selection(&mut self, delta: isize) {
        let len = self.visible_peers().len();
        if len == 0 {
            self.selected = 0;
            return;
        }
        self.selected = self
            .selected
            .saturating_add_signed(delta)
            .min(len.saturating_sub(1));
    }

    fn clamp_selection(&mut self) {
        self.selected = self
            .selected
            .min(self.visible_peers().len().saturating_sub(1));
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

pub async fn run(socket: &Path, interval: Duration) -> Result<()> {
    ensure!(
        interval >= Duration::from_millis(200) && interval <= Duration::from_secs(60),
        "top interval must be between 200 ms and 60 s"
    );
    ensure!(
        std::io::stdout().is_terminal() && std::io::stdin().is_terminal(),
        "top requires an interactive terminal"
    );

    let mut dashboard = Dashboard::default();
    let initial = control::snapshot(socket).await?;
    dashboard.update(initial, Instant::now());

    let mut terminal = ratatui::init();
    let _guard = TerminalGuard::enter();
    run_loop(&mut terminal, socket, interval, &mut dashboard).await
}

async fn run_loop(
    terminal: &mut DefaultTerminal,
    socket: &Path,
    interval: Duration,
    dashboard: &mut Dashboard,
) -> Result<()> {
    let mut next_refresh = Instant::now() + interval;
    loop {
        terminal.draw(|frame| render(frame, dashboard, interval))?;
        let timeout = next_refresh.saturating_duration_since(Instant::now());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                match key.code {
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return Ok(());
                    }
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Char('?') => dashboard.show_help = !dashboard.show_help,
                    KeyCode::Char('p') | KeyCode::Char(' ') => dashboard.paused = !dashboard.paused,
                    KeyCode::Char('c') => {
                        dashboard.filter_connected = !dashboard.filter_connected;
                        dashboard.clamp_selection();
                    }
                    KeyCode::Char('s') => {
                        dashboard.sort =
                            Some(dashboard.sort.map_or(SortMode::Traffic, SortMode::next));
                        dashboard.clamp_selection();
                    }
                    KeyCode::Char('r') => next_refresh = Instant::now(),
                    KeyCode::Enter | KeyCode::Char('d') => {
                        dashboard.detail_expanded = !dashboard.detail_expanded;
                    }
                    KeyCode::Down | KeyCode::Char('j') => dashboard.move_selection(1),
                    KeyCode::Up | KeyCode::Char('k') => dashboard.move_selection(-1),
                    _ => {}
                }
            }
        } else if !dashboard.paused {
            match control::snapshot(socket).await {
                Ok(status) => dashboard.update(status, Instant::now()),
                Err(error) => {
                    let message = error.to_string();
                    if dashboard.last_error.as_deref() != Some(&message) {
                        dashboard.push_event(Color::Red, format!("snapshot failed: {message}"));
                    }
                    dashboard.last_error = Some(message);
                }
            }
            next_refresh = Instant::now() + interval;
        } else {
            next_refresh = Instant::now() + interval;
        }
    }
}

fn render(frame: &mut Frame<'_>, dashboard: &Dashboard, interval: Duration) {
    let area = frame.area();
    if area.width < 80 || area.height < 22 {
        frame.render_widget(
            Paragraph::new("Terminal too small for iroh-sdwan top (minimum 80x22)")
                .block(Block::bordered().title(" iroh-sdwan top "))
                .wrap(Wrap { trim: true }),
            area,
        );
        return;
    }
    let main = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(3),
        Constraint::Min(8),
        Constraint::Length(if dashboard.detail_expanded { 9 } else { 5 }),
        Constraint::Length(1),
    ])
    .split(area);
    render_header(frame, main[0], dashboard, interval);
    render_summary(frame, main[1], dashboard);
    render_peers(frame, main[2], dashboard);
    render_bottom(frame, main[3], dashboard);
    render_footer(frame, main[4], dashboard);
    if dashboard.show_help {
        render_help(frame, centered(area, 64, 16));
    }
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
            " iroh-sdwan ",
            Style::new().fg(Color::Black).bg(Color::Cyan).bold(),
        ),
        Span::raw("  "),
        state,
        Span::raw(format!(
            "  up {}  peers {}/{}  snapshot {}s  interval {:.1}s",
            human_duration(status.uptime_seconds),
            status.peers.iter().filter(|peer| peer.connected).count(),
            status.peers.len(),
            age,
            interval.as_secs_f64(),
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
    }
    frame.render_widget(
        Paragraph::new(Line::from(line)).block(
            Block::new()
                .borders(Borders::ALL)
                .title(format!(" endpoint {} ", short(&status.endpoint_id, 16))),
        ),
        area,
    );
}

fn render_summary(frame: &mut Frame<'_>, area: Rect, dashboard: &Dashboard) {
    let Some(status) = &dashboard.status else {
        return;
    };
    let total = dashboard.total_history.back().copied().unwrap_or(0);
    let queues: u64 = status.peers.iter().map(|peer| peer.queue_bytes).sum();
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
        Span::raw("   PROBE "),
        Span::styled(
            format!(
                "{} fail={} table={}/{}",
                if status.capacity_probe_in_flight {
                    "active"
                } else {
                    "idle"
                },
                status.capacity_probe_failures,
                status.capacity_table_entries,
                status.capacity_table_limit
            ),
            Style::new().fg(if status.capacity_probe_failures == 0 {
                Color::Green
            } else {
                Color::Yellow
            }),
        ),
        Span::raw("   FLOWS "),
        Span::styled(
            format!(
                "{}/{} sw={} noroute={}",
                status.flow_router.active_flows,
                status.flow_router.max_flows,
                status.flow_router.route_switches,
                status.flow_router.no_route_drops,
            ),
            Style::new().fg(if status.flow_router.no_route_drops == 0 {
                Color::Green
            } else {
                Color::Yellow
            }),
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
            Cell::from(format_micros(peer.path_jitter_micros)),
            Cell::from(format_loss(peer.path_loss_ppm)),
            Cell::from(human_bytes(peer.queue_bytes)),
            Cell::from(human_rate(rate.tx_bps)),
            Cell::from(human_rate(rate.rx_bps)),
            Cell::from(format!("{}/{}", rate.latency_pps, rate.bulk_pps)),
            Cell::from(rate.drop_ps.to_string()),
            Cell::from(peer.path_switches.to_string()),
        ])
        .style(style)
    });
    let widths = [
        Constraint::Length(1),
        Constraint::Length(15),
        Constraint::Length(5),
        Constraint::Length(7),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(7),
        Constraint::Length(9),
        Constraint::Length(10),
        Constraint::Length(10),
        Constraint::Length(11),
        Constraint::Length(7),
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
                "", "PEER", "STATE", "PATH", "RTT", "JITTER", "LOSS", "QUEUE", "TX/s", "RX/s",
                "LAT/BULK", "DROP/s", "SWITCH",
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

    let capacity = best_capacity(&peer.capacities);
    let cap = detailed_capacity(capacity);
    let text = vec![
        Line::from(format!(
            "endpoint={}  remote={}",
            short(&peer.endpoint_id, 16),
            nonempty(&peer.selected_path_remote, "unknown")
        )),
        Line::from(format!(
            "tx={} rx={}  latency={}pps bulk={}pps  queue={} packets={} priority_age={}",
            human_rate(rate.tx_bps),
            human_rate(rate.rx_bps),
            rate.latency_pps,
            rate.bulk_pps,
            human_bytes(peer.queue_bytes),
            peer.queue_packets,
            format_micros(peer.queue_max_age_micros),
        )),
        Line::from(format!(
            "queue split: priority={}/{} bulk={}/{} active={} quic={} preemptions={}",
            human_bytes(peer.priority_queue_bytes),
            peer.priority_queue_packets,
            human_bytes(peer.bulk_queue_bytes),
            peer.bulk_queue_packets,
            human_bytes(peer.active_tx_bytes),
            human_bytes(peer.quic_send_buffer_used_bytes),
            peer.bulk_preemptions,
        )),
        Line::from(cap),
        Line::from(format!(
            "mtu={} frame={} cwnd={} open_paths={} path_lost={} mtu_reframes={}",
            peer.path_mtu,
            peer.effective_frame_size,
            human_bytes(peer.path_cwnd_bytes),
            peer.open_paths,
            peer.path_lost_packets,
            peer.mtu_reframes,
        )),
        Line::from(format!("errors: {}", error_detail(peer))),
        Line::from(format!("fec: {}", fec_detail(peer))),
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
    let capacity = best_capacity(&peer.capacities);
    let (capacity_text, capacity_style) = compact_capacity(capacity);
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
                    human_bytes(peer.queue_bytes),
                    peer.queue_packets
                ),
                pressure_style(peer.queue_bytes),
            ),
        ]),
        Line::from(vec![
            Span::raw(format!(
                "RTT {} ±{}   Loss {}   ",
                format_micros(peer.path_rtt_micros),
                format_micros(peer.path_jitter_micros),
                format_loss(peer.path_loss_ppm),
            )),
            Span::styled(capacity_text, capacity_style),
        ]),
        Line::from(Span::styled(health_text, health_style)),
    ];
    frame.render_widget(
        Paragraph::new(text)
            .block(Block::bordered().title(title))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn compact_capacity(capacity: Option<&RouteCapacityStatus>) -> (String, Style) {
    capacity.map_or_else(
        || ("Capacity unknown".into(), Style::new().fg(Color::DarkGray)),
        |route| {
            let health = f64::from(route.health_per_mille) / 10.0;
            (
                format!(
                    "Capacity {} · {:.0}%",
                    human_rate(route.effective_capacity_bps / 8),
                    health
                ),
                capacity_health_style(route.health_per_mille),
            )
        },
    )
}

fn detailed_capacity(capacity: Option<&RouteCapacityStatus>) -> String {
    capacity.map_or_else(
        || "capacity unknown".to_string(),
        |route| {
            format!(
                "capacity={} health={:.1}% age={} source={} probe={}",
                human_rate(route.effective_capacity_bps / 8),
                f64::from(route.health_per_mille) / 10.0,
                route
                    .sample_age_millis
                    .map_or_else(|| "?".into(), |age| format!("{}ms", age)),
                route.sample_source.as_deref().unwrap_or("none"),
                if route.probe_in_flight {
                    "active"
                } else {
                    "idle"
                }
            )
        },
    )
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
    if peer.path_loss_ppm >= 1_000 {
        messages.push(format!("loss {}", format_loss(peer.path_loss_ppm)));
        if rate.error_ps == 0 {
            style = Style::new().fg(Color::Yellow).bold();
        }
    }
    if peer.queue_bytes >= 4 * 1024 * 1024 {
        messages.push(format!("queue {}", human_bytes(peer.queue_bytes)));
        if rate.error_ps == 0 {
            style = Style::new().fg(Color::Yellow).bold();
        }
    }
    if messages.is_empty() {
        let fec = (peer.fec_recovered_shards > 0)
            .then(|| format!(" · FEC recovered {}", peer.fec_recovered_shards))
            .unwrap_or_default();
        (format!("✓ healthy{fec}"), style)
    } else {
        (format!("! {}", messages.join(" · ")), style)
    }
}

fn capacity_health_style(health_per_mille: u16) -> Style {
    if health_per_mille >= 900 {
        Style::new().fg(Color::Green)
    } else if health_per_mille >= 700 {
        Style::new().fg(Color::Yellow)
    } else {
        Style::new().fg(Color::Red).bold()
    }
}

fn error_detail(peer: &PeerStatus) -> String {
    let mut errors = Vec::new();
    for (label, count) in [
        ("conn", peer.connection_errors),
        ("send", peer.send_errors),
        ("invalid", peer.invalid_packets),
        ("policy", peer.policy_drops),
        ("frame", peer.frame_drops),
        ("queue", peer.queue_drops),
        ("expired", peer.queue_expired_drops),
        ("reassembly", peer.reassembly_evictions),
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
        ("tx", peer.fec_tx_recovery_shards),
        ("rx", peer.fec_rx_recovery_shards),
        ("recovered", peer.fec_recovered_shards),
        ("unprotected", peer.fec_unprotected_shards),
        ("expired", peer.fec_expired_blocks),
    ] {
        if count > 0 {
            fields.push(format!("{label}={count}"));
        }
    }
    if peer.fec_overhead_bytes > 0 {
        fields.push(format!("overhead={}", human_bytes(peer.fec_overhead_bytes)));
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
    let text = format!(
        " q quit  j/k select  Enter/d details  s sort  c connected  p pause  r refresh  ? help   traffic:{}",
        tiny_history(&dashboard.total_history)
    );
    frame.render_widget(
        Paragraph::new(text).style(Style::new().fg(Color::DarkGray)),
        area,
    );
}

fn render_help(frame: &mut Frame<'_>, area: Rect) {
    let text = vec![
        Line::from(Span::styled(
            "iroh-sdwan top",
            Style::new().fg(Color::Cyan).bold(),
        )),
        Line::from(""),
        Line::from("j / Down    select next peer"),
        Line::from("k / Up      select previous peer"),
        Line::from("s           cycle sort: traffic/rtt/queue/loss/name"),
        Line::from("c           show all / connected peers"),
        Line::from("p / Space   pause snapshots"),
        Line::from("r           refresh immediately"),
        Line::from("Enter / d   show / hide selected-peer details"),
        Line::from("?           close this help"),
        Line::from("q / Esc     quit"),
        Line::from(""),
        Line::from("Rates and events are deltas between daemon snapshots."),
        Line::from("No per-packet trace state is enabled by this command."),
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
        tx_bps: per_second(peer.tx_bytes.saturating_sub(previous.tx_bytes), elapsed),
        rx_bps: per_second(peer.rx_bytes.saturating_sub(previous.rx_bytes), elapsed),
        latency_pps: per_second(
            peer.flow_latency_packets
                .saturating_sub(previous.flow_latency_packets),
            elapsed,
        ),
        bulk_pps: per_second(
            peer.flow_bulk_packets
                .saturating_sub(previous.flow_bulk_packets),
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
    peer.invalid_packets
        .saturating_add(peer.policy_drops)
        .saturating_add(peer.frame_drops)
        .saturating_add(peer.queue_drops)
        .saturating_add(peer.queue_expired_drops)
        .saturating_add(peer.reassembly_evictions)
}

fn total_errors(peer: &PeerStatus) -> u64 {
    peer.connection_errors
        .saturating_add(peer.send_errors)
        .saturating_add(peer.trace_errors)
}

fn best_capacity(capacities: &[RouteCapacityStatus]) -> Option<&RouteCapacityStatus> {
    capacities
        .iter()
        .max_by_key(|capacity| capacity.effective_capacity_bps)
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
    human_unit(bytes, "B")
}

fn human_rate(bytes_per_second: u64) -> String {
    format!("{}/s", human_unit(bytes_per_second, "B"))
}

fn human_unit(value: u64, unit: &str) -> String {
    const UNITS: [&str; 4] = ["", "K", "M", "G"];
    let mut value = value as f64;
    let mut index = 0;
    while value >= 1000.0 && index + 1 < UNITS.len() {
        value /= 1000.0;
        index += 1;
    }
    if index == 0 {
        format!("{}{}{}", value as u64, UNITS[index], unit)
    } else if value >= 100.0 {
        format!("{value:.0}{}{}", UNITS[index], unit)
    } else {
        format!("{value:.1}{}{}", UNITS[index], unit)
    }
}

fn format_micros(micros: u64) -> String {
    if micros == 0 {
        "?".into()
    } else if micros < 1000 {
        format!("{}us", micros)
    } else {
        format!("{:.1}ms", micros as f64 / 1000.0)
    }
}

fn format_loss(ppm: u64) -> String {
    if ppm == 0 {
        "0%".into()
    } else {
        format!("{:.2}%", ppm as f64 / 10_000.0)
    }
}

fn human_duration(seconds: u64) -> String {
    let days = seconds / 86_400;
    let hours = seconds % 86_400 / 3_600;
    let minutes = seconds % 3_600 / 60;
    if days > 0 {
        format!("{days}d{hours:02}h")
    } else if hours > 0 {
        format!("{hours}h{minutes:02}m")
    } else {
        format!("{minutes}m{:02}s", seconds % 60)
    }
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
    use super::*;

    fn peer(tx_bytes: u64, bulk: u64) -> PeerStatus {
        serde_json::from_value(serde_json::json!({
            "name": "peer-a",
            "endpoint_id": "endpoint-a",
            "interface": "isw0",
            "connected": true,
            "connection_events": 1,
            "tx_packets": 10,
            "tx_bytes": tx_bytes,
            "flow_bulk_packets": bulk,
            "priority_queue_packets": 2,
            "priority_queue_bytes": 512,
            "bulk_queue_packets": 3,
            "bulk_queue_bytes": 4096,
            "active_tx_bytes": 1200,
            "quic_send_buffer_used_bytes": 2400,
            "bulk_preemptions": 7,
            "rx_packets": 4,
            "rx_bytes": 500,
            "tx_fragments": 0,
            "rx_fragments": 0,
            "invalid_packets": 0,
            "policy_drops": 0,
            "frame_drops": 0,
            "send_errors": 0
        }))
        .unwrap()
    }

    #[test]
    fn rates_use_saturating_counter_deltas() {
        let start = Instant::now();
        let previous = PreviousPeer::from_peer(&peer(1_000, 1), start);
        let rate = peer_rate(&peer(3_000, 5), &previous, start + Duration::from_secs(2));
        assert_eq!(rate.tx_bps, 1_000);
        assert_eq!(rate.bulk_pps, 2);

        let reset = peer_rate(&peer(5, 0), &previous, start + Duration::from_secs(2));
        assert_eq!(reset.tx_bps, 0);
        assert_eq!(reset.bulk_pps, 0);
    }

    #[test]
    fn peer_fixture_exposes_queue_isolation_detail() {
        let peer = peer(1_000, 1);
        assert_eq!(peer.priority_queue_packets, 2);
        assert_eq!(peer.priority_queue_bytes, 512);
        assert_eq!(peer.bulk_queue_packets, 3);
        assert_eq!(peer.bulk_queue_bytes, 4_096);
        assert_eq!(peer.active_tx_bytes, 1_200);
        assert_eq!(peer.quic_send_buffer_used_bytes, 2_400);
        assert_eq!(peer.bulk_preemptions, 7);
    }

    #[test]
    fn formatting_is_bounded_and_readable() {
        assert_eq!(short("abcdef", 4), "abc…");
        assert_eq!(human_bytes(1_500), "1.5KB");
        assert_eq!(human_rate(2_000_000), "2.0MB/s");
        assert_eq!(format_micros(12_500), "12.5ms");
        assert_eq!(format_loss(10_000), "1.00%");
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
        impaired.send_errors = 3;
        impaired.queue_drops = 4;
        impaired.fec_recovered_shards = 5;
        impaired.fec_overhead_bytes = 1_500;
        let (summary, style) = peer_health(
            &impaired,
            PeerRate {
                error_ps: 2,
                ..PeerRate::default()
            },
        );
        assert_eq!(summary, "! errors 2/s");
        assert_eq!(style.fg, Some(Color::Red));
        assert_eq!(error_detail(&impaired), "send=3 queue=4");
        assert_eq!(fec_detail(&impaired), "recovered=5 overhead=1.5KB");
    }
}

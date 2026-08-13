use std::{
    collections::HashSet,
    fmt::{Display, Write as _},
    io::{BufRead, IsTerminal, Write},
    net::{IpAddr, SocketAddr},
    os::unix::fs::FileTypeExt,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand, ValueEnum};
use ipnet::IpNet;
use iroh::EndpointId;
use iroh_sdwan::{
    address::network_alpn,
    config::{
        AttachmentMode, Config, FecConfig, ObservabilityConfig, PacketPolicyConfig, PeerConfig,
        RelayConfig, RoutingConfig,
    },
    control::{self, DEFAULT_CONTROL_SOCKET},
    deployment,
    derp::{DerpPublicKey, identity::DerpIdentity, probe_server, tls_config},
    display, identity, logging,
    observability::{PeerStatus, RuntimeStatus},
    routes::RouteRegistry,
    trace::{self, PingResult},
    tui,
};

#[derive(Debug, Parser)]
#[command(name = "iroh-sdwan", version, about)]
struct Cli {
    /// Configuration file. May also be set with IROH_SDWAN_CONFIG.
    #[arg(
        short = 'c',
        long,
        global = true,
        env = "IROH_SDWAN_CONFIG",
        default_value = "/etc/iroh-sdwan/config.toml"
    )]
    config: PathBuf,
    /// Daemon control socket. May also be set with IROH_SDWAN_SOCKET.
    #[arg(
        long,
        global = true,
        env = "IROH_SDWAN_SOCKET",
        default_value = DEFAULT_CONTROL_SOCKET
    )]
    socket: PathBuf,
    /// Reduce operational logging and suppress successful health output.
    #[arg(short, long, global = true)]
    quiet: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    #[default]
    Human,
    Json,
    #[value(alias = "ndjson")]
    Jsonl,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a node identity and initial configuration.
    Init {
        #[arg(long, default_value = "/var/lib/iroh-sdwan")]
        state_dir: PathBuf,
        /// Shared network join secret. Omit on the first node to generate one;
        /// pass the printed value when initialising additional nodes.
        #[arg(long)]
        network_id: Option<String>,
        /// Tailscale DERP URL; repeat once per region.
        #[arg(long = "derp-server")]
        derp_servers: Vec<String>,
        /// Do not ask setup questions. Values not supplied on the command line
        /// use their defaults.
        #[arg(long)]
        non_interactive: bool,
    },
    /// Print the deterministic interface and address plan.
    Inspect,
    /// Measure end-to-end RTT over the FlowRouter-selected overlay path.
    Ping {
        /// Destination node IPv4 or IPv6 overlay address.
        target: IpAddr,
        #[arg(short = 'n', long, default_value_t = 4, value_parser = clap::value_parser!(u16).range(1..=20))]
        count: u16,
        #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(1..=60_000))]
        timeout_ms: u64,
        /// Output for humans, a JSON document, or a compact JSON line.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// Print live adjacency state and measured path metrics.
    Peers {
        /// Output for humans, a JSON array, or one JSON object per peer.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// Trace the FlowRouter-selected overlay path and print each node's configured node_info.
    Trace {
        /// Destination node IPv4 or IPv6 overlay address.
        target: IpAddr,
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u8).range(1..=255))]
        max_hops: u8,
        #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(1..=60_000))]
        timeout_ms: u64,
        /// Output for humans, a JSON document, or one JSON object per hop.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// Print the last atomically published runtime status.
    Status {
        /// Output for humans or for pipelines.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
        /// Legacy alias for --output json.
        #[arg(long)]
        json: bool,
    },
    /// Open the interactive operations console for peers, routes, and diagnostics.
    #[command(visible_alias = "top")]
    Tui {
        /// Refresh interval in milliseconds.
        #[arg(long, default_value_t = 1_000, value_parser = clap::value_parser!(u64).range(200..=60_000))]
        interval_ms: u64,
    },
    /// Exit successfully only when the runtime is ready and its status is fresh.
    Health,
    /// Validate and atomically activate the current configuration.
    Reload,
    /// Validate configuration, identity, route policy, and the local endpoint ID.
    Validate,
    /// Validate a manually edited configuration and write its integrity digest.
    SealConfig,
    /// Atomically install a validated configuration and retain a previous copy.
    InstallConfig {
        #[arg(long)]
        source: PathBuf,
    },
    /// Swap the active configuration with its validated previous copy.
    RollbackConfig,
    /// Copy the configured node identity into a new mode-0600 backup.
    BackupIdentity {
        #[arg(long)]
        output: PathBuf,
    },
    /// Restore an identity only when the destination does not exist.
    RestoreIdentity {
        #[arg(long)]
        source: PathBuf,
        #[arg(long, default_value = "/var/lib/iroh-sdwan/identity.key")]
        identity_file: PathBuf,
    },
    /// Check host prerequisites and underlay reachability without changing state.
    Doctor,
    /// Manage the independent static route registry.
    Route {
        #[command(subcommand)]
        command: RouteCommand,
    },
}

#[derive(Debug, Subcommand)]
enum RouteCommand {
    /// Add one or more prefixes for a configured peer name or endpoint ID.
    Add {
        #[arg(required = true, value_name = "PREFIX")]
        prefixes: Vec<IpNet>,
        /// Final owner of these prefixes: a configured peer name or endpoint ID.
        #[arg(long, value_name = "PEER_OR_ENDPOINT_ID")]
        owner: String,
        /// Validate and preview the change without saving it.
        #[arg(long)]
        dry_run: bool,
        /// Save now and apply on the next daemon reload.
        #[arg(long, visible_alias = "no-reload")]
        defer: bool,
    },
    /// Merge routes from TOML or `<endpoint-id> <prefix>...` text.
    Import {
        /// Import file, or `-` to read from standard input.
        source: PathBuf,
        /// Replace the registry instead of merging it.
        #[arg(long)]
        replace: bool,
        /// Validate and preview the change without saving it.
        #[arg(long)]
        dry_run: bool,
        /// Save now and apply on the next daemon reload.
        #[arg(long, visible_alias = "no-reload")]
        defer: bool,
    },
    /// List routes from routes.toml.
    #[command(visible_alias = "ls")]
    List {
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// Remove prefixes or all routes owned by a configured peer/endpoint ID.
    #[command(visible_alias = "rm")]
    Remove {
        #[arg(required = true, value_name = "PREFIX_OR_OWNER")]
        selectors: Vec<String>,
        /// Validate and preview the change without saving it.
        #[arg(long)]
        dry_run: bool,
        /// Save now and apply on the next daemon reload.
        #[arg(long, visible_alias = "no-reload")]
        defer: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    logging::init(cli.quiet);
    let config = cli.config;
    let socket = cli.socket;

    match cli.command {
        Command::Init {
            state_dir,
            network_id,
            derp_servers,
            non_interactive,
        } => {
            init(
                &config,
                &state_dir,
                network_id,
                derp_servers,
                non_interactive,
            )
            .await
        }
        Command::Inspect => inspect(&config).await,
        Command::Ping {
            target,
            count,
            timeout_ms,
            output,
        } => ping(&socket, target, count, timeout_ms, output).await,
        Command::Peers { output } => peers(&socket, output).await,
        Command::Trace {
            target,
            max_hops,
            timeout_ms,
            output,
        } => {
            let result = control::trace_with(
                &socket,
                target,
                max_hops,
                Duration::from_millis(timeout_ms),
                |hop| {
                    if output == OutputFormat::Jsonl {
                        println!("{}", serde_json::to_string(hop)?);
                        std::io::stdout().flush()?;
                    }
                    Ok(())
                },
            )
            .await?;
            match output {
                OutputFormat::Human => trace::print_human(&result),
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&result)?),
                OutputFormat::Jsonl => {}
            }
            Ok(())
        }
        Command::Status { output, json } => {
            status(&socket, if json { OutputFormat::Json } else { output }).await
        }
        Command::Tui { interval_ms } => {
            tui::run(&config, &socket, Duration::from_millis(interval_ms)).await
        }
        Command::Health => health(&socket, cli.quiet).await,
        Command::Reload => {
            let ack = control::reload(&socket).await?;
            println!("reloaded generation={}", ack.generation);
            println!("endpoint_id={}", ack.endpoint_id);
            Ok(())
        }
        Command::Validate => validate(&config).await,
        Command::SealConfig => {
            deployment::seal(&config).await?;
            println!("sealed = {}", config.display());
            Ok(())
        }
        Command::InstallConfig { source } => deployment::install(&source, &config).await,
        Command::RollbackConfig => deployment::rollback(&config).await,
        Command::BackupIdentity { output } => backup_identity(&config, &output).await,
        Command::RestoreIdentity {
            source,
            identity_file,
        } => restore_identity(&source, &identity_file),
        Command::Doctor => doctor(&config).await,
        Command::Route { command } => route(&config, &socket, command).await,
    }
}

async fn route(config_path: &Path, socket_path: &Path, command: RouteCommand) -> Result<()> {
    let registry_path = Config::route_registry_path_for(config_path).await?;
    match command {
        RouteCommand::Add {
            prefixes,
            owner,
            dry_run,
            defer,
        } => {
            let config = Config::load(config_path).await?;
            let endpoint_id = resolve_route_owner(&config, &owner)?;
            let previous = RouteRegistry::load(&registry_path).await?;
            let mut candidate = previous.clone();
            candidate.merge(RouteRegistry {
                version: 1,
                routes: vec![iroh_sdwan::config::RouteOriginConfig {
                    endpoint_id,
                    prefixes,
                }],
            })?;
            apply_route_change(
                config_path,
                socket_path,
                &registry_path,
                previous,
                candidate,
                dry_run,
                defer,
            )
            .await
        }
        RouteCommand::Import {
            source,
            replace,
            dry_run,
            defer,
        } => {
            let imported = RouteRegistry::import(&source).await?;
            ensure!(imported.prefix_count() > 0, "route import is empty");
            let previous = RouteRegistry::load(&registry_path).await?;
            let mut candidate = if replace {
                RouteRegistry::default()
            } else {
                previous.clone()
            };
            candidate.merge(imported)?;
            apply_route_change(
                config_path,
                socket_path,
                &registry_path,
                previous,
                candidate,
                dry_run,
                defer,
            )
            .await
        }
        RouteCommand::List { output } => {
            let config = Config::load(config_path).await?;
            let registry = RouteRegistry::load(&registry_path).await?;
            let entries = registry.flattened();
            match output {
                OutputFormat::Human => {
                    if entries.is_empty() {
                        println!("No static routes.");
                        println!("Add one with: iroh-sdwan route add PREFIX --owner PEER");
                    } else {
                        println!("{:<22}  {:<20}  ENDPOINT ID", "PREFIX", "OWNER");
                        for (prefix, endpoint_id) in entries {
                            let prefix = prefix.to_string();
                            println!(
                                "{prefix:<22}  {:<20}  {endpoint_id}",
                                route_owner_name(&config, endpoint_id).unwrap_or("-")
                            );
                        }
                    }
                    println!("\nRoute file: {}", registry_path.display());
                }
                OutputFormat::Json => {
                    let entries = entries
                        .into_iter()
                        .map(|(prefix, endpoint_id)| {
                            serde_json::json!({
                                "prefix": prefix,
                                "endpoint_id": endpoint_id,
                                "owner_name": route_owner_name(&config, endpoint_id),
                            })
                        })
                        .collect::<Vec<_>>();
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "route_file": registry_path,
                            "routes": entries,
                        }))?
                    );
                }
                OutputFormat::Jsonl => {
                    for (prefix, endpoint_id) in entries {
                        println!(
                            "{}",
                            serde_json::to_string(&serde_json::json!({
                                "prefix": prefix,
                                "endpoint_id": endpoint_id,
                                "owner_name": route_owner_name(&config, endpoint_id),
                            }))?
                        );
                    }
                }
            }
            Ok(())
        }
        RouteCommand::Remove {
            selectors,
            dry_run,
            defer,
        } => {
            let config = Config::load(config_path).await?;
            let previous = RouteRegistry::load(&registry_path).await?;
            let mut candidate = previous.clone();
            for original in &selectors {
                let selector = normalize_route_selector(&config, original)?;
                let count = candidate.remove(&selector)?;
                ensure!(count > 0, "route not found: {original}");
            }
            apply_route_change(
                config_path,
                socket_path,
                &registry_path,
                previous,
                candidate,
                dry_run,
                defer,
            )
            .await
        }
    }
}

fn resolve_route_owner(config: &Config, owner: &str) -> Result<EndpointId> {
    if let Ok(endpoint_id) = owner.parse::<EndpointId>() {
        return Ok(endpoint_id);
    }
    config
        .peers
        .iter()
        .find(|peer| peer.name == owner)
        .map(|peer| peer.endpoint_id)
        .with_context(|| {
            format!("unknown route owner {owner:?}; use a configured peer name or full endpoint ID")
        })
}

fn normalize_route_selector(config: &Config, selector: &str) -> Result<String> {
    if selector.parse::<IpNet>().is_ok() || selector.parse::<EndpointId>().is_ok() {
        return Ok(selector.to_owned());
    }
    Ok(resolve_route_owner(config, selector)?.to_string())
}

fn route_owner_name(config: &Config, endpoint_id: EndpointId) -> Option<&str> {
    config
        .peers
        .iter()
        .find(|peer| peer.endpoint_id == endpoint_id)
        .map(|peer| peer.name.as_str())
}

async fn apply_route_change(
    config_path: &Path,
    socket_path: &Path,
    registry_path: &Path,
    previous: RouteRegistry,
    candidate: RouteRegistry,
    dry_run: bool,
    defer: bool,
) -> Result<()> {
    validate_route_registry(config_path, &candidate).await?;
    let before = previous.flattened().into_iter().collect::<HashSet<_>>();
    let after = candidate.flattened().into_iter().collect::<HashSet<_>>();
    let added = after.difference(&before).count();
    let removed = before.difference(&after).count();
    let unchanged = before.intersection(&after).count();

    if dry_run {
        println!(
            "Dry run: would add {added}, remove {removed}, keep {unchanged}; total {}.",
            after.len()
        );
        println!("Route file: {}", registry_path.display());
        return Ok(());
    }
    if added == 0 && removed == 0 {
        println!("No changes; {} routes already match.", after.len());
        println!("Route file: {}", registry_path.display());
        return Ok(());
    }

    candidate.write(registry_path)?;
    let reload = match reload_routes(socket_path, defer).await {
        Ok(reload) => reload,
        Err(error) => {
            previous.write(registry_path).context(
                "daemon rejected routes and the previous registry could not be restored",
            )?;
            return Err(error.context("daemon rejected routes; restored the previous registry"));
        }
    };
    println!(
        "Routes updated: +{added}, -{removed}, unchanged {unchanged}; total {}.",
        after.len()
    );
    println!("Route file: {}", registry_path.display());
    match reload {
        RouteReload::Deferred => println!("Apply: deferred until the next daemon reload."),
        RouteReload::Pending => println!("Apply: pending; the daemon is not running."),
        RouteReload::Reloaded(generation) => {
            println!("Applied: daemon reloaded to generation {generation}.")
        }
    }
    Ok(())
}

async fn validate_route_registry(config_path: &Path, registry: &RouteRegistry) -> Result<()> {
    iroh_sdwan::routes::validate_for_config(config_path, registry).await
}

enum RouteReload {
    Deferred,
    Pending,
    Reloaded(u64),
}

async fn reload_routes(socket_path: &Path, defer: bool) -> Result<RouteReload> {
    if defer {
        return Ok(RouteReload::Deferred);
    }
    if !socket_path.exists() {
        return Ok(RouteReload::Pending);
    }
    let ack = control::reload(socket_path).await?;
    Ok(RouteReload::Reloaded(ack.generation))
}

async fn backup_identity(config_path: &Path, output: &Path) -> Result<()> {
    let config = Config::load(config_path).await?;
    identity::backup(&config.identity_file, output)?;
    println!("identity_backup = {}", output.display());

    let derp_source = config.derp_identity_file();
    if derp_source.exists() {
        let derp_output = companion_derp_path(output);
        if let Err(error) = iroh_sdwan::derp::identity::backup(&derp_source, &derp_output) {
            let _ = std::fs::remove_file(output);
            return Err(error);
        }
        println!("derp_identity_backup = {}", derp_output.display());
    }
    Ok(())
}

fn restore_identity(source: &Path, identity_file: &Path) -> Result<()> {
    let key = identity::restore(source, identity_file)?;
    let derp_source = companion_derp_path(source);
    if derp_source.exists() {
        let derp_destination = companion_derp_path(identity_file);
        if let Err(error) = iroh_sdwan::derp::identity::restore(&derp_source, &derp_destination) {
            let _ = std::fs::remove_file(identity_file);
            return Err(error);
        }
        println!("derp_identity_file = {}", derp_destination.display());
    }
    println!("endpoint_id = {}", key.public());
    println!("identity_file = {}", identity_file.display());
    Ok(())
}

fn companion_derp_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".derp");
    PathBuf::from(value)
}

async fn status(socket_path: &Path, output: OutputFormat) -> Result<()> {
    let status = control::status(socket_path).await?;
    print!("{}", render_status(&status, output)?);
    Ok(())
}

fn render_status(status: &RuntimeStatus, output: OutputFormat) -> Result<String> {
    match output {
        OutputFormat::Json => return Ok(format!("{}\n", serde_json::to_string_pretty(status)?)),
        OutputFormat::Jsonl => return Ok(format!("{}\n", serde_json::to_string(status)?)),
        OutputFormat::Human => {}
    }
    let mut rendered = String::new();
    writeln!(rendered, "ready: {}", status.ready)?;
    writeln!(
        rendered,
        "endpoint_id: {}",
        single_line(&status.endpoint_id)
    )?;
    writeln!(
        rendered,
        "started: {}",
        display::unix_timestamp(status.started_unix)
    )?;
    writeln!(
        rendered,
        "updated: {}",
        display::unix_timestamp(status.updated_unix)
    )?;
    writeln!(
        rendered,
        "uptime: {}",
        display::duration(Duration::from_secs(status.uptime_seconds))
    )?;
    writeln!(rendered, "routes_ready: {}", status.routes_ready)?;
    writeln!(
        rendered,
        "capacity: table={}/{} probe_in_flight={} probe_budget={} probe_attempts={} probe_failures={} probe_transferred={}",
        status.capacity_table_entries,
        status.capacity_table_limit,
        status.capacity_probe_in_flight,
        display::bytes(status.capacity_probe_budget_bytes as u64),
        status.capacity_probe_attempts,
        status.capacity_probe_failures,
        display::bytes(status.capacity_probe_bytes),
    )?;
    writeln!(
        rendered,
        "flow_router: active_flows={}/{} decisions={} route_switches={} no_route_drops={}",
        status.flow_router.active_flows,
        status.flow_router.max_flows,
        status.flow_router.decisions,
        status.flow_router.route_switches,
        status.flow_router.no_route_drops,
    )?;
    writeln!(
        rendered,
        "mesh: enabled={} directory={} quarantined={} max_peers={}",
        status.mesh.enabled,
        status.mesh.directory_entries,
        status.mesh.quarantined_entries,
        status.mesh.max_total_peers
    )?;
    for node in &status.mesh.nodes {
        writeln!(
            rendered,
            "mesh_node {}: name={} direct={} relays={} prefixes={} transit={} quarantined={}",
            single_line(&node.endpoint_id),
            node.node_info
                .as_ref()
                .map(|info| single_line(&info.name))
                .unwrap_or_else(|| "unknown".into()),
            node.direct_addresses.len(),
            node.relay_urls.len(),
            node.prefixes.len(),
            node.transit_enabled,
            node.quarantined
        )?;
    }
    for route in status.routes.iter().filter(|route| !route.present) {
        writeln!(rendered, "missing_route: {}", single_line(&route.prefix))?;
    }
    for capacity in &status.capacities {
        writeln!(
            rendered,
            "capacity destination={} first_hop={} effective_rate={} measured_rate={} health={} freshness={} source={} age={} rtt={} switches={} probe_in_flight={} probe_next_due={} probe_attempts={} probe_failures={}",
            single_line(&capacity.destination),
            single_line(&capacity.first_hop),
            display::bits_per_second(capacity.effective_capacity_bps),
            capacity
                .measured_capacity_bps
                .map(display::bits_per_second)
                .unwrap_or_else(|| "unknown".into()),
            capacity.health_per_mille,
            single_line(&capacity.freshness),
            capacity.sample_source.as_deref().unwrap_or("none"),
            capacity
                .sample_age_millis
                .map_or_else(|| "unknown".into(), display::millis),
            capacity
                .rtt_ewma_micros
                .map_or_else(|| "unknown".into(), display::micros),
            capacity.route_switches,
            capacity.probe_in_flight,
            capacity
                .probe_next_due_millis
                .map_or_else(|| "unknown".into(), display::millis),
            capacity.probe_attempts,
            capacity.probe_failures,
        )?;
    }
    for peer in &status.peers {
        writeln!(rendered, "{}", format_peer_human(peer))?;
    }
    Ok(rendered)
}

async fn peers(socket_path: &Path, output: OutputFormat) -> Result<()> {
    let peers = control::peers(socket_path).await?;
    print!("{}", render_peers(&peers, output)?);
    Ok(())
}

fn render_peers(peers: &[PeerStatus], output: OutputFormat) -> Result<String> {
    match output {
        OutputFormat::Json => Ok(format!("{}\n", serde_json::to_string_pretty(peers)?)),
        OutputFormat::Jsonl => {
            let mut rendered = String::new();
            for peer in peers {
                writeln!(rendered, "{}", serde_json::to_string(peer)?)?;
            }
            Ok(rendered)
        }
        OutputFormat::Human => {
            let mut rendered = String::new();
            writeln!(
                rendered,
                "peers: total={} connected={}",
                peers.len(),
                peers.iter().filter(|peer| peer.connected).count()
            )?;
            for peer in peers {
                writeln!(rendered, "{}", format_peer_human(peer))?;
                for capacity in &peer.capacities {
                    writeln!(
                        rendered,
                        "  route destination={} effective_rate={} health={} freshness={} source={} age={} switches={}",
                        single_line(&capacity.destination),
                        display::bits_per_second(capacity.effective_capacity_bps),
                        capacity.health_per_mille,
                        single_line(&capacity.freshness),
                        capacity.sample_source.as_deref().unwrap_or("none"),
                        capacity
                            .sample_age_millis
                            .map_or_else(|| "unknown".into(), display::millis),
                        capacity.route_switches,
                    )?;
                }
            }
            Ok(rendered)
        }
    }
}

fn format_peer_human(peer: &PeerStatus) -> String {
    format!(
        "peer {}: endpoint_id={} interface={} connected={} path={}:{} rtt={} jitter={} loss={} queue={} tx_packets={} tx={} rx_packets={} rx={} policy_drops={} connection_errors={} send_errors={}",
        single_line(&peer.name),
        single_line(&peer.endpoint_id),
        single_line(&peer.interface),
        peer.connected,
        if peer.selected_path_transport.is_empty() {
            "unknown".into()
        } else {
            single_line(&peer.selected_path_transport)
        },
        if peer.selected_path_remote.is_empty() {
            "unknown".into()
        } else {
            single_line(&peer.selected_path_remote)
        },
        human_micros(peer.path_rtt_micros),
        human_micros(peer.path_jitter_micros),
        format_loss(peer.path_loss_ppm),
        display::bytes(peer.queue_bytes),
        peer.tx_packets,
        display::bytes(peer.tx_bytes),
        peer.rx_packets,
        display::bytes(peer.rx_bytes),
        peer.policy_drops,
        peer.connection_errors,
        peer.send_errors
    )
}

fn human_micros(value: u64) -> String {
    if value == 0 {
        "unknown".into()
    } else {
        display::micros(value)
    }
}

fn format_loss(ppm: u64) -> String {
    format!("{:.2}%", ppm as f64 / 10_000.0)
}

async fn ping(
    socket_path: &Path,
    target: IpAddr,
    count: u16,
    timeout_ms: u64,
    output: OutputFormat,
) -> Result<()> {
    let result = control::ping(
        socket_path,
        target,
        count,
        Duration::from_millis(timeout_ms),
    )
    .await?;
    print!("{}", render_ping(&result, output)?);
    ensure!(
        result.received > 0,
        "overlay ping did not reach {}",
        result.target
    );
    Ok(())
}

fn render_ping(result: &PingResult, output: OutputFormat) -> Result<String> {
    match output {
        OutputFormat::Human => Ok(trace::format_ping_human(result)),
        OutputFormat::Json => Ok(format!("{}\n", serde_json::to_string_pretty(result)?)),
        OutputFormat::Jsonl => Ok(format!("{}\n", serde_json::to_string(result)?)),
    }
}

fn single_line(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

async fn health(socket_path: &Path, quiet: bool) -> Result<()> {
    control::health(socket_path).await?;
    if !quiet {
        println!("healthy");
    }
    Ok(())
}

async fn validate(config_path: &Path) -> Result<()> {
    let (config, endpoint_id) = deployment::validate(config_path).await?;
    println!("valid");
    println!("network_id = {}", config.network_id);
    println!("endpoint_id = {endpoint_id}");
    println!("overlay_table = {}", config.routing.table);
    println!("static_route_owners = {}", config.route_origins.len());
    println!("route_file = {}", config.route_registry_path().display());
    println!("transit_enabled = {}", config.routing.transit_enabled);
    Ok(())
}

async fn doctor(config_path: &Path) -> Result<()> {
    let (config, endpoint_id) = deployment::validate(config_path).await?;
    ensure!(cfg!(target_os = "linux"), "runtime requires Linux");
    let tun = std::fs::metadata("/dev/net/tun").context("/dev/net/tun is missing")?;
    ensure!(
        tun.file_type().is_char_device(),
        "/dev/net/tun is not a character device"
    );
    let capabilities = std::fs::read_to_string("/proc/self/status")
        .context("failed reading process capabilities")?;
    let effective = capabilities
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"))
        .and_then(|value| u64::from_str_radix(value, 16).ok())
        .context("failed parsing effective process capabilities")?;
    ensure!(
        effective & (1 << 12) != 0,
        "CAP_NET_ADMIN is required; run doctor as root or with that capability"
    );
    let ip = tokio::process::Command::new("ip")
        .arg("-Version")
        .output()
        .await
        .context("failed executing iproute2")?;
    ensure!(ip.status.success(), "iproute2 is not operational");
    let has_ipv4_overlay = config
        .all_overlay_prefixes()
        .any(|prefix| prefix.addr().is_ipv4());
    let has_ipv6_overlay = config
        .all_overlay_prefixes()
        .any(|prefix| prefix.addr().is_ipv6());
    let needs_forwarding = config.requires_forwarding();
    if needs_forwarding && has_ipv4_overlay {
        ensure_sysctl("/proc/sys/net/ipv4/ip_forward", "1")?;
        for setting in [
            "/proc/sys/net/ipv4/conf/all/rp_filter",
            "/proc/sys/net/ipv4/conf/default/rp_filter",
        ] {
            let value = std::fs::read_to_string(setting)
                .with_context(|| format!("failed reading {setting}"))?;
            ensure!(
                matches!(value.trim(), "0" | "2"),
                "{setting} must use disabled or loose reverse-path filtering"
            );
        }
    }
    if needs_forwarding && has_ipv6_overlay {
        ensure_sysctl("/proc/sys/net/ipv6/conf/all/forwarding", "1")?;
    }
    for peer in &config.peers {
        for address in &peer.direct_addresses {
            let family = if address.is_ipv4() { "-4" } else { "-6" };
            let peer_ip = address.ip().to_string();
            let output = tokio::process::Command::new("ip")
                .args([family, "route", "get", &peer_ip])
                .output()
                .await
                .with_context(|| format!("failed resolving underlay route to {}", address.ip()))?;
            ensure!(
                output.status.success(),
                "no underlay route to peer {} at {}",
                peer.name,
                address.ip()
            );
            let route = String::from_utf8_lossy(&output.stdout);
            ensure!(
                !route.contains(&format!(" dev {}", config.node_interface)),
                "peer {} underlay route recursively enters overlay interface {}",
                peer.name,
                config.node_interface
            );
        }
    }
    let derp_servers = config.derp_servers()?;
    if !derp_servers.is_empty() {
        let identity = if config.derp_identity_file().exists() {
            iroh_sdwan::derp::identity::load(&config.derp_identity_file())?
        } else {
            DerpIdentity::generate()
        };
        let tls = tls_config()?;
        for server in &derp_servers {
            probe_server(server, identity.clone(), tls.clone())
                .await
                .with_context(|| format!("DERP probe failed for {}", server.display))?;
            println!(
                "derp_region {}: ok server={}",
                server.region_id, server.display
            );
        }
    }
    println!("doctor: ok");
    println!("endpoint_id = {endpoint_id}");
    println!("peers = {}", config.peers.len());
    println!("overlay_table = {}", config.routing.table);
    Ok(())
}

fn ensure_sysctl(path: &str, expected: &str) -> Result<()> {
    let actual = std::fs::read_to_string(path).with_context(|| format!("failed reading {path}"))?;
    ensure!(
        actual.trim() == expected,
        "{path} must be {expected}, got {}",
        actual.trim()
    );
    Ok(())
}

async fn init(
    config_path: &Path,
    state_dir: &Path,
    network_id: Option<String>,
    derp_servers: Vec<String>,
    non_interactive: bool,
) -> Result<()> {
    if config_path.exists() {
        bail!("configuration already exists at {}", config_path.display());
    }

    let interactive = !non_interactive && std::io::stdin().is_terminal();
    let answers = if interactive {
        println!("Interactive node setup (press Enter to accept an empty/default value).");
        let stdin = std::io::stdin();
        let mut reader = stdin.lock();
        let mut writer = std::io::stdout();
        collect_init_answers(&mut reader, &mut writer, network_id, derp_servers)?
    } else {
        InitAnswers {
            network_id,
            derp_servers,
            node_addresses: Vec::new(),
            advertised_prefixes: Vec::new(),
            transit_enabled: false,
            peers: Vec::new(),
        }
    };

    let identity_file = state_dir.join("identity.key");
    let network_id = answers
        .network_id
        .unwrap_or_else(|| hex::encode(iroh::SecretKey::generate().to_bytes()));
    let config = Config {
        network_id,
        identity_file: identity_file.clone(),
        bind_addresses: Vec::new(),
        forbidden_underlay_prefixes: Vec::new(),
        discovery_enabled: true,
        attachment: AttachmentMode::Tun,
        tun_mtu: u16::MAX,
        max_frame_size: 1400,
        node_interface: "isw0".into(),
        node_addresses: answers.node_addresses,
        advertised_prefixes: answers.advertised_prefixes,
        node_info: None,
        relay: RelayConfig {
            urls: Vec::new(),
            servers: answers.derp_servers,
        },
        peers: answers.peers,
        links: Vec::new(),
        route_origins: Vec::new(),
        routing: RoutingConfig {
            transit_enabled: answers.transit_enabled,
            ..RoutingConfig::default()
        },
        mesh: Default::default(),
        packet_policy: PacketPolicyConfig::default(),
        fec: FecConfig::default(),
        observability: ObservabilityConfig::default(),
    };
    let route_file = config.route_registry_path();
    if route_file.exists() {
        bail!("route registry already exists at {}", route_file.display());
    }
    config.validate()?;
    let secret_key = identity::load_or_create(&identity_file)?;
    config.validate_local_id(secret_key.public())?;
    let derp_public_key = if config.relay.derp_enabled() {
        Some(iroh_sdwan::derp::identity::load_or_create(&config.derp_identity_file())?.public_key())
    } else {
        None
    };
    if let Some(parent) = config_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let encoded = toml::to_string_pretty(&config)?;
    deployment::atomic_write(config_path, encoded.as_bytes(), 0o600)?;
    RouteRegistry::default().write(&route_file)?;
    deployment::seal(config_path).await?;
    println!("network_id = {}", config.network_id);
    println!("endpoint_id = {}", secret_key.public());
    println!("identity_file = {}", config.identity_file.display());
    if let Some(key) = derp_public_key {
        println!("derp_public_key = {key}");
    }
    println!("config = {}", config_path.display());
    println!("route_file = {}", route_file.display());
    Ok(())
}

#[derive(Debug)]
struct InitAnswers {
    network_id: Option<String>,
    derp_servers: Vec<String>,
    node_addresses: Vec<IpNet>,
    advertised_prefixes: Vec<IpNet>,
    transit_enabled: bool,
    peers: Vec<PeerConfig>,
}

fn collect_init_answers<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    network_id: Option<String>,
    derp_servers: Vec<String>,
) -> Result<InitAnswers> {
    let network_id = match network_id {
        Some(value) => Some(value),
        None => non_empty(prompt_line(
            reader,
            writer,
            "Network ID (blank creates a new network): ",
        )?),
    };
    let derp_servers = if derp_servers.is_empty() {
        prompt_strings(
            reader,
            writer,
            "DERP server URLs, comma-separated (blank disables DERP): ",
        )?
    } else {
        derp_servers
    };
    let node_addresses = prompt_values(
        reader,
        writer,
        "Node overlay addresses, comma-separated (for example 21.0.0.2/32): ",
        "overlay address",
    )?;
    let advertised_prefixes = prompt_values(
        reader,
        writer,
        "Local LAN/service prefixes to advertise, comma-separated (optional): ",
        "advertised prefix",
    )?;
    let transit_enabled = prompt_bool(
        reader,
        writer,
        "Forward traffic between overlay peers?",
        false,
    )?;

    let mut peers = Vec::new();
    loop {
        let endpoint_id = prompt_optional_value::<_, _, EndpointId>(
            reader,
            writer,
            "Bootstrap peer endpoint ID (blank finishes peer setup): ",
            "endpoint ID",
        )?;
        let Some(endpoint_id) = endpoint_id else {
            break;
        };
        let default_name = format!("bootstrap-{}", peers.len() + 1);
        let entered_name = prompt_line(reader, writer, &format!("Peer name [{default_name}]: "))?;
        let name = non_empty(entered_name).unwrap_or(default_name);
        let direct_addresses = prompt_values::<_, _, SocketAddr>(
            reader,
            writer,
            "Direct addresses, comma-separated (optional, address:port): ",
            "direct address",
        )?;
        let (relay_urls, derp_public_key) = if derp_servers.is_empty() {
            (
                prompt_strings(
                    reader,
                    writer,
                    "Peer relay URLs, comma-separated (optional; use at least two): ",
                )?,
                None,
            )
        } else {
            let key = prompt_required_value::<_, _, DerpPublicKey>(
                reader,
                writer,
                "Peer DERP public key: ",
                "DERP public key",
            )?;
            (Vec::new(), Some(key))
        };
        peers.push(PeerConfig {
            name,
            endpoint_id,
            transit_enabled: false,
            direct_addresses,
            relay_urls,
            derp_public_key,
            allowed_source_prefixes: Vec::new(),
        });
    }

    Ok(InitAnswers {
        network_id,
        derp_servers,
        node_addresses,
        advertised_prefixes,
        transit_enabled,
        peers,
    })
}

fn prompt_line<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    prompt: &str,
) -> Result<String> {
    writer.write_all(prompt.as_bytes())?;
    writer.flush()?;
    let mut value = String::new();
    ensure!(
        reader.read_line(&mut value)? != 0,
        "interactive input closed"
    );
    Ok(value.trim().to_owned())
}

fn prompt_strings<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    prompt: &str,
) -> Result<Vec<String>> {
    Ok(split_values(&prompt_line(reader, writer, prompt)?))
}

fn prompt_values<R, W, T>(
    reader: &mut R,
    writer: &mut W,
    prompt: &str,
    value_name: &str,
) -> Result<Vec<T>>
where
    R: BufRead,
    W: Write,
    T: FromStr,
    T::Err: Display,
{
    loop {
        let values = split_values(&prompt_line(reader, writer, prompt)?);
        let parsed: Result<Vec<_>, _> = values.iter().map(|value| value.parse::<T>()).collect();
        match parsed {
            Ok(values) => return Ok(values),
            Err(error) => writeln!(writer, "Invalid {value_name}: {error}. Please try again.")?,
        }
    }
}

fn prompt_optional_value<R, W, T>(
    reader: &mut R,
    writer: &mut W,
    prompt: &str,
    value_name: &str,
) -> Result<Option<T>>
where
    R: BufRead,
    W: Write,
    T: FromStr,
    T::Err: Display,
{
    loop {
        let value = prompt_line(reader, writer, prompt)?;
        if value.is_empty() {
            return Ok(None);
        }
        match value.parse() {
            Ok(value) => return Ok(Some(value)),
            Err(error) => writeln!(writer, "Invalid {value_name}: {error}. Please try again.")?,
        }
    }
}

fn prompt_required_value<R, W, T>(
    reader: &mut R,
    writer: &mut W,
    prompt: &str,
    value_name: &str,
) -> Result<T>
where
    R: BufRead,
    W: Write,
    T: FromStr,
    T::Err: Display,
{
    loop {
        if let Some(value) = prompt_optional_value(reader, writer, prompt, value_name)? {
            return Ok(value);
        }
        writeln!(writer, "{value_name} is required. Please try again.")?;
    }
}

fn prompt_bool<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    prompt: &str,
    default: bool,
) -> Result<bool> {
    let suffix = if default { "[Y/n]" } else { "[y/N]" };
    loop {
        let value = prompt_line(reader, writer, &format!("{prompt} {suffix}: "))?;
        match value.to_ascii_lowercase().as_str() {
            "" => return Ok(default),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => writeln!(writer, "Enter y or n.")?,
        }
    }
}

fn split_values(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

fn non_empty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

async fn inspect(config_path: &Path) -> Result<()> {
    let config = Config::load(config_path).await?;
    let secret_key = identity::load(&config.identity_file)?;
    let local_id = secret_key.public();
    config.validate_local_id(local_id)?;

    println!("network_id: {}", config.network_id);
    println!("endpoint_id: {local_id}");
    println!("transit_enabled: {}", config.routing.transit_enabled);
    println!("mesh_enabled: {}", config.mesh.enabled);
    println!("mesh_max_peers: {}", config.mesh.max_peers);
    if let Some(max_egress_mbps) = config.routing.max_egress_mbps {
        println!(
            "max_egress: {}",
            display::bits_per_second(max_egress_mbps.saturating_mul(1_000_000))
        );
    }
    println!(
        "alpn: {}",
        String::from_utf8_lossy(&network_alpn(&config.network_id))
    );
    println!("node_interface: {}", config.node_interface);
    let derp_servers = config.derp_servers()?;
    if !derp_servers.is_empty() {
        let identity = iroh_sdwan::derp::identity::load_or_create(&config.derp_identity_file())?;
        println!("derp_public_key: {}", identity.public_key());
        println!(
            "derp_identity_file: {}",
            config.derp_identity_file().display()
        );
        for server in &derp_servers {
            println!(
                "derp_region: {} server={}",
                server.region_id, server.display
            );
        }
    }
    for prefix in &config.forbidden_underlay_prefixes {
        println!("forbidden_underlay_prefix: {prefix}");
    }
    for address in &config.node_addresses {
        println!("node_address: {address}");
    }
    if let Some(node_info) = &config.node_info {
        println!("node_info:");
        println!("  name: {}", node_info.name);
        if let Some(description) = &node_info.description {
            println!("  description: {description}");
        }
        for (key, value) in &node_info.metadata {
            println!("  {key}: {value}");
        }
    }
    for peer in &config.peers {
        println!("peer {}:", peer.name);
        println!("  endpoint_id: {}", peer.endpoint_id);
        if let Some(key) = peer.derp_public_key {
            println!("  derp_public_key: {key}");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh_sdwan::{
        config::NodeInfo, mesh::MeshStatus, observability::RouteStatus, trace::PingSample,
    };
    use std::io::Cursor;

    fn sample_peer() -> PeerStatus {
        serde_json::from_value(serde_json::json!({
            "name": "bad\nname",
            "endpoint_id": "endpoint",
            "interface": "isw0",
            "connected": true,
            "connection_events": 1,
            "tx_packets": 2,
            "tx_bytes": 3,
            "rx_packets": 4,
            "rx_bytes": 5,
            "tx_fragments": 6,
            "rx_fragments": 7,
            "invalid_packets": 0,
            "policy_drops": 8,
            "frame_drops": 0,
            "send_errors": 9
        }))
        .unwrap()
    }

    fn sample_ping() -> PingResult {
        PingResult {
            target: "21.0.0.2".parse().unwrap(),
            source: "21.0.0.1".parse().unwrap(),
            source_name: "local".into(),
            transmitted: 2,
            received: 1,
            loss_ppm: 500_000,
            min_ms: Some(12.5),
            avg_ms: Some(12.5),
            max_ms: Some(12.5),
            samples: vec![
                PingSample {
                    sequence: 1,
                    reached: true,
                    address: Some("21.0.0.2".parse().unwrap()),
                    elapsed_ms: Some(12.5),
                    node_info: Some(NodeInfo {
                        name: "remote\nnode".into(),
                        description: None,
                        metadata: Default::default(),
                    }),
                },
                PingSample {
                    sequence: 2,
                    reached: false,
                    address: None,
                    elapsed_ms: None,
                    node_info: None,
                },
            ],
        }
    }

    #[test]
    fn global_config_is_accepted_after_subcommand() {
        let cli = Cli::try_parse_from([
            "iroh-sdwan",
            "trace",
            "21.0.0.1",
            "--config",
            "/tmp/node.toml",
            "--output",
            "jsonl",
        ])
        .unwrap();

        assert_eq!(cli.config, PathBuf::from("/tmp/node.toml"));
        assert_eq!(cli.socket, PathBuf::from(DEFAULT_CONTROL_SOCKET));
        match cli.command {
            Command::Trace { output, .. } => assert_eq!(output, OutputFormat::Jsonl),
            command => panic!("expected trace command, got {command:?}"),
        }
    }

    #[test]
    fn global_socket_is_accepted_after_subcommand() {
        let cli =
            Cli::try_parse_from(["iroh-sdwan", "status", "--socket", "/tmp/control.sock"]).unwrap();
        assert_eq!(cli.socket, PathBuf::from("/tmp/control.sock"));
    }

    #[test]
    fn ping_accepts_probe_count_timeout_and_machine_output() {
        let cli = Cli::try_parse_from([
            "iroh-sdwan",
            "ping",
            "21.0.0.2",
            "--count",
            "6",
            "--timeout-ms",
            "2500",
            "--output",
            "json",
        ])
        .unwrap();

        match cli.command {
            Command::Ping {
                target,
                count,
                timeout_ms,
                output,
            } => {
                assert_eq!(target, "21.0.0.2".parse::<IpAddr>().unwrap());
                assert_eq!(count, 6);
                assert_eq!(timeout_ms, 2_500);
                assert_eq!(output, OutputFormat::Json);
            }
            command => panic!("expected ping command, got {command:?}"),
        }
    }

    #[test]
    fn peers_supports_json_lines_output() {
        let cli = Cli::try_parse_from(["iroh-sdwan", "peers", "--output", "jsonl"]).unwrap();
        match cli.command {
            Command::Peers { output } => assert_eq!(output, OutputFormat::Jsonl),
            command => panic!("expected peers command, got {command:?}"),
        }
    }

    #[test]
    fn route_subcommands_match_the_operational_cli() {
        let cli = Cli::try_parse_from([
            "iroh-sdwan",
            "route",
            "import",
            "site.routes",
            "--replace",
            "--no-reload",
        ])
        .unwrap();
        match cli.command {
            Command::Route {
                command:
                    RouteCommand::Import {
                        source,
                        replace,
                        dry_run,
                        defer,
                    },
            } => {
                assert_eq!(source, PathBuf::from("site.routes"));
                assert!(replace);
                assert!(!dry_run);
                assert!(defer);
            }
            command => panic!("expected route import, got {command:?}"),
        }

        let cli = Cli::try_parse_from([
            "iroh-sdwan",
            "route",
            "remove",
            "10.0.0.0/24",
            "10.1.0.0/24",
        ])
        .unwrap();
        match cli.command {
            Command::Route {
                command: RouteCommand::Remove { selectors, .. },
            } => assert_eq!(selectors, ["10.0.0.0/24", "10.1.0.0/24"]),
            command => panic!("expected route remove, got {command:?}"),
        }

        let cli = Cli::try_parse_from([
            "iroh-sdwan",
            "route",
            "add",
            "10.2.0.0/24",
            "fd42::/64",
            "--owner",
            "branch-b",
            "--dry-run",
        ])
        .unwrap();
        match cli.command {
            Command::Route {
                command:
                    RouteCommand::Add {
                        prefixes,
                        owner,
                        dry_run,
                        ..
                    },
            } => {
                assert_eq!(prefixes.len(), 2);
                assert_eq!(owner, "branch-b");
                assert!(dry_run);
            }
            command => panic!("expected route add, got {command:?}"),
        }

        assert!(Cli::try_parse_from(["iroh-sdwan", "route", "ls"]).is_ok());
        assert!(Cli::try_parse_from(["iroh-sdwan", "route", "rm", "10.2.0.0/24"]).is_ok());
    }

    #[test]
    fn tui_accepts_bounded_refresh_interval_and_top_alias() {
        let cli = Cli::try_parse_from(["iroh-sdwan", "tui", "--interval-ms", "500"]).unwrap();
        match cli.command {
            Command::Tui { interval_ms } => assert_eq!(interval_ms, 500),
            command => panic!("expected tui command, got {command:?}"),
        }
        assert!(Cli::try_parse_from(["iroh-sdwan", "top"]).is_ok());
        assert!(Cli::try_parse_from(["iroh-sdwan", "tui", "--interval-ms", "199"]).is_err());
        assert!(Cli::try_parse_from(["iroh-sdwan", "tui", "--interval-ms", "60001"]).is_err());
    }

    #[test]
    fn ping_rejects_invalid_cli_boundaries_and_targets() {
        for arguments in [
            vec!["iroh-sdwan", "ping", "21.0.0.2", "--count", "0"],
            vec!["iroh-sdwan", "ping", "21.0.0.2", "--count", "21"],
            vec!["iroh-sdwan", "ping", "21.0.0.2", "--timeout-ms", "0"],
            vec!["iroh-sdwan", "ping", "21.0.0.2", "--timeout-ms", "60001"],
            vec!["iroh-sdwan", "ping", "not-an-ip"],
        ] {
            assert!(Cli::try_parse_from(arguments).is_err());
        }
    }

    #[test]
    fn peer_human_json_and_jsonl_outputs_have_stable_contracts() {
        let peer = sample_peer();
        let human = render_peers(std::slice::from_ref(&peer), OutputFormat::Human).unwrap();
        assert_eq!(
            human,
            "peers: total=1 connected=1\npeer bad name: endpoint_id=endpoint interface=isw0 connected=true path=unknown:unknown rtt=unknown jitter=unknown loss=0.00% queue=0B tx_packets=2 tx=3B rx_packets=4 rx=5B policy_drops=8 connection_errors=0 send_errors=9\n"
        );
        assert!(!human.contains("bad\nname"));

        let json = render_peers(std::slice::from_ref(&peer), OutputFormat::Json).unwrap();
        let decoded: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded[0]["name"], "bad\nname");
        assert!(json.ends_with('\n'));

        let jsonl = render_peers(std::slice::from_ref(&peer), OutputFormat::Jsonl).unwrap();
        assert_eq!(jsonl.lines().count(), 1);
        let decoded: PeerStatus = serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert_eq!(decoded.name, "bad\nname");
        assert_eq!(render_peers(&[], OutputFormat::Jsonl).unwrap(), "");
    }

    #[test]
    fn ping_human_json_and_jsonl_outputs_have_stable_contracts() {
        let ping = sample_ping();
        assert_eq!(
            render_ping(&ping, OutputFormat::Human).unwrap(),
            "overlay ping to 21.0.0.2 from local (21.0.0.1)\nseq=1 from=21.0.0.2 name=remote node time=12.5ms\nseq=2 timeout\n2 transmitted, 1 received, 50.0% loss\nrtt min/avg/max = 12.5ms/12.5ms/12.5ms\n"
        );

        let json = render_ping(&ping, OutputFormat::Json).unwrap();
        let decoded: PingResult = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, ping);
        assert!(json.ends_with('\n'));

        let jsonl = render_ping(&ping, OutputFormat::Jsonl).unwrap();
        assert_eq!(jsonl.lines().count(), 1);
        let decoded: PingResult = serde_json::from_str(&jsonl).unwrap();
        assert_eq!(decoded, ping);
    }

    #[test]
    fn status_human_json_and_jsonl_outputs_have_stable_contracts() {
        let status = RuntimeStatus {
            ready: false,
            endpoint_id: "local\nendpoint".into(),
            started_unix: 1,
            updated_unix: 2,
            uptime_seconds: 3,
            routes_ready: false,
            routes: vec![RouteStatus {
                prefix: "21.0.0.0/24".into(),
                present: false,
            }],
            peers: vec![sample_peer()],
            mesh: MeshStatus::default(),
            capacities: Vec::new(),
            capacity_table_entries: 0,
            capacity_table_limit: 4_096,
            capacity_probe_in_flight: false,
            capacity_probe_budget_bytes: 256 * 1024,
            capacity_probe_attempts: 0,
            capacity_probe_failures: 0,
            capacity_probe_bytes: 0,
            flow_router: Default::default(),
        };
        let human = render_status(&status, OutputFormat::Human).unwrap();
        let expected_prefix = format!(
            "ready: false\nendpoint_id: local endpoint\nstarted: {}\nupdated: {}\nuptime: 3s\nroutes_ready: false\n",
            display::unix_timestamp(1),
            display::unix_timestamp(2),
        );
        assert!(human.starts_with(&expected_prefix));
        assert!(human.contains("missing_route: 21.0.0.0/24\n"));
        assert!(human.contains("peer bad name:"));

        let json = render_status(&status, OutputFormat::Json).unwrap();
        let decoded: RuntimeStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.endpoint_id, "local\nendpoint");

        let jsonl = render_status(&status, OutputFormat::Jsonl).unwrap();
        assert_eq!(jsonl.lines().count(), 1);
        let decoded: RuntimeStatus = serde_json::from_str(&jsonl).unwrap();
        assert_eq!(decoded.peers.len(), 1);
    }

    #[test]
    fn interactive_init_collects_node_routing_answers() {
        let input = b"\n\n21.0.0.2/32, 21::2/128\n192.168.20.0/24\ny\n\n";
        let mut reader = Cursor::new(input);
        let mut output = Vec::new();

        let answers = collect_init_answers(&mut reader, &mut output, None, Vec::new()).unwrap();

        assert!(answers.network_id.is_none());
        assert!(answers.derp_servers.is_empty());
        assert_eq!(answers.node_addresses.len(), 2);
        assert_eq!(answers.advertised_prefixes.len(), 1);
        assert!(answers.transit_enabled);
        assert!(answers.peers.is_empty());
    }

    #[test]
    fn interactive_init_reprompts_invalid_values() {
        let input = b"\nnot-a-prefix\n21.0.0.2/32\n\nmaybe\nn\n\n";
        let mut reader = Cursor::new(input);
        let mut output = Vec::new();

        let answers = collect_init_answers(
            &mut reader,
            &mut output,
            Some("shared-network".into()),
            Vec::new(),
        )
        .unwrap();

        assert_eq!(answers.node_addresses.len(), 1);
        assert!(!answers.transit_enabled);
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("Invalid overlay address"));
        assert!(output.contains("Enter y or n"));
    }
}

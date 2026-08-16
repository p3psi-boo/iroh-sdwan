use std::{
    collections::HashSet,
    fmt::Write as _,
    io::{IsTerminal, Write},
    net::{IpAddr, SocketAddr},
    os::unix::fs::FileTypeExt,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand, ValueEnum};
use ipnet::IpNet;
use iroh::EndpointId;
use ironet::{
    address::network_alpn,
    config::Config,
    control::{self, DEFAULT_CONTROL_SOCKET},
    deployment,
    derp::{identity::DerpIdentity, probe_server, tls_config},
    display, identity, logging,
    observability::{PeerStatus, RuntimeStatus},
    product,
    routes::RouteRegistry,
    trace::{self, PingResult},
    tui,
};

#[derive(Debug, Parser)]
#[command(
    name = "ironet",
    version,
    about = "Create, join, and operate an ironet overlay network",
    long_about = "Create, join, and operate an ironet IP overlay network between Linux machines.\n\nA network contains nodes. Each node has an overlay address. An invite contains the network and peer information required by another machine to join. A node can also advertise subnets or forward overlay traffic between peers.\n\nSetup commands write the configuration and network state. The ironet daemon reads the configuration and provides the network interface. Runtime commands communicate with the daemon through its control socket.",
    after_help = "Common workflow:\n  ironet network create NAME\n  ironet invite create --address IP:PORT\n  ironet join INVITE\n\nInspect the network:\n  ironet network show\n  ironet node list\n  ironet status\n  ironet peers\n\nUse `ironet COMMAND --help` for command-specific behavior and examples. Use `--output json` or `--output jsonl` for machine-readable output."
)]
struct Cli {
    /// Path to the daemon configuration file.
    #[arg(
        short = 'c',
        long,
        global = true,
        env = "IRONET_CONFIG",
        default_value = "/etc/ironet/config.toml"
    )]
    config: PathBuf,
    /// Path to the daemon control socket.
    #[arg(
        long,
        global = true,
        env = "IRONET_SOCKET",
        default_value = DEFAULT_CONTROL_SOCKET
    )]
    socket: PathBuf,
    /// Directory containing network state and identity files.
    #[arg(
        long,
        global = true,
        env = "IRONET_STATE_DIR",
        default_value = "/var/lib/ironet"
    )]
    state_dir: PathBuf,
    /// Suppress informational logs; `health` also suppresses successful output.
    #[arg(short, long, global = true)]
    quiet: bool,
    #[command(subcommand)]
    command: Option<Command>,
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
    /// Create, show, or leave a network.
    ///
    /// These commands manage the network configuration and the membership of this
    /// machine. Use `network create` once for the first node. Other machines use
    /// `join` with an invite.
    Network {
        #[command(subcommand)]
        command: NetworkCommand,
    },
    /// Create, list, or revoke invites.
    ///
    /// The machine that created the network issues invites. Each invite is signed,
    /// expires at a fixed time, and identifies the node allowed to use it.
    Invite {
        #[command(subcommand)]
        command: InviteCommand,
    },
    /// Add this machine to an existing network by using an invite.
    ///
    /// The command validates the invite, writes the local configuration and identity,
    /// assigns an overlay address, and starts the service unless `--no-start` is set.
    /// With no invite argument on an interactive terminal, the command prompts for it.
    #[command(
        after_help = "Examples:\n  ironet join 'ironet://join/v1/...'\n  ironet join --invite-file invite.txt\n  cat invite.txt | ironet join --invite-file - --output json"
    )]
    Join {
        /// Invite URL; omit it to use `--invite-file` or the interactive prompt.
        #[arg(value_name = "INVITE")]
        invite: Option<String>,
        /// Read the invite URL from a file; use `-` to read standard input.
        #[arg(long, conflicts_with = "invite", value_name = "PATH")]
        invite_file: Option<PathBuf>,
        /// Set this node's name; the default is the machine hostname.
        #[arg(long, value_name = "NAME")]
        node_name: Option<String>,
        /// Reuse an identity retained by `network leave --keep-identity`.
        #[arg(long)]
        reuse_identity: bool,
        /// Write the configuration and state without starting the service.
        #[arg(long)]
        no_start: bool,
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// List nodes or change local node membership.
    ///
    /// `node list` combines local configuration with the daemon's current peer state.
    /// Rename and remove operations update this machine's configuration.
    Node {
        #[command(subcommand)]
        command: NodeCommand,
    },
    /// Manage subnets reachable through this node.
    ///
    /// Published subnets are advertised to other nodes as routes through this node.
    Subnet {
        #[command(subcommand)]
        command: SubnetCommand,
    },
    /// Control forwarding of overlay traffic between peers.
    ///
    /// Transit affects traffic received from one overlay peer and sent to another.
    /// Subnets reachable through this node are managed separately with `subnet`.
    Transit {
        #[command(subcommand)]
        command: TransitCommand,
    },
    /// Show the interface and address plan derived from the configuration.
    #[command(hide = true)]
    Inspect,
    /// Check reachability and round-trip time to an overlay address.
    ///
    /// Probes follow the same overlay route used for data traffic. The command returns
    /// a non-zero status when no probe reaches the destination.
    #[command(after_help = "Example:\n  ironet ping 10.42.0.8 --count 4 --timeout-ms 1000")]
    Ping {
        /// Destination IPv4 or IPv6 overlay address.
        #[arg(value_name = "ADDRESS")]
        target: IpAddr,
        /// Number of probes to send.
        #[arg(short = 'n', long, default_value_t = 4, value_parser = clap::value_parser!(u16).range(1..=20), value_name = "NUMBER")]
        count: u16,
        /// Timeout for each probe, in milliseconds.
        #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(1..=60_000), value_name = "MILLISECONDS")]
        timeout_ms: u64,
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// Show peer connection state and path measurements.
    ///
    /// Output includes peer identity, connection state, selected transport, latency,
    /// loss, queue use, and packet counters from the daemon status.
    Peers {
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// Show the node-by-node overlay path to an address.
    ///
    /// Each responding hop includes its overlay address, round-trip time, and node name
    /// when available. A timeout is reported for a hop that does not respond.
    #[command(after_help = "Example:\n  ironet trace 10.42.0.8 --max-hops 8 --timeout-ms 1000")]
    Trace {
        /// Destination IPv4 or IPv6 overlay address.
        #[arg(value_name = "ADDRESS")]
        target: IpAddr,
        /// Maximum number of overlay hops to inspect.
        #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u8).range(1..=255), value_name = "NUMBER")]
        max_hops: u8,
        /// Timeout for each hop, in milliseconds.
        #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(1..=60_000), value_name = "MILLISECONDS")]
        timeout_ms: u64,
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// Show the latest status published by the daemon.
    ///
    /// Status includes readiness, uptime, installed routes, peer connections, network
    /// discovery, path capacity, and packet forwarding counters.
    Status {
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
        /// Use JSON output; retained as an alias for `--output json`.
        #[arg(long)]
        json: bool,
    },
    /// Open a terminal view of status, peers, routes, and diagnostics.
    ///
    /// The view reads daemon state repeatedly and does not change the configuration.
    #[command(visible_alias = "top")]
    Tui {
        /// Refresh interval, in milliseconds.
        #[arg(long, default_value_t = 1_000, value_parser = clap::value_parser!(u64).range(200..=60_000), value_name = "MILLISECONDS")]
        interval_ms: u64,
    },
    /// Check whether the daemon is ready.
    ///
    /// Exit status is zero only when daemon status is recent, required routes are
    /// installed, and configured peers are connected. Intended for service checks.
    Health,
    /// Reload a validated configuration in the running daemon.
    #[command(hide = true)]
    Reload,
    /// Validate the configuration, identity, routes, and local endpoint ID.
    #[command(hide = true)]
    Validate,
    /// Validate a configuration file and write its integrity digest.
    #[command(hide = true)]
    SealConfig,
    /// Install a validated configuration and retain the previous file.
    #[command(hide = true)]
    InstallConfig {
        /// Configuration file to validate and install.
        #[arg(long, value_name = "PATH")]
        source: PathBuf,
    },
    /// Replace the active configuration with its previous validated copy.
    #[command(hide = true)]
    RollbackConfig,
    /// Copy the node identity to a new file with mode 0600.
    #[command(hide = true)]
    BackupIdentity {
        /// Path for the new identity backup.
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Restore an identity when the destination file does not exist.
    #[command(hide = true)]
    RestoreIdentity {
        /// Identity backup to restore.
        #[arg(long, value_name = "PATH")]
        source: PathBuf,
        /// Destination identity file.
        #[arg(
            long,
            default_value = "/var/lib/ironet/identity.key",
            value_name = "PATH"
        )]
        identity_file: PathBuf,
    },
    /// Check configuration, host requirements, and peer reachability.
    ///
    /// The command validates local files and system settings, then checks configured
    /// direct and relay addresses. It does not change configuration or network state.
    Doctor,
    /// Manage routes stored outside the main configuration file.
    ///
    /// Route changes update `routes.toml`. By default, changes are sent to the running
    /// daemon; use `--defer` to apply them during a later reload.
    #[command(hide = true)]
    Route {
        #[command(subcommand)]
        command: RouteCommand,
    },
}

#[derive(Debug, Subcommand)]
enum NetworkCommand {
    /// Create a network and configure this machine as its first node.
    ///
    /// Writes the node identity, network state, daemon configuration, route file, and
    /// configuration digest. The IPv4/IPv6 address pools and node name use defaults when omitted.
    /// Starts the system service unless `--no-start` is set.
    #[command(
        after_help = "Examples:\n  ironet network create office\n  ironet network create office --node-name gateway-a --listen 203.0.113.10:4000\n  ironet network create lab --address-pool 10.42.0.0/16 --ipv6-address-pool fd42:6972:6f68::/64 --no-start --output json"
    )]
    Create {
        /// Name used to identify the network in local status and invites.
        #[arg(value_name = "NAME")]
        name: String,
        /// Set this node's name; the default is the machine hostname.
        #[arg(long, value_name = "NAME")]
        node_name: Option<String>,
        /// IPv4 CIDR used for overlay addresses; the default is selected automatically.
        #[arg(long, value_name = "CIDR")]
        address_pool: Option<ipnet::Ipv4Net>,
        /// IPv6 ULA CIDR used for overlay addresses; the default is selected automatically.
        #[arg(long, value_name = "CIDR")]
        ipv6_address_pool: Option<ipnet::Ipv6Net>,
        /// Add a Tailscale DERP server URL; repeat the option for multiple servers.
        #[arg(long = "derp-server", value_name = "URL")]
        derp_servers: Vec<String>,
        /// Bind a fixed UDP address; repeat the option for multiple addresses.
        #[arg(long = "listen", value_name = "IP:PORT")]
        bind_addresses: Vec<SocketAddr>,
        /// Reuse an identity retained by `network leave --keep-identity`.
        #[arg(long)]
        reuse_identity: bool,
        /// Write the configuration and state without starting the service.
        #[arg(long)]
        no_start: bool,
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// Show the network and this node's stored identity and address.
    ///
    /// Reads local configuration and network state. The daemon does not need to be
    /// running.
    Show {
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// Remove this machine's network configuration and state.
    ///
    /// Stops the service by default, then removes the configuration, digest, route
    /// file, network state, and keys. Use `--keep-identity` only when the same node
    /// identity must be reused later.
    #[command(
        after_help = "Examples:\n  ironet network leave --yes\n  ironet network leave --yes --keep-identity"
    )]
    Leave {
        /// Confirm removal of this machine's network files.
        #[arg(long)]
        yes: bool,
        /// Keep the node identity file for later reuse.
        #[arg(long)]
        keep_identity: bool,
        /// Leave service state unchanged before removing network files.
        #[arg(long)]
        no_stop: bool,
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
}

#[derive(Debug, Subcommand)]
enum InviteCommand {
    /// Create an invite for one node to join the network.
    ///
    /// Only the machine that created the network has the signing key required for this
    /// command. The invite contains its expiry, the new node identity, network data,
    /// and bootstrap addresses. Creating an invite does not restart the daemon.
    #[command(
        after_help = "Examples:\n  ironet invite create\n  ironet invite create --expires 30m --address 203.0.113.10:4000\n  ironet invite create --address 192.0.2.10:4000 --address '[2001:db8::10]:4000' --output json"
    )]
    Create {
        /// Time before the invite expires, such as `30m`, `1h`, or `2d`.
        #[arg(long, default_value = "1h", value_name = "DURATION")]
        expires: String,
        /// Add an address that the joining node can use to reach this node.
        #[arg(long = "address", value_name = "IP:PORT")]
        addresses: Vec<SocketAddr>,
        /// Require an existing endpoint ID instead of generating a new node identity.
        #[arg(long, value_name = "ENDPOINT_ID")]
        node_id: Option<EndpointId>,
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// List invites issued by this machine.
    ///
    /// Shows each invite ID, expiry, and whether it has been revoked. Invite URLs are
    /// not stored and are therefore not included.
    List {
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// Reject future connection attempts that use an invite ID.
    ///
    /// Revocation takes effect for subsequent connection handshakes. It does not
    /// interrupt a connection that is already active.
    Revoke {
        /// Invite ID shown by `invite create` or `invite list`.
        #[arg(value_name = "ID")]
        id: String,
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
}

#[derive(Debug, Subcommand)]
enum NodeCommand {
    /// List the local node, configured peers, and connected nodes.
    ///
    /// Local configuration is always shown. When the daemon is running, nodes learned
    /// from current peer connections are included.
    List {
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// Change this node's name in the local configuration and network state.
    ///
    /// The endpoint ID and overlay address do not change. The running daemon is
    /// reloaded when available.
    Rename {
        /// New name for this node.
        #[arg(value_name = "NAME")]
        name: String,
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// Remove a node from this machine's peer and membership state.
    ///
    /// The selector may be a node name or endpoint ID. Removal blocks automatic
    /// admission of the same endpoint on this machine. The operation requires `--yes`.
    Remove {
        /// Node name or endpoint ID to remove.
        #[arg(value_name = "NODE")]
        node: String,
        /// Confirm the membership change.
        #[arg(long)]
        yes: bool,
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
}

#[derive(Debug, Subcommand)]
enum SubnetCommand {
    /// Advertise a subnet as reachable through this node.
    ///
    /// The CIDR is added to this node's advertised prefixes. This command does not
    /// create routes or enable packet forwarding outside ironet.
    Publish {
        /// IPv4 or IPv6 subnet in CIDR notation.
        #[arg(value_name = "CIDR")]
        prefix: IpNet,
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// List subnets advertised by this node.
    List {
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// Stop advertising a subnet through this node.
    Unpublish {
        /// IPv4 or IPv6 subnet in CIDR notation.
        #[arg(value_name = "CIDR")]
        prefix: IpNet,
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
}

#[derive(Debug, Subcommand)]
enum TransitCommand {
    /// Allow this node to forward overlay traffic between peers.
    ///
    /// Updates the local configuration and reloads the daemon when available.
    Enable {
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// Stop this node from forwarding overlay traffic between peers.
    ///
    /// Traffic addressed to this node and traffic for its published subnets are not
    /// changed by this setting.
    Disable {
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
}

#[derive(Debug, Subcommand)]
enum RouteCommand {
    /// Add routes whose destination is reached through a peer.
    Add {
        /// One or more destination subnets in CIDR notation.
        #[arg(required = true, value_name = "PREFIX")]
        prefixes: Vec<IpNet>,
        /// Peer name or endpoint ID that owns the destination subnets.
        #[arg(long, value_name = "PEER_OR_ENDPOINT_ID")]
        owner: String,
        /// Validate and print the change without saving it.
        #[arg(long)]
        dry_run: bool,
        /// Save the change without sending it to the running daemon.
        #[arg(long, visible_alias = "no-reload")]
        defer: bool,
    },
    /// Import routes from TOML or `<endpoint-id> <prefix>...` text.
    Import {
        /// File to import; use `-` to read standard input.
        #[arg(value_name = "PATH")]
        source: PathBuf,
        /// Replace existing routes instead of merging imported routes.
        #[arg(long)]
        replace: bool,
        /// Validate and print the change without saving it.
        #[arg(long)]
        dry_run: bool,
        /// Save the change without sending it to the running daemon.
        #[arg(long, visible_alias = "no-reload")]
        defer: bool,
    },
    /// List routes stored in `routes.toml`.
    #[command(visible_alias = "ls")]
    List {
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
    },
    /// Remove destination subnets or all routes owned by a peer.
    #[command(visible_alias = "rm")]
    Remove {
        /// CIDR, peer name, or endpoint ID to remove.
        #[arg(required = true, value_name = "PREFIX_OR_OWNER")]
        selectors: Vec<String>,
        /// Validate and print the change without saving it.
        #[arg(long)]
        dry_run: bool,
        /// Save the change without sending it to the running daemon.
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
    let state_dir = cli.state_dir;

    match cli.command {
        None => overview(&config, &socket, &state_dir).await,
        Some(Command::Network { command }) => {
            network_command(&config, &socket, &state_dir, command).await
        }
        Some(Command::Invite { command }) => invite_command(&config, &state_dir, command).await,
        Some(Command::Join {
            invite,
            invite_file,
            node_name,
            reuse_identity,
            no_start,
            output,
        }) => {
            let invite = read_invite(invite, invite_file)?;
            let summary =
                product::join_network(&config, &state_dir, &invite, node_name, reuse_identity)
                    .await?;
            let started = start_service(&config, &socket, &state_dir, no_start).await?;
            print_network_summary(&summary, output, Some(started))
        }
        Some(Command::Node { command }) => {
            node_command(&config, &socket, &state_dir, command).await
        }
        Some(Command::Subnet { command }) => subnet_command(&config, &socket, command).await,
        Some(Command::Transit { command }) => transit_command(&config, &socket, command).await,
        Some(Command::Inspect) => inspect(&config).await,
        Some(Command::Ping {
            target,
            count,
            timeout_ms,
            output,
        }) => ping(&socket, target, count, timeout_ms, output).await,
        Some(Command::Peers { output }) => peers(&socket, output).await,
        Some(Command::Trace {
            target,
            max_hops,
            timeout_ms,
            output,
        }) => {
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
        Some(Command::Status { output, json }) => {
            status(&socket, if json { OutputFormat::Json } else { output }).await
        }
        Some(Command::Tui { interval_ms }) => {
            tui::run(&config, &socket, Duration::from_millis(interval_ms)).await
        }
        Some(Command::Health) => health(&socket, cli.quiet).await,
        Some(Command::Reload) => {
            let ack = control::reload(&socket).await?;
            println!("reloaded generation={}", ack.generation);
            println!("endpoint_id={}", ack.endpoint_id);
            Ok(())
        }
        Some(Command::Validate) => validate(&config).await,
        Some(Command::SealConfig) => {
            deployment::seal(&config).await?;
            println!("sealed = {}", config.display());
            Ok(())
        }
        Some(Command::InstallConfig { source }) => deployment::install(&source, &config).await,
        Some(Command::RollbackConfig) => deployment::rollback(&config).await,
        Some(Command::BackupIdentity { output }) => backup_identity(&config, &output).await,
        Some(Command::RestoreIdentity {
            source,
            identity_file,
        }) => restore_identity(&source, &identity_file),
        Some(Command::Doctor) => doctor(&config).await,
        Some(Command::Route { command }) => route(&config, &socket, command).await,
    }
}

async fn overview(config: &Path, socket: &Path, state_dir: &Path) -> Result<()> {
    if !product::state_path(state_dir).exists() || !config.exists() {
        return print_unconfigured(OutputFormat::Human);
    }
    let summary = product::show_network(config, state_dir).await?;
    println!("Network: {}", summary.network);
    println!("Node:    {}", summary.node);
    println!("Addresses: {}", summary.addresses.join(", "));
    match control::snapshot(socket).await {
        Ok(status) => {
            println!(
                "State:   {}",
                if status.ready { "ready" } else { "starting" }
            );
            println!(
                "Peers:   {} connected",
                status.peers.iter().filter(|peer| peer.connected).count()
            );
        }
        Err(_) => {
            println!("State:   stopped");
            println!("Start:   sudo systemctl enable --now ironet");
        }
    }
    Ok(())
}

fn print_unconfigured(output: OutputFormat) -> Result<()> {
    match output {
        OutputFormat::Human => println!(
            "This machine has not joined an ironet network.\n\nCreate a new network:\n  sudo ironet network create <name>\n\nJoin an existing network:\n  sudo ironet join <invite>"
        ),
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "configured": false,
                "state": "unconfigured",
                "actions": {
                    "create": "sudo ironet network create <name>",
                    "join": "sudo ironet join <invite>"
                }
            }))?
        ),
        OutputFormat::Jsonl => println!(
            "{}",
            serde_json::to_string(
                &serde_json::json!({"configured": false, "state": "unconfigured"})
            )?
        ),
    }
    Ok(())
}

async fn network_command(
    config: &Path,
    socket: &Path,
    state_dir: &Path,
    command: NetworkCommand,
) -> Result<()> {
    match command {
        NetworkCommand::Create {
            name,
            node_name,
            address_pool,
            ipv6_address_pool,
            derp_servers,
            bind_addresses,
            reuse_identity,
            no_start,
            output,
        } => {
            let summary = product::create_network(
                config,
                state_dir,
                &name,
                product::CreateNetworkOptions {
                    node_name,
                    address_pool,
                    ipv6_address_pool,
                    derp_servers,
                    bind_addresses,
                    reuse_identity,
                },
            )
            .await?;
            let started = start_service(config, socket, state_dir, no_start).await?;
            print_network_summary(&summary, output, Some(started))
        }
        NetworkCommand::Show { output } => {
            let summary = product::show_network(config, state_dir).await?;
            print_network_summary(&summary, output, None)
        }
        NetworkCommand::Leave {
            yes,
            keep_identity,
            no_stop,
            output,
        } => {
            ensure!(
                yes,
                "network leave removes local network state; rerun with --yes"
            );
            if !no_stop {
                stop_service().await?;
            }
            let removed = product::leave_network(config, state_dir, keep_identity)?;
            match output {
                OutputFormat::Human => println!(
                    "✓ Left the network and removed {} state files",
                    removed.len()
                ),
                OutputFormat::Json => println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::json!({"left": true, "removed": removed})
                    )?
                ),
                OutputFormat::Jsonl => println!(
                    "{}",
                    serde_json::to_string(&serde_json::json!({"left": true, "removed": removed}))?
                ),
            }
            Ok(())
        }
    }
}

async fn invite_command(config: &Path, state_dir: &Path, command: InviteCommand) -> Result<()> {
    match command {
        InviteCommand::Create {
            expires,
            addresses,
            node_id,
            output,
        } => {
            let lifetime = product::parse_duration(&expires)?;
            let invite =
                product::create_invite(config, state_dir, Some(lifetime), addresses, node_id)?;
            match output {
                OutputFormat::Human => {
                    println!("{}", invite.token);
                    eprintln!(
                        "Invite {} expires at {}",
                        invite.id,
                        display::unix_timestamp(invite.expires_unix_secs)
                    );
                }
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&invite)?),
                OutputFormat::Jsonl => println!("{}", serde_json::to_string(&invite)?),
            }
            Ok(())
        }
        InviteCommand::List { output } => {
            let invites = product::list_invites(state_dir)?;
            match output {
                OutputFormat::Human => {
                    if invites.is_empty() {
                        println!("No invites.\nCreate one with: sudo ironet invite create");
                    } else {
                        println!("{:<26} {:<10} EXPIRES", "ID", "STATE");
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        for invite in invites {
                            let state = if invite.revoked {
                                "revoked"
                            } else if invite.expires_unix_secs < now {
                                "expired"
                            } else {
                                "active"
                            };
                            println!(
                                "{:<26} {:<10} {}",
                                invite.id,
                                state,
                                display::unix_timestamp(invite.expires_unix_secs)
                            );
                        }
                    }
                }
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&invites)?),
                OutputFormat::Jsonl => {
                    for invite in invites {
                        println!("{}", serde_json::to_string(&invite)?);
                    }
                }
            }
            Ok(())
        }
        InviteCommand::Revoke { id, output } => {
            let changed = product::revoke_invite(state_dir, &id)?;
            // Admission reads the authority registry for every new handshake, so invite
            // changes take effect immediately without restarting the data plane.
            print_change(output, "invite", &id, changed, true)
        }
    }
}

async fn node_command(
    config: &Path,
    socket: &Path,
    state_dir: &Path,
    command: NodeCommand,
) -> Result<()> {
    match command {
        NodeCommand::List { output } => {
            let mut nodes = product::list_nodes(config, state_dir).await?;
            if socket.exists()
                && let Ok(live) = control::snapshot(socket).await.map(|status| status.peers)
            {
                for peer in live {
                    if !nodes
                        .iter()
                        .any(|node| node.endpoint_id == peer.endpoint_id)
                    {
                        nodes.push(product::NodeSummary {
                            name: peer.name,
                            endpoint_id: peer.endpoint_id,
                            local: false,
                            removed: false,
                        });
                    }
                }
            }
            nodes.sort_by_key(|node| (!node.local, node.name.clone(), node.endpoint_id.clone()));
            match output {
                OutputFormat::Human => {
                    println!("{:<20} {:<7} ENDPOINT ID", "NAME", "LOCAL");
                    for node in nodes {
                        println!(
                            "{:<20} {:<7} {}{}",
                            node.name,
                            node.local,
                            node.endpoint_id,
                            if node.removed { " (removed)" } else { "" }
                        );
                    }
                }
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&nodes)?),
                OutputFormat::Jsonl => {
                    for node in nodes {
                        println!("{}", serde_json::to_string(&node)?);
                    }
                }
            }
            Ok(())
        }
        NodeCommand::Rename { name, output } => {
            let changed = product::rename_local_node(config, state_dir, &name).await?;
            let applied = reload_if_running(socket).await?;
            print_change(output, "node_name", &name, changed, applied)
        }
        NodeCommand::Remove { node, yes, output } => {
            ensure!(
                yes,
                "node removal changes adjacency state; rerun with --yes"
            );
            let removed = match product::remove_node(config, state_dir, &node).await {
                Ok(removed) => removed,
                Err(configured_error) => {
                    let live = control::peers(socket).await.unwrap_or_default();
                    let peer = live
                        .into_iter()
                        .find(|peer| peer.name == node || peer.endpoint_id == node)
                        .with_context(|| {
                            format!("{configured_error}; no live node matches {node}")
                        })?;
                    let endpoint = peer.endpoint_id.parse::<EndpointId>()?;
                    product::remove_node_endpoint(config, state_dir, endpoint, &peer.name).await?
                }
            };
            let (name, changed) = removed;
            let applied = reload_if_running(socket).await?;
            print_change(output, "node", &name, changed, applied)
        }
    }
}

async fn subnet_command(config: &Path, socket: &Path, command: SubnetCommand) -> Result<()> {
    match command {
        SubnetCommand::Publish { prefix, output } => {
            let mut change = product::publish_subnet(config, prefix).await?;
            change.applied = reload_if_running(socket).await?;
            print_capability_change(output, &change)
        }
        SubnetCommand::List { output } => {
            let subnets = product::list_subnets(config).await?;
            match output {
                OutputFormat::Human => {
                    if subnets.is_empty() {
                        println!(
                            "No local subnets are published.\nPublish one with: sudo ironet subnet publish <prefix>"
                        );
                    } else {
                        for subnet in subnets {
                            println!("{subnet}");
                        }
                    }
                }
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&subnets)?),
                OutputFormat::Jsonl => {
                    for subnet in subnets {
                        println!("{}", serde_json::to_string(&subnet)?);
                    }
                }
            }
            Ok(())
        }
        SubnetCommand::Unpublish { prefix, output } => {
            let mut change = product::unpublish_subnet(config, prefix).await?;
            change.applied = reload_if_running(socket).await?;
            print_capability_change(output, &change)
        }
    }
}

async fn transit_command(config: &Path, socket: &Path, command: TransitCommand) -> Result<()> {
    let (enabled, output) = match command {
        TransitCommand::Enable { output } => (true, output),
        TransitCommand::Disable { output } => (false, output),
    };
    let mut change = product::set_transit(config, enabled).await?;
    change.applied = reload_if_running(socket).await?;
    print_capability_change(output, &change)
}

fn read_invite(invite: Option<String>, invite_file: Option<PathBuf>) -> Result<String> {
    if let Some(invite) = invite {
        return Ok(invite);
    }
    let Some(path) = invite_file else {
        ensure!(
            std::io::stdin().is_terminal(),
            "join requires an invite URL or --invite-file"
        );
        eprint!("Paste invite: ");
        std::io::stderr().flush()?;
        let mut value = String::new();
        std::io::stdin().read_line(&mut value)?;
        ensure!(!value.trim().is_empty(), "invite cannot be empty");
        return Ok(value.trim().into());
    };
    if path == Path::new("-") {
        let mut value = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut value)?;
        Ok(value.trim().into())
    } else {
        Ok(std::fs::read_to_string(&path)
            .with_context(|| format!("failed reading invite {}", path.display()))?
            .trim()
            .into())
    }
}

fn print_network_summary(
    summary: &product::NetworkSummary,
    output: OutputFormat,
    started: Option<bool>,
) -> Result<()> {
    match output {
        OutputFormat::Human => {
            if started.is_none() {
                println!("Network:  {}", summary.network);
                println!("Node:     {}", summary.node);
                println!("Addresses: {}", summary.addresses.join(", "));
                println!("Endpoint: {}", summary.endpoint_id);
                return Ok(());
            } else if summary.created {
                println!("✓ Created network \"{}\"", summary.network);
            } else {
                println!("✓ Joined network \"{}\"", summary.network);
            }
            println!("✓ Added this machine as \"{}\"", summary.node);
            println!(
                "✓ Assigned overlay addresses {}",
                summary.addresses.join(", ")
            );
            match started {
                Some(true) => println!("✓ ironet is running"),
                Some(false) => println!("State created; service start was skipped"),
                None => {}
            }
            if summary.created {
                println!("\nAdd another machine:\n  sudo ironet invite create");
            }
        }
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(
                &serde_json::json!({"network": summary, "service_started": started})
            )?
        ),
        OutputFormat::Jsonl => println!(
            "{}",
            serde_json::to_string(
                &serde_json::json!({"network": summary, "service_started": started})
            )?
        ),
    }
    Ok(())
}

fn print_capability_change(output: OutputFormat, change: &product::CapabilityChange) -> Result<()> {
    match output {
        OutputFormat::Human => {
            let verb = if change.changed {
                "Updated"
            } else {
                "Already configured"
            };
            println!("✓ {verb} {} {}", change.capability, change.value);
            if !change.applied {
                println!("Apply with: sudo systemctl restart ironet");
            }
        }
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(change)?),
        OutputFormat::Jsonl => println!("{}", serde_json::to_string(change)?),
    }
    Ok(())
}

fn print_change(
    output: OutputFormat,
    resource: &str,
    value: &str,
    changed: bool,
    applied: bool,
) -> Result<()> {
    let change = product::CapabilityChange {
        capability: resource.into(),
        value: value.into(),
        changed,
        applied,
    };
    print_capability_change(output, &change)
}

async fn reload_if_running(socket: &Path) -> Result<bool> {
    if !socket.exists() {
        return Ok(false);
    }
    if control::health(socket).await.is_err() {
        return Ok(false);
    }
    control::reload(socket).await?;
    Ok(true)
}

async fn start_service(
    config: &Path,
    socket: &Path,
    state_dir: &Path,
    no_start: bool,
) -> Result<bool> {
    if no_start {
        return Ok(false);
    }
    ensure!(
        config == Path::new("/etc/ironet/config.toml")
            && socket == Path::new(DEFAULT_CONTROL_SOCKET)
            && state_dir == Path::new("/var/lib/ironet"),
        "automatic service start uses the system paths; pass --no-start for custom --config, --socket, or --state-dir values"
    );
    let status = tokio::process::Command::new("systemctl")
        .args(["enable", "--now", "ironet"])
        .status()
        .await
        .context(
            "failed to start ironet with systemctl; rerun with --no-start on non-systemd hosts",
        )?;
    ensure!(
        status.success(),
        "systemctl failed to start ironet; inspect `systemctl status ironet`"
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if control::health(socket).await.is_ok() {
            break;
        }
        ensure!(
            tokio::time::Instant::now() < deadline,
            "ironet service started but did not become ready; inspect `systemctl status ironet`"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Ok(true)
}

async fn stop_service() -> Result<()> {
    let status = tokio::process::Command::new("systemctl")
        .args(["disable", "--now", "ironet"])
        .status()
        .await
        .context(
            "failed to stop ironet with systemctl; rerun with --no-stop on non-systemd hosts",
        )?;
    ensure!(status.success(), "systemctl failed to stop ironet");
    Ok(())
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
                routes: vec![ironet::config::RouteOriginConfig {
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
                        println!("Add one with: ironet route add PREFIX --owner PEER");
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
    ironet::routes::validate_for_config(config_path, registry).await
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
        if let Err(error) = ironet::derp::identity::backup(&derp_source, &derp_output) {
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
        if let Err(error) = ironet::derp::identity::restore(&derp_source, &derp_destination) {
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
        "network: udp4={} udp6={} mapping_varies4={} mapping_varies6={} global4={} global6={} nat64={} candidates={}",
        status.network.udp_ipv4,
        status.network.udp_ipv6,
        status
            .network
            .mapping_varies_by_destination_ipv4
            .map_or("unknown".into(), |value| value.to_string()),
        status
            .network
            .mapping_varies_by_destination_ipv6
            .map_or("unknown".into(), |value| value.to_string()),
        status
            .network
            .global_ipv4
            .map_or("none".into(), |value| value.to_string()),
        status
            .network
            .global_ipv6
            .map_or("none".into(), |value| value.to_string()),
        status.network.nat64_prefix.map_or("none".into(), |prefix| {
            format!("{}/{}", prefix.network, prefix.prefix_len)
        }),
        status.network.candidates.len(),
    )?;
    for candidate in &status.network.candidates {
        writeln!(
            rendered,
            "network_candidate: kind={} address={}",
            single_line(&candidate.kind),
            candidate.address
        )?;
    }
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
        "peer {}: endpoint_id={} interface={} connected={} path={}:{} rtt={} jitter={} loss={} fec={} queue={} tx_packets={} tx={} rx_packets={} rx={} policy_drops={} connection_errors={} send_errors={}",
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
        if peer.fec_active {
            format!(
                "{}+{}@{}ms",
                peer.fec_data_shards, peer.fec_recovery_shards, peer.fec_block_timeout_millis
            )
        } else {
            "off".into()
        },
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
    println!("nat_enabled = {}", config.routing.nat_enabled);
    println!(
        "preferred_ip_family = {}",
        match config.path_selection.prefer {
            ironet::config::IpFamilyPreference::Ipv4 => "ipv4",
            ironet::config::IpFamilyPreference::Ipv6 => "ipv6",
        }
    );
    println!("iroh_relay_enabled = {}", config.relay.iroh_relay_enabled);
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
    if config.routing.nat_enabled && needs_forwarding {
        for (command, required) in [
            (
                "iptables",
                config
                    .advertised_prefixes
                    .iter()
                    .any(|prefix| prefix.addr().is_ipv4()),
            ),
            (
                "ip6tables",
                config
                    .advertised_prefixes
                    .iter()
                    .any(|prefix| prefix.addr().is_ipv6()),
            ),
        ] {
            if !required {
                continue;
            }
            let output = tokio::process::Command::new(command)
                .args(["-w", "5", "-t", "nat", "-L"])
                .output()
                .await
                .with_context(|| format!("failed executing {command} for advertised-prefix NAT"))?;
            ensure!(
                output.status.success(),
                "{command} NAT support is not operational: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
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
            ironet::derp::identity::load(&config.derp_identity_file())?
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
        let identity = ironet::derp::identity::load_or_create(&config.derp_identity_file())?;
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
    for prefix in &config.excluded_underlay_prefixes {
        println!("excluded_underlay_prefix: {prefix}");
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
    use clap::CommandFactory;
    use ironet::{
        config::NodeInfo, mesh::MeshStatus, observability::RouteStatus, trace::PingSample,
    };

    fn assert_command_help_is_complete(command: &clap::Command) {
        assert!(
            command.get_about().is_some(),
            "{} has no command description",
            command.get_name()
        );
        for argument in command.get_arguments() {
            assert!(
                argument.get_help().is_some(),
                "{} argument {} has no description",
                command.get_name(),
                argument.get_id()
            );
        }
        for child in command.get_subcommands() {
            assert_command_help_is_complete(child);
        }
    }

    fn sample_peer() -> PeerStatus {
        serde_json::from_value(serde_json::json!({
            "name": "bad\nname",
            "endpoint_id": "endpoint",
            "interface": "ironet0",
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
            "ironet",
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
            Some(Command::Trace { output, .. }) => assert_eq!(output, OutputFormat::Jsonl),
            command => panic!("expected trace command, got {command:?}"),
        }
    }

    #[test]
    fn global_socket_is_accepted_after_subcommand() {
        let cli =
            Cli::try_parse_from(["ironet", "status", "--socket", "/tmp/control.sock"]).unwrap();
        assert_eq!(cli.socket, PathBuf::from("/tmp/control.sock"));
    }

    #[test]
    fn help_explains_the_network_model_and_common_workflow() {
        let mut command = Cli::command();
        let help = command.render_long_help().to_string();
        for required in [
            "A network contains nodes",
            "Each node has an overlay address",
            "ironet network create NAME",
            "ironet invite create --address IP:PORT",
            "ironet join INVITE",
            "--output json",
        ] {
            assert!(help.contains(required), "root help is missing {required:?}");
        }
    }

    #[test]
    fn every_command_and_argument_has_a_description() {
        assert_command_help_is_complete(&Cli::command());
    }

    #[test]
    fn product_commands_expose_user_intent_without_init_vocabulary() {
        let create = Cli::try_parse_from([
            "ironet",
            "network",
            "create",
            "production",
            "--node-name",
            "edge-a",
            "--no-start",
            "--output",
            "json",
        ])
        .unwrap();
        assert!(matches!(
            create.command,
            Some(Command::Network {
                command: NetworkCommand::Create { .. }
            })
        ));

        let join = Cli::try_parse_from([
            "ironet",
            "join",
            "ironet://join/v1/00",
            "--node-name",
            "edge-b",
            "--no-start",
        ])
        .unwrap();
        assert!(matches!(join.command, Some(Command::Join { .. })));
        assert!(Cli::try_parse_from(["ironet", "init"]).is_err());
    }

    #[test]
    fn product_mutations_are_explicit_and_machine_readable() {
        for args in [
            vec![
                "ironet",
                "subnet",
                "publish",
                "192.168.50.0/24",
                "--output",
                "json",
            ],
            vec!["ironet", "transit", "enable", "--output", "json"],
            vec![
                "ironet", "node", "remove", "edge-b", "--yes", "--output", "json",
            ],
            vec![
                "ironet",
                "invite",
                "create",
                "--expires",
                "30m",
                "--output",
                "json",
            ],
        ] {
            Cli::try_parse_from(args).unwrap();
        }
    }

    #[test]
    fn ping_accepts_probe_count_timeout_and_machine_output() {
        let cli = Cli::try_parse_from([
            "ironet",
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
            Some(Command::Ping {
                target,
                count,
                timeout_ms,
                output,
            }) => {
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
        let cli = Cli::try_parse_from(["ironet", "peers", "--output", "jsonl"]).unwrap();
        match cli.command {
            Some(Command::Peers { output }) => assert_eq!(output, OutputFormat::Jsonl),
            command => panic!("expected peers command, got {command:?}"),
        }
    }

    #[test]
    fn route_subcommands_match_the_operational_cli() {
        let cli = Cli::try_parse_from([
            "ironet",
            "route",
            "import",
            "site.routes",
            "--replace",
            "--no-reload",
        ])
        .unwrap();
        match cli.command {
            Some(Command::Route {
                command:
                    RouteCommand::Import {
                        source,
                        replace,
                        dry_run,
                        defer,
                    },
            }) => {
                assert_eq!(source, PathBuf::from("site.routes"));
                assert!(replace);
                assert!(!dry_run);
                assert!(defer);
            }
            command => panic!("expected route import, got {command:?}"),
        }

        let cli = Cli::try_parse_from(["ironet", "route", "remove", "10.0.0.0/24", "10.1.0.0/24"])
            .unwrap();
        match cli.command {
            Some(Command::Route {
                command: RouteCommand::Remove { selectors, .. },
            }) => assert_eq!(selectors, ["10.0.0.0/24", "10.1.0.0/24"]),
            command => panic!("expected route remove, got {command:?}"),
        }

        let cli = Cli::try_parse_from([
            "ironet",
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
            Some(Command::Route {
                command:
                    RouteCommand::Add {
                        prefixes,
                        owner,
                        dry_run,
                        ..
                    },
            }) => {
                assert_eq!(prefixes.len(), 2);
                assert_eq!(owner, "branch-b");
                assert!(dry_run);
            }
            command => panic!("expected route add, got {command:?}"),
        }

        assert!(Cli::try_parse_from(["ironet", "route", "ls"]).is_ok());
        assert!(Cli::try_parse_from(["ironet", "route", "rm", "10.2.0.0/24"]).is_ok());
    }

    #[test]
    fn tui_accepts_bounded_refresh_interval_and_top_alias() {
        let cli = Cli::try_parse_from(["ironet", "tui", "--interval-ms", "500"]).unwrap();
        match cli.command {
            Some(Command::Tui { interval_ms }) => assert_eq!(interval_ms, 500),
            command => panic!("expected tui command, got {command:?}"),
        }
        assert!(Cli::try_parse_from(["ironet", "top"]).is_ok());
        assert!(Cli::try_parse_from(["ironet", "tui", "--interval-ms", "199"]).is_err());
        assert!(Cli::try_parse_from(["ironet", "tui", "--interval-ms", "60001"]).is_err());
    }

    #[test]
    fn ping_rejects_invalid_cli_boundaries_and_targets() {
        for arguments in [
            vec!["ironet", "ping", "21.0.0.2", "--count", "0"],
            vec!["ironet", "ping", "21.0.0.2", "--count", "21"],
            vec!["ironet", "ping", "21.0.0.2", "--timeout-ms", "0"],
            vec!["ironet", "ping", "21.0.0.2", "--timeout-ms", "60001"],
            vec!["ironet", "ping", "not-an-ip"],
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
            "peers: total=1 connected=1\npeer bad name: endpoint_id=endpoint interface=ironet0 connected=true path=unknown:unknown rtt=unknown jitter=unknown loss=0.00% fec=off queue=0B tx_packets=2 tx=3B rx_packets=4 rx=5B policy_drops=8 connection_errors=0 send_errors=9\n"
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
            network: Default::default(),
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
}

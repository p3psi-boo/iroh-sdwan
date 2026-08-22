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
    config::Config,
    control::{self, DEFAULT_CONTROL_SOCKET},
    deployment,
    derp::{identity::DerpIdentity, probe_server, tls_config},
    display, identity, logging, product,
    protocol::v2::{
        learner::LearnerModeV2,
        policy::{
            api::PolicyBackend,
            package::{
                self as policy_package, PackageLimits, PolicyManifestV1, PolicyPackage, TrustBasis,
            },
            runtime::{PolicyEngine, PolicyLoader},
            signature::{
                PolicyPublicKey, PolicySigningKey, TrustStoreV1, TrustedSigner, encode_digest,
                parse_digest,
            },
        },
        policy_tick::PolicySlotV1,
        replay::{ReplayTapSampleV2, TickReplayReportV2, replay_ticks},
        utility::Objective,
    },
    routes::RouteRegistry,
    status::{PeerStatus, RuntimeStatus},
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
        after_help = "Examples:\n  ironet join 'ironet://join/v2/...'\n  ironet join --invite-file invite.txt\n  cat invite.txt | ironet join --invite-file - --output json"
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
    /// Status includes readiness, uptime, installed routes, peer connections, live QUIC
    /// path state, and V2 Cell/PacketTrain/FEC/Repair counters.
    Status {
        /// Select the output format.
        #[arg(short, long, visible_alias = "format", value_enum, default_value_t)]
        output: OutputFormat,
        /// Use JSON output; retained as an alias for `--output json`.
        #[arg(long)]
        json: bool,
    },
    /// Export the live V2 runtime snapshot in Prometheus text format.
    ///
    /// Every metric is derived from the same in-memory snapshot as `status` and
    /// uses the `ironet_v2_` namespace; no V1 metric aliases are emitted.
    Metrics,
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
    /// Generate signing keys and inspect, sign, or verify WASM policy packages.
    ///
    /// A policy package is a WebAssembly component carrying an `ironet.manifest.v1`
    /// custom section and, once signed, a trailing `ironet.signature.v1` section
    /// (Ed25519 over the BLAKE3 digest of the preceding bytes).
    #[command(
        after_help = "Examples:\n  ironet policy keygen --output signer.key\n  ironet policy sign --key signer.key unsigned.wasm --output policy.wasm\n  ironet policy inspect policy.wasm\n  ironet policy verify policy.wasm --signer-pubkey ed25519:...\n  ironet policy verify policy.wasm            # trust store from the sealed configuration"
    )]
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    /// Generate an Ed25519 signing key and print its signer id and public key.
    ///
    /// The secret key is written with mode 0600; the public key is written next to it
    /// as `PATH.pub`.
    Keygen {
        /// Destination for the secret key.
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
        /// Signer id to print; defaults to the first 8 bytes of BLAKE3(public key).
        #[arg(long, value_name = "ID")]
        signer_id: Option<String>,
    },
    /// Show manifest, signer, digest, section table and file size.
    Inspect {
        /// Policy package (`.wasm`).
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// Print machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Verify a package against the sealed trust store or an explicit key/pin.
    ///
    /// Without `--signer-pubkey`/`--digest-pin` the `[autotune.wasm]` trust store of the
    /// configuration file (`--config`) is used.
    Verify {
        /// Policy package (`.wasm`).
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// Accept signatures from this `ed25519:<hex|base32>` public key (repeatable).
        #[arg(long, value_name = "KEY")]
        signer_pubkey: Vec<String>,
        /// Accept an unsigned package with this `blake3:<hex>` digest (repeatable).
        #[arg(long, value_name = "DIGEST")]
        digest_pin: Vec<String>,
    },
    /// Sign a package; an existing signature is replaced.
    Sign {
        /// Secret key file written by `keygen`.
        #[arg(long, value_name = "PATH")]
        key: PathBuf,
        /// Unsigned (or previously signed) package.
        #[arg(value_name = "FILE")]
        file: PathBuf,
        /// Destination for the signed package.
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
        /// Signer id recorded in the signature; defaults to the key's signer id.
        #[arg(long, value_name = "ID")]
        signer_id: Option<String>,
        /// Attach (or replace) the manifest from this JSON file before signing.
        #[arg(long, value_name = "MANIFEST_JSON")]
        manifest: Option<PathBuf>,
    },
    /// Replay a policy over a recorded autotune tap fixture, offline and
    /// deterministic, through the production PolicyBackend/guardrail pipeline.
    ///
    /// POLICY is `builtin`, `native`, or an absolute path to a `.wasm`
    /// package. `builtin` runs the embedded builtin.wasm component through
    /// the verified loader; an external `.wasm` package is verified against
    /// the sealed trust store of `--config`, or against
    /// `--signer-pubkey`/`--digest-pin`.
    Replay {
        /// `builtin`, `native`, or an absolute `.wasm` path.
        #[arg(value_name = "POLICY")]
        policy: String,
        /// Tap fixture: JSON array, profile summary, or JSONL; '-' reads stdin.
        #[arg(value_name = "FIXTURE")]
        fixture: PathBuf,
        /// Side selected from a profile summary's autotune_tap object.
        #[arg(long, default_value = "a")]
        side: String,
        /// Utility objective the host applies to the policy output.
        #[arg(long, value_enum, default_value_t = ReplayObjective::Balanced)]
        objective: ReplayObjective,
        /// Learner mode the policy runs in (`shadow` matches the checked-in
        /// golden fixtures).
        #[arg(long, value_enum, default_value_t = ReplayMode::Shadow)]
        mode: ReplayMode,
        /// Fixed deterministic seed for the policy pipeline.
        #[arg(long, default_value_t = 1)]
        seed: u64,
        /// Compare the run against a previously written report; exits non-zero
        /// on the first diverging sample (deterministic assert).
        #[arg(long, value_name = "REPORT_JSON")]
        golden: Option<PathBuf>,
        /// Report path; '-' writes stdout.
        #[arg(long, default_value = "-")]
        output: PathBuf,
        /// Accept `.wasm` signatures from this `ed25519:<hex|base32>` public
        /// key instead of the sealed trust store (repeatable).
        #[arg(long, value_name = "KEY")]
        signer_pubkey: Vec<String>,
        /// Accept an unsigned `.wasm` package with this `blake3:<hex>` digest
        /// (repeatable).
        #[arg(long, value_name = "DIGEST")]
        digest_pin: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ReplayObjective {
    Balanced,
    Throughput,
    Latency,
}

impl From<ReplayObjective> for ironet::protocol::v2::utility::Objective {
    fn from(value: ReplayObjective) -> Self {
        match value {
            ReplayObjective::Balanced => Self::Balanced,
            ReplayObjective::Throughput => Self::Throughput,
            ReplayObjective::Latency => Self::Latency,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ReplayMode {
    Off,
    Shadow,
    On,
}

impl From<ReplayMode> for ironet::protocol::v2::learner::LearnerModeV2 {
    fn from(value: ReplayMode) -> Self {
        match value {
            ReplayMode::Off => Self::Off,
            ReplayMode::Shadow => Self::Shadow,
            ReplayMode::On => Self::On,
        }
    }
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
        /// Bind one dual-stack UDP address.
        #[arg(long = "listen", value_name = "IP:PORT")]
        bind_address: Option<SocketAddr>,
        /// Override the embedded DNS suffix generated for this network.
        #[arg(long, value_name = "DOMAIN", conflicts_with = "no_dns")]
        dns_domain: Option<String>,
        /// Disable embedded authoritative DNS and host resolver integration.
        #[arg(long)]
        no_dns: bool,
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
        Some(Command::Invite { command }) => {
            invite_command(&config, &socket, &state_dir, command).await
        }
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
        Some(Command::Metrics) => metrics(&socket).await,
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
        Some(Command::Policy { command }) => policy_command(&config, command).await,
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
            bind_address,
            dns_domain,
            no_dns,
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
                    bind_address,
                    dns_domain,
                    no_dns,
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

async fn invite_command(
    config: &Path,
    socket: &Path,
    state_dir: &Path,
    command: InviteCommand,
) -> Result<()> {
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
            let _ = reload_if_running(socket).await?;
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
            let applied = reload_if_running(socket).await?;
            print_change(output, "invite", &id, changed, applied)
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
                println!(
                    "DNS:      {}",
                    summary.dns_domain.as_deref().unwrap_or("disabled")
                );
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
            if let Some(domain) = &summary.dns_domain {
                println!("✓ Enabled embedded DNS for {domain}");
            }
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

async fn policy_command(config_path: &Path, command: PolicyCommand) -> Result<()> {
    match command {
        PolicyCommand::Keygen { output, signer_id } => policy_keygen(&output, signer_id),
        PolicyCommand::Inspect { file, json } => policy_inspect(&file, json),
        PolicyCommand::Verify {
            file,
            signer_pubkey,
            digest_pin,
        } => policy_verify(config_path, &file, &signer_pubkey, &digest_pin).await,
        PolicyCommand::Sign {
            key,
            file,
            output,
            signer_id,
            manifest,
        } => policy_sign(&key, &file, &output, signer_id, manifest.as_deref()),
        PolicyCommand::Replay {
            policy,
            fixture,
            side,
            objective,
            mode,
            seed,
            golden,
            output,
            signer_pubkey,
            digest_pin,
        } => {
            policy_replay(
                config_path,
                &policy,
                &fixture,
                &side,
                objective.into(),
                mode.into(),
                seed,
                golden.as_deref(),
                &output,
                &signer_pubkey,
                &digest_pin,
            )
            .await
        }
    }
}

fn policy_keygen(output: &Path, signer_id: Option<String>) -> Result<()> {
    ensure!(
        !output.exists(),
        "refusing to overwrite existing key {}",
        output.display()
    );
    let key = PolicySigningKey::generate()?;
    key.write_file(output)?;
    let public = key.public();
    let public_path = companion_path(output, ".pub");
    deployment::atomic_write(
        &public_path,
        format!("{}\n", public.encode()).as_bytes(),
        0o644,
    )?;
    let signer_id = signer_id.unwrap_or_else(|| public.default_signer_id());
    println!("signer_id = {signer_id}");
    println!("public_key = {public}");
    println!("key_file = {}", output.display());
    println!("public_key_file = {}", public_path.display());
    Ok(())
}

fn companion_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn read_policy_package(file: &Path, limits: PackageLimits) -> Result<PolicyPackage> {
    let bytes =
        std::fs::read(file).with_context(|| format!("failed reading {}", file.display()))?;
    PolicyPackage::parse(&bytes, limits)
        .with_context(|| format!("{} is not a valid policy package", file.display()))
}

fn policy_inspect(file: &Path, json: bool) -> Result<()> {
    let package = read_policy_package(file, PackageLimits::default())?;
    if json {
        let value = serde_json::json!({
            "file": file.display().to_string(),
            "file_len": package.file_len,
            "body_len": package.body_len,
            "digest": package.digest_string(),
            "signed": package.signature.is_some(),
            "signer_id": package.signature.as_ref().map(|signature| signature.signer_id.clone()),
            "signature": package.signature,
            "manifest": package.manifest,
            "sections": package.sections,
        });
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    let manifest = &package.manifest;
    println!("file = {}", file.display());
    println!("size = {} bytes", package.file_len);
    println!("signed_prefix = {} bytes", package.body_len);
    println!("digest = {}", package.digest_string());
    match &package.signature {
        Some(signature) => {
            println!("signed = true");
            println!("signer_id = {}", signature.signer_id);
            println!("signature_format = {}", signature.signature_format);
            println!("signature_digest = {}", signature.digest);
            println!("signature = {}", signature.signature);
        }
        None => println!("signed = false"),
    }
    println!("policy_id = {}", manifest.policy_id);
    println!("policy_version = {}", manifest.policy_version);
    println!("format_version = {}", manifest.format_version);
    println!("abi_world = {}", manifest.abi_world);
    println!(
        "extensions_supported = [{}]",
        join_numbers(&manifest.extensions_supported)
    );
    println!("state_schema = {}", manifest.state_schema);
    println!(
        "state_schema_accepts = [{}]",
        join_numbers(&manifest.state_schema_accepts)
    );
    println!("capabilities = [{}]", manifest.capabilities.join(", "));
    println!("minimum_host_version = {}", manifest.minimum_host_version);
    println!("maximum_state_bytes = {}", manifest.maximum_state_bytes);
    println!(
        "requested_memory_bytes = {}",
        manifest.requested_memory_bytes
    );
    println!("requested_fuel = {}", manifest.requested_fuel);
    println!("built_at = {}", manifest.built_at);
    println!("source_revision = {}", manifest.source_revision);
    println!("sections:");
    for (index, section) in package.sections.iter().enumerate() {
        println!(
            "  #{index} id={} kind={} name={:?} offset={} len={} payload_len={}",
            section.id,
            section.kind(),
            section.name.as_deref().unwrap_or("-"),
            section.offset,
            section.len,
            section.payload_len
        );
    }
    Ok(())
}

fn join_numbers<T: ToString>(values: &[T]) -> String {
    values
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

async fn policy_verify(
    config_path: &Path,
    file: &Path,
    signer_pubkeys: &[String],
    digest_pins: &[String],
) -> Result<()> {
    let (limits, mut trust, trust_source) = if signer_pubkeys.is_empty() && digest_pins.is_empty() {
        let config = Config::load(config_path).await?;
        let trust = TrustStoreV1::from_config(&config.autotune.wasm).with_context(|| {
            format!(
                "invalid [autotune.wasm] trust store in {}",
                config_path.display()
            )
        })?;
        (
            PackageLimits::from_config(&config.autotune.wasm),
            trust,
            format!("config {}", config_path.display()),
        )
    } else {
        let mut trust = TrustStoreV1::default();
        trust.require_signature = !signer_pubkeys.is_empty();
        for pin in digest_pins {
            trust.add_digest_pin(parse_digest(pin)?);
        }
        (PackageLimits::default(), trust, "command line".to_owned())
    };
    let package = read_policy_package(file, limits)?;
    // Explicit keys match whichever signer id the package claims, so that
    // `--signer-pubkey` answers "was this signed by that key?".
    let claimed_signer = package
        .signature
        .as_ref()
        .map(|signature| signature.signer_id.clone());
    for text in signer_pubkeys {
        let mut signer = TrustedSigner::new(PolicyPublicKey::parse(text)?);
        if let Some(signer_id) = &claimed_signer {
            signer = signer.with_signer_id(signer_id.clone());
        }
        if trust.signer(&signer.signer_id).is_none() {
            trust.add_signer(signer)?;
        }
    }
    match package.verify(&trust, chrono::Utc::now()) {
        Ok(verified) => {
            println!("verify = ok");
            println!(
                "trust = {}",
                match verified.trust {
                    TrustBasis::Signer => "signer",
                    TrustBasis::DigestPin => "digest_pin",
                }
            );
            println!("trust_source = {trust_source}");
            println!(
                "signer_id = {}",
                verified.signer_id.as_deref().unwrap_or("-")
            );
            println!("digest = {}", verified.digest_string());
            println!("policy_id = {}", verified.manifest.policy_id);
            println!("policy_version = {}", verified.manifest.policy_version);
            Ok(())
        }
        Err(error) => {
            println!("verify = failed");
            println!("trust_source = {trust_source}");
            println!("digest = {}", package.digest_string());
            println!("signer_id = {}", claimed_signer.as_deref().unwrap_or("-"));
            println!("reason = {error}");
            Err(anyhow::Error::new(error)
                .context(format!("{} failed verification", file.display())))
        }
    }
}

fn policy_sign(
    key_path: &Path,
    file: &Path,
    output: &Path,
    signer_id: Option<String>,
    manifest_path: Option<&Path>,
) -> Result<()> {
    let key = PolicySigningKey::read_file(key_path)?;
    let limits = PackageLimits::default();
    let mut bytes =
        std::fs::read(file).with_context(|| format!("failed reading {}", file.display()))?;
    if let Some(manifest_path) = manifest_path {
        let manifest_json = std::fs::read(manifest_path)
            .with_context(|| format!("failed reading {}", manifest_path.display()))?;
        let manifest = PolicyManifestV1::from_json(&manifest_json)
            .with_context(|| format!("invalid manifest {}", manifest_path.display()))?;
        bytes = policy_package::attach_manifest(&bytes, &manifest, limits)?;
    }
    let signer_id = signer_id.unwrap_or_else(|| key.public().default_signer_id());
    let signed = policy_package::sign(&bytes, &key, &signer_id, limits)?;
    deployment::atomic_write(output, &signed, 0o644)
        .with_context(|| format!("failed writing {}", output.display()))?;
    let package = PolicyPackage::parse(&signed, limits)?;
    println!("signed = {}", output.display());
    println!("signer_id = {signer_id}");
    println!("public_key = {}", key.public());
    println!("digest = {}", package.digest_string());
    println!("policy_id = {}", package.manifest.policy_id);
    println!("policy_version = {}", package.manifest.policy_version);
    println!("size = {} bytes", signed.len());
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn policy_replay(
    config_path: &Path,
    policy: &str,
    fixture: &Path,
    side: &str,
    objective: Objective,
    mode: LearnerModeV2,
    seed: u64,
    golden: Option<&Path>,
    output: &Path,
    signer_pubkeys: &[String],
    digest_pins: &[String],
) -> Result<()> {
    let input = read_replay_source(fixture)?;
    let samples = decode_replay_samples(&input, side)?;
    let (slot, weights) = match policy {
        ironet::config::AUTOTUNE_POLICY_NATIVE => {
            // Host-side conservative rules, no learner (plan Phase 6).
            (PolicySlotV1::native_rules(), objective.weights())
        }
        ironet::config::AUTOTUNE_POLICY_BUILTIN => {
            // The same component the daemon runs: the embedded builtin.wasm
            // through the verified loader, trusted by its digest sidecar.
            let backend = PolicyLoader::new(PolicyEngine::try_new()?)
                .load_builtin(&ironet::config::AutotuneWasmConfig::default())
                .context("loading the embedded builtin policy component")?;
            let digest = backend
                .identity()
                .digest
                .map(|digest| encode_digest(&digest))
                .unwrap_or_default();
            (
                PolicySlotV1::new(Box::new(backend), None, digest),
                objective.weights(),
            )
        }
        selection if selection.to_ascii_lowercase().ends_with(".wasm") => {
            let path = Path::new(selection);
            ensure!(
                path.is_absolute(),
                "policy path must be absolute: {}",
                path.display()
            );
            let (config, trust) = if signer_pubkeys.is_empty() && digest_pins.is_empty() {
                let config = Config::load(config_path).await?;
                let trust =
                    TrustStoreV1::from_config(&config.autotune.wasm).with_context(|| {
                        format!(
                            "invalid [autotune.wasm] trust store in {}",
                            config_path.display()
                        )
                    })?;
                (config.autotune.wasm, trust)
            } else {
                let mut trust = TrustStoreV1::default();
                trust.require_signature = !signer_pubkeys.is_empty();
                for pin in digest_pins {
                    trust.add_digest_pin(parse_digest(pin)?);
                }
                for text in signer_pubkeys {
                    trust.add_signer(TrustedSigner::new(PolicyPublicKey::parse(text)?))?;
                }
                let config = ironet::config::AutotuneWasmConfig {
                    require_signature: trust.require_signature,
                    ..ironet::config::AutotuneWasmConfig::default()
                };
                (config, trust)
            };
            let backend = PolicyLoader::new(PolicyEngine::try_new()?)
                .load_from_path(path, &config, &trust, chrono::Utc::now())
                .with_context(|| format!("loading WASM policy {}", path.display()))?;
            let digest = backend
                .identity()
                .digest
                .map(|digest| encode_digest(&digest))
                .unwrap_or_default();
            (
                PolicySlotV1::new(Box::new(backend), None, digest),
                objective.weights(),
            )
        }
        selection => {
            let path = Path::new(selection);
            ensure!(
                path.is_absolute(),
                "policy path must be absolute: {}",
                path.display()
            );
            anyhow::bail!(
                "policy {} is not a .wasm component: external JSON policy artifacts were removed in Phase 6; deploy a signed .wasm component",
                path.display()
            );
        }
    };
    let report = replay_ticks(&samples, slot, weights, objective, mode, seed)?;
    if let Some(golden_path) = golden {
        let expected: TickReplayReportV2 = serde_json::from_str(&read_replay_source(golden_path)?)
            .with_context(|| format!("decoding golden report {}", golden_path.display()))?;
        if expected != report {
            let divergence = report
                .trace
                .iter()
                .zip(&expected.trace)
                .position(|(actual, expected)| actual != expected)
                .map(|index| format!("first diverging sample: {index}"));
            anyhow::bail!(
                "replay diverged from {} ({}; actual trace_digest {}, expected {})",
                golden_path.display(),
                divergence.as_deref().unwrap_or("report header differs"),
                report.trace_digest,
                expected.trace_digest
            );
        }
        println!(
            "golden = match ({} samples, trace_digest {})",
            report.samples, report.trace_digest
        );
    }
    let mut encoded = serde_json::to_vec_pretty(&report)?;
    encoded.push(b'\n');
    write_replay_output(output, &encoded)
}

fn read_replay_source(path: &Path) -> Result<String> {
    if path == Path::new("-") {
        let mut input = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut input)?;
        Ok(input)
    } else {
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
    }
}

fn decode_replay_samples(input: &str, side: &str) -> Result<Vec<ReplayTapSampleV2>> {
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(input) {
        let selected = if let Some(samples) = value.as_array() {
            serde_json::Value::Array(samples.clone())
        } else if let Some(samples) = value.get("samples") {
            samples.clone()
        } else if let Some(samples) = value.get("autotune_tap").and_then(|tap| tap.get(side)) {
            samples.clone()
        } else {
            serde_json::Value::Array(vec![value])
        };
        return serde_json::from_value(selected).context("decoding replay samples");
    }

    input
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_str(line)
                .with_context(|| format!("decoding JSONL replay sample on line {}", index + 1))
        })
        .collect()
}

fn write_replay_output(path: &Path, bytes: &[u8]) -> Result<()> {
    if path == Path::new("-") {
        std::io::stdout().write_all(bytes)?;
    } else {
        std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
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

async fn metrics(socket_path: &Path) -> Result<()> {
    let status = control::status(socket_path).await?;
    print!("{}", ironet::status::render_prometheus(&status));
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
    if let Some(dns) = &status.dns {
        writeln!(
            rendered,
            "dns: domain={} listen={} generation={} nodes={} conflicting_labels={} queries={}",
            single_line(&dns.domain),
            dns.listen_addr,
            dns.catalog_generation,
            dns.nodes,
            dns.conflicting_labels,
            dns.queries,
        )?;
    } else {
        writeln!(rendered, "dns: disabled")?;
    }
    writeln!(
        rendered,
        "mesh: enabled={} directory={} max_peers={}",
        status.mesh.enabled, status.mesh.directory_entries, status.mesh.max_total_peers
    )?;
    writeln!(
        rendered,
        "gateway: transit={} subnet_nat={} advertised_prefixes={}",
        status.gateway.transit_enabled,
        status.gateway.subnet_nat_enabled,
        status.gateway.advertised_prefixes.len()
    )?;
    for prefix in &status.gateway.advertised_prefixes {
        writeln!(rendered, "advertised_prefix: {prefix}")?;
    }
    for node in &status.mesh.nodes {
        writeln!(
            rendered,
            "mesh_node {}: direct={} prefixes={} transit={}",
            single_line(&node.endpoint_id),
            node.direct_addresses.len(),
            node.prefixes.len(),
            node.transit_enabled
        )?;
    }
    for route in status.routes.iter().filter(|route| !route.present) {
        writeln!(rendered, "missing_route: {}", single_line(&route.prefix))?;
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
            }
            Ok(rendered)
        }
    }
}

fn format_peer_human(peer: &PeerStatus) -> String {
    format!(
        "peer {}: endpoint_id={} interface={} protocol={} connected={} path={}:{} rtt={} pmtu={} cwnd={} queue={} tx_records={} tx={} rx_records={} rx={} trains={} cells={} fec_tx_cells={} fec_tx={} fec_rx_cells={} recovered={} repair={}/{} cover={}/{} drops={} errors={}",
        single_line(&peer.name),
        single_line(&peer.endpoint_id),
        single_line(&peer.interface),
        peer.protocol_major,
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
        peer.path_mtu,
        display::bytes(peer.path_cwnd_bytes),
        display::bytes(
            peer.packet_train_queue_bytes
                .saturating_add(peer.latency_queue_bytes)
        ),
        peer.tx_packets,
        display::bytes(peer.tx_bytes),
        peer.rx_packets,
        display::bytes(peer.rx_bytes),
        peer.trains_built,
        peer.cells_built,
        peer.fec_tx_cells,
        display::bytes(peer.fec_tx_bytes),
        peer.fec_rx_cells,
        peer.fec_recovered_cells,
        peer.repair_received_cells,
        peer.repair_requested_cells,
        display::bytes(peer.cover_tx_bytes),
        display::bytes(peer.cover_rx_bytes),
        peer.route_gate_drops
            .saturating_add(peer.tun_admission_drop_records)
            .saturating_add(peer.reassembly_pressure_evictions)
            .saturating_add(peer.pmtu_drop_datagrams),
        peer.connection_errors
            .saturating_add(peer.protocol_datagram_errors)
            .saturating_add(peer.repair_stale_responses),
    )
}

fn human_micros(value: u64) -> String {
    if value == 0 {
        "unknown".into()
    } else {
        display::micros(value)
    }
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
    println!("path_selection = automatic");
    println!("derp_enabled = {}", config.relay.derp_enabled());
    println!("dns_enabled = {}", config.dns.enabled);
    if let Some(domain) = &config.dns.domain {
        println!("dns_domain = {domain}");
    }
    Ok(())
}

async fn doctor(config_path: &Path) -> Result<()> {
    let (config, endpoint_id) = deployment::validate(config_path).await?;
    ironet::v2_runtime::V2RuntimeConfig::from_product_config(&config)
        .context("configuration is not valid for the V2-only dataplane")?;
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
    println!("protocol = 2");
    println!("quic_alpn = h3");
    println!("endpoint_id = {endpoint_id}");
    println!("peers = {}", config.peers.len());
    println!("overlay_table = {}", config.routing.table);
    println!("dns_enabled = {}", config.dns.enabled);
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
    println!("dns_enabled: {}", config.dns.enabled);
    if let Some(domain) = &config.dns.domain {
        println!("dns_domain: {domain}");
        println!("dns_listen_port: {}", config.dns.listen_port);
        println!("accept_dns: {}", config.dns.accept_dns);
    }
    if let Some(max_egress_mbps) = config.routing.max_egress_mbps {
        println!(
            "max_egress: {}",
            display::bits_per_second(max_egress_mbps.saturating_mul(1_000_000))
        );
    }
    println!("protocol: 2");
    println!("quic_alpn: h3");
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
        config::NodeInfo,
        status::{GatewayStatus, MeshStatus, RouteStatus},
        trace::PingSample,
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
        PeerStatus {
            name: "bad\nname".into(),
            endpoint_id: "endpoint".into(),
            interface: "ironet0".into(),
            protocol_major: 2,
            connected: true,
            connection_events: 1,
            tx_packets: 2,
            tx_bytes: 3,
            rx_packets: 4,
            rx_bytes: 5,
            route_gate_drops: 8,
            protocol_datagram_errors: 9,
            ..PeerStatus::default()
        }
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
            "ironet://join/v2/00",
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
            "peers: total=1 connected=1\npeer bad name: endpoint_id=endpoint interface=ironet0 protocol=2 connected=true path=unknown:unknown rtt=unknown pmtu=0 cwnd=0B queue=0B tx_records=2 tx=3B rx_records=4 rx=5B trains=0 cells=0 fec_tx_cells=0 fec_tx=0B fec_rx_cells=0 recovered=0 repair=0/0 cover=0B/0B drops=8 errors=9\n"
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
            gateway: GatewayStatus::default(),
            tun_admission_drop_records: 0,
            tun_admission_drop_bytes: 0,
            dns: None,
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

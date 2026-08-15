use std::{
    collections::{BTreeMap, HashSet},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use iroh::{EndpointId, RelayUrl};
use serde::{Deserialize, Serialize};

use crate::derp::{DerpPublicKey, DerpServer};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub network_id: String,
    pub identity_file: PathBuf,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bind_addresses: Vec<SocketAddr>,
    /// IP prefixes that direct underlay paths must not use. Both the local and
    /// remote address of an IP path are covered.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forbidden_underlay_prefixes: Vec<IpNet>,
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub discovery_enabled: bool,
    /// Local data-plane attachment. `none` turns the process into a pure
    /// userspace transit node and does not require CAP_NET_ADMIN or /dev/net/tun.
    #[serde(default, skip_serializing_if = "is_default")]
    pub attachment: AttachmentMode,
    #[serde(
        default = "default_tun_mtu",
        skip_serializing_if = "is_default_tun_mtu"
    )]
    pub tun_mtu: u16,
    #[serde(
        default = "default_max_frame_size",
        skip_serializing_if = "is_default_max_frame_size"
    )]
    pub max_frame_size: u16,
    #[serde(
        default = "default_node_interface",
        skip_serializing_if = "is_default_node_interface"
    )]
    pub node_interface: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub node_addresses: Vec<IpNet>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub advertised_prefixes: Vec<IpNet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_info: Option<NodeInfo>,
    /// Selection policy for concurrently available IPv4 and IPv6 underlay
    /// paths. The preference is applied only while path quality is comparable.
    #[serde(default, skip_serializing_if = "is_default")]
    pub path_selection: PathSelectionConfig,
    #[serde(default, skip_serializing_if = "is_default")]
    pub relay: RelayConfig,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<PeerConfig>,
    /// Pairwise transport contracts. Locators in this section are local-only
    /// and are never copied into the signed mesh directory.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub links: Vec<LinkConfig>,
    /// Resolved static routes. New configurations keep these in the sibling
    /// routes.toml registry; deserializing this field remains migration-only.
    #[serde(default, skip_serializing)]
    pub route_origins: Vec<RouteOriginConfig>,
    #[serde(default, skip_serializing_if = "is_default")]
    pub routing: RoutingConfig,
    /// Opportunistic peer discovery and bounded direct-mesh policy. Normal
    /// deployments only need the defaults; configured peers remain pinned.
    #[serde(default, skip_serializing_if = "is_default")]
    pub mesh: MeshConfig,
    #[serde(default, skip_serializing_if = "is_default")]
    pub packet_policy: PacketPolicyConfig,
    #[serde(default, skip_serializing_if = "is_default")]
    pub fec: FecConfig,
    #[serde(default, skip_serializing_if = "is_default")]
    pub observability: ObservabilityConfig,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttachmentMode {
    #[default]
    Tun,
    None,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IpFamilyPreference {
    Ipv4,
    #[default]
    Ipv6,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathSelectionConfig {
    /// Preferred direct-path address family when IPv4 and IPv6 have comparable
    /// health, loss and latency.
    #[serde(default, skip_serializing_if = "is_default")]
    pub prefer: IpFamilyPreference,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LinkClass {
    #[default]
    PrivateCircuit,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LinkVisibility {
    #[default]
    Pairwise,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DialRole {
    #[default]
    Auto,
    Active,
    Passive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkConfig {
    /// Stable identifier shared by exactly the two endpoints.
    pub id: String,
    pub name: String,
    pub peer_id: EndpointId,
    #[serde(default)]
    pub class: LinkClass,
    #[serde(default)]
    pub visibility: LinkVisibility,
    #[serde(default)]
    pub dial: DialRole,
    /// Private circuits are exclusive by default: path migration may not
    /// escape to discovery, relay, DERP or peer-observed public addresses.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub exclusive: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub fallback: bool,
    /// Optional local socket delivered by the circuit provider. This is a path
    /// allowlist, not an endpoint-wide bind directive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_bind: Option<SocketAddr>,
    /// Pairwise locators, including RFC1918/RFC4193 delivery and private port
    /// forwards. They are deliberately absent from Presence/NodeRecord.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remote_addresses: Vec<SocketAddr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_local_prefixes: Vec<IpNet>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_remote_prefixes: Vec<IpNet>,
    /// 32-byte hexadecimal pairwise secret used by the V1 session transcript.
    pub auth_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeInfo {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

/// Optional underlay relay transports. DERP is enabled whenever `servers` is
/// non-empty. iroh relay is disabled by default and requires an explicit
/// opt-in so deployments can restrict fallback to DERP, overlay transit and
/// direct UDP.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    /// Permit iroh relay registration and dialing. Direct iroh UDP paths stay
    /// available when this is false.
    #[serde(default, skip_serializing_if = "is_false")]
    pub iroh_relay_enabled: bool,
    /// Explicit iroh relay URLs inherited by peers without `relay_urls`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
    /// Public iroh relay/QAD endpoints used for address discovery even when
    /// normal peer traffic uses DERP or overlay transit.  These endpoints are
    /// also viable encrypted fallback paths, because iroh uses the same relay
    /// map for QAD and relay registration.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub discovery_urls: Vec<String>,
    /// Tailscale DERP transport servers. Each URL is one independent region.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub servers: Vec<String>,
}

impl RelayConfig {
    pub fn derp_enabled(&self) -> bool {
        !self.servers.is_empty()
    }

    pub fn iroh_urls(&self) -> impl Iterator<Item = &str> {
        self.urls
            .iter()
            .chain(&self.discovery_urls)
            .map(String::as_str)
            .filter(|_| self.iroh_relay_enabled)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    pub name: String,
    pub endpoint_id: EndpointId,
    /// Whether this peer may be used as a next hop for prefixes it does not own.
    #[serde(default, skip_serializing_if = "is_false")]
    pub transit_enabled: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub direct_addresses: Vec<SocketAddr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relay_urls: Vec<String>,
    /// X25519 public key used to address this peer on DERP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derp_public_key: Option<DerpPublicKey>,
    /// Overlay source prefixes this adjacency may deliver, including prefixes
    /// legitimately transited by this Peer.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_source_prefixes: Vec<IpNet>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteOriginConfig {
    pub endpoint_id: EndpointId,
    pub prefixes: Vec<IpNet>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingConfig {
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub isolate_overlay: bool,
    /// Permit packets received from one Overlay Peer to be forwarded to
    /// another Overlay Peer. Peer-to-local-node and Peer-to-LAN forwarding is
    /// independent of this setting.
    #[serde(default, skip_serializing_if = "is_false")]
    pub transit_enabled: bool,
    #[serde(
        default = "default_rule_priority",
        skip_serializing_if = "is_default_rule_priority"
    )]
    pub rule_priority: u32,
    /// Dedicated Linux policy-routing table owned by FlowRouter.
    #[serde(
        default = "default_routing_table",
        skip_serializing_if = "is_default_routing_table"
    )]
    pub table: u32,
    #[serde(default, skip_serializing_if = "is_false")]
    pub allow_default_routes: bool,
    /// Source-NAT packets arriving from the overlay before they are forwarded
    /// to a locally advertised LAN/service prefix. This removes the need for
    /// LAN hosts to carry explicit return routes for remote overlay prefixes.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub nat_enabled: bool,
    /// Optional local policy cap for this node's single overlay egress. This
    /// is never advertised to peers and is not a capacity measurement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_egress_mbps: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshConfig {
    /// Exchange signed node presence through authenticated peers and establish
    /// a bounded number of useful direct adjacencies.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub enabled: bool,
    /// Hard limit for configured and automatically selected peer adjacencies
    /// combined. Presence records do not consume an adjacency slot.
    #[serde(
        default = "default_mesh_max_peers",
        skip_serializing_if = "is_default_mesh_max_peers"
    )]
    pub max_peers: usize,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_peers: default_mesh_max_peers(),
        }
    }
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            isolate_overlay: true,
            transit_enabled: false,
            rule_priority: default_rule_priority(),
            table: default_routing_table(),
            allow_default_routes: false,
            nat_enabled: true,
            max_egress_mbps: None,
        }
    }
}

impl RoutingConfig {
    pub fn max_egress_bps(&self) -> Option<u64> {
        self.max_egress_mbps
            .and_then(|value| value.checked_mul(1_000_000))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketPolicyConfig {
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub enforce_overlay_prefixes: bool,
}

impl Default for PacketPolicyConfig {
    fn default() -> Self {
        Self {
            enforce_overlay_prefixes: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FecConfig {
    #[serde(default, skip_serializing_if = "is_false")]
    pub enabled: bool,
    #[serde(
        default = "default_fec_data_shards",
        skip_serializing_if = "is_default_fec_data_shards"
    )]
    pub data_shards: u8,
    #[serde(
        default = "default_fec_recovery_shards",
        skip_serializing_if = "is_default_fec_recovery_shards"
    )]
    pub recovery_shards: u8,
    #[serde(
        default = "default_fec_block_timeout",
        skip_serializing_if = "is_default_fec_block_timeout"
    )]
    pub block_timeout_millis: u64,
    #[serde(
        default = "default_fec_decoder_ttl",
        skip_serializing_if = "is_default_fec_decoder_ttl"
    )]
    pub decoder_ttl_millis: u64,
}

impl Default for FecConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            data_shards: default_fec_data_shards(),
            recovery_shards: default_fec_recovery_shards(),
            block_timeout_millis: default_fec_block_timeout(),
            decoder_ttl_millis: default_fec_decoder_ttl(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservabilityConfig {
    #[serde(
        default = "default_status_file",
        skip_serializing_if = "is_default_status_file"
    )]
    pub status_file: PathBuf,
    #[serde(
        default = "default_metrics_file",
        skip_serializing_if = "is_default_metrics_file"
    )]
    pub metrics_file: PathBuf,
    #[serde(
        default = "default_report_interval",
        skip_serializing_if = "is_default_report_interval"
    )]
    pub report_interval_secs: u64,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            status_file: default_status_file(),
            metrics_file: default_metrics_file(),
            report_interval_secs: default_report_interval(),
        }
    }
}

impl Config {
    /// Returns the first configured node address for the requested address
    /// family. Configuration order is the stable selection rule when a node
    /// has more than one address in the same family.
    pub fn node_address(&self, is_ipv4: bool) -> Option<IpAddr> {
        self.node_addresses
            .iter()
            .map(IpNet::addr)
            .find(|address| address.is_ipv4() == is_ipv4)
    }

    pub async fn load(path: &Path) -> Result<Self> {
        let raw = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("failed to read {}", path.display()))?;
        verify_config_digest(path, raw.as_bytes()).await?;
        let config = Self::decode(path, &raw)?;
        let routes = crate::routes::RouteRegistry::load(&config.route_registry_path()).await?;
        let extension_routes = crate::extensions::ExtensionState::load(
            &crate::extensions::state_path(&config.identity_file),
        )
        .await?
        .route_origins(crate::extensions::now_unix())?;
        Self::resolve_routes(
            config,
            merge_route_origins(routes.routes, extension_routes)?,
        )
    }

    pub async fn load_unsealed(path: &Path) -> Result<Self> {
        let raw = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("failed to read {}", path.display()))?;
        let config = Self::decode(path, &raw)?;
        let routes = crate::routes::RouteRegistry::load(&config.route_registry_path()).await?;
        let extension_routes = crate::extensions::ExtensionState::load(
            &crate::extensions::state_path(&config.identity_file),
        )
        .await?
        .route_origins(crate::extensions::now_unix())?;
        Self::resolve_routes(
            config,
            merge_route_origins(routes.routes, extension_routes)?,
        )
    }

    /// Load a sealed main configuration against an in-memory candidate route
    /// registry. Route CLI mutations use this before replacing routes.toml.
    pub async fn load_with_route_origins(
        path: &Path,
        route_origins: Vec<RouteOriginConfig>,
    ) -> Result<Self> {
        let raw = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("failed to read {}", path.display()))?;
        verify_config_digest(path, raw.as_bytes()).await?;
        let config = Self::decode(path, &raw)?;
        let extension_routes = crate::extensions::ExtensionState::load(
            &crate::extensions::state_path(&config.identity_file),
        )
        .await?
        .route_origins(crate::extensions::now_unix())?;
        Self::resolve_routes(
            config,
            merge_route_origins(route_origins, extension_routes)?,
        )
    }

    /// Resolve the mutable route registry from a sealed main configuration
    /// without requiring the current registry contents to be valid.
    pub async fn route_registry_path_for(path: &Path) -> Result<PathBuf> {
        let raw = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("failed to read {}", path.display()))?;
        verify_config_digest(path, raw.as_bytes()).await?;
        Ok(Self::decode(path, &raw)?.route_registry_path())
    }

    fn decode(path: &Path, raw: &str) -> Result<Self> {
        toml::from_str(raw).with_context(|| format!("failed to parse {}", path.display()))
    }

    fn resolve_routes(mut config: Self, external_routes: Vec<RouteOriginConfig>) -> Result<Self> {
        if !external_routes.is_empty() {
            let mut combined = crate::routes::RouteRegistry {
                version: 1,
                routes: std::mem::take(&mut config.route_origins),
            };
            combined.routes.extend(external_routes);
            combined.normalize()?;
            config.route_origins = combined.routes;
        }
        config.validate()?;
        Ok(config)
    }

    pub fn route_registry_path(&self) -> PathBuf {
        crate::routes::registry_path(&self.identity_file)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.network_id.trim().is_empty(),
            "network_id cannot be empty"
        );
        // 1280 is the IPv6 minimum link MTU. Transit-only nodes do not create
        // an interface, but keep validating the wire frame ceiling below.
        if self.attachment == AttachmentMode::Tun {
            ensure!(self.tun_mtu >= 1280, "tun_mtu must be at least 1280");
            validate_interface_name(&self.node_interface)?;
        }
        ensure!(
            self.max_frame_size >= 256,
            "max_frame_size must be at least 256"
        );
        ensure!(
            (2..=64).contains(&self.fec.data_shards),
            "fec.data_shards must be between 2 and 64"
        );
        ensure!(
            (1..=32).contains(&self.fec.recovery_shards),
            "fec.recovery_shards must be between 1 and 32"
        );
        ensure!(
            self.fec.block_timeout_millis > 0 && self.fec.block_timeout_millis <= 1_000,
            "fec.block_timeout_millis must be between 1 and 1000"
        );
        ensure!(
            self.fec.decoder_ttl_millis >= self.fec.block_timeout_millis
                && self.fec.decoder_ttl_millis <= 60_000,
            "fec.decoder_ttl_millis must be at least block_timeout_millis and at most 60000"
        );
        ensure!(
            (2..32_766).contains(&self.routing.rule_priority),
            "routing.rule_priority must be between 2 and 32765"
        );
        ensure!(
            !matches!(self.routing.table, 0 | 253 | 254 | 255),
            "routing.table must be a non-reserved Linux routing table"
        );
        if let Some(max_egress_mbps) = self.routing.max_egress_mbps {
            ensure!(
                max_egress_mbps > 0,
                "routing.max_egress_mbps must be non-zero"
            );
            ensure!(
                max_egress_mbps.checked_mul(1_000_000).is_some(),
                "routing.max_egress_mbps is too large"
            );
        }
        ensure!(
            (1..=32).contains(&self.mesh.max_peers),
            "mesh.max_peers must be between 1 and 32"
        );
        ensure!(
            !self.mesh.enabled || self.peers.len() <= self.mesh.max_peers,
            "configured peers exceed mesh.max_peers"
        );
        ensure!(
            self.observability.report_interval_secs > 0,
            "observability.report_interval_secs must be greater than zero"
        );
        ensure!(
            self.observability.status_file != self.observability.metrics_file,
            "observability status_file and metrics_file must differ"
        );
        self.validate_bind_addresses()?;
        self.validate_node_info()?;
        self.validate_attachment()?;

        let mut ids = HashSet::new();
        let mut names = HashSet::new();
        let mut direct_addresses = HashSet::new();
        let mut derp_public_keys = HashSet::new();
        for peer in &self.peers {
            ensure!(!peer.name.trim().is_empty(), "peer name cannot be empty");
            ensure!(
                names.insert(&peer.name),
                "duplicate peer name {}",
                peer.name
            );
            ensure!(ids.insert(peer.endpoint_id), "duplicate peer endpoint_id");
            let private_link = self.link_for_peer(peer.endpoint_id).is_some();
            ensure!(
                !private_link
                    || (peer.direct_addresses.is_empty()
                        && peer.relay_urls.is_empty()
                        && peer.derp_public_key.is_none()),
                "peer {} uses a private link and cannot also publish public/relay locators",
                peer.name
            );
            if let Some(key) = peer.derp_public_key {
                ensure!(
                    derp_public_keys.insert(key),
                    "DERP public key {key} is assigned to multiple peers"
                );
            }
            for url in &peer.relay_urls {
                url.parse::<RelayUrl>()
                    .with_context(|| format!("invalid relay URL for peer {}", peer.name))?;
            }
            let mut peer_relay_urls = HashSet::new();
            ensure!(
                peer.relay_urls
                    .iter()
                    .all(|url| peer_relay_urls.insert(url)),
                "peer {} contains duplicate relay_urls",
                peer.name
            );
            for address in &peer.direct_addresses {
                ensure!(address.port() != 0, "peer {} has port zero", peer.name);
                if let Some(prefix) = self.forbidden_underlay_prefix(address.ip()) {
                    bail!(
                        "peer {} direct address {address} is inside forbidden underlay prefix {prefix}",
                        peer.name
                    );
                }
                ensure!(
                    direct_addresses.insert(*address),
                    "direct address {address} is assigned to multiple peers"
                );
            }
            ensure!(
                peer.relay_urls.is_empty() || peer.relay_urls.len() >= 2,
                "peer {} requires at least two relay_urls for redundancy",
                peer.name
            );
        }

        self.validate_links(&ids)?;

        ensure!(
            !self.packet_policy.enforce_overlay_prefixes
                || self.mesh.enabled
                || self.peers.is_empty()
                || !self.route_origins.is_empty(),
            "packet source enforcement requires mesh discovery or at least one imported static route"
        );

        let mut origin_ids = HashSet::new();
        let mut owned_prefixes: Vec<(EndpointId, IpNet)> = Vec::new();
        for origin in &self.route_origins {
            ensure!(
                origin_ids.insert(origin.endpoint_id),
                "duplicate route origin endpoint_id {}",
                origin.endpoint_id
            );
            ensure!(
                !origin.prefixes.is_empty(),
                "route origin {} requires at least one prefix",
                origin.endpoint_id
            );
            for prefix in &origin.prefixes {
                validate_overlay_prefix(*prefix, self.routing.allow_default_routes)?;
                for (owner, existing) in &owned_prefixes {
                    ensure!(
                        *owner == origin.endpoint_id
                            || prefix.prefix_len() == 0
                            || existing.prefix_len() == 0
                            || !prefixes_overlap(*prefix, *existing),
                        "route origin prefix {prefix} overlaps {existing} owned by {owner}"
                    );
                }
                owned_prefixes.push((origin.endpoint_id, *prefix));
            }
        }

        for peer in &self.peers {
            let mut allowed_sources = HashSet::new();
            for prefix in &peer.allowed_source_prefixes {
                ensure!(
                    allowed_sources.insert(*prefix),
                    "peer {} contains duplicate allowed_source_prefixes entry {prefix}",
                    peer.name
                );
                ensure!(
                    owned_prefixes.iter().any(|(_, owned)| owned == prefix),
                    "peer {} allowed source {prefix} is not an exact remote route-origin prefix",
                    peer.name
                );
            }
            ensure!(
                !self.packet_policy.enforce_overlay_prefixes
                    || self.mesh.enabled
                    || !peer.allowed_source_prefixes.is_empty(),
                "peer {} requires mesh discovery or allowed_source_prefixes when packet policy is enabled",
                peer.name
            );
        }

        for prefix in self.all_advertised_prefixes() {
            validate_overlay_prefix(prefix, self.routing.allow_default_routes)?;
            for (owner, remote) in &owned_prefixes {
                ensure!(
                    prefix.prefix_len() == 0
                        || remote.prefix_len() == 0
                        || !prefixes_overlap(prefix, *remote),
                    "local overlay prefix {prefix} overlaps remote prefix {remote} owned by {owner}"
                );
            }
        }

        let has_default_route = self
            .all_overlay_prefixes()
            .any(|prefix| prefix.prefix_len() == 0);
        if has_default_route {
            ensure!(
                self.routing.rule_priority > 1,
                "default routes require routing.rule_priority greater than one"
            );
            ensure!(
                !self.discovery_enabled,
                "default routes require discovery_enabled = false"
            );
            ensure!(
                self.relay.urls.is_empty()
                    && self.relay.discovery_urls.is_empty()
                    && !self.relay.derp_enabled(),
                "default routes require relay.urls, relay.discovery_urls, and relay.servers to be empty"
            );
            ensure!(
                self.peers
                    .iter()
                    .all(|peer| !peer.direct_addresses.is_empty()
                        || self.link_for_peer(peer.endpoint_id).is_some()),
                "default routes require a static public or pairwise locator for every peer"
            );
        }

        for peer in &self.peers {
            for address in &peer.direct_addresses {
                ensure!(
                    !self
                        .all_overlay_prefixes()
                        .filter(|prefix| prefix.prefix_len() != 0)
                        .any(|prefix| prefix.contains(&address.ip())),
                    "peer {} direct address {} overlaps an overlay prefix",
                    peer.name,
                    address.ip()
                );
            }
        }

        self.validate_relay()?;
        Ok(())
    }

    fn validate_bind_addresses(&self) -> Result<()> {
        let mut forbidden_prefixes = HashSet::new();
        for prefix in &self.forbidden_underlay_prefixes {
            ensure!(
                forbidden_prefixes.insert(*prefix),
                "duplicate forbidden_underlay_prefixes entry {prefix}"
            );
        }

        let mut families = HashSet::new();
        for address in &self.bind_addresses {
            let family = if address.is_ipv4() { 4 } else { 6 };
            ensure!(
                families.insert(family),
                "only one bind_addresses entry is allowed per address family"
            );
            if !address.ip().is_unspecified()
                && let Some(prefix) = self.forbidden_underlay_prefix(address.ip())
            {
                bail!("bind address {address} is inside forbidden underlay prefix {prefix}");
            }
        }
        Ok(())
    }

    fn validate_node_info(&self) -> Result<()> {
        let Some(node_info) = &self.node_info else {
            return Ok(());
        };
        ensure!(
            !node_info.name.trim().is_empty(),
            "node_info.name cannot be empty"
        );
        ensure!(
            node_info.metadata.keys().all(|key| !key.trim().is_empty()),
            "node_info metadata keys cannot be empty"
        );
        ensure!(
            toml::to_string(node_info)?.len() <= 800,
            "encoded node_info cannot exceed 800 bytes"
        );
        Ok(())
    }

    fn validate_attachment(&self) -> Result<()> {
        if self.attachment == AttachmentMode::None {
            ensure!(
                self.node_addresses.is_empty() && self.advertised_prefixes.is_empty(),
                "attachment = none cannot own node_addresses or advertised_prefixes"
            );
            ensure!(
                self.routing.transit_enabled,
                "attachment = none requires routing.transit_enabled = true"
            );
        }
        Ok(())
    }

    fn validate_links(&self, peer_ids: &HashSet<EndpointId>) -> Result<()> {
        let mut ids = HashSet::new();
        let mut names = HashSet::new();
        let mut peers = HashSet::new();
        let mut remotes = HashSet::new();
        for link in &self.links {
            ensure!(!link.id.trim().is_empty(), "link id cannot be empty");
            ensure!(link.id.len() <= 128, "link {} id is too long", link.name);
            ensure!(!link.name.trim().is_empty(), "link name cannot be empty");
            ensure!(ids.insert(&link.id), "duplicate link id {}", link.id);
            ensure!(
                names.insert(&link.name),
                "duplicate link name {}",
                link.name
            );
            ensure!(
                peers.insert(link.peer_id),
                "peer {} has more than one link contract",
                link.peer_id
            );
            ensure!(
                peer_ids.contains(&link.peer_id),
                "link {} references an unknown peer",
                link.name
            );
            ensure!(
                link.exclusive,
                "private link {} must be exclusive",
                link.name
            );
            ensure!(
                !link.fallback,
                "private link {} cannot enable public fallback",
                link.name
            );
            ensure!(
                !link.remote_addresses.is_empty(),
                "private link {} requires remote_addresses",
                link.name
            );
            ensure!(
                hex::decode(&link.auth_key).is_ok_and(|key| key.len() == 32),
                "link {} auth_key must be 32-byte hexadecimal",
                link.name
            );
            if let Some(local) = link.local_bind {
                ensure!(
                    local.port() != 0,
                    "link {} local_bind has port zero",
                    link.name
                );
                ensure!(
                    !link.allowed_local_prefixes.is_empty(),
                    "link {} local_bind requires allowed_local_prefixes",
                    link.name
                );
                ensure!(
                    link.allowed_local_prefixes
                        .iter()
                        .any(|prefix| prefix.contains(&local.ip())),
                    "link {} local_bind is outside allowed_local_prefixes",
                    link.name
                );
                ensure!(
                    self.bind_addresses.is_empty()
                        || self.bind_addresses.iter().any(|address| address == &local),
                    "link {} local_bind must match the endpoint bind address when bind_addresses is configured",
                    link.name
                );
            }
            for remote in &link.remote_addresses {
                ensure!(
                    remote.port() != 0,
                    "link {} remote address has port zero",
                    link.name
                );
                ensure!(
                    remotes.insert(*remote),
                    "private remote address {remote} is assigned to multiple links"
                );
                ensure!(
                    !link.allowed_remote_prefixes.is_empty(),
                    "link {} requires allowed_remote_prefixes",
                    link.name
                );
                ensure!(
                    link.allowed_remote_prefixes
                        .iter()
                        .any(|prefix| prefix.contains(&remote.ip())),
                    "link {} remote address {remote} is outside allowed_remote_prefixes",
                    link.name
                );
            }
        }
        Ok(())
    }

    pub fn link_for_peer(&self, peer_id: EndpointId) -> Option<&LinkConfig> {
        self.links.iter().find(|link| link.peer_id == peer_id)
    }

    pub fn private_locator_prefixes(&self) -> impl Iterator<Item = IpNet> + '_ {
        self.links.iter().flat_map(|link| {
            link.allowed_local_prefixes
                .iter()
                .chain(&link.allowed_remote_prefixes)
                .copied()
        })
    }

    pub fn static_underlay_addresses(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.peers
            .iter()
            .flat_map(|peer| peer.direct_addresses.iter().copied())
            .chain(
                self.links
                    .iter()
                    .flat_map(|link| link.remote_addresses.iter().copied()),
            )
    }

    pub fn endpoint_bind_addresses(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.bind_addresses
            .iter()
            .copied()
            .chain(self.links.iter().filter_map(|link| {
                self.bind_addresses
                    .is_empty()
                    .then_some(link.local_bind)
                    .flatten()
            }))
    }

    fn validate_relay(&self) -> Result<()> {
        if !self.relay.iroh_relay_enabled {
            ensure!(
                self.relay.urls.is_empty() && self.relay.discovery_urls.is_empty(),
                "relay.urls and relay.discovery_urls require relay.iroh_relay_enabled = true"
            );
            ensure!(
                self.peers.iter().all(|peer| peer.relay_urls.is_empty()),
                "peer relay_urls require relay.iroh_relay_enabled = true"
            );
        }
        if !self.relay.urls.is_empty() {
            ensure!(
                self.relay.urls.len() >= 2,
                "relay.urls requires at least two URLs for redundancy"
            );
            let mut unique = HashSet::new();
            for url in &self.relay.urls {
                url.parse::<RelayUrl>()
                    .context("invalid relay.urls entry")?;
                ensure!(unique.insert(url), "duplicate relay URL {url}");
            }
        }

        if !self.relay.discovery_urls.is_empty() {
            ensure!(
                self.relay.discovery_urls.len() >= 2,
                "relay.discovery_urls requires at least two URLs to classify NAT mappings"
            );
            let mut unique = self.relay.urls.iter().collect::<HashSet<_>>();
            for url in &self.relay.discovery_urls {
                url.parse::<RelayUrl>()
                    .context("invalid relay.discovery_urls entry")?;
                ensure!(
                    unique.insert(url),
                    "duplicate iroh relay/discovery URL {url}"
                );
            }
        }

        if !self.relay.derp_enabled() {
            return self.ensure_no_derp_peer_keys();
        }

        let mut urls = HashSet::new();
        let mut regions = HashSet::new();
        for value in &self.relay.servers {
            let server = DerpServer::parse(value)
                .with_context(|| format!("invalid DERP server URL {value}"))?;
            ensure!(
                urls.insert(server.url.clone()),
                "duplicate DERP server URL {}",
                server.url
            );
            ensure!(
                regions.insert(server.region_id),
                "DERP region ID collision for {}",
                server.url
            );
        }
        for peer in &self.peers {
            ensure!(
                peer.derp_public_key.is_some(),
                "peer {} requires derp_public_key when relay.servers is configured",
                peer.name
            );
        }
        Ok(())
    }

    fn ensure_no_derp_peer_keys(&self) -> Result<()> {
        for peer in &self.peers {
            ensure!(
                peer.derp_public_key.is_none(),
                "peer {} derp_public_key requires relay.servers",
                peer.name
            );
        }
        Ok(())
    }

    pub fn forbidden_underlay_prefix(&self, address: IpAddr) -> Option<IpNet> {
        self.forbidden_underlay_prefixes
            .iter()
            .copied()
            .find(|prefix| prefix.contains(&address))
    }

    pub fn validate_local_id(&self, local_id: EndpointId) -> Result<()> {
        if self.peers.iter().any(|peer| peer.endpoint_id == local_id) {
            bail!("peer list contains this node's own endpoint ID");
        }
        if self
            .route_origins
            .iter()
            .any(|origin| origin.endpoint_id == local_id)
        {
            bail!("static route registry contains this node's own endpoint ID");
        }
        Ok(())
    }

    pub fn all_advertised_prefixes(&self) -> impl Iterator<Item = IpNet> + '_ {
        self.node_addresses
            .iter()
            .chain(&self.advertised_prefixes)
            .copied()
    }

    pub fn all_remote_prefixes(&self) -> impl Iterator<Item = IpNet> + '_ {
        self.route_origins
            .iter()
            .flat_map(|origin| origin.prefixes.iter().copied())
    }

    pub fn all_overlay_prefixes(&self) -> impl Iterator<Item = IpNet> + '_ {
        self.all_advertised_prefixes()
            .chain(self.all_remote_prefixes())
    }

    /// Whether Linux must forward packets from the FlowRouter TUN to a local
    /// LAN/service interface. Overlay transit itself stays in userspace.
    pub fn requires_forwarding(&self) -> bool {
        !self.advertised_prefixes.is_empty()
    }

    pub fn inherited_peer_relays(&self) -> Result<Vec<RelayUrl>> {
        self.relay
            .iroh_urls()
            .map(|url| url.parse().context("invalid relay.urls entry"))
            .collect()
    }

    pub fn derp_servers(&self) -> Result<Vec<DerpServer>> {
        self.relay
            .servers
            .iter()
            .map(|url| DerpServer::parse(url))
            .collect()
    }

    pub fn derp_identity_file(&self) -> PathBuf {
        let mut path = self.identity_file.as_os_str().to_os_string();
        path.push(".derp");
        PathBuf::from(path)
    }
}

fn merge_route_origins(
    mut first: Vec<RouteOriginConfig>,
    second: Vec<RouteOriginConfig>,
) -> Result<Vec<RouteOriginConfig>> {
    first.extend(second);
    let mut registry = crate::routes::RouteRegistry {
        version: 1,
        routes: first,
    };
    registry.normalize()?;
    Ok(registry.routes)
}

pub fn config_digest_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".blake3");
    PathBuf::from(value)
}

async fn verify_config_digest(path: &Path, raw: &[u8]) -> Result<()> {
    let digest_path = config_digest_path(path);
    let expected = tokio::fs::read_to_string(&digest_path)
        .await
        .with_context(|| {
            format!(
                "missing configuration integrity file {}; run seal-config",
                digest_path.display()
            )
        })?;
    let actual = blake3::hash(raw).to_hex();
    ensure!(
        expected.trim() == actual.as_str(),
        "configuration integrity check failed for {}",
        path.display()
    );
    Ok(())
}

pub fn validate_interface_name(name: &str) -> Result<()> {
    ensure!(!name.is_empty(), "interface name cannot be empty");
    ensure!(
        name.len() <= 15,
        "Linux interface names are limited to 15 bytes"
    );
    ensure!(
        name.bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')),
        "invalid Linux interface name: {name}"
    );
    Ok(())
}

fn default_true() -> bool {
    true
}

fn is_true(value: &bool) -> bool {
    *value
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_default<T: Default + PartialEq>(value: &T) -> bool {
    value == &T::default()
}

fn default_tun_mtu() -> u16 {
    u16::MAX
}

fn is_default_tun_mtu(value: &u16) -> bool {
    *value == default_tun_mtu()
}

fn default_max_frame_size() -> u16 {
    1400
}

fn is_default_max_frame_size(value: &u16) -> bool {
    *value == default_max_frame_size()
}

fn default_node_interface() -> String {
    "ironet0".into()
}

fn is_default_node_interface(value: &str) -> bool {
    value == default_node_interface()
}

fn default_routing_table() -> u32 {
    211
}

fn is_default_routing_table(value: &u32) -> bool {
    *value == default_routing_table()
}

fn default_rule_priority() -> u32 {
    10_000
}

fn is_default_rule_priority(value: &u32) -> bool {
    *value == default_rule_priority()
}

fn default_status_file() -> PathBuf {
    "/run/ironet/status.json".into()
}

fn is_default_status_file(value: &Path) -> bool {
    value == default_status_file()
}

fn default_metrics_file() -> PathBuf {
    "/run/ironet/metrics.prom".into()
}

fn is_default_metrics_file(value: &Path) -> bool {
    value == default_metrics_file()
}

fn default_report_interval() -> u64 {
    10
}

fn is_default_report_interval(value: &u64) -> bool {
    *value == default_report_interval()
}

fn default_mesh_max_peers() -> usize {
    12
}

fn is_default_mesh_max_peers(value: &usize) -> bool {
    *value == default_mesh_max_peers()
}

fn default_fec_data_shards() -> u8 {
    8
}
fn is_default_fec_data_shards(value: &u8) -> bool {
    *value == default_fec_data_shards()
}
fn default_fec_recovery_shards() -> u8 {
    2
}
fn is_default_fec_recovery_shards(value: &u8) -> bool {
    *value == default_fec_recovery_shards()
}
fn default_fec_block_timeout() -> u64 {
    20
}
fn is_default_fec_block_timeout(value: &u64) -> bool {
    *value == default_fec_block_timeout()
}
fn default_fec_decoder_ttl() -> u64 {
    2_000
}
fn is_default_fec_decoder_ttl(value: &u64) -> bool {
    *value == default_fec_decoder_ttl()
}

fn validate_overlay_prefix(prefix: IpNet, allow_default_routes: bool) -> Result<()> {
    ensure!(
        allow_default_routes || prefix.prefix_len() != 0,
        "default overlay route {prefix} requires routing.allow_default_routes = true"
    );
    let address = prefix.addr();
    ensure!(
        !address.is_loopback(),
        "loopback prefix {prefix} is not allowed"
    );
    ensure!(
        !address.is_multicast(),
        "multicast prefix {prefix} is not allowed"
    );
    ensure!(
        !address.is_unspecified() || prefix.prefix_len() == 0,
        "unspecified prefix {prefix} is not allowed"
    );
    if let std::net::IpAddr::V6(address) = address {
        ensure!(
            !address.is_unicast_link_local(),
            "link-local prefix {prefix} is not allowed"
        );
    }
    if let std::net::IpAddr::V4(address) = address {
        ensure!(
            !address.is_link_local(),
            "link-local prefix {prefix} is not allowed"
        );
    }
    Ok(())
}

fn prefixes_overlap(left: IpNet, right: IpNet) -> bool {
    left.addr().is_ipv4() == right.addr().is_ipv4()
        && (left.contains(&right.network()) || right.contains(&left.network()))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use iroh::SecretKey;

    use super::*;

    #[test]
    fn transit_node_info_does_not_require_an_attachment_address() {
        let config = Config {
            network_id: "example".into(),
            identity_file: "identity.key".into(),
            bind_addresses: Vec::new(),
            forbidden_underlay_prefixes: Vec::new(),
            discovery_enabled: true,
            attachment: AttachmentMode::Tun,
            tun_mtu: 1280,
            max_frame_size: 1400,
            node_interface: "ironet0".into(),
            node_addresses: Vec::new(),
            advertised_prefixes: Vec::new(),
            node_info: Some(NodeInfo {
                name: "branch-a".into(),
                description: None,
                metadata: BTreeMap::new(),
            }),
            path_selection: PathSelectionConfig::default(),
            relay: RelayConfig::default(),
            peers: Vec::new(),
            links: Vec::new(),
            route_origins: Vec::new(),
            routing: RoutingConfig::default(),
            mesh: MeshConfig::default(),
            packet_policy: PacketPolicyConfig::default(),
            fec: FecConfig::default(),
            observability: ObservabilityConfig::default(),
        };

        config.validate().unwrap();
    }

    #[test]
    fn node_address_uses_the_first_address_in_each_family() {
        let mut config: Config = toml::from_str(include_str!("../config/example.toml")).unwrap();
        config.node_addresses = vec![
            "21.0.0.9/32".parse().unwrap(),
            "21::9/128".parse().unwrap(),
            "21.0.0.1/32".parse().unwrap(),
            "21::1/128".parse().unwrap(),
        ];

        assert_eq!(config.node_address(true), Some("21.0.0.9".parse().unwrap()));
        assert_eq!(config.node_address(false), Some("21::9".parse().unwrap()));
    }

    #[test]
    fn example_configuration_is_valid() {
        let config: Config = toml::from_str(include_str!("../config/example.toml")).unwrap();
        config.validate().unwrap();
        assert_eq!(config.relay, RelayConfig::default());
        assert_eq!(config.path_selection.prefer, IpFamilyPreference::Ipv6);
        assert!(!config.routing.transit_enabled);
    }

    #[test]
    fn underlay_address_family_preference_is_user_selectable() {
        #[derive(Deserialize)]
        struct Wrapper {
            #[serde(default)]
            path_selection: PathSelectionConfig,
        }

        let defaults: Wrapper = toml::from_str("").unwrap();
        assert_eq!(defaults.path_selection.prefer, IpFamilyPreference::Ipv6);
        let ipv4: Wrapper = toml::from_str("[path_selection]\nprefer = \"ipv4\"").unwrap();
        assert_eq!(ipv4.path_selection.prefer, IpFamilyPreference::Ipv4);
    }

    #[test]
    fn default_sections_and_resolved_routes_are_omitted_when_serializing() {
        let remote = SecretKey::from_bytes(&[31; 32]).public();
        let mut config: Config = toml::from_str(include_str!("../config/example.toml")).unwrap();
        config.node_info = None;
        config.route_origins = vec![RouteOriginConfig {
            endpoint_id: remote,
            prefixes: vec!["10.31.0.0/16".parse().unwrap()],
        }];
        let encoded = toml::to_string_pretty(&config).unwrap();
        assert!(!encoded.contains("route_origins"));
        assert!(!encoded.contains("[routing]"));
        assert!(!encoded.contains("[mesh]"));
        assert!(!encoded.contains("[packet_policy]"));
        assert!(!encoded.contains("[fec]"));
        assert!(!encoded.contains("[observability]"));
    }

    #[tokio::test]
    async fn sealed_config_loads_state_route_registry() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        let mut source: Config = toml::from_str(include_str!("../config/example.toml")).unwrap();
        source.identity_file = dir.path().join("state/identity.key");
        let contents = toml::to_string_pretty(&source).unwrap().into_bytes();
        std::fs::write(&config_path, &contents).unwrap();
        std::fs::write(
            config_digest_path(&config_path),
            format!("{}\n", blake3::hash(&contents).to_hex()),
        )
        .unwrap();
        let remote = SecretKey::from_bytes(&[32; 32]).public();
        crate::routes::RouteRegistry {
            version: 1,
            routes: vec![RouteOriginConfig {
                endpoint_id: remote,
                prefixes: vec!["10.32.0.0/16".parse().unwrap()],
            }],
        }
        .write(&source.route_registry_path())
        .unwrap();

        let config = Config::load(&config_path).await.unwrap();
        assert_eq!(config.route_origins.len(), 1);
        assert_eq!(
            config.all_remote_prefixes().collect::<Vec<_>>(),
            vec!["10.32.0.0/16".parse().unwrap()]
        );
    }

    #[test]
    fn omitted_relay_disables_derp_and_iroh_relays() {
        #[derive(Deserialize)]
        struct Wrapper {
            #[serde(default)]
            relay: RelayConfig,
        }

        let wrapper: Wrapper = toml::from_str("").unwrap();
        assert!(!wrapper.relay.iroh_relay_enabled);
        assert!(wrapper.relay.urls.is_empty());
        assert!(wrapper.relay.discovery_urls.is_empty());
        assert!(wrapper.relay.servers.is_empty());
    }

    #[test]
    fn qad_discovery_requires_two_unique_observation_urls() {
        let mut config: Config = toml::from_str(include_str!("../config/example.toml")).unwrap();
        config.relay.iroh_relay_enabled = true;
        config.relay.discovery_urls = vec!["https://qad-a.example.com".into()];
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("at least two URLs")
        );
        config
            .relay
            .discovery_urls
            .push("https://qad-b.example.com".into());
        config.validate().unwrap();
        assert_eq!(config.inherited_peer_relays().unwrap().len(), 2);
        config.relay.urls = vec![
            "https://relay-a.example.com".into(),
            "https://relay-b.example.com".into(),
        ];
        config.relay.discovery_urls[0] = "https://relay-a.example.com".into();
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("duplicate iroh relay/discovery URL")
        );
    }

    #[test]
    fn optional_local_egress_cap_is_validated() {
        let mut config: Config = toml::from_str(include_str!("../config/example.toml")).unwrap();
        assert_eq!(config.routing.max_egress_bps(), None);
        config.routing.max_egress_mbps = Some(80);
        assert_eq!(config.routing.max_egress_bps(), Some(80_000_000));
        config.routing.max_egress_mbps = Some(0);
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("routing.max_egress_mbps")
        );
    }

    #[test]
    fn mesh_peer_limit_is_a_hard_validated_bound() {
        let mut config: Config = toml::from_str(include_str!("../config/example.toml")).unwrap();
        config.mesh.max_peers = 0;
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("between 1 and 32")
        );
        config.mesh.max_peers = 33;
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("between 1 and 32")
        );

        config.mesh.max_peers = 1;
        let peer = SecretKey::from_bytes(&[12; 32]).public();
        config.peers = vec![
            PeerConfig {
                name: "one".into(),
                endpoint_id: peer,
                transit_enabled: false,
                direct_addresses: Vec::new(),
                relay_urls: Vec::new(),
                derp_public_key: None,
                allowed_source_prefixes: Vec::new(),
            },
            PeerConfig {
                name: "two".into(),
                endpoint_id: SecretKey::from_bytes(&[13; 32]).public(),
                transit_enabled: false,
                direct_addresses: Vec::new(),
                relay_urls: Vec::new(),
                derp_public_key: None,
                allowed_source_prefixes: Vec::new(),
            },
        ];
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("configured peers exceed mesh.max_peers")
        );
    }

    #[test]
    fn transit_is_disabled_when_omitted() {
        let routing: RoutingConfig = toml::from_str(
            "isolate_overlay = true\nrule_priority = 10000\nallow_default_routes = false\n",
        )
        .unwrap();
        assert!(!routing.transit_enabled);
        assert!(routing.nat_enabled);
    }

    #[test]
    fn advertised_prefix_nat_can_be_disabled_explicitly() {
        let routing: RoutingConfig = toml::from_str("nat_enabled = false\n").unwrap();
        assert!(!routing.nat_enabled);
    }

    #[test]
    fn kernel_forwarding_is_required_only_for_local_lan_routes() {
        let mut config: Config = toml::from_str(include_str!("../config/example.toml")).unwrap();
        assert!(config.requires_forwarding());

        config.advertised_prefixes.clear();
        assert!(!config.requires_forwarding());

        config.routing.transit_enabled = true;
        assert!(!config.requires_forwarding());
    }

    #[test]
    fn attachment_none_is_a_transit_only_configuration() {
        let mut config: Config = toml::from_str(include_str!("../config/example.toml")).unwrap();
        config.attachment = AttachmentMode::None;
        config.node_addresses.clear();
        config.advertised_prefixes.clear();
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("requires routing.transit_enabled")
        );
        config.routing.transit_enabled = true;
        config.validate().unwrap();
    }

    #[test]
    fn pairwise_link_rejects_public_fallback_and_accepts_private_locator() {
        let mut config: Config = toml::from_str(include_str!("../config/example.toml")).unwrap();
        config.node_info = None;
        let endpoint_id = SecretKey::from_bytes(&[41; 32]).public();
        config.peers.push(PeerConfig {
            name: "private-b".into(),
            endpoint_id,
            transit_enabled: true,
            direct_addresses: Vec::new(),
            relay_urls: Vec::new(),
            derp_public_key: None,
            allowed_source_prefixes: Vec::new(),
        });
        config.links.push(LinkConfig {
            id: "iepl-ab".into(),
            name: "iepl-ab".into(),
            peer_id: endpoint_id,
            class: LinkClass::PrivateCircuit,
            visibility: LinkVisibility::Pairwise,
            dial: DialRole::Active,
            exclusive: true,
            fallback: false,
            local_bind: Some("10.255.0.1:4000".parse().unwrap()),
            remote_addresses: vec!["10.255.0.2:4000".parse().unwrap()],
            allowed_local_prefixes: vec!["10.255.0.1/32".parse().unwrap()],
            allowed_remote_prefixes: vec!["10.255.0.2/32".parse().unwrap()],
            auth_key: "11".repeat(32),
        });
        config.validate().unwrap();

        config.peers[0].direct_addresses = vec!["203.0.113.20:4000".parse().unwrap()];
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("cannot also publish")
        );
    }

    #[test]
    fn derp_servers_enable_transport_and_require_peer_keys() {
        let mut config: Config = toml::from_str(include_str!("../config/example.toml")).unwrap();
        config.relay = RelayConfig {
            iroh_relay_enabled: false,
            urls: Vec::new(),
            discovery_urls: Vec::new(),
            servers: vec![
                "https://derp-a.example.com".into(),
                "https://derp-b.example.com/derp".into(),
            ],
        };
        let peer = PeerConfig {
            name: "peer".into(),
            endpoint_id: SecretKey::from_bytes(&[21; 32]).public(),
            transit_enabled: false,
            direct_addresses: Vec::new(),
            relay_urls: Vec::new(),
            derp_public_key: Some(DerpPublicKey::from_bytes([22; 32])),
            allowed_source_prefixes: vec!["10.200.0.2/32".parse().unwrap()],
        };
        config.peers = vec![peer.clone()];
        config.route_origins = vec![RouteOriginConfig {
            endpoint_id: peer.endpoint_id,
            prefixes: vec!["10.200.0.2/32".parse().unwrap()],
        }];
        config.validate().unwrap();
        assert!(config.relay.derp_enabled());
        let regions = config.derp_servers().unwrap();
        assert_eq!(regions.len(), 2);
        assert_ne!(regions[0].region_id, regions[1].region_id);
        config.peers[0].derp_public_key = None;
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("requires derp_public_key")
        );
    }

    #[test]
    fn derp_and_iroh_relays_can_be_configured_together() {
        let mut config: Config = toml::from_str(include_str!("../config/example.toml")).unwrap();
        let peer = PeerConfig {
            name: "peer".into(),
            endpoint_id: SecretKey::from_bytes(&[23; 32]).public(),
            transit_enabled: false,
            direct_addresses: Vec::new(),
            relay_urls: vec![
                "https://peer-relay-a.example.com".into(),
                "https://peer-relay-b.example.com".into(),
            ],
            derp_public_key: Some(DerpPublicKey::from_bytes([24; 32])),
            allowed_source_prefixes: vec!["10.201.0.2/32".parse().unwrap()],
        };
        config.relay = RelayConfig {
            iroh_relay_enabled: true,
            urls: vec![
                "https://relay-a.example.com".into(),
                "https://relay-b.example.com".into(),
            ],
            discovery_urls: Vec::new(),
            servers: vec!["https://derp.example.com".into()],
        };
        config.peers = vec![peer.clone()];
        config.route_origins = vec![RouteOriginConfig {
            endpoint_id: peer.endpoint_id,
            prefixes: vec!["10.201.0.2/32".parse().unwrap()],
        }];

        config.validate().unwrap();
        assert_eq!(config.inherited_peer_relays().unwrap().len(), 2);
    }

    #[test]
    fn iroh_relay_requires_explicit_opt_in() {
        let mut config: Config = toml::from_str(include_str!("../config/example.toml")).unwrap();
        config.relay.urls = vec![
            "https://relay-a.example.com".into(),
            "https://relay-b.example.com".into(),
        ];
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("iroh_relay_enabled")
        );
    }

    #[test]
    fn relay_mode_is_not_a_supported_configuration_field() {
        let error = toml::from_str::<RelayConfig>("mode = \"derp\"").unwrap_err();
        assert!(error.to_string().contains("unknown field `mode`"));
    }

    #[test]
    fn fec_configuration_rejects_unsafe_bounds() {
        let mut config: Config = toml::from_str(include_str!("../config/example.toml")).unwrap();
        config.fec.data_shards = 1;
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("data_shards")
        );
        config.fec.data_shards = 8;
        config.fec.recovery_shards = 0;
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("recovery_shards")
        );
        config.fec.recovery_shards = 2;
        config.fec.decoder_ttl_millis = config.fec.block_timeout_millis - 1;
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("decoder_ttl_millis")
        );
    }

    #[test]
    fn default_route_requires_explicit_enablement() {
        let mut config: Config = toml::from_str(include_str!("../config/example.toml")).unwrap();
        config.advertised_prefixes = vec!["0.0.0.0/0".parse().unwrap()];
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("allow_default_routes")
        );
    }

    #[test]
    fn forbidden_underlay_prefix_rejects_bind_and_peer_addresses() {
        let mut config: Config = toml::from_str(include_str!("../config/example.toml")).unwrap();
        config.forbidden_underlay_prefixes = vec!["200::/7".parse().unwrap()];
        config.bind_addresses = vec!["[200:1234::1]:4000".parse().unwrap()];
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("bind address")
        );

        config.bind_addresses.clear();
        config.packet_policy.enforce_overlay_prefixes = false;
        config.peers.push(PeerConfig {
            name: "ygg-peer".into(),
            endpoint_id: SecretKey::from_bytes(&[9; 32]).public(),
            transit_enabled: false,
            direct_addresses: vec!["[201:2345::1]:4000".parse().unwrap()],
            relay_urls: Vec::new(),
            derp_public_key: None,
            allowed_source_prefixes: Vec::new(),
        });
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("ygg-peer direct address"));
        assert!(error.contains("200::/7"));
    }

    #[test]
    fn forbidden_underlay_prefix_matches_both_address_families() {
        let mut config: Config = toml::from_str(include_str!("../config/example.toml")).unwrap();
        config.forbidden_underlay_prefixes =
            vec!["100.64.0.0/10".parse().unwrap(), "200::/7".parse().unwrap()];
        assert_eq!(
            config.forbidden_underlay_prefix("100.96.0.1".parse().unwrap()),
            Some("100.64.0.0/10".parse().unwrap())
        );
        assert_eq!(
            config.forbidden_underlay_prefix("203:abcd::1".parse().unwrap()),
            Some("200::/7".parse().unwrap())
        );
        assert_eq!(
            config.forbidden_underlay_prefix("203.0.113.1".parse().unwrap()),
            None
        );
    }

    #[test]
    fn packet_policy_requires_per_adjacency_sources() {
        let peer = PeerConfig {
            name: "peer".into(),
            endpoint_id: SecretKey::from_bytes(&[8; 32]).public(),
            transit_enabled: false,
            direct_addresses: Vec::new(),
            relay_urls: Vec::new(),
            derp_public_key: None,
            allowed_source_prefixes: Vec::new(),
        };
        let mut config: Config = toml::from_str(include_str!("../config/example.toml")).unwrap();
        config.mesh.enabled = false;
        config.peers = vec![peer.clone()];
        config.route_origins = vec![RouteOriginConfig {
            endpoint_id: peer.endpoint_id,
            prefixes: vec!["10.201.0.1/32".parse().unwrap()],
        }];
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("allowed_source_prefixes")
        );
        config.peers[0].allowed_source_prefixes = vec!["10.202.0.1/32".parse().unwrap()];
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("not an exact remote route-origin prefix")
        );
    }

    #[test]
    fn remote_prefix_ownership_cannot_overlap() {
        let first = SecretKey::from_bytes(&[3; 32]).public();
        let second = SecretKey::from_bytes(&[4; 32]).public();
        let mut config: Config = toml::from_str(include_str!("../config/example.toml")).unwrap();
        config.route_origins = vec![
            RouteOriginConfig {
                endpoint_id: first,
                prefixes: vec!["10.20.0.0/16".parse().unwrap()],
            },
            RouteOriginConfig {
                endpoint_id: second,
                prefixes: vec!["10.20.1.0/24".parse().unwrap()],
            },
        ];
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("overlaps")
        );
    }

    #[tokio::test]
    async fn detects_configuration_tampering() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut config: Config = toml::from_str(include_str!("../config/example.toml")).unwrap();
        config.identity_file = dir.path().join("state/identity.key");
        let contents = toml::to_string_pretty(&config).unwrap().into_bytes();
        std::fs::write(&path, &contents).unwrap();
        std::fs::write(
            config_digest_path(&path),
            format!("{}\n", blake3::hash(&contents).to_hex()),
        )
        .unwrap();
        Config::load(&path).await.unwrap();
        std::fs::write(&path, [contents.as_slice(), b"\n# changed\n"].concat()).unwrap();
        assert!(
            Config::load(&path)
                .await
                .unwrap_err()
                .to_string()
                .contains("integrity check failed")
        );
    }
}

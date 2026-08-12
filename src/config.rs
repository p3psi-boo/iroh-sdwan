use std::{
    collections::{BTreeMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
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
    #[serde(default = "default_true")]
    pub discovery_enabled: bool,
    #[serde(default = "default_tun_mtu")]
    pub tun_mtu: u16,
    #[serde(default = "default_max_frame_size")]
    pub max_frame_size: u16,
    #[serde(default = "default_node_interface")]
    pub node_interface: String,
    #[serde(default)]
    pub node_addresses: Vec<IpNet>,
    #[serde(default)]
    pub advertised_prefixes: Vec<IpNet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_info: Option<NodeInfo>,
    #[serde(default)]
    pub relay: RelayConfig,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<PeerConfig>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub route_origins: Vec<RouteOriginConfig>,
    #[serde(default)]
    pub routing: RoutingConfig,
    /// Opportunistic peer discovery and bounded direct-mesh policy. Normal
    /// deployments only need the defaults; configured peers remain pinned.
    #[serde(default)]
    pub mesh: MeshConfig,
    #[serde(default)]
    pub packet_policy: PacketPolicyConfig,
    #[serde(default)]
    pub fec: FecConfig,
    #[serde(default)]
    pub observability: ObservabilityConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeInfo {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<Ipv6Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
pub enum RelayConfig {
    #[default]
    Default,
    Disabled,
    Custom {
        urls: Vec<String>,
    },
    /// Tailscale DERP transport. Each URL is one independent relay region.
    Derp {
        servers: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerConfig {
    pub name: String,
    pub endpoint_id: EndpointId,
    /// Whether this peer may be used as a next hop for prefixes it does not own.
    #[serde(default)]
    pub transit_enabled: bool,
    #[serde(default)]
    pub direct_addresses: Vec<SocketAddr>,
    #[serde(default)]
    pub relay_urls: Vec<String>,
    /// X25519 public key used to address this peer on DERP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derp_public_key: Option<DerpPublicKey>,
    /// Overlay source prefixes this adjacency may deliver, including prefixes
    /// legitimately transited by this Peer.
    #[serde(default)]
    pub allowed_source_prefixes: Vec<IpNet>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteOriginConfig {
    pub endpoint_id: EndpointId,
    pub prefixes: Vec<IpNet>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingConfig {
    #[serde(default = "default_true")]
    pub isolate_overlay: bool,
    /// Permit packets received from one Overlay Peer to be forwarded to
    /// another Overlay Peer. Peer-to-local-node and Peer-to-LAN forwarding is
    /// independent of this setting.
    #[serde(default)]
    pub transit_enabled: bool,
    #[serde(default = "default_rule_priority")]
    pub rule_priority: u32,
    /// Dedicated Linux policy-routing table owned by FlowRouter.
    #[serde(default = "default_routing_table")]
    pub table: u32,
    #[serde(default)]
    pub allow_default_routes: bool,
    /// Optional local policy cap for this node's single overlay egress. This
    /// is never advertised to peers and is not a capacity measurement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_egress_mbps: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeshConfig {
    /// Exchange signed node presence through authenticated peers and establish
    /// a bounded number of useful direct adjacencies.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Hard limit for configured and automatically selected peer adjacencies
    /// combined. Presence records do not consume an adjacency slot.
    #[serde(default = "default_mesh_max_peers")]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketPolicyConfig {
    #[serde(default = "default_true")]
    pub enforce_overlay_prefixes: bool,
}

impl Default for PacketPolicyConfig {
    fn default() -> Self {
        Self {
            enforce_overlay_prefixes: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FecConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_fec_data_shards")]
    pub data_shards: u8,
    #[serde(default = "default_fec_recovery_shards")]
    pub recovery_shards: u8,
    #[serde(default = "default_fec_block_timeout")]
    pub block_timeout_millis: u64,
    #[serde(default = "default_fec_decoder_ttl")]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservabilityConfig {
    #[serde(default = "default_status_file")]
    pub status_file: PathBuf,
    #[serde(default = "default_metrics_file")]
    pub metrics_file: PathBuf,
    #[serde(default = "default_report_interval")]
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
    pub async fn load(path: &Path) -> Result<Self> {
        let raw = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("failed to read {}", path.display()))?;
        verify_config_digest(path, raw.as_bytes()).await?;
        Self::parse(path, &raw)
    }

    pub async fn load_unsealed(path: &Path) -> Result<Self> {
        let raw = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("failed to read {}", path.display()))?;
        Self::parse(path, &raw)
    }

    fn parse(path: &Path, raw: &str) -> Result<Self> {
        let config: Self =
            toml::from_str(raw).with_context(|| format!("failed to parse {}", path.display()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.network_id.trim().is_empty(),
            "network_id cannot be empty"
        );
        // 1280 is the IPv6 minimum link MTU.
        ensure!(self.tun_mtu >= 1280, "tun_mtu must be at least 1280");
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
        validate_interface_name(&self.node_interface)?;
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

        ensure!(
            !self.packet_policy.enforce_overlay_prefixes
                || self.mesh.enabled
                || self.peers.is_empty()
                || !self.route_origins.is_empty(),
            "packet source enforcement requires mesh discovery or at least one [[route_origins]] entry"
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
                matches!(self.relay, RelayConfig::Disabled),
                "default routes require relay mode disabled"
            );
            ensure!(
                self.peers
                    .iter()
                    .all(|peer| !peer.direct_addresses.is_empty()),
                "default routes require static direct_addresses for every peer"
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
            node_info.ipv4.is_some() || node_info.ipv6.is_some(),
            "node_info requires ipv4 and/or ipv6"
        );
        let addresses = [
            node_info.ipv4.map(IpAddr::V4),
            node_info.ipv6.map(IpAddr::V6),
        ];
        for address in addresses.into_iter().flatten() {
            ensure!(
                self.node_addresses
                    .iter()
                    .any(|configured| configured.addr() == address),
                "node_info address {address} must also be present in node_addresses"
            );
        }
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

    fn validate_relay(&self) -> Result<()> {
        match &self.relay {
            RelayConfig::Custom { urls } => {
                ensure!(
                    urls.len() >= 2,
                    "custom relay mode requires at least two URLs for redundancy"
                );
                let mut unique = HashSet::new();
                for url in urls {
                    url.parse::<RelayUrl>()
                        .context("invalid custom relay URL")?;
                    ensure!(unique.insert(url), "duplicate custom relay URL {url}");
                }
                self.ensure_no_derp_peer_keys()
            }
            RelayConfig::Derp { servers } => {
                ensure!(
                    !servers.is_empty(),
                    "DERP relay mode requires at least one server"
                );
                let mut urls = HashSet::new();
                let mut regions = HashSet::new();
                for value in servers {
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
                        "peer {} requires derp_public_key in DERP relay mode",
                        peer.name
                    );
                    ensure!(
                        peer.relay_urls.is_empty(),
                        "peer {} relay_urls cannot be combined with DERP relay mode",
                        peer.name
                    );
                }
                Ok(())
            }
            RelayConfig::Default | RelayConfig::Disabled => self.ensure_no_derp_peer_keys(),
        }
    }

    fn ensure_no_derp_peer_keys(&self) -> Result<()> {
        for peer in &self.peers {
            ensure!(
                peer.derp_public_key.is_none(),
                "peer {} derp_public_key requires DERP relay mode",
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
            bail!("route_origins contains this node's own endpoint ID");
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
        match &self.relay {
            RelayConfig::Custom { urls } => urls
                .iter()
                .map(|url| url.parse().context("invalid custom relay URL"))
                .collect(),
            _ => Ok(Vec::new()),
        }
    }

    pub fn derp_servers(&self) -> Result<Vec<DerpServer>> {
        match &self.relay {
            RelayConfig::Derp { servers } => {
                servers.iter().map(|url| DerpServer::parse(url)).collect()
            }
            _ => Ok(Vec::new()),
        }
    }

    pub fn derp_identity_file(&self) -> PathBuf {
        let mut path = self.identity_file.as_os_str().to_os_string();
        path.push(".derp");
        PathBuf::from(path)
    }
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

fn default_tun_mtu() -> u16 {
    u16::MAX
}

fn default_max_frame_size() -> u16 {
    1400
}

fn default_node_interface() -> String {
    "isw0".into()
}

fn default_routing_table() -> u32 {
    100
}

fn default_rule_priority() -> u32 {
    10_000
}

fn default_status_file() -> PathBuf {
    "/run/iroh-sdwan/status.json".into()
}

fn default_metrics_file() -> PathBuf {
    "/run/iroh-sdwan/metrics.prom".into()
}

fn default_report_interval() -> u64 {
    10
}

fn default_mesh_max_peers() -> usize {
    12
}

fn default_fec_data_shards() -> u8 {
    8
}
fn default_fec_recovery_shards() -> u8 {
    2
}
fn default_fec_block_timeout() -> u64 {
    20
}
fn default_fec_decoder_ttl() -> u64 {
    2_000
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
    fn trace_addresses_must_be_configured_node_addresses() {
        let config = Config {
            network_id: "example".into(),
            identity_file: "identity.key".into(),
            bind_addresses: Vec::new(),
            forbidden_underlay_prefixes: Vec::new(),
            discovery_enabled: true,
            tun_mtu: 1280,
            max_frame_size: 1400,
            node_interface: "isw0".into(),
            node_addresses: vec!["10.200.0.1/32".parse().unwrap()],
            advertised_prefixes: Vec::new(),
            node_info: Some(NodeInfo {
                name: "branch-a".into(),
                ipv4: Some("10.200.0.2".parse().unwrap()),
                ipv6: None,
                description: None,
                metadata: BTreeMap::new(),
            }),
            relay: RelayConfig::Disabled,
            peers: Vec::new(),
            route_origins: Vec::new(),
            routing: RoutingConfig::default(),
            mesh: MeshConfig::default(),
            packet_policy: PacketPolicyConfig::default(),
            fec: FecConfig::default(),
            observability: ObservabilityConfig::default(),
        };

        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("must also be present in node_addresses")
        );
    }

    #[test]
    fn example_configuration_is_valid() {
        let config: Config = toml::from_str(include_str!("../config/example.toml")).unwrap();
        config.validate().unwrap();
        assert!(!config.routing.transit_enabled);
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
    fn derp_mode_derives_regions_and_requires_peer_keys() {
        let mut config: Config = toml::from_str(include_str!("../config/example.toml")).unwrap();
        config.relay = RelayConfig::Derp {
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
        let contents = include_bytes!("../config/example.toml");
        std::fs::write(&path, contents).unwrap();
        std::fs::write(
            config_digest_path(&path),
            format!("{}\n", blake3::hash(contents).to_hex()),
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

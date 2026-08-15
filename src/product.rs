use std::{
    collections::{BTreeMap, HashSet},
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use iroh::{EndpointId, SecretKey, Signature};
use serde::{Deserialize, Serialize};

use crate::{
    config::{
        AttachmentMode, Config, FecConfig, NodeInfo, ObservabilityConfig, PacketPolicyConfig,
        PeerConfig, RelayConfig, RoutingConfig, config_digest_path,
    },
    deployment,
    derp::DerpPublicKey,
    identity,
    routes::RouteRegistry,
};

pub const PRODUCT_STATE_VERSION: u8 = 1;
pub const INVITE_VERSION: u8 = 1;
pub const DEFAULT_ADDRESS_POOL: &str = "100.64.0.0/10";
/// Compatibility pool used when reading product state or V1 invites created
/// before Overlay IPv6 was represented explicitly.
pub const DEFAULT_IPV6_ADDRESS_POOL: &str = "fd42:6972:6f68::/64";
const PRODUCT_STATE_FILE: &str = "network.toml";
const AUTHORITY_KEY_FILE: &str = "network-authority.key";
const DEFAULT_INVITE_LIFETIME_SECS: u64 = 3_600;

fn default_ipv6_address_pool() -> Ipv6Net {
    DEFAULT_IPV6_ADDRESS_POOL
        .parse()
        .expect("default Overlay IPv6 pool is valid")
}

fn is_default_ipv6_address_pool(pool: &Ipv6Net) -> bool {
    *pool == default_ipv6_address_pool()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductState {
    pub version: u8,
    pub network_name: String,
    pub network_uid: String,
    pub node_name: String,
    pub authority: EndpointId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_key_file: Option<PathBuf>,
    pub address_pool: Ipv4Net,
    pub local_address: IpNet,
    #[serde(default = "default_ipv6_address_pool")]
    pub ipv6_address_pool: Ipv6Net,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_ipv6_address: Option<IpNet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub join_invite_id: Option<String>,
    pub created_unix_secs: u64,
    #[serde(default)]
    pub invites: Vec<InviteRecord>,
    #[serde(default)]
    pub removed_nodes: Vec<RemovedNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemovedNode {
    pub name: String,
    pub endpoint_id: EndpointId,
    pub removed_unix_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteRecord {
    pub id: String,
    pub created_unix_secs: u64,
    pub expires_unix_secs: u64,
    #[serde(default)]
    pub revoked: bool,
    /// One-way digest of the bearer token. This permits local revocation checks without storing
    /// the reusable invite itself.
    #[serde(default)]
    pub token_hash: String,
    pub member_endpoint_id: EndpointId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvitePayload {
    pub version: u8,
    pub id: String,
    pub network_name: String,
    pub network_uid: String,
    /// Existing V1 data planes use this high-entropy value as their admission secret.
    /// It only appears inside the signed, secret invite token.
    pub network_secret: String,
    pub authority: EndpointId,
    pub address_pool: Ipv4Net,
    #[serde(
        default = "default_ipv6_address_pool",
        skip_serializing_if = "is_default_ipv6_address_pool"
    )]
    pub ipv6_address_pool: Ipv6Net,
    pub issued_unix_secs: u64,
    pub expires_unix_secs: u64,
    pub capabilities: Vec<String>,
    pub member_endpoint_id: EndpointId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_secret: Option<String>,
    pub bootstrap: InviteBootstrap,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteBootstrap {
    pub name: String,
    pub endpoint_id: EndpointId,
    #[serde(default)]
    pub direct_addresses: Vec<SocketAddr>,
    #[serde(default)]
    pub relay_urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derp_public_key: Option<DerpPublicKey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedInvite {
    payload: InvitePayload,
    signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetworkSummary {
    pub network: String,
    pub network_id: String,
    pub node: String,
    pub endpoint_id: String,
    pub address: String,
    pub addresses: Vec<String>,
    pub config: String,
    pub state: String,
    pub created: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct InviteSummary {
    pub id: String,
    pub token: String,
    pub expires_unix_secs: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct NodeSummary {
    pub name: String,
    pub endpoint_id: String,
    pub local: bool,
    pub removed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapabilityChange {
    pub capability: String,
    pub value: String,
    pub changed: bool,
    pub applied: bool,
}

#[derive(Debug, Clone, Default)]
pub struct CreateNetworkOptions {
    pub node_name: Option<String>,
    pub address_pool: Option<Ipv4Net>,
    pub ipv6_address_pool: Option<Ipv6Net>,
    pub derp_servers: Vec<String>,
    pub bind_addresses: Vec<SocketAddr>,
    pub reuse_identity: bool,
}

pub fn state_path(state_dir: &Path) -> PathBuf {
    state_dir.join(PRODUCT_STATE_FILE)
}

pub fn authority_key_path(state_dir: &Path) -> PathBuf {
    state_dir.join(AUTHORITY_KEY_FILE)
}

pub fn default_node_name() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| fs::read_to_string("/etc/hostname").ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "ironet-node".into())
}

pub fn load_state(state_dir: &Path) -> Result<ProductState> {
    let path = state_path(state_dir);
    let raw = fs::read_to_string(&path).with_context(|| {
        format!(
            "this machine has not joined an ironet network ({})",
            path.display()
        )
    })?;
    let state: ProductState = toml::from_str(&raw)
        .with_context(|| format!("failed to parse product state {}", path.display()))?;
    ensure!(
        state.version == PRODUCT_STATE_VERSION,
        "unsupported product state version {}",
        state.version
    );
    Ok(state)
}

pub fn save_state(state_dir: &Path, state: &ProductState) -> Result<()> {
    ensure_private_dir(state_dir)?;
    let encoded = toml::to_string_pretty(state)?;
    deployment::atomic_write(&state_path(state_dir), encoded.as_bytes(), 0o600)
}

pub async fn create_network(
    config_path: &Path,
    state_dir: &Path,
    network_name: &str,
    options: CreateNetworkOptions,
) -> Result<NetworkSummary> {
    let CreateNetworkOptions {
        node_name,
        address_pool,
        ipv6_address_pool,
        derp_servers,
        bind_addresses,
        reuse_identity,
    } = options;
    validate_display_name(network_name, "network name")?;
    if state_path(state_dir).exists() && config_path.exists() {
        let existing = load_state(state_dir)?;
        ensure!(
            existing.network_name == network_name,
            "this machine already belongs to network {}",
            existing.network_name
        );
        ensure!(
            existing.authority_key_file.is_some(),
            "this machine joined network {} and is not its creator",
            existing.network_name
        );
        if let Some(node_name) = &node_name {
            ensure!(
                existing.node_name == *node_name,
                "network already exists with node name {}; omit --node-name or use `ironet node rename`",
                existing.node_name
            );
        }
        if let Some(address_pool) = address_pool {
            ensure!(
                existing.address_pool == address_pool,
                "network already uses address pool {}",
                existing.address_pool
            );
        }
        if let Some(ipv6_address_pool) = ipv6_address_pool {
            ensure!(
                existing.ipv6_address_pool == ipv6_address_pool,
                "network already uses IPv6 address pool {}",
                existing.ipv6_address_pool
            );
        }
        return show_network(config_path, state_dir).await;
    }
    let node_name = node_name.unwrap_or_else(default_node_name);
    validate_display_name(&node_name, "node name")?;
    let identity_file = state_dir.join("identity.key");
    let route_file = state_dir.join("routes.toml");
    let product_file = state_path(state_dir);
    let authority_file = authority_key_path(state_dir);
    preflight_new_paths(&[
        config_path,
        &config_digest_path(config_path),
        &route_file,
        &product_file,
        &authority_file,
    ])?;
    if reuse_identity {
        ensure!(
            identity_file.exists(),
            "--reuse-identity requires {}",
            identity_file.display()
        );
    } else {
        preflight_new_paths(&[&identity_file])?;
    }

    let node_key = if reuse_identity {
        identity::load(&identity_file)?
    } else {
        SecretKey::generate()
    };
    let authority_key = SecretKey::generate();
    let pool = match address_pool {
        Some(pool) => {
            validate_address_pool(pool)?;
            ensure_local_pool_available(pool)?;
            pool
        }
        None => select_address_pool(authority_key.public())?,
    };
    let ipv6_pool = match ipv6_address_pool {
        Some(pool) => {
            validate_ipv6_address_pool(pool)?;
            ensure_local_ipv6_pool_available(pool)?;
            pool
        }
        None => select_ipv6_address_pool(authority_key.public())?,
    };
    let network_secret = hex::encode(SecretKey::generate().to_bytes());
    let network_uid = short_network_uid(authority_key.public());
    let address = allocate_address(pool, node_key.public());
    let ipv6_address = allocate_ipv6_address(ipv6_pool, node_key.public());
    let now = now_unix()?;
    let config = base_config(
        network_secret,
        identity_file.clone(),
        node_name.clone(),
        vec![address, ipv6_address],
        derp_servers,
        bind_addresses,
        Vec::new(),
    );
    config.validate()?;
    config.validate_local_id(node_key.public())?;
    let state = ProductState {
        version: PRODUCT_STATE_VERSION,
        network_name: network_name.into(),
        network_uid: network_uid.clone(),
        node_name: node_name.clone(),
        authority: authority_key.public(),
        authority_key_file: Some(authority_file.clone()),
        address_pool: pool,
        local_address: address,
        ipv6_address_pool: ipv6_pool,
        local_ipv6_address: Some(ipv6_address),
        join_invite_id: None,
        created_unix_secs: now,
        invites: Vec::new(),
        removed_nodes: Vec::new(),
    };

    write_bundle(
        config_path,
        state_dir,
        &config,
        &state,
        &node_key,
        !reuse_identity,
        Some((&authority_file, &authority_key)),
    )
    .await?;

    Ok(NetworkSummary {
        network: network_name.into(),
        network_id: network_uid,
        node: node_name,
        endpoint_id: node_key.public().to_string(),
        address: address.to_string(),
        addresses: vec![address.to_string(), ipv6_address.to_string()],
        config: config_path.display().to_string(),
        state: product_file.display().to_string(),
        created: true,
    })
}

pub fn create_invite(
    config_path: &Path,
    state_dir: &Path,
    expires_in_secs: Option<u64>,
    direct_addresses: Vec<SocketAddr>,
    member_endpoint_id: Option<EndpointId>,
) -> Result<InviteSummary> {
    let config = load_sealed_sync(config_path)?;
    config.validate()?;
    let mut state = load_state(state_dir)?;
    let authority_file = state
        .authority_key_file
        .as_deref()
        .context("this node cannot issue invites; no network authority key is installed")?;
    let authority = identity::load(authority_file)?;
    ensure!(
        authority.public() == state.authority,
        "network authority key does not match state"
    );
    let node_key = identity::load(&config.identity_file)?;
    config.validate_local_id(node_key.public())?;
    let now = now_unix()?;
    let lifetime = expires_in_secs.unwrap_or(DEFAULT_INVITE_LIFETIME_SECS);
    ensure!(lifetime > 0, "invite lifetime must be greater than zero");
    let expires = now
        .checked_add(lifetime)
        .context("invite expiry overflow")?;
    let id = hex::encode(&SecretKey::generate().to_bytes()[..12]);
    let generated_member = member_endpoint_id.is_none().then(SecretKey::generate);
    let member_endpoint_id = member_endpoint_id
        .or_else(|| generated_member.as_ref().map(SecretKey::public))
        .expect("member identity is generated or supplied");
    let derp_public_key = if config.relay.derp_enabled() && config.derp_identity_file().exists() {
        Some(crate::derp::identity::load(&config.derp_identity_file())?.public_key())
    } else {
        None
    };
    let payload = InvitePayload {
        version: INVITE_VERSION,
        id: id.clone(),
        network_name: state.network_name.clone(),
        network_uid: state.network_uid.clone(),
        network_secret: config.network_id.clone(),
        authority: state.authority,
        address_pool: state.address_pool,
        ipv6_address_pool: state.ipv6_address_pool,
        issued_unix_secs: now,
        expires_unix_secs: expires,
        capabilities: vec!["join".into()],
        member_endpoint_id,
        member_secret: generated_member
            .as_ref()
            .map(|key| hex::encode(key.to_bytes())),
        bootstrap: InviteBootstrap {
            name: state.node_name.clone(),
            endpoint_id: node_key.public(),
            direct_addresses,
            relay_urls: config.relay.iroh_urls().map(str::to_owned).collect(),
            derp_public_key,
        },
    };
    let bytes = serde_json::to_vec(&payload)?;
    let signature = authority.sign(&bytes).to_bytes().to_vec();
    let envelope = SignedInvite { payload, signature };
    let token = format!(
        "ironet://join/v1/{}",
        hex::encode(serde_json::to_vec(&envelope)?)
    );
    state.invites.push(InviteRecord {
        id: id.clone(),
        created_unix_secs: now,
        expires_unix_secs: expires,
        revoked: false,
        token_hash: blake3::hash(token.as_bytes()).to_hex().to_string(),
        member_endpoint_id,
    });
    save_state(state_dir, &state)?;
    Ok(InviteSummary {
        id,
        token,
        expires_unix_secs: expires,
    })
}

pub fn list_invites(state_dir: &Path) -> Result<Vec<InviteRecord>> {
    let mut invites = load_state(state_dir)?.invites;
    invites.sort_by_key(|invite| (invite.revoked, invite.expires_unix_secs, invite.id.clone()));
    Ok(invites)
}

pub fn revoke_invite(state_dir: &Path, id: &str) -> Result<bool> {
    let mut state = load_state(state_dir)?;
    let invite = state
        .invites
        .iter_mut()
        .find(|invite| invite.id == id)
        .with_context(|| format!("unknown invite {id}"))?;
    let changed = !invite.revoked;
    invite.revoked = true;
    save_state(state_dir, &state)?;
    Ok(changed)
}

pub async fn join_network(
    config_path: &Path,
    state_dir: &Path,
    token: &str,
    node_name: Option<String>,
    reuse_identity: bool,
) -> Result<NetworkSummary> {
    let payload = decode_invite(token)?;
    if state_path(state_dir).exists() && config_path.exists() {
        let existing = load_state(state_dir)?;
        ensure!(
            existing.network_uid == payload.network_uid,
            "this machine already belongs to network {}",
            existing.network_name
        );
        if let Some(node_name) = &node_name {
            ensure!(
                existing.node_name == *node_name,
                "network already exists with node name {}; omit --node-name or use `ironet node rename`",
                existing.node_name
            );
        }
        return show_network(config_path, state_dir).await;
    }
    let now = now_unix()?;
    ensure!(payload.expires_unix_secs >= now, "invite has expired");
    let node_name = node_name.unwrap_or_else(default_node_name);
    validate_display_name(&node_name, "node name")?;
    validate_address_pool(payload.address_pool)?;
    validate_ipv6_address_pool(payload.ipv6_address_pool)?;
    ensure_local_pool_available(payload.address_pool).with_context(|| {
        format!(
            "invite address pool {} conflicts with this machine; recreate the network with a different --address-pool",
            payload.address_pool
        )
    })?;
    ensure_local_ipv6_pool_available(payload.ipv6_address_pool).with_context(|| {
        format!(
            "invite IPv6 address pool {} conflicts with this machine; recreate the network with a different --ipv6-address-pool",
            payload.ipv6_address_pool
        )
    })?;

    let identity_file = state_dir.join("identity.key");
    let route_file = state_dir.join("routes.toml");
    let product_file = state_path(state_dir);
    preflight_new_paths(&[
        config_path,
        &config_digest_path(config_path),
        &route_file,
        &product_file,
    ])?;
    if reuse_identity {
        ensure!(
            identity_file.exists(),
            "--reuse-identity requires {}",
            identity_file.display()
        );
    } else {
        preflight_new_paths(&[&identity_file])?;
    }
    let node_key = if reuse_identity {
        identity::load(&identity_file)?
    } else {
        payload
            .member_secret
            .as_deref()
            .context("invite is bound to an existing node identity; use --reuse-identity")?
            .parse::<SecretKey>()
            .context("invite contains an invalid member identity")?
    };
    ensure!(
        node_key.public() == payload.member_endpoint_id,
        "invite is bound to member identity {}; local identity is {}",
        payload.member_endpoint_id,
        node_key.public()
    );
    let address = allocate_address(payload.address_pool, node_key.public());
    let ipv6_address = allocate_ipv6_address(payload.ipv6_address_pool, node_key.public());
    let peer = PeerConfig {
        name: payload.bootstrap.name.clone(),
        endpoint_id: payload.bootstrap.endpoint_id,
        transit_enabled: false,
        direct_addresses: payload.bootstrap.direct_addresses.clone(),
        relay_urls: payload.bootstrap.relay_urls.clone(),
        derp_public_key: payload.bootstrap.derp_public_key,
        allowed_source_prefixes: Vec::new(),
    };
    let config = base_config(
        payload.network_secret,
        identity_file,
        node_name.clone(),
        vec![address, ipv6_address],
        Vec::new(),
        Vec::new(),
        vec![peer],
    );
    config.validate()?;
    config.validate_local_id(node_key.public())?;
    let state = ProductState {
        version: PRODUCT_STATE_VERSION,
        network_name: payload.network_name.clone(),
        network_uid: payload.network_uid.clone(),
        node_name: node_name.clone(),
        authority: payload.authority,
        authority_key_file: None,
        address_pool: payload.address_pool,
        local_address: address,
        ipv6_address_pool: payload.ipv6_address_pool,
        local_ipv6_address: Some(ipv6_address),
        join_invite_id: Some(payload.id.clone()),
        created_unix_secs: now,
        invites: Vec::new(),
        removed_nodes: Vec::new(),
    };
    write_bundle(
        config_path,
        state_dir,
        &config,
        &state,
        &node_key,
        !reuse_identity,
        None,
    )
    .await?;
    Ok(NetworkSummary {
        network: payload.network_name,
        network_id: payload.network_uid,
        node: node_name,
        endpoint_id: node_key.public().to_string(),
        address: address.to_string(),
        addresses: vec![address.to_string(), ipv6_address.to_string()],
        config: config_path.display().to_string(),
        state: product_file.display().to_string(),
        created: false,
    })
}

pub fn decode_invite(token: &str) -> Result<InvitePayload> {
    let encoded = token
        .trim()
        .strip_prefix("ironet://join/v1/")
        .context("invalid invite; expected ironet://join/v1/…")?;
    let raw = hex::decode(encoded).context("invite payload is not valid encoding")?;
    let signed: SignedInvite = serde_json::from_slice(&raw).context("invalid invite payload")?;
    ensure!(
        signed.payload.version == INVITE_VERSION,
        "unsupported invite version"
    );
    ensure!(
        signed
            .payload
            .capabilities
            .iter()
            .any(|capability| capability == "join"),
        "invite does not grant the join capability"
    );
    ensure!(
        signed.payload.authority.to_string() == signed.payload.network_uid,
        "invite network identity does not match its authority"
    );
    let signature_bytes: [u8; 64] = signed
        .signature
        .as_slice()
        .try_into()
        .context("invalid invite signature length")?;
    let signature = Signature::from_bytes(&signature_bytes);
    let bytes = serde_json::to_vec(&signed.payload)?;
    signed
        .payload
        .authority
        .verify(&bytes, &signature)
        .context("invite signature is invalid")?;
    Ok(signed.payload)
}

pub async fn show_network(config_path: &Path, state_dir: &Path) -> Result<NetworkSummary> {
    let state = load_state(state_dir)?;
    let config = Config::load(config_path).await?;
    let key = identity::load(&config.identity_file)?;
    Ok(NetworkSummary {
        network: state.network_name,
        network_id: state.network_uid,
        node: state.node_name,
        endpoint_id: key.public().to_string(),
        address: state.local_address.to_string(),
        addresses: config
            .node_addresses
            .iter()
            .map(ToString::to_string)
            .collect(),
        config: config_path.display().to_string(),
        state: state_path(state_dir).display().to_string(),
        created: state.authority_key_file.is_some(),
    })
}

pub async fn list_nodes(config_path: &Path, state_dir: &Path) -> Result<Vec<NodeSummary>> {
    let state = load_state(state_dir)?;
    let config = Config::load(config_path).await?;
    let key = identity::load(&config.identity_file)?;
    let mut nodes = vec![NodeSummary {
        name: state.node_name.clone(),
        endpoint_id: key.public().to_string(),
        local: true,
        removed: false,
    }];
    nodes.extend(config.peers.iter().map(|peer| {
        NodeSummary {
            name: peer.name.clone(),
            endpoint_id: peer.endpoint_id.to_string(),
            local: false,
            removed: state
                .removed_nodes
                .iter()
                .any(|removed| removed.endpoint_id == peer.endpoint_id),
        }
    }));
    for removed in &state.removed_nodes {
        if !nodes
            .iter()
            .any(|node| node.endpoint_id == removed.endpoint_id.to_string())
        {
            nodes.push(NodeSummary {
                name: removed.name.clone(),
                endpoint_id: removed.endpoint_id.to_string(),
                local: false,
                removed: true,
            });
        }
    }
    nodes.sort_by_key(|node| (!node.local, node.name.clone(), node.endpoint_id.clone()));
    Ok(nodes)
}

pub async fn rename_local_node(config_path: &Path, state_dir: &Path, name: &str) -> Result<bool> {
    validate_display_name(name, "node name")?;
    let mut state = load_state(state_dir)?;
    let changed = state.node_name != name;
    if !changed {
        return Ok(false);
    }
    update_config(config_path, |config| {
        let mut node_info = config.node_info.take().unwrap_or(NodeInfo {
            name: name.into(),
            description: None,
            metadata: BTreeMap::new(),
        });
        node_info.name = name.into();
        config.node_info = Some(node_info);
        Ok(())
    })
    .await?;
    state.node_name = name.into();
    save_state(state_dir, &state)?;
    Ok(true)
}

pub async fn remove_node(
    config_path: &Path,
    state_dir: &Path,
    selector: &str,
) -> Result<(String, bool)> {
    let mut state = load_state(state_dir)?;
    let config = Config::load(config_path).await?;
    if let Some(removed) = state
        .removed_nodes
        .iter()
        .find(|removed| removed.name == selector || removed.endpoint_id.to_string() == selector)
    {
        return Ok((removed.name.clone(), false));
    }
    let peer = config
        .peers
        .iter()
        .find(|peer| peer.name == selector || peer.endpoint_id.to_string() == selector)
        .cloned()
        .with_context(|| format!("unknown configured node {selector}"))?;
    let endpoint = peer.endpoint_id;
    update_config(config_path, |config| {
        config
            .peers
            .retain(|candidate| candidate.endpoint_id != endpoint);
        Ok(())
    })
    .await?;
    let changed = !state
        .removed_nodes
        .iter()
        .any(|removed| removed.endpoint_id == endpoint);
    if changed {
        state.removed_nodes.push(RemovedNode {
            name: peer.name.clone(),
            endpoint_id: endpoint,
            removed_unix_secs: now_unix()?,
        });
        save_state(state_dir, &state)?;
    }
    Ok((peer.name, changed))
}

pub async fn remove_node_endpoint(
    config_path: &Path,
    state_dir: &Path,
    endpoint: EndpointId,
    display_name: &str,
) -> Result<(String, bool)> {
    let mut state = load_state(state_dir)?;
    let config = Config::load(config_path).await?;
    let local = identity::load(&config.identity_file)?.public();
    ensure!(
        endpoint != local,
        "use `ironet network leave --yes` to remove this machine"
    );
    update_config(config_path, |config| {
        config
            .peers
            .retain(|candidate| candidate.endpoint_id != endpoint);
        Ok(())
    })
    .await?;
    let changed = !state
        .removed_nodes
        .iter()
        .any(|removed| removed.endpoint_id == endpoint);
    if changed {
        state.removed_nodes.push(RemovedNode {
            name: display_name.to_owned(),
            endpoint_id: endpoint,
            removed_unix_secs: now_unix()?,
        });
        save_state(state_dir, &state)?;
    }
    Ok((display_name.to_owned(), changed))
}

pub fn node_is_removed(identity_file: &Path, endpoint: EndpointId) -> bool {
    removed_node_ids(identity_file).contains(&endpoint)
}

pub fn removed_node_ids(identity_file: &Path) -> HashSet<EndpointId> {
    let Some(state_dir) = identity_file.parent() else {
        return HashSet::new();
    };
    load_state(state_dir)
        .map(|state| {
            state
                .removed_nodes
                .iter()
                .map(|removed| removed.endpoint_id)
                .collect()
        })
        .unwrap_or_default()
}

pub fn local_invite_id(identity_file: &Path) -> Option<String> {
    let state_dir = identity_file.parent()?;
    load_state(state_dir).ok()?.join_invite_id
}

pub fn authority_invites(identity_file: &Path) -> Option<BTreeMap<String, (EndpointId, bool)>> {
    let state_dir = identity_file.parent()?;
    let state = load_state(state_dir).ok()?;
    state.authority_key_file.as_ref()?;
    Some(
        state
            .invites
            .into_iter()
            .map(|invite| (invite.id, (invite.member_endpoint_id, invite.revoked)))
            .collect(),
    )
}

pub async fn publish_subnet(config_path: &Path, prefix: IpNet) -> Result<CapabilityChange> {
    let mut changed = false;
    update_config(config_path, |config| {
        if !config.advertised_prefixes.contains(&prefix) {
            config.advertised_prefixes.push(prefix);
            changed = true;
        }
        config.routing.nat_enabled = true;
        Ok(())
    })
    .await?;
    Ok(CapabilityChange {
        capability: "subnet".into(),
        value: prefix.to_string(),
        changed,
        applied: false,
    })
}

pub async fn unpublish_subnet(config_path: &Path, prefix: IpNet) -> Result<CapabilityChange> {
    let mut changed = false;
    update_config(config_path, |config| {
        let before = config.advertised_prefixes.len();
        config
            .advertised_prefixes
            .retain(|candidate| *candidate != prefix);
        changed = before != config.advertised_prefixes.len();
        Ok(())
    })
    .await?;
    Ok(CapabilityChange {
        capability: "subnet".into(),
        value: prefix.to_string(),
        changed,
        applied: false,
    })
}

pub async fn list_subnets(config_path: &Path) -> Result<Vec<IpNet>> {
    let mut values = Config::load(config_path).await?.advertised_prefixes;
    values.sort_by_key(ToString::to_string);
    Ok(values)
}

pub async fn set_transit(config_path: &Path, enabled: bool) -> Result<CapabilityChange> {
    let mut changed = false;
    update_config(config_path, |config| {
        changed = config.routing.transit_enabled != enabled;
        config.routing.transit_enabled = enabled;
        Ok(())
    })
    .await?;
    Ok(CapabilityChange {
        capability: "transit".into(),
        value: enabled.to_string(),
        changed,
        applied: false,
    })
}

pub fn leave_network(
    config_path: &Path,
    state_dir: &Path,
    keep_identity: bool,
) -> Result<Vec<PathBuf>> {
    if !state_path(state_dir).exists() {
        return Ok(Vec::new());
    }
    let state = load_state(state_dir)?;
    let config = load_sealed_sync(config_path)?;
    let mut paths = vec![
        config_path.to_path_buf(),
        config_digest_path(config_path),
        config.route_registry_path(),
        state_path(state_dir),
    ];
    if let Some(authority) = state.authority_key_file {
        paths.push(authority);
    }
    if !keep_identity {
        paths.push(config.derp_identity_file());
        paths.push(config.identity_file);
    }
    let mut removed = Vec::new();
    for path in paths {
        match fs::remove_file(&path) {
            Ok(()) => removed.push(path),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("failed removing {}", path.display()));
            }
        }
    }
    Ok(removed)
}

fn base_config(
    network_secret: String,
    identity_file: PathBuf,
    node_name: String,
    addresses: Vec<IpNet>,
    derp_servers: Vec<String>,
    bind_addresses: Vec<SocketAddr>,
    peers: Vec<PeerConfig>,
) -> Config {
    let iroh_relay_enabled = peers.iter().any(|peer| !peer.relay_urls.is_empty());
    Config {
        network_id: network_secret,
        identity_file,
        bind_addresses,
        forbidden_underlay_prefixes: Vec::new(),
        discovery_enabled: true,
        attachment: AttachmentMode::Tun,
        tun_mtu: u16::MAX,
        max_frame_size: 1400,
        udp_segmentation_offload: false,
        node_interface: "ironet0".into(),
        node_addresses: addresses,
        advertised_prefixes: Vec::new(),
        node_info: Some(NodeInfo {
            name: node_name,
            description: None,
            metadata: BTreeMap::new(),
        }),
        path_selection: Default::default(),
        relay: RelayConfig {
            iroh_relay_enabled,
            urls: Vec::new(),
            discovery_urls: Vec::new(),
            servers: derp_servers,
        },
        peers,
        links: Vec::new(),
        route_origins: Vec::new(),
        routing: RoutingConfig::default(),
        mesh: Default::default(),
        packet_policy: PacketPolicyConfig::default(),
        fec: FecConfig::default(),
        observability: ObservabilityConfig::default(),
    }
}

async fn write_bundle(
    config_path: &Path,
    state_dir: &Path,
    config: &Config,
    state: &ProductState,
    node_key: &SecretKey,
    write_node_key: bool,
    authority: Option<(&Path, &SecretKey)>,
) -> Result<()> {
    ensure_private_dir(state_dir)?;
    let identity_file = config.identity_file.clone();
    let route_file = config.route_registry_path();
    let mut created = Vec::<PathBuf>::new();
    let result: Result<()> = async {
        if write_node_key {
            write_secret(&identity_file, node_key)?;
            created.push(identity_file.clone());
        }
        if let Some((path, key)) = authority {
            write_secret(path, key)?;
            created.push(path.to_path_buf());
        }
        let encoded = toml::to_string_pretty(config)?;
        deployment::atomic_write(config_path, encoded.as_bytes(), 0o600)?;
        created.push(config_path.to_path_buf());
        RouteRegistry::default().write(&route_file)?;
        created.push(route_file.clone());
        deployment::seal(config_path).await?;
        created.push(config_digest_path(config_path));
        save_state(state_dir, state)?;
        created.push(state_path(state_dir));
        Ok(())
    }
    .await;
    if let Err(error) = result {
        for path in created.into_iter().rev() {
            let _ = fs::remove_file(path);
        }
        return Err(error.context("network setup was rolled back"));
    }
    Ok(())
}

async fn update_config(
    config_path: &Path,
    mutate: impl FnOnce(&mut Config) -> Result<()>,
) -> Result<()> {
    let mut config = Config::load(config_path).await?;
    mutate(&mut config)?;
    config.validate()?;
    let key = identity::load(&config.identity_file)?;
    config.validate_local_id(key.public())?;
    let previous = fs::read(config_path)
        .with_context(|| format!("failed reading {}", config_path.display()))?;
    let encoded = toml::to_string_pretty(&config)?;
    if let Err(error) = (|| -> Result<()> {
        deployment::atomic_write(config_path, encoded.as_bytes(), 0o600)?;
        Ok(())
    })() {
        let _ = deployment::atomic_write(config_path, &previous, 0o600);
        return Err(error);
    }
    if let Err(error) = deployment::seal(config_path).await {
        deployment::atomic_write(config_path, &previous, 0o600)?;
        deployment::seal(config_path).await?;
        return Err(error.context("configuration update was rolled back"));
    }
    Ok(())
}

fn load_sealed_sync(path: &Path) -> Result<Config> {
    let raw =
        fs::read_to_string(path).with_context(|| format!("failed reading {}", path.display()))?;
    let expected = fs::read_to_string(config_digest_path(path)).with_context(|| {
        format!(
            "missing configuration integrity file for {}",
            path.display()
        )
    })?;
    ensure!(
        expected.trim() == blake3::hash(raw.as_bytes()).to_hex().as_str(),
        "configuration integrity check failed for {}",
        path.display()
    );
    toml::from_str(&raw).with_context(|| format!("failed parsing {}", path.display()))
}

fn write_secret(path: &Path, key: &SecretKey) -> Result<()> {
    deployment::atomic_write(
        path,
        format!("{}\n", hex::encode(key.to_bytes())).as_bytes(),
        0o600,
    )
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("failed creating {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("failed securing {}", path.display()))
}

fn preflight_new_paths(paths: &[&Path]) -> Result<()> {
    for path in paths {
        ensure!(
            !path.exists(),
            "network state already exists at {}",
            path.display()
        );
    }
    Ok(())
}

fn validate_display_name(value: &str, kind: &str) -> Result<()> {
    let value = value.trim();
    ensure!(!value.is_empty(), "{kind} cannot be empty");
    ensure!(value.len() <= 63, "{kind} cannot exceed 63 bytes");
    ensure!(
        value
            .chars()
            .all(|character| character.is_ascii_alphanumeric()
                || matches!(character, '-' | '_' | '.')),
        "{kind} may only contain letters, digits, '.', '_' and '-'"
    );
    Ok(())
}

fn validate_address_pool(pool: Ipv4Net) -> Result<()> {
    ensure!(
        pool.prefix_len() <= 24,
        "address pool must provide at least 256 addresses"
    );
    ensure!(pool.prefix_len() >= 8, "address pool is too broad");
    Ok(())
}

fn validate_ipv6_address_pool(pool: Ipv6Net) -> Result<()> {
    ensure!(
        pool.prefix_len() <= 120,
        "IPv6 address pool must provide at least 256 addresses"
    );
    ensure!(
        pool.prefix_len() >= 48,
        "IPv6 address pool is too broad; use a /48 to /120 ULA prefix"
    );
    let ula: Ipv6Net = "fc00::/7".parse().expect("valid ULA prefix");
    ensure!(
        ula.contains(&pool.network()),
        "IPv6 address pool must use the ULA range fc00::/7"
    );
    Ok(())
}

fn select_address_pool(seed: EndpointId) -> Result<Ipv4Net> {
    let routes = local_ipv4_routes();
    let start = usize::from(blake3::hash(seed.as_bytes()).as_bytes()[0]);
    // Prefer a collision-free /16 from CGNAT space, then RFC1918 space. Searching small
    // pools avoids rejecting all of 100.64/10 merely because another VPN uses one slice.
    let candidates = (0..64)
        .map(|offset| 64 + ((start + offset) % 64) as u8)
        .map(|second| Ipv4Net::new(Ipv4Addr::new(100, second, 0, 0), 16).expect("valid pool"))
        .chain((0..16).map(|offset| {
            Ipv4Net::new(
                Ipv4Addr::new(172, 16 + ((start + offset) % 16) as u8, 0, 0),
                16,
            )
            .expect("valid pool")
        }))
        .chain((0..256).map(|offset| {
            Ipv4Net::new(Ipv4Addr::new(10, ((start + offset) % 256) as u8, 0, 0), 16)
                .expect("valid pool")
        }));
    candidates
        .into_iter()
        .find(|candidate| {
            !routes
                .iter()
                .any(|route| ipv4_nets_overlap(*candidate, *route))
        })
        .context("no collision-free automatic IPv4 address pool is available; pass --address-pool")
}

fn select_ipv6_address_pool(seed: EndpointId) -> Result<Ipv6Net> {
    let routes = local_ipv6_routes();
    (0_u16..=u16::MAX)
        .map(|subnet| {
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"ironet-auto-ipv6-pool-v1\0");
            hasher.update(seed.as_bytes());
            hasher.update(&subnet.to_be_bytes());
            let hash = hasher.finalize();
            let bytes = hash.as_bytes();
            let address = Ipv6Addr::from([
                0xfd, bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], 0, 0,
                0, 0, 0, 0, 0, 0,
            ]);
            Ipv6Net::new(address, 64).expect("valid automatic IPv6 pool")
        })
        .find(|candidate| {
            !routes
                .iter()
                .any(|route| ipv6_nets_overlap(*candidate, *route))
        })
        .context(
            "no collision-free automatic IPv6 address pool is available; pass --ipv6-address-pool",
        )
}

fn ensure_local_pool_available(pool: Ipv4Net) -> Result<()> {
    if let Some(route) = local_ipv4_routes()
        .into_iter()
        .find(|route| ipv4_nets_overlap(pool, *route))
    {
        bail!("address pool {pool} overlaps local route {route}");
    }
    Ok(())
}

fn ensure_local_ipv6_pool_available(pool: Ipv6Net) -> Result<()> {
    if let Some(route) = local_ipv6_routes()
        .into_iter()
        .find(|route| ipv6_nets_overlap(pool, *route))
    {
        bail!("IPv6 address pool {pool} overlaps local route {route}");
    }
    Ok(())
}

fn local_ipv4_routes() -> Vec<Ipv4Net> {
    let Ok(output) = std::process::Command::new("ip")
        .args(["-4", "route", "show", "table", "all"])
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|value| *value != "default")
        .filter_map(|value| {
            value.parse::<Ipv4Net>().ok().or_else(|| {
                value
                    .parse::<Ipv4Addr>()
                    .ok()
                    .map(|address| Ipv4Net::new(address, 32).expect("valid host route"))
            })
        })
        .collect()
}

fn local_ipv6_routes() -> Vec<Ipv6Net> {
    let Ok(output) = std::process::Command::new("ip")
        .args(["-6", "route", "show", "table", "all"])
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let ula: Ipv6Net = "fc00::/7".parse().expect("valid ULA prefix");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|value| *value != "default")
        .filter_map(|value| {
            value.parse::<Ipv6Net>().ok().or_else(|| {
                value
                    .parse::<Ipv6Addr>()
                    .ok()
                    .map(|address| Ipv6Net::new(address, 128).expect("valid IPv6 host route"))
            })
        })
        // Ignore default and split-default routes installed by general VPNs.
        // Only ULA-specific routes can conflict with an Overlay ULA pool.
        .filter(|route| route.prefix_len() >= ula.prefix_len() && ula.contains(&route.network()))
        .collect()
}

fn ipv4_nets_overlap(left: Ipv4Net, right: Ipv4Net) -> bool {
    left.contains(&right.network()) || right.contains(&left.network())
}

fn ipv6_nets_overlap(left: Ipv6Net, right: Ipv6Net) -> bool {
    left.contains(&right.network()) || right.contains(&left.network())
}

fn allocate_address(pool: Ipv4Net, endpoint: EndpointId) -> IpNet {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ironet-auto-address-v1\0");
    hasher.update(pool.to_string().as_bytes());
    hasher.update(endpoint.as_bytes());
    let hash = hasher.finalize();
    let raw = u32::from_be_bytes(hash.as_bytes()[..4].try_into().expect("four bytes"));
    let host_bits = 32 - pool.prefix_len();
    let host_mask = if host_bits == 32 {
        u32::MAX
    } else {
        (1u32 << host_bits) - 1
    };
    let usable = host_mask.saturating_sub(1).max(1);
    let host = 1 + raw % usable;
    let network = u32::from(pool.network());
    IpNet::new(IpAddr::V4(Ipv4Addr::from(network | host)), 32).expect("valid IPv4 host")
}

fn allocate_ipv6_address(pool: Ipv6Net, endpoint: EndpointId) -> IpNet {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ironet-auto-ipv6-address-v1\0");
    hasher.update(pool.to_string().as_bytes());
    hasher.update(endpoint.as_bytes());
    let hash = hasher.finalize();
    let raw = u128::from_be_bytes(hash.as_bytes()[..16].try_into().expect("sixteen bytes"));
    let host_bits = 128 - pool.prefix_len();
    let host_mask = (1_u128 << host_bits) - 1;
    let usable = host_mask.saturating_sub(1).max(1);
    let host = 1 + raw % usable;
    let network = u128::from(pool.network());
    IpNet::new(IpAddr::V6(Ipv6Addr::from(network | host)), 128).expect("valid IPv6 host")
}

fn short_network_uid(authority: EndpointId) -> String {
    authority.to_string()
}

fn now_unix() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs())
}

pub fn parse_duration(value: &str) -> Result<u64> {
    let value = value.trim();
    ensure!(!value.is_empty(), "duration cannot be empty");
    let (number, multiplier) = match value.as_bytes().last().copied() {
        Some(b's') => (&value[..value.len() - 1], 1),
        Some(b'm') => (&value[..value.len() - 1], 60),
        Some(b'h') => (&value[..value.len() - 1], 3_600),
        Some(b'd') => (&value[..value.len() - 1], 86_400),
        Some(byte) if byte.is_ascii_digit() => (value, 1),
        _ => bail!("duration must use s, m, h or d, for example 1h"),
    };
    let number = u64::from_str(number).context("invalid duration")?;
    number
        .checked_mul(multiplier)
        .context("duration is too large")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_round_trip_verifies_signature() {
        let authority = SecretKey::generate();
        let payload = InvitePayload {
            version: INVITE_VERSION,
            id: "invite".into(),
            network_name: "production".into(),
            network_uid: authority.public().to_string(),
            network_secret: "secret".into(),
            authority: authority.public(),
            address_pool: DEFAULT_ADDRESS_POOL.parse().unwrap(),
            ipv6_address_pool: default_ipv6_address_pool(),
            issued_unix_secs: 1,
            expires_unix_secs: u64::MAX,
            capabilities: vec!["join".into()],
            member_endpoint_id: SecretKey::generate().public(),
            member_secret: None,
            bootstrap: InviteBootstrap {
                name: "edge-a".into(),
                endpoint_id: SecretKey::generate().public(),
                direct_addresses: Vec::new(),
                relay_urls: Vec::new(),
                derp_public_key: None,
            },
        };
        let bytes = serde_json::to_vec(&payload).unwrap();
        let signed = SignedInvite {
            signature: authority.sign(&bytes).to_bytes().to_vec(),
            payload,
        };
        let token = format!(
            "ironet://join/v1/{}",
            hex::encode(serde_json::to_vec(&signed).unwrap())
        );
        let decoded = decode_invite(&token).unwrap();
        assert_eq!(decoded.network_name, "production");
    }

    #[test]
    fn invite_without_ipv6_pool_remains_valid_and_gets_compatibility_pool() {
        #[derive(Serialize)]
        struct LegacyInvitePayload {
            version: u8,
            id: String,
            network_name: String,
            network_uid: String,
            network_secret: String,
            authority: EndpointId,
            address_pool: Ipv4Net,
            issued_unix_secs: u64,
            expires_unix_secs: u64,
            capabilities: Vec<String>,
            member_endpoint_id: EndpointId,
            #[serde(skip_serializing_if = "Option::is_none")]
            member_secret: Option<String>,
            bootstrap: InviteBootstrap,
        }

        #[derive(Serialize)]
        struct LegacySignedInvite {
            payload: LegacyInvitePayload,
            signature: Vec<u8>,
        }

        let authority = SecretKey::generate();
        let payload = LegacyInvitePayload {
            version: INVITE_VERSION,
            id: "legacy".into(),
            network_name: "production".into(),
            network_uid: authority.public().to_string(),
            network_secret: "secret".into(),
            authority: authority.public(),
            address_pool: DEFAULT_ADDRESS_POOL.parse().unwrap(),
            issued_unix_secs: 1,
            expires_unix_secs: u64::MAX,
            capabilities: vec!["join".into()],
            member_endpoint_id: SecretKey::generate().public(),
            member_secret: None,
            bootstrap: InviteBootstrap {
                name: "edge-a".into(),
                endpoint_id: SecretKey::generate().public(),
                direct_addresses: Vec::new(),
                relay_urls: Vec::new(),
                derp_public_key: None,
            },
        };
        let bytes = serde_json::to_vec(&payload).unwrap();
        let envelope = LegacySignedInvite {
            signature: authority.sign(&bytes).to_bytes().to_vec(),
            payload,
        };
        let token = format!(
            "ironet://join/v1/{}",
            hex::encode(serde_json::to_vec(&envelope).unwrap())
        );
        let decoded = decode_invite(&token).unwrap();
        assert_eq!(decoded.ipv6_address_pool, default_ipv6_address_pool());
    }

    #[test]
    fn deterministic_addresses_stay_inside_pool() {
        let pool: Ipv4Net = "100.64.0.0/10".parse().unwrap();
        let key = SecretKey::generate();
        let first = allocate_address(pool, key.public());
        let second = allocate_address(pool, key.public());
        assert_eq!(first, second);
        let IpAddr::V4(address) = first.addr() else {
            panic!("expected IPv4 address")
        };
        assert!(pool.contains(&address));
        assert_eq!(first.prefix_len(), 32);

        let ipv6_pool: Ipv6Net = "fd42:6972:6f68::/64".parse().unwrap();
        let first_ipv6 = allocate_ipv6_address(ipv6_pool, key.public());
        let second_ipv6 = allocate_ipv6_address(ipv6_pool, key.public());
        assert_eq!(first_ipv6, second_ipv6);
        let IpAddr::V6(address) = first_ipv6.addr() else {
            panic!("expected IPv6 address")
        };
        assert!(ipv6_pool.contains(&address));
        assert_eq!(first_ipv6.prefix_len(), 128);
    }

    #[test]
    fn legacy_product_state_loads_without_ipv6_fields() {
        let authority = SecretKey::generate();
        let state: ProductState = toml::from_str(&format!(
            r#"
version = 1
network_name = "production"
network_uid = "{authority}"
node_name = "edge-a"
authority = "{authority}"
address_pool = "100.64.0.0/10"
local_address = "100.64.0.1/32"
created_unix_secs = 1
"#,
            authority = authority.public()
        ))
        .unwrap();
        assert_eq!(state.ipv6_address_pool, default_ipv6_address_pool());
        assert_eq!(state.local_ipv6_address, None);
    }

    #[test]
    fn human_durations_are_parsed() {
        assert_eq!(parse_duration("90").unwrap(), 90);
        assert_eq!(parse_duration("15m").unwrap(), 900);
        assert_eq!(parse_duration("2h").unwrap(), 7_200);
        assert!(parse_duration("soon").is_err());
    }

    #[tokio::test]
    async fn create_invite_join_and_capabilities_form_a_complete_product_flow() {
        let creator = tempfile::tempdir().unwrap();
        let joiner = tempfile::tempdir().unwrap();
        let creator_config = creator.path().join("config.toml");
        let joiner_config = joiner.path().join("config.toml");
        let pool: Ipv4Net = "198.18.0.0/16".parse().unwrap();

        let first = create_network(
            &creator_config,
            creator.path(),
            "production",
            CreateNetworkOptions {
                node_name: Some("edge-a".into()),
                address_pool: Some(pool),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(first.created);
        let invite = create_invite(
            &creator_config,
            creator.path(),
            Some(60),
            vec!["203.0.113.10:4000".parse().unwrap()],
            None,
        )
        .unwrap();
        let second = join_network(
            &joiner_config,
            joiner.path(),
            &invite.token,
            Some("edge-b".into()),
            false,
        )
        .await
        .unwrap();
        assert!(!second.created);
        assert_eq!(first.network_id, second.network_id);
        assert_ne!(first.address, second.address);
        assert_eq!(first.addresses.len(), 2);
        assert_eq!(second.addresses.len(), 2);
        assert!(
            first
                .addresses
                .iter()
                .any(|address| address.ends_with("/32"))
        );
        assert!(
            first
                .addresses
                .iter()
                .any(|address| address.ends_with("/128"))
        );
        let joiner_runtime = Config::load(&joiner_config).await.unwrap();
        assert_eq!(
            joiner_runtime
                .node_addresses
                .iter()
                .filter(|address| address.addr().is_ipv4())
                .count(),
            1
        );
        assert_eq!(
            joiner_runtime
                .node_addresses
                .iter()
                .filter(|address| address.addr().is_ipv6())
                .count(),
            1
        );

        publish_subnet(&creator_config, "192.168.50.0/24".parse().unwrap())
            .await
            .unwrap();
        set_transit(&creator_config, true).await.unwrap();
        rename_local_node(&creator_config, creator.path(), "edge-primary")
            .await
            .unwrap();
        let config = Config::load(&creator_config).await.unwrap();
        assert_eq!(
            config.advertised_prefixes,
            ["192.168.50.0/24".parse().unwrap()]
        );
        assert!(config.routing.transit_enabled);
        assert_eq!(config.node_info.unwrap().name, "edge-primary");

        let repeated = join_network(&joiner_config, joiner.path(), &invite.token, None, false)
            .await
            .unwrap();
        assert_eq!(repeated.endpoint_id, second.endpoint_id);
    }

    #[tokio::test]
    async fn setup_rolls_back_when_any_target_already_exists() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        fs::write(&config, "owned by another deployment").unwrap();
        let error = create_network(
            &config,
            dir.path(),
            "production",
            CreateNetworkOptions {
                node_name: Some("edge-a".into()),
                address_pool: Some("198.19.0.0/16".parse().unwrap()),
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("already exists"));
        assert_eq!(
            fs::read_to_string(config).unwrap(),
            "owned by another deployment"
        );
        assert!(!dir.path().join("identity.key").exists());
        assert!(!state_path(dir.path()).exists());
    }

    #[test]
    fn tampered_invite_is_rejected() {
        let authority = SecretKey::generate();
        let payload = InvitePayload {
            version: INVITE_VERSION,
            id: "invite".into(),
            network_name: "production".into(),
            network_uid: authority.public().to_string(),
            network_secret: "secret".into(),
            authority: authority.public(),
            address_pool: DEFAULT_ADDRESS_POOL.parse().unwrap(),
            ipv6_address_pool: default_ipv6_address_pool(),
            issued_unix_secs: 1,
            expires_unix_secs: u64::MAX,
            capabilities: vec!["join".into()],
            member_endpoint_id: SecretKey::generate().public(),
            member_secret: None,
            bootstrap: InviteBootstrap {
                name: "edge-a".into(),
                endpoint_id: SecretKey::generate().public(),
                direct_addresses: Vec::new(),
                relay_urls: Vec::new(),
                derp_public_key: None,
            },
        };
        let bytes = serde_json::to_vec(&payload).unwrap();
        let mut signed = SignedInvite {
            signature: authority.sign(&bytes).to_bytes().to_vec(),
            payload,
        };
        signed.payload.network_name = "attacker".into();
        let token = format!(
            "ironet://join/v1/{}",
            hex::encode(serde_json::to_vec(&signed).unwrap())
        );
        assert!(decode_invite(&token).is_err());
    }

    #[tokio::test]
    async fn leave_can_preserve_and_reuse_node_identity() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.toml");
        let pool: Ipv4Net = "198.20.0.0/16".parse().unwrap();
        let first = create_network(
            &config,
            dir.path(),
            "first",
            CreateNetworkOptions {
                node_name: Some("edge".into()),
                address_pool: Some(pool),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        leave_network(&config, dir.path(), true).unwrap();
        assert!(dir.path().join("identity.key").exists());
        let second = create_network(
            &config,
            dir.path(),
            "second",
            CreateNetworkOptions {
                node_name: Some("edge".into()),
                address_pool: Some(pool),
                reuse_identity: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(first.endpoint_id, second.endpoint_id);
    }
}

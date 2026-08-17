//! Decentralized node directory and bounded opportunistic mesh selection.
//!
//! The directory is intentionally much larger than the adjacency set: learning
//! that a node exists is cheap, while creating a TUN, QUIC connection and
//! routing tasks is bounded by [`MeshConfig::max_peers`](crate::config::MeshConfig::max_peers).

use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc, RwLock as StdRwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use futures_util::StreamExt;
use ipnet::IpNet;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayUrl, SecretKey, TransportAddr, endpoint::Connection,
};
use iroh_base::Signature;
use n0_watcher::Watcher as _;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Notify, RwLock, watch};
use tracing::{debug, warn};

use crate::{
    config::{Config, NodeInfo},
    derp::DerpPublicKey,
};

pub const PRESENCE_VERSION: u16 = 4;
pub const DIRECTORY_CAPACITY: usize = 4_096;
pub const MAX_ENDPOINT_CANDIDATES: usize = 8;
pub const MAX_RELAY_URLS: usize = 4;
pub const MAX_ADVERTISED_PREFIXES: usize = 16;
pub const PRESENCE_TTL: Duration = Duration::from_secs(180);
pub const MAX_PRESENCE_TTL: Duration = Duration::from_secs(600);
pub const MAX_PRESENCE_BYTES: usize = 16 * 1024;
pub const PROBE_CONCURRENCY: usize = 2;
pub const CANDIDATES_PER_ROUND: usize = 16;
pub const EVALUATION_INTERVAL: Duration = Duration::from_secs(30);
pub const MIN_PEER_LIFETIME: Duration = Duration::from_secs(5 * 60);
pub const EVICTION_COOLDOWN: Duration = Duration::from_secs(10 * 60);
/// Worst-case process-wide payload budget for each mesh buffering subsystem:
/// outbound queues, fragment reassembly, FEC decode, and selective repair.
pub const MESH_BUFFER_POOL_BUDGET_BYTES: usize = 64 * 1024 * 1024;
const CLOCK_SKEW: Duration = Duration::from_secs(30);
const REPLACEMENT_CONFIRMATIONS: u8 = 3;
const REPLACEMENT_IMPROVEMENT_PERCENT: u64 = 20;
const REPLACEMENT_IMPROVEMENT_MICROS: u64 = 10_000;
const GOSSIP_INTERVAL: Duration = Duration::from_secs(15);
const LOCAL_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
const CONTROL_STREAMS_PER_MINUTE: usize = 256;
const PROBES_PER_MINUTE: usize = 128;
const CONTROL_MAGIC: &str = "ironet-v1/node-record/1";
const RENDEZVOUS_MAGIC: &str = "ironet-v1/rendezvous/1";
const PROBE_MAGIC: &str = "ironet-v1/mesh-probe/1";
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const RENDEZVOUS_CANDIDATE_TTL: Duration = Duration::from_secs(45);
const MAX_RENDEZVOUS_TTL: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PresenceBody {
    pub version: u16,
    /// Domain separation without disclosing the network ID in gossip payloads.
    pub network_fingerprint: [u8; 32],
    pub owner: EndpointId,
    pub sequence: u64,
    pub issued_unix_secs: u64,
    pub expires_unix_secs: u64,
    #[serde(default)]
    pub direct_addresses: Vec<SocketAddr>,
    #[serde(default)]
    pub relay_urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derp_public_key: Option<DerpPublicKey>,
    #[serde(default)]
    pub prefixes: Vec<IpNet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_info: Option<NodeInfo>,
    #[serde(default)]
    pub transit_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPresence {
    pub body: PresenceBody,
    pub signature: Signature,
    /// A keyed BLAKE3 tag proves knowledge of the network ID. The Ed25519
    /// signature independently proves that the announced endpoint owns the
    /// record, so intermediaries can safely forward it unchanged.
    pub membership_tag: [u8; 32],
}

impl PresenceBody {
    pub fn from_config(
        config: &Config,
        owner: EndpointId,
        sequence: u64,
        now: SystemTime,
        direct_addresses: Vec<SocketAddr>,
        relay_urls: Vec<String>,
        derp_public_key: Option<DerpPublicKey>,
    ) -> Result<Self> {
        let issued_unix_secs = unix_secs(now)?;
        Ok(Self {
            version: PRESENCE_VERSION,
            network_fingerprint: network_fingerprint(&config.network_id),
            owner,
            sequence,
            issued_unix_secs,
            expires_unix_secs: issued_unix_secs + PRESENCE_TTL.as_secs(),
            direct_addresses,
            relay_urls,
            derp_public_key,
            prefixes: config.all_advertised_prefixes().collect(),
            node_info: config.node_info.clone(),
            transit_enabled: config.routing.transit_enabled,
        })
    }

    fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1024);
        field(&mut out, b"ironet-node-record-v1");
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.network_fingerprint);
        out.extend_from_slice(self.owner.as_bytes());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.issued_unix_secs.to_be_bytes());
        out.extend_from_slice(&self.expires_unix_secs.to_be_bytes());
        out.push(u8::from(self.transit_enabled));
        list_len(&mut out, self.direct_addresses.len());
        for address in &self.direct_addresses {
            field(&mut out, address.to_string().as_bytes());
        }
        list_len(&mut out, self.relay_urls.len());
        for relay in &self.relay_urls {
            field(&mut out, relay.as_bytes());
        }
        match self.derp_public_key {
            Some(key) => {
                out.push(1);
                out.extend_from_slice(key.as_bytes());
            }
            None => out.push(0),
        }
        list_len(&mut out, self.prefixes.len());
        for prefix in &self.prefixes {
            field(&mut out, prefix.to_string().as_bytes());
        }
        match &self.node_info {
            Some(info) => {
                out.push(1);
                field(&mut out, info.name.as_bytes());
                option_field(&mut out, info.description.clone());
                list_len(&mut out, info.metadata.len());
                for (key, value) in &info.metadata {
                    field(&mut out, key.as_bytes());
                    field(&mut out, value.as_bytes());
                }
            }
            None => out.push(0),
        }
        out
    }
}

impl SignedPresence {
    pub fn sign(body: PresenceBody, secret_key: &SecretKey, network_id: &str) -> Result<Self> {
        ensure!(
            body.owner == secret_key.public(),
            "presence owner does not match signing key"
        );
        ensure!(
            body.network_fingerprint == network_fingerprint(network_id),
            "presence belongs to a different network"
        );
        let signing_bytes = body.signing_bytes();
        let signature = secret_key.sign(&signing_bytes);
        let membership_tag = membership_tag(network_id, &signing_bytes, &signature);
        Ok(Self {
            body,
            signature,
            membership_tag,
        })
    }

    pub fn verify(&self, network_id: &str, now: SystemTime) -> Result<()> {
        ensure!(
            self.body.version == PRESENCE_VERSION,
            "unsupported presence version"
        );
        ensure!(self.body.sequence > 0, "presence sequence must be non-zero");
        ensure!(
            self.body.network_fingerprint == network_fingerprint(network_id),
            "presence belongs to a different network"
        );
        let signing_bytes = self.body.signing_bytes();
        self.body
            .owner
            .verify(&signing_bytes, &self.signature)
            .context("invalid presence owner signature")?;
        ensure!(
            constant_time_eq(
                &self.membership_tag,
                &membership_tag(network_id, &signing_bytes, &self.signature)
            ),
            "invalid presence membership tag"
        );
        self.validate_bounds(now)?;
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_PRESENCE_BYTES,
            "presence exceeds wire size limit"
        );
        Ok(())
    }

    fn validate_bounds(&self, now: SystemTime) -> Result<()> {
        let now = unix_secs(now)?;
        ensure!(
            self.body.issued_unix_secs <= now.saturating_add(CLOCK_SKEW.as_secs()),
            "presence issue time is too far in the future"
        );
        ensure!(self.body.expires_unix_secs > now, "presence has expired");
        ensure!(
            self.body.expires_unix_secs >= self.body.issued_unix_secs
                && self.body.expires_unix_secs - self.body.issued_unix_secs
                    <= MAX_PRESENCE_TTL.as_secs(),
            "presence TTL exceeds limit"
        );
        ensure!(
            self.body.direct_addresses.len() <= MAX_ENDPOINT_CANDIDATES,
            "too many direct address candidates"
        );
        ensure!(
            self.body.relay_urls.len() <= MAX_RELAY_URLS,
            "too many relay URLs"
        );
        ensure!(
            self.body.prefixes.len() <= MAX_ADVERTISED_PREFIXES,
            "too many advertised prefixes"
        );
        let mut addresses = HashSet::new();
        for address in &self.body.direct_addresses {
            ensure!(address.port() != 0, "direct address has zero port");
            ensure!(
                safe_underlay_ip(address.ip()),
                "unsafe direct address candidate"
            );
            ensure!(
                addresses.insert(*address),
                "duplicate direct address candidate"
            );
        }
        let mut relays = HashSet::new();
        for relay in &self.body.relay_urls {
            let parsed = relay
                .parse::<RelayUrl>()
                .with_context(|| format!("invalid relay URL {relay}"))?;
            ensure!(relays.insert(parsed), "duplicate relay URL");
        }
        let mut prefixes = HashSet::new();
        for prefix in &self.body.prefixes {
            ensure!(
                safe_overlay_prefix(*prefix),
                "unsafe advertised prefix {prefix}"
            );
            ensure!(prefixes.insert(*prefix), "duplicate advertised prefix");
        }
        if let Some(info) = &self.body.node_info {
            ensure!(
                !info.name.trim().is_empty(),
                "node_info.name cannot be empty"
            );
            ensure!(
                serde_json::to_vec(info)?.len() <= 1_024,
                "node_info exceeds presence limit"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    Inserted,
    Updated,
    Refreshed,
    Stale,
}

#[derive(Debug, Clone)]
struct DirectoryEntry {
    presence: SignedPresence,
    received_at: Instant,
}

#[derive(Debug)]
pub struct Directory {
    local_id: EndpointId,
    capacity: usize,
    reserved_prefixes: Vec<IpNet>,
    records: HashMap<EndpointId, DirectoryEntry>,
    quarantined: HashSet<EndpointId>,
}

impl Directory {
    pub fn new(local_id: EndpointId) -> Self {
        Self::with_capacity(local_id, DIRECTORY_CAPACITY)
    }

    pub fn with_reserved(
        local_id: EndpointId,
        reserved_prefixes: impl IntoIterator<Item = IpNet>,
    ) -> Self {
        let mut directory = Self::new(local_id);
        directory.reserved_prefixes = reserved_prefixes.into_iter().collect();
        directory
    }

    pub fn with_capacity(local_id: EndpointId, capacity: usize) -> Self {
        Self {
            local_id,
            capacity: capacity.clamp(1, DIRECTORY_CAPACITY),
            reserved_prefixes: Vec::new(),
            records: HashMap::new(),
            quarantined: HashSet::new(),
        }
    }

    pub fn insert(
        &mut self,
        presence: SignedPresence,
        network_id: &str,
        wall_now: SystemTime,
        monotonic_now: Instant,
    ) -> Result<InsertOutcome> {
        presence.verify(network_id, wall_now)?;
        if presence.body.owner == self.local_id {
            anyhow::bail!("received a forwarded copy of local presence");
        }
        if let Some(existing) = self.records.get_mut(&presence.body.owner) {
            if presence.body.sequence < existing.presence.body.sequence {
                return Ok(InsertOutcome::Stale);
            }
            if presence.body.sequence == existing.presence.body.sequence {
                if presence != existing.presence {
                    anyhow::bail!("conflicting presence at the same sequence");
                }
                existing.received_at = monotonic_now;
                return Ok(InsertOutcome::Refreshed);
            }
            let prefixes_changed = existing.presence.body.prefixes != presence.body.prefixes;
            existing.presence = presence;
            existing.received_at = monotonic_now;
            if prefixes_changed {
                self.recompute_conflicts();
            }
            return Ok(InsertOutcome::Updated);
        }

        if self.records.len() == self.capacity
            && let Some(oldest) = self
                .records
                .iter()
                .min_by_key(|(_, entry)| entry.received_at)
                .map(|(owner, _)| *owner)
        {
            self.records.remove(&oldest);
        }
        self.records.insert(
            presence.body.owner,
            DirectoryEntry {
                presence,
                received_at: monotonic_now,
            },
        );
        self.recompute_conflicts();
        Ok(InsertOutcome::Inserted)
    }

    pub fn prune(&mut self, wall_now: SystemTime) -> Result<Vec<EndpointId>> {
        let now = unix_secs(wall_now)?;
        let expired = self
            .records
            .iter()
            .filter(|(_, entry)| entry.presence.body.expires_unix_secs <= now)
            .map(|(owner, _)| *owner)
            .collect::<Vec<_>>();
        for owner in &expired {
            self.records.remove(owner);
        }
        if !expired.is_empty() {
            self.recompute_conflicts();
        }
        Ok(expired)
    }

    pub fn get(&self, owner: EndpointId) -> Option<&SignedPresence> {
        self.records.get(&owner).map(|entry| &entry.presence)
    }

    pub(crate) fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_quarantined(&self, owner: EndpointId) -> bool {
        self.quarantined.contains(&owner)
    }

    pub fn eligible(&self) -> impl Iterator<Item = &SignedPresence> {
        self.records
            .values()
            .filter(|entry| !self.quarantined.contains(&entry.presence.body.owner))
            .map(|entry| &entry.presence)
    }

    pub fn presences(&self) -> impl Iterator<Item = &SignedPresence> {
        self.records.values().map(|entry| &entry.presence)
    }

    fn recompute_conflicts(&mut self) {
        let mut v4 = PrefixTrie::default();
        let mut v6 = PrefixTrie::default();
        let mut conflicts = HashSet::new();
        for entry in self.records.values() {
            for prefix in &entry.presence.body.prefixes {
                if self
                    .reserved_prefixes
                    .iter()
                    .any(|reserved| prefixes_overlap(*reserved, *prefix))
                {
                    conflicts.insert(entry.presence.body.owner);
                }
                match prefix {
                    IpNet::V4(prefix) => v4.insert(
                        entry.presence.body.owner,
                        u128::from(u32::from(prefix.network())),
                        prefix.prefix_len(),
                        32,
                        &mut conflicts,
                    ),
                    IpNet::V6(prefix) => v6.insert(
                        entry.presence.body.owner,
                        u128::from(prefix.network()),
                        prefix.prefix_len(),
                        128,
                        &mut conflicts,
                    ),
                }
            }
        }
        self.quarantined = conflicts;
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlMessage {
    protocol: String,
    presence: SignedPresence,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RendezvousMessage {
    protocol: String,
    owner: EndpointId,
    address: SocketAddr,
    observed_unix_secs: u64,
    expires_unix_secs: u64,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum IncomingControlMessage {
    Presence(Box<ControlMessage>),
    Rendezvous(RendezvousMessage),
}

#[derive(Debug, Clone)]
struct RendezvousCandidate {
    address: SocketAddr,
    observer: EndpointId,
    expires_unix_secs: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeRequest {
    protocol: String,
    owner: EndpointId,
    issued_unix_secs: u64,
    nonce: u64,
    membership_tag: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProbeResponse {
    protocol: String,
    nonce: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshNodeStatus {
    pub endpoint_id: String,
    pub sequence: u64,
    pub expires_unix_secs: u64,
    pub direct_addresses: Vec<SocketAddr>,
    pub assisted_addresses: Vec<SocketAddr>,
    pub relay_urls: Vec<String>,
    pub prefixes: Vec<IpNet>,
    pub node_info: Option<NodeInfo>,
    pub transit_enabled: bool,
    pub quarantined: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MeshStatus {
    pub enabled: bool,
    pub directory_entries: usize,
    pub quarantined_entries: usize,
    pub max_total_peers: usize,
    pub nodes: Vec<MeshNodeStatus>,
}

/// Runtime Presence service shared by every pinned and dynamic adjacency.
/// QUIC streams carry control records so gossip size is independent of the
/// path's datagram MTU and does not compete with packet fragmentation.
pub struct MeshRuntime {
    config: Config,
    secret_key: SecretKey,
    endpoint: Endpoint,
    derp_public_key: Option<DerpPublicKey>,
    sequence: AtomicU64,
    probe_nonce: AtomicU64,
    sequence_file: PathBuf,
    local_presence: RwLock<SignedPresence>,
    local_presence_updates: watch::Sender<u64>,
    directory: Mutex<Directory>,
    /// Direct socket addresses observed on authenticated peer connections.
    /// Only locally observed records are forwarded, so rendezvous data is
    /// never amplified recursively through the mesh.
    connection_observations: Mutex<HashMap<EndpointId, RendezvousCandidate>>,
    /// Short-lived candidates reported by the authenticated peer currently
    /// carrying the control stream.
    assisted_candidates: Mutex<HashMap<EndpointId, Vec<RendezvousCandidate>>>,
    candidate_updates: Notify,
    rendezvous_updates: watch::Sender<u64>,
    hidden_underlay_prefixes: Vec<IpNet>,
    policy: StdRwLock<MeshPolicySnapshot>,
    probe_window: Mutex<ProbeWindow>,
}

#[derive(Debug, Clone, Default)]
struct MeshPolicySnapshot {
    local_prefixes: Vec<IpNet>,
    origins: Vec<(EndpointId, IpNet)>,
    transit_by_owner: HashMap<EndpointId, bool>,
}

#[derive(Debug)]
struct ProbeWindow {
    started: Instant,
    accepted: usize,
}

impl MeshRuntime {
    pub fn new(
        config: &Config,
        secret_key: SecretKey,
        endpoint: Endpoint,
        derp_public_key: Option<DerpPublicKey>,
    ) -> Result<Arc<Self>> {
        let owner = secret_key.public();
        let now = SystemTime::now();
        let sequence_file = sequence_file_path(config);
        let sequence = reserve_sequence(&sequence_file, now)?;
        let mut hidden_underlay_prefixes = config.excluded_underlay_prefixes.clone();
        hidden_underlay_prefixes.extend(config.all_overlay_prefixes());
        hidden_underlay_prefixes.extend(config.private_locator_prefixes());
        let local_presence = build_local_presence(
            config,
            &secret_key,
            &endpoint,
            derp_public_key,
            sequence,
            now,
            &hidden_underlay_prefixes,
        )?;
        let (rendezvous_updates, _) = watch::channel(0);
        let (local_presence_updates, _) = watch::channel(sequence);
        Ok(Arc::new(Self {
            config: config.clone(),
            secret_key,
            endpoint,
            derp_public_key,
            sequence: AtomicU64::new(sequence),
            probe_nonce: AtomicU64::new(sequence.rotate_left(17)),
            sequence_file,
            local_presence: RwLock::new(local_presence),
            local_presence_updates,
            directory: Mutex::new(Directory::with_reserved(
                owner,
                config.all_advertised_prefixes(),
            )),
            connection_observations: Mutex::new(HashMap::new()),
            assisted_candidates: Mutex::new(HashMap::new()),
            candidate_updates: Notify::new(),
            rendezvous_updates,
            hidden_underlay_prefixes,
            policy: StdRwLock::new(MeshPolicySnapshot {
                local_prefixes: config.all_advertised_prefixes().collect(),
                origins: Vec::new(),
                transit_by_owner: HashMap::new(),
            }),
            probe_window: Mutex::new(ProbeWindow {
                started: Instant::now(),
                accepted: 0,
            }),
        }))
    }

    pub async fn run_maintenance(self: Arc<Self>) -> Result<()> {
        let mut refresh = tokio::time::interval(LOCAL_REFRESH_INTERVAL);
        refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut address_updates = self.endpoint.watch_addr().stream_updates_only();
        // The constructor already published the first record.
        refresh.tick().await;
        loop {
            tokio::select! {
                _ = refresh.tick() => {}
                update = address_updates.next() => {
                    update.context("endpoint address watcher stopped")?;
                }
            }
            let now = SystemTime::now();
            let sequence = self.sequence.fetch_add(1, Ordering::Relaxed) + 1;
            crate::deployment::atomic_write(
                &self.sequence_file,
                format!("{sequence}\n").as_bytes(),
                0o600,
            )?;
            let presence = build_local_presence(
                &self.config,
                &self.secret_key,
                &self.endpoint,
                self.derp_public_key,
                sequence,
                now,
                &self.hidden_underlay_prefixes,
            )?;
            *self.local_presence.write().await = presence;
            self.local_presence_updates.send_replace(sequence);
            let mut directory = self.directory.lock().await;
            let expired = directory.prune(now)?;
            if !expired.is_empty() {
                self.update_policy(&directory);
                debug!(count = expired.len(), "expired mesh directory records");
            }
        }
    }

    pub async fn run_connection(
        self: Arc<Self>,
        connection: Connection,
        remote_id: EndpointId,
    ) -> Result<()> {
        self.refresh_connection_observation(remote_id, &connection)
            .await;
        let sender = self.clone().send_loop(connection.clone(), remote_id);
        let receiver = self.clone().receive_loop(connection.clone(), remote_id);
        tokio::select! {
            result = sender => result,
            result = receiver => result,
            reason = connection.closed() => {
                debug!(endpoint_id = %remote_id, %reason, "mesh control connection closed");
                Ok(())
            }
        }
    }

    pub async fn snapshot(&self) -> MeshStatus {
        let directory = self.directory.lock().await;
        let now = unix_secs(SystemTime::now()).unwrap_or_default();
        let assisted = self.assisted_candidates.lock().await;
        let mut nodes = directory
            .presences()
            .map(|presence| MeshNodeStatus {
                endpoint_id: presence.body.owner.to_string(),
                sequence: presence.body.sequence,
                expires_unix_secs: presence.body.expires_unix_secs,
                direct_addresses: presence.body.direct_addresses.clone(),
                assisted_addresses: assisted
                    .get(&presence.body.owner)
                    .into_iter()
                    .flatten()
                    .filter(|candidate| candidate.expires_unix_secs > now)
                    .map(|candidate| candidate.address)
                    .collect(),
                relay_urls: presence.body.relay_urls.clone(),
                prefixes: presence.body.prefixes.clone(),
                node_info: presence.body.node_info.clone(),
                transit_enabled: presence.body.transit_enabled,
                quarantined: directory.is_quarantined(presence.body.owner),
            })
            .collect::<Vec<_>>();
        nodes.sort_by(|left, right| left.endpoint_id.cmp(&right.endpoint_id));
        MeshStatus {
            enabled: true,
            directory_entries: directory.len(),
            quarantined_entries: nodes.iter().filter(|node| node.quarantined).count(),
            max_total_peers: self.config.mesh.max_peers,
            nodes,
        }
    }

    pub async fn eligible_presences(&self) -> Vec<SignedPresence> {
        self.directory.lock().await.eligible().cloned().collect()
    }

    /// Merge owner-signed candidates with short-lived addresses observed by
    /// connected peers. Endpoint authentication still proves the remote
    /// identity, so a bad rendezvous hint can waste a probe but cannot
    /// impersonate the advertised owner.
    pub async fn direct_candidates(&self, presence: &SignedPresence) -> Vec<SocketAddr> {
        let now = unix_secs(SystemTime::now()).unwrap_or_default();
        let mut assisted = self.assisted_candidates.lock().await;
        assisted.retain(|_, candidates| {
            candidates.retain(|candidate| candidate.expires_unix_secs > now);
            !candidates.is_empty()
        });
        merge_direct_candidates(
            &presence.body.direct_addresses,
            assisted.get(&presence.body.owner).into_iter().flatten(),
        )
    }

    pub async fn candidate_update_notified(&self) {
        self.candidate_updates.notified().await;
    }

    pub async fn add_connection_observation(&self, remote_id: EndpointId, address: SocketAddr) {
        self.store_connection_observation(remote_id, address).await;
    }

    pub fn overlay_address_known(&self, address: IpAddr) -> bool {
        let policy = self.read_policy();
        policy
            .local_prefixes
            .iter()
            .chain(policy.origins.iter().map(|(_, prefix)| prefix))
            .any(|prefix| prefix.contains(&address))
    }

    pub fn remote_overlay_address_known(&self, address: IpAddr) -> bool {
        self.read_policy()
            .origins
            .iter()
            .any(|(_, prefix)| prefix.contains(&address))
    }

    pub fn destination_owner(&self, address: IpAddr) -> Option<EndpointId> {
        self.read_policy()
            .origins
            .iter()
            .find_map(|(owner, prefix)| prefix.contains(&address).then_some(*owner))
    }

    pub fn source_allowed_from(&self, peer: EndpointId, source: IpAddr) -> bool {
        let policy = self.read_policy();
        let accepts_transit = policy.transit_by_owner.get(&peer) == Some(&true);
        policy
            .origins
            .iter()
            .any(|(owner, prefix)| prefix.contains(&source) && (accepts_transit || *owner == peer))
    }

    /// Return the advertised transit policy from the lock-free-sized policy
    /// snapshot. Hot packet routing needs only this bit, not a cloned signed
    /// Presence with address, metadata and signature allocations.
    pub fn transit_enabled_for(&self, owner: EndpointId) -> Option<bool> {
        self.read_policy().transit_by_owner.get(&owner).copied()
    }

    pub fn eligible_owners(&self) -> Vec<EndpointId> {
        self.read_policy()
            .transit_by_owner
            .keys()
            .copied()
            .collect()
    }

    pub fn remote_prefixes(&self) -> Vec<IpNet> {
        self.read_policy()
            .origins
            .iter()
            .map(|(_, prefix)| *prefix)
            .collect()
    }

    /// Clone the small control-plane policy as one coherent generation. Data
    /// plane route snapshots call this off the packet path, avoiding one lock
    /// acquisition per prefix lookup and another per adjacency.
    pub fn routing_policy_snapshot(&self) -> (Vec<(EndpointId, IpNet)>, HashMap<EndpointId, bool>) {
        let policy = self.read_policy();
        (policy.origins.clone(), policy.transit_by_owner.clone())
    }

    pub async fn presence(&self, owner: EndpointId) -> Option<SignedPresence> {
        let directory = self.directory.lock().await;
        directory
            .get(owner)
            .filter(|_| !directory.is_quarantined(owner))
            .cloned()
    }

    /// Bootstrap admission path for a Public node that has no pre-existing
    /// record for the connecting node. The first reliable control stream must
    /// carry the connecting endpoint's own signed Presence.
    pub async fn admit_connection_presence(
        &self,
        connection: &Connection,
        remote_id: EndpointId,
    ) -> Result<SignedPresence> {
        let mut receive = tokio::time::timeout(Duration::from_secs(5), connection.accept_uni())
            .await
            .context("timed out waiting for bootstrap presence")?
            .context("failed accepting bootstrap presence stream")?;
        let bytes = receive
            .read_to_end(MAX_PRESENCE_BYTES + 512)
            .await
            .context("failed reading bootstrap presence")?;
        let message: ControlMessage =
            serde_json::from_slice(&bytes).context("invalid bootstrap presence message")?;
        ensure!(
            message.protocol == CONTROL_MAGIC,
            "invalid mesh control protocol"
        );
        ensure!(
            message.presence.body.owner == remote_id,
            "bootstrap presence owner does not match QUIC identity"
        );
        ensure!(
            self.excluded_underlay_candidate(&message.presence)
                .is_none(),
            "bootstrap presence contains forbidden underlay candidate"
        );
        let presence = message.presence;
        let mut directory = self.directory.lock().await;
        directory.insert(
            presence.clone(),
            &self.config.network_id,
            SystemTime::now(),
            Instant::now(),
        )?;
        self.update_policy(&directory);
        Ok(presence)
    }

    /// Answer a short-lived probe on the dedicated mesh-probe ALPN. The
    /// keyed tag keeps non-members from using every node as a QUIC echo
    /// service, while the TLS endpoint identity binds `owner` to the caller.
    pub async fn answer_probe(&self, connection: &Connection) -> Result<()> {
        let remote_id = connection.remote_id();
        let (mut send, mut receive) = tokio::time::timeout(PROBE_TIMEOUT, connection.accept_bi())
            .await
            .context("timed out waiting for mesh probe")?
            .context("failed accepting mesh probe stream")?;
        let bytes = receive
            .read_to_end(1_024)
            .await
            .context("failed reading mesh probe")?;
        let request: ProbeRequest =
            serde_json::from_slice(&bytes).context("invalid mesh probe request")?;
        ensure!(
            request.protocol == PROBE_MAGIC,
            "invalid mesh probe protocol"
        );
        ensure!(request.owner == remote_id, "mesh probe owner mismatch");
        let now = unix_secs(SystemTime::now())?;
        ensure!(
            request.issued_unix_secs <= now.saturating_add(CLOCK_SKEW.as_secs())
                && now
                    <= request
                        .issued_unix_secs
                        .saturating_add(CLOCK_SKEW.as_secs()),
            "mesh probe timestamp outside acceptance window"
        );
        ensure!(
            constant_time_eq(
                &request.membership_tag,
                &probe_membership_tag(
                    &self.config.network_id,
                    request.owner,
                    request.issued_unix_secs,
                    request.nonce,
                )
            ),
            "invalid mesh probe membership tag"
        );
        {
            let mut window = self.probe_window.lock().await;
            if window.started.elapsed() >= Duration::from_secs(60) {
                window.started = Instant::now();
                window.accepted = 0;
            }
            ensure!(
                window.accepted < PROBES_PER_MINUTE,
                "mesh probe rate exceeded"
            );
            window.accepted += 1;
        }
        let response = serde_json::to_vec(&ProbeResponse {
            protocol: PROBE_MAGIC.into(),
            nonce: request.nonce,
        })?;
        send.write_all(&response)
            .await
            .context("failed writing mesh probe response")?;
        send.finish()
            .context("failed finishing mesh probe response")?;
        let _ = tokio::time::timeout(PROBE_TIMEOUT, send.stopped()).await;
        Ok(())
    }

    /// Measure a candidate without creating a TUN, queue, routing interface,
    /// or long-lived data-plane connection. Only direct IP paths are accepted.
    pub async fn probe_candidate(
        &self,
        presence: &SignedPresence,
        probe_alpn: &[u8],
    ) -> Result<(Duration, SocketAddr)> {
        ensure!(
            !presence.body.direct_addresses.is_empty(),
            "mesh candidate has no direct addresses"
        );
        let mut target = EndpointAddr::new(presence.body.owner);
        for address in presence
            .body
            .direct_addresses
            .iter()
            .take(MAX_ENDPOINT_CANDIDATES)
        {
            target = target.with_ip_addr(*address);
        }
        let started = Instant::now();
        let connection =
            tokio::time::timeout(PROBE_TIMEOUT, self.endpoint.connect(target, probe_alpn))
                .await
                .context("mesh probe connection timed out")?
                .context("mesh probe connection failed")?;
        let issued_unix_secs = unix_secs(SystemTime::now())?;
        let nonce = self.probe_nonce.fetch_add(1, Ordering::Relaxed);
        let request = ProbeRequest {
            protocol: PROBE_MAGIC.into(),
            owner: self.secret_key.public(),
            issued_unix_secs,
            nonce,
            membership_tag: probe_membership_tag(
                &self.config.network_id,
                self.secret_key.public(),
                issued_unix_secs,
                nonce,
            ),
        };
        let (mut send, mut receive) = connection
            .open_bi()
            .await
            .context("failed opening mesh probe stream")?;
        send.write_all(&serde_json::to_vec(&request)?)
            .await
            .context("failed writing mesh probe")?;
        send.finish().context("failed finishing mesh probe")?;
        let bytes = tokio::time::timeout(PROBE_TIMEOUT, receive.read_to_end(1_024))
            .await
            .context("mesh probe response timed out")?
            .context("failed reading mesh probe response")?;
        let response: ProbeResponse =
            serde_json::from_slice(&bytes).context("invalid mesh probe response")?;
        ensure!(
            response.protocol == PROBE_MAGIC && response.nonce == nonce,
            "mesh probe response mismatch"
        );
        let snapshot = connection.paths();
        let selected = snapshot
            .iter()
            .find(|path| path.is_selected())
            .context("mesh probe has no selected path")?;
        let TransportAddr::Ip(address) = selected.remote_addr() else {
            anyhow::bail!("mesh probe selected a non-direct path");
        };
        let path_rtt = selected.stats().rtt;
        let rtt = if path_rtt.is_zero() {
            started.elapsed()
        } else {
            path_rtt
        };
        let address = *address;
        connection.close(0_u8.into(), b"probe complete");
        Ok((rtt, address))
    }

    async fn send_loop(
        self: Arc<Self>,
        connection: Connection,
        remote_id: EndpointId,
    ) -> Result<()> {
        let mut interval = tokio::time::interval(GOSSIP_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut rendezvous_updates = self.rendezvous_updates.subscribe();
        let mut local_presence_updates = self.local_presence_updates.subscribe();
        let mut cursor = 0_usize;
        let mut rendezvous_cursor = 0_usize;
        loop {
            let (send_local, gossip) = tokio::select! {
                _ = interval.tick() => (true, true),
                update = rendezvous_updates.changed() => {
                    update.context("rendezvous update channel closed")?;
                    (false, false)
                }
                update = local_presence_updates.changed() => {
                    update.context("local Presence update channel closed")?;
                    (true, false)
                }
            };
            if send_local {
                let local = self.local_presence.read().await.clone();
                send_presence(&connection, &local).await?;
            }
            if gossip {
                self.refresh_connection_observation(remote_id, &connection)
                    .await;
                let mut records = self
                    .directory
                    .lock()
                    .await
                    .presences()
                    .filter(|presence| presence.body.owner != remote_id)
                    .cloned()
                    .collect::<Vec<_>>();
                records.sort_by_key(|presence| presence.body.owner);
                if !records.is_empty() {
                    cursor %= records.len();
                    for offset in 0..records.len().min(CANDIDATES_PER_ROUND) {
                        let index = (cursor + offset) % records.len();
                        send_presence(&connection, &records[index]).await?;
                    }
                    cursor = (cursor + CANDIDATES_PER_ROUND) % records.len();
                }
            }

            let now = unix_secs(SystemTime::now())?;
            let mut observations = self
                .connection_observations
                .lock()
                .await
                .values()
                .filter(|candidate| {
                    candidate.observer != remote_id && candidate.expires_unix_secs > now
                })
                .cloned()
                .collect::<Vec<_>>();
            observations.sort_by_key(|candidate| candidate.observer);
            if !observations.is_empty() {
                rendezvous_cursor %= observations.len();
                for offset in 0..observations.len().min(CANDIDATES_PER_ROUND) {
                    let candidate =
                        &observations[(rendezvous_cursor + offset) % observations.len()];
                    send_rendezvous_candidate(&connection, candidate, now).await?;
                }
                rendezvous_cursor = (rendezvous_cursor + CANDIDATES_PER_ROUND) % observations.len();
            }
        }
    }

    async fn receive_loop(
        self: Arc<Self>,
        connection: Connection,
        remote_id: EndpointId,
    ) -> Result<()> {
        let mut window_started = Instant::now();
        let mut streams = 0_usize;
        loop {
            if window_started.elapsed() >= Duration::from_secs(60) {
                window_started = Instant::now();
                streams = 0;
            }
            ensure!(
                streams < CONTROL_STREAMS_PER_MINUTE,
                "mesh control stream rate exceeded"
            );
            let mut receive = connection
                .accept_uni()
                .await
                .context("failed accepting mesh control stream")?;
            streams += 1;
            let bytes = receive
                .read_to_end(MAX_PRESENCE_BYTES + 512)
                .await
                .context("failed reading mesh control stream")?;
            let message: IncomingControlMessage =
                serde_json::from_slice(&bytes).context("invalid mesh control message")?;
            match message {
                IncomingControlMessage::Presence(message) => {
                    ensure!(
                        message.protocol == CONTROL_MAGIC,
                        "invalid mesh control protocol"
                    );
                    if message.presence.body.owner == self.secret_key.public() {
                        continue;
                    }
                    if let Some((address, prefix)) =
                        self.excluded_underlay_candidate(&message.presence)
                    {
                        warn!(endpoint_id = %remote_id, owner = %message.presence.body.owner, %address, %prefix, "discarding presence with forbidden underlay candidate");
                        continue;
                    }
                    let mut directory = self.directory.lock().await;
                    match directory.insert(
                        message.presence,
                        &self.config.network_id,
                        SystemTime::now(),
                        Instant::now(),
                    ) {
                        Ok(InsertOutcome::Inserted | InsertOutcome::Updated) => {
                            self.update_policy(&directory);
                        }
                        Ok(InsertOutcome::Refreshed | InsertOutcome::Stale) => {}
                        Err(error) => {
                            warn!(endpoint_id = %remote_id, %error, "discarding invalid mesh presence");
                        }
                    }
                }
                IncomingControlMessage::Rendezvous(message) => {
                    if let Err(error) = self.learn_rendezvous_candidate(remote_id, message).await {
                        warn!(endpoint_id = %remote_id, %error, "discarding invalid rendezvous candidate");
                    }
                }
            }
        }
    }

    async fn refresh_connection_observation(&self, remote_id: EndpointId, connection: &Connection) {
        let Some(address) = connection.paths().iter().find_map(|path| {
            (path.is_selected())
                .then_some(path.remote_addr())
                .and_then(|address| {
                    if let TransportAddr::Ip(address) = address {
                        Some(*address)
                    } else {
                        None
                    }
                })
        }) else {
            return;
        };
        self.store_connection_observation(remote_id, address).await;
    }

    async fn store_connection_observation(&self, remote_id: EndpointId, address: SocketAddr) {
        if !safe_underlay_ip(address.ip())
            || self
                .hidden_underlay_prefixes
                .iter()
                .any(|prefix| prefix.contains(&address.ip()))
        {
            return;
        }
        let now = unix_secs(SystemTime::now()).unwrap_or_default();
        let candidate = RendezvousCandidate {
            address,
            observer: remote_id,
            expires_unix_secs: now + RENDEZVOUS_CANDIDATE_TTL.as_secs(),
        };
        let changed = self
            .connection_observations
            .lock()
            .await
            .insert(remote_id, candidate)
            .is_none_or(|previous| previous.address != address);
        if changed {
            self.rendezvous_updates.send_modify(|epoch| *epoch += 1);
        }
    }

    async fn learn_rendezvous_candidate(
        &self,
        observer: EndpointId,
        message: RendezvousMessage,
    ) -> Result<()> {
        ensure!(
            message.protocol == RENDEZVOUS_MAGIC,
            "invalid rendezvous protocol"
        );
        ensure!(
            message.owner != self.secret_key.public(),
            "rendezvous candidate points back to the local endpoint"
        );
        ensure!(message.owner != observer, "observer reported itself");
        {
            let directory = self.directory.lock().await;
            ensure!(
                directory.get(message.owner).is_some() && !directory.is_quarantined(message.owner),
                "candidate owner has no eligible signed Presence"
            );
        }
        ensure!(message.address.port() != 0, "candidate has zero port");
        ensure!(
            safe_underlay_ip(message.address.ip()),
            "candidate address is unsafe"
        );
        ensure!(
            !self
                .hidden_underlay_prefixes
                .iter()
                .any(|prefix| prefix.contains(&message.address.ip())),
            "candidate address is inside a forbidden underlay prefix"
        );
        let now = unix_secs(SystemTime::now())?;
        ensure!(
            message.observed_unix_secs <= now.saturating_add(CLOCK_SKEW.as_secs()),
            "candidate observation is in the future"
        );
        ensure!(message.expires_unix_secs > now, "candidate has expired");
        ensure!(
            message.expires_unix_secs >= message.observed_unix_secs
                && message.expires_unix_secs - message.observed_unix_secs
                    <= MAX_RENDEZVOUS_TTL.as_secs(),
            "candidate TTL exceeds limit"
        );
        let candidate = RendezvousCandidate {
            address: message.address,
            observer,
            expires_unix_secs: message.expires_unix_secs,
        };
        let mut learned = self.assisted_candidates.lock().await;
        let candidates = learned.entry(message.owner).or_default();
        candidates.retain(|existing| {
            existing.expires_unix_secs > now
                && !(existing.observer == observer && existing.address == candidate.address)
        });
        candidates.push(candidate);
        candidates.sort_by_key(|candidate| std::cmp::Reverse(candidate.expires_unix_secs));
        candidates.truncate(MAX_ENDPOINT_CANDIDATES);
        drop(learned);
        self.candidate_updates.notify_one();
        Ok(())
    }

    fn update_policy(&self, directory: &Directory) {
        let mut snapshot = MeshPolicySnapshot {
            local_prefixes: self.config.all_advertised_prefixes().collect(),
            origins: Vec::new(),
            transit_by_owner: HashMap::new(),
        };
        for presence in directory.eligible() {
            snapshot
                .transit_by_owner
                .insert(presence.body.owner, presence.body.transit_enabled);
            snapshot.origins.extend(
                presence
                    .body
                    .prefixes
                    .iter()
                    .copied()
                    .map(|prefix| (presence.body.owner, prefix)),
            );
        }
        *self
            .policy
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = snapshot;
    }

    fn read_policy(&self) -> std::sync::RwLockReadGuard<'_, MeshPolicySnapshot> {
        self.policy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn excluded_underlay_candidate(
        &self,
        presence: &SignedPresence,
    ) -> Option<(SocketAddr, IpNet)> {
        presence.body.direct_addresses.iter().find_map(|address| {
            self.hidden_underlay_prefixes
                .iter()
                .copied()
                .find(|prefix| prefix.contains(&address.ip()))
                .map(|prefix| (*address, prefix))
        })
    }
}

fn build_local_presence(
    config: &Config,
    secret_key: &SecretKey,
    endpoint: &Endpoint,
    derp_public_key: Option<DerpPublicKey>,
    sequence: u64,
    now: SystemTime,
    hidden_prefixes: &[IpNet],
) -> Result<SignedPresence> {
    let endpoint_addr = endpoint.addr();
    let direct_addresses = endpoint_addr
        .ip_addrs()
        .copied()
        .filter(|address| {
            safe_underlay_ip(address.ip())
                && !hidden_prefixes
                    .iter()
                    .any(|prefix| prefix.contains(&address.ip()))
        })
        .take(MAX_ENDPOINT_CANDIDATES)
        .collect();
    let relay_urls = endpoint_addr
        .relay_urls()
        .map(ToString::to_string)
        .take(MAX_RELAY_URLS)
        .collect();
    let body = PresenceBody::from_config(
        config,
        secret_key.public(),
        sequence,
        now,
        direct_addresses,
        relay_urls,
        derp_public_key,
    )?;
    SignedPresence::sign(body, secret_key, &config.network_id)
}

async fn send_presence(connection: &Connection, presence: &SignedPresence) -> Result<()> {
    let message = ControlMessage {
        protocol: CONTROL_MAGIC.into(),
        presence: presence.clone(),
    };
    let bytes = serde_json::to_vec(&message).context("failed encoding mesh presence")?;
    ensure!(
        bytes.len() <= MAX_PRESENCE_BYTES + 512,
        "mesh control message exceeds limit"
    );
    let mut send = connection
        .open_uni()
        .await
        .context("failed opening mesh control stream")?;
    send.write_all(&bytes)
        .await
        .context("failed writing mesh control stream")?;
    send.finish()
        .context("failed finishing mesh control stream")?;
    Ok(())
}

async fn send_rendezvous_candidate(
    connection: &Connection,
    candidate: &RendezvousCandidate,
    now: u64,
) -> Result<()> {
    let message = RendezvousMessage {
        protocol: RENDEZVOUS_MAGIC.into(),
        owner: candidate.observer,
        address: candidate.address,
        observed_unix_secs: now,
        expires_unix_secs: now + RENDEZVOUS_CANDIDATE_TTL.as_secs(),
    };
    let bytes = serde_json::to_vec(&message).context("failed encoding rendezvous candidate")?;
    let mut send = connection
        .open_uni()
        .await
        .context("failed opening rendezvous control stream")?;
    send.write_all(&bytes)
        .await
        .context("failed writing rendezvous candidate")?;
    send.finish()
        .context("failed finishing rendezvous candidate")?;
    Ok(())
}

fn merge_direct_candidates<'a>(
    signed: &[SocketAddr],
    assisted: impl IntoIterator<Item = &'a RendezvousCandidate>,
) -> Vec<SocketAddr> {
    let mut seen = HashSet::new();
    signed
        .iter()
        .copied()
        .chain(assisted.into_iter().map(|candidate| candidate.address))
        .filter(|address| seen.insert(*address))
        .take(MAX_ENDPOINT_CANDIDATES)
        .collect()
}

#[derive(Debug, Default)]
struct PrefixTrie {
    nodes: Vec<TrieNode>,
}

#[derive(Debug, Default)]
struct TrieNode {
    children: [Option<usize>; 2],
    owners: Vec<EndpointId>,
}

impl PrefixTrie {
    fn insert(
        &mut self,
        owner: EndpointId,
        address: u128,
        prefix_len: u8,
        width: u8,
        conflicts: &mut HashSet<EndpointId>,
    ) {
        if self.nodes.is_empty() {
            self.nodes.push(TrieNode::default());
        }
        let mut cursor = 0;
        mark_conflicts(owner, &self.nodes[cursor].owners, conflicts);
        for bit_index in 0..prefix_len {
            let shift = width - bit_index - 1;
            let bit = ((address >> shift) & 1) as usize;
            cursor = match self.nodes[cursor].children[bit] {
                Some(child) => child,
                None => {
                    let child = self.nodes.len();
                    self.nodes.push(TrieNode::default());
                    self.nodes[cursor].children[bit] = Some(child);
                    child
                }
            };
            mark_conflicts(owner, &self.nodes[cursor].owners, conflicts);
        }
        let mut stack = self.nodes[cursor]
            .children
            .iter()
            .flatten()
            .copied()
            .collect::<Vec<_>>();
        while let Some(index) = stack.pop() {
            mark_conflicts(owner, &self.nodes[index].owners, conflicts);
            stack.extend(self.nodes[index].children.iter().flatten().copied());
        }
        if !self.nodes[cursor].owners.contains(&owner) {
            self.nodes[cursor].owners.push(owner);
        }
    }
}

fn mark_conflicts(owner: EndpointId, existing: &[EndpointId], conflicts: &mut HashSet<EndpointId>) {
    for other in existing.iter().copied().filter(|other| *other != owner) {
        conflicts.insert(owner);
        conflicts.insert(other);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PathKind {
    DirectIpv6,
    DirectIpv4,
    Relay,
    Unreachable,
}

#[derive(Debug, Clone)]
pub struct PeerMetrics {
    pub endpoint_id: EndpointId,
    pub path: PathKind,
    pub rtt_ewma: Duration,
    pub jitter_ewma: Duration,
    pub loss_ppm: u32,
    pub diversity_key: String,
    pub transit_enabled: bool,
    pub samples: u32,
    pub last_observed: Instant,
}

#[derive(Debug, Clone)]
pub struct ProbeObservation {
    pub endpoint_id: EndpointId,
    pub path: PathKind,
    pub rtt: Duration,
    pub loss_ppm: u32,
    pub diversity_key: String,
    pub transit_enabled: bool,
    pub observed_at: Instant,
}

#[derive(Debug, Clone)]
struct ActivePeer {
    activated_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PlannerDecision {
    pub activate: Vec<EndpointId>,
    pub drain: Vec<EndpointId>,
    pub reason: Option<&'static str>,
}

#[derive(Debug)]
pub struct MeshPlanner {
    max_total_peers: usize,
    pinned: HashSet<EndpointId>,
    active: HashMap<EndpointId, ActivePeer>,
    metrics: HashMap<EndpointId, PeerMetrics>,
    cooldown_until: HashMap<EndpointId, Instant>,
    challenger_streak: HashMap<EndpointId, u8>,
}

impl MeshPlanner {
    pub fn new(
        max_total_peers: usize,
        pinned: impl IntoIterator<Item = EndpointId>,
    ) -> Result<Self> {
        let pinned = pinned.into_iter().collect::<HashSet<_>>();
        ensure!(
            (1..=32).contains(&max_total_peers),
            "max peers must be between 1 and 32"
        );
        ensure!(
            pinned.len() <= max_total_peers,
            "pinned peers exceed max peers"
        );
        Ok(Self {
            max_total_peers,
            pinned,
            active: HashMap::new(),
            metrics: HashMap::new(),
            cooldown_until: HashMap::new(),
            challenger_streak: HashMap::new(),
        })
    }

    pub fn observe(&mut self, observation: ProbeObservation) {
        let ProbeObservation {
            endpoint_id,
            path,
            rtt,
            loss_ppm,
            diversity_key,
            transit_enabled,
            observed_at,
        } = observation;
        let sample_micros = duration_micros(rtt);
        self.metrics
            .entry(endpoint_id)
            .and_modify(|metrics| {
                let old = duration_micros(metrics.rtt_ewma);
                let jitter_sample = old.abs_diff(sample_micros);
                let jitter = duration_micros(metrics.jitter_ewma);
                metrics.rtt_ewma = Duration::from_micros(ewma(old, sample_micros));
                metrics.jitter_ewma = Duration::from_micros(ewma(jitter, jitter_sample));
                metrics.loss_ppm =
                    ((u64::from(metrics.loss_ppm) * 7 + u64::from(loss_ppm)) / 8) as u32;
                metrics.path = path;
                metrics.diversity_key = diversity_key.clone();
                metrics.transit_enabled = transit_enabled;
                metrics.samples = metrics.samples.saturating_add(1);
                metrics.last_observed = observed_at;
            })
            .or_insert(PeerMetrics {
                endpoint_id,
                path,
                rtt_ewma: rtt,
                jitter_ewma: Duration::ZERO,
                loss_ppm,
                diversity_key,
                transit_enabled,
                samples: 1,
                last_observed: observed_at,
            });
    }

    /// Evaluate one bounded change. Expired/ineligible adjacencies are drained
    /// immediately; normal RTT-based replacement changes at most one peer.
    pub fn evaluate(
        &mut self,
        eligible: impl IntoIterator<Item = EndpointId>,
        now: Instant,
    ) -> PlannerDecision {
        let eligible = eligible.into_iter().collect::<HashSet<_>>();
        let mut decision = PlannerDecision::default();
        let invalid = self
            .active
            .keys()
            .copied()
            .filter(|id| !eligible.contains(id))
            .collect::<Vec<_>>();
        for id in invalid {
            self.active.remove(&id);
            self.cooldown_until.insert(id, now + EVICTION_COOLDOWN);
            decision.drain.push(id);
        }
        if !decision.drain.is_empty() {
            decision.reason = Some("presence, policy, or connection no longer eligible");
        }

        self.cooldown_until.retain(|_, until| *until > now);
        let dynamic_capacity = self.max_total_peers.saturating_sub(self.pinned.len());
        if dynamic_capacity == 0 {
            return decision;
        }

        if self.active.len() < dynamic_capacity {
            if let Some(candidate) = self.best_inactive(&eligible, now) {
                self.active
                    .insert(candidate, ActivePeer { activated_at: now });
                decision.activate.push(candidate);
                decision.reason = Some("filling bounded mesh capacity");
            }
            return decision;
        }

        let Some(challenger) = self.best_inactive(&eligible, now) else {
            return decision;
        };
        let Some(incumbent) = self.worst_replaceable(now) else {
            return decision;
        };
        let challenger_score = self.score(challenger);
        let incumbent_score = self.score(incumbent);
        let required = REPLACEMENT_IMPROVEMENT_MICROS
            .max(incumbent_score.saturating_mul(REPLACEMENT_IMPROVEMENT_PERCENT) / 100);
        if challenger_score.saturating_add(required) >= incumbent_score {
            self.challenger_streak.clear();
            return decision;
        }
        let streak = {
            let streak = self.challenger_streak.entry(challenger).or_default();
            *streak = streak.saturating_add(1);
            *streak
        };
        self.challenger_streak.retain(|id, _| *id == challenger);
        if streak < REPLACEMENT_CONFIRMATIONS {
            return decision;
        }

        self.active.remove(&incumbent);
        self.active
            .insert(challenger, ActivePeer { activated_at: now });
        self.cooldown_until
            .insert(incumbent, now + EVICTION_COOLDOWN);
        self.challenger_streak.clear();
        decision.drain.push(incumbent);
        decision.activate.push(challenger);
        decision.reason = Some("stable RTT/path improvement");
        decision
    }

    /// Account for a canonical inbound adjacency selected by the remote node.
    /// The caller has already enforced the process-wide hard peer limit.
    pub fn admit_inbound(&mut self, endpoint_id: EndpointId, now: Instant) {
        let dynamic_capacity = self.max_total_peers.saturating_sub(self.pinned.len());
        if self.active.len() < dynamic_capacity {
            self.active
                .entry(endpoint_id)
                .or_insert(ActivePeer { activated_at: now });
        }
    }

    /// Roll back optimistic accounting when creating the corresponding TUN or
    /// connection task fails before the adjacency becomes active.
    pub fn activation_failed(&mut self, endpoint_id: EndpointId) {
        self.active.remove(&endpoint_id);
        self.challenger_streak.remove(&endpoint_id);
    }

    #[cfg(test)]
    fn active_total(&self) -> usize {
        self.pinned.len() + self.active.len()
    }

    #[cfg(test)]
    fn per_dynamic_peer_queue_budget(&self) -> usize {
        crate::transport::OUTBOUND_QUEUE_BYTES
            .min(MESH_BUFFER_POOL_BUDGET_BYTES / self.max_total_peers.max(1))
    }

    fn best_inactive(&self, eligible: &HashSet<EndpointId>, now: Instant) -> Option<EndpointId> {
        eligible
            .iter()
            .copied()
            .filter(|id| !self.pinned.contains(id) && !self.active.contains_key(id))
            .filter(|id| {
                self.cooldown_until
                    .get(id)
                    .is_none_or(|until| *until <= now)
            })
            .filter(|id| {
                self.metrics
                    .get(id)
                    .is_some_and(|metrics| metrics.path != PathKind::Unreachable)
            })
            .min_by_key(|id| (self.score(*id), *id))
    }

    fn worst_replaceable(&self, now: Instant) -> Option<EndpointId> {
        self.active
            .iter()
            .filter(|(_, active)| now.duration_since(active.activated_at) >= MIN_PEER_LIFETIME)
            .map(|(id, _)| *id)
            .max_by_key(|id| (self.score(*id), *id))
    }

    fn score(&self, id: EndpointId) -> u64 {
        let Some(metrics) = self.metrics.get(&id) else {
            return u64::MAX;
        };
        let path_penalty = match metrics.path {
            PathKind::DirectIpv6 => 0,
            PathKind::DirectIpv4 => 5_000,
            PathKind::Relay => 500_000,
            PathKind::Unreachable => u64::MAX / 2,
        };
        let same_domain = self
            .active
            .keys()
            .filter(|active| **active != id)
            .filter_map(|active| self.metrics.get(active))
            .filter(|active| active.diversity_key == metrics.diversity_key)
            .count() as u64;
        let has_transit = self
            .active
            .keys()
            .filter_map(|active| self.metrics.get(active))
            .any(|active| active.transit_enabled);
        duration_micros(metrics.rtt_ewma)
            .saturating_add(duration_micros(metrics.jitter_ewma).saturating_mul(2))
            .saturating_add(u64::from(metrics.loss_ppm))
            .saturating_add(path_penalty)
            .saturating_add(same_domain.saturating_mul(50_000))
            .saturating_sub(u64::from(metrics.transit_enabled && !has_transit) * 20_000)
    }
}

pub fn network_fingerprint(network_id: &str) -> [u8; 32] {
    blake3::derive_key(
        "ironet presence network fingerprint v1",
        network_id.as_bytes(),
    )
}

fn membership_tag(network_id: &str, body: &[u8], signature: &Signature) -> [u8; 32] {
    let key = blake3::derive_key(
        "ironet decentralized network admission v2",
        network_id.as_bytes(),
    );
    let mut hasher = blake3::Hasher::new_keyed(&key);
    hasher.update(body);
    hasher.update(&signature.to_bytes());
    *hasher.finalize().as_bytes()
}

fn probe_membership_tag(
    network_id: &str,
    owner: EndpointId,
    issued_unix_secs: u64,
    nonce: u64,
) -> [u8; 32] {
    let key = blake3::derive_key(
        "ironet decentralized mesh probe admission v1",
        network_id.as_bytes(),
    );
    let mut hasher = blake3::Hasher::new_keyed(&key);
    hasher.update(owner.as_bytes());
    hasher.update(&issued_unix_secs.to_be_bytes());
    hasher.update(&nonce.to_be_bytes());
    *hasher.finalize().as_bytes()
}

fn unix_secs(time: SystemTime) -> Result<u64> {
    Ok(time
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs())
}

fn sequence_file_path(config: &Config) -> PathBuf {
    let mut path = config.identity_file.as_os_str().to_owned();
    path.push(".mesh-sequence");
    PathBuf::from(path)
}

fn reserve_sequence(path: &std::path::Path, now: SystemTime) -> Result<u64> {
    let previous = match std::fs::read_to_string(path) {
        Ok(value) => value
            .trim()
            .parse::<u64>()
            .context("invalid mesh sequence state")?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => return Err(error).context("failed reading mesh sequence state"),
    };
    let current = now
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_micros()
        .min(u128::from(u64::MAX)) as u64;
    let sequence = previous.saturating_add(1).max(current).max(1);
    crate::deployment::atomic_write(path, format!("{sequence}\n").as_bytes(), 0o600)?;
    Ok(sequence)
}

fn safe_underlay_ip(ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && match ip {
            IpAddr::V4(ip) => !ip.is_link_local(),
            IpAddr::V6(ip) => !ip.is_unicast_link_local(),
        }
}

fn safe_overlay_prefix(prefix: IpNet) -> bool {
    prefix.prefix_len() != 0 && safe_underlay_ip(prefix.addr())
}

fn prefixes_overlap(left: IpNet, right: IpNet) -> bool {
    left.contains(&right.addr()) || right.contains(&left.addr())
}

fn field(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn option_field(out: &mut Vec<u8>, value: Option<String>) {
    match value {
        Some(value) => {
            out.push(1);
            field(out, value.as_bytes());
        }
        None => out.push(0),
    }
}

fn list_len(out: &mut Vec<u8>, len: usize) {
    out.extend_from_slice(&(len as u32).to_be_bytes());
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn duration_micros(duration: Duration) -> u64 {
    duration.as_micros().min(u128::from(u64::MAX)) as u64
}

fn ewma(old: u64, sample: u64) -> u64 {
    old.saturating_mul(7).saturating_add(sample) / 8
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::config::{
        AttachmentMode, FecConfig, MeshConfig, ObservabilityConfig, PacketPolicyConfig,
        RelayConfig, RoutingConfig, UdpSegmentationOffload,
    };

    use super::*;

    fn test_config() -> Config {
        Config {
            network_id: "mesh-test-secret".into(),
            identity_file: "identity.key".into(),
            bind_addresses: Vec::new(),
            excluded_underlay_prefixes: Vec::new(),
            discovery_enabled: true,
            attachment: AttachmentMode::Tun,
            tun_mtu: 1280,
            max_frame_size: 1400,
            udp_segmentation_offload: UdpSegmentationOffload::Disabled,
            quic_auto_tune: true,
            quic_cipher_preference: crate::config::QuicCipherPreference::default(),
            quic_send_buffer_bytes: crate::config::default_quic_send_buffer_bytes(),
            quic_receive_buffer_bytes: crate::config::default_quic_receive_buffer_bytes(),
            quic_data_lanes: crate::config::default_quic_data_lanes(),
            quic_congestion_controller: crate::config::QuicCongestionController::default(),
            quic_initial_rtt_millis: crate::config::default_quic_initial_rtt_millis(),
            quic_initial_mtu: crate::config::default_quic_initial_mtu(),
            quic_mtu_discovery_enabled: false,
            quic_mtu_black_hole_cooldown_millis:
                crate::config::default_quic_mtu_black_hole_cooldown_millis(),
            quic_keep_alive_millis: crate::config::default_quic_keep_alive_millis(),
            quic_passthrough_window_bytes: crate::config::default_quic_passthrough_window_bytes(),
            quic_passthrough_pacing_mbps: None,
            quic_adaptive_initial_mbps: crate::config::default_quic_adaptive_initial_mbps(),
            quic_adaptive_min_mbps: crate::config::default_quic_adaptive_min_mbps(),
            quic_adaptive_max_mbps: crate::config::default_quic_adaptive_max_mbps(),
            quic_adaptive_loss_backoff_bps: crate::config::default_quic_adaptive_loss_backoff_bps(),
            quic_pacing_quantum_bytes: crate::config::default_quic_pacing_quantum_bytes(),
            node_interface: "ironet0".into(),
            node_addresses: vec!["10.200.0.1/32".parse().unwrap()],
            advertised_prefixes: Vec::new(),
            node_info: Some(NodeInfo {
                name: "node-a".into(),
                description: None,
                metadata: BTreeMap::from([("site".into(), "test".into())]),
            }),
            path_selection: Default::default(),
            relay: RelayConfig::default(),
            peers: Vec::new(),
            links: Vec::new(),
            route_origins: Vec::new(),
            routing: RoutingConfig::default(),
            mesh: MeshConfig::default(),
            packet_policy: PacketPolicyConfig::default(),
            fec: FecConfig::default(),
            observability: ObservabilityConfig::default(),
        }
    }

    fn signed_presence(key_byte: u8, sequence: u64, prefix: &str) -> SignedPresence {
        let key = SecretKey::from_bytes(&[key_byte; 32]);
        let mut config = test_config();
        config.node_addresses = vec![prefix.parse().unwrap()];
        config.node_info = None;
        let body = PresenceBody::from_config(
            &config,
            key.public(),
            sequence,
            SystemTime::now(),
            vec![format!("192.0.2.{key_byte}:10119").parse().unwrap()],
            Vec::new(),
            None,
        )
        .unwrap();
        SignedPresence::sign(body, &key, &config.network_id).unwrap()
    }

    #[test]
    fn presence_authenticates_owner_and_network() {
        let config = test_config();
        let key = SecretKey::from_bytes(&[7; 32]);
        let body = PresenceBody::from_config(
            &config,
            key.public(),
            1,
            SystemTime::now(),
            vec!["192.0.2.7:10119".parse().unwrap()],
            vec!["https://relay.example.com".into()],
            None,
        )
        .unwrap();
        let mut signed = SignedPresence::sign(body, &key, &config.network_id).unwrap();
        signed
            .verify(&config.network_id, SystemTime::now())
            .unwrap();
        assert!(signed.verify("other-network", SystemTime::now()).is_err());
        signed.body.transit_enabled = true;
        assert!(
            signed
                .verify(&config.network_id, SystemTime::now())
                .is_err()
        );
        signed.body.transit_enabled = false;
        signed.body.sequence += 1;
        assert!(
            signed
                .verify(&config.network_id, SystemTime::now())
                .is_err()
        );
    }

    #[test]
    fn peer_assisted_candidates_extend_signed_presence_without_duplicates() {
        let signed = vec![
            "198.51.100.10:4000".parse().unwrap(),
            "[2001:db8::10]:4000".parse().unwrap(),
        ];
        let observer_a = SecretKey::from_bytes(&[31; 32]).public();
        let observer_b = SecretKey::from_bytes(&[32; 32]).public();
        let assisted = vec![
            RendezvousCandidate {
                address: signed[0],
                observer: observer_a,
                expires_unix_secs: 10,
            },
            RendezvousCandidate {
                address: "203.0.113.10:50123".parse().unwrap(),
                observer: observer_b,
                expires_unix_secs: 10,
            },
        ];

        assert_eq!(
            merge_direct_candidates(&signed, &assisted),
            vec![signed[0], signed[1], "203.0.113.10:50123".parse().unwrap(),]
        );
    }

    #[test]
    fn directory_is_bounded_and_rejects_stale_sequences() {
        let local = SecretKey::from_bytes(&[100; 32]).public();
        let mut directory = Directory::with_capacity(local, 3);
        let monotonic = Instant::now();
        for byte in 1..=4 {
            directory
                .insert(
                    signed_presence(byte, 2, &format!("10.0.{byte}.1/32")),
                    "mesh-test-secret",
                    SystemTime::now(),
                    monotonic + Duration::from_secs(u64::from(byte)),
                )
                .unwrap();
        }
        assert_eq!(directory.len(), 3);
        let stale = signed_presence(4, 1, "10.0.4.1/32");
        assert_eq!(
            directory
                .insert(stale, "mesh-test-secret", SystemTime::now(), monotonic)
                .unwrap(),
            InsertOutcome::Stale
        );
    }

    #[test]
    fn overlapping_prefix_owners_are_quarantined() {
        let local = SecretKey::from_bytes(&[100; 32]).public();
        let first = signed_presence(1, 1, "10.44.0.0/16");
        let second = signed_presence(2, 1, "10.44.7.0/24");
        let mut directory = Directory::new(local);
        let now = Instant::now();
        directory
            .insert(first.clone(), "mesh-test-secret", SystemTime::now(), now)
            .unwrap();
        directory
            .insert(second.clone(), "mesh-test-secret", SystemTime::now(), now)
            .unwrap();
        assert!(directory.is_quarantined(first.body.owner));
        assert!(directory.is_quarantined(second.body.owner));
        assert_eq!(directory.eligible().count(), 0);
    }

    #[test]
    fn a_remote_owner_cannot_claim_a_local_prefix() {
        let local = SecretKey::from_bytes(&[100; 32]).public();
        let remote = signed_presence(1, 1, "10.44.7.0/24");
        let mut directory = Directory::with_reserved(local, ["10.44.0.0/16".parse().unwrap()]);
        directory
            .insert(
                remote.clone(),
                "mesh-test-secret",
                SystemTime::now(),
                Instant::now(),
            )
            .unwrap();
        assert!(directory.is_quarantined(remote.body.owner));
        assert_eq!(directory.eligible().count(), 0);
    }

    #[test]
    fn planner_never_exceeds_total_peer_limit() {
        let pinned = SecretKey::from_bytes(&[90; 32]).public();
        let mut planner = MeshPlanner::new(8, [pinned]).unwrap();
        let now = Instant::now();
        let ids = (1..=50)
            .map(|byte| SecretKey::from_bytes(&[byte; 32]).public())
            .collect::<Vec<_>>();
        for (index, id) in ids.iter().copied().enumerate() {
            planner.observe(ProbeObservation {
                endpoint_id: id,
                path: PathKind::DirectIpv4,
                rtt: Duration::from_millis(10 + index as u64),
                loss_ppm: 0,
                diversity_key: format!("v4-{}", index % 8),
                transit_enabled: index == 7,
                observed_at: now,
            });
        }
        for round in 0..100 {
            planner.evaluate(ids.iter().copied(), now + Duration::from_secs(round * 30));
            assert!(planner.active_total() <= 8);
            assert!(planner.per_dynamic_peer_queue_budget() <= MESH_BUFFER_POOL_BUDGET_BYTES);
        }
        assert_eq!(planner.active_total(), 8);
    }

    #[test]
    fn planner_requires_stable_improvement_and_observes_cooldown() {
        let incumbent = SecretKey::from_bytes(&[1; 32]).public();
        let challenger = SecretKey::from_bytes(&[2; 32]).public();
        let now = Instant::now();
        let mut planner = MeshPlanner::new(1, []).unwrap();
        planner.observe(ProbeObservation {
            endpoint_id: incumbent,
            path: PathKind::DirectIpv4,
            rtt: Duration::from_millis(100),
            loss_ppm: 0,
            diversity_key: "old".into(),
            transit_enabled: false,
            observed_at: now,
        });
        assert_eq!(
            planner.evaluate([incumbent, challenger], now).activate,
            vec![incumbent]
        );
        planner.observe(ProbeObservation {
            endpoint_id: challenger,
            path: PathKind::DirectIpv4,
            rtt: Duration::from_millis(20),
            loss_ppm: 0,
            diversity_key: "new".into(),
            transit_enabled: false,
            observed_at: now,
        });
        let eligible = [incumbent, challenger];
        let mature = now + MIN_PEER_LIFETIME;
        assert!(planner.evaluate(eligible, mature).activate.is_empty());
        assert!(
            planner
                .evaluate(eligible, mature + EVALUATION_INTERVAL)
                .activate
                .is_empty()
        );
        let replaced = planner.evaluate(eligible, mature + EVALUATION_INTERVAL * 2);
        assert_eq!(replaced.drain, vec![incumbent]);
        assert_eq!(replaced.activate, vec![challenger]);
        assert!(
            planner
                .evaluate(eligible, mature + EVICTION_COOLDOWN / 2)
                .activate
                .is_empty()
        );
    }

    #[test]
    fn rtt_uses_slow_ewma_instead_of_last_sample() {
        let id = SecretKey::from_bytes(&[3; 32]).public();
        let now = Instant::now();
        let mut planner = MeshPlanner::new(2, []).unwrap();
        planner.observe(ProbeObservation {
            endpoint_id: id,
            path: PathKind::DirectIpv6,
            rtt: Duration::from_millis(80),
            loss_ppm: 0,
            diversity_key: "v6-a".into(),
            transit_enabled: false,
            observed_at: now,
        });
        planner.observe(ProbeObservation {
            endpoint_id: id,
            path: PathKind::DirectIpv6,
            rtt: Duration::from_millis(16),
            loss_ppm: 0,
            diversity_key: "v6-a".into(),
            transit_enabled: false,
            observed_at: now,
        });
        assert_eq!(planner.metrics[&id].rtt_ewma, Duration::from_millis(72));
        assert_eq!(planner.metrics[&id].jitter_ewma, Duration::from_millis(8));
    }

    #[test]
    fn failed_activation_releases_the_hard_capacity_slot() {
        let id = SecretKey::from_bytes(&[4; 32]).public();
        let now = Instant::now();
        let mut planner = MeshPlanner::new(1, []).unwrap();
        planner.observe(ProbeObservation {
            endpoint_id: id,
            path: PathKind::DirectIpv4,
            rtt: Duration::from_millis(10),
            loss_ppm: 0,
            diversity_key: "v4-test".into(),
            transit_enabled: false,
            observed_at: now,
        });
        assert_eq!(planner.evaluate([id], now).activate, vec![id]);
        planner.activation_failed(id);
        assert_eq!(planner.active_total(), 0);
        assert_eq!(
            planner.evaluate([id], now + EVALUATION_INTERVAL).activate,
            vec![id]
        );
    }
}

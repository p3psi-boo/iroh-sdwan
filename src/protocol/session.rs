use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use iroh::{
    EndpointId,
    endpoint::{Connection, Side},
};
use serde::{Deserialize, Serialize};

use super::{
    MAJOR, MAX_MINOR, MIN_MINOR,
    feature::{FeatureOffer, NegotiatedFeature, negotiate, validate_selection},
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RECORD_BYTES: usize = 32 * 1024;
const HELLO_KIND: &str = "hello";
const ACK_KIND: &str = "hello-ack";
const READY_KIND: &str = "ready";
static NONCE_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct LinkAuthentication {
    pub link_id: String,
    pub secret: [u8; 32],
}

/// Bounds advertised by one endpoint. In automatic mode these are ceilings,
/// not a request to start at the maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportCapabilities {
    pub auto_tune: bool,
    pub max_data_lanes: u8,
    pub fec_supported: bool,
    pub fec_initial: bool,
    pub max_frame_size: u16,
    pub send_buffer_bytes: u32,
    pub receive_buffer_bytes: u32,
    /// Zero means no explicit outer pacing ceiling.
    pub max_pacing_mbps: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectionalTransportProfile {
    pub frame_size: u16,
    pub data_lanes: u8,
    pub fec_enabled: bool,
    pub send_buffer_bytes: u32,
    pub receive_buffer_bytes: u32,
    /// Zero means no explicit outer pacing ceiling.
    pub pacing_mbps: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportProfile {
    /// Settings for traffic sent by this endpoint.
    pub outbound: DirectionalTransportProfile,
    /// Settings for traffic received by this endpoint.
    pub inbound: DirectionalTransportProfile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct WireTransportProfile {
    client_to_server: DirectionalTransportProfile,
    server_to_client: DirectionalTransportProfile,
}

#[derive(Debug, Clone)]
pub struct SessionPolicy {
    pub network_id: String,
    pub local_id: EndpointId,
    pub remote_id: EndpointId,
    pub max_datagram_size: u32,
    pub max_control_size: u32,
    pub features: Vec<FeatureOffer>,
    pub transport: TransportCapabilities,
    pub request_data_lane: bool,
    pub link: Option<LinkAuthentication>,
    /// Invite used to admit the local identity. Creator and legacy configurations omit it.
    pub local_invite_id: Option<String>,
    /// Present only on the network authority. Maps issued invite IDs to member identity and
    /// revocation state.
    pub authority_invites: Option<BTreeMap<String, (EndpointId, bool)>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedSession {
    pub minor: u16,
    pub max_datagram_size: u32,
    pub max_control_size: u32,
    pub features: Vec<NegotiatedFeature>,
    pub link_id: Option<String>,
    pub transport: Option<TransportProfile>,
    pub data_lane: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct Hello {
    kind: String,
    major: u16,
    min_minor: u16,
    max_minor: u16,
    owner: EndpointId,
    nonce: [u8; 32],
    max_datagram_size: u32,
    max_control_size: u32,
    features: Vec<FeatureOffer>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transport: Option<TransportCapabilities>,
    #[serde(default, skip_serializing_if = "is_false")]
    data_lane: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    link_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    invite_id: Option<String>,
    membership_proof: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    link_proof: Option<[u8; 32]>,
}

#[derive(Debug, Serialize, Deserialize)]
struct HelloAck {
    kind: String,
    major: u16,
    minor: u16,
    owner: EndpointId,
    client_nonce: [u8; 32],
    server_nonce: [u8; 32],
    max_datagram_size: u32,
    max_control_size: u32,
    features: Vec<NegotiatedFeature>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transport: Option<WireTransportProfile>,
    #[serde(default, skip_serializing_if = "is_false")]
    data_lane: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    link_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    invite_id: Option<String>,
    membership_proof: [u8; 32],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    link_proof: Option<[u8; 32]>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Ready {
    kind: String,
    transcript: [u8; 32],
}

pub async fn negotiate_connection(
    connection: &Connection,
    policy: &SessionPolicy,
) -> Result<NegotiatedSession> {
    ensure!(
        connection.remote_id() == policy.remote_id,
        "session peer identity mismatch"
    );
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        match connection.side() {
            Side::Client => client(connection, policy).await,
            Side::Server => server(connection, policy).await,
        }
    })
    .await
    .context("v1 session handshake timed out")?
}

async fn client(connection: &Connection, policy: &SessionPolicy) -> Result<NegotiatedSession> {
    let (mut send, mut receive) = connection
        .open_bi()
        .await
        .context("opening v1 session stream")?;
    let nonce = nonce(policy.local_id, policy.remote_id);
    let hello = make_hello(policy, nonce);
    let hello_bytes = serde_json::to_vec(&hello)?;
    write_record(&mut send, &hello_bytes).await?;
    let ack_bytes = read_record(&mut receive).await?;
    let ack: HelloAck =
        serde_json::from_slice(&ack_bytes).context("invalid v1 hello acknowledgement")?;
    validate_ack(policy, &hello, &ack)?;
    let transcript = transcript(&hello_bytes, &ack_bytes);
    write_record(
        &mut send,
        &serde_json::to_vec(&Ready {
            kind: READY_KIND.into(),
            transcript,
        })?,
    )
    .await?;
    send.finish().context("finishing v1 session stream")?;
    Ok(session_from_ack(ack, Side::Client))
}

async fn server(connection: &Connection, policy: &SessionPolicy) -> Result<NegotiatedSession> {
    let (mut send, mut receive) = connection
        .accept_bi()
        .await
        .context("accepting v1 session stream")?;
    let hello_bytes = read_record(&mut receive).await?;
    let hello: Hello = serde_json::from_slice(&hello_bytes).context("invalid v1 hello")?;
    validate_hello(policy, &hello)?;
    let features = negotiate(&policy.features, &hello.features)?;
    let server_nonce = nonce(policy.local_id, policy.remote_id);
    let minor = compatible_minor(MIN_MINOR, MAX_MINOR, hello.min_minor, hello.max_minor)
        .context("no compatible v1 minor version")?;
    let mut ack = HelloAck {
        kind: ACK_KIND.into(),
        major: MAJOR,
        minor,
        owner: policy.local_id,
        client_nonce: hello.nonce,
        server_nonce,
        max_datagram_size: policy.max_datagram_size.min(hello.max_datagram_size),
        max_control_size: policy.max_control_size.min(hello.max_control_size),
        features,
        transport: hello.transport.map(|client| WireTransportProfile {
            client_to_server: select_direction(client, policy.transport),
            server_to_client: select_direction(policy.transport, client),
        }),
        data_lane: hello.data_lane,
        link_id: policy.link.as_ref().map(|link| link.link_id.clone()),
        invite_id: policy.local_invite_id.clone(),
        membership_proof: [0; 32],
        link_proof: None,
    };
    ack.membership_proof = ack_proof(&policy.network_id, &ack);
    ack.link_proof = policy.link.as_ref().map(|link| link_ack_proof(link, &ack));
    let ack_bytes = serde_json::to_vec(&ack)?;
    write_record(&mut send, &ack_bytes).await?;
    let ready_bytes = read_record(&mut receive).await?;
    let ready: Ready = serde_json::from_slice(&ready_bytes).context("invalid v1 ready record")?;
    ensure!(ready.kind == READY_KIND, "invalid v1 ready kind");
    ensure!(
        constant_time_eq(&ready.transcript, &transcript(&hello_bytes, &ack_bytes)),
        "v1 session transcript mismatch"
    );
    send.finish().context("finishing v1 session response")?;
    Ok(session_from_ack(ack, Side::Server))
}

fn make_hello(policy: &SessionPolicy, nonce: [u8; 32]) -> Hello {
    let mut hello = Hello {
        kind: HELLO_KIND.into(),
        major: MAJOR,
        min_minor: MIN_MINOR,
        max_minor: MAX_MINOR,
        owner: policy.local_id,
        nonce,
        max_datagram_size: policy.max_datagram_size,
        max_control_size: policy.max_control_size,
        features: policy.features.clone(),
        transport: Some(policy.transport),
        data_lane: policy.request_data_lane,
        link_id: policy.link.as_ref().map(|link| link.link_id.clone()),
        invite_id: policy.local_invite_id.clone(),
        membership_proof: [0; 32],
        link_proof: None,
    };
    hello.membership_proof = hello_proof(&policy.network_id, &hello);
    hello.link_proof = policy
        .link
        .as_ref()
        .map(|link| link_hello_proof(link, &hello));
    hello
}

fn validate_hello(policy: &SessionPolicy, hello: &Hello) -> Result<()> {
    ensure!(
        hello.kind == HELLO_KIND && hello.major == MAJOR,
        "unsupported session protocol"
    );
    ensure!(
        hello.owner == policy.remote_id,
        "v1 hello identity mismatch"
    );
    ensure!(
        compatible_minor(MIN_MINOR, MAX_MINOR, hello.min_minor, hello.max_minor).is_some(),
        "no compatible v1 minor version"
    );
    ensure!(
        hello.max_datagram_size >= 256,
        "peer datagram limit is too small"
    );
    ensure!(
        hello.max_control_size >= 1024,
        "peer control limit is too small"
    );
    ensure!(
        !hello.data_lane
            || (hello
                .transport
                .is_some_and(|transport| transport.max_data_lanes > 1)
                && policy.transport.max_data_lanes > 1),
        "peer requested an unsupported parallel data lane"
    );
    ensure!(
        constant_time_eq(
            &hello.membership_proof,
            &hello_proof(&policy.network_id, hello)
        ),
        "invalid v1 network membership proof"
    );
    validate_invite(policy, hello.invite_id.as_deref())?;
    validate_link_hello(policy, hello)
}

fn validate_ack(policy: &SessionPolicy, hello: &Hello, ack: &HelloAck) -> Result<()> {
    ensure!(
        ack.kind == ACK_KIND
            && ack.major == MAJOR
            && (MIN_MINOR..=MAX_MINOR).contains(&ack.minor)
            && (hello.min_minor..=hello.max_minor).contains(&ack.minor),
        "unsupported v1 acknowledgement"
    );
    ensure!(
        ack.owner == policy.remote_id && ack.client_nonce == hello.nonce,
        "v1 acknowledgement identity mismatch"
    );
    ensure!(
        ack.data_lane == hello.data_lane,
        "peer did not acknowledge the requested connection role"
    );
    ensure!(
        ack.max_datagram_size <= policy.max_datagram_size
            && ack.max_datagram_size >= 256
            && ack.max_control_size <= policy.max_control_size
            && ack.max_control_size >= 1024,
        "v1 acknowledgement exceeds local limits"
    );
    ensure!(
        constant_time_eq(&ack.membership_proof, &ack_proof(&policy.network_id, ack)),
        "invalid v1 acknowledgement membership proof"
    );
    validate_invite(policy, ack.invite_id.as_deref())?;
    validate_selection(&policy.features, &ack.features)?;
    if let Some(profile) = ack.transport {
        validate_transport_profile(policy.transport, profile)?;
    }
    validate_link_ack(policy, ack)
}

fn validate_invite(policy: &SessionPolicy, invite_id: Option<&str>) -> Result<()> {
    let Some(invites) = &policy.authority_invites else {
        return Ok(());
    };
    let invite_id = invite_id.context("network authority requires an issued member invite")?;
    let (member, revoked) = invites
        .get(invite_id)
        .with_context(|| format!("unknown member invite {invite_id}"))?;
    ensure!(!revoked, "member invite {invite_id} has been revoked");
    ensure!(
        *member == policy.remote_id,
        "member invite {invite_id} belongs to a different node identity"
    );
    Ok(())
}

fn validate_link_hello(policy: &SessionPolicy, hello: &Hello) -> Result<()> {
    match (&policy.link, &hello.link_id, &hello.link_proof) {
        (None, None, None) => Ok(()),
        (Some(link), Some(id), Some(proof)) if id == &link.link_id => {
            ensure!(
                constant_time_eq(proof, &link_hello_proof(link, hello)),
                "invalid pairwise link proof"
            );
            Ok(())
        }
        _ => bail!("pairwise link contract mismatch"),
    }
}

fn validate_link_ack(policy: &SessionPolicy, ack: &HelloAck) -> Result<()> {
    match (&policy.link, &ack.link_id, &ack.link_proof) {
        (None, None, None) => Ok(()),
        (Some(link), Some(id), Some(proof)) if id == &link.link_id => {
            ensure!(
                constant_time_eq(proof, &link_ack_proof(link, ack)),
                "invalid pairwise link acknowledgement proof"
            );
            Ok(())
        }
        _ => bail!("pairwise link contract mismatch"),
    }
}

fn session_from_ack(ack: HelloAck, side: Side) -> NegotiatedSession {
    let transport = ack.transport.map(|profile| match side {
        Side::Client => TransportProfile {
            outbound: profile.client_to_server,
            inbound: profile.server_to_client,
        },
        Side::Server => TransportProfile {
            outbound: profile.server_to_client,
            inbound: profile.client_to_server,
        },
    });
    NegotiatedSession {
        minor: ack.minor,
        max_datagram_size: ack.max_datagram_size,
        max_control_size: ack.max_control_size,
        features: ack.features,
        link_id: ack.link_id,
        transport,
        data_lane: ack.data_lane,
    }
}

fn select_direction(
    sender: TransportCapabilities,
    receiver: TransportCapabilities,
) -> DirectionalTransportProfile {
    let data_lanes = sender.max_data_lanes.min(receiver.max_data_lanes).max(1);
    let pacing_mbps = match (sender.max_pacing_mbps, receiver.max_pacing_mbps) {
        (0, value) | (value, 0) => value,
        (left, right) => left.min(right),
    };
    DirectionalTransportProfile {
        frame_size: sender.max_frame_size.min(receiver.max_frame_size).max(256),
        data_lanes,
        fec_enabled: sender.fec_supported
            && receiver.fec_supported
            && (sender.fec_initial || receiver.fec_initial),
        send_buffer_bytes: sender.send_buffer_bytes,
        receive_buffer_bytes: receiver.receive_buffer_bytes,
        pacing_mbps,
    }
}

fn validate_transport_profile(
    local: TransportCapabilities,
    profile: WireTransportProfile,
) -> Result<()> {
    let inbound = profile.server_to_client;
    let outbound = profile.client_to_server;
    ensure!(
        outbound.frame_size <= local.max_frame_size
            && inbound.frame_size <= local.max_frame_size
            && outbound.frame_size >= 256
            && inbound.frame_size >= 256,
        "negotiated transport frame size exceeds local limits"
    );
    ensure!(
        outbound.data_lanes >= 1
            && inbound.data_lanes >= 1
            && outbound.data_lanes <= local.max_data_lanes
            && inbound.data_lanes <= local.max_data_lanes,
        "negotiated transport lane count exceeds local limits"
    );
    ensure!(
        (!outbound.fec_enabled && !inbound.fec_enabled) || local.fec_supported,
        "peer enabled unsupported FEC"
    );
    ensure!(
        outbound.send_buffer_bytes <= local.send_buffer_bytes
            && inbound.receive_buffer_bytes <= local.receive_buffer_bytes,
        "negotiated transport buffer exceeds local limits"
    );
    ensure!(
        local.max_pacing_mbps == 0
            || (outbound.pacing_mbps != 0
                && outbound.pacing_mbps <= local.max_pacing_mbps
                && inbound.pacing_mbps != 0
                && inbound.pacing_mbps <= local.max_pacing_mbps),
        "negotiated transport pacing exceeds local limits"
    );
    Ok(())
}

fn compatible_minor(
    local_min: u16,
    local_max: u16,
    remote_min: u16,
    remote_max: u16,
) -> Option<u16> {
    let minimum = local_min.max(remote_min);
    let maximum = local_max.min(remote_max);
    (minimum <= maximum).then_some(maximum)
}

fn hello_proof(network_id: &str, hello: &Hello) -> [u8; 32] {
    keyed(
        network_id.as_bytes(),
        &[b"ironet-v1-hello", &hello_unsigned(hello)],
    )
}

fn ack_proof(network_id: &str, ack: &HelloAck) -> [u8; 32] {
    keyed(
        network_id.as_bytes(),
        &[b"ironet-v1-ack", &ack_unsigned(ack)],
    )
}

fn link_hello_proof(link: &LinkAuthentication, hello: &Hello) -> [u8; 32] {
    keyed(
        &link.secret,
        &[
            b"ironet-v1-link-hello",
            link.link_id.as_bytes(),
            &hello_unsigned(hello),
        ],
    )
}

fn link_ack_proof(link: &LinkAuthentication, ack: &HelloAck) -> [u8; 32] {
    keyed(
        &link.secret,
        &[
            b"ironet-v1-link-ack",
            link.link_id.as_bytes(),
            &ack_unsigned(ack),
        ],
    )
}

fn hello_unsigned(hello: &Hello) -> Vec<u8> {
    serde_json::to_vec(&Hello {
        kind: hello.kind.clone(),
        major: hello.major,
        min_minor: hello.min_minor,
        max_minor: hello.max_minor,
        owner: hello.owner,
        nonce: hello.nonce,
        max_datagram_size: hello.max_datagram_size,
        max_control_size: hello.max_control_size,
        features: hello.features.clone(),
        transport: None,
        data_lane: false,
        link_id: hello.link_id.clone(),
        invite_id: hello.invite_id.clone(),
        membership_proof: [0; 32],
        link_proof: None,
    })
    .expect("v1 hello is serializable")
}

fn ack_unsigned(ack: &HelloAck) -> Vec<u8> {
    serde_json::to_vec(&HelloAck {
        kind: ack.kind.clone(),
        major: ack.major,
        minor: ack.minor,
        owner: ack.owner,
        client_nonce: ack.client_nonce,
        server_nonce: ack.server_nonce,
        max_datagram_size: ack.max_datagram_size,
        max_control_size: ack.max_control_size,
        features: ack.features.clone(),
        transport: None,
        data_lane: false,
        link_id: ack.link_id.clone(),
        invite_id: ack.invite_id.clone(),
        membership_proof: [0; 32],
        link_proof: None,
    })
    .expect("v1 acknowledgement is serializable")
}

fn keyed(secret: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let key = *blake3::hash(secret).as_bytes();
    let mut hasher = blake3::Hasher::new_keyed(&key);
    for part in parts {
        hasher.update(&(part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

fn transcript(hello: &[u8], ack: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ironet-v1-transcript");
    hasher.update(hello);
    hasher.update(ack);
    *hasher.finalize().as_bytes()
}

fn nonce(local: EndpointId, remote: EndpointId) -> [u8; 32] {
    let counter = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"ironet-v1-nonce");
    hasher.update(local.as_bytes());
    hasher.update(remote.as_bytes());
    hasher.update(&counter.to_be_bytes());
    hasher.update(&now.to_be_bytes());
    *hasher.finalize().as_bytes()
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

fn is_false(value: &bool) -> bool {
    !*value
}

async fn write_record(send: &mut iroh::endpoint::SendStream, bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() <= MAX_RECORD_BYTES,
        "v1 session record exceeds limit"
    );
    send.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    send.write_all(bytes).await?;
    Ok(())
}

async fn read_record(receive: &mut iroh::endpoint::RecvStream) -> Result<Vec<u8>> {
    let mut length = [0_u8; 4];
    receive.read_exact(&mut length).await?;
    let length = u32::from_be_bytes(length) as usize;
    ensure!(
        length <= MAX_RECORD_BYTES,
        "v1 session record exceeds limit"
    );
    let mut bytes = vec![0; length];
    receive.read_exact(&mut bytes).await?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey, endpoint::presets};

    use super::*;
    use crate::protocol::feature;

    async fn connections() -> (Endpoint, Endpoint, Connection, Connection) {
        let alpn = b"ironet/session-v1-test".to_vec();
        let client_key = SecretKey::generate();
        let server_key = SecretKey::generate();
        let client = Endpoint::builder(presets::N0)
            .secret_key(client_key)
            .alpns(vec![alpn.clone()])
            .relay_mode(RelayMode::Disabled)
            .clear_address_lookup()
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let server = Endpoint::builder(presets::N0)
            .secret_key(server_key.clone())
            .alpns(vec![alpn.clone()])
            .relay_mode(RelayMode::Disabled)
            .clear_address_lookup()
            .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
            .unwrap()
            .bind()
            .await
            .unwrap();
        let address = *server.addr().ip_addrs().next().unwrap();
        let target = EndpointAddr::new(server_key.public()).with_ip_addr(address);
        let (client_connection, server_connection) =
            tokio::join!(client.connect(target, &alpn), async {
                server.accept().await.unwrap().accept().unwrap().await
            });
        (
            client,
            server,
            client_connection.unwrap(),
            server_connection.unwrap(),
        )
    }

    fn policy(network_id: &str, local_id: EndpointId, remote_id: EndpointId) -> SessionPolicy {
        SessionPolicy {
            network_id: network_id.into(),
            local_id,
            remote_id,
            max_datagram_size: 1_400,
            max_control_size: 32 * 1024,
            features: feature::core_offers(true, true, true, false),
            transport: TransportCapabilities {
                auto_tune: true,
                max_data_lanes: 4,
                fec_supported: true,
                fec_initial: false,
                max_frame_size: 1_400,
                send_buffer_bytes: 131_072,
                receive_buffer_bytes: 8 * 1024 * 1024,
                max_pacing_mbps: 0,
            },
            request_data_lane: false,
            link: None,
            local_invite_id: None,
            authority_invites: None,
        }
    }

    async fn negotiate_pair(
        client: &Connection,
        server: &Connection,
        client_policy: &SessionPolicy,
        server_policy: &SessionPolicy,
    ) -> (Result<NegotiatedSession>, Result<NegotiatedSession>) {
        tokio::join!(
            negotiate_connection(client, client_policy),
            negotiate_connection(server, server_policy)
        )
    }

    #[test]
    fn authority_binds_invites_to_members_and_enforces_revocation() {
        let authority = iroh::SecretKey::generate().public();
        let member = iroh::SecretKey::generate().public();
        let mut member_policy = policy("network-a", member, authority);
        member_policy.local_invite_id = Some("invite-a".into());
        let hello = make_hello(&member_policy, [7; 32]);

        let mut authority_policy = policy("network-a", authority, member);
        authority_policy.authority_invites =
            Some(BTreeMap::from([("invite-a".into(), (member, false))]));
        validate_hello(&authority_policy, &hello).unwrap();

        authority_policy.authority_invites =
            Some(BTreeMap::from([("invite-a".into(), (member, true))]));
        assert!(
            validate_hello(&authority_policy, &hello)
                .unwrap_err()
                .to_string()
                .contains("revoked")
        );

        authority_policy.authority_invites = Some(BTreeMap::from([(
            "invite-a".into(),
            (iroh::SecretKey::generate().public(), false),
        )]));
        assert!(
            validate_hello(&authority_policy, &hello)
                .unwrap_err()
                .to_string()
                .contains("different node identity")
        );
    }

    #[tokio::test]
    async fn quic_session_negotiates_limits_and_optional_features() {
        let (client_endpoint, server_endpoint, client, server) = connections().await;
        let mut client_policy = policy("network-a", client_endpoint.id(), server_endpoint.id());
        let mut server_policy = policy("network-a", server_endpoint.id(), client_endpoint.id());
        client_policy.max_datagram_size = 1_350;
        client_policy.max_control_size = 16 * 1024;
        server_policy.max_datagram_size = 1_200;
        server_policy.max_control_size = 8 * 1024;
        server_policy
            .features
            .retain(|offer| offer.id != feature::FEC);

        let (client_session, server_session) =
            negotiate_pair(&client, &server, &client_policy, &server_policy).await;
        let client_session = client_session.unwrap();
        let server_session = server_session.unwrap();
        assert_eq!(client_session, server_session);
        assert_eq!(client_session.minor, MAX_MINOR);
        assert_eq!(client_session.max_datagram_size, 1_200);
        assert_eq!(client_session.max_control_size, 8 * 1024);
        let selected = client_session
            .features
            .iter()
            .map(|feature| feature.id)
            .collect::<HashSet<_>>();
        assert!(selected.contains(&feature::DATA_PLANE));
        assert!(!selected.contains(&feature::FEC));
        client.close(0_u8.into(), b"done");
        client_endpoint.close().await;
        server_endpoint.close().await;
    }

    #[tokio::test]
    async fn transport_profile_is_directional_and_starts_conservatively() {
        let (client_endpoint, server_endpoint, client, server) = connections().await;
        let mut client_policy = policy("network-a", client_endpoint.id(), server_endpoint.id());
        let mut server_policy = policy("network-a", server_endpoint.id(), client_endpoint.id());
        client_policy.transport.send_buffer_bytes = 64 * 1024;
        client_policy.transport.receive_buffer_bytes = 4 * 1024 * 1024;
        server_policy.transport.send_buffer_bytes = 256 * 1024;
        server_policy.transport.receive_buffer_bytes = 16 * 1024 * 1024;

        let (client_session, server_session) =
            negotiate_pair(&client, &server, &client_policy, &server_policy).await;
        let client_profile = client_session.unwrap().transport.unwrap();
        let server_profile = server_session.unwrap().transport.unwrap();
        assert_eq!(client_profile.outbound, server_profile.inbound);
        assert_eq!(client_profile.inbound, server_profile.outbound);
        assert_eq!(client_profile.outbound.data_lanes, 4);
        assert!(!client_profile.outbound.fec_enabled);
        assert_eq!(client_profile.outbound.send_buffer_bytes, 64 * 1024);
        assert_eq!(
            client_profile.outbound.receive_buffer_bytes,
            16 * 1024 * 1024
        );
        assert_eq!(client_profile.inbound.send_buffer_bytes, 256 * 1024);
        assert_eq!(client_profile.inbound.receive_buffer_bytes, 4 * 1024 * 1024);
        client.close(0_u8.into(), b"done");
        client_endpoint.close().await;
        server_endpoint.close().await;
    }

    #[tokio::test]
    async fn parallel_lane_role_is_explicitly_acknowledged() {
        let (client_endpoint, server_endpoint, client, server) = connections().await;
        let mut client_policy = policy("network-a", client_endpoint.id(), server_endpoint.id());
        let server_policy = policy("network-a", server_endpoint.id(), client_endpoint.id());
        client_policy.request_data_lane = true;
        let (client_session, server_session) =
            negotiate_pair(&client, &server, &client_policy, &server_policy).await;
        assert!(client_session.unwrap().data_lane);
        assert!(server_session.unwrap().data_lane);
        client.close(0_u8.into(), b"done");
        client_endpoint.close().await;
        server_endpoint.close().await;
    }

    #[tokio::test]
    async fn quic_session_rejects_wrong_network_membership() {
        let (client_endpoint, server_endpoint, client, server) = connections().await;
        let client_policy = policy("network-a", client_endpoint.id(), server_endpoint.id());
        let server_policy = policy("network-b", server_endpoint.id(), client_endpoint.id());
        let (client_result, server_result) =
            negotiate_pair(&client, &server, &client_policy, &server_policy).await;
        assert!(client_result.is_err());
        assert!(server_result.is_err());
        client_endpoint.close().await;
        server_endpoint.close().await;
    }

    #[tokio::test]
    async fn quic_session_rejects_pairwise_secret_or_contract_mismatch() {
        let (client_endpoint, server_endpoint, client, server) = connections().await;
        let mut client_policy = policy("network-a", client_endpoint.id(), server_endpoint.id());
        let mut server_policy = policy("network-a", server_endpoint.id(), client_endpoint.id());
        client_policy.link = Some(LinkAuthentication {
            link_id: "iepl-ab".into(),
            secret: [7; 32],
        });
        server_policy.link = Some(LinkAuthentication {
            link_id: "iepl-ab".into(),
            secret: [8; 32],
        });
        client_policy.features = feature::core_offers(true, false, false, true);
        server_policy.features = feature::core_offers(true, false, false, true);

        let (client_result, server_result) =
            negotiate_pair(&client, &server, &client_policy, &server_policy).await;
        assert!(client_result.is_err());
        assert!(server_result.is_err());
        client_endpoint.close().await;
        server_endpoint.close().await;
    }

    #[tokio::test]
    async fn quic_session_authenticates_matching_pairwise_link() {
        let (client_endpoint, server_endpoint, client, server) = connections().await;
        let mut client_policy = policy("network-a", client_endpoint.id(), server_endpoint.id());
        let mut server_policy = policy("network-a", server_endpoint.id(), client_endpoint.id());
        let authentication = LinkAuthentication {
            link_id: "iepl-ab".into(),
            secret: [7; 32],
        };
        client_policy.link = Some(authentication.clone());
        server_policy.link = Some(authentication);
        client_policy.features = feature::core_offers(true, false, false, true);
        server_policy.features = feature::core_offers(true, false, false, true);

        let (client_session, server_session) =
            negotiate_pair(&client, &server, &client_policy, &server_policy).await;
        let client_session = client_session.unwrap();
        assert_eq!(client_session, server_session.unwrap());
        assert_eq!(client_session.link_id.as_deref(), Some("iepl-ab"));
        assert!(
            client_session
                .features
                .iter()
                .any(|selected| selected.id == feature::PRIVATE_LINK)
        );
        client.close(0_u8.into(), b"done");
        client_endpoint.close().await;
        server_endpoint.close().await;
    }

    #[tokio::test]
    async fn quic_session_rejects_required_feature_mismatch() {
        let (client_endpoint, server_endpoint, client, server) = connections().await;
        let mut client_policy = policy("network-a", client_endpoint.id(), server_endpoint.id());
        let mut server_policy = policy("network-a", server_endpoint.id(), client_endpoint.id());
        client_policy.features.push(FeatureOffer {
            id: 700,
            min_version: 1,
            max_version: 1,
            required: true,
        });
        server_policy.features.retain(|feature| feature.id != 700);

        let (client_result, server_result) =
            negotiate_pair(&client, &server, &client_policy, &server_policy).await;
        assert!(client_result.is_err());
        assert!(server_result.is_err());
        client_endpoint.close().await;
        server_endpoint.close().await;
    }

    #[test]
    fn hello_proof_covers_the_complete_offer_and_contract() {
        let local = SecretKey::generate().public();
        let remote = SecretKey::generate().public();
        let mut policy = policy("network-a", local, remote);
        policy.link = Some(LinkAuthentication {
            link_id: "iepl-ab".into(),
            secret: [9; 32],
        });
        let hello = make_hello(&policy, [3; 32]);

        let mut altered = make_hello(&policy, [3; 32]);
        altered.max_datagram_size -= 1;
        altered.membership_proof = hello.membership_proof;
        altered.link_proof = hello.link_proof;
        assert!(validate_hello(&policy, &altered).is_err());

        let mut altered = make_hello(&policy, [3; 32]);
        altered.features[0].max_version += 1;
        altered.membership_proof = hello.membership_proof;
        altered.link_proof = hello.link_proof;
        assert!(validate_hello(&policy, &altered).is_err());

        let mut altered = make_hello(&policy, [3; 32]);
        altered.link_id = Some("iepl-other".into());
        altered.membership_proof = hello.membership_proof;
        altered.link_proof = hello.link_proof;
        assert!(validate_hello(&policy, &altered).is_err());
    }

    #[test]
    fn session_validation_rejects_disjoint_versions_and_unsafe_limits() {
        let local = SecretKey::generate().public();
        let remote = SecretKey::generate().public();
        let policy = policy("network-a", local, remote);

        let mut hello = make_hello(&policy, [4; 32]);
        hello.min_minor = MAX_MINOR + 1;
        hello.max_minor = MAX_MINOR + 1;
        hello.membership_proof = hello_proof(&policy.network_id, &hello);
        assert!(validate_hello(&policy, &hello).is_err());

        let hello = make_hello(&policy, [5; 32]);
        let mut ack = HelloAck {
            kind: ACK_KIND.into(),
            major: MAJOR,
            minor: MAX_MINOR,
            owner: remote,
            client_nonce: hello.nonce,
            server_nonce: [6; 32],
            max_datagram_size: 0,
            max_control_size: 0,
            features: feature::negotiate(&policy.features, &hello.features).unwrap(),
            transport: None,
            data_lane: false,
            link_id: None,
            invite_id: None,
            membership_proof: [0; 32],
            link_proof: None,
        };
        ack.membership_proof = ack_proof(&policy.network_id, &ack);
        assert!(validate_ack(&policy, &hello, &ack).is_err());
    }
}

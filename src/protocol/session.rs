use std::{
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

#[derive(Debug, Clone)]
pub struct SessionPolicy {
    pub network_id: String,
    pub local_id: EndpointId,
    pub remote_id: EndpointId,
    pub max_datagram_size: u32,
    pub max_control_size: u32,
    pub features: Vec<FeatureOffer>,
    pub link: Option<LinkAuthentication>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedSession {
    pub minor: u16,
    pub max_datagram_size: u32,
    pub max_control_size: u32,
    pub features: Vec<NegotiatedFeature>,
    pub link_id: Option<String>,
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
    link_id: Option<String>,
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
    link_id: Option<String>,
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
    .context("v4 session handshake timed out")?
}

async fn client(connection: &Connection, policy: &SessionPolicy) -> Result<NegotiatedSession> {
    let (mut send, mut receive) = connection
        .open_bi()
        .await
        .context("opening v4 session stream")?;
    let nonce = nonce(policy.local_id, policy.remote_id);
    let hello = make_hello(policy, nonce);
    let hello_bytes = serde_json::to_vec(&hello)?;
    write_record(&mut send, &hello_bytes).await?;
    let ack_bytes = read_record(&mut receive).await?;
    let ack: HelloAck =
        serde_json::from_slice(&ack_bytes).context("invalid v4 hello acknowledgement")?;
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
    send.finish().context("finishing v4 session stream")?;
    Ok(session_from_ack(ack))
}

async fn server(connection: &Connection, policy: &SessionPolicy) -> Result<NegotiatedSession> {
    let (mut send, mut receive) = connection
        .accept_bi()
        .await
        .context("accepting v4 session stream")?;
    let hello_bytes = read_record(&mut receive).await?;
    let hello: Hello = serde_json::from_slice(&hello_bytes).context("invalid v4 hello")?;
    validate_hello(policy, &hello)?;
    let features = negotiate(&policy.features, &hello.features)?;
    let server_nonce = nonce(policy.local_id, policy.remote_id);
    let minor = MAX_MINOR.min(hello.max_minor);
    ensure!(
        minor >= MIN_MINOR.max(hello.min_minor),
        "no compatible v4 minor version"
    );
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
        link_id: policy.link.as_ref().map(|link| link.link_id.clone()),
        membership_proof: [0; 32],
        link_proof: None,
    };
    ack.membership_proof = ack_proof(&policy.network_id, &ack);
    ack.link_proof = policy.link.as_ref().map(|link| link_ack_proof(link, &ack));
    let ack_bytes = serde_json::to_vec(&ack)?;
    write_record(&mut send, &ack_bytes).await?;
    let ready_bytes = read_record(&mut receive).await?;
    let ready: Ready = serde_json::from_slice(&ready_bytes).context("invalid v4 ready record")?;
    ensure!(ready.kind == READY_KIND, "invalid v4 ready kind");
    ensure!(
        constant_time_eq(&ready.transcript, &transcript(&hello_bytes, &ack_bytes)),
        "v4 session transcript mismatch"
    );
    send.finish().context("finishing v4 session response")?;
    Ok(session_from_ack(ack))
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
        link_id: policy.link.as_ref().map(|link| link.link_id.clone()),
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
        "v4 hello identity mismatch"
    );
    ensure!(
        hello.min_minor <= MAX_MINOR && MIN_MINOR <= hello.max_minor,
        "no compatible v4 minor version"
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
        constant_time_eq(
            &hello.membership_proof,
            &hello_proof(&policy.network_id, hello)
        ),
        "invalid v4 network membership proof"
    );
    validate_link_hello(policy, hello)
}

fn validate_ack(policy: &SessionPolicy, hello: &Hello, ack: &HelloAck) -> Result<()> {
    ensure!(
        ack.kind == ACK_KIND
            && ack.major == MAJOR
            && (MIN_MINOR..=MAX_MINOR).contains(&ack.minor)
            && (hello.min_minor..=hello.max_minor).contains(&ack.minor),
        "unsupported v4 acknowledgement"
    );
    ensure!(
        ack.owner == policy.remote_id && ack.client_nonce == hello.nonce,
        "v4 acknowledgement identity mismatch"
    );
    ensure!(
        ack.max_datagram_size <= policy.max_datagram_size
            && ack.max_datagram_size >= 256
            && ack.max_control_size <= policy.max_control_size
            && ack.max_control_size >= 1024,
        "v4 acknowledgement exceeds local limits"
    );
    ensure!(
        constant_time_eq(&ack.membership_proof, &ack_proof(&policy.network_id, ack)),
        "invalid v4 acknowledgement membership proof"
    );
    validate_selection(&policy.features, &ack.features)?;
    validate_link_ack(policy, ack)
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

fn session_from_ack(ack: HelloAck) -> NegotiatedSession {
    NegotiatedSession {
        minor: ack.minor,
        max_datagram_size: ack.max_datagram_size,
        max_control_size: ack.max_control_size,
        features: ack.features,
        link_id: ack.link_id,
    }
}

fn hello_proof(network_id: &str, hello: &Hello) -> [u8; 32] {
    keyed(
        network_id.as_bytes(),
        &[b"isw-v4-hello", &hello_unsigned(hello)],
    )
}

fn ack_proof(network_id: &str, ack: &HelloAck) -> [u8; 32] {
    keyed(network_id.as_bytes(), &[b"isw-v4-ack", &ack_unsigned(ack)])
}

fn link_hello_proof(link: &LinkAuthentication, hello: &Hello) -> [u8; 32] {
    keyed(
        &link.secret,
        &[
            b"isw-v4-link-hello",
            link.link_id.as_bytes(),
            &hello_unsigned(hello),
        ],
    )
}

fn link_ack_proof(link: &LinkAuthentication, ack: &HelloAck) -> [u8; 32] {
    keyed(
        &link.secret,
        &[
            b"isw-v4-link-ack",
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
        link_id: hello.link_id.clone(),
        membership_proof: [0; 32],
        link_proof: None,
    })
    .expect("v4 hello is serializable")
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
        link_id: ack.link_id.clone(),
        membership_proof: [0; 32],
        link_proof: None,
    })
    .expect("v4 acknowledgement is serializable")
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
    hasher.update(b"isw-v4-transcript");
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
    hasher.update(b"isw-v4-nonce");
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

async fn write_record(send: &mut iroh::endpoint::SendStream, bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() <= MAX_RECORD_BYTES,
        "v4 session record exceeds limit"
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
        "v4 session record exceeds limit"
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
        let alpn = b"iroh-sdwan/session-v4-test".to_vec();
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
            link: None,
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
            link_id: None,
            membership_proof: [0; 32],
            link_proof: None,
        };
        ack.membership_proof = ack_proof(&policy.network_id, &ack);
        assert!(validate_ack(&policy, &hello, &ack).is_err());
    }
}

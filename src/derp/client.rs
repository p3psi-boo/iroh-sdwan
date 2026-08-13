use std::{pin::Pin, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use bytes::{Bytes, BytesMut};
use crypto_box::{
    Nonce, SalsaBox,
    aead::{Aead, AeadCore, OsRng},
};
use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufStream, ReadHalf, WriteHalf},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;

use super::{
    address::{DerpPublicKey, DerpServer},
    codec::{
        self, FRAME_CLIENT_INFO, FRAME_HEALTH, FRAME_KEEP_ALIVE, FRAME_NOTE_PREFERRED,
        FRAME_PEER_GONE, FRAME_PING, FRAME_PONG, FRAME_RECV_PACKET, FRAME_RESTARTING,
        FRAME_SEND_PACKET, FRAME_SERVER_INFO, FRAME_SERVER_KEY, MAX_PACKET_SIZE,
    },
    identity::DerpIdentity,
};

trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
type BoxStream = Pin<Box<dyn AsyncStream>>;
type DerpIo = BufStream<BoxStream>;

#[derive(Debug)]
pub enum DerpMessage {
    Packet {
        source: DerpPublicKey,
        payload: Bytes,
    },
    ServerInfo {
        bytes_per_second: u64,
        burst_bytes: u64,
    },
    Ping([u8; 8]),
    Pong([u8; 8]),
    KeepAlive,
    Preferred(bool),
    PeerGone {
        peer: DerpPublicKey,
        reason: u8,
    },
    Health(String),
    Restarting {
        reconnect_in: Duration,
        try_for: Duration,
    },
    Unknown(u8),
}

#[derive(Debug, Serialize)]
struct ClientInfo<'a> {
    #[serde(rename = "version")]
    version: u8,
    #[serde(rename = "CanAckPings")]
    can_ack_pings: bool,
    #[serde(rename = "AppName")]
    app_name: &'a str,
}

#[derive(Debug, Default, Deserialize)]
struct ServerInfo {
    #[serde(rename = "TokenBucketBytesPerSecond", default)]
    token_bucket_bytes_per_second: u64,
    #[serde(rename = "TokenBucketBytesBurst", default)]
    token_bucket_bytes_burst: u64,
}

pub fn tls_config() -> Result<Arc<ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Ok(Arc::new(
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .context("failed configuring DERP TLS protocol versions")?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

pub async fn probe_server(
    server: &DerpServer,
    identity: DerpIdentity,
    tls_config: Arc<ClientConfig>,
) -> Result<()> {
    let mut connection = tokio::time::timeout(
        Duration::from_secs(10),
        DerpConnection::connect(server, identity, tls_config),
    )
    .await
    .context("DERP connection timed out")??;
    tokio::time::timeout(Duration::from_secs(5), connection.read_message())
        .await
        .context("DERP server-info timed out")??;
    Ok(())
}

pub struct DerpConnection {
    reader: DerpReader,
    writer: DerpWriter,
}

/// The receive half of a DERP connection.
///
/// `read_message` reads a frame in several asynchronous steps and therefore
/// must not be cancelled and restarted midway through a frame.  The transport
/// keeps this half in one dedicated reader task for the lifetime of the
/// connection.
pub struct DerpReader {
    reader: ReadHalf<DerpIo>,
    identity: DerpIdentity,
    server_key: DerpPublicKey,
}

/// The send half of a DERP connection.
pub struct DerpWriter {
    writer: WriteHalf<DerpIo>,
}

impl DerpConnection {
    pub async fn connect(
        server: &DerpServer,
        identity: DerpIdentity,
        tls_config: Arc<ClientConfig>,
    ) -> Result<Self> {
        let host = server.url.host_str().context("DERP URL has no host")?;
        let port = server
            .url
            .port_or_known_default()
            .context("DERP URL has no known port")?;
        let tcp = TcpStream::connect((host, port))
            .await
            .with_context(|| format!("failed connecting to {}", server.display))?;
        tcp.set_nodelay(true)?;

        let stream: BoxStream = if server.url.scheme() == "https" {
            let name = ServerName::try_from(host.to_owned()).context("invalid DERP TLS name")?;
            let tls = TlsConnector::from(tls_config)
                .connect(name, tcp)
                .await
                .with_context(|| format!("DERP TLS handshake failed for {}", server.display))?;
            Box::pin(tls)
        } else {
            Box::pin(tcp)
        };
        let mut io = BufStream::new(stream);
        http_upgrade(&mut io, server).await?;

        let greeting = codec::read_frame(&mut io)
            .await
            .context("failed reading DERP server key")?;
        ensure!(
            greeting.frame_type == FRAME_SERVER_KEY && greeting.payload.len() >= 40,
            "invalid DERP server greeting"
        );
        ensure!(&greeting.payload[..8] == codec::MAGIC, "invalid DERP magic");
        let server_key = DerpPublicKey::from_bytes(
            greeting.payload[8..40]
                .try_into()
                .expect("validated greeting length"),
        );
        send_client_info(&mut io, &identity, server_key).await?;
        let (reader, writer) = tokio::io::split(io);
        Ok(Self {
            reader: DerpReader {
                reader,
                identity,
                server_key,
            },
            writer: DerpWriter { writer },
        })
    }

    pub async fn read_message(&mut self) -> Result<DerpMessage> {
        self.reader.read_message().await
    }

    #[cfg(test)]
    pub async fn send_packet(&mut self, destination: DerpPublicKey, packet: &[u8]) -> Result<()> {
        self.writer.send_packet(destination, packet).await
    }

    pub fn into_split(self) -> (DerpReader, DerpWriter) {
        (self.reader, self.writer)
    }
}

impl DerpReader {
    pub async fn read_message(&mut self) -> Result<DerpMessage> {
        let frame = codec::read_frame(&mut self.reader).await?;
        match frame.frame_type {
            FRAME_RECV_PACKET => {
                ensure!(frame.payload.len() >= 32, "short DERP receive packet");
                let source = DerpPublicKey::from_bytes(
                    frame.payload[..32]
                        .try_into()
                        .expect("validated packet length"),
                );
                Ok(DerpMessage::Packet {
                    source,
                    payload: frame.payload.slice(32..),
                })
            }
            FRAME_SERVER_INFO => {
                let plaintext = open_box(&self.identity, self.server_key, &frame.payload)?;
                let info: ServerInfo =
                    serde_json::from_slice(&plaintext).context("invalid DERP server info JSON")?;
                Ok(DerpMessage::ServerInfo {
                    bytes_per_second: info.token_bucket_bytes_per_second,
                    burst_bytes: info.token_bucket_bytes_burst,
                })
            }
            FRAME_PING | FRAME_PONG => {
                ensure!(frame.payload.len() >= 8, "short DERP ping/pong frame");
                let data: [u8; 8] = frame.payload[..8]
                    .try_into()
                    .expect("validated ping length");
                if frame.frame_type == FRAME_PING {
                    Ok(DerpMessage::Ping(data))
                } else {
                    Ok(DerpMessage::Pong(data))
                }
            }
            FRAME_KEEP_ALIVE => Ok(DerpMessage::KeepAlive),
            FRAME_NOTE_PREFERRED => Ok(DerpMessage::Preferred(
                frame.payload.first().copied().unwrap_or(0) != 0,
            )),
            FRAME_PEER_GONE => {
                ensure!(frame.payload.len() >= 32, "short DERP peer-gone frame");
                let peer = DerpPublicKey::from_bytes(
                    frame.payload[..32]
                        .try_into()
                        .expect("validated peer key length"),
                );
                Ok(DerpMessage::PeerGone {
                    peer,
                    reason: frame.payload.get(32).copied().unwrap_or(0),
                })
            }
            FRAME_HEALTH => Ok(DerpMessage::Health(
                String::from_utf8_lossy(&frame.payload).into_owned(),
            )),
            FRAME_RESTARTING => {
                ensure!(frame.payload.len() >= 8, "short DERP restarting frame");
                let reconnect = u32::from_be_bytes(frame.payload[..4].try_into().expect("length"));
                let try_for = u32::from_be_bytes(frame.payload[4..8].try_into().expect("length"));
                Ok(DerpMessage::Restarting {
                    reconnect_in: Duration::from_millis(u64::from(reconnect)),
                    try_for: Duration::from_millis(u64::from(try_for)),
                })
            }
            other => Ok(DerpMessage::Unknown(other)),
        }
    }
}

impl DerpWriter {
    pub async fn send_packet(&mut self, destination: DerpPublicKey, packet: &[u8]) -> Result<()> {
        ensure!(
            packet.len() <= MAX_PACKET_SIZE,
            "DERP packet exceeds 64 KiB"
        );
        let mut payload = BytesMut::with_capacity(32 + packet.len());
        payload.extend_from_slice(destination.as_bytes());
        payload.extend_from_slice(packet);
        codec::write_frame(&mut self.writer, FRAME_SEND_PACKET, &payload).await
    }

    pub async fn send_pong(&mut self, payload: [u8; 8]) -> Result<()> {
        codec::write_frame(&mut self.writer, FRAME_PONG, &payload).await
    }
}

async fn http_upgrade(io: &mut DerpIo, server: &DerpServer) -> Result<()> {
    let host = server.url.host_str().expect("validated host");
    let authority = match server.url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {authority}\r\nConnection: Upgrade\r\nUpgrade: DERP\r\nUser-Agent: ironet/{}\r\n\r\n",
        server.url.path(),
        env!("CARGO_PKG_VERSION")
    );
    io.write_all(request.as_bytes()).await?;
    io.flush().await?;

    let mut response = Vec::with_capacity(1024);
    let mut byte = [0_u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        ensure!(
            response.len() < 64 * 1024,
            "DERP HTTP response headers too large"
        );
        io.read_exact(&mut byte).await?;
        response.push(byte[0]);
    }
    let response = String::from_utf8(response).context("DERP HTTP response is not UTF-8")?;
    let status = response.lines().next().unwrap_or_default();
    if !status.contains(" 101 ") {
        bail!("DERP HTTP upgrade failed: {status}");
    }
    Ok(())
}

async fn send_client_info(
    io: &mut DerpIo,
    identity: &DerpIdentity,
    server_key: DerpPublicKey,
) -> Result<()> {
    let info = serde_json::to_vec(&ClientInfo {
        version: 2,
        can_ack_pings: true,
        app_name: "ironet",
    })?;
    let nonce = SalsaBox::generate_nonce(&mut OsRng);
    let cipher = SalsaBox::new(&DerpIdentity::crypto_public(server_key), identity.secret());
    let encrypted = cipher
        .encrypt(&nonce, info.as_slice())
        .map_err(|_| anyhow::anyhow!("failed encrypting DERP client info"))?;
    let mut payload = Vec::with_capacity(32 + 24 + encrypted.len());
    payload.extend_from_slice(identity.public_key().as_bytes());
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&encrypted);
    codec::write_frame(io, FRAME_CLIENT_INFO, &payload).await
}

fn open_box(identity: &DerpIdentity, server_key: DerpPublicKey, payload: &[u8]) -> Result<Vec<u8>> {
    ensure!(payload.len() >= 24 + 16, "short DERP encrypted frame");
    let cipher = SalsaBox::new(&DerpIdentity::crypto_public(server_key), identity.secret());
    cipher
        .decrypt(Nonce::from_slice(&payload[..24]), &payload[24..])
        .map_err(|_| anyhow::anyhow!("failed authenticating DERP server info"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_info_uses_tailscale_field_names() {
        let encoded = serde_json::to_string(&ClientInfo {
            version: 2,
            can_ack_pings: true,
            app_name: "ironet",
        })
        .unwrap();
        assert!(encoded.contains("\"version\":2"));
        assert!(encoded.contains("\"CanAckPings\":true"));
        assert!(encoded.contains("\"AppName\":\"ironet\""));
    }

    /// Optional live interoperability check against a Go tailscale/derper.
    #[tokio::test]
    #[ignore = "requires network access to a DERP server"]
    async fn interoperates_with_tailscale_derper() {
        let url = std::env::var("IRONET_DERP_TEST_URL")
            .unwrap_or_else(|_| "https://derp1.tailscale.com".into());
        let server = DerpServer::parse(&url).unwrap();
        probe_server(&server, DerpIdentity::generate(), tls_config().unwrap())
            .await
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires network access to a DERP server"]
    async fn relays_packet_between_two_clients() {
        let url = std::env::var("IRONET_DERP_TEST_URL")
            .unwrap_or_else(|_| "https://derp1.tailscale.com".into());
        let server = DerpServer::parse(&url).unwrap();
        let tls = tls_config().unwrap();
        let left_identity = DerpIdentity::generate();
        let right_identity = DerpIdentity::generate();
        let mut left = DerpConnection::connect(&server, left_identity, tls.clone())
            .await
            .unwrap();
        let mut right = DerpConnection::connect(&server, right_identity.clone(), tls)
            .await
            .unwrap();

        left.send_packet(right_identity.public_key(), b"derp-interoperability")
            .await
            .unwrap();
        let received = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let DerpMessage::Packet { payload, .. } = right.read_message().await.unwrap() {
                    break payload;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(&received[..], b"derp-interoperability");
    }
}

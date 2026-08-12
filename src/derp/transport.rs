use std::{
    collections::{HashMap, HashSet},
    io,
    num::NonZeroUsize,
    pin::Pin,
    sync::{Arc, Mutex, RwLock},
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use iroh::endpoint::transports::{
    CustomEndpoint, CustomSender, CustomTransport, RecvInfo, Transmit,
};
use iroh_base::CustomAddr;
use n0_watcher::Watchable;
use rustls::ClientConfig;
use tokio::{sync::mpsc, task::JoinHandle};
use tokio_util::sync::PollSender;
use tracing::{debug, info, warn};

use super::{
    address::{DerpAddr, DerpPublicKey, DerpServer, RegionId},
    client::{DerpConnection, DerpMessage, DerpReader},
    identity::DerpIdentity,
};

const REGION_QUEUE_DEPTH: usize = 4096;
const INBOUND_QUEUE_DEPTH: usize = 4096;
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(30);
type RegionReceivers = Vec<(DerpServer, mpsc::Receiver<OutboundBatch>)>;
type DerpReadResult = anyhow::Result<DerpMessage>;

#[derive(Debug)]
struct InboundPacket {
    source: CustomAddr,
    local: CustomAddr,
    payload: Bytes,
}

#[derive(Debug)]
struct OutboundBatch {
    destination: DerpPublicKey,
    packets: Vec<Bytes>,
}

#[derive(Debug, Clone)]
struct RegionHandle {
    server: DerpServer,
    sender: mpsc::Sender<OutboundBatch>,
}

#[derive(Debug)]
pub struct DerpTransport {
    identity: DerpIdentity,
    tls_config: Arc<ClientConfig>,
    allowed_peers: Arc<RwLock<HashSet<DerpPublicKey>>>,
    regions: HashMap<RegionId, RegionHandle>,
    region_receivers: Mutex<Option<RegionReceivers>>,
    inbound_sender: mpsc::Sender<InboundPacket>,
    inbound_receiver: Mutex<Option<mpsc::Receiver<InboundPacket>>>,
    local_addresses: Watchable<Vec<CustomAddr>>,
}

impl DerpTransport {
    pub fn new(
        identity: DerpIdentity,
        servers: Vec<DerpServer>,
        allowed_peers: HashSet<DerpPublicKey>,
        tls_config: Arc<ClientConfig>,
    ) -> Arc<Self> {
        let (inbound_sender, inbound_receiver) = mpsc::channel(INBOUND_QUEUE_DEPTH);
        let mut regions = HashMap::new();
        let mut receivers = Vec::new();
        let mut local_addresses = Vec::new();
        for server in servers {
            let (sender, receiver) = mpsc::channel(REGION_QUEUE_DEPTH);
            local_addresses.push(
                DerpAddr {
                    region_id: server.region_id,
                    public_key: identity.public_key(),
                }
                .to_custom(),
            );
            regions.insert(
                server.region_id,
                RegionHandle {
                    server: server.clone(),
                    sender,
                },
            );
            receivers.push((server, receiver));
        }
        Arc::new(Self {
            identity,
            tls_config,
            allowed_peers: Arc::new(RwLock::new(allowed_peers)),
            regions,
            region_receivers: Mutex::new(Some(receivers)),
            inbound_sender,
            inbound_receiver: Mutex::new(Some(inbound_receiver)),
            local_addresses: Watchable::new(local_addresses),
        })
    }

    pub fn remote_addresses(&self, public_key: DerpPublicKey) -> Vec<CustomAddr> {
        self.regions
            .keys()
            .map(|region_id| {
                DerpAddr {
                    region_id: *region_id,
                    public_key,
                }
                .to_custom()
            })
            .collect()
    }

    pub fn local_public_key(&self) -> DerpPublicKey {
        self.identity.public_key()
    }

    pub fn allow_peer(&self, public_key: DerpPublicKey) {
        self.allowed_peers
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(public_key);
    }

    pub fn remove_peer(&self, public_key: DerpPublicKey) {
        self.allowed_peers
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&public_key);
    }

    pub fn server_name(&self, region_id: RegionId) -> Option<&str> {
        self.regions
            .get(&region_id)
            .map(|region| region.server.display.as_str())
    }
}

impl CustomTransport for DerpTransport {
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
        let receivers = self
            .region_receivers
            .lock()
            .expect("DERP receiver lock poisoned")
            .take()
            .ok_or_else(|| io::Error::other("DERP transport already bound"))?;
        let inbound_receiver = self
            .inbound_receiver
            .lock()
            .expect("DERP inbound lock poisoned")
            .take()
            .ok_or_else(|| io::Error::other("DERP transport already bound"))?;
        for (server, receiver) in receivers {
            tokio::spawn(run_region(
                server,
                self.identity.clone(),
                self.tls_config.clone(),
                self.allowed_peers.clone(),
                receiver,
                self.inbound_sender.clone(),
            ));
        }
        Ok(Box::new(DerpEndpoint {
            inbound: inbound_receiver,
            local_addresses: self.local_addresses.clone(),
            senders: self
                .regions
                .iter()
                .map(|(id, handle)| (*id, handle.sender.clone()))
                .collect(),
        }))
    }
}

#[derive(Debug)]
struct DerpEndpoint {
    inbound: mpsc::Receiver<InboundPacket>,
    local_addresses: Watchable<Vec<CustomAddr>>,
    senders: HashMap<RegionId, mpsc::Sender<OutboundBatch>>,
}

impl CustomEndpoint for DerpEndpoint {
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>> {
        self.local_addresses.watch()
    }

    fn create_sender(&self) -> Arc<dyn CustomSender> {
        Arc::new(DerpSender {
            senders: self
                .senders
                .iter()
                .map(|(id, sender)| (*id, Mutex::new(PollSender::new(sender.clone()))))
                .collect(),
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
        recv_infos: &mut [RecvInfo],
    ) -> Poll<io::Result<usize>> {
        debug_assert_eq!(bufs.len(), metas.len());
        debug_assert_eq!(bufs.len(), recv_infos.len());
        if bufs.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            let mut packets = Vec::new();
            match self.inbound.poll_recv_many(cx, &mut packets, bufs.len()) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(0) => {
                    return Poll::Ready(Err(io::Error::other("DERP receive queue closed")));
                }
                Poll::Ready(_) => {}
            }
            let mut count = 0;
            for packet in packets {
                if packet.payload.len() > bufs[count].len() {
                    continue;
                }
                bufs[count][..packet.payload.len()].copy_from_slice(&packet.payload);
                metas[count].len = packet.payload.len();
                metas[count].stride = packet.payload.len();
                recv_infos[count] = RecvInfo::new(packet.source, Some(packet.local));
                count += 1;
            }
            if count > 0 {
                return Poll::Ready(Ok(count));
            }
        }
    }

    fn max_transmit_segments(&self) -> NonZeroUsize {
        NonZeroUsize::MIN
    }
}

#[derive(Debug)]
struct DerpSender {
    senders: HashMap<RegionId, Mutex<PollSender<OutboundBatch>>>,
}

impl CustomSender for DerpSender {
    fn is_valid_send_addr(&self, addr: &CustomAddr) -> bool {
        DerpAddr::from_custom(addr)
            .ok()
            .is_some_and(|address| self.senders.contains_key(&address.region_id))
    }

    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        dst: &CustomAddr,
        src: Option<&CustomAddr>,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        let destination = DerpAddr::from_custom(dst).map_err(io::Error::other)?;
        if let Some(source) = src {
            let source = DerpAddr::from_custom(source).map_err(io::Error::other)?;
            if source.region_id != destination.region_id {
                return Poll::Ready(Err(io::Error::other(
                    "DERP source and destination regions differ",
                )));
            }
        }
        let Some(sender) = self.senders.get(&destination.region_id) else {
            return Poll::Ready(Err(io::Error::other("unknown DERP region")));
        };
        let mut sender = sender.lock().expect("DERP sender lock poisoned");
        match Pin::new(&mut *sender).poll_reserve(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::other("DERP region queue closed"))),
            Poll::Ready(Ok(())) => {
                let segment_size = transmit.segment_size.unwrap_or(transmit.contents.len());
                let packets = transmit
                    .contents
                    .chunks(segment_size.max(1))
                    .map(Bytes::copy_from_slice)
                    .collect();
                sender
                    .send_item(OutboundBatch {
                        destination: destination.public_key,
                        packets,
                    })
                    .map_err(|_| io::Error::other("DERP region queue closed"))?;
                Poll::Ready(Ok(()))
            }
        }
    }
}

async fn run_region(
    server: DerpServer,
    identity: DerpIdentity,
    tls_config: Arc<ClientConfig>,
    allowed_peers: Arc<RwLock<HashSet<DerpPublicKey>>>,
    mut outbound: mpsc::Receiver<OutboundBatch>,
    inbound: mpsc::Sender<InboundPacket>,
) {
    let mut attempt = 0_u32;
    loop {
        info!(
            region = %server.region_id,
            server = %server.display,
            url = %server.url,
            attempt = attempt.saturating_add(1),
            "DERP region connecting"
        );
        match DerpConnection::connect(&server, identity.clone(), tls_config.clone()).await {
            Ok(connection) => {
                info!(
                    region = %server.region_id,
                    server = %server.display,
                    url = %server.url,
                    "DERP region connected"
                );
                attempt = 0;
                let (reader, mut writer) = connection.into_split();
                let (reader_task, mut messages) = spawn_reader(reader);
                let mut outbound_closed = false;
                loop {
                    tokio::select! {
                        message = messages.recv() => match message {
                            Some(Ok(DerpMessage::Packet { source, payload })) => {
                                if !allowed_peers
                                    .read()
                                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                                    .contains(&source)
                                {
                                    warn!(region = %server.region_id, %source, "dropped DERP packet from unknown key");
                                    continue;
                                }
                                let packet = InboundPacket {
                                    source: DerpAddr { region_id: server.region_id, public_key: source }.to_custom(),
                                    local: DerpAddr { region_id: server.region_id, public_key: identity.public_key() }.to_custom(),
                                    payload,
                                };
                                if inbound.try_send(packet).is_err() {
                                    warn!(region = %server.region_id, "dropped DERP packet because inbound queue is full");
                                }
                            }
                            Some(Ok(DerpMessage::Ping(payload))) => {
                                if let Err(error) = writer.send_pong(payload).await {
                                    warn!(
                                        region = %server.region_id,
                                        server = %server.display,
                                        %error,
                                        "DERP connection lost while sending pong"
                                    );
                                    break;
                                }
                            }
                            Some(Ok(DerpMessage::ServerInfo { bytes_per_second, burst_bytes })) => {
                                info!(region = %server.region_id, bytes_per_second, burst_bytes, "DERP server rate information received");
                            }
                            Some(Ok(DerpMessage::PeerGone { peer, reason })) => {
                                debug!(region = %server.region_id, %peer, reason, "DERP peer is not present");
                            }
                            Some(Ok(DerpMessage::Health(problem))) if !problem.is_empty() => {
                                warn!(region = %server.region_id, %problem, "DERP connection reported unhealthy");
                            }
                            Some(Ok(DerpMessage::Restarting { reconnect_in, try_for })) => {
                                info!(region = %server.region_id, ?reconnect_in, ?try_for, "DERP server is restarting");
                                if !reconnect_in.is_zero() {
                                    tokio::time::sleep(reconnect_in.min(MAX_RECONNECT_DELAY)).await;
                                }
                                break;
                            }
                            Some(Ok(DerpMessage::Pong(payload))) => {
                                debug!(region = %server.region_id, ?payload, "DERP pong received");
                            }
                            Some(Ok(DerpMessage::Preferred(preferred))) => {
                                debug!(region = %server.region_id, preferred, "DERP preferred status received");
                            }
                            Some(Ok(DerpMessage::Unknown(frame_type))) => {
                                debug!(region = %server.region_id, frame_type, "ignored unknown DERP frame");
                            }
                            Some(Ok(DerpMessage::KeepAlive | DerpMessage::Health(_))) => {}
                            Some(Err(error)) => {
                                warn!(
                                    region = %server.region_id,
                                    server = %server.display,
                                    %error,
                                    "DERP connection lost while receiving"
                                );
                                break;
                            }
                            None => {
                                warn!(
                                    region = %server.region_id,
                                    server = %server.display,
                                    "DERP reader task stopped unexpectedly"
                                );
                                break;
                            }
                        },
                        batch = outbound.recv() => {
                            let Some(batch) = batch else {
                                outbound_closed = true;
                                break;
                            };
                            let mut failed = false;
                            for packet in batch.packets {
                                if let Err(error) = writer.send_packet(batch.destination, &packet).await {
                                    warn!(
                                        region = %server.region_id,
                                        server = %server.display,
                                        destination = %batch.destination,
                                        %error,
                                        "DERP connection lost while sending packet"
                                    );
                                    failed = true;
                                    break;
                                }
                            }
                            if failed { break; }
                        }
                    }
                }
                reader_task.abort();
                let _ = reader_task.await;
                if outbound_closed {
                    return;
                }
            }
            Err(error) => {
                warn!(
                    region = %server.region_id,
                    server = %server.display,
                    url = %server.url,
                    attempt = attempt.saturating_add(1),
                    %error,
                    "DERP region connection failed"
                );
            }
        }
        attempt = attempt.saturating_add(1);
        let shift = attempt.min(5);
        let delay = Duration::from_secs(1_u64 << shift).min(MAX_RECONNECT_DELAY);
        info!(
            region = %server.region_id,
            server = %server.display,
            failed_attempts = attempt,
            retry_in_ms = delay.as_millis(),
            "DERP region reconnect scheduled"
        );
        tokio::time::sleep(delay).await;
    }
}

/// Run all frame reads in one task. `codec::read_frame` uses `read_exact`,
/// which is not cancellation-safe; polling it directly beside the outbound
/// queue would discard a partially-read frame whenever an outbound packet won
/// `select!`, desynchronising the byte stream.
fn spawn_reader(mut reader: DerpReader) -> (JoinHandle<()>, mpsc::Receiver<DerpReadResult>) {
    let (sender, receiver) = mpsc::channel(256);
    let task = tokio::spawn(async move {
        loop {
            let result = reader.read_message().await;
            let terminal = result.is_err();
            if sender.send(result).await.is_err() || terminal {
                break;
            }
        }
    });
    (task, receiver)
}

#[cfg(test)]
mod tests {
    use crate::derp::DERP_TRANSPORT_ID;
    use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey, TransportAddr};

    use super::*;

    #[test]
    fn one_server_produces_one_region_address() {
        let identity = DerpIdentity::from_bytes([31; 32]);
        let first = DerpServer::parse("https://derp-a.example.com").unwrap();
        let second = DerpServer::parse("https://derp-b.example.com").unwrap();
        let transport = DerpTransport::new(
            identity,
            vec![first.clone(), second.clone()],
            HashSet::new(),
            super::super::client::tls_config().unwrap(),
        );
        let remote_key = DerpPublicKey::from_bytes([32; 32]);
        let mut addresses = transport
            .remote_addresses(remote_key)
            .into_iter()
            .map(|address| DerpAddr::from_custom(&address).unwrap())
            .collect::<Vec<_>>();
        addresses.sort_by_key(|address| address.region_id);
        let mut expected = vec![first.region_id, second.region_id];
        expected.sort();
        assert_eq!(
            addresses
                .iter()
                .map(|address| address.region_id)
                .collect::<Vec<_>>(),
            expected
        );
        assert!(
            addresses
                .iter()
                .all(|address| address.public_key == remote_key)
        );
    }

    /// End-to-end check that iroh QUIC can bootstrap and exchange datagrams over DERP.
    #[tokio::test]
    #[ignore = "requires network access to a DERP server"]
    async fn iroh_connection_uses_derp_custom_transport() {
        let url = std::env::var("IROH_SDWAN_DERP_TEST_URL")
            .unwrap_or_else(|_| "https://derp1.tailscale.com".into());
        let server = DerpServer::parse(&url).unwrap();
        exercise_iroh_over_derp(vec![server]).await;
    }

    /// End-to-end check that unavailable regions do not prevent another DERP region from working.
    #[tokio::test]
    #[ignore = "requires network access to multiple DERP servers"]
    async fn iroh_connection_uses_multiple_derp_regions() {
        let urls = std::env::var("IROH_SDWAN_DERP_TEST_URLS")
            .expect("IROH_SDWAN_DERP_TEST_URLS must contain comma-separated DERP URLs");
        let servers = urls
            .split(',')
            .map(str::trim)
            .filter(|url| !url.is_empty())
            .map(|url| DerpServer::parse(url).unwrap())
            .collect::<Vec<_>>();
        assert!(servers.len() >= 2, "at least two DERP servers are required");
        exercise_iroh_over_derp(servers).await;
    }

    async fn exercise_iroh_over_derp(servers: Vec<DerpServer>) {
        let left_derp = DerpIdentity::generate();
        let right_derp = DerpIdentity::generate();
        let left_key = SecretKey::generate();
        let right_key = SecretKey::generate();
        let alpn = b"iroh-sdwan/derp-test/1".to_vec();
        let tls = super::super::client::tls_config().unwrap();

        let left_transport = DerpTransport::new(
            left_derp.clone(),
            servers.clone(),
            HashSet::from([right_derp.public_key()]),
            tls.clone(),
        );
        let right_transport = DerpTransport::new(
            right_derp.clone(),
            servers,
            HashSet::from([left_derp.public_key()]),
            tls,
        );
        let left = Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(left_key)
            .alpns(vec![alpn.clone()])
            .relay_mode(RelayMode::Disabled)
            .clear_ip_transports()
            .clear_address_lookup()
            .add_custom_transport(left_transport.clone())
            .bind()
            .await
            .unwrap();
        let right = Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(right_key.clone())
            .alpns(vec![alpn.clone()])
            .relay_mode(RelayMode::Disabled)
            .clear_ip_transports()
            .clear_address_lookup()
            .add_custom_transport(right_transport.clone())
            .bind()
            .await
            .unwrap();

        let remote = EndpointAddr::new(right_key.public()).with_addrs(
            left_transport
                .remote_addresses(right_derp.public_key())
                .into_iter()
                .map(TransportAddr::Custom),
        );
        let right_task = tokio::spawn(async move {
            let incoming = right.accept().await.unwrap();
            let connection = incoming.accept().unwrap().await.unwrap();
            let received = connection.read_datagram().await.unwrap();
            connection.send_datagram_wait(received).await.unwrap();
            connection.closed().await;
            right.close().await;
        });
        let connection = tokio::time::timeout(Duration::from_secs(30), left.connect(remote, &alpn))
            .await
            .unwrap()
            .unwrap();
        connection
            .send_datagram_wait(Bytes::from_static(b"iroh-over-derp"))
            .await
            .unwrap();
        let echoed = tokio::time::timeout(Duration::from_secs(10), connection.read_datagram())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&echoed[..], b"iroh-over-derp");
        let selected = connection
            .paths()
            .iter()
            .find(|path| path.is_selected())
            .and_then(|path| match path.remote_addr() {
                TransportAddr::Custom(address) if address.id() == DERP_TRANSPORT_ID => {
                    DerpAddr::from_custom(address).ok()
                }
                _ => None,
            })
            .expect("selected path must be DERP");
        eprintln!(
            "selected DERP region={} server={}",
            selected.region_id,
            left_transport
                .server_name(selected.region_id)
                .expect("selected region must be configured")
        );
        connection.close(0_u8.into(), b"done");
        left.close().await;
        right_task.await.unwrap();
    }
}

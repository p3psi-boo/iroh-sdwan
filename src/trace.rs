use std::{
    collections::HashSet,
    fmt::Write as _,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{net::UdpSocket, time};
use tracing::debug;

use crate::{
    config::{Config, NodeInfo},
    display,
};

pub const TRACE_PORT: u16 = 49_091;
pub const MAX_PING_COUNT: u16 = 20;

const REQUEST_MAGIC: &[u8; 8] = b"ISWTRC1Q";
const RESPONSE_MAGIC: &[u8; 8] = b"ISWTRC1R";
// Pad requests to the maximum response size so a spoofed probe cannot turn a
// node into a UDP amplification source.
const REQUEST_LEN: usize = 1_024;
const REQUEST_HEADER_LEN: usize = REQUEST_MAGIC.len() + size_of::<u64>();
const RESPONSE_HEADER_LEN: usize = RESPONSE_MAGIC.len() + size_of::<u64>() + 1;
const MAX_RESPONSE_LEN: usize = 1_024;
const UDP_HEADER_LEN: usize = 8;
const IP_PROTOCOL_UDP: u8 = 17;
const PING_HOP_LIMIT: u8 = u8::MAX;
const PING_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Probe {
    request_id: u64,
    source: IpAddr,
    destination: IpAddr,
    source_port: u16,
    hops_remaining: u8,
}

#[derive(Debug, PartialEq, Eq)]
struct Response {
    request_id: u64,
    destination: bool,
    node_info: NodeInfo,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceResult {
    pub target: IpAddr,
    pub source: IpAddr,
    pub source_name: String,
    pub max_hops: u8,
    pub reached: bool,
    pub hops: Vec<TraceHop>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceHop {
    pub hop: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<f64>,
    pub destination: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_info: Option<NodeInfo>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PingResult {
    pub target: IpAddr,
    pub source: IpAddr,
    pub source_name: String,
    pub transmitted: u16,
    pub received: u16,
    pub loss_ppm: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_ms: Option<f64>,
    pub samples: Vec<PingSample>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PingSample {
    pub sequence: u16,
    pub reached: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_info: Option<NodeInfo>,
}

pub struct TraceResponder {
    node_info: NodeInfo,
    encoded_node_info: Vec<u8>,
    local_addresses: HashSet<IpAddr>,
    ipv4_socket: Option<Arc<UdpSocket>>,
    ipv6_socket: Option<Arc<UdpSocket>>,
}

impl TraceResponder {
    pub async fn bind(config: &Config) -> Result<Option<Arc<Self>>> {
        let Some(node_info) = config.node_info.clone() else {
            return Ok(None);
        };

        let ipv4_socket = bind_optional_response_socket(config.node_address(true)).await?;
        let ipv6_socket = bind_optional_response_socket(config.node_address(false)).await?;
        let encoded_node_info = toml::to_string(&node_info)?.into_bytes();
        ensure!(
            RESPONSE_HEADER_LEN + encoded_node_info.len() <= MAX_RESPONSE_LEN,
            "encoded trace response exceeds {MAX_RESPONSE_LEN} bytes"
        );

        Ok(Some(Arc::new(Self {
            node_info,
            encoded_node_info,
            local_addresses: config
                .node_addresses
                .iter()
                .map(|network| network.addr())
                .collect(),
            ipv4_socket,
            ipv6_socket,
        })))
    }

    /// Inspect an inbound raw IP packet before it enters the local TUN.
    ///
    /// Returns true when this node consumed a trace request. Requests with more
    /// hops remaining are left untouched so FlowRouter can forward them.
    pub async fn handle_packet(&self, packet: &[u8]) -> Result<bool> {
        let Some(probe) = parse_probe(packet) else {
            return Ok(false);
        };
        let is_destination = self.local_addresses.contains(&probe.destination);
        if probe.hops_remaining > 1 && !is_destination {
            return Ok(false);
        }

        let socket = match probe.source {
            IpAddr::V4(_) => self.ipv4_socket.as_ref(),
            IpAddr::V6(_) => self.ipv6_socket.as_ref(),
        };
        let Some(socket) = socket else {
            debug!(source = %probe.source, "trace request has no matching node_info address family");
            return Ok(true);
        };

        let response = encode_response(probe.request_id, is_destination, &self.encoded_node_info);
        socket
            .send_to(&response, SocketAddr::new(probe.source, probe.source_port))
            .await
            .with_context(|| format!("failed responding to trace probe from {}", probe.source))?;
        debug!(
            node = %self.node_info.name,
            source = %probe.source,
            destination = is_destination,
            "answered overlay trace probe"
        );
        Ok(true)
    }
}

pub async fn run(
    config: &Config,
    target: IpAddr,
    max_hops: u8,
    timeout: Duration,
) -> Result<TraceResult> {
    run_streaming(config, target, max_hops, timeout, None).await
}

/// Run a trace and optionally publish each hop as soon as it is observed.
/// Dropping the receiver never aborts the underlying trace.
pub async fn run_streaming(
    config: &Config,
    target: IpAddr,
    max_hops: u8,
    timeout: Duration,
    hop_sender: Option<tokio::sync::mpsc::Sender<TraceHop>>,
) -> Result<TraceResult> {
    ensure!(
        !timeout.is_zero(),
        "trace timeout must be greater than zero"
    );
    let (node_info, source) = probe_identity(config, target)?;

    let mut result = TraceResult {
        target,
        source,
        source_name: node_info.name.clone(),
        max_hops,
        reached: target == source,
        hops: Vec::new(),
    };
    if target == source {
        let hop = TraceHop {
            hop: 0,
            address: Some(source),
            elapsed_ms: Some(0.0),
            destination: true,
            node_info: Some(node_info.clone()),
        };
        publish_hop(&hop_sender, &hop).await;
        result.hops.push(hop);
        return Ok(result);
    }

    for hop in 1..=max_hops {
        match send_probe(source, target, hop, u64::from(hop), timeout).await? {
            Some((response, sender, elapsed_ms)) => {
                let destination = response.destination;
                let trace_hop = TraceHop {
                    hop,
                    address: Some(sender.ip()),
                    elapsed_ms: Some(elapsed_ms),
                    destination,
                    node_info: Some(response.node_info),
                };
                publish_hop(&hop_sender, &trace_hop).await;
                result.hops.push(trace_hop);
                if response.destination {
                    result.reached = true;
                    break;
                }
            }
            None => {
                let trace_hop = TraceHop {
                    hop,
                    address: None,
                    elapsed_ms: None,
                    destination: false,
                    node_info: None,
                };
                publish_hop(&hop_sender, &trace_hop).await;
                result.hops.push(trace_hop);
            }
        }
    }
    Ok(result)
}

/// Measure end-to-end reachability and RTT over the FlowRouter-selected
/// overlay path. This deliberately reuses the authenticated trace responder,
/// so it does not depend on host ICMP policy and also works across transit
/// nodes.
pub async fn ping(
    config: &Config,
    target: IpAddr,
    count: u16,
    timeout: Duration,
) -> Result<PingResult> {
    ping_streaming(config, target, count, timeout, None).await
}

/// Run an overlay ping and publish each completed sample. A dropped receiver
/// cancels the remaining probes instead of leaving a detached long-running
/// control task behind.
pub async fn ping_streaming(
    config: &Config,
    target: IpAddr,
    count: u16,
    timeout: Duration,
    sample_sender: Option<tokio::sync::mpsc::Sender<PingSample>>,
) -> Result<PingResult> {
    ensure!(
        (1..=MAX_PING_COUNT).contains(&count),
        "ping count must be between 1 and {MAX_PING_COUNT}"
    );
    ensure!(!timeout.is_zero(), "ping timeout must be greater than zero");
    let (node_info, source) = probe_identity(config, target)?;
    let mut samples = Vec::with_capacity(usize::from(count));

    for sequence in 1..=count {
        let sample = if target == source {
            PingSample {
                sequence,
                reached: true,
                address: Some(source),
                elapsed_ms: Some(0.0),
                node_info: Some(node_info.clone()),
            }
        } else {
            match send_probe(source, target, PING_HOP_LIMIT, u64::from(sequence), timeout).await {
                Ok(Some((response, sender, elapsed_ms))) => PingSample {
                    sequence,
                    reached: response.destination,
                    address: Some(sender.ip()),
                    elapsed_ms: Some(elapsed_ms),
                    node_info: Some(response.node_info),
                },
                Ok(None) => PingSample {
                    sequence,
                    reached: false,
                    address: None,
                    elapsed_ms: None,
                    node_info: None,
                },
                Err(error) => {
                    debug!(sequence, %target, %error, "overlay ping probe failed");
                    PingSample {
                        sequence,
                        reached: false,
                        address: None,
                        elapsed_ms: None,
                        node_info: None,
                    }
                }
            }
        };
        publish_ping_sample(&sample_sender, &sample).await?;
        samples.push(sample);
        if target != source && sequence < count {
            time::sleep(PING_INTERVAL).await;
        }
    }

    Ok(summarize_ping(
        target,
        source,
        node_info.name.clone(),
        samples,
    ))
}

async fn publish_ping_sample(
    sender: &Option<tokio::sync::mpsc::Sender<PingSample>>,
    sample: &PingSample,
) -> Result<()> {
    if let Some(sender) = sender {
        sender
            .send(sample.clone())
            .await
            .context("ping sample receiver closed")?;
    }
    Ok(())
}

async fn publish_hop(sender: &Option<tokio::sync::mpsc::Sender<TraceHop>>, hop: &TraceHop) {
    if let Some(sender) = sender {
        let _ = sender.send(hop.clone()).await;
    }
}

pub fn print_human(result: &TraceResult) {
    println!(
        "trace to {} from {} ({}), {} hops max",
        result.target, result.source_name, result.source, result.max_hops
    );
    for hop in &result.hops {
        match (&hop.address, &hop.elapsed_ms, &hop.node_info) {
            (Some(address), Some(elapsed_ms), Some(node_info)) => {
                print_hop(hop.hop, *address, *elapsed_ms, node_info);
            }
            _ => println!("{:>2}  *", hop.hop),
        }
    }
}

pub fn format_ping_human(result: &PingResult) -> String {
    let mut output = String::new();
    writeln!(
        output,
        "overlay ping to {} from {} ({})",
        result.target, result.source_name, result.source
    )
    .expect("writing to a String cannot fail");
    for sample in &result.samples {
        match (
            sample.reached,
            sample.address,
            sample.elapsed_ms,
            sample.node_info.as_ref(),
        ) {
            (true, Some(address), Some(elapsed_ms), Some(node_info)) => writeln!(
                output,
                "seq={} from={} name={} time={}",
                sample.sequence,
                address,
                single_line(&node_info.name),
                display::millis_f64(elapsed_ms),
            ),
            (false, Some(address), Some(elapsed_ms), Some(node_info)) => writeln!(
                output,
                "seq={} stopped_at={} name={} time={}",
                sample.sequence,
                address,
                single_line(&node_info.name),
                display::millis_f64(elapsed_ms),
            ),
            _ => writeln!(output, "seq={} timeout", sample.sequence),
        }
        .expect("writing to a String cannot fail");
    }
    writeln!(
        output,
        "{} transmitted, {} received, {:.1}% loss",
        result.transmitted,
        result.received,
        f64::from(result.loss_ppm) / 10_000.0
    )
    .expect("writing to a String cannot fail");
    if let (Some(min_ms), Some(avg_ms), Some(max_ms)) =
        (result.min_ms, result.avg_ms, result.max_ms)
    {
        writeln!(
            output,
            "rtt min/avg/max = {}/{}/{}",
            display::millis_f64(min_ms),
            display::millis_f64(avg_ms),
            display::millis_f64(max_ms),
        )
        .expect("writing to a String cannot fail");
    }
    output
}

fn probe_identity(config: &Config, target: IpAddr) -> Result<(&NodeInfo, IpAddr)> {
    let node_info = config
        .node_info
        .as_ref()
        .context("overlay probes require [node_info] in the local configuration")?;
    let source = config.node_address(target.is_ipv4()).with_context(|| {
        format!(
            "local node_addresses does not define a {} probe address",
            if target.is_ipv4() { "IPv4" } else { "IPv6" }
        )
    })?;
    Ok((node_info, source))
}

async fn send_probe(
    source: IpAddr,
    target: IpAddr,
    hops: u8,
    nonce: u64,
    timeout: Duration,
) -> Result<Option<(Response, SocketAddr, f64)>> {
    let socket = probe_socket(source, target, hops)?;
    let request_id = request_id(nonce);
    let request = encode_request(request_id);
    let started = Instant::now();
    socket
        .send_to(&request, SocketAddr::new(target, TRACE_PORT))
        .await
        .with_context(|| format!("failed sending overlay probe to {target}"))?;
    Ok(receive_response(&socket, request_id, target, timeout)
        .await?
        .map(|(response, sender)| (response, sender, started.elapsed().as_secs_f64() * 1_000.0)))
}

fn summarize_ping(
    target: IpAddr,
    source: IpAddr,
    source_name: String,
    samples: Vec<PingSample>,
) -> PingResult {
    let transmitted = u16::try_from(samples.len()).unwrap_or(u16::MAX);
    let elapsed = samples
        .iter()
        .filter(|sample| sample.reached)
        .filter_map(|sample| sample.elapsed_ms)
        .collect::<Vec<_>>();
    let received = u16::try_from(elapsed.len()).unwrap_or(u16::MAX);
    let loss_ppm = if transmitted == 0 {
        0
    } else {
        u32::from(transmitted - received) * 1_000_000 / u32::from(transmitted)
    };
    let min_ms = elapsed.iter().copied().reduce(f64::min);
    let max_ms = elapsed.iter().copied().reduce(f64::max);
    let avg_ms = (!elapsed.is_empty()).then(|| elapsed.iter().sum::<f64>() / elapsed.len() as f64);
    PingResult {
        target,
        source,
        source_name,
        transmitted,
        received,
        loss_ppm,
        min_ms,
        avg_ms,
        max_ms,
        samples,
    }
}

async fn receive_response(
    socket: &UdpSocket,
    request_id: u64,
    target: IpAddr,
    timeout: Duration,
) -> Result<Option<(Response, SocketAddr)>> {
    let deadline = time::Instant::now() + timeout;
    let mut buffer = [0_u8; MAX_RESPONSE_LEN];
    loop {
        let remaining = deadline.saturating_duration_since(time::Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        let received = match time::timeout(remaining, socket.recv_from(&mut buffer)).await {
            Ok(received) => received.context("failed receiving trace response")?,
            Err(_) => return Ok(None),
        };
        let (len, sender) = received;
        let Some(response) = decode_response(&buffer[..len]) else {
            debug!(%sender, len, "ignored malformed trace response");
            continue;
        };
        if response.request_id == request_id {
            if response.destination && sender.ip() != target {
                debug!(
                    %sender,
                    %target,
                    "ignored destination probe response from an unexpected address"
                );
                continue;
            }
            return Ok(Some((response, sender)));
        }
        debug!(
            %sender,
            expected_request_id = request_id,
            received_request_id = response.request_id,
            "ignored trace response for another request"
        );
    }
}

fn print_hop(hop: u8, address: IpAddr, elapsed_ms: f64, node_info: &NodeInfo) {
    let mut details = Vec::new();
    if let Some(description) = &node_info.description {
        details.push(single_line(description));
    }
    details.extend(
        node_info
            .metadata
            .iter()
            .map(|(key, value)| format!("{}={}", single_line(key), single_line(value))),
    );
    let details = if details.is_empty() {
        String::new()
    } else {
        format!("  [{}]", details.join(", "))
    };
    println!(
        "{hop:>2}  {} ({address})  {}{details}",
        single_line(&node_info.name),
        display::millis_f64(elapsed_ms),
    );
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

fn probe_socket(source: IpAddr, target: IpAddr, hops: u8) -> Result<UdpSocket> {
    ensure!(
        source.is_ipv4() == target.is_ipv4(),
        "trace source and target address families differ"
    );
    let domain = Domain::for_address(SocketAddr::new(target, TRACE_PORT));
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
        .context("failed creating trace UDP socket")?;
    socket
        .set_nonblocking(true)
        .context("failed enabling non-blocking trace socket")?;
    match target {
        IpAddr::V4(_) => socket.set_ttl_v4(u32::from(hops)),
        IpAddr::V6(_) => socket.set_unicast_hops_v6(u32::from(hops)),
    }
    .context("failed setting trace hop limit")?;
    socket
        .bind(&SocketAddr::new(source, 0).into())
        .with_context(|| format!("failed binding trace source address {source}"))?;
    let socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(socket).context("failed creating async trace socket")
}

async fn bind_response_socket(address: IpAddr) -> Result<UdpSocket> {
    UdpSocket::bind(SocketAddr::new(address, 0))
        .await
        .with_context(|| format!("failed binding trace response address {address}"))
}

async fn bind_optional_response_socket(address: Option<IpAddr>) -> Result<Option<Arc<UdpSocket>>> {
    match address {
        Some(address) => Ok(Some(Arc::new(bind_response_socket(address).await?))),
        None => Ok(None),
    }
}

fn request_id(nonce: u64) -> u64 {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    time ^ (u64::from(std::process::id()) << 16) ^ nonce
}

fn encode_request(request_id: u64) -> [u8; REQUEST_LEN] {
    let mut output = [0_u8; REQUEST_LEN];
    output[..REQUEST_MAGIC.len()].copy_from_slice(REQUEST_MAGIC);
    output[REQUEST_MAGIC.len()..REQUEST_HEADER_LEN].copy_from_slice(&request_id.to_be_bytes());
    output
}

fn encode_response(request_id: u64, destination: bool, node_info: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(RESPONSE_HEADER_LEN + node_info.len());
    output.extend_from_slice(RESPONSE_MAGIC);
    output.extend_from_slice(&request_id.to_be_bytes());
    output.push(u8::from(destination));
    output.extend_from_slice(node_info);
    output
}

fn decode_response(packet: &[u8]) -> Option<Response> {
    if packet.len() < RESPONSE_HEADER_LEN || &packet[..RESPONSE_MAGIC.len()] != RESPONSE_MAGIC {
        return None;
    }
    let request_id_end = RESPONSE_MAGIC.len() + size_of::<u64>();
    let request_id = u64::from_be_bytes(
        packet[RESPONSE_MAGIC.len()..request_id_end]
            .try_into()
            .ok()?,
    );
    let destination = match packet[request_id_end] {
        0 => false,
        1 => true,
        _ => return None,
    };
    let node_info = toml::from_slice(&packet[RESPONSE_HEADER_LEN..]).ok()?;
    Some(Response {
        request_id,
        destination,
        node_info,
    })
}

fn parse_probe(packet: &[u8]) -> Option<Probe> {
    match packet.first()? >> 4 {
        4 => parse_ipv4_probe(packet),
        6 => parse_ipv6_probe(packet),
        _ => None,
    }
}

fn parse_ipv4_probe(packet: &[u8]) -> Option<Probe> {
    if packet.len() < 20 || packet[9] != IP_PROTOCOL_UDP {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    let fragments = u16::from_be_bytes([packet[6], packet[7]]);
    if header_len < 20 || total_len > packet.len() || fragments & 0x3fff != 0 {
        return None;
    }
    parse_udp_probe(
        &packet[header_len..total_len],
        IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        )),
        IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        )),
        packet[8],
    )
}

fn parse_ipv6_probe(packet: &[u8]) -> Option<Probe> {
    if packet.len() < 40 || packet[6] != IP_PROTOCOL_UDP {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    if 40 + payload_len > packet.len() {
        return None;
    }
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?);
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?);
    parse_udp_probe(
        &packet[40..40 + payload_len],
        IpAddr::V6(source),
        IpAddr::V6(destination),
        packet[7],
    )
}

fn parse_udp_probe(
    udp: &[u8],
    source: IpAddr,
    destination: IpAddr,
    hops_remaining: u8,
) -> Option<Probe> {
    if udp.len() < UDP_HEADER_LEN + REQUEST_LEN {
        return None;
    }
    let source_port = u16::from_be_bytes([udp[0], udp[1]]);
    let destination_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
    if destination_port != TRACE_PORT
        || udp_len < UDP_HEADER_LEN + REQUEST_LEN
        || udp_len > udp.len()
    {
        return None;
    }
    let request = &udp[UDP_HEADER_LEN..udp_len];
    if request.len() != REQUEST_LEN || &request[..REQUEST_MAGIC.len()] != REQUEST_MAGIC {
        return None;
    }
    let request_id = u64::from_be_bytes(
        request[REQUEST_MAGIC.len()..REQUEST_HEADER_LEN]
            .try_into()
            .ok()?,
    );
    Some(Probe {
        request_id,
        source,
        destination,
        source_port,
        hops_remaining,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn parses_ipv4_trace_request() {
        let request = encode_request(42);
        let mut packet = vec![0_u8; 20 + 8 + request.len()];
        packet[0] = 0x45;
        let packet_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        packet[8] = 3;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 4]);
        packet[20..22].copy_from_slice(&31_337_u16.to_be_bytes());
        packet[22..24].copy_from_slice(&TRACE_PORT.to_be_bytes());
        let udp_len = (8 + request.len()) as u16;
        packet[24..26].copy_from_slice(&udp_len.to_be_bytes());
        packet[28..].copy_from_slice(&request);

        assert_eq!(
            parse_probe(&packet),
            Some(Probe {
                request_id: 42,
                source: "10.0.0.1".parse().unwrap(),
                destination: "10.0.0.4".parse().unwrap(),
                source_port: 31_337,
                hops_remaining: 3,
            })
        );
    }

    #[test]
    fn parses_ipv6_trace_request() {
        let request = encode_request(99);
        let mut packet = vec![0_u8; 40 + 8 + request.len()];
        packet[0] = 0x60;
        let payload_len = (8 + request.len()) as u16;
        packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
        packet[6] = 17;
        packet[7] = 5;
        let source: Ipv6Addr = "fd73:9db8:4200::1".parse().unwrap();
        let destination: Ipv6Addr = "fd73:9db8:4200::4".parse().unwrap();
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&destination.octets());
        packet[40..42].copy_from_slice(&31_337_u16.to_be_bytes());
        packet[42..44].copy_from_slice(&TRACE_PORT.to_be_bytes());
        packet[44..46].copy_from_slice(&payload_len.to_be_bytes());
        packet[48..].copy_from_slice(&request);

        assert_eq!(
            parse_probe(&packet),
            Some(Probe {
                request_id: 99,
                source: IpAddr::V6(source),
                destination: IpAddr::V6(destination),
                source_port: 31_337,
                hops_remaining: 5,
            })
        );
    }

    #[test]
    fn response_round_trip_preserves_node_info() {
        let node_info = NodeInfo {
            name: "branch-b".into(),
            description: Some("branch router".into()),
            metadata: BTreeMap::from([("site".into(), "beijing".into())]),
        };
        let encoded = toml::to_string(&node_info).unwrap();
        let response = encode_response(7, true, encoded.as_bytes());

        assert_eq!(
            decode_response(&response),
            Some(Response {
                request_id: 7,
                destination: true,
                node_info,
            })
        );
    }

    #[test]
    fn malformed_probe_responses_are_rejected() {
        let node_info = NodeInfo {
            name: "branch-b".into(),
            description: None,
            metadata: BTreeMap::new(),
        };
        let encoded = toml::to_string(&node_info).unwrap();
        let valid = encode_response(7, true, encoded.as_bytes());

        assert!(decode_response(&valid[..RESPONSE_HEADER_LEN - 1]).is_none());
        let mut wrong_magic = valid.clone();
        wrong_magic[0] ^= 0xff;
        assert!(decode_response(&wrong_magic).is_none());
        let mut invalid_destination = valid.clone();
        invalid_destination[RESPONSE_MAGIC.len() + size_of::<u64>()] = 2;
        assert!(decode_response(&invalid_destination).is_none());
        let invalid_node_info = encode_response(7, true, b"[");
        assert!(decode_response(&invalid_node_info).is_none());
    }

    #[tokio::test]
    async fn receive_ignores_wrong_ids_malformed_packets_and_forged_destination_sources() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_address = receiver.local_addr().unwrap();
        let valid_sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let forged_sender = UdpSocket::bind("127.0.0.2:0").await.unwrap();
        let node_info = NodeInfo {
            name: "target".into(),
            description: None,
            metadata: BTreeMap::new(),
        };
        let encoded = toml::to_string(&node_info).unwrap();

        valid_sender
            .send_to(
                &encode_response(6, true, encoded.as_bytes()),
                receiver_address,
            )
            .await
            .unwrap();
        valid_sender
            .send_to(b"malformed", receiver_address)
            .await
            .unwrap();
        forged_sender
            .send_to(
                &encode_response(7, true, encoded.as_bytes()),
                receiver_address,
            )
            .await
            .unwrap();
        let expected = encode_response(7, true, encoded.as_bytes());
        valid_sender
            .send_to(&expected, receiver_address)
            .await
            .unwrap();
        valid_sender
            .send_to(&expected, receiver_address)
            .await
            .unwrap();

        let (response, sender) = receive_response(
            &receiver,
            7,
            "127.0.0.1".parse().unwrap(),
            Duration::from_secs(1),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(response.destination);
        assert_eq!(response.node_info.name, "target");
        assert_eq!(sender.ip(), "127.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn late_probe_response_does_not_extend_deadline() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_address = receiver.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let response = encode_response(
            9,
            true,
            toml::to_string(&NodeInfo {
                name: "late".into(),
                description: None,
                metadata: BTreeMap::new(),
            })
            .unwrap()
            .as_bytes(),
        );
        let send = tokio::spawn(async move {
            time::sleep(Duration::from_millis(50)).await;
            sender.send_to(&response, receiver_address).await.unwrap();
        });

        let received = receive_response(
            &receiver,
            9,
            "127.0.0.1".parse().unwrap(),
            Duration::from_millis(10),
        )
        .await
        .unwrap();
        assert!(received.is_none());
        send.await.unwrap();
    }

    #[test]
    fn trace_result_has_stable_machine_readable_fields() {
        let result = TraceResult {
            target: "21.0.0.2".parse().unwrap(),
            source: "21.0.0.4".parse().unwrap(),
            source_name: "lambda".into(),
            max_hops: 30,
            reached: true,
            hops: vec![TraceHop {
                hop: 1,
                address: Some("21.0.0.3".parse().unwrap()),
                elapsed_ms: Some(52.25),
                destination: false,
                node_info: Some(NodeInfo {
                    name: "vps-can0".into(),
                    description: None,
                    metadata: BTreeMap::new(),
                }),
            }],
        };

        let json = serde_json::to_value(result).unwrap();
        assert_eq!(json["target"], "21.0.0.2");
        assert_eq!(json["source_name"], "lambda");
        assert_eq!(json["hops"][0]["node_info"]["name"], "vps-can0");
        assert_eq!(json["hops"][0]["elapsed_ms"], 52.25);
    }

    #[tokio::test]
    async fn pinging_local_node_produces_complete_summary() {
        let config: Config = toml::from_str(include_str!("../config/example.toml")).unwrap();
        let result = ping(
            &config,
            "21.0.0.1".parse().unwrap(),
            3,
            Duration::from_millis(1),
        )
        .await
        .unwrap();

        assert_eq!(result.transmitted, 3);
        assert_eq!(result.received, 3);
        assert_eq!(result.loss_ppm, 0);
        assert_eq!(result.min_ms, Some(0.0));
        assert_eq!(result.avg_ms, Some(0.0));
        assert_eq!(result.max_ms, Some(0.0));
        assert!(result.samples.iter().all(|sample| sample.reached));
    }

    #[tokio::test]
    async fn dropping_ping_sample_receiver_cancels_remaining_probes() {
        let config: Config = toml::from_str(include_str!("../config/example.toml")).unwrap();
        let (sample_tx, mut sample_rx) = tokio::sync::mpsc::channel(1);
        let task = tokio::spawn(async move {
            ping_streaming(
                &config,
                "21.0.0.1".parse().unwrap(),
                20,
                Duration::from_secs(1),
                Some(sample_tx),
            )
            .await
        });

        assert!(sample_rx.recv().await.unwrap().reached);
        drop(sample_rx);
        let error = time::timeout(Duration::from_secs(1), task)
            .await
            .expect("cancelled ping should stop promptly")
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains("receiver closed"));
    }

    #[tokio::test]
    async fn ping_rejects_invalid_count_and_missing_address_family() {
        let mut config: Config = toml::from_str(include_str!("../config/example.toml")).unwrap();
        let count_error = ping(
            &config,
            "21.0.0.1".parse().unwrap(),
            0,
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert!(count_error.to_string().contains("count must be between"));

        config
            .node_addresses
            .retain(|address| address.addr().is_ipv4());
        let family_error = ping(&config, "21::2".parse().unwrap(), 1, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(family_error.to_string().contains("IPv6 probe address"));
    }

    #[test]
    fn ping_summary_counts_only_destination_responses() {
        let samples = vec![
            PingSample {
                sequence: 1,
                reached: true,
                address: Some("21.0.0.2".parse().unwrap()),
                elapsed_ms: Some(10.0),
                node_info: None,
            },
            PingSample {
                sequence: 2,
                reached: false,
                address: Some("21.0.0.3".parse().unwrap()),
                elapsed_ms: Some(20.0),
                node_info: None,
            },
            PingSample {
                sequence: 3,
                reached: false,
                address: None,
                elapsed_ms: None,
                node_info: None,
            },
        ];
        let result = summarize_ping(
            "21.0.0.2".parse().unwrap(),
            "21.0.0.1".parse().unwrap(),
            "branch-a".into(),
            samples,
        );

        assert_eq!(result.received, 1);
        assert_eq!(result.loss_ppm, 666_666);
        assert_eq!(result.min_ms, Some(10.0));
        assert_eq!(result.avg_ms, Some(10.0));
        assert_eq!(result.max_ms, Some(10.0));
    }
}

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

use anyhow::{Result, ensure};
use bytes::Bytes;

use crate::capacity_probe::{CapacityProbeMessage, PROBE_MAGIC, decode_probe};
use crate::delivery::{
    DELIVERY_MAGIC, DELIVERY_TAG_WIRE_BYTES, DeliveryMessage, DeliveryTag, decode_delivery,
};

const MAGIC: &[u8; 8] = b"ISWIP3\0\0";
const BATCH_MAGIC: &[u8; 8] = b"ISWBT2\0\0";
const REPAIR_MAGIC: &[u8; 8] = b"ISWRQ2\0\0";
const HEARTBEAT_MAGIC: &[u8; 8] = b"ISWHB2\0\0";
const REFRESH_MAGIC: &[u8; 8] = b"ISWRF2\0\0";
const ADDRESSES_MAGIC: &[u8; 8] = b"ISWAD2\0\0";
const HEADER_LEN: usize = 24;
pub const MAX_PACKET_FRAME_HEADER_LEN: usize = HEADER_LEN + DELIVERY_TAG_WIRE_BYTES;
const FLAG_DELIVERY_TAG: u16 = 1;
const BATCH_HEADER_LEN: usize = 10;
const REPAIR_HEADER_LEN: usize = 18;
const ASSEMBLY_TTL: Duration = Duration::from_secs(10);
const EXPIRY_INTERVAL: Duration = Duration::from_millis(250);
const MAX_ASSEMBLIES: usize = 4_096;
const MAX_BUFFERED_BYTES: usize = 32 * 1024 * 1024;
const MAX_PACKET_LEN: usize = u16::MAX as usize;
const MAX_REPAIR_ATTEMPTS: u8 = 2;
const MAX_REPAIR_OFFSETS: usize = 8;
const MAX_ADDRESS_CANDIDATES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairRequest {
    pub packet_id: u64,
    pub missing_offsets: Vec<u16>,
}

#[derive(Debug, Clone)]
pub enum WireDatagram {
    Frames(Vec<Bytes>),
    RepairRequest(RepairRequest),
    CapacityProbe(CapacityProbeMessage),
    Delivery(DeliveryMessage),
    Heartbeat,
    ConnectionRefresh,
    AddressCandidates(Vec<SocketAddr>),
}

pub fn encode_heartbeat() -> Bytes {
    Bytes::from_static(HEARTBEAT_MAGIC)
}

#[cfg(test)]
fn encode_connection_refresh() -> Bytes {
    Bytes::from_static(REFRESH_MAGIC)
}

pub fn encode_address_candidates(addresses: &[SocketAddr]) -> Result<Bytes> {
    ensure!(!addresses.is_empty(), "address candidate list is empty");
    ensure!(
        addresses.len() <= MAX_ADDRESS_CANDIDATES,
        "too many address candidates"
    );
    let length = ADDRESSES_MAGIC.len()
        + 2
        + addresses
            .iter()
            .map(|address| if address.is_ipv4() { 7 } else { 19 })
            .sum::<usize>();
    let mut bytes = Vec::with_capacity(length);
    bytes.extend_from_slice(ADDRESSES_MAGIC);
    bytes.extend_from_slice(&(addresses.len() as u16).to_be_bytes());
    for address in addresses {
        match address.ip() {
            IpAddr::V4(ip) => {
                bytes.push(4);
                bytes.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                bytes.push(6);
                bytes.extend_from_slice(&ip.octets());
            }
        }
        bytes.extend_from_slice(&address.port().to_be_bytes());
    }
    Ok(Bytes::from(bytes))
}

#[cfg(test)]
pub(crate) fn encode_packet(packet: &[u8], maximum: usize, packet_id: u64) -> Result<Vec<Bytes>> {
    encode_packet_tagged(packet, maximum, packet_id, None)
}

pub fn encode_packet_tagged(
    packet: &[u8],
    maximum: usize,
    packet_id: u64,
    delivery_tag: Option<DeliveryTag>,
) -> Result<Vec<Bytes>> {
    ensure!(!packet.is_empty(), "cannot frame an empty packet");
    ensure!(
        packet.len() <= MAX_PACKET_LEN,
        "packet exceeds wire protocol maximum"
    );
    let header_len = HEADER_LEN + delivery_tag.map_or(0, |_| DELIVERY_TAG_WIRE_BYTES);
    ensure!(maximum > header_len, "QUIC datagram limit is too small");

    let chunk_size = maximum - header_len;
    let mut frames = Vec::with_capacity(packet.len().div_ceil(chunk_size));
    for (index, chunk) in packet.chunks(chunk_size).enumerate() {
        let offset = index * chunk_size;
        let mut frame = Vec::with_capacity(header_len + chunk.len());
        frame.extend_from_slice(MAGIC);
        frame.extend_from_slice(&packet_id.to_be_bytes());
        frame.extend_from_slice(&(packet.len() as u16).to_be_bytes());
        frame.extend_from_slice(&(offset as u16).to_be_bytes());
        frame.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        frame.extend_from_slice(&delivery_tag.map_or(0, |_| FLAG_DELIVERY_TAG).to_be_bytes());
        if let Some(tag) = delivery_tag {
            frame.extend_from_slice(&tag.session_id.to_be_bytes());
            frame.extend_from_slice(&tag.sequence.to_be_bytes());
        }
        frame.extend_from_slice(chunk);
        frames.push(Bytes::from(frame));
    }
    Ok(frames)
}

pub fn encode_batch(frames: &[Bytes], maximum: usize) -> Result<Bytes> {
    ensure!(frames.len() >= 2, "a batch requires at least two frames");
    ensure!(
        frames.len() <= u16::MAX as usize,
        "too many frames in batch"
    );
    let length = BATCH_HEADER_LEN
        + frames
            .iter()
            .map(|frame| 2_usize.saturating_add(frame.len()))
            .sum::<usize>();
    ensure!(length <= maximum, "overlay batch exceeds path limit");
    let mut batch = Vec::with_capacity(length);
    batch.extend_from_slice(BATCH_MAGIC);
    batch.extend_from_slice(&(frames.len() as u16).to_be_bytes());
    for frame in frames {
        ensure!(frame.len() <= u16::MAX as usize, "batch frame is too large");
        batch.extend_from_slice(&(frame.len() as u16).to_be_bytes());
        batch.extend_from_slice(frame);
    }
    Ok(Bytes::from(batch))
}

pub fn encode_repair_request(request: &RepairRequest) -> Result<Bytes> {
    ensure!(
        !request.missing_offsets.is_empty(),
        "repair request has no missing offsets"
    );
    ensure!(
        request.missing_offsets.len() <= MAX_REPAIR_OFFSETS,
        "repair request has too many offsets"
    );
    let mut bytes = Vec::with_capacity(REPAIR_HEADER_LEN + request.missing_offsets.len() * 2);
    bytes.extend_from_slice(REPAIR_MAGIC);
    bytes.extend_from_slice(&request.packet_id.to_be_bytes());
    bytes.extend_from_slice(&(request.missing_offsets.len() as u16).to_be_bytes());
    for offset in &request.missing_offsets {
        bytes.extend_from_slice(&offset.to_be_bytes());
    }
    Ok(Bytes::from(bytes))
}

pub fn decode_datagram(datagram: Bytes) -> Result<WireDatagram> {
    ensure!(datagram.len() >= MAGIC.len(), "truncated overlay datagram");
    if &datagram[..MAGIC.len()] == MAGIC {
        return Ok(WireDatagram::Frames(vec![datagram]));
    }
    if datagram.as_ref() == HEARTBEAT_MAGIC {
        return Ok(WireDatagram::Heartbeat);
    }
    if datagram.as_ref() == REFRESH_MAGIC {
        return Ok(WireDatagram::ConnectionRefresh);
    }
    if &datagram[..PROBE_MAGIC.len()] == PROBE_MAGIC {
        return Ok(WireDatagram::CapacityProbe(decode_probe(&datagram)?));
    }
    if &datagram[..DELIVERY_MAGIC.len()] == DELIVERY_MAGIC {
        return Ok(WireDatagram::Delivery(decode_delivery(&datagram)?));
    }
    if &datagram[..ADDRESSES_MAGIC.len()] == ADDRESSES_MAGIC {
        return decode_address_candidates(&datagram);
    }
    if &datagram[..REPAIR_MAGIC.len()] == REPAIR_MAGIC {
        return decode_repair_request(&datagram);
    }
    ensure!(
        &datagram[..BATCH_MAGIC.len()] == BATCH_MAGIC,
        "invalid overlay datagram magic"
    );
    decode_batch(datagram)
}

fn decode_address_candidates(datagram: &[u8]) -> Result<WireDatagram> {
    ensure!(
        datagram.len() >= ADDRESSES_MAGIC.len() + 2,
        "truncated address candidates"
    );
    let count = usize::from(u16::from_be_bytes(datagram[8..10].try_into().unwrap()));
    ensure!(
        (1..=MAX_ADDRESS_CANDIDATES).contains(&count),
        "invalid address candidate count"
    );

    let mut cursor = 10;
    let mut addresses = Vec::with_capacity(count);
    for _ in 0..count {
        ensure!(
            cursor < datagram.len(),
            "truncated address candidate family"
        );
        let family = datagram[cursor];
        cursor += 1;
        let ip = match family {
            4 => {
                ensure!(cursor + 4 <= datagram.len(), "truncated IPv4 candidate");
                let octets: [u8; 4] = datagram[cursor..cursor + 4].try_into().unwrap();
                cursor += 4;
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            6 => {
                ensure!(cursor + 16 <= datagram.len(), "truncated IPv6 candidate");
                let octets: [u8; 16] = datagram[cursor..cursor + 16].try_into().unwrap();
                cursor += 16;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => anyhow::bail!("invalid address candidate family"),
        };
        ensure!(
            cursor + 2 <= datagram.len(),
            "truncated address candidate port"
        );
        let port = u16::from_be_bytes(datagram[cursor..cursor + 2].try_into().unwrap());
        cursor += 2;
        ensure!(port != 0, "address candidate has zero port");
        addresses.push(SocketAddr::new(ip, port));
    }
    ensure!(cursor == datagram.len(), "trailing address candidate bytes");
    Ok(WireDatagram::AddressCandidates(addresses))
}

fn decode_repair_request(datagram: &[u8]) -> Result<WireDatagram> {
    ensure!(
        datagram.len() >= REPAIR_HEADER_LEN,
        "invalid repair request length"
    );
    let packet_id = u64::from_be_bytes(datagram[8..16].try_into().unwrap());
    let count = usize::from(u16::from_be_bytes(datagram[16..18].try_into().unwrap()));
    ensure!(
        (1..=MAX_REPAIR_OFFSETS).contains(&count),
        "invalid repair offset count"
    );
    ensure!(
        datagram.len() == REPAIR_HEADER_LEN + count * 2,
        "repair request length mismatch"
    );
    let missing_offsets = datagram[REPAIR_HEADER_LEN..]
        .chunks_exact(2)
        .map(|bytes| u16::from_be_bytes(bytes.try_into().unwrap()))
        .collect();
    Ok(WireDatagram::RepairRequest(RepairRequest {
        packet_id,
        missing_offsets,
    }))
}

fn decode_batch(datagram: Bytes) -> Result<WireDatagram> {
    ensure!(
        datagram.len() >= BATCH_HEADER_LEN,
        "truncated overlay batch"
    );
    let count = usize::from(u16::from_be_bytes(datagram[8..10].try_into().unwrap()));
    ensure!(count >= 2, "overlay batch contains too few frames");
    let mut frames = Vec::with_capacity(count);
    let mut cursor = BATCH_HEADER_LEN;
    for _ in 0..count {
        ensure!(cursor + 2 <= datagram.len(), "truncated batch frame length");
        let length = usize::from(u16::from_be_bytes(
            datagram[cursor..cursor + 2].try_into().unwrap(),
        ));
        cursor += 2;
        ensure!(length >= HEADER_LEN, "invalid batch frame length");
        ensure!(cursor + length <= datagram.len(), "truncated batch frame");
        frames.push(datagram.slice(cursor..cursor + length));
        cursor += length;
    }
    ensure!(cursor == datagram.len(), "trailing bytes in overlay batch");
    Ok(WireDatagram::Frames(frames))
}

#[derive(Debug)]
struct Assembly {
    created: Instant,
    last_repair: Option<Instant>,
    repair_attempts: u8,
    buffer: Vec<u8>,
    received: Vec<bool>,
    received_count: usize,
    delivery_tag: Option<DeliveryTag>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReassembledPacket {
    pub data: Vec<u8>,
    pub delivery_tag: Option<DeliveryTag>,
}

#[derive(Debug)]
pub struct Reassembler {
    assemblies: HashMap<u64, Assembly>,
    buffered_bytes: usize,
    max_buffered_bytes: usize,
    next_expiry: Instant,
    evictions: u64,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self {
            assemblies: HashMap::new(),
            buffered_bytes: 0,
            max_buffered_bytes: MAX_BUFFERED_BYTES,
            next_expiry: Instant::now() + EXPIRY_INTERVAL,
            evictions: 0,
        }
    }
}

impl Reassembler {
    pub fn with_max_buffered_bytes(max_buffered_bytes: usize) -> Self {
        Self {
            max_buffered_bytes: max_buffered_bytes.max(u16::MAX as usize),
            ..Self::default()
        }
    }

    pub fn push(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.push_tagged(frame)?.map(|packet| packet.data))
    }

    pub fn push_tagged(&mut self, frame: &[u8]) -> Result<Option<ReassembledPacket>> {
        ensure!(frame.len() >= HEADER_LEN, "truncated overlay frame");
        ensure!(
            &frame[..MAGIC.len()] == MAGIC,
            "invalid overlay frame magic"
        );
        let packet_id = u64::from_be_bytes(frame[8..16].try_into().unwrap());
        let total_len = usize::from(u16::from_be_bytes(frame[16..18].try_into().unwrap()));
        let offset = usize::from(u16::from_be_bytes(frame[18..20].try_into().unwrap()));
        let fragment_len = usize::from(u16::from_be_bytes(frame[20..22].try_into().unwrap()));
        let flags = u16::from_be_bytes(frame[22..24].try_into().unwrap());
        ensure!(
            flags & !FLAG_DELIVERY_TAG == 0,
            "unsupported overlay frame flags"
        );
        let delivery_tag = if flags & FLAG_DELIVERY_TAG != 0 {
            ensure!(
                frame.len() >= HEADER_LEN + DELIVERY_TAG_WIRE_BYTES,
                "truncated delivery tag"
            );
            Some(DeliveryTag {
                session_id: u64::from_be_bytes(frame[24..32].try_into().unwrap()),
                sequence: u32::from_be_bytes(frame[32..36].try_into().unwrap()),
            })
        } else {
            None
        };
        let header_len = HEADER_LEN + delivery_tag.map_or(0, |_| DELIVERY_TAG_WIRE_BYTES);
        ensure!(total_len > 0, "invalid empty overlay packet");
        ensure!(fragment_len > 0, "invalid empty overlay fragment");
        ensure!(
            frame.len() == header_len + fragment_len,
            "overlay fragment length mismatch"
        );
        ensure!(
            offset + fragment_len <= total_len,
            "overlay fragment exceeds packet length"
        );

        self.expire(false);
        if offset == 0 && fragment_len == total_len {
            return Ok(Some(ReassembledPacket {
                data: frame[header_len..].to_vec(),
                delivery_tag,
            }));
        }

        if !self.assemblies.contains_key(&packet_id) {
            if self.assemblies.len() >= MAX_ASSEMBLIES
                || self.buffered_bytes.saturating_add(total_len) > self.max_buffered_bytes
            {
                self.make_room(total_len);
            }
            ensure!(
                self.assemblies.len() < MAX_ASSEMBLIES,
                "too many incomplete overlay packets"
            );
            ensure!(
                self.buffered_bytes.saturating_add(total_len) <= self.max_buffered_bytes,
                "incomplete overlay packets exceed memory limit"
            );
            self.buffered_bytes += total_len;
        }
        let assembly = self
            .assemblies
            .entry(packet_id)
            .or_insert_with(|| Assembly {
                created: Instant::now(),
                last_repair: None,
                repair_attempts: 0,
                buffer: vec![0; total_len],
                received: vec![false; total_len],
                received_count: 0,
                delivery_tag,
            });
        ensure!(
            assembly.buffer.len() == total_len,
            "overlay packet length changed"
        );
        ensure!(
            assembly.delivery_tag == delivery_tag,
            "overlay packet delivery tag changed"
        );

        for (relative, byte) in frame[header_len..].iter().copied().enumerate() {
            let position = offset + relative;
            if assembly.received[position] {
                ensure!(
                    assembly.buffer[position] == byte,
                    "conflicting duplicate overlay fragment"
                );
                continue;
            }
            assembly.buffer[position] = byte;
            assembly.received[position] = true;
            assembly.received_count += 1;
        }

        if assembly.received_count == total_len {
            let complete = self.assemblies.remove(&packet_id);
            if let Some(complete) = complete {
                self.buffered_bytes = self.buffered_bytes.saturating_sub(complete.buffer.len());
                return Ok(Some(ReassembledPacket {
                    data: complete.buffer,
                    delivery_tag: complete.delivery_tag,
                }));
            }
        }
        Ok(None)
    }

    pub fn repair_requests(&mut self, delay: Duration, limit: usize) -> Vec<RepairRequest> {
        self.expire(false);
        let now = Instant::now();
        self.assemblies
            .iter_mut()
            .filter_map(|(packet_id, assembly)| {
                let missing_offsets = missing_offsets(assembly);
                let due = now.duration_since(assembly.created) >= delay
                    && assembly.repair_attempts < MAX_REPAIR_ATTEMPTS
                    && assembly.received_count.saturating_mul(2) >= assembly.buffer.len()
                    && !missing_offsets.is_empty()
                    && missing_offsets.len() <= MAX_REPAIR_OFFSETS
                    && assembly
                        .last_repair
                        .is_none_or(|last| now.duration_since(last) >= delay);
                if due {
                    assembly.last_repair = Some(now);
                    assembly.repair_attempts += 1;
                    Some(RepairRequest {
                        packet_id: *packet_id,
                        missing_offsets,
                    })
                } else {
                    None
                }
            })
            .take(limit)
            .collect()
    }

    pub fn take_evictions(&mut self) -> u64 {
        std::mem::take(&mut self.evictions)
    }

    fn expire(&mut self, force: bool) {
        let now = Instant::now();
        if !force && now < self.next_expiry {
            return;
        }
        self.assemblies
            .retain(|_, assembly| assembly.created.elapsed() < ASSEMBLY_TTL);
        self.buffered_bytes = self
            .assemblies
            .values()
            .map(|assembly| assembly.buffer.len())
            .sum();
        self.next_expiry = now + EXPIRY_INTERVAL;
    }

    fn make_room(&mut self, incoming: usize) {
        self.expire(true);
        while self.assemblies.len() >= MAX_ASSEMBLIES
            || self.buffered_bytes.saturating_add(incoming) > self.max_buffered_bytes
        {
            let Some(oldest) = self
                .assemblies
                .iter()
                .min_by_key(|(_, assembly)| assembly.created)
                .map(|(packet_id, _)| *packet_id)
            else {
                break;
            };
            if let Some(assembly) = self.assemblies.remove(&oldest) {
                self.buffered_bytes = self.buffered_bytes.saturating_sub(assembly.buffer.len());
                self.evictions += 1;
            }
        }
    }
}

fn missing_offsets(assembly: &Assembly) -> Vec<u16> {
    assembly
        .received
        .iter()
        .enumerate()
        .filter_map(|(offset, received)| {
            if !received && (offset == 0 || assembly.received[offset - 1]) {
                Some(offset as u16)
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragmented_packet_reassembles_out_of_order() {
        let packet: Vec<u8> = (0..=255).cycle().take(4_000).collect();
        let mut frames = encode_packet(&packet, 1_200, 42).unwrap();
        frames.reverse();
        let mut reassembler = Reassembler::default();
        let mut complete = None;
        for frame in frames {
            if let Some(packet) = reassembler.push(&frame).unwrap() {
                complete = Some(packet);
            }
        }
        assert_eq!(complete.unwrap(), packet);
    }

    #[test]
    fn unfragmented_packet_round_trips() {
        let packet = vec![7; 128];
        let frame = encode_packet(&packet, 1_200, 1).unwrap().remove(0);
        assert_eq!(
            Reassembler::default().push(&frame).unwrap().unwrap(),
            packet
        );
    }

    #[test]
    fn delivery_tag_survives_fragmentation_and_out_of_order_reassembly() {
        let packet = vec![9; 4_000];
        let tag = DeliveryTag {
            session_id: 77,
            sequence: 12,
        };
        let mut frames = encode_packet_tagged(&packet, 1_200, 9, Some(tag)).unwrap();
        frames.reverse();
        let mut reassembler = Reassembler::default();
        let mut complete = None;
        for frame in frames {
            if let Some(value) = reassembler.push_tagged(&frame).unwrap() {
                complete = Some(value);
            }
        }
        assert_eq!(
            complete.unwrap(),
            ReassembledPacket {
                data: packet,
                delivery_tag: Some(tag),
            }
        );
    }

    #[test]
    fn batched_frames_decode_without_copying_payloads() {
        let first = encode_packet(&[1; 80], 1_200, 1).unwrap().remove(0);
        let second = encode_packet(&[2; 90], 1_200, 2).unwrap().remove(0);
        let batch = encode_batch(&[first, second], 1_200).unwrap();
        let WireDatagram::Frames(frames) = decode_datagram(batch).unwrap() else {
            panic!("expected a frame batch");
        };
        let mut reassembler = Reassembler::default();
        assert_eq!(reassembler.push(&frames[0]).unwrap().unwrap(), vec![1; 80]);
        assert_eq!(reassembler.push(&frames[1]).unwrap().unwrap(), vec![2; 90]);
    }

    #[test]
    fn repair_request_round_trips() {
        let request = RepairRequest {
            packet_id: 123,
            missing_offsets: vec![0, 976],
        };
        let WireDatagram::RepairRequest(decoded) =
            decode_datagram(encode_repair_request(&request).unwrap()).unwrap()
        else {
            panic!("expected repair request");
        };
        assert_eq!(decoded, request);
    }

    #[test]
    fn heartbeat_round_trips_and_rejects_trailing_data() {
        assert!(matches!(
            decode_datagram(encode_heartbeat()).unwrap(),
            WireDatagram::Heartbeat
        ));
        let mut invalid = encode_heartbeat().to_vec();
        invalid.push(0);
        assert!(decode_datagram(Bytes::from(invalid)).is_err());
    }

    #[test]
    fn connection_refresh_round_trips() {
        assert!(matches!(
            decode_datagram(encode_connection_refresh()).unwrap(),
            WireDatagram::ConnectionRefresh
        ));
    }

    #[test]
    fn address_candidates_round_trip() {
        let addresses = vec![
            "111.62.241.102:10119".parse().unwrap(),
            "[2001:db8::1]:4000".parse().unwrap(),
        ];
        let WireDatagram::AddressCandidates(decoded) =
            decode_datagram(encode_address_candidates(&addresses).unwrap()).unwrap()
        else {
            panic!("expected address candidates");
        };
        assert_eq!(decoded, addresses);
    }

    #[test]
    fn incomplete_assembly_requests_at_most_two_repairs() {
        let packet = vec![9; 1_280];
        let frames = encode_packet(&packet, 1_000, 77).unwrap();
        let mut reassembler = Reassembler::default();
        reassembler.push(&frames[0]).unwrap();
        let expected = vec![RepairRequest {
            packet_id: 77,
            missing_offsets: vec![976],
        }];
        assert_eq!(reassembler.repair_requests(Duration::ZERO, 1), expected);
        assert_eq!(reassembler.repair_requests(Duration::ZERO, 1), expected);
        assert!(reassembler.repair_requests(Duration::ZERO, 1).is_empty());
    }

    #[test]
    fn full_reassembly_table_evicts_oldest_packet() {
        let packet = vec![5; 1_280];
        let mut reassembler = Reassembler::default();
        for packet_id in 0..=MAX_ASSEMBLIES as u64 {
            let frame = encode_packet(&packet, 1_000, packet_id).unwrap().remove(0);
            assert!(reassembler.push(&frame).unwrap().is_none());
        }
        assert_eq!(reassembler.assemblies.len(), MAX_ASSEMBLIES);
        assert_eq!(reassembler.take_evictions(), 1);
    }

    #[test]
    fn supports_bandwidth_delay_product_larger_than_legacy_window() {
        let packets: Vec<Vec<u8>> = (0..512)
            .map(|packet_id| (0..=255).cycle().skip(packet_id).take(1_280).collect())
            .collect();
        let frames: Vec<Vec<Bytes>> = packets
            .iter()
            .enumerate()
            .map(|(packet_id, packet)| encode_packet(packet, 1_000, packet_id as u64).unwrap())
            .collect();
        let mut reassembler = Reassembler::default();

        for packet_frames in &frames {
            assert!(reassembler.push(&packet_frames[0]).unwrap().is_none());
        }
        for (expected, packet_frames) in packets.iter().zip(&frames) {
            let complete = reassembler.push(&packet_frames[1]).unwrap().unwrap();
            assert_eq!(&complete, expected);
        }
        assert_eq!(reassembler.buffered_bytes, 0);
    }

    #[test]
    fn rejects_legacy_unframed_packets() {
        let mut legacy_packet = vec![0_u8; 20];
        legacy_packet[0] = 0x45;
        legacy_packet[2..4].copy_from_slice(&20_u16.to_be_bytes());
        assert!(Reassembler::default().push(&legacy_packet).is_err());
    }
}

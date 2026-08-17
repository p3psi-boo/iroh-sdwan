use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    ops::Range,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Result, ensure};
use bytes::{BufMut, Bytes, BytesMut};

use crate::buffer::{BufferBudget, BufferPermit, DataplaneBuf};
use crate::capacity_probe::{CapacityProbeMessage, decode_probe};
use crate::delivery::{DELIVERY_TAG_WIRE_BYTES, DeliveryMessage, DeliveryTag, decode_delivery};
use crate::protocol::envelope::{self, Envelope, HEADER_LEN as ENVELOPE_HEADER_LEN, MessageType};

const HEADER_LEN: usize = 16;
pub const MAX_PACKET_FRAME_HEADER_LEN: usize =
    ENVELOPE_HEADER_LEN + HEADER_LEN + DELIVERY_TAG_WIRE_BYTES;
const FLAG_DELIVERY_TAG: u16 = 1;
const BATCH_HEADER_LEN: usize = 2;
const REPAIR_HEADER_LEN: usize = 10;
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

/// Cumulative receiver-side evidence used by the sender's adaptive FEC
/// controller.  Cumulative values make the feedback robust to loss of the
/// unreliable heartbeat datagram; the sender derives interval deltas from the
/// newest report it receives.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FecFeedback {
    pub received_recovery_shards: u64,
    pub recovered_data_shards: u64,
    pub expired_blocks: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Heartbeat {
    pub fec_feedback: Option<FecFeedback>,
}

#[derive(Debug, Clone)]
pub enum WireDatagram {
    Frames(Vec<Bytes>),
    RepairRequest(RepairRequest),
    CapacityProbe(CapacityProbeMessage),
    Delivery(DeliveryMessage),
    Heartbeat(Heartbeat),
    ConnectionRefresh,
    AddressCandidates(Vec<SocketAddr>),
}

pub fn encode_heartbeat() -> Bytes {
    Envelope::new(MessageType::Heartbeat, Bytes::new())
        .encode()
        .expect("empty V1 heartbeat envelope is valid")
}

pub fn encode_heartbeat_with_fec_feedback(feedback: FecFeedback) -> Bytes {
    const VERSION: u8 = 1;
    let mut payload = BytesMut::with_capacity(1 + 3 * size_of::<u64>());
    payload.put_u8(VERSION);
    payload.put_u64(feedback.received_recovery_shards);
    payload.put_u64(feedback.recovered_data_shards);
    payload.put_u64(feedback.expired_blocks);
    Envelope::new(MessageType::Heartbeat, payload.freeze())
        .encode()
        .expect("bounded V1 heartbeat feedback is valid")
}

#[cfg(test)]
fn encode_connection_refresh() -> Bytes {
    Envelope::new(MessageType::ConnectionRefresh, Bytes::new())
        .encode()
        .expect("empty V1 refresh envelope is valid")
}

pub fn encode_address_candidates(addresses: &[SocketAddr]) -> Result<Bytes> {
    ensure!(!addresses.is_empty(), "address candidate list is empty");
    ensure!(
        addresses.len() <= MAX_ADDRESS_CANDIDATES,
        "too many address candidates"
    );
    let length = 2 + addresses
        .iter()
        .map(|address| if address.is_ipv4() { 7 } else { 19 })
        .sum::<usize>();
    let mut bytes = Vec::with_capacity(length);
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
    envelope::encode_parts(MessageType::AddressCandidates, 0, &[], &bytes)
}

#[cfg(test)]
pub(crate) fn encode_packet(packet: &[u8], maximum: usize, packet_id: u64) -> Result<Vec<Bytes>> {
    encode_packet_tagged(packet, maximum, packet_id, None)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EncodeStats {
    pub payload_copy_bytes: u64,
    pub frames: u64,
}

pub fn encode_packet_tagged(
    packet: &[u8],
    maximum: usize,
    packet_id: u64,
    delivery_tag: Option<DeliveryTag>,
) -> Result<Vec<Bytes>> {
    let mut packet = DataplaneBuf::from_bytes(Bytes::copy_from_slice(packet));
    encode_packet_from_buf(&mut packet, maximum, packet_id, delivery_tag).map(|(frames, _)| frames)
}

/// Encode an owned packet. A unique buffer with enough unused prefix is
/// sealed in place for the single-datagram case (`payload_copy_bytes == 0`).
/// Jumbo packets freeze the payload once and copy each fragment once.
pub fn encode_packet_from_buf(
    packet: &mut DataplaneBuf,
    maximum: usize,
    packet_id: u64,
    delivery_tag: Option<DeliveryTag>,
) -> Result<(Vec<Bytes>, EncodeStats)> {
    ensure!(!packet.is_empty(), "cannot frame an empty packet");
    ensure!(
        packet.len() <= MAX_PACKET_LEN,
        "packet exceeds wire protocol maximum"
    );
    let fragment_header_len = HEADER_LEN + delivery_tag.map_or(0, |_| DELIVERY_TAG_WIRE_BYTES);
    let sealed_header_len = ENVELOPE_HEADER_LEN + fragment_header_len;
    ensure!(
        maximum > sealed_header_len,
        "QUIC datagram limit is too small"
    );

    let chunk_size = maximum - sealed_header_len;
    if packet.len() <= chunk_size {
        let header = fragment_header(packet_id, packet.len(), 0, packet.len(), delivery_tag);
        // Temporarily remove the only owner so Bytes::try_into_mut can patch
        // the reserved prefix in place. Restore the logical payload as a slice
        // of the sealed frame for retry/requeue ownership.
        let owned = std::mem::take(packet);
        let (frame, copies) = seal_fragment(owned, &header);
        *packet = DataplaneBuf::from_bytes(frame.slice(sealed_header_len..));
        return Ok((
            vec![frame],
            EncodeStats {
                payload_copy_bytes: copies.saturating_mul(packet.len() as u64),
                frames: 1,
            },
        ));
    }

    let payload = packet.as_slice();
    let frame_count = payload.len().div_ceil(chunk_size);
    let allocation_len = payload
        .len()
        .saturating_add(frame_count.saturating_mul(sealed_header_len));
    // All jumbo fragments share one allocation. This retains the unavoidable
    // single payload copy required by noq's contiguous DATAGRAM API while
    // removing one allocator trip and one ref-count owner per fragment.
    let mut backing = BytesMut::with_capacity(allocation_len);
    let mut ranges = Vec::with_capacity(frame_count);
    for (index, chunk) in payload.chunks(chunk_size).enumerate() {
        let start = backing.len();
        let offset = index * chunk_size;
        let header = fragment_header(packet_id, payload.len(), offset, chunk.len(), delivery_tag);
        envelope::write_header(
            &mut backing,
            MessageType::IpFragment,
            0,
            ENVELOPE_HEADER_LEN as u16,
        );
        backing.extend_from_slice(&header);
        backing.extend_from_slice(chunk);
        ranges.push(start..backing.len());
    }
    let backing = backing.freeze();
    let frames = ranges
        .into_iter()
        .map(|range| backing.slice(range))
        .collect::<Vec<_>>();
    let frame_count = frames.len() as u64;
    Ok((
        frames,
        EncodeStats {
            payload_copy_bytes: payload.len() as u64,
            frames: frame_count,
        },
    ))
}

fn fragment_header(
    packet_id: u64,
    total_len: usize,
    offset: usize,
    chunk_len: usize,
    delivery_tag: Option<DeliveryTag>,
) -> Vec<u8> {
    let mut header =
        Vec::with_capacity(HEADER_LEN + delivery_tag.map_or(0, |_| DELIVERY_TAG_WIRE_BYTES));
    header.extend_from_slice(&packet_id.to_be_bytes());
    header.extend_from_slice(&(total_len as u16).to_be_bytes());
    header.extend_from_slice(&(offset as u16).to_be_bytes());
    header.extend_from_slice(&(chunk_len as u16).to_be_bytes());
    header.extend_from_slice(&delivery_tag.map_or(0, |_| FLAG_DELIVERY_TAG).to_be_bytes());
    if let Some(tag) = delivery_tag {
        header.extend_from_slice(&tag.session_id.to_be_bytes());
        header.extend_from_slice(&tag.sequence.to_be_bytes());
    }
    header
}

fn seal_fragment(packet: DataplaneBuf, fragment_header: &[u8]) -> (Bytes, u64) {
    let needed = ENVELOPE_HEADER_LEN + fragment_header.len();
    if packet.can_prepend(needed) {
        let mut prefix = [0_u8; ENVELOPE_HEADER_LEN + HEADER_LEN + DELIVERY_TAG_WIRE_BYTES];
        envelope::write_header_at(
            &mut prefix[..ENVELOPE_HEADER_LEN],
            MessageType::IpFragment,
            0,
        )
        .expect("fixed-size envelope prefix always fits");
        prefix[ENVELOPE_HEADER_LEN..needed].copy_from_slice(fragment_header);
        match packet.try_prepend(&prefix[..needed]) {
            Ok(frame) => return (frame, 0),
            Err(packet) => {
                return (packet.copy_with_prefix(&prefix[..needed]), 1);
            }
        }
    }
    let mut out = BytesMut::with_capacity(needed + packet.len());
    envelope::write_header(
        &mut out,
        MessageType::IpFragment,
        0,
        ENVELOPE_HEADER_LEN as u16,
    );
    out.extend_from_slice(fragment_header);
    out.extend_from_slice(packet.as_slice());
    (out.freeze(), 1)
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
    ensure!(
        length + ENVELOPE_HEADER_LEN <= maximum,
        "overlay batch exceeds path limit"
    );
    let mut batch = BytesMut::with_capacity(length);
    batch.put_u16(frames.len() as u16);
    for frame in frames {
        ensure!(frame.len() <= u16::MAX as usize, "batch frame is too large");
        batch.put_u16(frame.len() as u16);
        batch.extend_from_slice(frame);
    }
    envelope::encode_parts(MessageType::IpBatch, 0, &[], &batch)
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
    bytes.extend_from_slice(&request.packet_id.to_be_bytes());
    bytes.extend_from_slice(&(request.missing_offsets.len() as u16).to_be_bytes());
    for offset in &request.missing_offsets {
        bytes.extend_from_slice(&offset.to_be_bytes());
    }
    envelope::encode_parts(MessageType::RepairRequest, 0, &[], &bytes)
}

pub fn decode_datagram(datagram: Bytes) -> Result<WireDatagram> {
    let envelope = Envelope::decode(datagram)?;
    ensure!(envelope.flags == 0, "unsupported V1 datagram flags");
    ensure!(
        envelope.extension.is_empty(),
        "unexpected V1 datagram extension"
    );
    match envelope.kind {
        MessageType::IpFragment => Ok(WireDatagram::Frames(vec![envelope.payload])),
        MessageType::IpBatch => decode_batch(envelope.payload),
        MessageType::RepairRequest => decode_repair_request(&envelope.payload),
        MessageType::CapacityProbe => Ok(WireDatagram::CapacityProbe(decode_probe(
            &envelope.payload,
        )?)),
        MessageType::Delivery => Ok(WireDatagram::Delivery(decode_delivery(&envelope.payload)?)),
        MessageType::Heartbeat => decode_heartbeat(&envelope.payload),
        MessageType::ConnectionRefresh => {
            ensure!(envelope.payload.is_empty(), "refresh payload is not empty");
            Ok(WireDatagram::ConnectionRefresh)
        }
        MessageType::AddressCandidates => decode_address_candidates(&envelope.payload),
        MessageType::FecShard => anyhow::bail!("FEC shard reached the inner V1 decoder"),
    }
}

fn decode_heartbeat(payload: &[u8]) -> Result<WireDatagram> {
    if payload.is_empty() {
        return Ok(WireDatagram::Heartbeat(Heartbeat::default()));
    }
    const VERSION: u8 = 1;
    const FEEDBACK_LEN: usize = 1 + 3 * size_of::<u64>();
    ensure!(
        payload.len() == FEEDBACK_LEN,
        "invalid heartbeat feedback length"
    );
    ensure!(
        payload[0] == VERSION,
        "unsupported heartbeat feedback version"
    );
    Ok(WireDatagram::Heartbeat(Heartbeat {
        fec_feedback: Some(FecFeedback {
            received_recovery_shards: u64::from_be_bytes(payload[1..9].try_into().unwrap()),
            recovered_data_shards: u64::from_be_bytes(payload[9..17].try_into().unwrap()),
            expired_blocks: u64::from_be_bytes(payload[17..25].try_into().unwrap()),
        }),
    }))
}

fn decode_address_candidates(datagram: &[u8]) -> Result<WireDatagram> {
    ensure!(datagram.len() >= 2, "truncated address candidates");
    let count = usize::from(u16::from_be_bytes(datagram[0..2].try_into().unwrap()));
    ensure!(
        (1..=MAX_ADDRESS_CANDIDATES).contains(&count),
        "invalid address candidate count"
    );

    let mut cursor = 2;
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
    let packet_id = u64::from_be_bytes(datagram[0..8].try_into().unwrap());
    let count = usize::from(u16::from_be_bytes(datagram[8..10].try_into().unwrap()));
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
    let count = usize::from(u16::from_be_bytes(datagram[0..2].try_into().unwrap()));
    ensure!(count >= 2, "overlay batch contains too few frames");
    let mut frames = Vec::with_capacity(count);
    let mut cursor = BATCH_HEADER_LEN;
    for _ in 0..count {
        ensure!(cursor + 2 <= datagram.len(), "truncated batch frame length");
        let length = usize::from(u16::from_be_bytes(
            datagram[cursor..cursor + 2].try_into().unwrap(),
        ));
        cursor += 2;
        ensure!(
            length >= ENVELOPE_HEADER_LEN + HEADER_LEN,
            "invalid batch frame length"
        );
        ensure!(cursor + length <= datagram.len(), "truncated batch frame");
        let frame = Envelope::decode(datagram.slice(cursor..cursor + length))?;
        ensure!(
            frame.kind == MessageType::IpFragment,
            "batch item is not an IP fragment"
        );
        ensure!(
            frame.flags == 0 && frame.extension.is_empty(),
            "unsupported batched fragment envelope"
        );
        frames.push(frame.payload);
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
    /// Owns both the virtio prefix and the reassembled payload so completion
    /// can hand the allocation to the tunnel without another packet-sized
    /// copy.
    buffer: BytesMut,
    total_len: usize,
    /// Sorted, disjoint byte ranges already present in `buffer`. Fragment
    /// count is bounded by packet length / path MTU, so range merging avoids a
    /// second allocation proportional to every packet byte and replaces the
    /// previous byte-at-a-time hot loop with slice copies.
    received_ranges: Vec<Range<usize>>,
    received_count: usize,
    delivery_tag: Option<DeliveryTag>,
    _budget_permit: Option<BufferPermit>,
}

#[derive(Debug, Clone)]
pub struct ReassembledPacket {
    pub data: DataplaneBuf,
    pub delivery_tag: Option<DeliveryTag>,
}

impl PartialEq for ReassembledPacket {
    fn eq(&self, other: &Self) -> bool {
        self.data.as_slice() == other.data.as_slice() && self.delivery_tag == other.delivery_tag
    }
}

impl Eq for ReassembledPacket {}

#[derive(Debug)]
pub struct Reassembler {
    assemblies: HashMap<u64, Assembly>,
    /// Creation-ordered ids. Completed ids may remain as tombstones and are
    /// discarded lazily, making expiry and eviction O(1) amortized.
    order: VecDeque<(u64, Instant)>,
    repair_clock: VecDeque<(u64, Instant)>,
    buffered_bytes: usize,
    max_buffered_bytes: usize,
    next_expiry: Instant,
    evictions: u64,
    copy_bytes: u64,
    budget: Option<Arc<BufferBudget>>,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self {
            assemblies: HashMap::new(),
            order: VecDeque::new(),
            repair_clock: VecDeque::new(),
            buffered_bytes: 0,
            max_buffered_bytes: MAX_BUFFERED_BYTES,
            next_expiry: Instant::now() + EXPIRY_INTERVAL,
            evictions: 0,
            copy_bytes: 0,
            budget: None,
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

    pub fn with_max_buffered_bytes_and_budget(
        max_buffered_bytes: usize,
        budget: Option<Arc<BufferBudget>>,
    ) -> Self {
        Self {
            max_buffered_bytes: max_buffered_bytes.max(u16::MAX as usize),
            budget,
            ..Self::default()
        }
    }

    pub fn push(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self
            .push_tagged(Bytes::copy_from_slice(frame))?
            .map(|packet| packet.data.as_slice().to_vec()))
    }

    pub fn push_tagged(&mut self, frame: Bytes) -> Result<Option<ReassembledPacket>> {
        if frame.starts_with(crate::protocol::envelope::MAGIC) {
            let envelope = Envelope::decode(frame)?;
            ensure!(
                envelope.kind == MessageType::IpFragment,
                "V1 envelope does not contain an IP fragment"
            );
            return self.push_tagged(envelope.payload);
        }
        ensure!(frame.len() >= HEADER_LEN, "truncated overlay frame");
        let packet_id = u64::from_be_bytes(frame[0..8].try_into().unwrap());
        let total_len = usize::from(u16::from_be_bytes(frame[8..10].try_into().unwrap()));
        let offset = usize::from(u16::from_be_bytes(frame[10..12].try_into().unwrap()));
        let fragment_len = usize::from(u16::from_be_bytes(frame[12..14].try_into().unwrap()));
        let flags = u16::from_be_bytes(frame[14..16].try_into().unwrap());
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
                session_id: u64::from_be_bytes(frame[16..24].try_into().unwrap()),
                sequence: u32::from_be_bytes(frame[24..28].try_into().unwrap()),
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
                data: DataplaneBuf::from_pooled(frame, header_len),
                delivery_tag,
            }));
        }

        let mut budget_permit = None;
        let mut assembly_created = None;
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
            if let Some(budget) = self.budget.clone() {
                loop {
                    if let Some(permit) = budget.try_acquire(total_len) {
                        budget_permit = Some(permit);
                        break;
                    }
                    ensure!(
                        self.evict_oldest(),
                        "process payload budget exhausted by incomplete overlay packets"
                    );
                }
            }
            self.buffered_bytes += total_len;
            let created = Instant::now();
            self.order.push_back((packet_id, created));
            self.repair_clock.push_back((packet_id, created));
            assembly_created = Some(created);
        }
        let assembly = self
            .assemblies
            .entry(packet_id)
            .or_insert_with(|| Assembly {
                created: assembly_created.unwrap_or_else(Instant::now),
                last_repair: None,
                repair_attempts: 0,
                buffer: BytesMut::zeroed(tun_rs::VIRTIO_NET_HDR_LEN + total_len),
                total_len,
                received_ranges: Vec::with_capacity(8),
                received_count: 0,
                delivery_tag,
                _budget_permit: budget_permit,
            });
        ensure!(
            assembly.total_len == total_len,
            "overlay packet length changed"
        );
        ensure!(
            assembly.delivery_tag == delivery_tag,
            "overlay packet delivery tag changed"
        );

        let copied = record_fragment(assembly, offset, &frame[header_len..])?;
        self.copy_bytes = self.copy_bytes.saturating_add(copied as u64);

        if assembly.received_count == total_len {
            let complete = self.assemblies.remove(&packet_id);
            if let Some(complete) = complete {
                self.buffered_bytes = self.buffered_bytes.saturating_sub(complete.total_len);
                self.compact_metadata_if_needed();
                return Ok(Some(ReassembledPacket {
                    data: DataplaneBuf::from_pooled(
                        complete.buffer.freeze(),
                        tun_rs::VIRTIO_NET_HDR_LEN,
                    ),
                    delivery_tag: complete.delivery_tag,
                }));
            }
        }
        Ok(None)
    }

    pub fn repair_requests(&mut self, delay: Duration, limit: usize) -> Vec<RepairRequest> {
        self.expire(false);
        if limit == 0 {
            return Vec::new();
        }
        let now = Instant::now();
        let checks = self
            .repair_clock
            .len()
            .min(limit.saturating_mul(4).clamp(16, 256));
        let mut requests = Vec::with_capacity(limit.min(16));
        for _ in 0..checks {
            let Some((packet_id, created)) = self.repair_clock.pop_front() else {
                break;
            };
            let Some(assembly) = self.assemblies.get_mut(&packet_id) else {
                continue;
            };
            if assembly.created != created {
                continue;
            }
            self.repair_clock.push_back((packet_id, created));
            let due = now.duration_since(assembly.created) >= delay
                && assembly.repair_attempts < MAX_REPAIR_ATTEMPTS
                && assembly.received_count.saturating_mul(2) >= assembly.total_len
                && assembly
                    .last_repair
                    .is_none_or(|last| now.duration_since(last) >= delay);
            if !due {
                continue;
            }
            let missing_offsets = missing_offsets(assembly);
            if missing_offsets.is_empty() || missing_offsets.len() > MAX_REPAIR_OFFSETS {
                continue;
            }
            assembly.last_repair = Some(now);
            assembly.repair_attempts += 1;
            requests.push(RepairRequest {
                packet_id,
                missing_offsets,
            });
            if requests.len() == limit {
                break;
            }
        }
        requests
    }

    pub fn take_evictions(&mut self) -> u64 {
        std::mem::take(&mut self.evictions)
    }

    pub fn take_copy_bytes(&mut self) -> u64 {
        std::mem::take(&mut self.copy_bytes)
    }

    fn expire(&mut self, force: bool) {
        let now = Instant::now();
        if !force && now < self.next_expiry {
            return;
        }
        while let Some(&(packet_id, created)) = self.order.front() {
            let Some(assembly) = self.assemblies.get(&packet_id) else {
                self.order.pop_front();
                continue;
            };
            if assembly.created != created {
                self.order.pop_front();
                continue;
            }
            if now.duration_since(created) < ASSEMBLY_TTL {
                break;
            }
            self.order.pop_front();
            if let Some(assembly) = self.assemblies.remove(&packet_id) {
                self.buffered_bytes = self.buffered_bytes.saturating_sub(assembly.total_len);
            }
        }
        self.next_expiry = now + EXPIRY_INTERVAL;
        self.compact_metadata_if_needed();
    }

    fn make_room(&mut self, incoming: usize) {
        self.expire(true);
        while self.assemblies.len() >= MAX_ASSEMBLIES
            || self.buffered_bytes.saturating_add(incoming) > self.max_buffered_bytes
        {
            if !self.evict_oldest() {
                break;
            }
        }
    }

    fn evict_oldest(&mut self) -> bool {
        while let Some((packet_id, created)) = self.order.pop_front() {
            let is_current = self
                .assemblies
                .get(&packet_id)
                .is_some_and(|assembly| assembly.created == created);
            if !is_current {
                continue;
            }
            if let Some(assembly) = self.assemblies.remove(&packet_id) {
                self.buffered_bytes = self.buffered_bytes.saturating_sub(assembly.total_len);
                self.evictions += 1;
                self.compact_metadata_if_needed();
                return true;
            }
        }
        false
    }

    fn compact_metadata_if_needed(&mut self) {
        let bound = self.assemblies.len().saturating_mul(4).max(64);
        if self.order.len() <= bound && self.repair_clock.len() <= bound {
            return;
        }
        let mut live = self
            .assemblies
            .iter()
            .map(|(packet_id, assembly)| (*packet_id, assembly.created))
            .collect::<Vec<_>>();
        live.sort_unstable_by_key(|(_, created)| *created);
        self.order = live.iter().copied().collect();
        self.repair_clock = live.into_iter().collect();
    }
}

fn missing_offsets(assembly: &Assembly) -> Vec<u16> {
    let mut missing = Vec::new();
    let mut covered_until = 0_usize;
    for range in &assembly.received_ranges {
        if range.start > covered_until {
            missing.push(covered_until as u16);
        }
        covered_until = covered_until.max(range.end);
    }
    if covered_until < assembly.total_len {
        missing.push(covered_until as u16);
    }
    missing
}

fn record_fragment(assembly: &mut Assembly, offset: usize, data: &[u8]) -> Result<usize> {
    let end = offset + data.len();
    let payload_offset = tun_rs::VIRTIO_NET_HDR_LEN;
    let mut already_received = 0_usize;
    for range in &assembly.received_ranges {
        let overlap_start = offset.max(range.start);
        let overlap_end = end.min(range.end);
        if overlap_start >= overlap_end {
            continue;
        }
        let incoming_start = overlap_start - offset;
        let incoming_end = overlap_end - offset;
        ensure!(
            assembly.buffer[payload_offset + overlap_start..payload_offset + overlap_end]
                == data[incoming_start..incoming_end],
            "conflicting duplicate overlay fragment"
        );
        already_received += overlap_end - overlap_start;
    }

    if already_received == data.len() {
        return Ok(0);
    }
    assembly.buffer[payload_offset + offset..payload_offset + end].copy_from_slice(data);
    assembly.received_count = assembly
        .received_count
        .saturating_add(data.len().saturating_sub(already_received));

    let mut merged_start = offset;
    let mut merged_end = end;
    let mut first = 0_usize;
    while first < assembly.received_ranges.len()
        && assembly.received_ranges[first].end < merged_start
    {
        first += 1;
    }
    let mut last = first;
    while last < assembly.received_ranges.len()
        && assembly.received_ranges[last].start <= merged_end
    {
        merged_start = merged_start.min(assembly.received_ranges[last].start);
        merged_end = merged_end.max(assembly.received_ranges[last].end);
        last += 1;
    }
    assembly
        .received_ranges
        .splice(first..last, std::iter::once(merged_start..merged_end));
    Ok(data.len())
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
    fn jumbo_fragments_share_one_backing_allocation_and_copy_payload_once() {
        let mut packet = DataplaneBuf::from_vec(vec![7; 4_000]);
        let (frames, stats) = encode_packet_from_buf(&mut packet, 1_200, 42, None).unwrap();
        assert_eq!(stats.payload_copy_bytes, 4_000);
        assert_eq!(stats.frames, frames.len() as u64);
        for adjacent in frames.windows(2) {
            assert_eq!(
                adjacent[0].as_ptr().wrapping_add(adjacent[0].len()),
                adjacent[1].as_ptr(),
            );
        }
    }

    #[test]
    fn incomplete_reassembly_releases_process_budget_on_drop() {
        let budget = BufferBudget::new(65_535);
        let frames = encode_packet(&vec![7; 2_000], 600, 77).unwrap();
        let mut reassembler =
            Reassembler::with_max_buffered_bytes_and_budget(65_535, Some(budget.clone()));
        assert!(
            reassembler
                .push_tagged(frames[0].clone())
                .unwrap()
                .is_none()
        );
        assert_eq!(budget.used(), 2_000);
        drop(reassembler);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn reassembly_clock_metadata_stays_bounded_behind_a_long_lived_packet() {
        let mut reassembler = Reassembler::default();
        let anchor = encode_packet(&vec![1; 2_000], 600, 1).unwrap();
        reassembler.push_tagged(anchor[0].clone()).unwrap();
        for packet_id in 2..=200 {
            let frames = encode_packet(&vec![packet_id as u8; 1_000], 600, packet_id).unwrap();
            for frame in frames {
                reassembler.push_tagged(frame).unwrap();
            }
            let bound = reassembler.assemblies.len().saturating_mul(4).max(64);
            assert!(reassembler.order.len() <= bound);
            assert!(reassembler.repair_clock.len() <= bound);
        }
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
            if let Some(value) = reassembler.push_tagged(frame).unwrap() {
                complete = Some(value);
            }
        }
        let complete = complete.unwrap();
        assert_eq!(complete.data.as_slice(), packet);
        assert_eq!(complete.delivery_tag, Some(tag));
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
            WireDatagram::Heartbeat(Heartbeat { fec_feedback: None })
        ));
        let mut invalid = encode_heartbeat().to_vec();
        invalid.push(0);
        assert!(decode_datagram(Bytes::from(invalid)).is_err());
    }

    #[test]
    fn heartbeat_carries_cumulative_fec_feedback() {
        let feedback = FecFeedback {
            received_recovery_shards: 10_000,
            recovered_data_shards: 321,
            expired_blocks: 7,
        };
        let WireDatagram::Heartbeat(heartbeat) =
            decode_datagram(encode_heartbeat_with_fec_feedback(feedback)).unwrap()
        else {
            panic!("expected heartbeat");
        };
        assert_eq!(heartbeat.fec_feedback, Some(feedback));
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
            missing_offsets: vec![972],
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

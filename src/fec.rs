use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};

use crate::buffer::{BufferBudget, BufferPermit};
use crate::protocol::envelope::{
    self, Envelope as V1Envelope, HEADER_LEN as V1_HEADER_LEN, MessageType,
};

const HEADER_LEN: usize = 16;
const LENGTH_PREFIX_LEN: usize = 2;
const KIND_ORIGINAL: u8 = 0;
const KIND_RECOVERY: u8 = 1;
const MAX_DATA_SHARDS: usize = 64;
const MAX_RECOVERY_SHARDS: usize = 32;
const MAX_BLOCKS: usize = 4_096;
const MAX_BUFFERED_BYTES: usize = 32 * 1024 * 1024;
const EXPIRY_INTERVAL: Duration = Duration::from_millis(50);

/// Number of bytes unavailable to an inner overlay frame when FEC is enabled.
pub const WIRE_OVERHEAD: usize = V1_HEADER_LEN + HEADER_LEN + LENGTH_PREFIX_LEN;

#[derive(Debug)]
pub struct EncodedDatagram {
    pub bytes: Bytes,
    pub recovery: bool,
}

#[derive(Debug, Default)]
pub struct EncodeBatch {
    pub datagrams: Vec<EncodedDatagram>,
    /// Original shards whose block aged out or changed size before parity could be made.
    pub unprotected_shards: u64,
    pub overhead_bytes: u64,
}

#[derive(Debug)]
struct EncodeBlock {
    id: u64,
    created: Instant,
    shard_bytes: usize,
    originals: Vec<Vec<u8>>,
}

/// A systematic application-layer encoder.
///
/// Original shards are returned immediately. Once `data_shards` originals have
/// been emitted, Reed-Solomon recovery shards are appended to the returned batch.
pub struct FecEncoder {
    data_shards: usize,
    recovery_shards: usize,
    block_timeout: Duration,
    next_block_id: u64,
    block: Option<EncodeBlock>,
    codec: Option<ReedSolomonEncoder>,
}

impl FecEncoder {
    pub fn new(
        data_shards: usize,
        recovery_shards: usize,
        block_timeout: Duration,
    ) -> Result<Self> {
        validate_counts(data_shards, recovery_shards)?;
        ensure!(!block_timeout.is_zero(), "FEC block timeout cannot be zero");
        Ok(Self {
            data_shards,
            recovery_shards,
            block_timeout,
            next_block_id: 1,
            block: None,
            codec: None,
        })
    }

    pub fn inner_frame_limit(maximum: usize) -> Result<usize> {
        ensure!(maximum > WIRE_OVERHEAD, "FEC datagram limit is too small");
        let shard_bytes = even_shard_bytes(maximum)?;
        ensure!(
            shard_bytes > LENGTH_PREFIX_LEN,
            "FEC datagram limit leaves no frame payload"
        );
        Ok(shard_bytes - LENGTH_PREFIX_LEN)
    }

    pub fn push(&mut self, frame: Bytes, maximum: usize) -> Result<EncodeBatch> {
        let shard_bytes = shard_bytes_for_frame(frame.len(), maximum)?;
        ensure!(
            frame.len() <= shard_bytes - LENGTH_PREFIX_LEN,
            "overlay frame exceeds FEC shard capacity"
        );
        ensure!(
            frame.len() <= u16::MAX as usize,
            "overlay frame exceeds FEC wire maximum"
        );

        let mut batch = EncodeBatch::default();
        let replace = self.block.as_ref().is_some_and(|block| {
            block.created.elapsed() >= self.block_timeout || block.shard_bytes != shard_bytes
        });
        if replace {
            batch.unprotected_shards = self
                .block
                .take()
                .map_or(0, |block| block.originals.len() as u64);
        }

        if self.block.is_none() {
            let id = self.next_block_id;
            self.next_block_id = self.next_block_id.wrapping_add(1).max(1);
            self.block = Some(EncodeBlock {
                id,
                created: Instant::now(),
                shard_bytes,
                originals: Vec::with_capacity(self.data_shards),
            });
        }

        let block = self.block.as_mut().expect("block was initialized");
        let index = block.originals.len();
        let mut original = Vec::with_capacity(shard_bytes);
        original.extend_from_slice(&(frame.len() as u16).to_be_bytes());
        original.extend_from_slice(&frame);
        batch.overhead_bytes += WIRE_OVERHEAD as u64;
        batch.datagrams.push(EncodedDatagram {
            bytes: encode_envelope(
                block.id,
                KIND_ORIGINAL,
                index,
                self.data_shards,
                self.recovery_shards,
                shard_bytes,
                &original,
            )?,
            recovery: false,
        });
        original.resize(shard_bytes, 0);
        block.originals.push(original);

        if block.originals.len() == self.data_shards {
            let encoder = match self.codec.as_mut() {
                Some(encoder) => {
                    encoder
                        .reset(self.data_shards, self.recovery_shards, shard_bytes)
                        .context("unsupported FEC encoder parameters")?;
                    encoder
                }
                None => {
                    self.codec = Some(
                        ReedSolomonEncoder::new(
                            self.data_shards,
                            self.recovery_shards,
                            shard_bytes,
                        )
                        .context("unsupported FEC encoder parameters")?,
                    );
                    self.codec.as_mut().expect("encoder was stored")
                }
            };
            for original in &block.originals {
                encoder
                    .add_original_shard(original)
                    .context("failed adding FEC original shard")?;
            }
            let encoded = encoder.encode().context("failed encoding FEC block")?;
            for (index, recovery) in encoded.recovery_iter().enumerate() {
                batch.overhead_bytes += (HEADER_LEN + recovery.len()) as u64;
                batch.datagrams.push(EncodedDatagram {
                    bytes: encode_envelope(
                        block.id,
                        KIND_RECOVERY,
                        index,
                        self.data_shards,
                        self.recovery_shards,
                        shard_bytes,
                        recovery,
                    )?,
                    recovery: true,
                });
            }
            self.block = None;
        }
        Ok(batch)
    }

    pub fn reset(&mut self) -> u64 {
        self.block
            .take()
            .map_or(0, |block| block.originals.len() as u64)
    }
}

#[derive(Debug, Default)]
pub struct DecodeBatch {
    pub frames: Vec<Bytes>,
    pub recovery_shards: u64,
    pub recovered_shards: u64,
    pub expired_blocks: u64,
}

#[derive(Debug)]
struct DecodeBlock {
    created: Instant,
    data_shards: usize,
    recovery_shards: usize,
    shard_bytes: usize,
    originals: Vec<Option<Vec<u8>>>,
    recoveries: Vec<Option<Vec<u8>>>,
    delivered: Vec<bool>,
    _budget_permits: Vec<BufferPermit>,
}

impl DecodeBlock {
    fn buffered_bytes(&self) -> usize {
        self.originals
            .iter()
            .chain(&self.recoveries)
            .filter_map(Option::as_ref)
            .map(Vec::len)
            .sum()
    }

    fn parameters_match(&self, envelope: &Envelope) -> bool {
        self.data_shards == envelope.data_shards
            && self.recovery_shards == envelope.recovery_shards
            && self.shard_bytes == envelope.shard_bytes
    }

    fn received_shards(&self) -> (usize, usize) {
        (
            self.originals.iter().flatten().count(),
            self.recoveries.iter().flatten().count(),
        )
    }
}

/// Decodes FEC envelopes and passes non-FEC frames through unchanged.
pub struct FecDecoder {
    block_ttl: Duration,
    blocks: HashMap<u64, DecodeBlock>,
    block_order: VecDeque<(u64, Instant)>,
    completed: HashSet<u64>,
    completed_order: VecDeque<u64>,
    buffered_bytes: usize,
    max_buffered_bytes: usize,
    next_expiry: Instant,
    codec: Option<ReedSolomonDecoder>,
    budget: Option<Arc<BufferBudget>>,
}

impl FecDecoder {
    pub fn new(block_ttl: Duration) -> Result<Self> {
        Self::with_max_buffered_bytes(block_ttl, MAX_BUFFERED_BYTES)
    }

    pub fn with_max_buffered_bytes(block_ttl: Duration, max_buffered_bytes: usize) -> Result<Self> {
        Self::with_max_buffered_bytes_and_budget(block_ttl, max_buffered_bytes, None)
    }

    pub fn with_max_buffered_bytes_and_budget(
        block_ttl: Duration,
        max_buffered_bytes: usize,
        budget: Option<Arc<BufferBudget>>,
    ) -> Result<Self> {
        ensure!(!block_ttl.is_zero(), "FEC decoder TTL cannot be zero");
        Ok(Self {
            block_ttl,
            blocks: HashMap::new(),
            block_order: VecDeque::new(),
            completed: HashSet::new(),
            completed_order: VecDeque::new(),
            buffered_bytes: 0,
            max_buffered_bytes: max_buffered_bytes.max(u16::MAX as usize),
            next_expiry: Instant::now() + EXPIRY_INTERVAL,
            codec: None,
            budget,
        })
    }

    pub fn push(&mut self, datagram: Bytes) -> Result<DecodeBatch> {
        let mut batch = DecodeBatch {
            expired_blocks: self.expire(false),
            ..DecodeBatch::default()
        };
        let Ok(v1) = V1Envelope::decode(datagram.clone()) else {
            batch.frames.push(datagram);
            return Ok(batch);
        };
        if v1.kind != MessageType::FecShard {
            batch.frames.push(datagram);
            return Ok(batch);
        }

        let envelope = Envelope::parse(v1.payload)?;
        if self.completed.contains(&envelope.block_id) {
            return Ok(batch);
        }
        if envelope.kind == KIND_RECOVERY {
            batch.recovery_shards = 1;
        }
        if !self.blocks.contains_key(&envelope.block_id) {
            if self.capacity_exceeded(envelope.shard_bytes) {
                batch.expired_blocks += self.expire(true);
            }
            while self.capacity_exceeded(envelope.shard_bytes) {
                let Some(expired) = self.evict_oldest() else {
                    break;
                };
                batch.expired_blocks += expired;
            }
            ensure!(self.blocks.len() < MAX_BLOCKS, "too many active FEC blocks");
            ensure!(
                self.buffered_bytes.saturating_add(envelope.shard_bytes) <= self.max_buffered_bytes,
                "active FEC blocks exceed memory limit"
            );
            let created = Instant::now();
            self.blocks.insert(
                envelope.block_id,
                DecodeBlock {
                    created,
                    data_shards: envelope.data_shards,
                    recovery_shards: envelope.recovery_shards,
                    shard_bytes: envelope.shard_bytes,
                    originals: vec![None; envelope.data_shards],
                    recoveries: vec![None; envelope.recovery_shards],
                    delivered: vec![false; envelope.data_shards],
                    _budget_permits: Vec::with_capacity(
                        envelope.data_shards + envelope.recovery_shards,
                    ),
                },
            );
            self.block_order.push_back((envelope.block_id, created));
        }

        let additional_bytes = {
            let block = self
                .blocks
                .get(&envelope.block_id)
                .expect("FEC block was initialized");
            ensure!(
                block.parameters_match(&envelope),
                "FEC block parameters changed"
            );
            match envelope.kind {
                KIND_ORIGINAL if block.originals[envelope.index].is_none() => envelope.shard_bytes,
                KIND_RECOVERY if block.recoveries[envelope.index].is_none() => envelope.shard_bytes,
                _ => 0,
            }
        };
        while self.buffered_bytes.saturating_add(additional_bytes) > self.max_buffered_bytes {
            let Some(expired) = self.evict_oldest_except(envelope.block_id) else {
                bail!("active FEC blocks exceed memory limit");
            };
            batch.expired_blocks += expired;
        }
        let budget_permit = if additional_bytes == 0 {
            None
        } else if let Some(budget) = self.budget.clone() {
            loop {
                if let Some(permit) = budget.try_acquire(additional_bytes) {
                    break Some(permit);
                }
                let Some(expired) = self.evict_oldest_except(envelope.block_id) else {
                    bail!("process payload budget exhausted by active FEC blocks");
                };
                batch.expired_blocks += expired;
            }
        } else {
            None
        };
        let block = self
            .blocks
            .get_mut(&envelope.block_id)
            .expect("FEC block was initialized");
        match envelope.kind {
            KIND_ORIGINAL => {
                let original = expand_original(&envelope.payload, envelope.shard_bytes)?;
                if let Some(existing) = &block.originals[envelope.index] {
                    ensure!(
                        existing == &original,
                        "conflicting duplicate FEC original shard"
                    );
                } else {
                    self.buffered_bytes += original.len();
                    block.originals[envelope.index] = Some(original);
                    if let Some(permit) = budget_permit {
                        block._budget_permits.push(permit);
                    }
                }
                if !block.delivered[envelope.index] {
                    block.delivered[envelope.index] = true;
                    batch
                        .frames
                        .push(original_payload(envelope.payload.clone())?);
                }
            }
            KIND_RECOVERY => {
                let recovery = envelope.payload.to_vec();
                if let Some(existing) = &block.recoveries[envelope.index] {
                    ensure!(
                        existing == &recovery,
                        "conflicting duplicate FEC recovery shard"
                    );
                } else {
                    self.buffered_bytes += recovery.len();
                    block.recoveries[envelope.index] = Some(recovery);
                    if let Some(permit) = budget_permit {
                        block._budget_permits.push(permit);
                    }
                }
            }
            _ => unreachable!(),
        }

        let (original_count, recovery_count) = block.received_shards();
        if original_count < block.data_shards
            && original_count + recovery_count >= block.data_shards
        {
            let decoder = match self.codec.as_mut() {
                Some(decoder) => {
                    decoder
                        .reset(block.data_shards, block.recovery_shards, block.shard_bytes)
                        .context("unsupported FEC decoder parameters")?;
                    decoder
                }
                None => {
                    self.codec = Some(
                        ReedSolomonDecoder::new(
                            block.data_shards,
                            block.recovery_shards,
                            block.shard_bytes,
                        )
                        .context("unsupported FEC decoder parameters")?,
                    );
                    self.codec.as_mut().expect("decoder was stored")
                }
            };
            for (index, original) in block.originals.iter().enumerate() {
                if let Some(original) = original {
                    decoder
                        .add_original_shard(index, original)
                        .context("failed adding FEC original shard")?;
                }
            }
            for (index, recovery) in block.recoveries.iter().enumerate() {
                if let Some(recovery) = recovery {
                    decoder
                        .add_recovery_shard(index, recovery)
                        .context("failed adding FEC recovery shard")?;
                }
            }
            let decoded = decoder.decode().context("failed decoding FEC block")?;
            let restored: Vec<(usize, Vec<u8>)> = decoded
                .restored_original_iter()
                .map(|(index, shard)| (index, shard.to_vec()))
                .collect();
            drop(decoded);
            for (index, original) in restored {
                let frame = original_from_expanded(&original)?;
                if !block.delivered[index] {
                    block.delivered[index] = true;
                    batch.recovered_shards += 1;
                    batch.frames.push(frame);
                }
            }
        }

        if block.delivered.iter().all(|delivered| *delivered) {
            if let Some(block) = self.blocks.remove(&envelope.block_id) {
                self.buffered_bytes = self.buffered_bytes.saturating_sub(block.buffered_bytes());
            }
            self.completed.insert(envelope.block_id);
            self.completed_order.push_back(envelope.block_id);
            while self.completed_order.len() > MAX_BLOCKS {
                if let Some(oldest) = self.completed_order.pop_front() {
                    self.completed.remove(&oldest);
                }
            }
            self.compact_block_order_if_needed();
        }
        Ok(batch)
    }

    pub fn reset(&mut self) {
        self.blocks.clear();
        self.block_order.clear();
        self.completed.clear();
        self.completed_order.clear();
        self.buffered_bytes = 0;
        self.next_expiry = Instant::now() + EXPIRY_INTERVAL;
    }

    fn capacity_exceeded(&self, additional_bytes: usize) -> bool {
        self.blocks.len() >= MAX_BLOCKS
            || self.buffered_bytes.saturating_add(additional_bytes) > self.max_buffered_bytes
    }

    fn expire(&mut self, force: bool) -> u64 {
        let now = Instant::now();
        if !force && now < self.next_expiry {
            return 0;
        }
        let mut expired = 0_u64;
        while let Some(&(block_id, created)) = self.block_order.front() {
            let Some(block) = self.blocks.get(&block_id) else {
                self.block_order.pop_front();
                continue;
            };
            if block.created != created {
                self.block_order.pop_front();
                continue;
            }
            if now.duration_since(created) < self.block_ttl {
                break;
            }
            self.block_order.pop_front();
            if let Some(block) = self.blocks.remove(&block_id) {
                self.buffered_bytes = self.buffered_bytes.saturating_sub(block.buffered_bytes());
                expired += 1;
            }
        }
        self.next_expiry = now + EXPIRY_INTERVAL;
        expired
    }

    fn evict_oldest(&mut self) -> Option<u64> {
        while let Some((block_id, created)) = self.block_order.pop_front() {
            let is_current = self
                .blocks
                .get(&block_id)
                .is_some_and(|block| block.created == created);
            if !is_current {
                continue;
            }
            if let Some(block) = self.blocks.remove(&block_id) {
                self.buffered_bytes = self.buffered_bytes.saturating_sub(block.buffered_bytes());
                return Some(1);
            }
        }
        None
    }

    fn evict_oldest_except(&mut self, protected: u64) -> Option<u64> {
        let candidates = self.block_order.len();
        let mut deferred = Vec::new();
        for _ in 0..candidates {
            let Some((block_id, created)) = self.block_order.pop_front() else {
                break;
            };
            let is_current = self
                .blocks
                .get(&block_id)
                .is_some_and(|block| block.created == created);
            if !is_current {
                continue;
            }
            if block_id == protected {
                deferred.push((block_id, created));
                continue;
            }
            if let Some(block) = self.blocks.remove(&block_id) {
                self.buffered_bytes = self.buffered_bytes.saturating_sub(block.buffered_bytes());
                for token in deferred.into_iter().rev() {
                    self.block_order.push_front(token);
                }
                return Some(1);
            }
        }
        for token in deferred.into_iter().rev() {
            self.block_order.push_front(token);
        }
        None
    }

    fn compact_block_order_if_needed(&mut self) {
        let bound = self.blocks.len().saturating_mul(4).max(64);
        if self.block_order.len() <= bound {
            return;
        }
        let mut live = self
            .blocks
            .iter()
            .map(|(block_id, block)| (*block_id, block.created))
            .collect::<Vec<_>>();
        live.sort_unstable_by_key(|(_, created)| *created);
        self.block_order = live.into_iter().collect();
    }
}

struct Envelope {
    block_id: u64,
    kind: u8,
    index: usize,
    data_shards: usize,
    recovery_shards: usize,
    shard_bytes: usize,
    payload: Bytes,
}

impl Envelope {
    fn parse(datagram: Bytes) -> Result<Self> {
        ensure!(datagram.len() >= HEADER_LEN, "truncated FEC envelope");
        let block_id = u64::from_be_bytes(datagram[0..8].try_into().unwrap());
        let kind = datagram[8];
        let index = usize::from(datagram[9]);
        let data_shards = usize::from(datagram[10]);
        let recovery_shards = usize::from(datagram[11]);
        let shard_bytes = usize::from(u16::from_be_bytes(datagram[12..14].try_into().unwrap()));
        let payload_bytes = usize::from(u16::from_be_bytes(datagram[14..16].try_into().unwrap()));
        ensure!(block_id != 0, "invalid zero FEC block ID");
        validate_counts(data_shards, recovery_shards)?;
        ensure!(shard_bytes > LENGTH_PREFIX_LEN, "invalid FEC shard size");
        ensure!(shard_bytes.is_multiple_of(2), "FEC shard size must be even");
        ensure!(
            datagram.len() == HEADER_LEN + payload_bytes,
            "FEC envelope payload length mismatch"
        );
        let payload = datagram.slice(HEADER_LEN..);
        match kind {
            KIND_ORIGINAL => {
                ensure!(index < data_shards, "invalid FEC original shard index");
                ensure!(
                    payload.len() <= shard_bytes,
                    "FEC original exceeds shard size"
                );
                original_payload(payload.clone())?;
            }
            KIND_RECOVERY => {
                ensure!(index < recovery_shards, "invalid FEC recovery shard index");
                ensure!(
                    payload.len() == shard_bytes,
                    "invalid FEC recovery shard size"
                );
            }
            _ => bail!("unsupported FEC shard kind {kind}"),
        }
        Ok(Self {
            block_id,
            kind,
            index,
            data_shards,
            recovery_shards,
            shard_bytes,
            payload,
        })
    }
}

fn validate_counts(data_shards: usize, recovery_shards: usize) -> Result<()> {
    ensure!(
        (2..=MAX_DATA_SHARDS).contains(&data_shards),
        "FEC data shards must be between 2 and {MAX_DATA_SHARDS}"
    );
    ensure!(
        (1..=MAX_RECOVERY_SHARDS).contains(&recovery_shards),
        "FEC recovery shards must be between 1 and {MAX_RECOVERY_SHARDS}"
    );
    ensure!(
        ReedSolomonEncoder::supports(data_shards, recovery_shards),
        "unsupported FEC shard count combination"
    );
    Ok(())
}

fn even_shard_bytes(maximum: usize) -> Result<usize> {
    ensure!(
        maximum <= u16::MAX as usize,
        "FEC datagram limit exceeds wire maximum"
    );
    ensure!(maximum > WIRE_OVERHEAD, "FEC datagram limit is too small");
    // `encode_envelope` wraps the FEC header in the protocol-v1 envelope.
    // Account for both headers here; otherwise a maximum-sized original and
    // every full recovery shard exceed QUIC's datagram limit by
    // `V1_HEADER_LEN`.  The send path then continuously reframes originals and
    // drops parity, which makes FEC unusable for MTU-sized bulk traffic.
    let available = maximum - V1_HEADER_LEN - HEADER_LEN;
    Ok(available - available % 2)
}

/// Use one stable shard size for the current path MTU.
///
/// A TUN commonly yields alternating full and short fragments for every inner
/// packet. Size-classing those frames with a single in-progress block resets
/// the block on every fragment, so it never reaches the parity threshold under
/// real bulk traffic. Originals remain unpadded on the wire; only recovery
/// shards pay the full path-MTU size.
fn shard_bytes_for_frame(frame_len: usize, maximum: usize) -> Result<usize> {
    let maximum_shard = even_shard_bytes(maximum)?;
    let required = frame_len
        .checked_add(LENGTH_PREFIX_LEN)
        .context("FEC frame length overflow")?;
    ensure!(
        required <= maximum_shard,
        "overlay frame exceeds FEC shard capacity"
    );
    Ok(maximum_shard)
}

fn encode_envelope(
    block_id: u64,
    kind: u8,
    index: usize,
    data_shards: usize,
    recovery_shards: usize,
    shard_bytes: usize,
    payload: &[u8],
) -> Result<Bytes> {
    ensure!(block_id != 0, "invalid zero FEC block ID");
    ensure!(
        index <= u8::MAX as usize,
        "FEC shard index exceeds wire maximum"
    );
    ensure!(
        data_shards <= u8::MAX as usize,
        "FEC data shard count exceeds wire maximum"
    );
    ensure!(
        recovery_shards <= u8::MAX as usize,
        "FEC recovery shard count exceeds wire maximum"
    );
    ensure!(
        shard_bytes <= u16::MAX as usize,
        "FEC shard size exceeds wire maximum"
    );
    ensure!(
        payload.len() <= u16::MAX as usize,
        "FEC payload exceeds wire maximum"
    );
    let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
    frame.extend_from_slice(&block_id.to_be_bytes());
    frame.push(kind);
    frame.push(index as u8);
    frame.push(data_shards as u8);
    frame.push(recovery_shards as u8);
    frame.extend_from_slice(&(shard_bytes as u16).to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    envelope::encode_parts(MessageType::FecShard, 0, &[], &frame)
}

fn expand_original(payload: &[u8], shard_bytes: usize) -> Result<Vec<u8>> {
    ensure!(
        payload.len() <= shard_bytes,
        "FEC original exceeds shard size"
    );
    let mut original = Vec::with_capacity(shard_bytes);
    original.extend_from_slice(payload);
    original.resize(shard_bytes, 0);
    Ok(original)
}

fn original_payload(payload: Bytes) -> Result<Bytes> {
    ensure!(
        payload.len() >= LENGTH_PREFIX_LEN,
        "truncated FEC original shard"
    );
    let frame_len = usize::from(u16::from_be_bytes(payload[..2].try_into().unwrap()));
    ensure!(frame_len > 0, "empty FEC original shard");
    ensure!(
        payload.len() == LENGTH_PREFIX_LEN + frame_len,
        "FEC original shard length mismatch"
    );
    Ok(payload.slice(LENGTH_PREFIX_LEN..LENGTH_PREFIX_LEN + frame_len))
}

fn original_from_expanded(original: &[u8]) -> Result<Bytes> {
    ensure!(
        original.len() >= LENGTH_PREFIX_LEN,
        "truncated restored FEC shard"
    );
    let frame_len = usize::from(u16::from_be_bytes(original[..2].try_into().unwrap()));
    ensure!(frame_len > 0, "empty restored FEC shard");
    ensure!(
        frame_len <= original.len() - LENGTH_PREFIX_LEN,
        "restored FEC shard length exceeds shard size"
    );
    Ok(Bytes::copy_from_slice(&original[2..2 + frame_len]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Reassembler, encode_packet};

    fn encoder() -> FecEncoder {
        FecEncoder::new(4, 2, Duration::from_millis(100)).unwrap()
    }

    #[test]
    fn originals_are_systematic_and_immediate() {
        let mut encoder = encoder();
        let batch = encoder.push(Bytes::from_static(b"one"), 128).unwrap();
        assert_eq!(batch.datagrams.len(), 1);
        assert!(!batch.datagrams[0].recovery);

        let mut decoder = FecDecoder::new(Duration::from_secs(1)).unwrap();
        let decoded = decoder.push(batch.datagrams[0].bytes.clone()).unwrap();
        assert_eq!(decoded.frames, [Bytes::from_static(b"one")]);
        assert_eq!(decoded.recovered_shards, 0);
    }

    #[test]
    fn recovers_two_missing_originals_out_of_order() {
        let mut encoder = encoder();
        let mut datagrams = Vec::new();
        for frame in [b"zero".as_slice(), b"one", b"two", b"three"] {
            datagrams.extend(
                encoder
                    .push(Bytes::copy_from_slice(frame), 128)
                    .unwrap()
                    .datagrams,
            );
        }
        assert_eq!(datagrams.len(), 6);
        assert!(datagrams[4..].iter().all(|datagram| datagram.recovery));
        assert!(datagrams.iter().all(|datagram| datagram.bytes.len() <= 128));

        let mut decoder = FecDecoder::new(Duration::from_secs(1)).unwrap();
        let mut output = Vec::new();
        for index in [4, 0, 5, 2] {
            let decoded = decoder.push(datagrams[index].bytes.clone()).unwrap();
            output.extend(decoded.frames);
        }
        output.sort();
        assert_eq!(
            output,
            [
                Bytes::from_static(b"one"),
                Bytes::from_static(b"three"),
                Bytes::from_static(b"two"),
                Bytes::from_static(b"zero"),
            ]
        );
    }

    #[test]
    fn every_two_original_loss_combination_is_recoverable() {
        let mut encoder = encoder();
        let mut datagrams = Vec::new();
        for frame in [b"zero".as_slice(), b"one", b"two", b"three"] {
            datagrams.extend(
                encoder
                    .push(Bytes::copy_from_slice(frame), 128)
                    .unwrap()
                    .datagrams,
            );
        }
        for first_missing in 0..4 {
            for second_missing in first_missing + 1..4 {
                let mut decoder = FecDecoder::new(Duration::from_secs(1)).unwrap();
                let mut output = Vec::new();
                for (index, datagram) in datagrams.iter().enumerate() {
                    if index == first_missing || index == second_missing {
                        continue;
                    }
                    output.extend(decoder.push(datagram.bytes.clone()).unwrap().frames);
                }
                output.sort();
                assert_eq!(
                    output,
                    [
                        Bytes::from_static(b"one"),
                        Bytes::from_static(b"three"),
                        Bytes::from_static(b"two"),
                        Bytes::from_static(b"zero"),
                    ],
                    "failed loss combination {first_missing}, {second_missing}"
                );
            }
        }
    }

    #[test]
    fn recovered_overlay_frames_reassemble_original_packets() {
        let maximum = 160;
        let inner_maximum = FecEncoder::inner_frame_limit(maximum).unwrap();
        let packets = [
            b"first packet".as_slice(),
            b"second packet is longer",
            b"third",
            b"fourth application packet",
        ];
        let mut encoder = encoder();
        let mut datagrams = Vec::new();
        for (packet_id, packet) in packets.iter().enumerate() {
            let frame = encode_packet(packet, inner_maximum, packet_id as u64 + 1)
                .unwrap()
                .remove(0);
            datagrams.extend(encoder.push(frame, maximum).unwrap().datagrams);
        }

        let mut decoder = FecDecoder::new(Duration::from_secs(1)).unwrap();
        let mut reassembler = Reassembler::default();
        let mut recovered_packets = Vec::new();
        // Drop two systematic datagrams and recover them from both repair shards.
        for index in [0, 2, 4, 5] {
            for frame in decoder.push(datagrams[index].bytes.clone()).unwrap().frames {
                if let Some(packet) = reassembler.push(&frame).unwrap() {
                    recovered_packets.push(packet);
                }
            }
        }
        recovered_packets.sort();
        let mut expected = packets
            .iter()
            .map(|packet| packet.to_vec())
            .collect::<Vec<_>>();
        expected.sort();
        assert_eq!(recovered_packets, expected);
    }

    #[test]
    fn late_original_after_recovery_is_suppressed() {
        let mut encoder = encoder();
        let mut datagrams = Vec::new();
        for frame in [b"zero".as_slice(), b"one", b"two", b"three"] {
            datagrams.extend(
                encoder
                    .push(Bytes::copy_from_slice(frame), 128)
                    .unwrap()
                    .datagrams,
            );
        }
        let mut decoder = FecDecoder::new(Duration::from_secs(1)).unwrap();
        for index in [0, 2, 3, 4] {
            decoder.push(datagrams[index].bytes.clone()).unwrap();
        }
        assert!(
            decoder
                .push(datagrams[1].bytes.clone())
                .unwrap()
                .frames
                .is_empty()
        );
    }

    #[test]
    fn insufficient_recovery_does_not_invent_frames() {
        let mut encoder = encoder();
        let mut datagrams = Vec::new();
        for frame in [b"zero".as_slice(), b"one", b"two", b"three"] {
            datagrams.extend(
                encoder
                    .push(Bytes::copy_from_slice(frame), 128)
                    .unwrap()
                    .datagrams,
            );
        }
        let mut decoder = FecDecoder::new(Duration::from_secs(1)).unwrap();
        let first = decoder.push(datagrams[0].bytes.clone()).unwrap();
        let parity = decoder.push(datagrams[4].bytes.clone()).unwrap();
        assert_eq!(first.frames, [Bytes::from_static(b"zero")]);
        assert!(parity.frames.is_empty());
    }

    #[test]
    fn expired_or_resized_partial_block_is_reported_unprotected() {
        let mut encoder = FecEncoder::new(4, 2, Duration::ZERO + Duration::from_nanos(1)).unwrap();
        encoder.push(Bytes::from_static(b"one"), 128).unwrap();
        std::thread::sleep(Duration::from_millis(1));
        let batch = encoder.push(Bytes::from_static(b"two"), 128).unwrap();
        assert_eq!(batch.unprotected_shards, 1);

        let resized = encoder.push(Bytes::from(vec![3; 80]), 126).unwrap();
        assert_eq!(resized.unprotected_shards, 1);
    }

    #[test]
    fn mixed_frame_sizes_share_a_stable_mtu_sized_block() {
        let mut encoder = encoder();
        let mut datagrams = Vec::new();
        for frame in [b"zero".as_slice(), b"one", b"two", b"three"] {
            datagrams.extend(
                encoder
                    .push(Bytes::copy_from_slice(frame), 1_400)
                    .unwrap()
                    .datagrams,
            );
        }
        assert_eq!(datagrams.len(), 6);
        assert!(datagrams[4..].iter().all(|datagram| datagram.recovery));
        assert!(
            datagrams[4..]
                .iter()
                .all(|datagram| datagram.bytes.len() <= 1_400)
        );
        assert_eq!(datagrams[4].bytes.len(), 1_400);
    }

    #[test]
    fn mtu_sized_originals_and_recovery_stay_within_datagram_limit() {
        let maximum = 1_362;
        let inner_maximum = FecEncoder::inner_frame_limit(maximum).unwrap();
        let mut encoder = encoder();
        let mut datagrams = Vec::new();
        for value in 0..4_u8 {
            datagrams.extend(
                encoder
                    .push(Bytes::from(vec![value; inner_maximum]), maximum)
                    .unwrap()
                    .datagrams,
            );
        }

        assert_eq!(datagrams.len(), 6);
        assert!(
            datagrams
                .iter()
                .all(|datagram| datagram.bytes.len() <= maximum)
        );
        assert!(datagrams[4..].iter().all(|datagram| datagram.recovery));
    }

    #[test]
    fn plain_overlay_frames_pass_through() {
        let mut decoder = FecDecoder::new(Duration::from_secs(1)).unwrap();
        let batch = decoder
            .push(Bytes::from_static(b"IRNIP1\0\0frame"))
            .unwrap();
        assert_eq!(batch.frames, [Bytes::from_static(b"IRNIP1\0\0frame")]);
    }

    #[test]
    fn incomplete_decode_block_releases_process_budget_on_drop() {
        let budget = BufferBudget::new(65_535);
        let mut encoder = encoder();
        let datagram = encoder
            .push(Bytes::from_static(b"one"), 128)
            .unwrap()
            .datagrams
            .remove(0)
            .bytes;
        let mut decoder = FecDecoder::with_max_buffered_bytes_and_budget(
            Duration::from_secs(1),
            65_535,
            Some(budget.clone()),
        )
        .unwrap();
        decoder.push(datagram).unwrap();
        assert!(budget.used() > 0);
        drop(decoder);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn decode_clock_metadata_stays_bounded_behind_a_long_lived_block() {
        let mut decoder = FecDecoder::new(Duration::from_secs(60)).unwrap();
        let original = |block_id, index, value| {
            encode_envelope(block_id, KIND_ORIGINAL, index, 2, 1, 4, &[0, 1, value]).unwrap()
        };
        decoder.push(original(1, 0, 1)).unwrap();
        for block_id in 2..=200 {
            decoder.push(original(block_id, 0, 2)).unwrap();
            decoder.push(original(block_id, 1, 3)).unwrap();
            let bound = decoder.blocks.len().saturating_mul(4).max(64);
            assert!(decoder.block_order.len() <= bound);
        }
    }

    #[test]
    fn sustained_rate_evicts_old_tombstones_instead_of_dropping_new_blocks() {
        let mut encoder = FecEncoder::new(2, 1, Duration::from_secs(1)).unwrap();
        let mut decoder = FecDecoder::new(Duration::from_secs(60)).unwrap();
        for block in 0..(MAX_BLOCKS + 512) {
            for index in 0..2 {
                let frame = Bytes::from(format!("{block}:{index}"));
                for datagram in encoder.push(frame, 128).unwrap().datagrams {
                    decoder.push(datagram.bytes.clone()).unwrap();
                }
            }
        }
        assert!(decoder.blocks.is_empty());
        assert_eq!(decoder.completed.len(), MAX_BLOCKS);
        assert_eq!(decoder.completed_order.len(), MAX_BLOCKS);
    }
}

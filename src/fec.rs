use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use bytes::Bytes;
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};

const MAGIC: &[u8; 8] = b"ISWFEC1\0";
const HEADER_LEN: usize = 24;
const LENGTH_PREFIX_LEN: usize = 2;
const KIND_ORIGINAL: u8 = 0;
const KIND_RECOVERY: u8 = 1;
const MAX_DATA_SHARDS: usize = 64;
const MAX_RECOVERY_SHARDS: usize = 32;
const MAX_BLOCKS: usize = 4_096;
const MAX_BUFFERED_BYTES: usize = 32 * 1024 * 1024;
const EXPIRY_INTERVAL: Duration = Duration::from_millis(50);

/// Number of bytes unavailable to an inner overlay frame when FEC is enabled.
pub const WIRE_OVERHEAD: usize = HEADER_LEN + LENGTH_PREFIX_LEN;

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
        let mut original = vec![0; shard_bytes];
        original[..2].copy_from_slice(&(frame.len() as u16).to_be_bytes());
        original[2..2 + frame.len()].copy_from_slice(&frame);
        batch.overhead_bytes += WIRE_OVERHEAD as u64;
        batch.datagrams.push(EncodedDatagram {
            bytes: encode_envelope(
                block.id,
                KIND_ORIGINAL,
                index,
                self.data_shards,
                self.recovery_shards,
                shard_bytes,
                &original[..2 + frame.len()],
            )?,
            recovery: false,
        });
        block.originals.push(original);

        if block.originals.len() == self.data_shards {
            let mut encoder =
                ReedSolomonEncoder::new(self.data_shards, self.recovery_shards, shard_bytes)
                    .context("unsupported FEC encoder parameters")?;
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
    complete: bool,
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

    fn finish(&mut self) {
        self.complete = true;
        self.originals.fill(None);
        self.recoveries.fill(None);
    }

    fn parameters_match(&self, envelope: &Envelope<'_>) -> bool {
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
    buffered_bytes: usize,
    max_buffered_bytes: usize,
    next_expiry: Instant,
}

impl FecDecoder {
    pub fn new(block_ttl: Duration) -> Result<Self> {
        Self::with_max_buffered_bytes(block_ttl, MAX_BUFFERED_BYTES)
    }

    pub fn with_max_buffered_bytes(block_ttl: Duration, max_buffered_bytes: usize) -> Result<Self> {
        ensure!(!block_ttl.is_zero(), "FEC decoder TTL cannot be zero");
        Ok(Self {
            block_ttl,
            blocks: HashMap::new(),
            buffered_bytes: 0,
            max_buffered_bytes: max_buffered_bytes.max(u16::MAX as usize),
            next_expiry: Instant::now() + EXPIRY_INTERVAL,
        })
    }

    pub fn push(&mut self, datagram: Bytes) -> Result<DecodeBatch> {
        let mut batch = DecodeBatch {
            expired_blocks: self.expire(false),
            ..DecodeBatch::default()
        };
        if !datagram.starts_with(MAGIC) {
            batch.frames.push(datagram);
            return Ok(batch);
        }

        let envelope = Envelope::parse(&datagram)?;
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
            self.blocks.insert(
                envelope.block_id,
                DecodeBlock {
                    created: Instant::now(),
                    data_shards: envelope.data_shards,
                    recovery_shards: envelope.recovery_shards,
                    shard_bytes: envelope.shard_bytes,
                    originals: vec![None; envelope.data_shards],
                    recoveries: vec![None; envelope.recovery_shards],
                    delivered: vec![false; envelope.data_shards],
                    complete: false,
                },
            );
        }

        let additional_bytes = {
            let block = self
                .blocks
                .get(&envelope.block_id)
                .expect("FEC block was initialized");
            match envelope.kind {
                KIND_ORIGINAL if block.originals[envelope.index].is_none() => envelope.shard_bytes,
                KIND_RECOVERY if block.recoveries[envelope.index].is_none() => envelope.shard_bytes,
                _ => 0,
            }
        };
        ensure!(
            self.buffered_bytes.saturating_add(additional_bytes) <= self.max_buffered_bytes,
            "active FEC blocks exceed memory limit"
        );
        let block = self
            .blocks
            .get_mut(&envelope.block_id)
            .expect("FEC block was initialized");
        ensure!(
            block.parameters_match(&envelope),
            "FEC block parameters changed"
        );
        if block.complete {
            return Ok(batch);
        }

        match envelope.kind {
            KIND_ORIGINAL => {
                let original = expand_original(envelope.payload, envelope.shard_bytes)?;
                if let Some(existing) = &block.originals[envelope.index] {
                    ensure!(
                        existing == &original,
                        "conflicting duplicate FEC original shard"
                    );
                } else {
                    self.buffered_bytes += original.len();
                    block.originals[envelope.index] = Some(original);
                }
                if !block.delivered[envelope.index] {
                    block.delivered[envelope.index] = true;
                    batch.frames.push(original_payload(envelope.payload)?);
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
                }
            }
            _ => unreachable!(),
        }

        let (original_count, recovery_count) = block.received_shards();
        if original_count < block.data_shards
            && original_count + recovery_count >= block.data_shards
        {
            let mut decoder = ReedSolomonDecoder::new(
                block.data_shards,
                block.recovery_shards,
                block.shard_bytes,
            )
            .context("unsupported FEC decoder parameters")?;
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
                if block.originals[index].is_none() {
                    self.buffered_bytes += original.len();
                    block.originals[index] = Some(original);
                }
                if !block.delivered[index] {
                    block.delivered[index] = true;
                    batch.recovered_shards += 1;
                    batch.frames.push(frame);
                }
            }
        }

        if block.delivered.iter().all(|delivered| *delivered) {
            self.buffered_bytes = self.buffered_bytes.saturating_sub(block.buffered_bytes());
            block.finish();
        }
        Ok(batch)
    }

    pub fn reset(&mut self) {
        self.blocks.clear();
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
        let before = self.blocks.len();
        self.blocks
            .retain(|_, block| block.created.elapsed() < self.block_ttl);
        let expired = before - self.blocks.len();
        self.buffered_bytes = self.blocks.values().map(DecodeBlock::buffered_bytes).sum();
        self.next_expiry = now + EXPIRY_INTERVAL;
        expired as u64
    }

    fn evict_oldest(&mut self) -> Option<u64> {
        let oldest = self
            .blocks
            .iter()
            .min_by_key(|(_, block)| block.created)
            .map(|(id, _)| *id)?;
        let removed = self.blocks.remove(&oldest)?;
        self.buffered_bytes = self.buffered_bytes.saturating_sub(removed.buffered_bytes());
        Some(1)
    }
}

struct Envelope<'a> {
    block_id: u64,
    kind: u8,
    index: usize,
    data_shards: usize,
    recovery_shards: usize,
    shard_bytes: usize,
    payload: &'a [u8],
}

impl<'a> Envelope<'a> {
    fn parse(datagram: &'a [u8]) -> Result<Self> {
        ensure!(datagram.len() >= HEADER_LEN, "truncated FEC envelope");
        ensure!(&datagram[..8] == MAGIC, "invalid FEC envelope magic");
        let block_id = u64::from_be_bytes(datagram[8..16].try_into().unwrap());
        let kind = datagram[16];
        let index = usize::from(datagram[17]);
        let data_shards = usize::from(datagram[18]);
        let recovery_shards = usize::from(datagram[19]);
        let shard_bytes = usize::from(u16::from_be_bytes(datagram[20..22].try_into().unwrap()));
        let payload_bytes = usize::from(u16::from_be_bytes(datagram[22..24].try_into().unwrap()));
        ensure!(block_id != 0, "invalid zero FEC block ID");
        validate_counts(data_shards, recovery_shards)?;
        ensure!(shard_bytes > LENGTH_PREFIX_LEN, "invalid FEC shard size");
        ensure!(shard_bytes.is_multiple_of(2), "FEC shard size must be even");
        ensure!(
            datagram.len() == HEADER_LEN + payload_bytes,
            "FEC envelope payload length mismatch"
        );
        let payload = &datagram[HEADER_LEN..];
        match kind {
            KIND_ORIGINAL => {
                ensure!(index < data_shards, "invalid FEC original shard index");
                ensure!(
                    payload.len() <= shard_bytes,
                    "FEC original exceeds shard size"
                );
                original_payload(payload)?;
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
    let available = maximum - HEADER_LEN;
    Ok(available - available % 2)
}

/// Select a stable size class for a frame instead of padding every recovery
/// shard to the path MTU. This keeps FEC for FlowRouter and interactive packets
/// from turning each small block into multiple full-MTU datagrams.
fn shard_bytes_for_frame(frame_len: usize, maximum: usize) -> Result<usize> {
    let maximum_shard = even_shard_bytes(maximum)?;
    let required = frame_len
        .checked_add(LENGTH_PREFIX_LEN)
        .context("FEC frame length overflow")?;
    ensure!(
        required <= maximum_shard,
        "overlay frame exceeds FEC shard capacity"
    );
    let size_class = required
        .checked_next_power_of_two()
        .unwrap_or(maximum_shard)
        .max(64);
    Ok(size_class.min(maximum_shard))
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
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&block_id.to_be_bytes());
    frame.push(kind);
    frame.push(index as u8);
    frame.push(data_shards as u8);
    frame.push(recovery_shards as u8);
    frame.extend_from_slice(&(shard_bytes as u16).to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(Bytes::from(frame))
}

fn expand_original(payload: &[u8], shard_bytes: usize) -> Result<Vec<u8>> {
    original_payload(payload)?;
    ensure!(
        payload.len() <= shard_bytes,
        "FEC original exceeds shard size"
    );
    let mut original = vec![0; shard_bytes];
    original[..payload.len()].copy_from_slice(payload);
    Ok(original)
}

fn original_payload(payload: &[u8]) -> Result<Bytes> {
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
    Ok(Bytes::copy_from_slice(&payload[2..]))
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

        let resized = encoder.push(Bytes::from(vec![3; 80]), 128).unwrap();
        assert_eq!(resized.unprotected_shards, 1);
    }

    #[test]
    fn small_frames_do_not_generate_full_mtu_recovery_shards() {
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
                .all(|datagram| datagram.bytes.len() == HEADER_LEN + 64)
        );
    }

    #[test]
    fn plain_overlay_frames_pass_through() {
        let mut decoder = FecDecoder::new(Duration::from_secs(1)).unwrap();
        let batch = decoder
            .push(Bytes::from_static(b"ISWIP3\0\0frame"))
            .unwrap();
        assert_eq!(batch.frames, [Bytes::from_static(b"ISWIP3\0\0frame")]);
    }

    #[test]
    fn sustained_rate_evicts_old_tombstones_instead_of_dropping_new_blocks() {
        let mut encoder = FecEncoder::new(2, 1, Duration::from_secs(1)).unwrap();
        let mut decoder = FecDecoder::new(Duration::from_secs(60)).unwrap();
        let mut expired = 0;
        for block in 0..(MAX_BLOCKS + 512) {
            for index in 0..2 {
                let frame = Bytes::from(format!("{block}:{index}"));
                for datagram in encoder.push(frame, 128).unwrap().datagrams {
                    expired += decoder.push(datagram.bytes.clone()).unwrap().expired_blocks;
                }
            }
        }
        assert!(expired >= 512);
        assert!(decoder.blocks.len() <= MAX_BLOCKS);
    }
}

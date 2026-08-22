use std::{
    collections::VecDeque,
    fmt,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, ensure};
use bytes::{BufMut, Bytes, BytesMut};
use reed_solomon_simd::{ReedSolomonDecoder, ReedSolomonEncoder};
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};

use crate::buffer::RecyclingBytePool;

use super::cell::{
    CellBody, CellV2, HEADER_LEN, OVERLAY_HOP_LIMIT_OFFSET, OVERLAY_HOPS_OFFSET,
    SEGMENT_HEADER_LEN, TrafficClass,
};

const PARITY_MAGIC: &[u8; 4] = b"FPV2";
const PARITY_FIXED_LEN: usize = 12;
const ALIGNMENT_RESERVE: usize = 1;
const STRIPE_DATA_SHIFT: u32 = 24;
const STRIPE_SEQUENCE_MASK: u32 = (1 << STRIPE_DATA_SHIFT) - 1;
pub const MAX_DATA_CELLS: usize = 16;
pub const MAX_PARITY_CELLS: usize = 8;
const DEFAULT_MAX_STRIPES: usize = 4096;
const DEFAULT_MAX_BUFFERED_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FecGeometryV2 {
    pub data_cells: usize,
    pub parity_cells: usize,
}

impl FecGeometryV2 {
    pub fn validate(self) -> Result<()> {
        ensure!(
            (2..=MAX_DATA_CELLS).contains(&self.data_cells),
            "V2 FEC data Cell count is out of range"
        );
        ensure!(
            self.parity_cells <= MAX_PARITY_CELLS,
            "V2 FEC parity Cell count is out of range"
        );
        Ok(())
    }
}

/// Maximum encoded systematic Cell size that leaves room for a worst-case
/// parity prefix and one alignment byte. Systematic Cells themselves remain
/// compact and are never padded on the wire.
pub fn protected_cell_maximum(path_maximum: usize, data_cells: usize) -> Result<usize> {
    ensure!(
        (2..=MAX_DATA_CELLS).contains(&data_cells),
        "invalid V2 FEC data Cell count"
    );
    let overhead = HEADER_LEN
        .checked_add(PARITY_FIXED_LEN + data_cells * 2)
        .and_then(|value| value.checked_add(ALIGNMENT_RESERVE))
        .context("V2 FEC overhead overflow")?;
    ensure!(
        path_maximum > overhead + HEADER_LEN,
        "QUIC DATAGRAM limit is too small for V2 Cell FEC"
    );
    Ok(path_maximum - overhead)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FecEncodeStatsV2 {
    pub protected_data_cells: u64,
    pub parity_cells: u64,
    pub parity_bytes: u64,
    pub encode_copy_bytes: u64,
    pub unprotected_tail_cells: u64,
}

#[derive(Debug, Default)]
pub struct EncodedTrainV2 {
    pub systematic: Vec<Bytes>,
    pub parity: Vec<Bytes>,
    pub ordered: Vec<EncodedCellV2>,
    pub stats: FecEncodeStatsV2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedCellV2 {
    pub bytes: Bytes,
    pub recovery: bool,
}

pub struct CellStripeEncoder {
    geometry: FecGeometryV2,
    wire_pool: RecyclingBytePool,
    encoder: Option<ReedSolomonEncoder>,
}

impl fmt::Debug for CellStripeEncoder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CellStripeEncoder")
            .field("geometry", &self.geometry)
            .field("wire_pool", &self.wire_pool)
            .field("encoder_warm", &self.encoder.is_some())
            .finish()
    }
}

impl CellStripeEncoder {
    pub fn new(geometry: FecGeometryV2) -> Result<Self> {
        geometry.validate()?;
        Ok(Self {
            geometry,
            // Allocation is lazy: only descriptors exist until protection is
            // actually enabled and real Cell sizes are known.
            wire_pool: RecyclingBytePool::new(256, 0),
            encoder: None,
        })
    }

    pub fn geometry(&self) -> FecGeometryV2 {
        self.geometry
    }

    pub fn reconfigure(&mut self, geometry: FecGeometryV2) -> Result<()> {
        geometry.validate()?;
        self.geometry = geometry;
        Ok(())
    }

    pub fn encode(
        &mut self,
        mut cells: Vec<CellV2>,
        path_maximum: usize,
    ) -> Result<EncodedTrainV2> {
        ensure!(!cells.is_empty(), "cannot FEC-encode an empty V2 train");
        let first = &cells[0];
        let identity = (
            first.class,
            first.session_epoch,
            first.route_label,
            first.train_id,
            first.overlay_hop_limit,
            first.overlay_hops,
        );
        ensure!(
            cells.iter().all(|cell| {
                matches!(cell.body, CellBody::Records(_))
                    && (
                        cell.class,
                        cell.session_epoch,
                        cell.route_label,
                        cell.train_id,
                        cell.overlay_hop_limit,
                        cell.overlay_hops,
                    ) == identity
            }),
            "V2 FEC stripe crosses train, route, epoch, or class"
        );
        if self.geometry.parity_cells == 0 {
            let systematic = cells
                .into_iter()
                .map(|cell| {
                    self.wire_pool
                        .build(|out| cell.encode_into(path_maximum, out))
                })
                .collect::<Result<Vec<_>>>()?;
            let ordered = systematic
                .iter()
                .cloned()
                .map(|bytes| EncodedCellV2 {
                    bytes,
                    recovery: false,
                })
                .collect();
            return Ok(EncodedTrainV2 {
                systematic,
                ordered,
                ..EncodedTrainV2::default()
            });
        }

        let mut output = EncodedTrainV2::default();
        let protected_maximum = protected_cell_maximum(path_maximum, self.geometry.data_cells)?;
        for stripe in cells.chunks_mut(self.geometry.data_cells) {
            // A single Cell cannot form a Reed-Solomon stripe. Any larger
            // tail is encoded with its actual data count, which is already
            // embedded in the stripe ID and parity length table. The former
            // all-or-nothing rule left up to `data_cells - 1` systematic Cells
            // unprotected; on 16 KiB congestion-sized PacketTrains that could
            // expose a third of the train and amplify one wire loss into a
            // complete inner packet/train loss.
            if stripe.len() == 1 {
                for cell in stripe {
                    cell.stripe_id = 0;
                    let bytes = self
                        .wire_pool
                        .build(|out| cell.encode_into(path_maximum, out))?;
                    output.systematic.push(bytes.clone());
                    output.ordered.push(EncodedCellV2 {
                        bytes,
                        recovery: false,
                    });
                    output.stats.unprotected_tail_cells += 1;
                }
                continue;
            }
            let first_sequence = stripe[0].cell_sequence;
            let stripe_id = encode_stripe_id(first_sequence, stripe.len())?;
            for (offset, cell) in stripe.iter_mut().enumerate() {
                ensure!(
                    usize::from(cell.cell_sequence) == usize::from(first_sequence) + offset,
                    "V2 FEC data Cells are not contiguous"
                );
                cell.stripe_id = stripe_id;
            }
            let lengths = stripe
                .iter()
                .map(encoded_data_cell_len)
                .map(|length| u16::try_from(length?).context("V2 systematic Cell length overflow"))
                .collect::<std::result::Result<Vec<_>, _>>()
                .context("V2 systematic Cell length overflow")?;
            let symbol_bytes = lengths
                .iter()
                .map(|length| usize::from(*length))
                .max()
                .expect("non-empty stripe")
                .next_multiple_of(2);
            let prefix_len = PARITY_FIXED_LEN + stripe.len() * 2;
            ensure!(
                HEADER_LEN + prefix_len + symbol_bytes <= path_maximum,
                "V2 parity Cell exceeds QUIC DATAGRAM limit"
            );
            let data_cells = stripe.len();
            let parity_cells = self.geometry.parity_cells;
            let encoder = match self.encoder.as_mut() {
                Some(encoder) => {
                    encoder
                        .reset(data_cells, parity_cells, symbol_bytes)
                        .context("resetting V2 FEC encoder geometry")?;
                    encoder
                }
                None => self.encoder.insert(
                    ReedSolomonEncoder::new(data_cells, parity_cells, symbol_bytes)
                        .context("unsupported V2 FEC encoder geometry")?,
                ),
            };
            let systematic = stripe
                .iter()
                .zip(&lengths)
                .map(|(cell, length)| {
                    let wire_len = usize::from(*length);
                    self.wire_pool.build(|out| {
                        cell.encode_into(protected_maximum, out)?;
                        debug_assert_eq!(out.len(), wire_len);

                        // reed-solomon-simd copies every original into its
                        // reusable work area. Temporarily zero-pad and
                        // normalize the recyclable wire buffer before that
                        // copy, then restore the real mutable routing shim and
                        // length before freezing it for QUIC. This removes the
                        // former full-size `Vec` expansion copy per data Cell.
                        out.resize(symbol_bytes, 0);
                        let routing_shim =
                            (out[OVERLAY_HOP_LIMIT_OFFSET], out[OVERLAY_HOPS_OFFSET]);
                        normalize_routing_shim(out);
                        let result = encoder
                            .add_original_shard(out.as_ref())
                            .context("adding V2 FEC data Cell");
                        out[OVERLAY_HOP_LIMIT_OFFSET] = routing_shim.0;
                        out[OVERLAY_HOPS_OFFSET] = routing_shim.1;
                        out.truncate(wire_len);
                        result
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let encoded = encoder.encode().context("encoding V2 FEC stripe")?;
            for (recovery_index, recovery) in encoded.recovery_iter().enumerate() {
                let payload = encode_parity_payload(
                    systematic.len(),
                    self.geometry.parity_cells,
                    recovery_index,
                    first_sequence,
                    symbol_bytes,
                    &lengths,
                    recovery,
                )?;
                let parity = CellV2 {
                    class: identity.0,
                    flags: 0,
                    session_epoch: identity.1,
                    route_label: identity.2,
                    train_id: identity.3,
                    cell_sequence: recovery_index as u16,
                    stripe_id,
                    overlay_hop_limit: identity.4,
                    overlay_hops: identity.5,
                    body: CellBody::Parity(payload),
                };
                let parity = self
                    .wire_pool
                    .build(|out| parity.encode_into(path_maximum, out))?;
                output.stats.parity_cells += 1;
                output.stats.parity_bytes = output
                    .stats
                    .parity_bytes
                    .saturating_add(parity.len() as u64);
                output.parity.push(parity);
            }
            output.stats.protected_data_cells += systematic.len() as u64;
            for bytes in systematic {
                output.systematic.push(bytes.clone());
                output.ordered.push(EncodedCellV2 {
                    bytes,
                    recovery: false,
                });
            }
            let parity_start = output.parity.len() - self.geometry.parity_cells;
            output
                .ordered
                .extend(
                    output.parity[parity_start..]
                        .iter()
                        .cloned()
                        .map(|bytes| EncodedCellV2 {
                            bytes,
                            recovery: true,
                        }),
                );
        }
        Ok(output)
    }
}

fn encode_stripe_id(first_sequence: u16, data_cells: usize) -> Result<u32> {
    ensure!(
        (2..=MAX_DATA_CELLS).contains(&data_cells),
        "invalid V2 stripe data count"
    );
    // Zero remains the unprotected-stripe sentinel. Store sequence + 1 in
    // the low bits so variable-size final stripes can describe their actual
    // position without assuming every preceding stripe had the same width.
    let sequence = u32::from(first_sequence) + 1;
    ensure!(
        sequence <= STRIPE_SEQUENCE_MASK,
        "V2 FEC stripe sequence is out of range"
    );
    Ok((data_cells as u32) << STRIPE_DATA_SHIFT | sequence)
}

fn encoded_data_cell_len(cell: &CellV2) -> Result<usize> {
    let CellBody::Records(segments) = &cell.body else {
        anyhow::bail!("V2 FEC systematic Cell is not data");
    };
    segments.iter().try_fold(HEADER_LEN, |total, segment| {
        total
            .checked_add(SEGMENT_HEADER_LEN)
            .and_then(|value| value.checked_add(segment.metadata.len()))
            .and_then(|value| value.checked_add(segment.data.len()))
            .context("V2 systematic Cell length overflow")
    })
}

fn decode_stripe_id(value: u32) -> Result<(u16, usize)> {
    let data_cells = (value >> STRIPE_DATA_SHIFT) as usize;
    let encoded_sequence = value & STRIPE_SEQUENCE_MASK;
    ensure!(
        (2..=MAX_DATA_CELLS).contains(&data_cells) && encoded_sequence != 0,
        "invalid self-describing V2 FEC stripe ID"
    );
    let first_sequence =
        u16::try_from(encoded_sequence - 1).context("V2 FEC stripe sequence overflow")?;
    Ok((first_sequence, data_cells))
}

fn encode_parity_payload(
    data_cells: usize,
    parity_cells: usize,
    recovery_index: usize,
    first_sequence: u16,
    symbol_bytes: usize,
    lengths: &[u16],
    recovery: &[u8],
) -> Result<Bytes> {
    ensure!(data_cells == lengths.len(), "V2 FEC length table mismatch");
    ensure!(
        recovery.len() == symbol_bytes,
        "V2 FEC symbol length mismatch"
    );
    let mut output = BytesMut::with_capacity(PARITY_FIXED_LEN + lengths.len() * 2 + recovery.len());
    output.extend_from_slice(PARITY_MAGIC);
    output.put_u8(data_cells as u8);
    output.put_u8(parity_cells as u8);
    output.put_u8(recovery_index as u8);
    output.put_u8(0);
    output.put_u16(first_sequence);
    output.put_u16(symbol_bytes as u16);
    for length in lengths {
        output.put_u16(*length);
    }
    output.extend_from_slice(recovery);
    Ok(output.freeze())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParityPayload {
    data_cells: usize,
    parity_cells: usize,
    recovery_index: usize,
    first_sequence: u16,
    symbol_bytes: usize,
    lengths: Vec<u16>,
    recovery: Bytes,
}

fn decode_parity_payload(bytes: Bytes) -> Result<ParityPayload> {
    ensure!(
        bytes.len() >= PARITY_FIXED_LEN,
        "truncated V2 parity prefix"
    );
    ensure!(&bytes[..4] == PARITY_MAGIC, "invalid V2 parity magic");
    let data_cells = usize::from(bytes[4]);
    let parity_cells = usize::from(bytes[5]);
    let recovery_index = usize::from(bytes[6]);
    ensure!(bytes[7] == 0, "unsupported V2 parity flags");
    FecGeometryV2 {
        data_cells,
        parity_cells,
    }
    .validate()?;
    ensure!(
        parity_cells > 0 && recovery_index < parity_cells,
        "invalid V2 parity recovery index"
    );
    let first_sequence = u16::from_be_bytes(bytes[8..10].try_into().unwrap());
    let symbol_bytes = usize::from(u16::from_be_bytes(bytes[10..12].try_into().unwrap()));
    ensure!(
        symbol_bytes > 0 && symbol_bytes % 2 == 0,
        "invalid V2 FEC symbol size"
    );
    let lengths_end = PARITY_FIXED_LEN + data_cells * 2;
    ensure!(
        lengths_end <= bytes.len(),
        "truncated V2 parity length table"
    );
    let lengths = bytes[PARITY_FIXED_LEN..lengths_end]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|value| u16::from_be_bytes(*value))
        .collect::<Vec<_>>();
    ensure!(
        lengths
            .iter()
            .all(|length| *length > 0 && usize::from(*length) <= symbol_bytes),
        "invalid V2 FEC original length"
    );
    ensure!(
        bytes.len() - lengths_end == symbol_bytes,
        "invalid V2 parity symbol length"
    );
    Ok(ParityPayload {
        data_cells,
        parity_cells,
        recovery_index,
        first_sequence,
        symbol_bytes,
        lengths,
        recovery: bytes.slice(lengths_end..),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct StripeKey {
    class: TrafficClass,
    session_epoch: u32,
    route_label: u32,
    train_id: u64,
    stripe_id: u32,
}

impl StripeKey {
    fn from_cell(cell: &CellV2) -> Self {
        Self {
            class: cell.class,
            session_epoch: cell.session_epoch,
            route_label: cell.route_label,
            train_id: cell.train_id,
            stripe_id: cell.stripe_id,
        }
    }
}

#[derive(Debug)]
struct DecodeStripe {
    created: Instant,
    updated: Instant,
    geometry: Option<ParityPayload>,
    repair_shape: (u16, usize),
    routing_shim: (u8, u8),
    originals: HashMap<u16, Bytes>,
    recoveries: HashMap<usize, Bytes>,
    delivered: HashSet<u16>,
    repair_requested: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingStripeV2 {
    pub class: TrafficClass,
    pub session_epoch: u32,
    pub route_label: u32,
    pub train_id: u64,
    pub stripe_id: u32,
    pub missing_sequences: Vec<u16>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LossRunHistogramV2 {
    pub run_1: u64,
    pub run_2: u64,
    pub run_3_4: u64,
    pub run_5_plus: u64,
}

impl LossRunHistogramV2 {
    /// Classify consecutive missing Cell sequences. Repair candidates are
    /// naturally sorted, but accepting arbitrary order here keeps the metric
    /// helper correct for decoded test fixtures and future callers.
    pub fn from_missing_sequences(sequences: &[u16]) -> Self {
        if sequences.is_empty() {
            return Self::default();
        }
        let mut sorted = sequences.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        let mut histogram = Self::default();
        let mut run = 1_u64;
        for pair in sorted.windows(2) {
            if pair[1] == pair[0].saturating_add(1) {
                run += 1;
            } else {
                histogram.observe_run(run);
                run = 1;
            }
        }
        histogram.observe_run(run);
        histogram
    }

    fn observe_run(&mut self, length: u64) {
        match length {
            0 => {}
            1 => self.run_1 = self.run_1.saturating_add(1),
            2 => self.run_2 = self.run_2.saturating_add(1),
            3..=4 => self.run_3_4 = self.run_3_4.saturating_add(1),
            _ => self.run_5_plus = self.run_5_plus.saturating_add(1),
        }
    }
}

impl DecodeStripe {
    fn buffered_bytes(&self) -> usize {
        self.originals.values().map(Bytes::len).sum::<usize>()
            + self.recoveries.values().map(Bytes::len).sum::<usize>()
    }
}

#[derive(Debug, Default)]
pub struct FecDecodeOutputV2 {
    pub cells: Vec<CellV2>,
    pub parity_received: u64,
    pub recovered_cells: u64,
    pub wasted_parity: u64,
    pub expired_stripes: u64,
    pub decode_copy_bytes: u64,
    pub recovery_latency_micros: u64,
}

#[derive(Debug)]
pub struct CellStripeDecoder {
    session_epoch: u32,
    ttl: Duration,
    maximum_stripes: usize,
    maximum_buffered_bytes: usize,
    stripes: HashMap<StripeKey, DecodeStripe>,
    order: VecDeque<(StripeKey, Instant)>,
    completed: HashSet<StripeKey>,
    completed_order: VecDeque<StripeKey>,
    buffered_bytes: usize,
}

impl CellStripeDecoder {
    pub fn new(session_epoch: u32, ttl: Duration) -> Result<Self> {
        Self::with_limits(
            session_epoch,
            ttl,
            DEFAULT_MAX_STRIPES,
            DEFAULT_MAX_BUFFERED_BYTES,
        )
    }

    pub fn with_limits(
        session_epoch: u32,
        ttl: Duration,
        maximum_stripes: usize,
        maximum_buffered_bytes: usize,
    ) -> Result<Self> {
        ensure!(session_epoch != 0, "V2 FEC session epoch zero is reserved");
        ensure!(!ttl.is_zero(), "V2 FEC stripe TTL is zero");
        ensure!(maximum_stripes > 0, "V2 FEC stripe limit is zero");
        ensure!(maximum_buffered_bytes > 0, "V2 FEC byte limit is zero");
        Ok(Self {
            session_epoch,
            ttl,
            maximum_stripes,
            maximum_buffered_bytes,
            stripes: HashMap::default(),
            order: VecDeque::new(),
            completed: HashSet::default(),
            completed_order: VecDeque::new(),
            buffered_bytes: 0,
        })
    }

    pub fn push(&mut self, bytes: Bytes) -> Result<FecDecodeOutputV2> {
        self.push_at(bytes, Instant::now())
    }

    pub fn push_at(&mut self, bytes: Bytes, now: Instant) -> Result<FecDecodeOutputV2> {
        let cell = CellV2::decode(bytes.clone())?;
        ensure!(
            cell.session_epoch == self.session_epoch,
            "V2 FEC Cell belongs to another session epoch"
        );
        let mut output = FecDecodeOutputV2 {
            expired_stripes: self.expire(now),
            ..FecDecodeOutputV2::default()
        };
        if cell.stripe_id == 0 {
            ensure!(
                matches!(cell.body, CellBody::Records(_)),
                "unstriped V2 parity Cell"
            );
            output.cells.push(cell);
            return Ok(output);
        }
        let key = StripeKey::from_cell(&cell);
        let (first_sequence, stripe_data_cells) = decode_stripe_id(cell.stripe_id)?;
        if matches!(&cell.body, CellBody::Records(_)) {
            ensure!(
                (first_sequence..first_sequence.saturating_add(stripe_data_cells as u16))
                    .contains(&cell.cell_sequence),
                "V2 systematic Cell is outside its stripe"
            );
        }
        if self.completed.contains(&key) {
            if matches!(cell.body, CellBody::Parity(_)) {
                output.parity_received = 1;
                output.wasted_parity = 1;
            }
            return Ok(output);
        }
        self.ensure_stripe(key, now, (cell.overlay_hop_limit, cell.overlay_hops))?;
        match &cell.body {
            CellBody::Records(_) => {
                let sequence = cell.cell_sequence;
                let stripe = self.stripes.get_mut(&key).expect("stripe was inserted");
                if let Some(existing) = stripe.originals.get(&sequence) {
                    ensure!(existing == &bytes, "conflicting V2 FEC data Cell duplicate");
                } else {
                    self.reserve(bytes.len(), key)?;
                    let stripe = self.stripes.get_mut(&key).expect("stripe remains present");
                    stripe.originals.insert(sequence, bytes);
                    stripe.delivered.insert(sequence);
                    self.buffered_bytes += stripe.originals[&sequence].len();
                    output.cells.push(cell);
                }
            }
            CellBody::Parity(payload) => {
                output.parity_received = 1;
                let metadata = decode_parity_payload(payload.clone())?;
                ensure!(
                    metadata.data_cells == stripe_data_cells
                        && metadata.first_sequence == first_sequence,
                    "V2 parity metadata disagrees with stripe ID"
                );
                let stripe = self.stripes.get_mut(&key).expect("stripe was inserted");
                match &stripe.geometry {
                    Some(existing) => ensure!(
                        same_geometry(existing, &metadata),
                        "V2 FEC stripe geometry changed"
                    ),
                    None => stripe.geometry = Some(metadata.clone()),
                }
                if let Some(existing) = stripe.recoveries.get(&metadata.recovery_index) {
                    ensure!(
                        existing == &metadata.recovery,
                        "conflicting V2 parity duplicate"
                    );
                } else {
                    self.reserve(metadata.recovery.len(), key)?;
                    let stripe = self.stripes.get_mut(&key).expect("stripe remains present");
                    stripe
                        .recoveries
                        .insert(metadata.recovery_index, metadata.recovery.clone());
                    self.buffered_bytes += metadata.recovery.len();
                }
            }
        }
        if let Some(mut recovered) = self.try_recover(key)? {
            output.recovery_latency_micros = self.stripes.get(&key).map_or(0, |stripe| {
                now.saturating_duration_since(stripe.created)
                    .as_micros()
                    .min(u128::from(u64::MAX)) as u64
            });
            output.recovered_cells = recovered.len() as u64;
            output.decode_copy_bytes = recovered.iter().map(|(_, bytes, _)| *bytes as u64).sum();
            output
                .cells
                .extend(recovered.drain(..).map(|(_, _, cell)| cell));
        }
        if self.stripe_complete(key) {
            let parity_count = self
                .stripes
                .get(&key)
                .map_or(0, |stripe| stripe.recoveries.len());
            if output.recovered_cells == 0 && output.parity_received != 0 {
                output.wasted_parity = parity_count as u64;
            }
            self.complete(key);
        } else if let Some(stripe) = self.stripes.get_mut(&key) {
            stripe.updated = now;
            self.order.push_back((key, now));
        }
        Ok(output)
    }

    pub fn buffered_bytes(&self) -> usize {
        self.buffered_bytes
    }

    /// Resize the decoder budget in place. Shrinking retains the newest
    /// stripes and evicts complete stripe allocations atomically, so no
    /// partially retained Reed-Solomon geometry can escape the new limit.
    pub fn set_maximum_buffered_bytes(&mut self, maximum_buffered_bytes: usize) -> Result<usize> {
        ensure!(maximum_buffered_bytes > 0, "V2 FEC byte limit is zero");
        self.maximum_buffered_bytes = maximum_buffered_bytes;
        let mut evicted = 0;
        while self.buffered_bytes > maximum_buffered_bytes {
            let Some((candidate, generation)) = self.order.pop_front() else {
                break;
            };
            let current = self
                .stripes
                .get(&candidate)
                .is_some_and(|stripe| stripe.updated == generation);
            if current {
                self.remove_stripe(candidate);
                evicted += 1;
            }
        }
        debug_assert!(self.buffered_bytes <= maximum_buffered_bytes);
        Ok(evicted)
    }

    pub fn maximum_buffered_bytes(&self) -> usize {
        self.maximum_buffered_bytes
    }

    /// Update only the retention horizon. FEC geometry is carried by every
    /// parity Cell, so a receiver must remain able to decode a peer whose
    /// directional tuner enables protection before the local tuner does.
    pub fn set_ttl(&mut self, ttl: Duration) -> Result<()> {
        ensure!(!ttl.is_zero(), "V2 FEC stripe TTL is zero");
        self.ttl = ttl;
        self.expire(Instant::now());
        Ok(())
    }

    pub fn active_stripes(&self) -> usize {
        self.stripes.len()
    }

    pub fn repair_candidates(
        &mut self,
        now: Instant,
        minimum_age: Duration,
    ) -> Vec<MissingStripeV2> {
        let mut candidates = Vec::new();
        for (&key, stripe) in &mut self.stripes {
            let (first_sequence, data_cells) = stripe.repair_shape;
            // Repair runs on a reliable QUIC stream and a response is a
            // definitive snapshot of the sender's stripe cache. Reissuing a
            // request while the first one is in flight only amplifies control
            // traffic on the exact congested/lossy path Repair is meant to
            // help. One request per stripe is therefore sufficient; the
            // stripe itself remains alive for natural/FEC completion.
            if stripe.repair_requested
                // A stripe can be intentionally interleaved with other Bulk
                // flows for several scheduler rounds. Age from the most
                // recently received Cell, not the first Cell, otherwise a
                // healthy but paced stripe emits a false Repair request while
                // it is still making forward progress.
                || now.saturating_duration_since(stripe.updated) < minimum_age
            {
                continue;
            }
            let missing_sequences = (0..data_cells)
                .filter_map(|index| u16::try_from(usize::from(first_sequence) + index).ok())
                .filter(|sequence| !stripe.delivered.contains(sequence))
                .collect::<Vec<_>>();
            if missing_sequences.is_empty() {
                continue;
            }
            stripe.repair_requested = true;
            candidates.push(MissingStripeV2 {
                class: key.class,
                session_epoch: key.session_epoch,
                route_label: key.route_label,
                train_id: key.train_id,
                stripe_id: key.stripe_id,
                missing_sequences,
            });
        }
        candidates
    }

    pub fn expire(&mut self, now: Instant) -> u64 {
        let mut expired = 0_u64;
        while let Some(&(key, generation)) = self.order.front() {
            let current = self.stripes.get(&key).is_some_and(|stripe| {
                stripe.updated == generation
                    && now.saturating_duration_since(stripe.updated) >= self.ttl
            });
            let obsolete = self
                .stripes
                .get(&key)
                .is_none_or(|stripe| stripe.updated != generation);
            if !current && !obsolete {
                break;
            }
            self.order.pop_front();
            if current {
                self.remove_stripe(key);
                expired += 1;
            }
        }
        expired
    }

    fn ensure_stripe(
        &mut self,
        key: StripeKey,
        now: Instant,
        routing_shim: (u8, u8),
    ) -> Result<()> {
        if let Some(stripe) = self.stripes.get(&key) {
            ensure!(
                stripe.routing_shim == routing_shim,
                "V2 FEC stripe crossed overlay hop generations"
            );
            return Ok(());
        }
        while self.stripes.len() >= self.maximum_stripes {
            let Some((oldest, _)) = self.order.pop_front() else {
                break;
            };
            self.remove_stripe(oldest);
        }
        ensure!(
            self.stripes.len() < self.maximum_stripes,
            "too many active V2 FEC stripes"
        );
        self.stripes.insert(
            key,
            DecodeStripe {
                created: now,
                updated: now,
                geometry: None,
                repair_shape: { decode_stripe_id(key.stripe_id)? },
                routing_shim,
                originals: HashMap::default(),
                recoveries: HashMap::default(),
                delivered: HashSet::default(),
                repair_requested: false,
            },
        );
        self.order.push_back((key, now));
        Ok(())
    }

    fn reserve(&mut self, additional: usize, protected: StripeKey) -> Result<()> {
        while self.buffered_bytes.saturating_add(additional) > self.maximum_buffered_bytes {
            let Some((candidate, _)) = self.order.pop_front() else {
                break;
            };
            if candidate == protected {
                self.order
                    .push_back((candidate, self.stripes[&candidate].updated));
                if self.stripes.len() == 1 {
                    break;
                }
                continue;
            }
            self.remove_stripe(candidate);
        }
        ensure!(
            self.buffered_bytes.saturating_add(additional) <= self.maximum_buffered_bytes,
            "V2 FEC buffered byte limit exceeded"
        );
        Ok(())
    }

    fn try_recover(&mut self, key: StripeKey) -> Result<Option<Vec<(u16, usize, CellV2)>>> {
        let stripe = self.stripes.get(&key).context("missing V2 FEC stripe")?;
        let Some(geometry) = stripe.geometry.clone() else {
            return Ok(None);
        };
        let present = (0..geometry.data_cells)
            .filter(|index| {
                let sequence = usize::from(geometry.first_sequence) + index;
                u16::try_from(sequence)
                    .ok()
                    .is_some_and(|sequence| stripe.originals.contains_key(&sequence))
            })
            .count();
        if present == geometry.data_cells || present + stripe.recoveries.len() < geometry.data_cells
        {
            return Ok(None);
        }
        let mut decoder = ReedSolomonDecoder::new(
            geometry.data_cells,
            geometry.parity_cells,
            geometry.symbol_bytes,
        )
        .context("unsupported V2 FEC decoder geometry")?;
        let mut expanded = Vec::new();
        for index in 0..geometry.data_cells {
            let sequence = u16::try_from(usize::from(geometry.first_sequence) + index)
                .context("V2 FEC sequence overflow")?;
            if let Some(original) = stripe.originals.get(&sequence) {
                let mut symbol = vec![0_u8; geometry.symbol_bytes];
                symbol[..original.len()].copy_from_slice(original);
                normalize_routing_shim(&mut symbol);
                expanded.push((index, symbol));
            }
        }
        for (index, symbol) in &expanded {
            decoder
                .add_original_shard(*index, symbol)
                .context("adding V2 FEC received data Cell")?;
        }
        for (&index, recovery) in &stripe.recoveries {
            decoder
                .add_recovery_shard(index, recovery)
                .context("adding V2 FEC parity Cell")?;
        }
        let decoded = decoder.decode().context("decoding V2 FEC stripe")?;
        let restored = decoded
            .restored_original_iter()
            .map(|(index, symbol)| (index, symbol.to_vec()))
            .collect::<Vec<_>>();
        drop(decoded);
        let stripe = self.stripes.get_mut(&key).expect("stripe remains present");
        let mut output = Vec::new();
        for (index, symbol) in restored {
            let sequence = u16::try_from(usize::from(geometry.first_sequence) + index)
                .context("V2 recovered Cell sequence overflow")?;
            let length = usize::from(geometry.lengths[index]);
            let mut bytes = BytesMut::from(&symbol[..length]);
            bytes[OVERLAY_HOP_LIMIT_OFFSET] = stripe.routing_shim.0;
            bytes[OVERLAY_HOPS_OFFSET] = stripe.routing_shim.1;
            let bytes = bytes.freeze();
            let cell = CellV2::decode(bytes.clone())?;
            ensure!(
                StripeKey::from_cell(&cell) == key && cell.cell_sequence == sequence,
                "recovered V2 Cell identity mismatch"
            );
            if stripe.delivered.insert(sequence) {
                output.push((sequence, length, cell));
            }
        }
        Ok(Some(output))
    }

    fn stripe_complete(&self, key: StripeKey) -> bool {
        let Some(stripe) = self.stripes.get(&key) else {
            return false;
        };
        let Some(geometry) = &stripe.geometry else {
            return false;
        };
        (0..geometry.data_cells).all(|index| {
            u16::try_from(usize::from(geometry.first_sequence) + index)
                .ok()
                .is_some_and(|sequence| stripe.delivered.contains(&sequence))
        })
    }

    fn complete(&mut self, key: StripeKey) {
        self.remove_stripe(key);
        self.completed.insert(key);
        self.completed_order.push_back(key);
        while self.completed.len() > self.maximum_stripes {
            let Some(oldest) = self.completed_order.pop_front() else {
                break;
            };
            self.completed.remove(&oldest);
        }
    }

    fn remove_stripe(&mut self, key: StripeKey) {
        if let Some(stripe) = self.stripes.remove(&key) {
            self.buffered_bytes = self.buffered_bytes.saturating_sub(stripe.buffered_bytes());
        }
        self.order.retain(|(candidate, _)| candidate != &key);
    }
}

fn normalize_routing_shim(symbol: &mut [u8]) {
    debug_assert!(symbol.len() >= HEADER_LEN);
    symbol[OVERLAY_HOP_LIMIT_OFFSET] = 0;
    symbol[OVERLAY_HOPS_OFFSET] = 0;
}

fn same_geometry(left: &ParityPayload, right: &ParityPayload) -> bool {
    left.data_cells == right.data_cells
        && left.parity_cells == right.parity_cells
        && left.first_sequence == right.first_sequence
        && left.symbol_bytes == right.symbol_bytes
        && left.lengths == right.lengths
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::v2::cell::advance_overlay_hop;
    use crate::protocol::v2::train::{TrainContext, TrainRecord, build_packet_train};

    fn cells(records: usize) -> Vec<CellV2> {
        let protected = protected_cell_maximum(1382, 4).unwrap();
        build_packet_train(
            TrainContext {
                class: TrafficClass::Bulk,
                session_epoch: 7,
                route_label: 9,
                overlay_hop_limit: 64,
                train_id: 11,
                maximum_datagram_size: protected,
                maximum_cells: 256,
            },
            (1..=records).map(|record_id| TrainRecord {
                record_id: record_id as u16,
                metadata: Bytes::new(),
                data: Bytes::from(vec![record_id as u8; 1200]),
            }),
        )
        .unwrap()
        .cells
    }

    #[test]
    fn missing_sequence_runs_are_classified_by_burst_length() {
        let histogram =
            LossRunHistogramV2::from_missing_sequences(&[20, 2, 1, 8, 7, 6, 5, 12, 21, 22, 23, 24]);
        assert_eq!(
            histogram,
            LossRunHistogramV2 {
                run_1: 1,
                run_2: 1,
                run_3_4: 1,
                run_5_plus: 1,
            }
        );
    }

    #[test]
    fn systematic_cells_are_not_padded_on_wire() {
        let encoded = CellStripeEncoder::new(FecGeometryV2 {
            data_cells: 4,
            parity_cells: 1,
        })
        .unwrap()
        .encode(cells(4), 1382)
        .unwrap();
        assert_eq!(encoded.stats.protected_data_cells, 4);
        assert_eq!(encoded.stats.encode_copy_bytes, 0);
        assert_eq!(encoded.parity.len(), 1);
        assert!(encoded.systematic.iter().any(|cell| cell.len() < 1300));
        assert!(encoded.systematic.iter().all(|cell| cell.len() <= 1382));
        assert!(encoded.parity.iter().all(|cell| cell.len() <= 1382));
    }

    #[test]
    fn reconfiguration_preserves_and_reuses_fec_wire_storage() {
        let mut encoder = CellStripeEncoder::new(FecGeometryV2 {
            data_cells: 4,
            parity_cells: 0,
        })
        .unwrap();
        let first = encoder.encode(cells(1), 1382).unwrap();
        let pointer = first.systematic[0].as_ptr();
        drop(first);

        encoder
            .reconfigure(FecGeometryV2 {
                data_cells: 8,
                parity_cells: 0,
            })
            .unwrap();
        let second = encoder.encode(cells(1), 1382).unwrap();
        assert_eq!(second.systematic[0].as_ptr(), pointer);
    }

    #[test]
    fn mutable_transit_shim_is_excluded_from_fec_symbols() {
        let encoded = CellStripeEncoder::new(FecGeometryV2 {
            data_cells: 4,
            parity_cells: 1,
        })
        .unwrap()
        .encode(cells(4), 1382)
        .unwrap();
        assert_eq!(encoded.systematic.len(), 4);
        let missing = encoded.systematic[0].clone();
        let missing_sequence = CellV2::decode(missing).unwrap().cell_sequence;
        let mut decoder = CellStripeDecoder::new(7, Duration::from_secs(1)).unwrap();
        let mut received = Vec::new();
        let mut recovered = 0;
        for (index, cell) in encoded.ordered.into_iter().enumerate() {
            if index == 0 {
                continue;
            }
            let forwarded = advance_overlay_hop(cell.bytes).unwrap();
            let output = decoder.push(forwarded.bytes).unwrap();
            recovered += output.recovered_cells;
            received.extend(output.cells);
        }
        assert_eq!(recovered, 1);
        assert_eq!(received.len(), 4);
        let restored = received
            .iter()
            .find(|cell| cell.cell_sequence == missing_sequence)
            .unwrap();
        assert_eq!(restored.overlay_hop_limit, 63);
        assert_eq!(restored.overlay_hops, 1);
    }

    #[test]
    fn one_missing_cell_is_recovered_and_originals_are_immediate() {
        let encoded = CellStripeEncoder::new(FecGeometryV2 {
            data_cells: 4,
            parity_cells: 1,
        })
        .unwrap()
        .encode(cells(4), 1382)
        .unwrap();
        let missing = 2;
        let expected = CellV2::decode(encoded.systematic[missing].clone()).unwrap();
        let mut decoder = CellStripeDecoder::new(7, Duration::from_secs(1)).unwrap();
        let mut delivered = Vec::new();
        for (index, systematic) in encoded.systematic.into_iter().enumerate() {
            if index == missing {
                continue;
            }
            let output = decoder.push(systematic).unwrap();
            assert_eq!(output.cells.len(), 1);
            assert_eq!(output.recovered_cells, 0);
            delivered.extend(output.cells);
        }
        let output = decoder.push(encoded.parity[0].clone()).unwrap();
        assert_eq!(output.recovered_cells, 1);
        assert_eq!(output.cells, vec![expected]);
        delivered.extend(output.cells);
        assert_eq!(delivered.len(), 4);
        assert_eq!(decoder.active_stripes(), 0);
        assert_eq!(decoder.buffered_bytes(), 0);
    }

    #[test]
    fn burst_loss_up_to_parity_count_is_recovered_out_of_order() {
        let encoded = CellStripeEncoder::new(FecGeometryV2 {
            data_cells: 4,
            parity_cells: 2,
        })
        .unwrap()
        .encode(cells(4), 1382)
        .unwrap();
        let expected = encoded
            .systematic
            .iter()
            .map(|cell| CellV2::decode(cell.clone()).unwrap().cell_sequence)
            .collect::<HashSet<_>>();
        let mut decoder = CellStripeDecoder::new(7, Duration::from_secs(1)).unwrap();
        let mut delivered = HashSet::default();
        for index in [3, 0] {
            delivered.extend(
                decoder
                    .push(encoded.systematic[index].clone())
                    .unwrap()
                    .cells
                    .into_iter()
                    .map(|cell| cell.cell_sequence),
            );
        }
        for parity in encoded.parity.into_iter().rev() {
            delivered.extend(
                decoder
                    .push(parity)
                    .unwrap()
                    .cells
                    .into_iter()
                    .map(|cell| cell.cell_sequence),
            );
        }
        assert_eq!(delivered, expected);
    }

    #[test]
    fn stripe_epoch_geometry_and_memory_are_bounded() {
        assert!(
            FecGeometryV2 {
                data_cells: 1,
                parity_cells: 1
            }
            .validate()
            .is_err()
        );
        assert!(
            FecGeometryV2 {
                data_cells: 4,
                parity_cells: 9
            }
            .validate()
            .is_err()
        );
        let encoded = CellStripeEncoder::new(FecGeometryV2 {
            data_cells: 4,
            parity_cells: 1,
        })
        .unwrap()
        .encode(cells(4), 1382)
        .unwrap();
        let mut decoder =
            CellStripeDecoder::with_limits(8, Duration::from_millis(10), 1, 4096).unwrap();
        assert!(decoder.push(encoded.systematic[0].clone()).is_err());

        let mut decoder =
            CellStripeDecoder::with_limits(7, Duration::from_millis(10), 1, 4096).unwrap();
        let start = Instant::now();
        decoder
            .push_at(encoded.systematic[0].clone(), start)
            .unwrap();
        assert_eq!(decoder.active_stripes(), 1);
        assert_eq!(decoder.expire(start + Duration::from_millis(10)), 1);
        assert_eq!(decoder.buffered_bytes(), 0);
    }

    #[test]
    fn decoder_budget_shrink_evicts_oldest_stripe_in_place() {
        let first = CellStripeEncoder::new(FecGeometryV2 {
            data_cells: 4,
            parity_cells: 1,
        })
        .unwrap()
        .encode(cells(4), 1382)
        .unwrap();
        let mut second_cells = cells(4);
        for cell in &mut second_cells {
            cell.train_id += 1;
        }
        let second = CellStripeEncoder::new(FecGeometryV2 {
            data_cells: 4,
            parity_cells: 1,
        })
        .unwrap()
        .encode(second_cells, 1382)
        .unwrap();
        let start = Instant::now();
        let mut decoder =
            CellStripeDecoder::with_limits(7, Duration::from_secs(1), 4, 16 * 1024).unwrap();
        decoder.push_at(first.systematic[0].clone(), start).unwrap();
        decoder
            .push_at(
                second.systematic[0].clone(),
                start + Duration::from_millis(1),
            )
            .unwrap();
        let newest_bytes = second.systematic[0].len();

        assert_eq!(decoder.set_maximum_buffered_bytes(newest_bytes).unwrap(), 1);
        assert_eq!(decoder.maximum_buffered_bytes(), newest_bytes);
        assert_eq!(decoder.active_stripes(), 1);
        assert_eq!(decoder.buffered_bytes(), newest_bytes);
    }

    #[test]
    fn insufficient_parity_requests_missing_cells_only_once() {
        let encoded = CellStripeEncoder::new(FecGeometryV2 {
            data_cells: 4,
            parity_cells: 1,
        })
        .unwrap()
        .encode(cells(4), 1382)
        .unwrap();
        let start = Instant::now();
        let mut decoder = CellStripeDecoder::new(7, Duration::from_secs(1)).unwrap();
        decoder
            .push_at(encoded.systematic[0].clone(), start)
            .unwrap();
        decoder
            .push_at(encoded.systematic[3].clone(), start)
            .unwrap();
        decoder.push_at(encoded.parity[0].clone(), start).unwrap();
        assert!(
            decoder
                .repair_candidates(start + Duration::from_millis(5), Duration::from_millis(10))
                .is_empty()
        );
        let requests =
            decoder.repair_candidates(start + Duration::from_millis(10), Duration::from_millis(10));
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].missing_sequences, vec![1, 2]);
        assert!(
            decoder
                .repair_candidates(start + Duration::from_millis(200), Duration::ZERO,)
                .is_empty()
        );
        let output = decoder
            .push_at(
                encoded.systematic[1].clone(),
                start + Duration::from_millis(21),
            )
            .unwrap();
        assert_eq!(output.cells.len(), 2);
        assert_eq!(output.recovered_cells, 1);
        assert_eq!(decoder.active_stripes(), 0);
    }

    #[test]
    fn forward_progress_restarts_the_repair_grace_period() {
        let encoded = CellStripeEncoder::new(FecGeometryV2 {
            data_cells: 4,
            parity_cells: 1,
        })
        .unwrap()
        .encode(cells(4), 1382)
        .unwrap();
        let start = Instant::now();
        let mut decoder = CellStripeDecoder::new(7, Duration::from_secs(1)).unwrap();
        decoder
            .push_at(encoded.systematic[0].clone(), start)
            .unwrap();
        decoder
            .push_at(
                encoded.systematic[2].clone(),
                start + Duration::from_millis(9),
            )
            .unwrap();
        assert!(
            decoder
                .repair_candidates(start + Duration::from_millis(10), Duration::from_millis(10))
                .is_empty()
        );
        assert_eq!(
            decoder
                .repair_candidates(start + Duration::from_millis(19), Duration::from_millis(10))
                .len(),
            1
        );
    }

    #[test]
    fn self_describing_stripe_requests_repair_when_all_parity_is_lost() {
        let encoded = CellStripeEncoder::new(FecGeometryV2 {
            data_cells: 4,
            parity_cells: 1,
        })
        .unwrap()
        .encode(cells(4), 1382)
        .unwrap();
        let start = Instant::now();
        let mut decoder = CellStripeDecoder::new(7, Duration::from_secs(1)).unwrap();
        for index in [0, 2, 3] {
            decoder
                .push_at(encoded.systematic[index].clone(), start)
                .unwrap();
        }
        let requests =
            decoder.repair_candidates(start + Duration::from_millis(20), Duration::from_millis(10));
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].missing_sequences, vec![1]);
    }

    #[test]
    fn incomplete_tail_has_no_redundant_parity() {
        let encoded = CellStripeEncoder::new(FecGeometryV2 {
            data_cells: 4,
            parity_cells: 2,
        })
        .unwrap()
        .encode(cells(5), 1382)
        .unwrap();
        assert_eq!(encoded.stats.protected_data_cells, 4);
        assert_eq!(encoded.stats.unprotected_tail_cells, 1);
        assert_eq!(encoded.parity.len(), 2);
        assert_eq!(
            CellV2::decode(encoded.systematic[4].clone())
                .unwrap()
                .stripe_id,
            0
        );
    }

    #[test]
    fn multi_cell_tail_is_self_describing_and_recoverable() {
        let encoded = CellStripeEncoder::new(FecGeometryV2 {
            data_cells: 4,
            parity_cells: 1,
        })
        .unwrap()
        .encode(cells(6), 1382)
        .unwrap();
        assert_eq!(encoded.stats.protected_data_cells, 6);
        assert_eq!(encoded.stats.unprotected_tail_cells, 0);
        assert_eq!(encoded.parity.len(), 2);

        let tail_stripe = CellV2::decode(encoded.systematic[4].clone())
            .unwrap()
            .stripe_id;
        assert_eq!(decode_stripe_id(tail_stripe).unwrap().1, 2);

        let expected = CellV2::decode(encoded.systematic[5].clone()).unwrap();
        let mut decoder = CellStripeDecoder::new(7, Duration::from_secs(1)).unwrap();
        decoder.push(encoded.systematic[4].clone()).unwrap();
        let recovered = decoder.push(encoded.parity[1].clone()).unwrap();
        assert_eq!(recovered.recovered_cells, 1);
        assert_eq!(recovered.cells, vec![expected]);
    }
}

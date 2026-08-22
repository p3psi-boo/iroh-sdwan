use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use anyhow::{Result, ensure};
use bytes::{Bytes, BytesMut};
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};
use smallvec::{SmallVec, smallvec};

use super::cell::{
    CellBody, CellV2, FLAG_TRAIN_END, FLAG_TRAIN_START, MAX_RECORD_BYTES, RecordSegment,
    SegmentKind, TrafficClass,
};

const MAX_EXPIRY_SWEEP_INTERVAL: Duration = Duration::from_millis(10);
const COMPLETED_RECORD_SMALL_LIMIT: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReassemblyLimits {
    pub maximum_cells: usize,
    pub maximum_active_records: usize,
    pub maximum_buffered_bytes: usize,
}

impl ReassemblyLimits {
    fn validate(self) -> Result<()> {
        ensure!(
            (1..=u16::MAX as usize).contains(&self.maximum_cells),
            "invalid V2 reassembly cell limit"
        );
        ensure!(
            (1..=u16::MAX as usize).contains(&self.maximum_active_records),
            "invalid V2 reassembly record limit"
        );
        ensure!(
            self.maximum_buffered_bytes >= MAX_RECORD_BYTES,
            "V2 reassembly byte limit is too small"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TrainKey {
    pub class: TrafficClass,
    pub session_epoch: u32,
    pub route_label: u32,
    pub train_id: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct ReassemblyTableLimits {
    pub session_epoch: u32,
    pub maximum_active_trains: usize,
    pub maximum_buffered_bytes: usize,
    pub train_timeout: Duration,
    pub per_train: ReassemblyLimits,
}

impl ReassemblyTableLimits {
    fn validate(self) -> Result<()> {
        ensure!(
            self.session_epoch != 0,
            "V2 reassembly epoch zero is reserved"
        );
        ensure!(
            (1..=u16::MAX as usize).contains(&self.maximum_active_trains),
            "invalid V2 active train limit"
        );
        ensure!(
            self.maximum_buffered_bytes >= MAX_RECORD_BYTES,
            "V2 global reassembly budget is too small"
        );
        ensure!(
            !self.train_timeout.is_zero(),
            "V2 train timeout must be positive"
        );
        self.per_train.validate()
    }
}

#[derive(Debug)]
struct TimedTrain {
    reassembler: TrainReassembler,
    last_update: Instant,
}

/// Bounded peer-level table for concurrently interleaved PacketTrains.
#[derive(Debug)]
pub struct ReassemblyTableV2 {
    limits: ReassemblyTableLimits,
    // QUIC preserves DATAGRAM order on the normal path and the scheduler emits
    // one PacketTrain contiguously. Keep that overwhelmingly common train out
    // of the hash table: otherwise every Cell paid four hash probes (completed,
    // duplicate, presence, mutable lookup) even though its key was unchanged.
    hot_train: Option<(TrainKey, TimedTrain)>,
    trains: HashMap<TrainKey, TimedTrain>,
    completed: HashMap<TrainKey, Instant>,
    completed_order: VecDeque<TrainKey>,
    buffered_bytes: usize,
    next_expiry_check: Option<Instant>,
}

impl ReassemblyTableV2 {
    pub fn new(limits: ReassemblyTableLimits) -> Result<Self> {
        limits.validate()?;
        Ok(Self {
            limits,
            hot_train: None,
            trains: HashMap::default(),
            completed: HashMap::default(),
            completed_order: VecDeque::new(),
            buffered_bytes: 0,
            next_expiry_check: None,
        })
    }

    pub fn accept(&mut self, mut cell: CellV2) -> Result<ReassemblyOutput> {
        self.accept_reusing_at(&mut cell, Instant::now())
    }

    pub(crate) fn accept_reusing(&mut self, cell: &mut CellV2) -> Result<ReassemblyOutput> {
        self.accept_reusing_at(cell, Instant::now())
    }

    pub fn accept_at(&mut self, mut cell: CellV2, now: Instant) -> Result<ReassemblyOutput> {
        self.accept_reusing_at(&mut cell, now)
    }

    fn accept_reusing_at(&mut self, cell: &mut CellV2, now: Instant) -> Result<ReassemblyOutput> {
        ensure!(
            cell.session_epoch == self.limits.session_epoch,
            "V2 Cell belongs to another session epoch"
        );
        let mut timeout_expirations = self.expire_if_due(now);
        let key = TrainKey {
            class: cell.class,
            session_epoch: cell.session_epoch,
            route_label: cell.route_label,
            train_id: cell.train_id,
        };
        let hot_matches = self.hot_train.as_ref().is_some_and(|(hot, _)| *hot == key);
        // While a train is hot it cannot also be completed. This removes the
        // completed-tombstone hash lookup from every Cell after the first.
        if !hot_matches && self.completed.contains_key(&key) {
            return Ok(ReassemblyOutput {
                records: Vec::new(),
                duplicate_cell: true,
                train_complete: true,
                pressure_evicted_trains: 0,
                reassembly_expired_trains: timeout_expirations as u64,
                reorder_cells: 0,
                missing_cells: 0,
                fec: FecReceiveStatsV2::default(),
            });
        }
        let duplicate = if hot_matches {
            self.hot_train
                .as_ref()
                .expect("matching V2 hot train exists")
                .1
                .reassembler
                .cell_seen(cell.cell_sequence)
        } else {
            self.trains
                .get(&key)
                .is_some_and(|train| train.reassembler.cell_seen(cell.cell_sequence))
        };
        let incoming_bytes = if duplicate {
            0
        } else {
            match &cell.body {
                CellBody::Records(segments) => segments.iter().fold(0_usize, |total, segment| {
                    total
                        .saturating_add(segment.metadata.len())
                        .saturating_add(segment.data.len())
                }),
                CellBody::Parity(_) => 0,
            }
        };
        // DATAGRAM loss and reordering are normal dataplane conditions. Memory
        // pressure must therefore shed incomplete work instead of tearing down
        // the whole QUIC session. Prefer the least recently updated train; the
        // currently arriving train is naturally the last candidate unless it
        // is the only retained train.
        let mut pressure_evictions = 0_u64;
        while self.buffered_bytes.saturating_add(incoming_bytes)
            > self.limits.maximum_buffered_bytes
        {
            let Some(oldest) = self.oldest_train_key() else {
                break;
            };
            self.remove_train(oldest);
            pressure_evictions = pressure_evictions.saturating_add(1);
        }
        ensure!(
            incoming_bytes <= self.limits.maximum_buffered_bytes,
            "V2 Cell exceeds the global reassembly byte budget"
        );
        let hot_matches_after_pressure =
            self.hot_train.as_ref().is_some_and(|(hot, _)| *hot == key);
        if !hot_matches_after_pressure {
            if self.active_trains() >= self.limits.maximum_active_trains
                && !self.trains.contains_key(&key)
            {
                // Capacity pressure bypasses the cadence gate so expired
                // state can never cause a false hard-limit rejection.
                timeout_expirations = timeout_expirations.saturating_add(self.expire(now));
            }
            if self.active_trains() >= self.limits.maximum_active_trains
                && !self.trains.contains_key(&key)
                && let Some(oldest) = self.oldest_train_key()
            {
                self.remove_train(oldest);
                pressure_evictions = pressure_evictions.saturating_add(1);
            }
            let train = self.trains.remove(&key).unwrap_or(TimedTrain {
                reassembler: TrainReassembler::new(self.limits.per_train)?,
                last_update: now,
            });
            if let Some((previous_key, previous)) = self.hot_train.replace((key, train)) {
                let replaced = self.trains.insert(previous_key, previous);
                debug_assert!(replaced.is_none());
            }
        }
        let (before, after, accepted) = {
            let (hot_key, train) = self.hot_train.as_mut().expect("V2 hot train was installed");
            debug_assert_eq!(*hot_key, key);
            let before = train.reassembler.buffered_bytes();
            let accepted = train.reassembler.accept_reusing(cell);
            train.last_update = now;
            (before, train.reassembler.buffered_bytes(), accepted)
        };
        self.buffered_bytes = self
            .buffered_bytes
            .saturating_sub(before)
            .saturating_add(after);
        let mut output = match accepted {
            Ok(output) => output,
            Err(error) => {
                self.remove_train(key);
                return Err(error);
            }
        };
        output.pressure_evicted_trains = output
            .pressure_evicted_trains
            .saturating_add(pressure_evictions);
        output.reassembly_expired_trains = output
            .reassembly_expired_trains
            .saturating_add(timeout_expirations as u64);
        if output.train_complete {
            self.remove_train(key);
            self.completed.insert(key, now);
            self.completed_order.push_back(key);
            while self.completed.len() > self.limits.maximum_active_trains {
                let Some(oldest) = self.completed_order.pop_front() else {
                    break;
                };
                self.completed.remove(&oldest);
            }
        }
        Ok(output)
    }

    pub fn buffered_bytes(&self) -> usize {
        self.buffered_bytes
    }

    pub fn active_trains(&self) -> usize {
        self.trains.len() + usize::from(self.hot_train.is_some())
    }

    /// Resize the peer-level byte budget without discarding the table or its
    /// completion tombstones. Shrinking evicts the least recently updated
    /// incomplete trains until the new hard limit is satisfied.
    pub fn set_maximum_buffered_bytes(&mut self, maximum_buffered_bytes: usize) -> Result<usize> {
        ensure!(
            maximum_buffered_bytes >= MAX_RECORD_BYTES,
            "V2 global reassembly budget is too small"
        );
        self.limits.maximum_buffered_bytes = maximum_buffered_bytes;
        let mut evicted = 0;
        while self.buffered_bytes > maximum_buffered_bytes {
            let Some(oldest) = self.oldest_train_key() else {
                break;
            };
            self.remove_train(oldest);
            evicted += 1;
        }
        debug_assert!(self.buffered_bytes <= maximum_buffered_bytes);
        Ok(evicted)
    }

    pub fn maximum_buffered_bytes(&self) -> usize {
        self.limits.maximum_buffered_bytes
    }

    /// Resize the concurrently interleaved train limit. Shrinking trims the
    /// completion tombstones immediately; incomplete trains converge through
    /// the byte budget and the train timeout.
    pub fn set_maximum_active_trains(&mut self, maximum_active_trains: usize) -> Result<()> {
        ensure!(
            (1..=u16::MAX as usize).contains(&maximum_active_trains),
            "invalid V2 active train limit"
        );
        self.limits.maximum_active_trains = maximum_active_trains;
        while self.completed.len() > maximum_active_trains {
            let Some(oldest) = self.completed_order.pop_front() else {
                break;
            };
            self.completed.remove(&oldest);
        }
        Ok(())
    }

    pub fn maximum_active_trains(&self) -> usize {
        self.limits.maximum_active_trains
    }

    pub fn expire(&mut self, now: Instant) -> usize {
        let mut expired = 0;
        let mut released_bytes = 0_usize;
        self.trains.retain(|_, train| {
            let stale =
                now.saturating_duration_since(train.last_update) >= self.limits.train_timeout;
            if stale {
                released_bytes = released_bytes.saturating_add(train.reassembler.buffered_bytes());
                expired += 1;
            }
            !stale
        });
        if self.hot_train.as_ref().is_some_and(|(_, train)| {
            now.saturating_duration_since(train.last_update) >= self.limits.train_timeout
        }) && let Some((_, train)) = self.hot_train.take()
        {
            released_bytes = released_bytes.saturating_add(train.reassembler.buffered_bytes());
            expired += 1;
        }
        self.buffered_bytes = self.buffered_bytes.saturating_sub(released_bytes);
        while let Some(key) = self.completed_order.front().copied() {
            let stale = self.completed.get(&key).is_none_or(|completed| {
                now.saturating_duration_since(*completed) >= self.limits.train_timeout
            });
            if !stale {
                break;
            }
            self.completed_order.pop_front();
            self.completed.remove(&key);
        }
        self.next_expiry_check =
            Some(now + self.limits.train_timeout.min(MAX_EXPIRY_SWEEP_INTERVAL));
        expired
    }

    #[inline]
    fn expire_if_due(&mut self, now: Instant) -> usize {
        if self
            .next_expiry_check
            .is_none_or(|deadline| now >= deadline)
        {
            self.expire(now)
        } else {
            0
        }
    }

    fn oldest_train_key(&self) -> Option<TrainKey> {
        let cold = self
            .trains
            .iter()
            .min_by_key(|(_, train)| train.last_update)
            .map(|(&key, train)| (key, train.last_update));
        match (self.hot_train.as_ref(), cold) {
            (Some((key, train)), Some((cold_key, cold_update))) => {
                Some(if train.last_update <= cold_update {
                    *key
                } else {
                    cold_key
                })
            }
            (Some((key, _)), None) => Some(*key),
            (None, Some((key, _))) => Some(key),
            (None, None) => None,
        }
    }

    fn remove_train(&mut self, key: TrainKey) {
        if self.hot_train.as_ref().is_some_and(|(hot, _)| *hot == key) {
            let (_, train) = self.hot_train.take().expect("matching V2 hot train exists");
            self.buffered_bytes = self
                .buffered_bytes
                .saturating_sub(train.reassembler.buffered_bytes());
            return;
        }
        if let Some(train) = self.trains.remove(&key) {
            self.buffered_bytes = self
                .buffered_bytes
                .saturating_sub(train.reassembler.buffered_bytes());
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletedRecord {
    pub train: TrainKey,
    pub record_id: u16,
    pub metadata: Bytes,
    pub total_len: usize,
    pub fragments: SmallVec<[Bytes; 2]>,
}

impl CompletedRecord {
    /// Return the original slice for an unsplit record and perform exactly one
    /// allocation when a TUN backend requires a fragmented record to be
    /// contiguous.
    pub fn coalesce(&self) -> Bytes {
        if self.fragments.len() == 1 {
            return self.fragments[0].clone();
        }
        let mut out = BytesMut::with_capacity(self.total_len);
        for fragment in &self.fragments {
            out.extend_from_slice(fragment);
        }
        debug_assert_eq!(out.len(), self.total_len);
        out.freeze()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FecReceiveStatsV2 {
    pub parity_received: u64,
    pub recovered_cells: u64,
    pub wasted_parity: u64,
    pub expired_stripes: u64,
    pub decode_copy_bytes: u64,
    pub recovery_latency_micros: u64,
}

impl FecReceiveStatsV2 {
    pub fn merge(&mut self, other: Self) {
        self.parity_received = self.parity_received.saturating_add(other.parity_received);
        self.recovered_cells = self.recovered_cells.saturating_add(other.recovered_cells);
        self.wasted_parity = self.wasted_parity.saturating_add(other.wasted_parity);
        self.expired_stripes = self.expired_stripes.saturating_add(other.expired_stripes);
        self.decode_copy_bytes = self
            .decode_copy_bytes
            .saturating_add(other.decode_copy_bytes);
        self.recovery_latency_micros = self
            .recovery_latency_micros
            .saturating_add(other.recovery_latency_micros);
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReassemblyOutput {
    pub records: Vec<CompletedRecord>,
    pub duplicate_cell: bool,
    pub train_complete: bool,
    pub pressure_evicted_trains: u64,
    pub reassembly_expired_trains: u64,
    pub reorder_cells: u64,
    pub missing_cells: u64,
    pub fec: FecReceiveStatsV2,
}

impl ReassemblyOutput {
    pub fn merge(&mut self, other: Self) {
        self.records.extend(other.records);
        self.duplicate_cell |= other.duplicate_cell;
        self.train_complete |= other.train_complete;
        self.pressure_evicted_trains = self
            .pressure_evicted_trains
            .saturating_add(other.pressure_evicted_trains);
        self.reassembly_expired_trains = self
            .reassembly_expired_trains
            .saturating_add(other.reassembly_expired_trains);
        self.reorder_cells = self.reorder_cells.saturating_add(other.reorder_cells);
        self.missing_cells = self.missing_cells.saturating_add(other.missing_cells);
        self.fec.merge(other.fec);
    }
}

#[derive(Debug)]
struct RecordState {
    total_len: usize,
    metadata: Option<Bytes>,
    offsets: SmallVec<[usize; 2]>,
    fragments: SmallVec<[Bytes; 2]>,
    data_bytes: usize,
    buffered_bytes: usize,
}

impl RecordState {
    fn new(total_len: usize) -> Self {
        // The common 1,100-1,382 byte Cell range needs roughly one fragment
        // per 1,200 record bytes. Reserve once for GSO super-packets while
        // keeping tiny/adversarial partial records cheap.
        let estimated_fragments = total_len.div_ceil(1_200).clamp(1, 64);
        Self {
            total_len,
            metadata: None,
            offsets: SmallVec::with_capacity(estimated_fragments),
            fragments: SmallVec::with_capacity(estimated_fragments),
            data_bytes: 0,
            buffered_bytes: 0,
        }
    }

    fn additional_bytes(&self, segment: &RecordSegment) -> usize {
        segment.data.len()
            + if self.metadata.is_none() {
                segment.metadata.len()
            } else {
                0
            }
    }

    fn insert(&mut self, segment: RecordSegment) -> Result<()> {
        ensure!(
            self.total_len == segment.total_len as usize,
            "V2 record total length changed"
        );
        let offset = segment.offset as usize;
        let end = offset + segment.data.len();
        let index = self.offsets.partition_point(|existing| *existing < offset);
        if index > 0 {
            let previous_offset = self.offsets[index - 1];
            let previous = &self.fragments[index - 1];
            ensure!(
                previous_offset + previous.len() <= offset,
                "overlapping V2 record segment"
            );
        }
        if let Some(next_offset) = self.offsets.get(index) {
            ensure!(end <= *next_offset, "overlapping V2 record segment");
        }
        if matches!(segment.kind, SegmentKind::Full | SegmentKind::Start) {
            match &self.metadata {
                Some(existing) => {
                    ensure!(existing == &segment.metadata, "V2 record metadata changed")
                }
                None => {
                    self.buffered_bytes += segment.metadata.len();
                    self.metadata = Some(segment.metadata);
                }
            }
        }
        self.data_bytes += segment.data.len();
        self.buffered_bytes += segment.data.len();
        self.offsets.insert(index, offset);
        self.fragments.insert(index, segment.data);
        Ok(())
    }

    fn complete(&self) -> bool {
        // Every insertion is range-checked and rejects overlap. Therefore a
        // covered-byte sum equal to `total_len` proves there are no holes,
        // without rescanning all previous fragments after every Cell.
        self.metadata.is_some() && self.data_bytes == self.total_len
    }

    fn finish(self, train: TrainKey, record_id: u16) -> CompletedRecord {
        CompletedRecord {
            train,
            record_id,
            metadata: self.metadata.expect("complete record has metadata"),
            total_len: self.total_len,
            fragments: self.fragments,
        }
    }
}

#[derive(Debug)]
pub struct TrainReassembler {
    limits: ReassemblyLimits,
    key: Option<TrainKey>,
    seen_cells: Vec<u64>,
    seen_cell_count: usize,
    max_seen_sequence: Option<u16>,
    // PacketTrain record IDs are already bounded and, for the hot GSO path,
    // there is normally exactly one split record. Sorted small vectors avoid
    // two hash-table probes per Cell without adding a fixed 64K bitmap to
    // every active train.
    completed_records: CompletedRecordIds,
    records: Vec<(u16, RecordState)>,
    end_sequence: Option<u16>,
    saw_start: bool,
    closure_observed: bool,
    buffered_bytes: usize,
}

#[derive(Debug)]
enum CompletedRecordIds {
    Small(Vec<u16>),
    Large(HashSet<u16>),
}

impl CompletedRecordIds {
    fn new() -> Self {
        Self::Small(Vec::new())
    }

    #[inline]
    fn contains(&self, value: u16) -> bool {
        match self {
            Self::Small(values) => values.binary_search(&value).is_ok(),
            Self::Large(values) => values.contains(&value),
        }
    }

    fn insert(&mut self, value: u16) -> bool {
        match self {
            Self::Small(values) => match values.binary_search(&value) {
                Ok(_) => false,
                Err(index) if values.len() < COMPLETED_RECORD_SMALL_LIMIT => {
                    values.insert(index, value);
                    true
                }
                Err(_) => {
                    let mut large = HashSet::default();
                    large.reserve(values.len().saturating_mul(2));
                    large.extend(values.drain(..));
                    let inserted = large.insert(value);
                    *self = Self::Large(large);
                    inserted
                }
            },
            Self::Large(values) => values.insert(value),
        }
    }
}

impl TrainReassembler {
    pub fn new(limits: ReassemblyLimits) -> Result<Self> {
        limits.validate()?;
        let seen_words = limits.maximum_cells.div_ceil(u64::BITS as usize);
        Ok(Self {
            limits,
            key: None,
            seen_cells: vec![0; seen_words],
            seen_cell_count: 0,
            max_seen_sequence: None,
            completed_records: CompletedRecordIds::new(),
            records: Vec::new(),
            end_sequence: None,
            saw_start: false,
            closure_observed: false,
            buffered_bytes: 0,
        })
    }

    pub fn key(&self) -> Option<TrainKey> {
        self.key
    }

    pub fn buffered_bytes(&self) -> usize {
        self.buffered_bytes
    }

    pub fn accept(&mut self, mut cell: CellV2) -> Result<ReassemblyOutput> {
        self.accept_reusing(&mut cell)
    }

    pub(crate) fn accept_reusing(&mut self, cell: &mut CellV2) -> Result<ReassemblyOutput> {
        let key = TrainKey {
            class: cell.class,
            session_epoch: cell.session_epoch,
            route_label: cell.route_label,
            train_id: cell.train_id,
        };
        match self.key {
            Some(expected) => ensure!(expected == key, "V2 cell belongs to another train"),
            None => self.key = Some(key),
        }
        ensure!(
            (cell.cell_sequence as usize) < self.limits.maximum_cells,
            "V2 cell sequence exceeds reassembly limit"
        );
        let reordered = self
            .max_seen_sequence
            .is_some_and(|maximum| cell.cell_sequence < maximum);
        if !self.mark_cell_seen(cell.cell_sequence) {
            return Ok(ReassemblyOutput {
                records: Vec::new(),
                duplicate_cell: true,
                train_complete: self.is_complete(),
                pressure_evicted_trains: 0,
                reassembly_expired_trains: 0,
                reorder_cells: 0,
                missing_cells: 0,
                fec: FecReceiveStatsV2::default(),
            });
        }
        self.max_seen_sequence = Some(
            self.max_seen_sequence
                .map_or(cell.cell_sequence, |maximum| {
                    maximum.max(cell.cell_sequence)
                }),
        );
        if cell.flags & FLAG_TRAIN_START != 0 {
            ensure!(cell.cell_sequence == 0, "V2 train start is not cell zero");
            self.saw_start = true;
        }
        if cell.flags & FLAG_TRAIN_END != 0 {
            match self.end_sequence {
                Some(sequence) => ensure!(
                    sequence == cell.cell_sequence,
                    "V2 train has conflicting end cells"
                ),
                None => self.end_sequence = Some(cell.cell_sequence),
            }
        }
        let missing_cells = if !self.closure_observed && self.saw_start {
            if let Some(end_sequence) = self.end_sequence {
                self.closure_observed = true;
                (usize::from(end_sequence) + 1).saturating_sub(self.seen_cell_count) as u64
            } else {
                0
            }
        } else {
            0
        };
        let CellBody::Records(segments) = &mut cell.body else {
            anyhow::bail!("V2 parity cell must pass through FEC recovery before reassembly");
        };

        let mut completed = Vec::new();
        for segment in segments.drain(..) {
            let record_id = segment.record_id;
            ensure!(
                !self.completed_records.contains(record_id),
                "V2 record id reused after completion"
            );
            if segment.kind == SegmentKind::Full {
                // The Cell decoder already proved this is an offset-zero,
                // exact-length record. Deliver its Bytes view directly and
                // avoid transient RecordState/BTreeMap allocation and lookup.
                ensure!(
                    self.records
                        .binary_search_by_key(&record_id, |(id, _)| *id)
                        .is_err(),
                    "V2 full record collides with partial record"
                );
                let inserted = self.completed_records.insert(record_id);
                debug_assert!(inserted);
                completed.push(CompletedRecord {
                    train: key,
                    record_id,
                    metadata: segment.metadata,
                    total_len: segment.total_len as usize,
                    fragments: smallvec![segment.data],
                });
                continue;
            }
            let index = match self.records.binary_search_by_key(&record_id, |(id, _)| *id) {
                Ok(index) => index,
                Err(index) => {
                    ensure!(
                        self.records.len() < self.limits.maximum_active_records,
                        "too many active V2 records"
                    );
                    self.records.insert(
                        index,
                        (record_id, RecordState::new(segment.total_len as usize)),
                    );
                    index
                }
            };
            let state = &mut self.records[index].1;
            let additional = state.additional_bytes(&segment);
            ensure!(
                self.buffered_bytes.saturating_add(additional)
                    <= self.limits.maximum_buffered_bytes,
                "V2 reassembly byte budget exceeded"
            );
            state.insert(segment)?;
            self.buffered_bytes += additional;
            if state.complete() {
                let (_, state) = self.records.remove(index);
                self.buffered_bytes = self.buffered_bytes.saturating_sub(state.buffered_bytes);
                let inserted = self.completed_records.insert(record_id);
                debug_assert!(inserted);
                completed.push(state.finish(key, record_id));
            }
        }
        Ok(ReassemblyOutput {
            records: completed,
            duplicate_cell: false,
            train_complete: self.is_complete(),
            pressure_evicted_trains: 0,
            reassembly_expired_trains: 0,
            reorder_cells: u64::from(reordered),
            missing_cells,
            fec: FecReceiveStatsV2::default(),
        })
    }

    fn is_complete(&self) -> bool {
        let Some(end) = self.end_sequence else {
            return false;
        };
        self.saw_start && self.records.is_empty() && self.seen_cell_count == usize::from(end) + 1
    }

    fn cell_seen(&self, sequence: u16) -> bool {
        let sequence = usize::from(sequence);
        self.seen_cells
            .get(sequence / u64::BITS as usize)
            .is_some_and(|word| word & (1_u64 << (sequence % u64::BITS as usize)) != 0)
    }

    fn mark_cell_seen(&mut self, sequence: u16) -> bool {
        let sequence = usize::from(sequence);
        let word = sequence / u64::BITS as usize;
        let bit = 1_u64 << (sequence % u64::BITS as usize);
        let unseen = self.seen_cells[word] & bit == 0;
        if unseen {
            self.seen_cells[word] |= bit;
            self.seen_cell_count += 1;
        }
        unseen
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::v2::cell::MAX_METADATA_BYTES;
    use crate::protocol::v2::train::{TrainContext, TrainRecord, build_packet_train};

    fn limits() -> ReassemblyLimits {
        ReassemblyLimits {
            maximum_cells: 256,
            maximum_active_records: 128,
            maximum_buffered_bytes: 1024 * 1024,
        }
    }

    fn table_limits() -> ReassemblyTableLimits {
        ReassemblyTableLimits {
            session_epoch: 1,
            maximum_active_trains: 4,
            maximum_buffered_bytes: 2 * 1024 * 1024,
            train_timeout: Duration::from_millis(100),
            per_train: limits(),
        }
    }

    #[test]
    fn completed_record_ids_promote_without_quadratic_growth_or_reuse() {
        let mut completed = CompletedRecordIds::new();
        for record_id in 1..=4_096 {
            assert!(completed.insert(record_id));
        }
        assert!(matches!(completed, CompletedRecordIds::Large(_)));
        for record_id in 1..=4_096 {
            assert!(completed.contains(record_id));
            assert!(!completed.insert(record_id));
        }
    }

    fn context(maximum_datagram_size: usize) -> TrainContext {
        TrainContext {
            class: TrafficClass::Bulk,
            session_epoch: 1,
            route_label: 2,
            overlay_hop_limit: 64,
            train_id: 3,
            maximum_datagram_size,
            maximum_cells: 256,
        }
    }

    #[test]
    fn out_of_order_cells_complete_records_without_waiting_for_the_train() {
        let expected = (1..=8)
            .map(|id| (id, Bytes::from(vec![id as u8; 1500])))
            .collect::<HashMap<_, _>>();
        let train = build_packet_train(
            context(512),
            expected.iter().map(|(&record_id, data)| TrainRecord {
                record_id,
                metadata: Bytes::new(),
                data: data.clone(),
            }),
        )
        .unwrap();
        let mut reassembler = TrainReassembler::new(limits()).unwrap();
        let mut completed = HashMap::default();
        let cell_count = train.cells.len();
        for (index, cell) in train.cells.into_iter().rev().enumerate() {
            let output = reassembler.accept(cell).unwrap();
            for record in output.records {
                completed.insert(record.record_id, record.coalesce());
            }
            assert_eq!(output.train_complete, index + 1 == cell_count);
        }
        assert_eq!(completed, expected);
        assert_eq!(reassembler.buffered_bytes(), 0);
    }

    #[test]
    fn train_closure_reports_reordering_and_observed_gaps_once() {
        let train = build_packet_train(
            context(256),
            [TrainRecord {
                record_id: 1,
                metadata: Bytes::new(),
                data: Bytes::from(vec![7; 2_000]),
            }],
        )
        .unwrap();
        assert!(train.cells.len() > 3);
        let expected_missing = train.cells.len() as u64 - 2;
        let mut reassembler = TrainReassembler::new(limits()).unwrap();

        let end = reassembler
            .accept(train.cells.last().unwrap().clone())
            .unwrap();
        assert_eq!(end.reorder_cells, 0);
        assert_eq!(end.missing_cells, 0);
        let start = reassembler.accept(train.cells[0].clone()).unwrap();
        assert_eq!(start.reorder_cells, 1);
        assert_eq!(start.missing_cells, expected_missing);

        let middle = reassembler.accept(train.cells[1].clone()).unwrap();
        assert_eq!(middle.missing_cells, 0);
    }

    #[test]
    fn maximum_gso_record_budget_includes_bounded_metadata() {
        let metadata = Bytes::from(vec![9; MAX_METADATA_BYTES]);
        let data = Bytes::from(vec![7; MAX_RECORD_BYTES]);
        let train = build_packet_train(
            context(1_382),
            [TrainRecord {
                record_id: 1,
                metadata: metadata.clone(),
                data: data.clone(),
            }],
        )
        .unwrap();
        let mut limits = limits();
        limits.maximum_buffered_bytes = MAX_RECORD_BYTES + MAX_METADATA_BYTES;
        let mut reassembler = TrainReassembler::new(limits).unwrap();
        let mut completed = Vec::new();
        for cell in train.cells {
            completed.extend(reassembler.accept(cell).unwrap().records);
        }
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].metadata, metadata);
        assert_eq!(completed[0].coalesce(), data);
        assert_eq!(reassembler.buffered_bytes(), 0);
    }

    #[test]
    fn two_cell_record_keeps_fragment_descriptors_inline() {
        let train = build_packet_train(
            context(1_382),
            [TrainRecord {
                record_id: 1,
                metadata: Bytes::new(),
                data: Bytes::from(vec![7; 1_500]),
            }],
        )
        .unwrap();
        assert_eq!(train.cells.len(), 2);
        let mut reassembler = TrainReassembler::new(limits()).unwrap();
        assert!(
            reassembler
                .accept(train.cells[0].clone())
                .unwrap()
                .records
                .is_empty()
        );
        let output = reassembler.accept(train.cells[1].clone()).unwrap();
        assert_eq!(output.records.len(), 1);
        assert_eq!(output.records[0].fragments.len(), 2);
        assert!(!output.records[0].fragments.spilled());
    }

    #[test]
    fn decoded_segment_storage_is_drained_and_reused_across_cells() {
        let train = build_packet_train(
            context(1_382),
            [TrainRecord {
                record_id: 1,
                metadata: Bytes::new(),
                data: Bytes::from(vec![9; 1_500]),
            }],
        )
        .unwrap();
        let wire = train.cells[0].encode(1_382).unwrap();
        let storage = Vec::with_capacity(8);
        let mut decoded = CellV2::decode_reusing(wire, storage).unwrap();
        let mut reassembler = TrainReassembler::new(limits()).unwrap();
        reassembler.accept_reusing(&mut decoded).unwrap();
        let storage = decoded.take_record_storage();
        assert!(storage.is_empty());
        assert!(storage.capacity() >= 8);
    }

    #[test]
    fn a_full_record_is_delivered_before_train_end() {
        let train = build_packet_train(
            context(100),
            [
                TrainRecord {
                    record_id: 1,
                    metadata: Bytes::new(),
                    data: Bytes::from_static(b"first"),
                },
                TrainRecord {
                    record_id: 2,
                    metadata: Bytes::new(),
                    data: Bytes::from(vec![2; 100]),
                },
            ],
        )
        .unwrap();
        assert!(train.cells.len() > 1);
        let mut reassembler = TrainReassembler::new(limits()).unwrap();
        let output = reassembler.accept(train.cells[0].clone()).unwrap();
        assert!(output.records.iter().any(|record| record.record_id == 1));
        assert!(!output.train_complete);
    }

    #[test]
    fn duplicate_cell_is_idempotent() {
        let train = build_packet_train(
            context(100),
            [TrainRecord {
                record_id: 1,
                metadata: Bytes::new(),
                data: Bytes::from_static(b"payload"),
            }],
        )
        .unwrap();
        let mut reassembler = TrainReassembler::new(limits()).unwrap();
        let first = reassembler.accept(train.cells[0].clone()).unwrap();
        assert_eq!(first.records.len(), 1);
        let duplicate = reassembler.accept(train.cells[0].clone()).unwrap();
        assert!(duplicate.duplicate_cell);
        assert!(duplicate.records.is_empty());
    }

    #[test]
    fn overlapping_segments_are_rejected() {
        let mut reassembler = TrainReassembler::new(limits()).unwrap();
        let base = CellV2 {
            class: TrafficClass::Bulk,
            flags: FLAG_TRAIN_START,
            session_epoch: 1,
            route_label: 2,
            train_id: 3,
            cell_sequence: 0,
            stripe_id: 0,
            overlay_hop_limit: 64,
            overlay_hops: 0,
            body: CellBody::Records(vec![RecordSegment {
                kind: SegmentKind::Start,
                flags: 0,
                record_id: 1,
                total_len: 8,
                offset: 0,
                metadata: Bytes::new(),
                data: Bytes::from_static(b"1234"),
            }]),
        };
        reassembler.accept(base).unwrap();
        let overlap = CellV2 {
            class: TrafficClass::Bulk,
            flags: FLAG_TRAIN_END,
            session_epoch: 1,
            route_label: 2,
            train_id: 3,
            cell_sequence: 1,
            stripe_id: 0,
            overlay_hop_limit: 64,
            overlay_hops: 0,
            body: CellBody::Records(vec![RecordSegment {
                kind: SegmentKind::End,
                flags: 0,
                record_id: 1,
                total_len: 8,
                offset: 3,
                metadata: Bytes::new(),
                data: Bytes::from_static(b"45678"),
            }]),
        };
        assert!(reassembler.accept(overlap).is_err());
    }

    #[test]
    fn table_reassembles_interleaved_trains_and_tombstones_completion() {
        let mut first_context = context(512);
        first_context.train_id = 10;
        let mut second_context = first_context;
        second_context.train_id = 11;
        let first = build_packet_train(
            first_context,
            [TrainRecord {
                record_id: 1,
                metadata: Bytes::new(),
                data: Bytes::from(vec![1; 1500]),
            }],
        )
        .unwrap();
        let second = build_packet_train(
            second_context,
            [TrainRecord {
                record_id: 1,
                metadata: Bytes::new(),
                data: Bytes::from(vec![2; 1500]),
            }],
        )
        .unwrap();
        let duplicate = first.cells[0].clone();
        let mut table = ReassemblyTableV2::new(table_limits()).unwrap();
        let mut completed = Vec::new();
        for index in 0..first.cells.len().max(second.cells.len()) {
            for cells in [&first.cells, &second.cells] {
                if let Some(cell) = cells.get(index) {
                    completed.extend(table.accept(cell.clone()).unwrap().records);
                }
            }
        }
        assert_eq!(completed.len(), 2);
        assert_eq!(table.active_trains(), 0);
        assert_eq!(table.buffered_bytes(), 0);
        let late = table.accept(duplicate).unwrap();
        assert!(late.duplicate_cell);
        assert!(late.train_complete);
    }

    #[test]
    fn table_rejects_old_epoch_and_expires_partial_train() {
        let base = Instant::now();
        let train = build_packet_train(
            context(512),
            [TrainRecord {
                record_id: 1,
                metadata: Bytes::new(),
                data: Bytes::from(vec![1; 1500]),
            }],
        )
        .unwrap();
        let mut table = ReassemblyTableV2::new(table_limits()).unwrap();
        table.accept_at(train.cells[0].clone(), base).unwrap();
        assert_eq!(table.active_trains(), 1);
        assert!(table.buffered_bytes() > 0);
        assert_eq!(table.expire(base + Duration::from_millis(100)), 1);
        assert_eq!(table.active_trains(), 0);
        assert_eq!(table.buffered_bytes(), 0);

        let mut old = train.cells[0].clone();
        old.session_epoch = 2;
        assert!(table.accept_at(old, base).is_err());
    }

    #[test]
    fn active_train_limit_resizes_and_trims_tombstones() {
        let base = Instant::now();
        let mut probes = Vec::new();
        let mut table = ReassemblyTableV2::new(table_limits()).unwrap();
        assert_eq!(table.maximum_active_trains(), 4);
        for train_id in 1..=4_u64 {
            let mut train_context = context(512);
            train_context.train_id = train_id;
            let train = build_packet_train(
                train_context,
                [TrainRecord {
                    record_id: 1,
                    metadata: Bytes::new(),
                    data: Bytes::from(vec![1; 1500]),
                }],
            )
            .unwrap();
            probes.push(train.cells[0].clone());
            for cell in train.cells {
                table.accept_at(cell, base).unwrap();
            }
        }
        assert_eq!(table.active_trains(), 0);
        // Completion tombstones recognise a late duplicate of every train.
        assert!(
            table
                .accept_at(probes[0].clone(), base)
                .unwrap()
                .duplicate_cell
        );
        table.set_maximum_active_trains(2).unwrap();
        assert_eq!(table.maximum_active_trains(), 2);
        // The oldest tombstones were trimmed: their late Cells open a fresh
        // train instead of being recognised as duplicates, while the newest
        // tombstones still catch duplicates.
        assert!(
            !table
                .accept_at(probes[0].clone(), base)
                .unwrap()
                .duplicate_cell
        );
        assert!(
            table
                .accept_at(probes[3].clone(), base)
                .unwrap()
                .duplicate_cell
        );
        assert!(table.set_maximum_active_trains(0).is_err());
    }

    #[test]
    fn cadence_expiration_is_returned_with_the_next_receive_output() {
        let base = Instant::now();
        let partial = build_packet_train(
            context(256),
            [TrainRecord {
                record_id: 1,
                metadata: Bytes::new(),
                data: Bytes::from(vec![1; 2_000]),
            }],
        )
        .unwrap();
        let mut next_context = context(512);
        next_context.train_id = 99;
        let complete = build_packet_train(
            next_context,
            [TrainRecord {
                record_id: 1,
                metadata: Bytes::new(),
                data: Bytes::from_static(b"next"),
            }],
        )
        .unwrap();
        let mut table = ReassemblyTableV2::new(table_limits()).unwrap();
        table.accept_at(partial.cells[0].clone(), base).unwrap();
        let output = table
            .accept_at(complete.cells[0].clone(), base + Duration::from_millis(100))
            .unwrap();
        assert_eq!(output.reassembly_expired_trains, 1);
    }

    #[test]
    fn accept_after_idle_sweeps_an_expired_partial_train() {
        let base = Instant::now();
        let train = build_packet_train(
            context(512),
            [TrainRecord {
                record_id: 1,
                metadata: Bytes::new(),
                data: Bytes::from(vec![1; 1500]),
            }],
        )
        .unwrap();
        let mut table = ReassemblyTableV2::new(table_limits()).unwrap();
        let first_cell = train.cells[0].clone();
        table.accept_at(first_cell.clone(), base).unwrap();
        assert_eq!(table.active_trains(), 1);

        let accepted = table
            .accept_at(first_cell, base + Duration::from_millis(100))
            .unwrap();
        assert!(!accepted.duplicate_cell);
        assert_eq!(table.active_trains(), 1);
    }

    #[test]
    fn resizing_budget_evicts_oldest_partial_trains_without_resetting_table() {
        let base = Instant::now();
        let mut first_context = context(40 * 1024);
        first_context.train_id = 10;
        let mut second_context = first_context;
        second_context.train_id = 11;
        let first = build_packet_train(
            first_context,
            [TrainRecord {
                record_id: 1,
                metadata: Bytes::new(),
                data: Bytes::from(vec![1; 60 * 1024]),
            }],
        )
        .unwrap();
        let second = build_packet_train(
            second_context,
            [TrainRecord {
                record_id: 1,
                metadata: Bytes::new(),
                data: Bytes::from(vec![2; 60 * 1024]),
            }],
        )
        .unwrap();
        let mut table = ReassemblyTableV2::new(table_limits()).unwrap();
        table.accept_at(first.cells[0].clone(), base).unwrap();
        table
            .accept_at(second.cells[0].clone(), base + Duration::from_millis(1))
            .unwrap();
        let limit = MAX_RECORD_BYTES;

        assert_eq!(table.set_maximum_buffered_bytes(limit).unwrap(), 1);
        assert_eq!(table.maximum_buffered_bytes(), limit);
        assert_eq!(table.active_trains(), 1);
        assert!(table.buffered_bytes() <= limit);
        assert!(
            table
                .accept_at(second.cells[0].clone(), base)
                .unwrap()
                .duplicate_cell
        );
    }

    #[test]
    fn admission_pressure_sheds_oldest_train_without_stopping_session() {
        let base = Instant::now();
        let mut first_context = context(40 * 1024);
        first_context.train_id = 20;
        let mut second_context = first_context;
        second_context.train_id = 21;
        let record = |byte: u8| TrainRecord {
            record_id: 1,
            metadata: Bytes::new(),
            data: Bytes::from(vec![byte; 60 * 1024]),
        };
        let first = build_packet_train(first_context, [record(1)]).unwrap();
        let second = build_packet_train(second_context, [record(2)]).unwrap();
        let mut constrained = table_limits();
        constrained.maximum_buffered_bytes = MAX_RECORD_BYTES;
        let mut table = ReassemblyTableV2::new(constrained).unwrap();

        table.accept_at(first.cells[0].clone(), base).unwrap();
        let output = table
            .accept_at(second.cells[0].clone(), base + Duration::from_millis(1))
            .unwrap();

        assert_eq!(output.pressure_evicted_trains, 1);
        assert_eq!(table.active_trains(), 1);
        assert!(table.buffered_bytes() <= MAX_RECORD_BYTES);
    }
}

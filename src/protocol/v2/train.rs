use std::collections::HashSet;

use anyhow::{Result, ensure};
use bytes::Bytes;

use super::cell::{
    CellBody, CellV2, FLAG_TRAIN_END, FLAG_TRAIN_START, HEADER_LEN, MAX_CELL_BYTES,
    MAX_METADATA_BYTES, MAX_RECORD_BYTES, MAX_SEGMENTS_PER_CELL, RecordSegment, SEGMENT_HEADER_LEN,
    SegmentKind, TrafficClass,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrainRecord {
    pub record_id: u16,
    pub metadata: Bytes,
    pub data: Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrainContext {
    pub class: TrafficClass,
    pub session_epoch: u32,
    pub route_label: u32,
    pub overlay_hop_limit: u8,
    pub train_id: u64,
    pub maximum_datagram_size: usize,
    pub maximum_cells: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TrainBuildStats {
    pub records: u64,
    pub record_bytes: u64,
    pub metadata_bytes: u64,
    pub split_records: u64,
    pub cells: u64,
    pub full_payload_cells: u64,
    pub cell_payload_bytes: u64,
    pub cell_wire_bytes: u64,
    pub unused_payload_capacity: u64,
    pub fec_stripes: u64,
    pub fec_protected_data_cells: u64,
    pub fec_parity_cells: u64,
    pub fec_encode_copy_bytes: u64,
    pub fec_unprotected_tail_cells: u64,
}

impl TrainBuildStats {
    pub fn data_utilization(self) -> f64 {
        let capacity = self
            .cell_payload_bytes
            .saturating_add(self.unused_payload_capacity);
        if capacity == 0 {
            return 0.0;
        }
        self.record_bytes as f64 / capacity as f64
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketTrain {
    pub cells: Vec<CellV2>,
    pub stats: TrainBuildStats,
}

/// Reuses the small segment descriptor vectors owned by locally-originated
/// data Cells. A Bulk GSO record commonly produces about fifty one-segment
/// Cells, so allocating and freeing one `Vec<RecordSegment>` per Cell costs
/// more CPU than the descriptor work itself.
#[derive(Debug)]
pub(crate) struct SegmentBufferPool {
    buffers: Vec<Vec<RecordSegment>>,
}

impl Default for SegmentBufferPool {
    fn default() -> Self {
        Self {
            buffers: Vec::with_capacity(64),
        }
    }
}

impl SegmentBufferPool {
    const MAX_BUFFERS: usize = 256;
    const INITIAL_SEGMENTS: usize = 2;

    fn take(&mut self) -> Vec<RecordSegment> {
        self.buffers
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(Self::INITIAL_SEGMENTS))
    }

    pub(crate) fn recycle(&mut self, mut buffer: Vec<RecordSegment>) {
        buffer.clear();
        if self.buffers.len() < Self::MAX_BUFFERS && buffer.capacity() <= MAX_SEGMENTS_PER_CELL {
            self.buffers.push(buffer);
        }
    }

    #[cfg(test)]
    fn available(&self) -> usize {
        self.buffers.len()
    }
}

pub fn build_packet_train(
    context: TrainContext,
    records: impl IntoIterator<Item = TrainRecord>,
) -> Result<PacketTrain> {
    build_packet_train_pooled(context, records, &mut SegmentBufferPool::default())
}

pub(crate) fn build_packet_train_pooled(
    context: TrainContext,
    records: impl IntoIterator<Item = TrainRecord>,
    segment_pool: &mut SegmentBufferPool,
) -> Result<PacketTrain> {
    validate_context(context)?;
    let payload_capacity = context.maximum_datagram_size - HEADER_LEN;
    let mut records = records.into_iter().peekable();
    ensure!(
        records.peek().is_some(),
        "cannot build an empty V2 packet train"
    );
    let record_capacity = records.size_hint().1.unwrap_or(records.size_hint().0);

    // The common Bulk/GSO train contains one record. Defer the duplicate-ID
    // table until a second record actually arrives, avoiding one allocation
    // per train without weakening validation for multi-record trains.
    let mut first_record_id = None;
    let mut ids = None::<HashSet<u16>>;
    let mut cells = Vec::new();
    let mut current = segment_pool.take();
    let mut used = 0_usize;
    let mut stats = TrainBuildStats::default();

    for record in records {
        validate_record(&record, payload_capacity)?;
        if let Some(first) = first_record_id {
            let ids = ids.get_or_insert_with(|| {
                let mut ids = HashSet::with_capacity(record_capacity.max(2));
                ids.insert(first);
                ids
            });
            ensure!(
                ids.insert(record.record_id),
                "duplicate record id {} in V2 packet train",
                record.record_id
            );
        } else {
            first_record_id = Some(record.record_id);
        }
        stats.records += 1;
        stats.record_bytes = stats.record_bytes.saturating_add(record.data.len() as u64);
        stats.metadata_bytes = stats
            .metadata_bytes
            .saturating_add(record.metadata.len() as u64);

        let total_len = record.data.len() as u32;
        // Reserve the Cell descriptor array once from the known record size.
        // Each new Cell needs one segment header, so this is a conservative
        // upper estimate even when the current Cell is partially occupied.
        let data_per_empty_cell = payload_capacity - SEGMENT_HEADER_LEN;
        let estimated_cells = record.data.len().div_ceil(data_per_empty_cell) + 1;
        cells.reserve(estimated_cells.min(context.maximum_cells.saturating_sub(cells.len())));
        let mut offset = 0_usize;
        let mut segment_count = 0_u64;
        while offset < record.data.len() {
            if current.len() == MAX_SEGMENTS_PER_CELL {
                finish_cell(
                    context,
                    &mut cells,
                    &mut current,
                    &mut used,
                    payload_capacity,
                    &mut stats,
                    segment_pool,
                )?;
            }

            let metadata_len = if offset == 0 {
                record.metadata.len()
            } else {
                0
            };
            let fixed = SEGMENT_HEADER_LEN + metadata_len;
            if payload_capacity.saturating_sub(used) <= fixed {
                finish_cell(
                    context,
                    &mut cells,
                    &mut current,
                    &mut used,
                    payload_capacity,
                    &mut stats,
                    segment_pool,
                )?;
            }
            let available = payload_capacity - used - fixed;
            let remaining = record.data.len() - offset;
            let take = available.min(remaining);
            ensure!(take > 0, "V2 train builder made no record progress");
            let end = offset + take;
            let kind = match (offset == 0, end == record.data.len()) {
                (true, true) => SegmentKind::Full,
                (true, false) => SegmentKind::Start,
                (false, true) => SegmentKind::End,
                (false, false) => SegmentKind::Continue,
            };
            current.push(RecordSegment {
                kind,
                flags: 0,
                record_id: record.record_id,
                total_len,
                offset: offset as u32,
                metadata: if offset == 0 {
                    record.metadata.clone()
                } else {
                    Bytes::new()
                },
                data: record.data.slice(offset..end),
            });
            used += fixed + take;
            offset = end;
            segment_count += 1;

            if used == payload_capacity {
                finish_cell(
                    context,
                    &mut cells,
                    &mut current,
                    &mut used,
                    payload_capacity,
                    &mut stats,
                    segment_pool,
                )?;
            }
        }
        if segment_count > 1 {
            stats.split_records += 1;
        }
    }
    if !current.is_empty() {
        finish_cell(
            context,
            &mut cells,
            &mut current,
            &mut used,
            payload_capacity,
            &mut stats,
            segment_pool,
        )?;
    }
    segment_pool.recycle(std::mem::take(&mut current));
    ensure!(!cells.is_empty(), "V2 packet train produced no cells");
    cells[0].flags |= FLAG_TRAIN_START;
    cells.last_mut().expect("checked non-empty").flags |= FLAG_TRAIN_END;

    Ok(PacketTrain { cells, stats })
}

fn validate_context(context: TrainContext) -> Result<()> {
    ensure!(
        (HEADER_LEN + SEGMENT_HEADER_LEN + 1..=MAX_CELL_BYTES)
            .contains(&context.maximum_datagram_size),
        "invalid V2 packet train datagram limit"
    );
    ensure!(
        (1..=u16::MAX as usize).contains(&context.maximum_cells),
        "invalid V2 packet train cell limit"
    );
    ensure!(
        context.session_epoch != 0,
        "V2 session epoch zero is reserved"
    );
    ensure!(context.route_label != 0, "V2 route label zero is reserved");
    ensure!(
        context.overlay_hop_limit != 0,
        "V2 overlay hop limit is exhausted"
    );
    ensure!(context.train_id != 0, "V2 train id zero is reserved");
    Ok(())
}

fn validate_record(record: &TrainRecord, payload_capacity: usize) -> Result<()> {
    ensure!(record.record_id != 0, "V2 record id zero is reserved");
    ensure!(
        !record.data.is_empty() && record.data.len() <= MAX_RECORD_BYTES,
        "invalid V2 packet train record length"
    );
    ensure!(
        record.metadata.len() <= MAX_METADATA_BYTES,
        "V2 packet train metadata is too large"
    );
    ensure!(
        SEGMENT_HEADER_LEN + record.metadata.len() < payload_capacity,
        "V2 packet train metadata leaves no payload capacity"
    );
    Ok(())
}

fn finish_cell(
    context: TrainContext,
    cells: &mut Vec<CellV2>,
    current: &mut Vec<RecordSegment>,
    used: &mut usize,
    payload_capacity: usize,
    stats: &mut TrainBuildStats,
    segment_pool: &mut SegmentBufferPool,
) -> Result<()> {
    ensure!(!current.is_empty(), "cannot finish an empty V2 data cell");
    ensure!(
        cells.len() < context.maximum_cells,
        "V2 packet train exceeds negotiated cell limit"
    );
    ensure!(*used <= payload_capacity, "V2 packet train cell overflow");
    // The builder already knows the exact encoded payload length. Computing
    // statistics here avoids allocating and copying a complete throwaway Cell
    // before the scheduler performs the one real wire encoding.
    stats.cells += 1;
    stats.full_payload_cells = stats
        .full_payload_cells
        .saturating_add(u64::from(*used == payload_capacity));
    stats.cell_payload_bytes = stats.cell_payload_bytes.saturating_add(*used as u64);
    stats.cell_wire_bytes = stats
        .cell_wire_bytes
        .saturating_add((HEADER_LEN + *used) as u64);
    stats.unused_payload_capacity = stats
        .unused_payload_capacity
        .saturating_add((payload_capacity - *used) as u64);
    let sequence = u16::try_from(cells.len())
        .map_err(|_| anyhow::anyhow!("V2 packet train sequence overflow"))?;
    cells.push(CellV2 {
        class: context.class,
        flags: 0,
        session_epoch: context.session_epoch,
        route_label: context.route_label,
        train_id: context.train_id,
        cell_sequence: sequence,
        stripe_id: 0,
        overlay_hop_limit: context.overlay_hop_limit,
        overlay_hops: 0,
        body: CellBody::Records(std::mem::replace(current, segment_pool.take())),
    });
    *used = 0;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn forty_four_mtu_records_are_continuously_packed() {
        let records = (1..=44)
            .map(|record_id| TrainRecord {
                record_id,
                metadata: Bytes::new(),
                data: Bytes::from(vec![record_id as u8; 1500]),
            })
            .collect::<Vec<_>>();
        let train = build_packet_train(context(1382), records).unwrap();
        assert!(train.cells.len() <= 51, "cells={}", train.cells.len());
        assert_eq!(train.stats.records, 44);
        assert_eq!(train.stats.record_bytes, 66_000);
        assert_eq!(train.stats.split_records, 44);
        assert!(train.stats.data_utilization() >= 0.95);
        assert!(
            train.stats.full_payload_cells * 2 > train.stats.cells,
            "full={} cells={}",
            train.stats.full_payload_cells,
            train.stats.cells
        );
        assert_eq!(train.cells[0].flags, FLAG_TRAIN_START);
        assert_eq!(train.cells.last().unwrap().flags, FLAG_TRAIN_END);
    }

    #[test]
    fn an_end_segment_and_next_record_share_the_same_cell() {
        let train = build_packet_train(
            context(100),
            [
                TrainRecord {
                    record_id: 1,
                    metadata: Bytes::new(),
                    data: Bytes::from(vec![1; 60]),
                },
                TrainRecord {
                    record_id: 2,
                    metadata: Bytes::new(),
                    data: Bytes::from(vec![2; 10]),
                },
            ],
        )
        .unwrap();
        assert_eq!(train.cells.len(), 2);
        let CellBody::Records(second) = &train.cells[1].body else {
            panic!("expected data cell");
        };
        assert_eq!(second.len(), 2);
        assert_eq!(second[0].kind, SegmentKind::End);
        assert_eq!(second[1].kind, SegmentKind::Full);
    }

    #[test]
    fn record_data_is_reassembled_from_zero_copy_segments() {
        let source = Bytes::from((0..=254).cycle().take(4000).collect::<Vec<_>>());
        let train = build_packet_train(
            context(512),
            [TrainRecord {
                record_id: 1,
                metadata: Bytes::from_static(b"meta"),
                data: source.clone(),
            }],
        )
        .unwrap();
        let mut rebuilt = Vec::new();
        for cell in train.cells {
            let CellBody::Records(segments) = cell.body else {
                panic!("expected data cell");
            };
            for segment in segments {
                rebuilt.extend_from_slice(&segment.data);
            }
        }
        assert_eq!(rebuilt, source);
    }

    #[test]
    fn segment_descriptor_buffers_are_reused_across_bulk_trains() {
        let mut pool = SegmentBufferPool::default();
        let make = |train_id| TrainRecord {
            record_id: 1,
            metadata: Bytes::new(),
            data: Bytes::from(vec![train_id as u8; MAX_RECORD_BYTES]),
        };
        let mut first_context = context(1382);
        first_context.train_id = 10;
        let first = build_packet_train_pooled(first_context, [make(10)], &mut pool).unwrap();
        let cell_count = first.cells.len();
        for cell in first.cells {
            let CellBody::Records(segments) = cell.body else {
                panic!("expected data Cell");
            };
            pool.recycle(segments);
        }
        assert!(pool.available() >= cell_count);

        let available = pool.available();
        let mut second_context = first_context;
        second_context.train_id = 11;
        let second = build_packet_train_pooled(second_context, [make(11)], &mut pool).unwrap();
        for cell in second.cells {
            let CellBody::Records(segments) = cell.body else {
                panic!("expected data Cell");
            };
            pool.recycle(segments);
        }
        assert_eq!(pool.available(), available);
    }

    #[test]
    fn duplicate_ids_and_cell_limit_are_rejected() {
        let duplicate = [
            TrainRecord {
                record_id: 1,
                metadata: Bytes::new(),
                data: Bytes::from_static(b"a"),
            },
            TrainRecord {
                record_id: 1,
                metadata: Bytes::new(),
                data: Bytes::from_static(b"b"),
            },
        ];
        assert!(build_packet_train(context(100), duplicate).is_err());

        let mut limited = context(100);
        limited.maximum_cells = 1;
        assert!(
            build_packet_train(
                limited,
                [TrainRecord {
                    record_id: 1,
                    metadata: Bytes::new(),
                    data: Bytes::from(vec![0; 200]),
                }]
            )
            .is_err()
        );
    }
}

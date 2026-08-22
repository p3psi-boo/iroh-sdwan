use anyhow::{Result, ensure};
use bytes::{BufMut, Bytes, BytesMut};

pub const MAGIC: &[u8; 4] = b"ICV2";
pub const HEADER_LEN: usize = 36;
pub const SEGMENT_HEADER_LEN: usize = 16;
pub const MAX_CELL_BYTES: usize = u16::MAX as usize;
pub const MAX_RECORD_BYTES: usize = u16::MAX as usize;
pub const MAX_SEGMENTS_PER_CELL: usize = 64;
pub const MAX_METADATA_BYTES: usize = 256;
pub const DEFAULT_OVERLAY_HOP_LIMIT: u8 = 64;
pub const OVERLAY_HOP_LIMIT_OFFSET: usize = 34;
pub const OVERLAY_HOPS_OFFSET: usize = 35;

pub const FLAG_TRAIN_START: u8 = 1 << 0;
pub const FLAG_TRAIN_END: u8 = 1 << 1;
const KNOWN_FLAGS: u8 = FLAG_TRAIN_START | FLAG_TRAIN_END;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CellKind {
    Data = 1,
    FecParity = 2,
}

impl CellKind {
    fn from_wire(value: u8) -> Result<Self> {
        Ok(match value {
            1 => Self::Data,
            2 => Self::FecParity,
            _ => anyhow::bail!("unknown V2 cell kind {value}"),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TrafficClass {
    Latency = 1,
    Bulk = 2,
}

impl TrafficClass {
    fn from_wire(value: u8) -> Result<Self> {
        Ok(match value {
            1 => Self::Latency,
            2 => Self::Bulk,
            _ => anyhow::bail!("unknown V2 traffic class {value}"),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SegmentKind {
    Full = 1,
    Start = 2,
    Continue = 3,
    End = 4,
}

impl SegmentKind {
    fn from_wire(value: u8) -> Result<Self> {
        Ok(match value {
            1 => Self::Full,
            2 => Self::Start,
            3 => Self::Continue,
            4 => Self::End,
            _ => anyhow::bail!("unknown V2 record segment kind {value}"),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordSegment {
    pub kind: SegmentKind,
    pub flags: u8,
    pub record_id: u16,
    pub total_len: u32,
    pub offset: u32,
    pub metadata: Bytes,
    pub data: Bytes,
}

impl RecordSegment {
    fn validate(&self) -> Result<()> {
        ensure!(self.flags == 0, "unsupported V2 record flags");
        ensure!(self.record_id != 0, "V2 record id zero is reserved");
        ensure!(
            (1..=MAX_RECORD_BYTES as u32).contains(&self.total_len),
            "invalid V2 record length"
        );
        ensure!(!self.data.is_empty(), "empty V2 record segment");
        ensure!(
            self.data.len() <= u16::MAX as usize,
            "V2 record segment data is too large"
        );
        ensure!(
            self.metadata.len() <= MAX_METADATA_BYTES,
            "V2 record metadata is too large"
        );
        let end = self
            .offset
            .checked_add(self.data.len() as u32)
            .ok_or_else(|| anyhow::anyhow!("V2 record segment offset overflow"))?;
        ensure!(end <= self.total_len, "V2 record segment exceeds record");
        match self.kind {
            SegmentKind::Full => {
                ensure!(self.offset == 0, "full V2 record has non-zero offset");
                ensure!(
                    end == self.total_len,
                    "full V2 record does not contain the complete payload"
                );
            }
            SegmentKind::Start => {
                ensure!(self.offset == 0, "start V2 segment has non-zero offset");
                ensure!(end < self.total_len, "start V2 segment completes record");
            }
            SegmentKind::Continue => {
                ensure!(self.offset > 0, "continuation V2 segment has zero offset");
                ensure!(
                    end < self.total_len,
                    "continuation V2 segment completes record"
                );
                ensure!(
                    self.metadata.is_empty(),
                    "continuation V2 segment carries metadata"
                );
            }
            SegmentKind::End => {
                ensure!(self.offset > 0, "end V2 segment has zero offset");
                ensure!(end == self.total_len, "end V2 segment is not final");
                ensure!(self.metadata.is_empty(), "end V2 segment carries metadata");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CellBody {
    Records(Vec<RecordSegment>),
    Parity(Bytes),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellV2 {
    pub class: TrafficClass,
    pub flags: u8,
    pub session_epoch: u32,
    pub route_label: u32,
    pub train_id: u64,
    pub cell_sequence: u16,
    pub stripe_id: u32,
    /// Remaining logical overlay hops. The ingress copies the minimum IP
    /// TTL/Hop-Limit of the records in this train; a transit node decrements
    /// this byte without parsing or reassembling the Cell payload.
    pub overlay_hop_limit: u8,
    /// Number of overlay transit hops already crossed. Together with
    /// `overlay_hop_limit` this preserves the ingress value for OAM/trace.
    pub overlay_hops: u8,
    pub body: CellBody,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CellRouteHeaderV2 {
    pub kind: CellKind,
    pub class: TrafficClass,
    pub session_epoch: u32,
    pub route_label: u32,
    pub train_id: u64,
    pub cell_sequence: u16,
    pub stripe_id: u32,
    pub segment_count: u16,
    pub payload_len: u16,
    pub overlay_hop_limit: u8,
    pub overlay_hops: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardedCellV2 {
    pub bytes: Bytes,
    /// False when the received `Bytes` allocation was uniquely owned and its
    /// routing shim could be changed in place.
    pub copied: bool,
    pub header: CellRouteHeaderV2,
}

impl CellV2 {
    pub fn kind(&self) -> CellKind {
        match self.body {
            CellBody::Records(_) => CellKind::Data,
            CellBody::Parity(_) => CellKind::FecParity,
        }
    }

    pub fn encode(&self, maximum: usize) -> Result<Bytes> {
        let mut out = BytesMut::new();
        self.encode_into(maximum, &mut out)?;
        Ok(out.freeze())
    }

    /// Encode a Cell as a small immutable prefix plus an optional zero-copy
    /// record-data tail. The split form applies only to the common locally
    /// originated one-segment data Cell; parity and multi-segment Cells remain
    /// contiguous so FEC, Repair, and transit mutation keep their exact
    /// current ownership semantics.
    pub(crate) fn encode_datagram_parts_into(
        &self,
        maximum: usize,
        out: &mut BytesMut,
    ) -> Result<(Option<Bytes>, CellRouteHeaderV2)> {
        let header = self.checked_route_header(maximum)?;
        let CellBody::Records(segments) = &self.body else {
            self.encode_contiguous_with_header(out, header);
            return Ok((None, header));
        };
        let [segment] = segments.as_slice() else {
            self.encode_contiguous_with_header(out, header);
            return Ok((None, header));
        };

        let prefix_len = HEADER_LEN + SEGMENT_HEADER_LEN + segment.metadata.len();
        out.clear();
        if out.capacity() < prefix_len {
            out.reserve(prefix_len);
        }
        self.encode_header_into(out, header);
        Self::encode_segment_header_into(out, segment);
        out.extend_from_slice(&segment.metadata);
        debug_assert_eq!(out.len(), prefix_len);
        Ok((Some(segment.data.clone()), header))
    }

    /// Encode into a caller-owned allocation. The scheduler uses this path to
    /// recycle Cell wire buffers after QUIC releases its final `Bytes` clone.
    pub fn encode_into(&self, maximum: usize, out: &mut BytesMut) -> Result<()> {
        let header = self.checked_route_header(maximum)?;
        self.encode_contiguous_with_header(out, header);
        Ok(())
    }

    fn checked_route_header(&self, maximum: usize) -> Result<CellRouteHeaderV2> {
        self.validate()?;
        ensure!(
            (HEADER_LEN + 1..=MAX_CELL_BYTES).contains(&maximum),
            "invalid V2 cell maximum"
        );
        let (segment_count, payload_len) = match &self.body {
            CellBody::Records(segments) => {
                let payload_len = segments.iter().try_fold(0_usize, |total, segment| {
                    total
                        .checked_add(SEGMENT_HEADER_LEN)
                        .and_then(|value| value.checked_add(segment.metadata.len()))
                        .and_then(|value| value.checked_add(segment.data.len()))
                        .ok_or_else(|| anyhow::anyhow!("V2 cell length overflow"))
                })?;
                (segments.len(), payload_len)
            }
            CellBody::Parity(parity) => (0, parity.len()),
        };
        ensure!(
            payload_len <= u16::MAX as usize,
            "V2 cell payload is too large"
        );
        ensure!(
            HEADER_LEN + payload_len <= maximum,
            "V2 cell exceeds negotiated datagram maximum"
        );

        Ok(CellRouteHeaderV2 {
            kind: self.kind(),
            class: self.class,
            session_epoch: self.session_epoch,
            route_label: self.route_label,
            train_id: self.train_id,
            cell_sequence: self.cell_sequence,
            stripe_id: self.stripe_id,
            segment_count: segment_count as u16,
            payload_len: payload_len as u16,
            overlay_hop_limit: self.overlay_hop_limit,
            overlay_hops: self.overlay_hops,
        })
    }

    fn encode_contiguous_with_header(&self, out: &mut BytesMut, header: CellRouteHeaderV2) {
        let wire_len = HEADER_LEN + usize::from(header.payload_len);
        out.clear();
        if out.capacity() < wire_len {
            out.reserve(wire_len);
        }
        self.encode_header_into(out, header);
        match &self.body {
            CellBody::Records(segments) => {
                for segment in segments {
                    Self::encode_segment_header_into(out, segment);
                    out.extend_from_slice(&segment.metadata);
                    out.extend_from_slice(&segment.data);
                }
            }
            CellBody::Parity(parity) => out.extend_from_slice(parity),
        }
        debug_assert_eq!(out.len(), wire_len);
    }

    fn encode_header_into(&self, out: &mut BytesMut, header: CellRouteHeaderV2) {
        out.extend_from_slice(MAGIC);
        out.put_u8(super::MAJOR as u8);
        out.put_u8(header.kind as u8);
        out.put_u8(header.class as u8);
        out.put_u8(self.flags);
        out.put_u32(header.session_epoch);
        out.put_u32(header.route_label);
        out.put_u64(header.train_id);
        out.put_u16(header.cell_sequence);
        out.put_u32(header.stripe_id);
        out.put_u16(header.segment_count);
        out.put_u16(header.payload_len);
        out.put_u8(header.overlay_hop_limit);
        out.put_u8(header.overlay_hops);
        debug_assert_eq!(out.len(), HEADER_LEN);
    }

    fn encode_segment_header_into(out: &mut BytesMut, segment: &RecordSegment) {
        out.put_u8(segment.kind as u8);
        out.put_u8(segment.flags);
        out.put_u16(segment.record_id);
        out.put_u32(segment.total_len);
        out.put_u32(segment.offset);
        out.put_u16(segment.data.len() as u16);
        out.put_u16(segment.metadata.len() as u16);
    }

    pub fn decode(bytes: Bytes) -> Result<Self> {
        Self::decode_reusing(bytes, Vec::new())
    }

    /// Decode while reusing the caller's segment descriptor allocation. The
    /// RX epoch takes this Vec back after reassembly drains it, removing one
    /// malloc/free pair per unstriped QUIC DATAGRAM.
    pub(crate) fn decode_reusing(bytes: Bytes, record_storage: Vec<RecordSegment>) -> Result<Self> {
        let header = CellRouteHeaderV2::decode(&bytes)?;
        Self::decode_reusing_with_header(bytes, record_storage, header)
    }

    /// Decode a Cell whose fixed routing shim was already validated by the
    /// immutable route snapshot. This keeps route admission and payload
    /// reassembly at one fixed-header parse per DATAGRAM.
    pub(crate) fn decode_reusing_with_header(
        bytes: Bytes,
        mut record_storage: Vec<RecordSegment>,
        header: CellRouteHeaderV2,
    ) -> Result<Self> {
        record_storage.clear();
        let segment_count = usize::from(header.segment_count);

        let body = match header.kind {
            CellKind::Data => {
                ensure!(segment_count > 0, "V2 data cell has no records");
                let mut cursor = HEADER_LEN;
                if record_storage.capacity() < segment_count {
                    record_storage.reserve(segment_count - record_storage.len());
                }
                for _ in 0..segment_count {
                    ensure!(
                        cursor + SEGMENT_HEADER_LEN <= bytes.len(),
                        "truncated V2 record segment header"
                    );
                    let segment_kind = SegmentKind::from_wire(bytes[cursor])?;
                    let segment_flags = bytes[cursor + 1];
                    let record_id =
                        u16::from_be_bytes(bytes[cursor + 2..cursor + 4].try_into().unwrap());
                    let total_len =
                        u32::from_be_bytes(bytes[cursor + 4..cursor + 8].try_into().unwrap());
                    let offset =
                        u32::from_be_bytes(bytes[cursor + 8..cursor + 12].try_into().unwrap());
                    let data_len = usize::from(u16::from_be_bytes(
                        bytes[cursor + 12..cursor + 14].try_into().unwrap(),
                    ));
                    let metadata_len = usize::from(u16::from_be_bytes(
                        bytes[cursor + 14..cursor + 16].try_into().unwrap(),
                    ));
                    ensure!(
                        metadata_len <= MAX_METADATA_BYTES,
                        "V2 record metadata is too large"
                    );
                    cursor += SEGMENT_HEADER_LEN;
                    let metadata_end = cursor
                        .checked_add(metadata_len)
                        .ok_or_else(|| anyhow::anyhow!("V2 metadata length overflow"))?;
                    let data_end = metadata_end
                        .checked_add(data_len)
                        .ok_or_else(|| anyhow::anyhow!("V2 data length overflow"))?;
                    ensure!(data_end <= bytes.len(), "truncated V2 record segment");
                    let segment = RecordSegment {
                        kind: segment_kind,
                        flags: segment_flags,
                        record_id,
                        total_len,
                        offset,
                        // Continuation segments normally carry no metadata.
                        // Construct the canonical empty value explicitly so
                        // `Bytes::slice(n..n)` cannot retain/clone the whole
                        // QUIC DATAGRAM allocation merely to represent zero
                        // bytes. A large GSO record has dozens of continuation
                        // Cells, making this the dominant RX clone-avoidance
                        // case rather than a rare micro-optimization.
                        metadata: if metadata_len == 0 {
                            Bytes::new()
                        } else {
                            bytes.slice(cursor..metadata_end)
                        },
                        data: bytes.slice(metadata_end..data_end),
                    };
                    segment.validate()?;
                    record_storage.push(segment);
                    cursor = data_end;
                }
                ensure!(cursor == bytes.len(), "trailing V2 cell payload bytes");
                CellBody::Records(record_storage)
            }
            CellKind::FecParity => {
                ensure!(segment_count == 0, "V2 parity cell contains record headers");
                CellBody::Parity(bytes.slice(HEADER_LEN..))
            }
        };
        let cell = Self {
            class: header.class,
            flags: bytes[7],
            session_epoch: header.session_epoch,
            route_label: header.route_label,
            train_id: header.train_id,
            cell_sequence: header.cell_sequence,
            stripe_id: header.stripe_id,
            overlay_hop_limit: header.overlay_hop_limit,
            overlay_hops: header.overlay_hops,
            body,
        };
        // Segment headers and payload bounds were validated while walking the
        // wire buffer. Re-running `validate()` here rescans every segment on
        // the RX hot path, so only validate the fixed header and the parity
        // invariants that are not covered by that walk.
        if let CellBody::Parity(parity) = &cell.body {
            ensure!(!parity.is_empty(), "empty V2 parity cell");
            ensure!(cell.stripe_id != 0, "V2 parity cell has no stripe id");
            ensure!(cell.flags == 0, "V2 parity cell has train boundary flags");
        }
        Ok(cell)
    }

    /// Recover reusable descriptor storage after the receiver moved all
    /// payload views into partial or completed Record state.
    pub(crate) fn take_record_storage(&mut self) -> Vec<RecordSegment> {
        match &mut self.body {
            CellBody::Records(records) => std::mem::take(records),
            CellBody::Parity(_) => Vec::new(),
        }
    }

    fn validate(&self) -> Result<()> {
        self.validate_header()?;
        match &self.body {
            CellBody::Records(segments) => {
                ensure!(!segments.is_empty(), "V2 data cell has no records");
                ensure!(
                    segments.len() <= MAX_SEGMENTS_PER_CELL,
                    "too many V2 record segments"
                );
                for segment in segments {
                    segment.validate()?;
                }
            }
            CellBody::Parity(parity) => {
                ensure!(!parity.is_empty(), "empty V2 parity cell");
                ensure!(self.stripe_id != 0, "V2 parity cell has no stripe id");
                ensure!(self.flags == 0, "V2 parity cell has train boundary flags");
            }
        }
        Ok(())
    }

    fn validate_header(&self) -> Result<()> {
        ensure!(self.flags & !KNOWN_FLAGS == 0, "unsupported V2 cell flags");
        ensure!(self.session_epoch != 0, "V2 session epoch zero is reserved");
        ensure!(self.route_label != 0, "V2 route label zero is reserved");
        ensure!(self.train_id != 0, "V2 train id zero is reserved");
        ensure!(
            self.overlay_hop_limit != 0,
            "V2 overlay hop limit is exhausted"
        );
        ensure!(
            u16::from(self.overlay_hop_limit) + u16::from(self.overlay_hops) <= u16::from(u8::MAX),
            "invalid V2 overlay hop accounting"
        );
        Ok(())
    }
}

impl CellRouteHeaderV2 {
    /// Parse only the fixed routing shim. Transit forwarding uses this path so
    /// it never allocates record state, scans segment headers, or invokes FEC
    /// and PacketTrain reassembly.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            (HEADER_LEN + 1..=MAX_CELL_BYTES).contains(&bytes.len()),
            "invalid V2 cell length"
        );
        ensure!(&bytes[..4] == MAGIC, "invalid V2 cell magic");
        ensure!(bytes[4] == super::MAJOR as u8, "unsupported V2 cell major");
        let kind = CellKind::from_wire(bytes[5])?;
        let class = TrafficClass::from_wire(bytes[6])?;
        ensure!(bytes[7] & !KNOWN_FLAGS == 0, "unsupported V2 cell flags");
        let session_epoch = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
        let route_label = u32::from_be_bytes(bytes[12..16].try_into().unwrap());
        let train_id = u64::from_be_bytes(bytes[16..24].try_into().unwrap());
        let cell_sequence = u16::from_be_bytes(bytes[24..26].try_into().unwrap());
        let stripe_id = u32::from_be_bytes(bytes[26..30].try_into().unwrap());
        let segment_count = u16::from_be_bytes(bytes[30..32].try_into().unwrap());
        let payload_len = u16::from_be_bytes(bytes[32..34].try_into().unwrap());
        let overlay_hop_limit = bytes[OVERLAY_HOP_LIMIT_OFFSET];
        let overlay_hops = bytes[OVERLAY_HOPS_OFFSET];
        ensure!(session_epoch != 0, "V2 session epoch zero is reserved");
        ensure!(route_label != 0, "V2 route label zero is reserved");
        ensure!(train_id != 0, "V2 train id zero is reserved");
        ensure!(overlay_hop_limit != 0, "V2 overlay hop limit is exhausted");
        ensure!(
            u16::from(overlay_hop_limit) + u16::from(overlay_hops) <= u16::from(u8::MAX),
            "invalid V2 overlay hop accounting"
        );
        ensure!(
            HEADER_LEN + usize::from(payload_len) == bytes.len(),
            "invalid V2 cell payload length"
        );
        ensure!(
            usize::from(segment_count) <= MAX_SEGMENTS_PER_CELL,
            "too many V2 record segments"
        );
        match kind {
            CellKind::Data => ensure!(segment_count != 0, "V2 data cell has no records"),
            CellKind::FecParity => {
                ensure!(segment_count == 0, "V2 parity cell contains record headers")
            }
        }
        Ok(Self {
            kind,
            class,
            session_epoch,
            route_label,
            train_id,
            cell_sequence,
            stripe_id,
            segment_count,
            payload_len,
            overlay_hop_limit,
            overlay_hops,
        })
    }

    pub fn ingress_hop_limit(self) -> u8 {
        self.overlay_hop_limit.saturating_add(self.overlay_hops)
    }
}

/// Advance the fixed routing shim by one overlay transit hop. This attempts an
/// in-place `Bytes` -> `BytesMut` conversion first and copies only when another
/// owner still references the received allocation.
pub fn advance_overlay_hop(bytes: Bytes) -> Result<ForwardedCellV2> {
    let mut header = CellRouteHeaderV2::decode(&bytes)?;
    ensure!(header.overlay_hop_limit > 1, "V2 overlay hop limit expired");
    let (mut bytes, copied) = match bytes.try_into_mut() {
        Ok(bytes) => (bytes, false),
        Err(bytes) => (BytesMut::from(bytes.as_ref()), true),
    };
    header.overlay_hop_limit -= 1;
    header.overlay_hops = header
        .overlay_hops
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("V2 overlay hop count overflow"))?;
    bytes[OVERLAY_HOP_LIMIT_OFFSET] = header.overlay_hop_limit;
    bytes[OVERLAY_HOPS_OFFSET] = header.overlay_hops;
    Ok(ForwardedCellV2 {
        bytes: bytes.freeze(),
        copied,
        header,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cell(body: CellBody) -> CellV2 {
        let flags = if matches!(body, CellBody::Parity(_)) {
            0
        } else {
            FLAG_TRAIN_START | FLAG_TRAIN_END
        };
        CellV2 {
            class: TrafficClass::Bulk,
            flags,
            session_epoch: 7,
            route_label: 11,
            train_id: 13,
            cell_sequence: 0,
            stripe_id: 17,
            overlay_hop_limit: DEFAULT_OVERLAY_HOP_LIMIT,
            overlay_hops: 0,
            body,
        }
    }

    #[test]
    fn cell_round_trips_multiple_records_without_copying_decode_slices() {
        let value = cell(CellBody::Records(vec![
            RecordSegment {
                kind: SegmentKind::Full,
                flags: 0,
                record_id: 1,
                total_len: 4,
                offset: 0,
                metadata: Bytes::from_static(b"meta"),
                data: Bytes::from_static(b"abcd"),
            },
            RecordSegment {
                kind: SegmentKind::Full,
                flags: 0,
                record_id: 2,
                total_len: 3,
                offset: 0,
                metadata: Bytes::new(),
                data: Bytes::from_static(b"xyz"),
            },
        ]));
        let encoded = value.encode(1382).unwrap();
        assert_eq!(CellV2::decode(encoded).unwrap(), value);
    }

    #[test]
    fn split_record_segments_round_trip_independently() {
        let start = cell(CellBody::Records(vec![RecordSegment {
            kind: SegmentKind::Start,
            flags: 0,
            record_id: 9,
            total_len: 10,
            offset: 0,
            metadata: Bytes::from_static(b"gso"),
            data: Bytes::from_static(b"1234"),
        }]));
        let mut end = cell(CellBody::Records(vec![RecordSegment {
            kind: SegmentKind::End,
            flags: 0,
            record_id: 9,
            total_len: 10,
            offset: 4,
            metadata: Bytes::new(),
            data: Bytes::from_static(b"567890"),
        }]));
        end.cell_sequence = 1;
        assert_eq!(CellV2::decode(start.encode(1382).unwrap()).unwrap(), start);
        assert_eq!(CellV2::decode(end.encode(1382).unwrap()).unwrap(), end);
    }

    #[test]
    fn one_segment_datagram_parts_match_contiguous_wire_encoding() {
        let value = cell(CellBody::Records(vec![RecordSegment {
            kind: SegmentKind::Full,
            flags: 0,
            record_id: 3,
            total_len: 12,
            offset: 0,
            metadata: Bytes::from_static(b"meta"),
            data: Bytes::from_static(b"payload-body"),
        }]));
        let contiguous = value.encode(1382).unwrap();
        let mut prefix = BytesMut::new();
        let (tail, header) = value.encode_datagram_parts_into(1382, &mut prefix).unwrap();
        let tail = tail.expect("one-segment data Cell uses split encoding");
        let mut flattened = prefix.to_vec();
        flattened.extend_from_slice(&tail);
        assert_eq!(flattened, contiguous);
        assert_eq!(header, CellRouteHeaderV2::decode(&contiguous).unwrap());
        assert_eq!(prefix.len(), HEADER_LEN + SEGMENT_HEADER_LEN + 4);
    }

    #[test]
    fn parity_cell_round_trips() {
        let value = cell(CellBody::Parity(Bytes::from_static(b"parity")));
        assert_eq!(CellV2::decode(value.encode(1382).unwrap()).unwrap(), value);
    }

    #[test]
    fn decoder_rejects_trailing_payload_and_unknown_flags() {
        let value = cell(CellBody::Parity(Bytes::from_static(b"parity")));
        let encoded = value.encode(1382).unwrap();
        let mut trailing = encoded.to_vec();
        trailing.push(0);
        assert!(CellV2::decode(Bytes::from(trailing)).is_err());

        let mut flags = encoded.to_vec();
        flags[7] = 0x80;
        assert!(CellV2::decode(Bytes::from(flags)).is_err());
    }

    #[test]
    fn record_shape_is_strictly_validated() {
        let invalid = cell(CellBody::Records(vec![RecordSegment {
            kind: SegmentKind::End,
            flags: 0,
            record_id: 1,
            total_len: 8,
            offset: 2,
            metadata: Bytes::new(),
            data: Bytes::from_static(b"abc"),
        }]));
        assert!(invalid.encode(1382).is_err());
    }

    #[test]
    fn negotiated_maximum_is_enforced() {
        let value = cell(CellBody::Records(vec![RecordSegment {
            kind: SegmentKind::Full,
            flags: 0,
            record_id: 1,
            total_len: 8,
            offset: 0,
            metadata: Bytes::new(),
            data: Bytes::from_static(b"12345678"),
        }]));
        assert!(value.encode(HEADER_LEN + SEGMENT_HEADER_LEN + 7).is_err());
    }

    #[test]
    fn encode_into_matches_encode_and_overwrites_reused_storage() {
        let value = cell(CellBody::Records(vec![RecordSegment {
            kind: SegmentKind::Full,
            flags: 0,
            record_id: 1,
            total_len: 8,
            offset: 0,
            metadata: Bytes::from_static(b"meta"),
            data: Bytes::from_static(b"12345678"),
        }]));
        let expected = value.encode(1382).unwrap();
        let mut storage = BytesMut::from(&b"stale trailing bytes that must disappear"[..]);
        value.encode_into(1382, &mut storage).unwrap();
        assert_eq!(storage.as_ref(), expected.as_ref());
    }

    #[test]
    fn routing_shim_advances_without_decoding_records() {
        let value = cell(CellBody::Records(vec![RecordSegment {
            kind: SegmentKind::Full,
            flags: 0,
            record_id: 1,
            total_len: 3,
            offset: 0,
            metadata: Bytes::new(),
            data: Bytes::from_static(b"abc"),
        }]));
        let encoded = value.encode(1382).unwrap();
        let advanced = advance_overlay_hop(encoded).unwrap();
        assert!(!advanced.copied);
        assert_eq!(advanced.header.overlay_hop_limit, 63);
        assert_eq!(advanced.header.overlay_hops, 1);
        let decoded = CellV2::decode(advanced.bytes).unwrap();
        assert_eq!(decoded.overlay_hop_limit, 63);
        assert_eq!(decoded.overlay_hops, 1);
    }

    #[test]
    fn routing_shim_expires_and_copies_shared_storage() {
        let mut value = cell(CellBody::Parity(Bytes::from_static(b"parity")));
        value.overlay_hop_limit = 1;
        let encoded = value.encode(1382).unwrap();
        assert!(advance_overlay_hop(encoded).is_err());

        value.overlay_hop_limit = 4;
        let encoded = value.encode(1382).unwrap();
        let shared = encoded.clone();
        let advanced = advance_overlay_hop(encoded).unwrap();
        assert!(advanced.copied);
        assert_eq!(shared[OVERLAY_HOP_LIMIT_OFFSET], 4);
        assert_eq!(advanced.bytes[OVERLAY_HOP_LIMIT_OFFSET], 3);
    }
}

//! Process-wide payload accounting and TUN/overlay buffer ownership.
//!
//! Queue, reassembly, repair, and FEC-decode reservations share one budget so
//! four independent 64 MiB caps cannot stack. Packet buffers keep a payload
//! offset so encode/TUN write can patch headers in unused prefix bytes.

use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use bytes::{Bytes, BytesMut};

/// Combined process-wide cap for outbound queues, fragment reassembly,
/// selective repair, and FEC decode. Not four independent 64 MiB pools.
pub const PROCESS_PAYLOAD_BUDGET_BYTES: usize = 64 * 1024 * 1024;
pub const DEFAULT_QUEUE_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_REASSEMBLY_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_REPAIR_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_FEC_DECODE_BYTES: usize = 8 * 1024 * 1024;

/// Bytes reserved in front of an IP payload for overlay headers.
/// envelope (12) + fragment (16) + delivery tag (12).
pub const OVERLAY_HEADER_HEADROOM: usize = 12 + 16 + 12;
pub const SMALL_TUN_SLOT: usize = 4 * 1024;
pub const LARGE_TUN_SLOT: usize = u16::MAX as usize;
const LARGE_SLOT_COUNT: usize = 16;

#[derive(Debug)]
pub struct BufferBudget {
    used: AtomicU64,
    max: u64,
}

impl BufferBudget {
    pub fn process_wide() -> Arc<Self> {
        static BUDGET: std::sync::OnceLock<Arc<BufferBudget>> = std::sync::OnceLock::new();
        BUDGET
            .get_or_init(|| BufferBudget::new(PROCESS_PAYLOAD_BUDGET_BYTES))
            .clone()
    }

    pub fn new(max: usize) -> Arc<Self> {
        Arc::new(Self {
            used: AtomicU64::new(0),
            max: max.max(1) as u64,
        })
    }

    pub fn try_reserve(&self, bytes: usize) -> bool {
        if bytes == 0 {
            return true;
        }
        let add = bytes as u64;
        let mut current = self.used.load(Ordering::Relaxed);
        loop {
            if current.saturating_add(add) > self.max {
                return false;
            }
            match self.used.compare_exchange_weak(
                current,
                current + add,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    pub fn release(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        self.used
            .fetch_sub((bytes as u64).min(self.used.load(Ordering::Relaxed)), Ordering::AcqRel);
    }

    pub fn used(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }

    pub fn max(&self) -> u64 {
        self.max
    }
}

/// IP packet sitting in an allocation that may still have unused prefix bytes.
#[derive(Debug, Clone)]
pub struct DataplaneBuf {
    buf: Bytes,
    offset: usize,
}

impl DataplaneBuf {
    pub fn from_bytes(buf: Bytes) -> Self {
        Self { buf, offset: 0 }
    }

    pub fn from_vec(buf: Vec<u8>) -> Self {
        Self {
            buf: Bytes::from(buf),
            offset: 0,
        }
    }

    pub fn from_static(bytes: &'static [u8]) -> Self {
        Self {
            buf: Bytes::from_static(bytes),
            offset: 0,
        }
    }

    pub fn from_pooled(buf: Bytes, offset: usize) -> Self {
        debug_assert!(offset <= buf.len());
        Self { buf, offset }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf[self.offset..]
    }

    pub fn len(&self) -> usize {
        self.buf.len().saturating_sub(self.offset)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn payload_offset(&self) -> usize {
        self.offset
    }

    pub fn into_payload_bytes(self) -> Bytes {
        self.buf.slice(self.offset..)
    }

    pub fn payload_bytes(&self) -> Bytes {
        self.buf.slice(self.offset..)
    }

    pub fn can_prepend(&self, header_len: usize) -> bool {
        self.offset >= header_len
    }

    /// Write `header` into unused prefix and return a contiguous `Bytes`
    /// covering header+payload without copying the payload. Fails when the
    /// allocation is shared or the prefix is too small.
    pub fn try_prepend(self, header: &[u8]) -> Result<Bytes, Self> {
        if header.is_empty() {
            return Ok(self.buf.slice(self.offset..));
        }
        if self.offset < header.len() {
            return Err(self);
        }
        let start = self.offset - header.len();
        let mut unique = match self.buf.try_into_mut() {
            Ok(buf) => buf,
            Err(buf) => {
                return Err(Self {
                    buf,
                    offset: self.offset,
                });
            }
        };
        unique[start..self.offset].copy_from_slice(header);
        Ok(unique.freeze().slice(start..))
    }

    pub fn try_map_payload<E>(
        &mut self,
        update: impl FnOnce(&mut [u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        let buf = std::mem::replace(&mut self.buf, Bytes::new());
        match buf.try_into_mut() {
            Ok(mut unique) => {
                let result = update(&mut unique[self.offset..]);
                self.buf = unique.freeze();
                result
            }
            Err(buf) => {
                let mut copy = buf[self.offset..].to_vec();
                let result = update(&mut copy);
                self.buf = Bytes::from(copy);
                self.offset = 0;
                result
            }
        }
    }

    /// Copy payload into a new allocation that already contains `header`.
    pub fn copy_with_prefix(&self, header: &[u8]) -> Bytes {
        let mut out = BytesMut::with_capacity(header.len() + self.len());
        out.extend_from_slice(header);
        out.extend_from_slice(self.as_slice());
        out.freeze()
    }
}

impl AsRef<[u8]> for DataplaneBuf {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl From<Bytes> for DataplaneBuf {
    fn from(buf: Bytes) -> Self {
        Self::from_bytes(buf)
    }
}

impl From<Vec<u8>> for DataplaneBuf {
    fn from(buf: Vec<u8>) -> Self {
        Self::from_vec(buf)
    }
}

/// Mixed-size TUN read slots: a few 64 KiB GSO holders and many 4 KiB slots.
#[derive(Debug)]
pub struct PacketSlotPool {
    small: Vec<BytesMut>,
    large: Vec<BytesMut>,
    headroom: usize,
    small_payload: usize,
    large_payload: usize,
}

impl PacketSlotPool {
    pub fn new(batch: usize, headroom: usize) -> Self {
        let large_count = batch.min(LARGE_SLOT_COUNT).max(1);
        let small_count = batch.saturating_sub(large_count);
        Self {
            small: (0..small_count)
                .map(|_| BytesMut::zeroed(headroom + SMALL_TUN_SLOT))
                .collect(),
            large: (0..large_count)
                .map(|_| BytesMut::zeroed(headroom + LARGE_TUN_SLOT))
                .collect(),
            headroom,
            small_payload: SMALL_TUN_SLOT,
            large_payload: LARGE_TUN_SLOT,
        }
    }

    pub fn headroom(&self) -> usize {
        self.headroom
    }

    pub fn slot_count(&self) -> usize {
        self.small.len() + self.large.len()
    }

    pub fn large_slot_count(&self) -> usize {
        self.large.len()
    }

    pub fn small_slot_count(&self) -> usize {
        self.small.len()
    }

    pub fn slot_payload_capacity(&self, index: usize) -> usize {
        if index < self.large.len() {
            self.large_payload
        } else {
            self.small_payload
        }
    }

    /// Large slots first so a 64 KiB GSO_NONE packet always lands in bufs[0].
    pub fn fill_batch<'a>(&'a mut self, dest: &mut Vec<&'a mut BytesMut>) {
        dest.clear();
        for slot in &mut self.large {
            dest.push(slot);
        }
        for slot in &mut self.small {
            dest.push(slot);
        }
    }

    pub fn take(&mut self, index: usize, payload_len: usize) -> DataplaneBuf {
        let slot = if index < self.large.len() {
            &mut self.large[index]
        } else {
            &mut self.small[index - self.large.len()]
        };
        let total = self.headroom + payload_len;
        if slot.len() < total {
            slot.resize(total, 0);
        }
        let mut taken = std::mem::replace(
            slot,
            BytesMut::zeroed(self.headroom + self.slot_payload_capacity(index)),
        );
        taken.truncate(total);
        DataplaneBuf::from_pooled(taken.freeze(), self.headroom)
    }

    pub fn recycle_empty(&mut self, index: usize) {
        let cap = self.headroom + self.slot_payload_capacity(index);
        let slot = if index < self.large.len() {
            &mut self.large[index]
        } else {
            &mut self.small[index - self.large.len()]
        };
        if slot.capacity() < cap {
            *slot = BytesMut::zeroed(cap);
        } else {
            slot.resize(cap, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budget_is_shared_and_hard_capped() {
        let budget = BufferBudget::new(1_000);
        assert!(budget.try_reserve(600));
        assert!(budget.try_reserve(400));
        assert!(!budget.try_reserve(1));
        budget.release(400);
        assert!(budget.try_reserve(400));
        assert_eq!(budget.used(), 1_000);
    }

    #[test]
    fn prepend_reuses_unique_prefix_without_payload_copy() {
        let mut raw = BytesMut::zeroed(OVERLAY_HEADER_HEADROOM + 8);
        raw[OVERLAY_HEADER_HEADROOM..].copy_from_slice(b"abcdefgh");
        let buf = DataplaneBuf::from_pooled(raw.freeze(), OVERLAY_HEADER_HEADROOM);
        let header = [7_u8; 12];
        let sealed = buf.try_prepend(&header).expect("unique prefix");
        assert_eq!(&sealed[..12], &header);
        assert_eq!(&sealed[12..], b"abcdefgh");
    }

    #[test]
    fn prepend_fails_when_buffer_is_shared() {
        let mut raw = BytesMut::zeroed(OVERLAY_HEADER_HEADROOM + 4);
        raw[OVERLAY_HEADER_HEADROOM..].copy_from_slice(b"data");
        let frozen = raw.freeze();
        let _hold = frozen.clone();
        let buf = DataplaneBuf::from_pooled(frozen, OVERLAY_HEADER_HEADROOM);
        assert!(buf.try_prepend(&[1, 2, 3, 4]).is_err());
    }

    #[test]
    fn tun_pool_keeps_mixed_slot_sizes() {
        let pool = PacketSlotPool::new(128, OVERLAY_HEADER_HEADROOM);
        assert_eq!(pool.slot_count(), 128);
        assert_eq!(pool.large_slot_count(), LARGE_SLOT_COUNT);
        assert_eq!(pool.slot_payload_capacity(0), LARGE_TUN_SLOT);
        assert_eq!(
            pool.slot_payload_capacity(LARGE_SLOT_COUNT),
            SMALL_TUN_SLOT
        );
        assert!(pool.large_slot_count() * LARGE_TUN_SLOT < 128 * LARGE_TUN_SLOT);
    }
}

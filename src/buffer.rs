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
use crossbeam_channel::{Receiver, Sender, unbounded};

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

/// RAII reservation against a [`BufferBudget`]. Keeping the reservation beside
/// the allocation makes cancellation, queue destruction and task abortion
/// release accounting automatically.
#[derive(Debug)]
pub struct BufferPermit {
    budget: Arc<BufferBudget>,
    bytes: usize,
}

impl Drop for BufferPermit {
    fn drop(&mut self) {
        self.budget.release(self.bytes);
    }
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

    fn try_reserve(&self, bytes: usize) -> bool {
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

    pub fn try_acquire(self: &Arc<Self>, bytes: usize) -> Option<BufferPermit> {
        self.try_reserve(bytes).then(|| BufferPermit {
            budget: self.clone(),
            bytes,
        })
    }

    fn release(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let previous = self.used.fetch_sub(bytes as u64, Ordering::AcqRel);
        debug_assert!(previous >= bytes as u64, "buffer budget underflow");
    }

    pub fn used(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }

    pub fn max(&self) -> u64 {
        self.max
    }
}

#[derive(Debug)]
struct RecyclingBuffer {
    buf: BytesMut,
    recycler: Option<Sender<BytesMut>>,
}

impl RecyclingBuffer {
    fn freeze(mut self) -> Bytes {
        let owner = FrozenRecyclingBuffer {
            buf: std::mem::take(&mut self.buf),
            recycler: self.recycler.take(),
        };
        Bytes::from_owner(owner)
    }
}

impl Drop for RecyclingBuffer {
    fn drop(&mut self) {
        if let Some(recycler) = self.recycler.take() {
            let _ = recycler.send(std::mem::take(&mut self.buf));
        }
    }
}

#[derive(Debug)]
struct FrozenRecyclingBuffer {
    buf: BytesMut,
    recycler: Option<Sender<BytesMut>>,
}

impl AsRef<[u8]> for FrozenRecyclingBuffer {
    fn as_ref(&self) -> &[u8] {
        &self.buf
    }
}

impl Drop for FrozenRecyclingBuffer {
    fn drop(&mut self) {
        if let Some(recycler) = self.recycler.take() {
            let _ = recycler.send(std::mem::take(&mut self.buf));
        }
    }
}

#[derive(Debug)]
enum BufferStorage {
    Frozen(Bytes),
    Recycling(RecyclingBuffer),
}

impl BufferStorage {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Frozen(buf) => buf,
            Self::Recycling(buf) => &buf.buf,
        }
    }
}

/// IP packet sitting in an allocation that may still have unused prefix bytes.
/// TUN-owned allocations carry a recycler through every zero-copy `Bytes`
/// slice and return to the queue-local slab after the final reference drops.
#[derive(Debug)]
pub struct DataplaneBuf {
    storage: BufferStorage,
    offset: usize,
}

impl Clone for DataplaneBuf {
    fn clone(&self) -> Self {
        match &self.storage {
            BufferStorage::Frozen(buf) => Self {
                storage: BufferStorage::Frozen(buf.clone()),
                offset: self.offset,
            },
            // Cloning a live mutable TUN slot is exceptional. Keep the
            // original recyclable and detach only the requested clone.
            BufferStorage::Recycling(buf) => Self {
                storage: BufferStorage::Frozen(Bytes::copy_from_slice(&buf.buf)),
                offset: self.offset,
            },
        }
    }
}

impl Default for DataplaneBuf {
    fn default() -> Self {
        Self::from_bytes(Bytes::new())
    }
}

impl DataplaneBuf {
    pub fn from_bytes(buf: Bytes) -> Self {
        Self {
            storage: BufferStorage::Frozen(buf),
            offset: 0,
        }
    }

    pub fn from_vec(buf: Vec<u8>) -> Self {
        Self {
            storage: BufferStorage::Frozen(Bytes::from(buf)),
            offset: 0,
        }
    }

    pub fn from_static(bytes: &'static [u8]) -> Self {
        Self {
            storage: BufferStorage::Frozen(Bytes::from_static(bytes)),
            offset: 0,
        }
    }

    pub fn from_pooled(buf: Bytes, offset: usize) -> Self {
        debug_assert!(offset <= buf.len());
        Self {
            storage: BufferStorage::Frozen(buf),
            offset,
        }
    }

    fn from_recycling(buf: BytesMut, offset: usize, recycler: Sender<BytesMut>) -> Self {
        debug_assert!(offset <= buf.len());
        Self {
            storage: BufferStorage::Recycling(RecyclingBuffer {
                buf,
                recycler: Some(recycler),
            }),
            offset,
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.storage.as_slice()[self.offset..]
    }

    pub fn len(&self) -> usize {
        self.storage.as_slice().len().saturating_sub(self.offset)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn payload_offset(&self) -> usize {
        self.offset
    }

    pub fn can_prepend(&self, header_len: usize) -> bool {
        self.offset >= header_len
    }

    /// Write `header` into unused prefix and return a contiguous `Bytes`
    /// covering header+payload without copying the payload. Fails when the
    /// allocation is shared or the prefix is too small.
    pub fn try_prepend(self, header: &[u8]) -> Result<Bytes, Self> {
        if self.offset < header.len() {
            return Err(self);
        }
        let start = self.offset - header.len();
        match self.storage {
            BufferStorage::Frozen(buf) => {
                if header.is_empty() {
                    return Ok(buf.slice(self.offset..));
                }
                let mut unique = match buf.try_into_mut() {
                    Ok(buf) => buf,
                    Err(buf) => {
                        return Err(Self {
                            storage: BufferStorage::Frozen(buf),
                            offset: self.offset,
                        });
                    }
                };
                unique[start..self.offset].copy_from_slice(header);
                Ok(unique.freeze().slice(start..))
            }
            BufferStorage::Recycling(mut buf) => {
                buf.buf[start..self.offset].copy_from_slice(header);
                Ok(buf.freeze().slice(start..))
            }
        }
    }

    pub fn try_map_payload<E>(
        &mut self,
        update: impl FnOnce(&mut [u8]) -> Result<(), E>,
    ) -> Result<(), E> {
        match &mut self.storage {
            BufferStorage::Recycling(buf) => update(&mut buf.buf[self.offset..]),
            BufferStorage::Frozen(_) => {
                let storage =
                    std::mem::replace(&mut self.storage, BufferStorage::Frozen(Bytes::new()));
                let BufferStorage::Frozen(buf) = storage else {
                    unreachable!();
                };
                match buf.try_into_mut() {
                    Ok(mut unique) => {
                        let result = update(&mut unique[self.offset..]);
                        self.storage = BufferStorage::Frozen(unique.freeze());
                        result
                    }
                    Err(buf) => {
                        let mut copy = BytesMut::from(&buf[self.offset..]);
                        let result = update(&mut copy);
                        self.storage = BufferStorage::Frozen(copy.freeze());
                        self.offset = 0;
                        result
                    }
                }
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
    slots: Vec<BytesMut>,
    free_small: Vec<BytesMut>,
    free_large: Vec<BytesMut>,
    recycle_tx: Sender<BytesMut>,
    recycle_rx: Receiver<BytesMut>,
    large_count: usize,
    headroom: usize,
    small_payload: usize,
    large_payload: usize,
}

impl PacketSlotPool {
    pub fn new(batch: usize, headroom: usize) -> Self {
        Self::with_small_payload(batch, headroom, SMALL_TUN_SLOT)
    }

    pub fn with_small_payload(batch: usize, headroom: usize, small_payload: usize) -> Self {
        let large_count = batch.clamp(1, LARGE_SLOT_COUNT);
        let small_count = batch.saturating_sub(large_count);
        let small_payload = small_payload.clamp(SMALL_TUN_SLOT, LARGE_TUN_SLOT);
        let (recycle_tx, recycle_rx) = unbounded();
        let mut slots = Vec::with_capacity(batch);
        slots.extend((0..large_count).map(|_| BytesMut::zeroed(headroom + LARGE_TUN_SLOT)));
        slots.extend((0..small_count).map(|_| BytesMut::zeroed(headroom + small_payload)));
        Self {
            slots,
            free_small: Vec::with_capacity(small_count),
            free_large: Vec::with_capacity(large_count),
            recycle_tx,
            recycle_rx,
            large_count,
            headroom,
            small_payload,
            large_payload: LARGE_TUN_SLOT,
        }
    }

    pub fn headroom(&self) -> usize {
        self.headroom
    }

    pub fn slot_count(&self) -> usize {
        self.slots.len()
    }

    pub fn large_slot_count(&self) -> usize {
        self.large_count
    }

    pub fn small_slot_count(&self) -> usize {
        self.slots.len().saturating_sub(self.large_count)
    }

    pub fn slot_payload_capacity(&self, index: usize) -> usize {
        if index < self.large_count {
            self.large_payload
        } else {
            self.small_payload
        }
    }

    /// Large slots are first so a 64 KiB GSO_NONE packet always lands in slot 0.
    pub fn slots_mut(&mut self) -> &mut [BytesMut] {
        self.drain_recycled();
        &mut self.slots
    }

    pub fn take(&mut self, index: usize, payload_len: usize) -> DataplaneBuf {
        self.drain_recycled();
        let replacement_capacity = self.headroom + self.slot_payload_capacity(index);
        let replacement = if index < self.large_count {
            self.free_large.pop()
        } else {
            self.free_small.pop()
        }
        .map(|mut slot| {
            slot.resize(replacement_capacity, 0);
            slot
        })
        .unwrap_or_else(|| BytesMut::zeroed(replacement_capacity));
        let slot = &mut self.slots[index];
        let total = self.headroom + payload_len;
        if slot.len() < total {
            slot.resize(total, 0);
        }
        let mut taken = std::mem::replace(slot, replacement);
        taken.truncate(total);
        DataplaneBuf::from_recycling(taken, self.headroom, self.recycle_tx.clone())
    }

    pub fn recycle_empty(&mut self, index: usize) {
        self.drain_recycled();
        let cap = self.headroom + self.slot_payload_capacity(index);
        let slot = &mut self.slots[index];
        if slot.capacity() < cap {
            *slot = BytesMut::zeroed(cap);
        } else {
            slot.resize(cap, 0);
        }
    }

    fn drain_recycled(&mut self) {
        while let Ok(mut slot) = self.recycle_rx.try_recv() {
            let large = slot.capacity() >= self.headroom + self.large_payload;
            if large {
                if self.free_large.len() >= self.large_count {
                    continue;
                }
                slot.resize(self.headroom + self.large_payload, 0);
                self.free_large.push(slot);
            } else {
                if self.free_small.len() >= self.small_slot_count() {
                    continue;
                }
                slot.resize(self.headroom + self.small_payload, 0);
                self.free_small.push(slot);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::encode_packet_from_buf;

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
    fn permit_releases_budget_on_every_drop_path() {
        let budget = BufferBudget::new(1_000);
        let permit = budget.try_acquire(700).unwrap();
        assert_eq!(budget.used(), 700);
        drop(permit);
        assert_eq!(budget.used(), 0);
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
        assert_eq!(pool.slot_payload_capacity(LARGE_SLOT_COUNT), SMALL_TUN_SLOT);
        assert!(pool.large_slot_count() * LARGE_TUN_SLOT < 128 * LARGE_TUN_SLOT);
    }

    #[test]
    fn tun_slots_recycle_through_zero_copy_wire_frames() {
        let mut pool = PacketSlotPool::new(32, OVERLAY_HEADER_HEADROOM);
        let mut packet = pool.take(LARGE_SLOT_COUNT, 128);
        let payload_pointer = packet.as_slice().as_ptr();
        let (frames, stats) = encode_packet_from_buf(&mut packet, 1_200, 1, None).unwrap();
        assert_eq!(stats.payload_copy_bytes, 0);
        assert_eq!(frames[0][12 + 16..].as_ptr(), payload_pointer);

        drop(frames);
        pool.slots_mut();
        assert!(
            pool.free_small.is_empty(),
            "packet still owns the slab slot"
        );
        drop(packet);
        pool.slots_mut();
        assert_eq!(pool.free_small.len(), 1);

        // Repeated handoff alternates the two warmed allocations rather than
        // allocating a fresh replacement for every packet.
        let mut pointers = std::collections::HashSet::new();
        for _ in 0..100 {
            let packet = pool.take(LARGE_SLOT_COUNT, 128);
            pointers.insert(packet.as_slice().as_ptr());
            drop(packet);
        }
        assert!(pointers.len() <= 2);
    }
}

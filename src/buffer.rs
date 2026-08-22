//! V2 TUN and encoded-Cell buffer ownership.
//!
//! A buffer moves into immutable `Bytes` without copying and returns to its
//! bounded producer-local recycler only after the transport releases the last
//! owner. There is no V1 envelope headroom or generic packet wrapper here.

use bytes::{Bytes, BytesMut};
use crossbeam_channel::{Receiver, Sender, bounded};

const SMALL_TUN_SLOT: usize = 4 * 1024;
const LARGE_SLOT_COUNT: usize = 16;

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
            let _ = recycler.try_send(std::mem::take(&mut self.buf));
        }
    }
}

fn freeze_recycling(buf: BytesMut, recycler: Sender<BytesMut>, offset: usize) -> Bytes {
    let length = buf.len();
    Bytes::from_owner(FrozenRecyclingBuffer {
        buf,
        recycler: Some(recycler),
    })
    .slice(offset..length)
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

/// Recyclable variable-length byte slots for encoded wire records. Unlike
/// [`PacketSlotPool`], this pool has no permanently occupied read slots: every
/// allocation is owned by `Bytes` until QUIC releases its final clone, then is
/// returned through the bounded recycler.
#[derive(Debug)]
pub struct RecyclingBytePool {
    free: Vec<BytesMut>,
    recycle_tx: Sender<BytesMut>,
    recycle_rx: Receiver<BytesMut>,
    minimum_slot_capacity: usize,
    maximum_cached: usize,
}

impl RecyclingBytePool {
    pub fn new(preallocate: usize, minimum_slot_capacity: usize) -> Self {
        let maximum_cached = preallocate.max(1);
        let (recycle_tx, recycle_rx) = bounded(maximum_cached);
        let free = (0..preallocate)
            .map(|_| BytesMut::with_capacity(minimum_slot_capacity))
            .collect();
        Self {
            free,
            recycle_tx,
            recycle_rx,
            minimum_slot_capacity,
            maximum_cached,
        }
    }

    /// Build one immutable record in a reusable allocation. `writer` may use
    /// normal `BytesMut::put_*` APIs; the resulting allocation remains owned
    /// by the returned `Bytes` until all transport clones are gone.
    pub fn build<E>(
        &mut self,
        writer: impl FnOnce(&mut BytesMut) -> Result<(), E>,
    ) -> Result<Bytes, E> {
        self.drain_recycled();
        let mut slot = self
            .free
            .pop()
            .unwrap_or_else(|| BytesMut::with_capacity(self.minimum_slot_capacity));
        slot.clear();
        if slot.capacity() < self.minimum_slot_capacity {
            slot.reserve(self.minimum_slot_capacity);
        }
        if let Err(error) = writer(&mut slot) {
            let _ = self.recycle_tx.try_send(slot);
            return Err(error);
        }
        Ok(freeze_recycling(slot, self.recycle_tx.clone(), 0))
    }

    fn drain_recycled(&mut self) {
        while self.free.len() < self.maximum_cached {
            let Ok(mut slot) = self.recycle_rx.try_recv() else {
                break;
            };
            slot.clear();
            self.free.push(slot);
        }
    }
}

impl PacketSlotPool {
    /// Build a mixed-size pool with an explicit jumbo capacity. V2 raw TUN
    /// records include the virtio-net header, so their maximum is ten bytes
    /// larger than an IP packet and cannot use `LARGE_TUN_SLOT` directly.
    pub fn with_payload_sizes(
        batch: usize,
        headroom: usize,
        small_payload: usize,
        large_payload: usize,
    ) -> Self {
        let large_count = batch.clamp(1, LARGE_SLOT_COUNT);
        let small_count = batch.saturating_sub(large_count);
        let large_payload = large_payload.max(SMALL_TUN_SLOT);
        let small_payload = small_payload.clamp(SMALL_TUN_SLOT, large_payload);
        // A bounded array channel has no per-return allocation. Drops must
        // never block a dataplane worker, so a full recycler simply releases
        // the excess slot to the allocator instead of applying hidden queue
        // backpressure.
        let (recycle_tx, recycle_rx) = bounded(batch.max(1));
        let mut slots = Vec::with_capacity(batch);
        slots.extend((0..large_count).map(|_| BytesMut::zeroed(headroom + large_payload)));
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
            large_payload,
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

    pub fn take(&mut self, index: usize, payload_len: usize) -> Bytes {
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
        freeze_recycling(taken, self.recycle_tx.clone(), self.headroom)
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

    #[test]
    fn tun_slots_recycle_after_last_bytes_owner_drops() {
        let mut pool = PacketSlotPool::with_payload_sizes(32, 0, 4_106, 65_545);
        let payload_pointer = pool.slots_mut()[LARGE_SLOT_COUNT].as_ptr();
        let bytes = pool.take(LARGE_SLOT_COUNT, 128);
        assert_eq!(bytes.as_ptr(), payload_pointer);

        pool.slots_mut();
        assert!(pool.free_small.is_empty(), "Bytes still owns the slab slot");
        drop(bytes);
        pool.slots_mut();
        assert_eq!(pool.free_small.len(), 1);

        // Repeated handoff alternates the two warmed allocations rather than
        // allocating a fresh replacement for every packet.
        let mut pointers = std::collections::HashSet::new();
        for _ in 0..100 {
            let bytes = pool.take(LARGE_SLOT_COUNT, 128);
            pointers.insert(bytes.as_ptr());
            drop(bytes);
        }
        assert!(pointers.len() <= 2);
    }

    #[test]
    fn recyclable_slot_transfers_into_bytes_without_copy() {
        let mut pool = PacketSlotPool::with_payload_sizes(32, 0, 4_106, 65_545);
        pool.slots_mut()[16][..4].copy_from_slice(b"data");
        let bytes = pool.take(16, 4);
        let pointer = bytes.as_ptr();
        assert_eq!(bytes.as_ref(), b"data");
        assert_eq!(bytes.as_ptr(), pointer);

        pool.slots_mut();
        assert!(pool.free_small.is_empty());
        drop(bytes);
        pool.slots_mut();
        assert_eq!(pool.free_small.len(), 1);
    }

    #[test]
    fn explicit_jumbo_capacity_covers_raw_virtio_record() {
        let pool = PacketSlotPool::with_payload_sizes(32, 0, 4_106, 65_545);
        assert_eq!(pool.slot_payload_capacity(0), 65_545);
        assert_eq!(pool.slot_payload_capacity(16), 4_106);
    }

    #[test]
    fn variable_wire_slots_return_after_the_last_bytes_owner_drops() {
        let mut pool = RecyclingBytePool::new(1, 128);
        let bytes = pool
            .build::<std::convert::Infallible>(|slot| {
                slot.extend_from_slice(b"cell");
                Ok(())
            })
            .unwrap();
        assert_eq!(&bytes[..], b"cell");
        let first_pointer = bytes.as_ptr();
        let held = bytes.clone();
        drop(bytes);
        let second = pool
            .build::<std::convert::Infallible>(|slot| {
                slot.extend_from_slice(b"next");
                Ok(())
            })
            .unwrap();
        assert_eq!(&second[..], b"next");
        assert_ne!(second.as_ptr(), first_pointer);
        drop(held);
        drop(second);
        let third = pool
            .build::<std::convert::Infallible>(|slot| {
                slot.extend_from_slice(b"reused");
                Ok(())
            })
            .unwrap();
        assert_eq!(&third[..], b"reused");
        assert_eq!(third.as_ptr(), first_pointer);
    }
}

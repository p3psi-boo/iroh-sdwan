use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use crossbeam_channel::{Receiver, Sender, TrySendError, bounded};
use tokio::sync::Notify;

use crate::buffer::{BufferBudget, DataplaneBuf};
use crate::delivery::DeliveryTag;
use crate::observability::PeerCounters;
use crate::protocol::envelope::{Envelope, MessageType};
use crate::wire::RepairRequest;

pub const OUTBOUND_QUEUE_BYTES: usize = 8 * 1024 * 1024;
const OUTBOUND_QUEUE_PACKETS: usize = 8_192;
const CONTROL_QUEUE_PACKETS: usize = 1_024;
const CONTROL_QUEUE_BYTES: usize = 1024 * 1024;
const PROBE_QUEUE_BYTES: usize = 256 * 1024;
const MIN_OUTBOUND_MAX_AGE: Duration = Duration::from_millis(100);
const MAX_OUTBOUND_MAX_AGE: Duration = Duration::from_secs(2);
const REPAIR_CACHE_BYTES: usize = 16 * 1024 * 1024;
const REPAIR_CACHE_TTL: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
pub struct OutboundPacket {
    pub data: DataplaneBuf,
    pub enqueued: Instant,
    pub latency_sensitive: bool,
    pub delivery_tag: Option<DeliveryTag>,
}

impl OutboundPacket {
    pub fn new(data: impl Into<DataplaneBuf>, latency_sensitive: bool) -> Self {
        Self {
            data: data.into(),
            enqueued: Instant::now(),
            latency_sensitive,
            delivery_tag: None,
        }
    }

    pub fn with_delivery_tag(mut self, delivery_tag: Option<DeliveryTag>) -> Self {
        self.delivery_tag = delivery_tag;
        self
    }

    fn expired(&self, priority_maximum_age: Duration) -> bool {
        self.latency_sensitive && self.enqueued.elapsed() > priority_maximum_age
    }
}

#[derive(Debug)]
pub enum OutboundItem {
    Control(Bytes),
    Packet(OutboundPacket),
    Probe(Bytes),
}

#[derive(Debug)]
struct QueueCore {
    control_tx: Sender<Bytes>,
    control_rx: Receiver<Bytes>,
    priority_tx: Sender<OutboundPacket>,
    priority_rx: Receiver<OutboundPacket>,
    bulk_tx: Sender<OutboundPacket>,
    bulk_rx: Receiver<OutboundPacket>,
    probe_tx: Sender<Bytes>,
    probe_rx: Receiver<Bytes>,
    total: AtomicU64,
    priority: AtomicU64,
    bulk: AtomicU64,
    control: AtomicU64,
    probe: AtomicU64,
    started: Instant,
    last_push_micros: AtomicU64,
    interarrival_ewma_micros: AtomicU64,
    ready: Notify,
    counters: Arc<PeerCounters>,
    max_bytes: usize,
    depth_dirty: AtomicU64,
    budget: Option<Arc<BufferBudget>>,
}

#[derive(Debug)]
pub struct OutboundQueue {
    core: Arc<QueueCore>,
    // Taken once by the peer's network task. The packet path never touches
    // this mutex; after startup all dequeue/scheduling state has one writer.
    consumer: Mutex<Option<OutboundConsumer>>,
}

#[derive(Debug)]
pub struct OutboundConsumer {
    core: Arc<QueueCore>,
    deferred_priority: Option<OutboundPacket>,
    deferred_bulk: Option<OutboundPacket>,
}

impl OutboundQueue {
    pub fn new(counters: Arc<PeerCounters>) -> Self {
        Self::with_max_bytes(counters, OUTBOUND_QUEUE_BYTES)
    }

    pub fn with_max_bytes(counters: Arc<PeerCounters>, max_bytes: usize) -> Self {
        Self::with_max_bytes_and_budget(counters, max_bytes, None)
    }

    pub fn with_max_bytes_and_budget(
        counters: Arc<PeerCounters>,
        max_bytes: usize,
        budget: Option<Arc<BufferBudget>>,
    ) -> Self {
        let (control_tx, control_rx) = bounded(CONTROL_QUEUE_PACKETS);
        let (priority_tx, priority_rx) = bounded(OUTBOUND_QUEUE_PACKETS);
        let (bulk_tx, bulk_rx) = bounded(OUTBOUND_QUEUE_PACKETS);
        let (probe_tx, probe_rx) = bounded(CONTROL_QUEUE_PACKETS);
        let core = Arc::new(QueueCore {
            control_tx,
            control_rx,
            priority_tx,
            priority_rx,
            bulk_tx,
            bulk_rx,
            probe_tx,
            probe_rx,
            total: AtomicU64::new(0),
            priority: AtomicU64::new(0),
            bulk: AtomicU64::new(0),
            control: AtomicU64::new(0),
            probe: AtomicU64::new(0),
            started: Instant::now(),
            last_push_micros: AtomicU64::new(0),
            interarrival_ewma_micros: AtomicU64::new(0),
            ready: Notify::new(),
            counters,
            max_bytes: max_bytes.max(65_535),
            depth_dirty: AtomicU64::new(0),
            budget,
        });
        Self {
            consumer: Mutex::new(Some(OutboundConsumer {
                core: core.clone(),
                deferred_priority: None,
                deferred_bulk: None,
            })),
            core,
        }
    }

    pub fn take_consumer(&self) -> Option<OutboundConsumer> {
        self.consumer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    pub fn push(&self, packet: OutboundPacket) {
        let packet_len = packet.data.len();
        // A packet which cannot fit even in an empty queue must not empty the
        // queue and then make its byte accounting exceed the hard bound.
        if packet_len > self.core.max_bytes {
            self.core
                .counters
                .queue_drops
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        let latency_sensitive = packet.latency_sensitive;
        let mut packet = packet;
        loop {
            if reserve(
                &self.core.total,
                packet_len,
                OUTBOUND_QUEUE_PACKETS,
                self.core.max_bytes,
            ) {
                if let Some(budget) = &self.core.budget
                    && !budget.try_reserve(packet_len)
                {
                    release(&self.core.total, packet_len);
                    self.core
                        .counters
                        .queue_drops
                        .fetch_add(1, Ordering::Relaxed);
                    self.core.mark_depth_dirty();
                    return;
                }
                let class = if latency_sensitive {
                    &self.core.priority
                } else {
                    &self.core.bulk
                };
                class.fetch_add(packed(1, packet_len), Ordering::Relaxed);
                let result = if latency_sensitive {
                    self.core.priority_tx.try_send(packet)
                } else {
                    self.core.bulk_tx.try_send(packet)
                };
                match result {
                    Ok(()) => {
                        self.core.record_push();
                        self.core.mark_depth_dirty();
                        self.core.notify_if_first_application();
                        return;
                    }
                    Err(TrySendError::Full(returned) | TrySendError::Disconnected(returned)) => {
                        release(&self.core.total, packet_len);
                        if let Some(budget) = &self.core.budget {
                            budget.release(packet_len);
                        }
                        class.fetch_sub(packed(1, packet_len), Ordering::Relaxed);
                        packet = returned;
                    }
                }
            }

            // Congestion is the only path where producers consume from a
            // channel. The steady state is wait-free admission plus a single
            // network-task consumer. Priority replaces Bulk first; fresh Bulk
            // replaces only Bulk and never displaces priority reservations.
            let evicted = if latency_sensitive {
                self.core
                    .bulk_rx
                    .try_recv()
                    .map(|packet| (packet, false))
                    .or_else(|_| {
                        self.core
                            .priority_rx
                            .try_recv()
                            .map(|packet| (packet, true))
                    })
                    .ok()
            } else {
                let (priority_packets, priority_bytes) =
                    unpack(self.core.priority.load(Ordering::Acquire));
                if priority_packets >= OUTBOUND_QUEUE_PACKETS
                    || priority_bytes.saturating_add(packet_len) > self.core.max_bytes
                {
                    None
                } else {
                    self.core
                        .bulk_rx
                        .try_recv()
                        .map(|packet| (packet, false))
                        .ok()
                }
            };
            let Some((evicted, was_priority)) = evicted else {
                self.core
                    .counters
                    .queue_drops
                    .fetch_add(1, Ordering::Relaxed);
                self.core.mark_depth_dirty();
                return;
            };
            self.core.release_packet(&evicted, was_priority);
            self.core
                .counters
                .queue_drops
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn push_control(&self, datagram: Bytes) -> bool {
        if datagram.is_empty()
            || !reserve(
                &self.core.control,
                datagram.len(),
                CONTROL_QUEUE_PACKETS,
                CONTROL_QUEUE_BYTES,
            )
        {
            return false;
        }
        let len = datagram.len();
        match self.core.control_tx.try_send(datagram) {
            Ok(()) => {
                self.core.notify_if_first_control();
                true
            }
            Err(_) => {
                release(&self.core.control, len);
                false
            }
        }
    }

    pub fn push_probe(&self, datagram: Bytes) -> bool {
        if datagram.is_empty()
            || !reserve(
                &self.core.probe,
                datagram.len(),
                CONTROL_QUEUE_PACKETS,
                PROBE_QUEUE_BYTES,
            )
        {
            return false;
        }
        let len = datagram.len();
        match self.core.probe_tx.try_send(datagram) {
            Ok(()) => {
                self.core.notify_if_first_probe();
                true
            }
            Err(_) => {
                release(&self.core.probe, len);
                false
            }
        }
    }

    pub fn queued_bytes(&self) -> u64 {
        unpack(self.core.total.load(Ordering::Relaxed)).1 as u64
    }

    pub fn publish_depth(&self) {
        self.core.publish_depth();
    }

    pub fn requeue(&self, item: OutboundItem) {
        match item {
            OutboundItem::Control(datagram) => {
                self.push_control(datagram);
            }
            OutboundItem::Packet(packet) => self.push(packet),
            OutboundItem::Probe(datagram) => {
                self.push_probe(datagram);
            }
        }
    }
}

impl QueueCore {
    fn notify_if_first_application(&self) {
        let (packets, _) = unpack(self.total.load(Ordering::Relaxed));
        if packets == 1 {
            self.ready.notify_one();
        }
    }

    fn notify_if_first_control(&self) {
        let (packets, _) = unpack(self.control.load(Ordering::Relaxed));
        if packets == 1 {
            self.ready.notify_one();
        }
    }

    fn notify_if_first_probe(&self) {
        let (packets, _) = unpack(self.probe.load(Ordering::Relaxed));
        if packets == 1 {
            self.ready.notify_one();
        }
    }

    fn mark_depth_dirty(&self) {
        let (packets, bytes) = unpack(self.total.load(Ordering::Relaxed));
        self.counters
            .queue_bytes
            .store(bytes as u64, Ordering::Relaxed);
        self.counters
            .queue_packets
            .store(packets as u64, Ordering::Relaxed);
        self.counters
            .queue_peak_bytes
            .fetch_max(bytes as u64, Ordering::Relaxed);
        self.depth_dirty.store(1, Ordering::Relaxed);
    }

    fn publish_depth(&self) {
        if self.depth_dirty.swap(0, Ordering::Relaxed) == 0 {
            return;
        }
        self.update_depth();
    }

    fn record_push(&self) {
        let now = duration_micros(self.started.elapsed()).max(1);
        let previous = self.last_push_micros.swap(now, Ordering::Relaxed);
        if previous == 0 {
            return;
        }
        let sample = now.saturating_sub(previous);
        let mut current = self.interarrival_ewma_micros.load(Ordering::Relaxed);
        loop {
            let updated = if current == 0 {
                sample
            } else {
                ewma(current, sample)
            };
            match self.interarrival_ewma_micros.compare_exchange_weak(
                current,
                updated,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(observed) => current = observed,
            }
        }
    }

    fn release_packet(&self, packet: &OutboundPacket, priority: bool) {
        let len = packet.data.len();
        release(&self.total, len);
        if let Some(budget) = &self.budget {
            budget.release(len);
        }
        let class = if priority { &self.priority } else { &self.bulk };
        class.fetch_sub(packed(1, len), Ordering::Relaxed);
        self.mark_depth_dirty();
    }

    fn update_depth(&self) {
        let (packets, bytes) = unpack(self.total.load(Ordering::Relaxed));
        let (priority_packets, priority_bytes) = unpack(self.priority.load(Ordering::Relaxed));
        let (bulk_packets, bulk_bytes) = unpack(self.bulk.load(Ordering::Relaxed));
        self.counters
            .queue_bytes
            .store(bytes as u64, Ordering::Relaxed);
        self.counters
            .queue_packets
            .store(packets as u64, Ordering::Relaxed);
        self.counters
            .priority_queue_bytes
            .store(priority_bytes as u64, Ordering::Relaxed);
        self.counters
            .priority_queue_packets
            .store(priority_packets as u64, Ordering::Relaxed);
        self.counters
            .bulk_queue_bytes
            .store(bulk_bytes as u64, Ordering::Relaxed);
        self.counters
            .bulk_queue_packets
            .store(bulk_packets as u64, Ordering::Relaxed);
        self.counters
            .queue_peak_bytes
            .fetch_max(bytes as u64, Ordering::Relaxed);
    }
}

impl OutboundConsumer {
    fn take_priority(&mut self) -> Option<OutboundPacket> {
        self.deferred_priority
            .take()
            .or_else(|| self.core.priority_rx.try_recv().ok())
    }

    fn take_bulk(&mut self) -> Option<OutboundPacket> {
        self.deferred_bulk
            .take()
            .or_else(|| self.core.bulk_rx.try_recv().ok())
    }

    fn take_application(&mut self) -> Option<(OutboundPacket, bool)> {
        self.take_priority()
            .map(|packet| (packet, true))
            .or_else(|| self.take_bulk().map(|packet| (packet, false)))
    }

    /// Pop immediately available control or priority work without waiting for
    /// queue notification. Bulk and probes remain queued. Expired priority
    /// packets are discarded before returning the next urgent item.
    pub fn try_pop_urgent(&mut self, priority_maximum_age: Duration) -> Option<OutboundItem> {
        if let Ok(control) = self.core.control_rx.try_recv() {
            release(&self.core.control, control.len());
            self.core.publish_depth();
            return Some(OutboundItem::Control(control));
        }
        while let Some(packet) = self.take_priority() {
            self.core.release_packet(&packet, true);
            if !packet.expired(priority_maximum_age) {
                self.core.publish_depth();
                return Some(OutboundItem::Packet(packet));
            }
            self.core
                .counters
                .queue_expired_drops
                .fetch_add(1, Ordering::Relaxed);
        }
        self.core.publish_depth();
        None
    }

    pub async fn pop_for_network(&mut self, priority_maximum_age: Duration) -> OutboundItem {
        loop {
            let core = self.core.clone();
            let notified = core.ready.notified();
            if let Ok(control) = self.core.control_rx.try_recv() {
                release(&self.core.control, control.len());
                self.core.publish_depth();
                return OutboundItem::Control(control);
            }
            while let Some((packet, priority)) = self.take_application() {
                self.core.release_packet(&packet, priority);
                if !packet.expired(priority_maximum_age) {
                    self.core.publish_depth();
                    return OutboundItem::Packet(packet);
                }
                self.core
                    .counters
                    .queue_expired_drops
                    .fetch_add(1, Ordering::Relaxed);
            }
            if let Ok(probe) = self.core.probe_rx.try_recv() {
                release(&self.core.probe, probe.len());
                self.core.publish_depth();
                return OutboundItem::Probe(probe);
            }
            notified.await;
        }
    }

    pub async fn pop(&mut self, priority_maximum_age: Duration) -> OutboundPacket {
        loop {
            let core = self.core.clone();
            let notified = core.ready.notified();
            if let Some(packet) = self.try_pop(priority_maximum_age) {
                self.core.publish_depth();
                return packet;
            }
            notified.await;
        }
    }

    /// Non-blocking single-consumer application dequeue. This is useful for
    /// draining after a batched producer burst without constructing an async
    /// state machine for every packet.
    pub fn try_pop(&mut self, priority_maximum_age: Duration) -> Option<OutboundPacket> {
        while let Some((packet, priority)) = self.take_application() {
            self.core.release_packet(&packet, priority);
            if !packet.expired(priority_maximum_age) {
                self.core.publish_depth();
                return Some(packet);
            }
            self.core
                .counters
                .queue_expired_drops
                .fetch_add(1, Ordering::Relaxed);
        }
        self.core.publish_depth();
        None
    }

    /// Pop a small packet from exactly one traffic class. This keeps a wire
    /// batch's scheduling semantics uniform, so a Bulk transmission cannot
    /// hide a priority packet (and a priority transmission does not pull Bulk
    /// ahead of other queued priority work).
    pub fn try_pop_small_class(
        &mut self,
        latency_sensitive: bool,
        maximum_packet_len: usize,
        priority_maximum_age: Duration,
    ) -> Option<OutboundPacket> {
        loop {
            let candidate = if latency_sensitive {
                self.take_priority()
            } else {
                self.take_bulk()
            }?;
            if candidate.data.len() > maximum_packet_len {
                if latency_sensitive {
                    self.deferred_priority = Some(candidate);
                } else {
                    self.deferred_bulk = Some(candidate);
                }
                return None;
            }
            let packet = candidate;
            self.core.release_packet(&packet, latency_sensitive);
            if !packet.expired(priority_maximum_age) {
                self.core.publish_depth();
                return Some(packet);
            }
            self.core
                .counters
                .queue_expired_drops
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Drain one scheduling class under a single queue lock. `wire_budget`
    /// accounts for payload plus a conservative fixed envelope cost per
    /// packet, allowing the caller to encode the returned packets without
    /// repeatedly locking the producer/consumer boundary.
    pub fn try_pop_small_batch_class(
        &mut self,
        latency_sensitive: bool,
        maximum_packet_len: usize,
        mut wire_budget: usize,
        per_packet_overhead: usize,
        maximum_packets: usize,
        priority_maximum_age: Duration,
    ) -> Vec<OutboundPacket> {
        let mut packets = Vec::with_capacity(maximum_packets.min(16));
        while packets.len() < maximum_packets {
            let Some(candidate) = (if latency_sensitive {
                self.take_priority()
            } else {
                self.take_bulk()
            }) else {
                break;
            };
            if candidate.data.len() > maximum_packet_len {
                if latency_sensitive {
                    self.deferred_priority = Some(candidate);
                } else {
                    self.deferred_bulk = Some(candidate);
                }
                break;
            }
            let wire_cost = candidate.data.len().saturating_add(per_packet_overhead);
            if wire_cost > wire_budget {
                if latency_sensitive {
                    self.deferred_priority = Some(candidate);
                } else {
                    self.deferred_bulk = Some(candidate);
                }
                break;
            }
            let packet = candidate;
            self.core.release_packet(&packet, latency_sensitive);
            if packet.expired(priority_maximum_age) {
                self.core
                    .counters
                    .queue_expired_drops
                    .fetch_add(1, Ordering::Relaxed);
                continue;
            }
            wire_budget = wire_budget.saturating_sub(wire_cost);
            packets.push(packet);
        }
        self.core.publish_depth();
        packets
    }

    pub fn aggregation_delay(&self) -> Duration {
        let (pending_packets, _) = unpack(self.core.total.load(Ordering::Relaxed));
        recommended_aggregation_delay(
            pending_packets,
            self.core.interarrival_ewma_micros.load(Ordering::Relaxed),
        )
    }
}

fn packed(packets: usize, bytes: usize) -> u64 {
    ((packets as u64) << 32) | bytes as u64
}

fn unpack(value: u64) -> (usize, usize) {
    (
        (value >> 32) as usize,
        (value & u64::from(u32::MAX)) as usize,
    )
}

fn reserve(state: &AtomicU64, bytes: usize, max_packets: usize, max_bytes: usize) -> bool {
    let mut current = state.load(Ordering::Acquire);
    loop {
        let (packets, queued_bytes) = unpack(current);
        if packets >= max_packets || queued_bytes.saturating_add(bytes) > max_bytes {
            return false;
        }
        let updated = packed(packets + 1, queued_bytes + bytes);
        match state.compare_exchange_weak(current, updated, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return true,
            Err(observed) => current = observed,
        }
    }
}

fn release(state: &AtomicU64, bytes: usize) {
    let mut current = state.load(Ordering::Acquire);
    loop {
        let (packets, queued_bytes) = unpack(current);
        debug_assert!(packets > 0 && queued_bytes >= bytes);
        let updated = packed(
            packets.saturating_sub(1),
            queued_bytes.saturating_sub(bytes),
        );
        match state.compare_exchange_weak(current, updated, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

pub fn adaptive_queue_max_age(rtt: Duration) -> Duration {
    rtt.saturating_mul(4)
        .clamp(MIN_OUTBOUND_MAX_AGE, MAX_OUTBOUND_MAX_AGE)
}

fn recommended_aggregation_delay(_pending_packets: usize, _interarrival_micros: u64) -> Duration {
    // A 50µs timer is rounded up to the Tokio 1ms wheel and delays the first
    // packet of a burst. Only drain packets already in the queue.
    Duration::ZERO
}

#[derive(Debug)]
struct CachedPacket {
    created: Instant,
    frames: Vec<(u16, Bytes)>,
    bytes: usize,
}

#[derive(Debug)]
pub struct RepairCache {
    packets: HashMap<u64, CachedPacket>,
    order: VecDeque<u64>,
    bytes: usize,
    max_bytes: usize,
}

impl Default for RepairCache {
    fn default() -> Self {
        Self {
            packets: HashMap::new(),
            order: VecDeque::new(),
            bytes: 0,
            max_bytes: REPAIR_CACHE_BYTES,
        }
    }
}

impl RepairCache {
    pub fn with_max_bytes(max_bytes: usize) -> Self {
        Self {
            max_bytes: max_bytes.max(u16::MAX as usize),
            ..Self::default()
        }
    }

    pub fn insert(&mut self, packet_id: u64, frames: &[Bytes]) {
        if frames.len() < 2 {
            return;
        }
        self.expire();
        let bytes = frames.iter().map(Bytes::len).sum();
        while self.bytes.saturating_add(bytes) > self.max_bytes {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.remove_packet(oldest);
        }
        if bytes > self.max_bytes {
            return;
        }
        self.bytes += bytes;
        self.order.push_back(packet_id);
        self.packets.insert(
            packet_id,
            CachedPacket {
                created: Instant::now(),
                frames: frames.iter().cloned().filter_map(frame_offset).collect(),
                bytes,
            },
        );
    }

    pub fn get(&mut self, request: &RepairRequest) -> Option<Vec<Bytes>> {
        self.expire();
        self.packets
            .get(&request.packet_id)
            .map(|packet| {
                packet
                    .frames
                    .iter()
                    .filter(|(offset, _)| request.missing_offsets.contains(offset))
                    .map(|(_, frame)| frame.clone())
                    .collect()
            })
            .filter(|frames: &Vec<Bytes>| !frames.is_empty())
    }

    fn expire(&mut self) {
        while let Some(packet_id) = self.order.front().copied() {
            let expired = self
                .packets
                .get(&packet_id)
                .is_none_or(|packet| packet.created.elapsed() >= REPAIR_CACHE_TTL);
            if !expired {
                break;
            }
            self.order.pop_front();
            self.remove_packet(packet_id);
        }
    }

    fn remove_packet(&mut self, packet_id: u64) {
        if let Some(packet) = self.packets.remove(&packet_id) {
            self.bytes = self.bytes.saturating_sub(packet.bytes);
        }
    }
}

#[derive(Debug)]
pub struct AdaptiveFrameSizer {
    ceiling: usize,
    current: usize,
}

impl AdaptiveFrameSizer {
    pub fn new(ceiling: usize) -> Self {
        let current = ceiling.clamp(256, 1_200);
        Self { ceiling, current }
    }

    pub fn current(&self) -> usize {
        self.current
    }

    pub fn update(&mut self, path_limit: usize) -> usize {
        // QUIC exposes the live payload limit and lowers it on black-hole
        // detection. A second loss heuristic or a slow application-level
        // ramp only adds packet-rate overhead and delays recovery.
        self.current = self.ceiling.min(path_limit).max(256);
        self.current
    }
}

pub fn store_duration_micros(target: &AtomicU64, duration: Duration) {
    target.store(duration_micros(duration), Ordering::Relaxed);
}

fn frame_offset(frame: Bytes) -> Option<(u16, Bytes)> {
    let envelope = Envelope::decode(frame.clone()).ok()?;
    (envelope.kind == MessageType::IpFragment)
        .then(|| {
            envelope
                .payload
                .get(10..12)
                .map(|bytes| u16::from_be_bytes(bytes.try_into().unwrap()))
        })
        .flatten()
        .map(|offset| (offset, frame))
}

fn duration_micros(duration: Duration) -> u64 {
    duration.as_micros().min(u128::from(u64::MAX)) as u64
}

fn ewma(previous: u64, sample: u64) -> u64 {
    previous.saturating_mul(7).saturating_add(sample) / 8
}

#[cfg(test)]
mod tests {
    use iroh::SecretKey;

    use super::*;
    use crate::wire::encode_packet;

    #[test]
    fn frame_sizer_tracks_the_live_quic_limit() {
        let mut sizer = AdaptiveFrameSizer::new(1_400);
        assert_eq!(sizer.current(), 1_200);
        assert_eq!(sizer.update(1_162), 1_162);
        assert_eq!(sizer.update(1_414), 1_400);
        assert_eq!(sizer.update(1_200), 1_200);
    }

    fn counters() -> Arc<PeerCounters> {
        Arc::new(PeerCounters::new(
            "test".into(),
            SecretKey::from_bytes(&[9; 32]).public(),
            "ironet-test".into(),
        ))
    }

    #[tokio::test]
    async fn queue_prioritizes_latency_sensitive_packets() {
        let counters = counters();
        let queue = OutboundQueue::new(counters.clone());
        let mut consumer = queue.take_consumer().unwrap();
        queue.push(OutboundPacket::new(Bytes::from_static(b"bulk"), false));
        queue.push(OutboundPacket::new(Bytes::from_static(b"priority"), true));
        assert_eq!(
            consumer.pop(Duration::from_secs(1)).await.data.as_slice(),
            b"priority"
        );
        assert_eq!(
            consumer.pop(Duration::from_secs(1)).await.data.as_slice(),
            b"bulk"
        );
        assert_eq!(counters.queue_packets.load(Ordering::Relaxed), 0);
        assert_eq!(counters.queue_bytes.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn control_precedes_application_and_probe_is_strictly_last() {
        let counters = counters();
        let queue = OutboundQueue::new(counters.clone());
        let mut consumer = queue.take_consumer().unwrap();
        assert!(queue.push_probe(Bytes::from_static(b"probe")));
        queue.push(OutboundPacket::new(Bytes::from_static(b"bulk"), false));
        queue.push(OutboundPacket::new(Bytes::from_static(b"priority"), true));
        assert!(queue.push_control(Bytes::from_static(b"control")));

        assert!(
            matches!(consumer.pop_for_network(Duration::from_secs(1)).await, OutboundItem::Control(bytes) if bytes == Bytes::from_static(b"control"))
        );
        assert!(
            matches!(consumer.pop_for_network(Duration::from_secs(1)).await, OutboundItem::Packet(packet) if packet.data.as_slice() == b"priority")
        );
        assert!(
            matches!(consumer.pop_for_network(Duration::from_secs(1)).await, OutboundItem::Packet(packet) if packet.data.as_slice() == b"bulk")
        );
        assert!(
            matches!(consumer.pop_for_network(Duration::from_secs(1)).await, OutboundItem::Probe(bytes) if bytes == Bytes::from_static(b"probe"))
        );
        assert_eq!(counters.queue_packets.load(Ordering::Relaxed), 0);
        assert_eq!(counters.queue_bytes.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn queue_honours_a_per_peer_memory_budget() {
        let counters = counters();
        let queue = OutboundQueue::with_max_bytes(counters.clone(), 65_535);
        let mut consumer = queue.take_consumer().unwrap();
        queue.push(OutboundPacket::new(Bytes::from(vec![1; 40_000]), false));
        queue.push(OutboundPacket::new(Bytes::from(vec![2; 40_000]), false));
        assert_eq!(counters.queue_packets.load(Ordering::Relaxed), 1);
        assert_eq!(counters.queue_bytes.load(Ordering::Relaxed), 40_000);
        assert_eq!(counters.queue_drops.load(Ordering::Relaxed), 1);
        let packet = consumer.pop(Duration::from_secs(1)).await;
        assert_eq!(packet.data.as_slice()[0], 2);
    }

    #[tokio::test]
    async fn bulk_admission_never_evicts_priority() {
        let counters = counters();
        let queue = OutboundQueue::with_max_bytes(counters.clone(), 65_535);
        let mut consumer = queue.take_consumer().unwrap();
        queue.push(OutboundPacket::new(Bytes::from(vec![1; 50_000]), true));
        queue.push(OutboundPacket::new(Bytes::from(vec![2; 15_000]), false));

        // Removing the queued Bulk packet still would not leave room for the
        // new one. Admission must therefore leave both queued packets intact
        // and discard only the incoming Bulk packet.
        queue.push(OutboundPacket::new(Bytes::from(vec![3; 20_000]), false));

        assert_eq!(counters.queue_packets.load(Ordering::Relaxed), 2);
        assert_eq!(counters.queue_bytes.load(Ordering::Relaxed), 65_000);
        assert_eq!(counters.queue_drops.load(Ordering::Relaxed), 1);
        assert_eq!(consumer.pop(Duration::from_secs(1)).await.data.as_slice()[0], 1);
        assert_eq!(consumer.pop(Duration::from_secs(1)).await.data.as_slice()[0], 2);
    }

    #[tokio::test]
    async fn priority_admission_evicts_bulk_first() {
        let counters = counters();
        let queue = OutboundQueue::with_max_bytes(counters.clone(), 65_535);
        let mut consumer = queue.take_consumer().unwrap();
        queue.push(OutboundPacket::new(Bytes::from(vec![1; 40_000]), false));
        queue.push(OutboundPacket::new(Bytes::from(vec![2; 40_000]), true));

        assert_eq!(counters.queue_packets.load(Ordering::Relaxed), 1);
        assert_eq!(counters.queue_bytes.load(Ordering::Relaxed), 40_000);
        assert_eq!(counters.queue_drops.load(Ordering::Relaxed), 1);
        let packet = consumer.pop(Duration::from_secs(1)).await;
        assert!(packet.latency_sensitive);
        assert_eq!(packet.data.as_slice()[0], 2);
    }

    #[tokio::test]
    async fn urgent_pop_returns_control_then_fresh_priority_only() {
        let counters = counters();
        let queue = OutboundQueue::new(counters.clone());
        let mut consumer = queue.take_consumer().unwrap();
        assert!(queue.push_probe(Bytes::from_static(b"probe")));
        queue.push(OutboundPacket::new(Bytes::from_static(b"bulk"), false));
        let mut expired = OutboundPacket::new(Bytes::from_static(b"expired"), true);
        expired.enqueued = Instant::now() - Duration::from_secs(1);
        queue.push(expired);
        queue.push(OutboundPacket::new(Bytes::from_static(b"priority"), true));
        assert!(queue.push_control(Bytes::from_static(b"control")));

        assert!(matches!(
            consumer.try_pop_urgent(Duration::from_millis(100)),
            Some(OutboundItem::Control(bytes)) if bytes == Bytes::from_static(b"control")
        ));
        assert!(matches!(
            consumer.try_pop_urgent(Duration::from_millis(100)),
            Some(OutboundItem::Packet(packet)) if packet.data.as_slice() == b"priority"
        ));
        assert!(
            consumer
                .try_pop_urgent(Duration::from_millis(100))
                .is_none()
        );
        assert_eq!(counters.queue_expired_drops.load(Ordering::Relaxed), 1);
        assert_eq!(counters.queue_packets.load(Ordering::Relaxed), 1);
        assert_eq!(counters.queue_bytes.load(Ordering::Relaxed), 4);

        assert!(matches!(
            consumer
                .pop_for_network(Duration::from_secs(1))
                .await,
            OutboundItem::Packet(packet) if packet.data.as_slice() == b"bulk"
        ));
        assert!(matches!(
            consumer
                .pop_for_network(Duration::from_secs(1))
                .await,
            OutboundItem::Probe(bytes) if bytes == Bytes::from_static(b"probe")
        ));
    }

    #[tokio::test]
    async fn small_batch_pop_never_crosses_traffic_classes() {
        let counters = counters();
        let queue = OutboundQueue::new(counters.clone());
        let mut consumer = queue.take_consumer().unwrap();
        queue.push(OutboundPacket::new(Bytes::from_static(b"bulk"), false));
        queue.push(OutboundPacket::new(Bytes::from_static(b"priority"), true));

        let bulk = consumer
            .try_pop_small_class(false, 512, Duration::from_secs(1))
            .expect("Bulk packet should remain directly selectable by class");
        assert_eq!(bulk.data.as_slice(), b"bulk");
        assert!(!bulk.latency_sensitive);
        assert!(
            consumer
                .try_pop_small_class(false, 512, Duration::from_secs(1))
                .is_none()
        );

        let priority = consumer
            .try_pop_small_class(true, 512, Duration::from_secs(1))
            .expect("priority packet should remain queued");
        assert_eq!(priority.data.as_slice(), b"priority");
        assert!(priority.latency_sensitive);
        assert_eq!(counters.queue_packets.load(Ordering::Relaxed), 0);
        assert_eq!(counters.queue_bytes.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn bulk_uses_the_byte_bound_instead_of_latency_expiry() {
        let counters = counters();
        let queue = OutboundQueue::new(counters.clone());
        let mut consumer = queue.take_consumer().unwrap();
        let mut bulk = OutboundPacket::new(Bytes::from_static(b"bulk"), false);
        bulk.enqueued = Instant::now() - Duration::from_secs(30);
        queue.push(bulk);

        let packet = consumer.pop(Duration::from_millis(100)).await;
        assert_eq!(packet.data.as_slice(), b"bulk");
        assert_eq!(counters.queue_expired_drops.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn eight_megabyte_queue_stays_bounded_near_capacity() {
        let counters = counters();
        let queue = OutboundQueue::with_max_bytes(counters.clone(), OUTBOUND_QUEUE_BYTES);
        for _ in 0..(OUTBOUND_QUEUE_BYTES / 1024 - 1) {
            queue.push(OutboundPacket::new(Bytes::from(vec![1; 1024]), false));
        }
        assert_eq!(
            counters.queue_bytes.load(Ordering::Relaxed),
            (OUTBOUND_QUEUE_BYTES - 1024) as u64
        );

        queue.push(OutboundPacket::new(Bytes::from(vec![2; 2048]), false));
        assert_eq!(
            counters.queue_bytes.load(Ordering::Relaxed),
            OUTBOUND_QUEUE_BYTES as u64
        );
        assert_eq!(counters.queue_drops.load(Ordering::Relaxed), 1);
        assert!(counters.queue_peak_bytes.load(Ordering::Relaxed) <= OUTBOUND_QUEUE_BYTES as u64);
    }

    #[test]
    fn concurrent_producers_preserve_exact_lock_free_accounting() {
        const PRODUCERS: usize = 4;
        const PER_PRODUCER: usize = 1_000;
        let counters = counters();
        let queue = Arc::new(OutboundQueue::new(counters.clone()));
        let mut consumer = queue.take_consumer().unwrap();
        std::thread::scope(|scope| {
            for producer in 0..PRODUCERS {
                let queue = queue.clone();
                scope.spawn(move || {
                    for sequence in 0..PER_PRODUCER {
                        queue.push(OutboundPacket::new(
                            Bytes::from(vec![(producer ^ sequence) as u8; 64]),
                            sequence % 8 == 0,
                        ));
                    }
                });
            }
        });
        assert_eq!(
            counters.queue_packets.load(Ordering::Relaxed),
            (PRODUCERS * PER_PRODUCER) as u64
        );
        for _ in 0..PRODUCERS * PER_PRODUCER {
            assert!(consumer.try_pop(Duration::from_secs(1)).is_some());
        }
        assert!(consumer.try_pop(Duration::from_secs(1)).is_none());
        assert_eq!(counters.queue_packets.load(Ordering::Relaxed), 0);
        assert_eq!(counters.queue_bytes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn queue_age_tracks_four_rtts_with_wan_bounds() {
        assert_eq!(
            adaptive_queue_max_age(Duration::from_millis(5)),
            Duration::from_millis(100)
        );
        assert_eq!(
            adaptive_queue_max_age(Duration::from_millis(50)),
            Duration::from_millis(200)
        );
        assert_eq!(
            adaptive_queue_max_age(Duration::from_secs(1)),
            Duration::from_secs(2)
        );
    }

    #[test]
    fn aggregation_wait_is_never_a_timer() {
        assert_eq!(recommended_aggregation_delay(0, 100), Duration::ZERO);
        assert_eq!(recommended_aggregation_delay(1, 100), Duration::ZERO);
        assert_eq!(recommended_aggregation_delay(0, 1_000), Duration::ZERO);
        assert_eq!(recommended_aggregation_delay(0, 0), Duration::ZERO);
    }

    #[test]
    fn repair_cache_only_keeps_fragmented_packets() {
        let mut cache = RepairCache::default();
        cache.insert(1, &[Bytes::from_static(b"one")]);
        let request = RepairRequest {
            packet_id: 1,
            missing_offsets: vec![0],
        };
        assert!(cache.get(&request).is_none());
        let frames = encode_packet(&vec![3; 1_280], 1_000, 2).unwrap();
        cache.insert(2, &frames);
        let request = RepairRequest {
            packet_id: 2,
            missing_offsets: vec![972],
        };
        assert_eq!(cache.get(&request).unwrap(), vec![frames[1].clone()]);
    }
}

use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use tokio::sync::{Mutex, Notify};

use crate::delivery::DeliveryTag;
use crate::observability::PeerCounters;
use crate::wire::RepairRequest;

pub const OUTBOUND_QUEUE_BYTES: usize = 8 * 1024 * 1024;
const OUTBOUND_QUEUE_PACKETS: usize = 8_192;
const CONTROL_QUEUE_PACKETS: usize = 1_024;
const CONTROL_QUEUE_BYTES: usize = 1024 * 1024;
const PROBE_QUEUE_BYTES: usize = 256 * 1024;
const MIN_OUTBOUND_MAX_AGE: Duration = Duration::from_millis(100);
const MAX_OUTBOUND_MAX_AGE: Duration = Duration::from_secs(2);
const AGGREGATION_INTERARRIVAL_THRESHOLD: Duration = Duration::from_micros(250);
const ADAPTIVE_AGGREGATION_DELAY: Duration = Duration::from_micros(50);
const REPAIR_CACHE_BYTES: usize = 16 * 1024 * 1024;
const REPAIR_CACHE_TTL: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
pub struct OutboundPacket {
    pub data: Bytes,
    pub enqueued: Instant,
    pub latency_sensitive: bool,
    pub delivery_tag: Option<DeliveryTag>,
}

impl OutboundPacket {
    pub fn new(data: Bytes, latency_sensitive: bool) -> Self {
        Self {
            data,
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

#[derive(Debug, Default)]
struct QueueState {
    control: VecDeque<Bytes>,
    priority: VecDeque<OutboundPacket>,
    bulk: VecDeque<OutboundPacket>,
    probe: VecDeque<Bytes>,
    priority_bytes: usize,
    bulk_bytes: usize,
    control_bytes: usize,
    probe_bytes: usize,
    last_push: Option<Instant>,
    interarrival_ewma_micros: u64,
}

impl QueueState {
    fn packets(&self) -> usize {
        self.priority.len() + self.bulk.len()
    }

    fn bytes(&self) -> usize {
        self.priority_bytes.saturating_add(self.bulk_bytes)
    }

    fn record_push(&mut self, now: Instant) {
        if let Some(previous) = self.last_push {
            let sample = duration_micros(now.duration_since(previous));
            self.interarrival_ewma_micros = if self.interarrival_ewma_micros == 0 {
                sample
            } else {
                ewma(self.interarrival_ewma_micros, sample)
            };
        }
        self.last_push = Some(now);
    }

    fn pop_application(&mut self) -> Option<OutboundPacket> {
        if let Some(packet) = self.priority.pop_front() {
            self.priority_bytes = self.priority_bytes.saturating_sub(packet.data.len());
            return Some(packet);
        }
        let packet = self.bulk.pop_front()?;
        self.bulk_bytes = self.bulk_bytes.saturating_sub(packet.data.len());
        Some(packet)
    }

    fn pop_for_send(&mut self) -> Option<OutboundItem> {
        if let Some(control) = self.control.pop_front() {
            self.control_bytes = self.control_bytes.saturating_sub(control.len());
            return Some(OutboundItem::Control(control));
        }
        if let Some(packet) = self.pop_application() {
            return Some(OutboundItem::Packet(packet));
        }
        let probe = self.probe.pop_front()?;
        self.probe_bytes = self.probe_bytes.saturating_sub(probe.len());
        Some(OutboundItem::Probe(probe))
    }

    fn evict_one(&mut self) -> Option<OutboundPacket> {
        if let Some(packet) = self.bulk.pop_front() {
            self.bulk_bytes = self.bulk_bytes.saturating_sub(packet.data.len());
            return Some(packet);
        }
        let packet = self.priority.pop_front()?;
        self.priority_bytes = self.priority_bytes.saturating_sub(packet.data.len());
        Some(packet)
    }

    fn evict_bulk(&mut self) -> Option<OutboundPacket> {
        let packet = self.bulk.pop_front()?;
        self.bulk_bytes = self.bulk_bytes.saturating_sub(packet.data.len());
        Some(packet)
    }

    /// Number of oldest Bulk packets that have to be removed to admit one
    /// packet. This is linear only when the queue is already over budget; the
    /// common uncongested admission path returns without scanning.
    fn bulk_evictions_to_fit(&self, packet_len: usize, max_bytes: usize) -> Option<usize> {
        if self.packets() < OUTBOUND_QUEUE_PACKETS
            && self.bytes().saturating_add(packet_len) <= max_bytes
        {
            return Some(0);
        }
        if self.priority.len() >= OUTBOUND_QUEUE_PACKETS
            || self.priority_bytes.saturating_add(packet_len) > max_bytes
        {
            return None;
        }

        let byte_deficit = self
            .bytes()
            .saturating_add(packet_len)
            .saturating_sub(max_bytes);
        let packet_deficit = self
            .packets()
            .saturating_add(1)
            .saturating_sub(OUTBOUND_QUEUE_PACKETS);
        let mut freed_bytes = 0_usize;
        for (index, packet) in self.bulk.iter().enumerate() {
            freed_bytes = freed_bytes.saturating_add(packet.data.len());
            let evictions = index + 1;
            if evictions >= packet_deficit && freed_bytes >= byte_deficit {
                return Some(evictions);
            }
        }
        None
    }
}

#[derive(Debug)]
pub enum OutboundItem {
    Control(Bytes),
    Packet(OutboundPacket),
    Probe(Bytes),
}

#[derive(Debug)]
pub struct OutboundQueue {
    state: Mutex<QueueState>,
    ready: Notify,
    counters: Arc<PeerCounters>,
    max_bytes: usize,
}

impl OutboundQueue {
    pub fn new(counters: Arc<PeerCounters>) -> Self {
        Self::with_max_bytes(counters, OUTBOUND_QUEUE_BYTES)
    }

    pub fn with_max_bytes(counters: Arc<PeerCounters>, max_bytes: usize) -> Self {
        Self {
            state: Mutex::new(QueueState::default()),
            ready: Notify::new(),
            counters,
            max_bytes: max_bytes.max(65_535),
        }
    }

    pub async fn push(&self, packet: OutboundPacket) {
        let packet_len = packet.data.len();
        // A packet which cannot fit even in an empty queue must not empty the
        // queue and then make its byte accounting exceed the hard bound.
        if packet_len > self.max_bytes {
            self.counters.queue_drops.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let mut state = self.state.lock().await;

        if packet.latency_sensitive {
            // Fresh priority traffic first displaces Bulk.  If the queue is
            // entirely priority traffic, replace its oldest entry so latency
            // traffic remains fresh while the total budget stays bounded.
            while state.packets() >= OUTBOUND_QUEUE_PACKETS
                || state.bytes().saturating_add(packet_len) > self.max_bytes
            {
                if state.evict_one().is_none() {
                    break;
                }
                self.counters.queue_drops.fetch_add(1, Ordering::Relaxed);
            }
        } else {
            // Bulk may replace older Bulk, but it must never consume space by
            // evicting priority traffic.  Plan the admission transactionally:
            // when priority traffic leaves insufficient room, retain every
            // queued packet and drop only the incoming Bulk packet.
            let Some(evictions) = state.bulk_evictions_to_fit(packet_len, self.max_bytes) else {
                self.counters.queue_drops.fetch_add(1, Ordering::Relaxed);
                self.update_depth(&state);
                return;
            };
            for _ in 0..evictions {
                let evicted = state.evict_bulk();
                debug_assert!(evicted.is_some(), "priority-only fit was checked");
                self.counters.queue_drops.fetch_add(1, Ordering::Relaxed);
            }
        }

        state.record_push(Instant::now());
        if packet.latency_sensitive {
            state.priority_bytes += packet_len;
            state.priority.push_back(packet);
        } else {
            state.bulk_bytes += packet_len;
            state.bulk.push_back(packet);
        }
        self.update_depth(&state);
        drop(state);
        self.ready.notify_one();
    }

    /// Pop immediately available control or priority work without waiting for
    /// queue notification. Bulk and probes remain queued. Expired priority
    /// packets are discarded before returning the next urgent item.
    pub async fn try_pop_urgent(&self, priority_maximum_age: Duration) -> Option<OutboundItem> {
        let mut state = self.state.lock().await;
        if let Some(control) = state.control.pop_front() {
            state.control_bytes = state.control_bytes.saturating_sub(control.len());
            self.update_depth(&state);
            return Some(OutboundItem::Control(control));
        }
        while let Some(packet) = state.priority.pop_front() {
            state.priority_bytes = state.priority_bytes.saturating_sub(packet.data.len());
            if packet.enqueued.elapsed() <= priority_maximum_age {
                self.update_depth(&state);
                return Some(OutboundItem::Packet(packet));
            }
            self.counters
                .queue_expired_drops
                .fetch_add(1, Ordering::Relaxed);
        }
        self.update_depth(&state);
        None
    }

    pub async fn push_control(&self, datagram: Bytes) -> bool {
        let mut state = self.state.lock().await;
        if datagram.is_empty()
            || state.control.len() >= CONTROL_QUEUE_PACKETS
            || state.control_bytes.saturating_add(datagram.len()) > CONTROL_QUEUE_BYTES
        {
            return false;
        }
        state.control_bytes = state.control_bytes.saturating_add(datagram.len());
        state.control.push_back(datagram);
        drop(state);
        self.ready.notify_one();
        true
    }

    pub async fn push_probe(&self, datagram: Bytes) -> bool {
        let mut state = self.state.lock().await;
        if datagram.is_empty()
            || state.probe_bytes.saturating_add(datagram.len()) > PROBE_QUEUE_BYTES
        {
            return false;
        }
        state.probe_bytes = state.probe_bytes.saturating_add(datagram.len());
        state.probe.push_back(datagram);
        drop(state);
        self.ready.notify_one();
        true
    }

    pub async fn requeue(&self, item: OutboundItem) {
        match item {
            OutboundItem::Control(datagram) => {
                self.push_control(datagram).await;
            }
            OutboundItem::Packet(packet) => self.push(packet).await,
            OutboundItem::Probe(datagram) => {
                self.push_probe(datagram).await;
            }
        }
    }

    pub async fn pop_for_network(&self, priority_maximum_age: Duration) -> OutboundItem {
        loop {
            let notified = self.ready.notified();
            {
                let mut state = self.state.lock().await;
                while let Some(item) = state.pop_for_send() {
                    let OutboundItem::Packet(packet) = item else {
                        self.update_depth(&state);
                        return item;
                    };
                    if !packet.expired(priority_maximum_age) {
                        self.update_depth(&state);
                        return OutboundItem::Packet(packet);
                    }
                    self.counters
                        .queue_expired_drops
                        .fetch_add(1, Ordering::Relaxed);
                }
                self.update_depth(&state);
            }
            notified.await;
        }
    }

    pub async fn pop(&self, priority_maximum_age: Duration) -> OutboundPacket {
        loop {
            let notified = self.ready.notified();
            {
                let mut state = self.state.lock().await;
                while let Some(packet) = state.pop_application() {
                    if !packet.expired(priority_maximum_age) {
                        self.update_depth(&state);
                        return packet;
                    }
                    self.counters
                        .queue_expired_drops
                        .fetch_add(1, Ordering::Relaxed);
                }
                self.update_depth(&state);
            }
            notified.await;
        }
    }

    /// Pop a small packet from exactly one traffic class. This keeps a wire
    /// batch's scheduling semantics uniform, so a Bulk transmission cannot
    /// hide a priority packet (and a priority transmission does not pull Bulk
    /// ahead of other queued priority work).
    pub async fn try_pop_small_class(
        &self,
        latency_sensitive: bool,
        maximum_packet_len: usize,
        priority_maximum_age: Duration,
    ) -> Option<OutboundPacket> {
        let mut state = self.state.lock().await;
        loop {
            let candidate = if latency_sensitive {
                state.priority.front()
            } else {
                state.bulk.front()
            }?;
            if candidate.data.len() > maximum_packet_len {
                return None;
            }
            let packet = if latency_sensitive {
                state.priority.pop_front()
            } else {
                state.bulk.pop_front()
            }
            .expect("selected class had a front packet");
            if latency_sensitive {
                state.priority_bytes = state.priority_bytes.saturating_sub(packet.data.len());
            } else {
                state.bulk_bytes = state.bulk_bytes.saturating_sub(packet.data.len());
            }
            if !packet.expired(priority_maximum_age) {
                self.update_depth(&state);
                return Some(packet);
            }
            self.counters
                .queue_expired_drops
                .fetch_add(1, Ordering::Relaxed);
            self.update_depth(&state);
        }
    }

    pub async fn aggregation_delay(&self) -> Duration {
        let state = self.state.lock().await;
        recommended_aggregation_delay(state.packets(), state.interarrival_ewma_micros)
    }

    fn update_depth(&self, state: &QueueState) {
        self.counters
            .queue_bytes
            .store(state.bytes() as u64, Ordering::Relaxed);
        self.counters
            .queue_packets
            .store(state.packets() as u64, Ordering::Relaxed);
        self.counters
            .priority_queue_bytes
            .store(state.priority_bytes as u64, Ordering::Relaxed);
        self.counters
            .priority_queue_packets
            .store(state.priority.len() as u64, Ordering::Relaxed);
        self.counters
            .bulk_queue_bytes
            .store(state.bulk_bytes as u64, Ordering::Relaxed);
        self.counters
            .bulk_queue_packets
            .store(state.bulk.len() as u64, Ordering::Relaxed);
        self.counters
            .queue_peak_bytes
            .fetch_max(state.bytes() as u64, Ordering::Relaxed);
    }
}

pub fn adaptive_queue_max_age(rtt: Duration) -> Duration {
    rtt.saturating_mul(4)
        .clamp(MIN_OUTBOUND_MAX_AGE, MAX_OUTBOUND_MAX_AGE)
}

fn recommended_aggregation_delay(pending_packets: usize, interarrival_micros: u64) -> Duration {
    if pending_packets == 0
        && interarrival_micros > 0
        && interarrival_micros <= AGGREGATION_INTERARRIVAL_THRESHOLD.as_micros() as u64
    {
        ADAPTIVE_AGGREGATION_DELAY
    } else {
        Duration::ZERO
    }
}

#[derive(Debug)]
struct CachedPacket {
    created: Instant,
    frames: Vec<Bytes>,
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
                frames: frames.to_vec(),
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
                    .filter(|frame| {
                        let offset = u16::from_be_bytes(frame[18..20].try_into().unwrap());
                        request.missing_offsets.contains(&offset)
                    })
                    .cloned()
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
            "isw-test".into(),
        ))
    }

    #[tokio::test]
    async fn queue_prioritizes_latency_sensitive_packets() {
        let counters = counters();
        let queue = OutboundQueue::new(counters.clone());
        queue
            .push(OutboundPacket::new(Bytes::from_static(b"bulk"), false))
            .await;
        queue
            .push(OutboundPacket::new(Bytes::from_static(b"priority"), true))
            .await;
        assert_eq!(
            queue.pop(Duration::from_secs(1)).await.data,
            Bytes::from_static(b"priority")
        );
        assert_eq!(
            queue.pop(Duration::from_secs(1)).await.data,
            Bytes::from_static(b"bulk")
        );
        assert_eq!(counters.queue_packets.load(Ordering::Relaxed), 0);
        assert_eq!(counters.queue_bytes.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn control_precedes_application_and_probe_is_strictly_last() {
        let counters = counters();
        let queue = OutboundQueue::new(counters.clone());
        assert!(queue.push_probe(Bytes::from_static(b"probe")).await);
        queue
            .push(OutboundPacket::new(Bytes::from_static(b"bulk"), false))
            .await;
        queue
            .push(OutboundPacket::new(Bytes::from_static(b"priority"), true))
            .await;
        assert!(queue.push_control(Bytes::from_static(b"control")).await);

        let pop = || queue.pop_for_network(Duration::from_secs(1));
        assert!(
            matches!(pop().await, OutboundItem::Control(bytes) if bytes == Bytes::from_static(b"control"))
        );
        assert!(
            matches!(pop().await, OutboundItem::Packet(packet) if packet.data == Bytes::from_static(b"priority"))
        );
        assert!(
            matches!(pop().await, OutboundItem::Packet(packet) if packet.data == Bytes::from_static(b"bulk"))
        );
        assert!(
            matches!(pop().await, OutboundItem::Probe(bytes) if bytes == Bytes::from_static(b"probe"))
        );
        assert_eq!(counters.queue_packets.load(Ordering::Relaxed), 0);
        assert_eq!(counters.queue_bytes.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn queue_honours_a_per_peer_memory_budget() {
        let counters = counters();
        let queue = OutboundQueue::with_max_bytes(counters.clone(), 65_535);
        queue
            .push(OutboundPacket::new(Bytes::from(vec![1; 40_000]), false))
            .await;
        queue
            .push(OutboundPacket::new(Bytes::from(vec![2; 40_000]), false))
            .await;
        assert_eq!(counters.queue_packets.load(Ordering::Relaxed), 1);
        assert_eq!(counters.queue_bytes.load(Ordering::Relaxed), 40_000);
        assert_eq!(counters.queue_drops.load(Ordering::Relaxed), 1);
        let packet = queue.pop(Duration::from_secs(1)).await;
        assert_eq!(packet.data[0], 2);
    }

    #[tokio::test]
    async fn bulk_admission_never_evicts_priority() {
        let counters = counters();
        let queue = OutboundQueue::with_max_bytes(counters.clone(), 65_535);
        queue
            .push(OutboundPacket::new(Bytes::from(vec![1; 50_000]), true))
            .await;
        queue
            .push(OutboundPacket::new(Bytes::from(vec![2; 15_000]), false))
            .await;

        // Removing the queued Bulk packet still would not leave room for the
        // new one. Admission must therefore leave both queued packets intact
        // and discard only the incoming Bulk packet.
        queue
            .push(OutboundPacket::new(Bytes::from(vec![3; 20_000]), false))
            .await;

        assert_eq!(counters.queue_packets.load(Ordering::Relaxed), 2);
        assert_eq!(counters.queue_bytes.load(Ordering::Relaxed), 65_000);
        assert_eq!(counters.queue_drops.load(Ordering::Relaxed), 1);
        assert_eq!(queue.pop(Duration::from_secs(1)).await.data[0], 1);
        assert_eq!(queue.pop(Duration::from_secs(1)).await.data[0], 2);
    }

    #[tokio::test]
    async fn priority_admission_evicts_bulk_first() {
        let counters = counters();
        let queue = OutboundQueue::with_max_bytes(counters.clone(), 65_535);
        queue
            .push(OutboundPacket::new(Bytes::from(vec![1; 40_000]), false))
            .await;
        queue
            .push(OutboundPacket::new(Bytes::from(vec![2; 40_000]), true))
            .await;

        assert_eq!(counters.queue_packets.load(Ordering::Relaxed), 1);
        assert_eq!(counters.queue_bytes.load(Ordering::Relaxed), 40_000);
        assert_eq!(counters.queue_drops.load(Ordering::Relaxed), 1);
        let packet = queue.pop(Duration::from_secs(1)).await;
        assert!(packet.latency_sensitive);
        assert_eq!(packet.data[0], 2);
    }

    #[tokio::test]
    async fn urgent_pop_returns_control_then_fresh_priority_only() {
        let counters = counters();
        let queue = OutboundQueue::new(counters.clone());
        assert!(queue.push_probe(Bytes::from_static(b"probe")).await);
        queue
            .push(OutboundPacket::new(Bytes::from_static(b"bulk"), false))
            .await;
        let mut expired = OutboundPacket::new(Bytes::from_static(b"expired"), true);
        expired.enqueued = Instant::now() - Duration::from_secs(1);
        queue.push(expired).await;
        queue
            .push(OutboundPacket::new(Bytes::from_static(b"priority"), true))
            .await;
        assert!(queue.push_control(Bytes::from_static(b"control")).await);

        assert!(matches!(
            queue.try_pop_urgent(Duration::from_millis(100)).await,
            Some(OutboundItem::Control(bytes)) if bytes == Bytes::from_static(b"control")
        ));
        assert!(matches!(
            queue.try_pop_urgent(Duration::from_millis(100)).await,
            Some(OutboundItem::Packet(packet)) if packet.data == Bytes::from_static(b"priority")
        ));
        assert!(
            queue
                .try_pop_urgent(Duration::from_millis(100))
                .await
                .is_none()
        );
        assert_eq!(counters.queue_expired_drops.load(Ordering::Relaxed), 1);
        assert_eq!(counters.queue_packets.load(Ordering::Relaxed), 1);
        assert_eq!(counters.queue_bytes.load(Ordering::Relaxed), 4);

        assert!(matches!(
            queue
                .pop_for_network(Duration::from_secs(1))
                .await,
            OutboundItem::Packet(packet) if packet.data == Bytes::from_static(b"bulk")
        ));
        assert!(matches!(
            queue
                .pop_for_network(Duration::from_secs(1))
                .await,
            OutboundItem::Probe(bytes) if bytes == Bytes::from_static(b"probe")
        ));
    }

    #[tokio::test]
    async fn small_batch_pop_never_crosses_traffic_classes() {
        let counters = counters();
        let queue = OutboundQueue::new(counters.clone());
        queue
            .push(OutboundPacket::new(Bytes::from_static(b"bulk"), false))
            .await;
        queue
            .push(OutboundPacket::new(Bytes::from_static(b"priority"), true))
            .await;

        let bulk = queue
            .try_pop_small_class(false, 512, Duration::from_secs(1))
            .await
            .expect("Bulk packet should remain directly selectable by class");
        assert_eq!(bulk.data, Bytes::from_static(b"bulk"));
        assert!(!bulk.latency_sensitive);
        assert!(
            queue
                .try_pop_small_class(false, 512, Duration::from_secs(1))
                .await
                .is_none()
        );

        let priority = queue
            .try_pop_small_class(true, 512, Duration::from_secs(1))
            .await
            .expect("priority packet should remain queued");
        assert_eq!(priority.data, Bytes::from_static(b"priority"));
        assert!(priority.latency_sensitive);
        assert_eq!(counters.queue_packets.load(Ordering::Relaxed), 0);
        assert_eq!(counters.queue_bytes.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn bulk_uses_the_byte_bound_instead_of_latency_expiry() {
        let counters = counters();
        let queue = OutboundQueue::new(counters.clone());
        let mut bulk = OutboundPacket::new(Bytes::from_static(b"bulk"), false);
        bulk.enqueued = Instant::now() - Duration::from_secs(30);
        queue.push(bulk).await;

        let packet = queue.pop(Duration::from_millis(100)).await;
        assert_eq!(packet.data, Bytes::from_static(b"bulk"));
        assert_eq!(counters.queue_expired_drops.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn eight_megabyte_queue_stays_bounded_near_capacity() {
        let counters = counters();
        let queue = OutboundQueue::with_max_bytes(counters.clone(), OUTBOUND_QUEUE_BYTES);
        for _ in 0..(OUTBOUND_QUEUE_BYTES / 1024 - 1) {
            queue
                .push(OutboundPacket::new(Bytes::from(vec![1; 1024]), false))
                .await;
        }
        assert_eq!(
            counters.queue_bytes.load(Ordering::Relaxed),
            (OUTBOUND_QUEUE_BYTES - 1024) as u64
        );

        queue
            .push(OutboundPacket::new(Bytes::from(vec![2; 2048]), false))
            .await;
        assert_eq!(
            counters.queue_bytes.load(Ordering::Relaxed),
            OUTBOUND_QUEUE_BYTES as u64
        );
        assert_eq!(counters.queue_drops.load(Ordering::Relaxed), 1);
        assert!(counters.queue_peak_bytes.load(Ordering::Relaxed) <= OUTBOUND_QUEUE_BYTES as u64);
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
    fn aggregation_wait_is_only_used_for_high_rate_empty_queue() {
        assert_eq!(
            recommended_aggregation_delay(0, 100),
            Duration::from_micros(50)
        );
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
            missing_offsets: vec![976],
        };
        assert_eq!(cache.get(&request).unwrap(), vec![frames[1].clone()]);
    }
}

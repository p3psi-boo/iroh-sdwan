//! Receiver-confirmed passive delivery measurement.
//!
//! Reports are cumulative and rate-limited; the source derives a sample from
//! receiver monotonic deltas, so clocks never need to be synchronized.

use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use anyhow::{Result, bail, ensure};
use bytes::Bytes;
use iroh::EndpointId;

use crate::capacity::RouteKey;
use crate::protocol::envelope::{Envelope, MessageType};

pub const MAX_DELIVERY_SESSIONS: usize = 4_096;
pub const DELIVERY_SESSION_TTL: Duration = Duration::from_secs(10);
/// A completed active probe's fixed hop list may seed later delivery sessions.
/// Keep that bounded route template through the capacity stale horizon while
/// expiring the per-session sequence/report state aggressively.
pub const DELIVERY_ROUTE_TEMPLATE_TTL: Duration = Duration::from_secs(180);
pub const DELIVERY_REPORT_BYTES: u64 = 256 * 1024;
pub const DELIVERY_REPORT_INTERVAL: Duration = Duration::from_millis(50);
pub const MAX_DELIVERY_HOPS: usize = 16;
pub const DELIVERY_TAG_WIRE_BYTES: usize = 12;
// Match the full per-peer application queue so any plausible in-process/path
// reordering remains exactly deduplicated while memory stays constant.
const DELIVERY_SEQUENCE_WINDOW: usize = 8_192;
const DELIVERY_SEQUENCE_WORDS: usize = DELIVERY_SEQUENCE_WINDOW / u64::BITS as usize;

const TYPE_REGISTER: u8 = 1;
const TYPE_REPORT: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeliveryTag {
    pub session_id: u64,
    pub sequence: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliverySessionRegister {
    pub session_id: u64,
    pub origin: EndpointId,
    pub destination: EndpointId,
    pub first_hop: EndpointId,
    pub path_epoch: u64,
    pub forward_hops: Vec<EndpointId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryReport {
    pub session_id: u64,
    pub origin: EndpointId,
    pub destination: EndpointId,
    pub path_epoch: u64,
    pub delivered_bytes: u64,
    pub delivered_packets: u64,
    pub duplicate_or_gap_count: u32,
    pub receiver_elapsed_micros: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryMessage {
    Register(DeliverySessionRegister),
    Report(DeliveryReport),
}

pub fn encode_delivery(message: &DeliveryMessage) -> Result<Bytes> {
    validate_delivery(message)?;
    let mut out = Vec::new();
    match message {
        DeliveryMessage::Register(message) => {
            out.push(TYPE_REGISTER);
            out.extend_from_slice(&message.session_id.to_be_bytes());
            out.extend_from_slice(message.origin.as_bytes());
            out.extend_from_slice(message.destination.as_bytes());
            out.extend_from_slice(message.first_hop.as_bytes());
            out.extend_from_slice(&message.path_epoch.to_be_bytes());
            out.push(message.forward_hops.len() as u8);
            for hop in &message.forward_hops {
                out.extend_from_slice(hop.as_bytes());
            }
        }
        DeliveryMessage::Report(message) => {
            out.push(TYPE_REPORT);
            out.extend_from_slice(&message.session_id.to_be_bytes());
            out.extend_from_slice(message.origin.as_bytes());
            out.extend_from_slice(message.destination.as_bytes());
            out.extend_from_slice(&message.path_epoch.to_be_bytes());
            out.extend_from_slice(&message.delivered_bytes.to_be_bytes());
            out.extend_from_slice(&message.delivered_packets.to_be_bytes());
            out.extend_from_slice(&message.duplicate_or_gap_count.to_be_bytes());
            out.extend_from_slice(&message.receiver_elapsed_micros.to_be_bytes());
        }
    }
    Envelope::new(MessageType::Delivery, out).encode()
}

pub fn decode_delivery(bytes: &[u8]) -> Result<DeliveryMessage> {
    if bytes.starts_with(crate::protocol::envelope::MAGIC) {
        let envelope = Envelope::decode(Bytes::copy_from_slice(bytes))?;
        ensure!(
            envelope.kind == MessageType::Delivery,
            "v4 envelope does not contain a delivery message"
        );
        return decode_delivery(&envelope.payload);
    }
    ensure!(bytes.len() >= 9, "truncated delivery message");
    let kind = bytes[0];
    let session_id = u64::from_be_bytes(bytes[1..9].try_into().unwrap());
    let message = match kind {
        TYPE_REGISTER => {
            ensure!(bytes.len() >= 114, "truncated delivery registration");
            let origin = decode_endpoint(&bytes[9..41])?;
            let destination = decode_endpoint(&bytes[41..73])?;
            let first_hop = decode_endpoint(&bytes[73..105])?;
            let path_epoch = u64::from_be_bytes(bytes[105..113].try_into().unwrap());
            let count = usize::from(bytes[113]);
            ensure!(count <= MAX_DELIVERY_HOPS, "too many delivery hops");
            ensure!(
                bytes.len() == 114 + count * 32,
                "delivery registration length mismatch"
            );
            let mut forward_hops = Vec::with_capacity(count);
            for chunk in bytes[114..].chunks_exact(32) {
                forward_hops.push(decode_endpoint(chunk)?);
            }
            DeliveryMessage::Register(DeliverySessionRegister {
                session_id,
                origin,
                destination,
                first_hop,
                path_epoch,
                forward_hops,
            })
        }
        TYPE_REPORT => {
            ensure!(bytes.len() == 109, "delivery report length mismatch");
            DeliveryMessage::Report(DeliveryReport {
                session_id,
                origin: decode_endpoint(&bytes[9..41])?,
                destination: decode_endpoint(&bytes[41..73])?,
                path_epoch: u64::from_be_bytes(bytes[73..81].try_into().unwrap()),
                delivered_bytes: u64::from_be_bytes(bytes[81..89].try_into().unwrap()),
                delivered_packets: u64::from_be_bytes(bytes[89..97].try_into().unwrap()),
                duplicate_or_gap_count: u32::from_be_bytes(bytes[97..101].try_into().unwrap()),
                receiver_elapsed_micros: u64::from_be_bytes(bytes[101..109].try_into().unwrap()),
            })
        }
        _ => bail!("unknown delivery message type"),
    };
    validate_delivery(&message)?;
    Ok(message)
}

pub fn validate_delivery(message: &DeliveryMessage) -> Result<()> {
    match message {
        DeliveryMessage::Register(message) => {
            ensure!(message.session_id != 0, "zero delivery session id");
            ensure!(
                message.origin != message.destination,
                "delivery origin equals destination"
            );
            ensure!(
                !message.forward_hops.is_empty() && message.forward_hops.len() <= MAX_DELIVERY_HOPS,
                "invalid delivery hop count"
            );
            ensure!(
                message.forward_hops[0] == message.origin
                    && message.forward_hops.get(1) == Some(&message.first_hop)
                    && message.forward_hops.last() == Some(&message.destination),
                "delivery hop list does not match route"
            );
            let mut unique = HashSet::with_capacity(message.forward_hops.len());
            ensure!(
                message.forward_hops.iter().all(|hop| unique.insert(*hop)),
                "delivery hop list contains a loop"
            );
        }
        DeliveryMessage::Report(message) => {
            ensure!(message.session_id != 0, "zero delivery session id");
            ensure!(
                message.origin != message.destination,
                "delivery origin equals destination"
            );
            ensure!(
                message.delivered_packets == 0 || message.delivered_bytes > 0,
                "delivery report has packets without bytes"
            );
            ensure!(
                message.delivered_packets == 0 || message.receiver_elapsed_micros > 0,
                "delivery report has zero receiver elapsed"
            );
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PassiveObservation {
    pub route: RouteKey,
    pub path_epoch: u64,
    pub delivered_bytes: u64,
    pub receiver_interval: Duration,
    pub app_limited: bool,
}

#[derive(Debug)]
struct SourceSession {
    route: RouteKey,
    destination: EndpointId,
    path_epoch: u64,
    next_sequence: u32,
    last_used: Instant,
    queue_nonempty_since: Option<Instant>,
    last_report_bytes: u64,
    last_report_packets: u64,
    last_report_elapsed_micros: u64,
}

#[derive(Debug)]
pub struct DeliverySource {
    sessions: HashMap<u64, SourceSession>,
    next_session_id: u64,
    capacity: usize,
}

impl Default for DeliverySource {
    fn default() -> Self {
        Self::new(MAX_DELIVERY_SESSIONS)
    }
}

impl DeliverySource {
    pub fn new(capacity: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            next_session_id: 1,
            capacity: capacity.max(1),
        }
    }

    pub fn register(
        &mut self,
        origin: EndpointId,
        route: RouteKey,
        path_epoch: u64,
        forward_hops: Vec<EndpointId>,
        now: Instant,
    ) -> Result<DeliverySessionRegister> {
        let destination = route.destination;
        let registration = DeliverySessionRegister {
            session_id: self.allocate_session_id(origin),
            origin,
            destination,
            first_hop: route.first_hop,
            path_epoch,
            forward_hops,
        };
        validate_delivery(&DeliveryMessage::Register(registration.clone()))?;
        self.make_room(now);
        self.sessions.insert(
            registration.session_id,
            SourceSession {
                route,
                destination,
                path_epoch,
                next_sequence: 0,
                last_used: now,
                queue_nonempty_since: None,
                last_report_bytes: 0,
                last_report_packets: 0,
                last_report_elapsed_micros: 0,
            },
        );
        Ok(registration)
    }

    pub fn next_tag(
        &mut self,
        session_id: u64,
        route: RouteKey,
        path_epoch: u64,
        now: Instant,
    ) -> Option<DeliveryTag> {
        let session = self.sessions.get_mut(&session_id)?;
        if session.route != route
            || session.destination != route.destination
            || session.path_epoch != path_epoch
            || now.saturating_duration_since(session.last_used) > DELIVERY_SESSION_TTL
        {
            return None;
        }
        let tag = DeliveryTag {
            session_id,
            sequence: session.next_sequence,
        };
        session.next_sequence = session.next_sequence.wrapping_add(1);
        session.last_used = now;
        Some(tag)
    }

    pub fn observe_queue(&mut self, session_id: u64, nonempty: bool, now: Instant) {
        let Some(session) = self.sessions.get_mut(&session_id) else {
            return;
        };
        session.last_used = now;
        if nonempty {
            session.queue_nonempty_since.get_or_insert(now);
        } else {
            session.queue_nonempty_since = None;
        }
    }

    pub fn apply_report(
        &mut self,
        report: &DeliveryReport,
        route: RouteKey,
        path_epoch: u64,
        now: Instant,
    ) -> Option<PassiveObservation> {
        let session = self.sessions.get_mut(&report.session_id)?;
        if session.route != route
            || session.destination != report.destination
            || session.path_epoch != path_epoch
            || report.path_epoch != path_epoch
            || now.saturating_duration_since(session.last_used) > DELIVERY_SESSION_TTL
            || report.delivered_bytes < session.last_report_bytes
            || report.delivered_packets < session.last_report_packets
            || report.receiver_elapsed_micros <= session.last_report_elapsed_micros
        {
            return None;
        }
        let delivered_bytes = report.delivered_bytes - session.last_report_bytes;
        let receiver_interval = Duration::from_micros(
            report.receiver_elapsed_micros - session.last_report_elapsed_micros,
        );
        if delivered_bytes == 0 || receiver_interval.is_zero() {
            return None;
        }
        let app_limited = session
            .queue_nonempty_since
            .is_none_or(|since| now.saturating_duration_since(since) < receiver_interval);
        session.last_report_bytes = report.delivered_bytes;
        session.last_report_packets = report.delivered_packets;
        session.last_report_elapsed_micros = report.receiver_elapsed_micros;
        session.last_used = now;
        Some(PassiveObservation {
            route,
            path_epoch,
            delivered_bytes,
            receiver_interval,
            app_limited,
        })
    }

    pub fn invalidate_route(&mut self, route: RouteKey) {
        self.sessions.retain(|_, session| session.route != route);
    }

    pub fn prune(&mut self, now: Instant) {
        self.sessions.retain(|_, session| {
            now.saturating_duration_since(session.last_used) <= DELIVERY_SESSION_TTL
        });
    }

    fn allocate_session_id(&mut self, origin: EndpointId) -> u64 {
        loop {
            let sequence = self.next_session_id.max(1);
            self.next_session_id = self.next_session_id.wrapping_add(1).max(1);
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"iroh-sdwan-delivery-session-v1\0");
            hasher.update(origin.as_bytes());
            hasher.update(&sequence.to_be_bytes());
            let id = u64::from_be_bytes(
                hasher.finalize().as_bytes()[..8]
                    .try_into()
                    .expect("hash prefix has fixed length"),
            );
            if id != 0 && !self.sessions.contains_key(&id) {
                return id;
            }
        }
    }

    fn make_room(&mut self, now: Instant) {
        self.prune(now);
        if self.sessions.len() < self.capacity {
            return;
        }
        if let Some(oldest) = self
            .sessions
            .iter()
            .min_by_key(|(_, session)| session.last_used)
            .map(|(id, _)| *id)
        {
            self.sessions.remove(&oldest);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SequenceObservation {
    InOrder,
    Reordered,
    Duplicate,
}

#[derive(Debug, Clone)]
struct SequenceWindow {
    highest: Option<u32>,
    bits: [u64; DELIVERY_SEQUENCE_WORDS],
}

impl Default for SequenceWindow {
    fn default() -> Self {
        Self {
            highest: None,
            bits: [0; DELIVERY_SEQUENCE_WORDS],
        }
    }
}

impl SequenceWindow {
    fn observe(&mut self, sequence: u32) -> SequenceObservation {
        let Some(highest) = self.highest else {
            self.highest = Some(sequence);
            self.mark(sequence);
            return SequenceObservation::InOrder;
        };

        let forward = sequence.wrapping_sub(highest);
        if forward == 0 {
            return SequenceObservation::Duplicate;
        }
        // RFC-style serial arithmetic: values less than half the sequence
        // space ahead are newer, including the normal u32 wraparound.
        if forward < 1_u32 << 31 {
            let advance = forward as usize;
            if advance >= DELIVERY_SEQUENCE_WINDOW {
                self.bits.fill(0);
            } else {
                for step in 1..=forward {
                    self.clear(highest.wrapping_add(step));
                }
            }
            self.highest = Some(sequence);
            self.mark(sequence);
            return if forward == 1 {
                SequenceObservation::InOrder
            } else {
                SequenceObservation::Reordered
            };
        }

        let behind = highest.wrapping_sub(sequence) as usize;
        if behind >= DELIVERY_SEQUENCE_WINDOW || self.contains(sequence) {
            SequenceObservation::Duplicate
        } else {
            self.mark(sequence);
            SequenceObservation::Reordered
        }
    }

    fn bit(sequence: u32) -> (usize, u64) {
        let index = sequence as usize & (DELIVERY_SEQUENCE_WINDOW - 1);
        (
            index / u64::BITS as usize,
            1_u64 << (index % u64::BITS as usize),
        )
    }

    fn contains(&self, sequence: u32) -> bool {
        let (word, mask) = Self::bit(sequence);
        self.bits[word] & mask != 0
    }

    fn mark(&mut self, sequence: u32) {
        let (word, mask) = Self::bit(sequence);
        self.bits[word] |= mask;
    }

    fn clear(&mut self, sequence: u32) {
        let (word, mask) = Self::bit(sequence);
        self.bits[word] &= !mask;
    }
}

#[derive(Debug)]
struct ReceiverSession {
    registration: DeliverySessionRegister,
    last_used: Instant,
    first_delivery: Option<Instant>,
    last_report_at: Instant,
    last_report_bytes: u64,
    delivered_bytes: u64,
    delivered_packets: u64,
    duplicate_or_gap_count: u32,
    sequences: SequenceWindow,
}

#[derive(Debug)]
pub struct DeliveryReceiver {
    sessions: HashMap<u64, ReceiverSession>,
    capacity: usize,
}

impl Default for DeliveryReceiver {
    fn default() -> Self {
        Self::new(MAX_DELIVERY_SESSIONS)
    }
}

impl DeliveryReceiver {
    pub fn new(capacity: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            capacity: capacity.max(1),
        }
    }

    pub fn register(&mut self, registration: DeliverySessionRegister, now: Instant) -> Result<()> {
        validate_delivery(&DeliveryMessage::Register(registration.clone()))?;
        self.make_room(now);
        self.sessions.insert(
            registration.session_id,
            ReceiverSession {
                registration,
                last_used: now,
                first_delivery: None,
                last_report_at: now,
                last_report_bytes: 0,
                delivered_bytes: 0,
                delivered_packets: 0,
                duplicate_or_gap_count: 0,
                sequences: SequenceWindow::default(),
            },
        );
        Ok(())
    }

    pub fn observe(
        &mut self,
        tag: DeliveryTag,
        delivered_bytes: usize,
        now: Instant,
    ) -> Option<DeliveryReport> {
        if self.sessions.get(&tag.session_id).is_some_and(|session| {
            now.saturating_duration_since(session.last_used) > DELIVERY_SESSION_TTL
        }) {
            self.sessions.remove(&tag.session_id);
            return None;
        }
        let session = self.sessions.get_mut(&tag.session_id)?;
        session.last_used = now;
        match session.sequences.observe(tag.sequence) {
            SequenceObservation::InOrder => {}
            SequenceObservation::Reordered => {
                session.duplicate_or_gap_count = session.duplicate_or_gap_count.saturating_add(1);
            }
            SequenceObservation::Duplicate => {
                session.duplicate_or_gap_count = session.duplicate_or_gap_count.saturating_add(1);
                return None;
            }
        }
        session.first_delivery.get_or_insert(now);
        session.delivered_bytes = session
            .delivered_bytes
            .saturating_add(delivered_bytes as u64);
        session.delivered_packets = session.delivered_packets.saturating_add(1);
        let due_bytes = session
            .delivered_bytes
            .saturating_sub(session.last_report_bytes)
            >= DELIVERY_REPORT_BYTES;
        let due_time =
            now.saturating_duration_since(session.last_report_at) >= DELIVERY_REPORT_INTERVAL;
        let elapsed = session
            .first_delivery
            .map_or(Duration::ZERO, |first| now.saturating_duration_since(first));
        // Byte thresholds control aggregation, but never allow a burst that
        // was dequeued in one receive-loop turn to create a microsecond-scale
        // rate sample. Receiver elapsed deltas need at least one report
        // interval of real arrival time.
        (due_time && due_bytes && !elapsed.is_zero()).then(|| make_report(session, now))
    }

    pub fn finish(&mut self, session_id: u64, now: Instant) -> Option<DeliveryReport> {
        let mut session = self.sessions.remove(&session_id)?;
        (session.delivered_bytes > session.last_report_bytes)
            .then(|| make_report(&mut session, now))
    }

    pub fn prune(&mut self, now: Instant) {
        self.sessions.retain(|_, session| {
            now.saturating_duration_since(session.last_used) <= DELIVERY_SESSION_TTL
        });
    }

    fn make_room(&mut self, now: Instant) {
        self.prune(now);
        if self.sessions.len() < self.capacity {
            return;
        }
        if let Some(oldest) = self
            .sessions
            .iter()
            .min_by_key(|(_, session)| session.last_used)
            .map(|(id, _)| *id)
        {
            self.sessions.remove(&oldest);
        }
    }
}

fn make_report(session: &mut ReceiverSession, now: Instant) -> DeliveryReport {
    session.last_report_at = now;
    session.last_report_bytes = session.delivered_bytes;
    DeliveryReport {
        session_id: session.registration.session_id,
        origin: session.registration.origin,
        destination: session.registration.destination,
        path_epoch: session.registration.path_epoch,
        delivered_bytes: session.delivered_bytes,
        delivered_packets: session.delivered_packets,
        duplicate_or_gap_count: session.duplicate_or_gap_count,
        receiver_elapsed_micros: session
            .first_delivery
            .map_or(0, |first| now.saturating_duration_since(first).as_micros())
            .min(u128::from(u64::MAX)) as u64,
    }
}

fn decode_endpoint(bytes: &[u8]) -> Result<EndpointId> {
    ensure!(bytes.len() == 32, "invalid endpoint id length");
    let bytes: &[u8; 32] = bytes.try_into().expect("length was checked");
    EndpointId::from_bytes(bytes).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use iroh::SecretKey;

    use super::*;

    fn endpoint(byte: u8) -> EndpointId {
        SecretKey::from_bytes(&[byte; 32]).public()
    }

    fn route() -> RouteKey {
        RouteKey {
            destination: endpoint(4),
            first_hop: endpoint(2),
        }
    }

    fn registration() -> DeliverySessionRegister {
        DeliverySessionRegister {
            session_id: 9,
            origin: endpoint(1),
            destination: endpoint(4),
            first_hop: endpoint(2),
            path_epoch: 3,
            forward_hops: vec![endpoint(1), endpoint(2), endpoint(4)],
        }
    }

    #[test]
    fn messages_round_trip_and_trailing_bytes_are_rejected() {
        let messages = [
            DeliveryMessage::Register(registration()),
            DeliveryMessage::Report(DeliveryReport {
                session_id: 9,
                origin: endpoint(1),
                destination: endpoint(4),
                path_epoch: 3,
                delivered_bytes: 500_000,
                delivered_packets: 400,
                duplicate_or_gap_count: 2,
                receiver_elapsed_micros: 50_000,
            }),
        ];
        for message in messages {
            let encoded = encode_delivery(&message).unwrap();
            assert_eq!(decode_delivery(&encoded).unwrap(), message);
            let mut trailing = encoded.to_vec();
            trailing.push(0);
            assert!(decode_delivery(&trailing).is_err());
        }
    }

    #[test]
    fn invalid_hop_list_and_zero_elapsed_are_rejected() {
        let mut register = registration();
        register.forward_hops.push(endpoint(2));
        assert!(validate_delivery(&DeliveryMessage::Register(register)).is_err());
        let report = DeliveryReport {
            session_id: 9,
            origin: endpoint(1),
            destination: endpoint(4),
            path_epoch: 3,
            delivered_bytes: 1,
            delivered_packets: 1,
            duplicate_or_gap_count: 0,
            receiver_elapsed_micros: 0,
        };
        assert!(validate_delivery(&DeliveryMessage::Report(report)).is_err());
    }

    #[test]
    fn receiver_aggregates_reports_and_deduplicates() {
        let now = Instant::now();
        let mut receiver = DeliveryReceiver::new(8);
        receiver.register(registration(), now).unwrap();
        assert!(
            receiver
                .observe(
                    DeliveryTag {
                        session_id: 9,
                        sequence: 0,
                    },
                    1_000,
                    now,
                )
                .is_none()
        );
        assert!(
            receiver
                .observe(
                    DeliveryTag {
                        session_id: 9,
                        sequence: 0,
                    },
                    1_000,
                    now,
                )
                .is_none()
        );
        let report = receiver
            .observe(
                DeliveryTag {
                    session_id: 9,
                    sequence: 2,
                },
                DELIVERY_REPORT_BYTES as usize,
                now + DELIVERY_REPORT_INTERVAL,
            )
            .unwrap();
        assert_eq!(report.delivered_packets, 2);
        assert_eq!(report.delivered_bytes, DELIVERY_REPORT_BYTES + 1_000);
        assert_eq!(report.duplicate_or_gap_count, 2);
        assert_eq!(report.receiver_elapsed_micros, 50_000);
    }

    #[test]
    fn receiver_sequence_tracking_is_fixed_size_and_wrap_aware() {
        assert!(std::mem::size_of::<SequenceWindow>() <= 1_040);

        let mut window = SequenceWindow::default();
        assert_eq!(window.observe(10), SequenceObservation::InOrder);
        assert_eq!(window.observe(12), SequenceObservation::Reordered);
        assert_eq!(window.observe(11), SequenceObservation::Reordered);
        assert_eq!(window.observe(11), SequenceObservation::Duplicate);

        let mut wrapping = SequenceWindow::default();
        assert_eq!(wrapping.observe(u32::MAX - 1), SequenceObservation::InOrder);
        assert_eq!(wrapping.observe(u32::MAX), SequenceObservation::InOrder);
        assert_eq!(wrapping.observe(0), SequenceObservation::InOrder);
        assert_eq!(wrapping.observe(u32::MAX), SequenceObservation::Duplicate);
    }

    #[test]
    fn receiver_sequence_tracking_stays_bounded_under_sustained_traffic() {
        let mut window = SequenceWindow::default();
        for sequence in 0..100_000 {
            assert_ne!(window.observe(sequence), SequenceObservation::Duplicate);
        }
        assert_eq!(window.observe(99_999), SequenceObservation::Duplicate);
        assert_eq!(
            window.observe(100_000 - DELIVERY_SEQUENCE_WINDOW as u32),
            SequenceObservation::Duplicate
        );
    }

    #[test]
    fn source_uses_cumulative_receiver_deltas() {
        let now = Instant::now();
        let mut source = DeliverySource::new(8);
        let registration = source
            .register(
                endpoint(1),
                route(),
                3,
                vec![endpoint(1), endpoint(2), endpoint(4)],
                now,
            )
            .unwrap();
        source.observe_queue(registration.session_id, true, now);
        let first = DeliveryReport {
            session_id: registration.session_id,
            origin: endpoint(1),
            destination: endpoint(4),
            path_epoch: 3,
            delivered_bytes: 500_000,
            delivered_packets: 400,
            duplicate_or_gap_count: 0,
            receiver_elapsed_micros: 50_000,
        };
        let observation = source
            .apply_report(&first, route(), 3, now + Duration::from_millis(50))
            .unwrap();
        assert_eq!(observation.delivered_bytes, 500_000);
        assert_eq!(observation.receiver_interval, Duration::from_millis(50));
        assert!(!observation.app_limited);

        let second = DeliveryReport {
            delivered_bytes: 800_000,
            delivered_packets: 640,
            receiver_elapsed_micros: 100_000,
            ..first
        };
        let observation = source
            .apply_report(&second, route(), 3, now + Duration::from_millis(100))
            .unwrap();
        assert_eq!(observation.delivered_bytes, 300_000);
        assert_eq!(observation.receiver_interval, Duration::from_millis(50));
    }

    #[test]
    fn route_or_epoch_mismatch_rejects_report_and_tag() {
        let now = Instant::now();
        let mut source = DeliverySource::new(8);
        let registration = source
            .register(
                endpoint(1),
                route(),
                3,
                vec![endpoint(1), endpoint(2), endpoint(4)],
                now,
            )
            .unwrap();
        assert!(
            source
                .next_tag(registration.session_id, route(), 4, now)
                .is_none()
        );
        let report = DeliveryReport {
            session_id: registration.session_id,
            origin: endpoint(1),
            destination: endpoint(4),
            path_epoch: 4,
            delivered_bytes: 1_000,
            delivered_packets: 1,
            duplicate_or_gap_count: 0,
            receiver_elapsed_micros: 1_000,
        };
        assert!(source.apply_report(&report, route(), 3, now).is_none());
    }

    #[test]
    fn app_limited_is_derived_from_route_queue_interval() {
        let now = Instant::now();
        let mut source = DeliverySource::new(8);
        let registration = source
            .register(
                endpoint(1),
                route(),
                3,
                vec![endpoint(1), endpoint(2), endpoint(4)],
                now,
            )
            .unwrap();
        let report = DeliveryReport {
            session_id: registration.session_id,
            origin: endpoint(1),
            destination: endpoint(4),
            path_epoch: 3,
            delivered_bytes: 1_000,
            delivered_packets: 1,
            duplicate_or_gap_count: 0,
            receiver_elapsed_micros: 1_000,
        };
        assert!(
            source
                .apply_report(&report, route(), 3, now + Duration::from_millis(1))
                .unwrap()
                .app_limited
        );
    }

    #[test]
    fn tables_are_ttl_and_capacity_bounded() {
        let now = Instant::now();
        let mut receiver = DeliveryReceiver::new(2);
        for index in 1..=8_u64 {
            let mut register = registration();
            register.session_id = index;
            receiver
                .register(register, now + Duration::from_millis(index))
                .unwrap();
            assert!(receiver.sessions.len() <= 2);
        }
        receiver.prune(now + DELIVERY_SESSION_TTL + Duration::from_secs(1));
        assert!(receiver.sessions.is_empty());
    }
}

//! Bounded active probes for complete overlay routes.
//!
//! Probe packets never enter the TUN, FEC, repair cache, or application
//! queues.  The source fixes a first hop and the Ready response fixes the
//! remaining overlay hop list for one short train.

use std::{
    cmp::Reverse,
    collections::BinaryHeap,
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

use anyhow::{Result, bail, ensure};
use bytes::Bytes;
use iroh::EndpointId;

use crate::capacity::{FRESH_TTL, RouteKey};
use crate::protocol::envelope::{Envelope, MessageType};

pub const MAX_PROBE_HOPS: usize = 16;
pub const MAX_PROBE_PACKET_COUNT: u16 = 256;
pub const MAX_PROBE_PAYLOAD_SIZE: u16 = 1_200;
pub const MAX_PROBE_BYTES: usize = 256 * 1024;
pub const MAX_PROBE_DURATION: Duration = Duration::from_millis(250);
pub const MAX_PROBE_ROUTES: usize = 4_096;
pub const INITIAL_RETRY: Duration = Duration::from_secs(2);
pub const MAX_RETRY: Duration = Duration::from_secs(5 * 60);
pub const COLD_REPROBE: Duration = Duration::from_secs(1);
pub const STABLE_REPROBE: Duration = Duration::from_secs(2 * 60);
const BUSY_RETRY: Duration = Duration::from_millis(50);
const MAX_CONCURRENT_PROBES: usize = 4;

const TYPE_START: u8 = 1;
const TYPE_READY: u8 = 2;
const TYPE_PACKET: u8 = 3;
const TYPE_REPORT: u8 = 4;
const FIXED_ID_FIELDS: usize = 1 + 8 + 32 + 32;

pub type ProbeId = u64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacityProbeStart {
    pub probe_id: ProbeId,
    pub origin: EndpointId,
    pub destination: EndpointId,
    pub packet_count: u16,
    pub payload_size: u16,
    pub hop_limit: u8,
    pub traversed_hops: Vec<EndpointId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacityProbeReady {
    pub probe_id: ProbeId,
    pub origin: EndpointId,
    pub destination: EndpointId,
    pub traversed_hops: Vec<EndpointId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacityProbePacket {
    pub probe_id: ProbeId,
    pub origin: EndpointId,
    pub destination: EndpointId,
    pub sequence: u16,
    pub packet_count: u16,
    pub planned_gap_micros: u32,
    pub forward_hops: Vec<EndpointId>,
    pub payload: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacityProbeReport {
    pub probe_id: ProbeId,
    pub origin: EndpointId,
    pub destination: EndpointId,
    pub received_packets: u16,
    pub received_bytes: u32,
    pub first_to_last_arrival_micros: u32,
    pub gap_expansion_per_mille: u16,
    pub loss_ppm: u32,
    pub traversed_hops: Vec<EndpointId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapacityProbeMessage {
    Start(CapacityProbeStart),
    Ready(CapacityProbeReady),
    Packet(CapacityProbePacket),
    Report(CapacityProbeReport),
}

impl CapacityProbeMessage {
    pub fn probe_id(&self) -> ProbeId {
        match self {
            Self::Start(message) => message.probe_id,
            Self::Ready(message) => message.probe_id,
            Self::Packet(message) => message.probe_id,
            Self::Report(message) => message.probe_id,
        }
    }
}

pub fn encode_probe(message: &CapacityProbeMessage) -> Result<Bytes> {
    validate_probe(message)?;
    let mut out = Vec::new();
    match message {
        CapacityProbeMessage::Start(message) => {
            encode_common(
                &mut out,
                TYPE_START,
                message.probe_id,
                message.origin,
                message.destination,
            );
            out.extend_from_slice(&message.packet_count.to_be_bytes());
            out.extend_from_slice(&message.payload_size.to_be_bytes());
            out.push(message.hop_limit);
            encode_hops(&mut out, &message.traversed_hops);
        }
        CapacityProbeMessage::Ready(message) => {
            encode_common(
                &mut out,
                TYPE_READY,
                message.probe_id,
                message.origin,
                message.destination,
            );
            encode_hops(&mut out, &message.traversed_hops);
        }
        CapacityProbeMessage::Packet(message) => {
            encode_common(
                &mut out,
                TYPE_PACKET,
                message.probe_id,
                message.origin,
                message.destination,
            );
            out.extend_from_slice(&message.sequence.to_be_bytes());
            out.extend_from_slice(&message.packet_count.to_be_bytes());
            out.extend_from_slice(&message.planned_gap_micros.to_be_bytes());
            encode_hops(&mut out, &message.forward_hops);
            out.extend_from_slice(&(message.payload.len() as u16).to_be_bytes());
            out.extend_from_slice(&message.payload);
        }
        CapacityProbeMessage::Report(message) => {
            encode_common(
                &mut out,
                TYPE_REPORT,
                message.probe_id,
                message.origin,
                message.destination,
            );
            out.extend_from_slice(&message.received_packets.to_be_bytes());
            out.extend_from_slice(&message.received_bytes.to_be_bytes());
            out.extend_from_slice(&message.first_to_last_arrival_micros.to_be_bytes());
            out.extend_from_slice(&message.gap_expansion_per_mille.to_be_bytes());
            out.extend_from_slice(&message.loss_ppm.to_be_bytes());
            encode_hops(&mut out, &message.traversed_hops);
        }
    }
    ensure!(out.len() <= MAX_PROBE_BYTES, "probe message exceeds budget");
    Envelope::new(MessageType::CapacityProbe, out).encode()
}

pub fn decode_probe(bytes: &[u8]) -> Result<CapacityProbeMessage> {
    if bytes.starts_with(crate::protocol::envelope::MAGIC) {
        let envelope = Envelope::decode(Bytes::copy_from_slice(bytes))?;
        ensure!(
            envelope.kind == MessageType::CapacityProbe,
            "V1 envelope does not contain a capacity probe"
        );
        return decode_probe(&envelope.payload);
    }
    ensure!(bytes.len() >= FIXED_ID_FIELDS, "truncated capacity probe");
    ensure!(
        bytes.len() <= MAX_PROBE_BYTES,
        "probe message exceeds budget"
    );
    let kind = bytes[0];
    let probe_id = u64::from_be_bytes(bytes[1..9].try_into().unwrap());
    let origin = decode_endpoint(&bytes[9..41])?;
    let destination = decode_endpoint(&bytes[41..73])?;
    let mut cursor = 73;
    let message = match kind {
        TYPE_START => {
            ensure!(cursor + 5 <= bytes.len(), "truncated probe start");
            let packet_count = read_u16(bytes, &mut cursor)?;
            let payload_size = read_u16(bytes, &mut cursor)?;
            let hop_limit = bytes[cursor];
            cursor += 1;
            let traversed_hops = decode_hops(bytes, &mut cursor)?;
            CapacityProbeMessage::Start(CapacityProbeStart {
                probe_id,
                origin,
                destination,
                packet_count,
                payload_size,
                hop_limit,
                traversed_hops,
            })
        }
        TYPE_READY => CapacityProbeMessage::Ready(CapacityProbeReady {
            probe_id,
            origin,
            destination,
            traversed_hops: decode_hops(bytes, &mut cursor)?,
        }),
        TYPE_PACKET => {
            ensure!(cursor + 8 <= bytes.len(), "truncated probe packet");
            let sequence = read_u16(bytes, &mut cursor)?;
            let packet_count = read_u16(bytes, &mut cursor)?;
            let planned_gap_micros = read_u32(bytes, &mut cursor)?;
            let forward_hops = decode_hops(bytes, &mut cursor)?;
            let payload_len = usize::from(read_u16(bytes, &mut cursor)?);
            ensure!(
                cursor + payload_len == bytes.len(),
                "probe payload length mismatch"
            );
            let payload = Bytes::copy_from_slice(&bytes[cursor..]);
            cursor = bytes.len();
            CapacityProbeMessage::Packet(CapacityProbePacket {
                probe_id,
                origin,
                destination,
                sequence,
                packet_count,
                planned_gap_micros,
                forward_hops,
                payload,
            })
        }
        TYPE_REPORT => {
            ensure!(cursor + 16 <= bytes.len(), "truncated probe report");
            let received_packets = read_u16(bytes, &mut cursor)?;
            let received_bytes = read_u32(bytes, &mut cursor)?;
            let first_to_last_arrival_micros = read_u32(bytes, &mut cursor)?;
            let gap_expansion_per_mille = read_u16(bytes, &mut cursor)?;
            let loss_ppm = read_u32(bytes, &mut cursor)?;
            let traversed_hops = decode_hops(bytes, &mut cursor)?;
            CapacityProbeMessage::Report(CapacityProbeReport {
                probe_id,
                origin,
                destination,
                received_packets,
                received_bytes,
                first_to_last_arrival_micros,
                gap_expansion_per_mille,
                loss_ppm,
                traversed_hops,
            })
        }
        _ => bail!("unknown capacity probe type"),
    };
    ensure!(cursor == bytes.len(), "trailing capacity probe bytes");
    validate_probe(&message)?;
    Ok(message)
}

pub fn validate_probe(message: &CapacityProbeMessage) -> Result<()> {
    let (origin, destination, hops) = match message {
        CapacityProbeMessage::Start(message) => {
            ensure!(
                (1..=MAX_PROBE_PACKET_COUNT).contains(&message.packet_count),
                "invalid probe packet count"
            );
            ensure!(
                (1..=MAX_PROBE_PAYLOAD_SIZE).contains(&message.payload_size),
                "invalid probe payload size"
            );
            ensure!(message.hop_limit > 0, "probe hop limit exhausted");
            ensure!(
                usize::from(message.packet_count) * usize::from(message.payload_size)
                    <= MAX_PROBE_BYTES,
                "probe train exceeds byte budget"
            );
            (message.origin, message.destination, &message.traversed_hops)
        }
        CapacityProbeMessage::Ready(message) => {
            (message.origin, message.destination, &message.traversed_hops)
        }
        CapacityProbeMessage::Packet(message) => {
            ensure!(
                (1..=MAX_PROBE_PACKET_COUNT).contains(&message.packet_count),
                "invalid probe packet count"
            );
            ensure!(
                message.sequence < message.packet_count,
                "probe sequence exceeds packet count"
            );
            ensure!(
                !message.payload.is_empty()
                    && message.payload.len() <= usize::from(MAX_PROBE_PAYLOAD_SIZE),
                "invalid probe payload size"
            );
            ensure!(
                usize::from(message.packet_count) * message.payload.len() <= MAX_PROBE_BYTES,
                "probe train exceeds byte budget"
            );
            ensure!(
                message.planned_gap_micros > 0
                    && Duration::from_micros(u64::from(message.planned_gap_micros))
                        * u32::from(message.packet_count)
                        <= MAX_PROBE_DURATION,
                "probe train exceeds duration budget"
            );
            (message.origin, message.destination, &message.forward_hops)
        }
        CapacityProbeMessage::Report(message) => {
            ensure!(
                message.received_packets <= MAX_PROBE_PACKET_COUNT,
                "invalid report packet count"
            );
            ensure!(
                usize::try_from(message.received_bytes).unwrap_or(usize::MAX) <= MAX_PROBE_BYTES,
                "report exceeds byte budget"
            );
            ensure!(message.loss_ppm <= 1_000_000, "invalid report loss");
            (message.origin, message.destination, &message.traversed_hops)
        }
    };
    ensure!(origin != destination, "probe origin equals destination");
    validate_hops(hops, origin, destination)
}

pub fn append_probe_hop(start: &mut CapacityProbeStart, local: EndpointId) -> Result<()> {
    ensure!(start.hop_limit > 0, "probe hop limit exhausted");
    ensure!(
        start.traversed_hops.len() < MAX_PROBE_HOPS,
        "probe hop list is full"
    );
    ensure!(
        local != start.origin && !start.traversed_hops.contains(&local),
        "probe route contains a loop"
    );
    start.traversed_hops.push(local);
    start.hop_limit -= 1;
    validate_probe(&CapacityProbeMessage::Start(start.clone()))
}

pub fn reverse_next_hop(hops: &[EndpointId], local: EndpointId) -> Option<EndpointId> {
    let index = hops.iter().position(|hop| *hop == local)?;
    index.checked_sub(1).map(|previous| hops[previous])
}

pub fn forward_next_hop(hops: &[EndpointId], local: EndpointId) -> Option<EndpointId> {
    let index = hops.iter().position(|hop| *hop == local)?;
    hops.get(index + 1).copied()
}

#[derive(Debug, Clone)]
pub struct ProbeBookkeeping {
    pub in_flight: Option<ProbeId>,
    pub next_due: Instant,
    pub failure_count: u8,
    pub active_samples: u64,
    pub passive_samples: u64,
    pub last_passive_sample: Option<Instant>,
    pub attempts_total: u64,
    pub failures_total: u64,
    pub bytes_total: u64,
    last_used: Instant,
    deadline_generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeRouteSnapshot {
    pub in_flight: bool,
    pub next_due_in: Duration,
    pub failure_count: u8,
    pub attempts_total: u64,
    pub failures_total: u64,
    pub bytes_total: u64,
}

#[derive(Debug, Clone, Default)]
pub struct ProbeStatusSnapshot {
    pub routes: HashMap<RouteKey, ProbeRouteSnapshot>,
    pub global_in_flight: bool,
    pub attempts_total: u64,
    pub failures_total: u64,
    pub bytes_total: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeRequest {
    pub route: RouteKey,
    pub probe_id: ProbeId,
}

#[derive(Debug)]
pub struct ActiveProbeScheduler {
    routes: HashMap<RouteKey, ProbeBookkeeping>,
    deadlines: BinaryHeap<Reverse<(Instant, u64, RouteKey)>>,
    in_flight: HashMap<ProbeId, ProbeRequest>,
    next_probe_id: ProbeId,
    capacity: usize,
}

impl Default for ActiveProbeScheduler {
    fn default() -> Self {
        Self::new(MAX_PROBE_ROUTES)
    }
}

impl ActiveProbeScheduler {
    pub fn new(capacity: usize) -> Self {
        Self {
            routes: HashMap::new(),
            deadlines: BinaryHeap::new(),
            in_flight: HashMap::new(),
            next_probe_id: 1,
            capacity: capacity.max(1),
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn register(&mut self, route: RouteKey, now: Instant) -> bool {
        if self.routes.contains_key(&route) {
            if let Some(bookkeeping) = self.routes.get_mut(&route) {
                bookkeeping.last_used = now;
            }
            return true;
        }
        if !self.make_room() {
            return false;
        }
        self.routes.insert(
            route,
            ProbeBookkeeping {
                in_flight: None,
                next_due: now,
                failure_count: 0,
                active_samples: 0,
                passive_samples: 0,
                last_passive_sample: None,
                attempts_total: 0,
                failures_total: 0,
                bytes_total: 0,
                last_used: now,
                deadline_generation: 0,
            },
        );
        self.reschedule(route);
        true
    }

    pub fn next(
        &mut self,
        now: Instant,
        first_hop_queue_busy: impl Fn(RouteKey) -> bool,
        bulk_busy: bool,
        priority_busy: bool,
    ) -> Option<ProbeRequest> {
        if self.in_flight.len() >= MAX_CONCURRENT_PROBES || bulk_busy || priority_busy {
            return None;
        }
        let route = loop {
            let Reverse((due, generation, route)) = self.deadlines.pop()?;
            let Some(state) = self.routes.get_mut(&route) else {
                continue;
            };
            if state.deadline_generation != generation || state.next_due != due {
                continue;
            }
            if due > now {
                self.deadlines.push(Reverse((due, generation, route)));
                return None;
            }
            if state.in_flight.is_some() {
                continue;
            }
            if let Some(sample) = state.last_passive_sample
                && now.saturating_duration_since(sample) <= FRESH_TTL
            {
                state.next_due = sample + FRESH_TTL + Duration::from_nanos(1);
                self.reschedule(route);
                continue;
            }
            if first_hop_queue_busy(route) {
                state.next_due = now + BUSY_RETRY;
                self.reschedule(route);
                continue;
            }
            if self
                .in_flight
                .values()
                .any(|active| active.route.first_hop == route.first_hop)
            {
                state.next_due = now + BUSY_RETRY;
                self.reschedule(route);
                continue;
            }
            break route;
        };
        let probe_id = self.next_probe_id;
        self.next_probe_id = self.next_probe_id.wrapping_add(1).max(1);
        let request = ProbeRequest { route, probe_id };
        let state = self.routes.get_mut(&route).expect("registered route");
        state.in_flight = Some(probe_id);
        state.attempts_total = state.attempts_total.saturating_add(1);
        state.last_used = now;
        self.in_flight.insert(probe_id, request);
        Some(request)
    }

    pub fn active_succeeded(&mut self, request: ProbeRequest, now: Instant) -> bool {
        if self.in_flight.get(&request.probe_id) != Some(&request) {
            return false;
        }
        let Some(state) = self.routes.get_mut(&request.route) else {
            self.in_flight.remove(&request.probe_id);
            return false;
        };
        if state.in_flight != Some(request.probe_id) {
            self.in_flight.remove(&request.probe_id);
            return false;
        }
        state.in_flight = None;
        state.failure_count = 0;
        state.active_samples = state.active_samples.saturating_add(1);
        state.next_due = now
            + if state.active_samples < 3 {
                COLD_REPROBE
            } else {
                STABLE_REPROBE
            };
        state.last_used = now;
        self.in_flight.remove(&request.probe_id);
        self.reschedule(request.route);
        true
    }

    pub fn failed(&mut self, request: ProbeRequest, now: Instant) -> bool {
        if self.in_flight.get(&request.probe_id) != Some(&request) {
            return false;
        }
        let Some(state) = self.routes.get_mut(&request.route) else {
            self.in_flight.remove(&request.probe_id);
            return false;
        };
        if state.in_flight != Some(request.probe_id) {
            self.in_flight.remove(&request.probe_id);
            return false;
        }
        state.in_flight = None;
        state.failure_count = state.failure_count.saturating_add(1);
        state.failures_total = state.failures_total.saturating_add(1);
        let shift = u32::from(state.failure_count.saturating_sub(1).min(8));
        let multiplier = 1_u32 << shift;
        state.next_due = now + INITIAL_RETRY.saturating_mul(multiplier).min(MAX_RETRY);
        state.last_used = now;
        self.in_flight.remove(&request.probe_id);
        self.reschedule(request.route);
        true
    }

    pub fn observe_passive(&mut self, route: RouteKey, now: Instant) {
        if !self.register(route, now) {
            return;
        }
        let state = self.routes.get_mut(&route).expect("registered route");
        state.passive_samples = state.passive_samples.saturating_add(1);
        state.last_passive_sample = Some(now);
        state.next_due = now + STABLE_REPROBE;
        state.last_used = now;
        self.reschedule(route);
    }

    pub fn record_bytes(&mut self, request: ProbeRequest, bytes: u64) -> bool {
        let Some(state) = self.routes.get_mut(&request.route) else {
            return false;
        };
        if state.in_flight != Some(request.probe_id) {
            return false;
        }
        state.bytes_total = state.bytes_total.saturating_add(bytes);
        true
    }

    pub fn invalidate(&mut self, route: RouteKey, now: Instant) {
        if !self.register(route, now) {
            return;
        }
        if let Some(probe_id) = self
            .in_flight
            .iter()
            .find_map(|(probe_id, request)| (request.route == route).then_some(*probe_id))
        {
            self.in_flight.remove(&probe_id);
        }
        let state = self.routes.get_mut(&route).expect("registered route");
        state.in_flight = None;
        state.next_due = now;
        state.last_passive_sample = None;
        state.last_used = now;
        self.reschedule(route);
    }

    pub fn bookkeeping(&self, route: &RouteKey) -> Option<&ProbeBookkeeping> {
        self.routes.get(route)
    }

    pub fn snapshot(&self, now: Instant) -> ProbeStatusSnapshot {
        let routes = self
            .routes
            .iter()
            .map(|(route, state)| {
                (
                    *route,
                    ProbeRouteSnapshot {
                        in_flight: state.in_flight.is_some(),
                        next_due_in: state.next_due.saturating_duration_since(now),
                        failure_count: state.failure_count,
                        attempts_total: state.attempts_total,
                        failures_total: state.failures_total,
                        bytes_total: state.bytes_total,
                    },
                )
            })
            .collect::<HashMap<_, _>>();
        ProbeStatusSnapshot {
            global_in_flight: !self.in_flight.is_empty(),
            attempts_total: self.routes.values().map(|state| state.attempts_total).sum(),
            failures_total: self.routes.values().map(|state| state.failures_total).sum(),
            bytes_total: self.routes.values().map(|state| state.bytes_total).sum(),
            routes,
        }
    }

    fn make_room(&mut self) -> bool {
        if self.routes.len() < self.capacity {
            return true;
        }
        if let Some(oldest) = self
            .routes
            .iter()
            .filter(|(_, state)| state.in_flight.is_none())
            .min_by_key(|(_, state)| state.last_used)
            .map(|(route, _)| *route)
        {
            self.routes.remove(&oldest);
            return true;
        }
        false
    }

    fn reschedule(&mut self, route: RouteKey) {
        let Some(state) = self.routes.get_mut(&route) else {
            return;
        };
        state.deadline_generation = state.deadline_generation.wrapping_add(1).max(1);
        self.deadlines
            .push(Reverse((state.next_due, state.deadline_generation, route)));
        // Generational entries make updates O(log N). Compact stale entries
        // before they can become an unbounded secondary table under repeated
        // invalidation/passive observations.
        if self.deadlines.len() > self.routes.len().saturating_mul(4).max(64) {
            self.deadlines = self
                .routes
                .iter()
                .filter(|(_, state)| state.in_flight.is_none())
                .map(|(route, state)| Reverse((state.next_due, state.deadline_generation, *route)))
                .collect();
        }
    }
}

#[derive(Debug)]
pub struct ProbeReceiver {
    expected_packets: u16,
    payload_size: u16,
    planned_gap: Duration,
    received: HashSet<u16>,
    received_bytes: u32,
    first_arrival: Option<Instant>,
    last_arrival: Option<Instant>,
}

impl ProbeReceiver {
    pub fn new(packet_count: u16, payload_size: u16, planned_gap: Duration) -> Result<Self> {
        ensure!(
            (1..=MAX_PROBE_PACKET_COUNT).contains(&packet_count),
            "invalid probe packet count"
        );
        ensure!(
            (1..=MAX_PROBE_PAYLOAD_SIZE).contains(&payload_size),
            "invalid probe payload size"
        );
        ensure!(!planned_gap.is_zero(), "invalid probe gap");
        ensure!(
            planned_gap * u32::from(packet_count) <= MAX_PROBE_DURATION,
            "probe train exceeds duration budget"
        );
        Ok(Self {
            expected_packets: packet_count,
            payload_size,
            planned_gap,
            received: HashSet::with_capacity(usize::from(packet_count)),
            received_bytes: 0,
            first_arrival: None,
            last_arrival: None,
        })
    }

    pub fn observe(&mut self, sequence: u16, bytes: usize, now: Instant) -> Result<bool> {
        ensure!(
            sequence < self.expected_packets,
            "probe sequence out of range"
        );
        ensure!(
            bytes == usize::from(self.payload_size),
            "probe payload mismatch"
        );
        if !self.received.insert(sequence) {
            return Ok(false);
        }
        self.received_bytes = self
            .received_bytes
            .saturating_add(u32::try_from(bytes).unwrap_or(u32::MAX));
        self.first_arrival.get_or_insert(now);
        self.last_arrival = Some(now);
        Ok(true)
    }

    pub fn is_complete(&self) -> bool {
        self.received.len() == usize::from(self.expected_packets)
    }

    pub fn report(
        &self,
        probe_id: ProbeId,
        origin: EndpointId,
        destination: EndpointId,
        traversed_hops: Vec<EndpointId>,
    ) -> CapacityProbeReport {
        let received_packets = self.received.len().min(usize::from(u16::MAX)) as u16;
        let span = self
            .first_arrival
            .zip(self.last_arrival)
            .map_or(Duration::ZERO, |(first, last)| {
                last.saturating_duration_since(first)
            });
        let expected_span = self
            .planned_gap
            .saturating_mul(u32::from(received_packets.saturating_sub(1)));
        let expansion = if expected_span.is_zero() {
            1_000
        } else {
            (span.as_nanos().saturating_mul(1_000) / expected_span.as_nanos())
                .min(u128::from(u16::MAX)) as u16
        };
        let lost = self.expected_packets.saturating_sub(received_packets);
        CapacityProbeReport {
            probe_id,
            origin,
            destination,
            received_packets,
            received_bytes: self.received_bytes,
            first_to_last_arrival_micros: span.as_micros().min(u128::from(u32::MAX)) as u32,
            gap_expansion_per_mille: expansion,
            loss_ppm: u32::from(lost) * 1_000_000 / u32::from(self.expected_packets),
            traversed_hops,
        }
    }
}

fn encode_common(
    out: &mut Vec<u8>,
    kind: u8,
    probe_id: ProbeId,
    origin: EndpointId,
    destination: EndpointId,
) {
    out.push(kind);
    out.extend_from_slice(&probe_id.to_be_bytes());
    out.extend_from_slice(origin.as_bytes());
    out.extend_from_slice(destination.as_bytes());
}

fn encode_hops(out: &mut Vec<u8>, hops: &[EndpointId]) {
    out.push(hops.len() as u8);
    for hop in hops {
        out.extend_from_slice(hop.as_bytes());
    }
}

fn decode_hops(bytes: &[u8], cursor: &mut usize) -> Result<Vec<EndpointId>> {
    ensure!(*cursor < bytes.len(), "truncated probe hop count");
    let count = usize::from(bytes[*cursor]);
    *cursor += 1;
    ensure!(count <= MAX_PROBE_HOPS, "probe hop list exceeds limit");
    ensure!(
        *cursor + count * 32 <= bytes.len(),
        "truncated probe hop list"
    );
    let mut hops = Vec::with_capacity(count);
    for _ in 0..count {
        hops.push(decode_endpoint(&bytes[*cursor..*cursor + 32])?);
        *cursor += 32;
    }
    Ok(hops)
}

fn validate_hops(hops: &[EndpointId], origin: EndpointId, destination: EndpointId) -> Result<()> {
    ensure!(
        !hops.is_empty() && hops.len() <= MAX_PROBE_HOPS,
        "invalid probe hop count"
    );
    ensure!(hops[0] == origin, "probe route does not start at origin");
    let mut unique = HashSet::with_capacity(hops.len());
    for hop in hops {
        ensure!(unique.insert(*hop), "probe route contains duplicate hop");
    }
    if hops.last() == Some(&destination) {
        return Ok(());
    }
    ensure!(
        !hops.contains(&destination),
        "probe destination appears before route end"
    );
    Ok(())
}

fn decode_endpoint(bytes: &[u8]) -> Result<EndpointId> {
    ensure!(bytes.len() == 32, "invalid endpoint id length");
    let bytes: &[u8; 32] = bytes.try_into().expect("length was checked");
    EndpointId::from_bytes(bytes).map_err(Into::into)
}

fn read_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16> {
    ensure!(*cursor + 2 <= bytes.len(), "truncated u16");
    let value = u16::from_be_bytes(bytes[*cursor..*cursor + 2].try_into().unwrap());
    *cursor += 2;
    Ok(value)
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32> {
    ensure!(*cursor + 4 <= bytes.len(), "truncated u32");
    let value = u32::from_be_bytes(bytes[*cursor..*cursor + 4].try_into().unwrap());
    *cursor += 4;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use iroh::SecretKey;

    use super::*;

    fn endpoint(byte: u8) -> EndpointId {
        SecretKey::from_bytes(&[byte; 32]).public()
    }

    fn start() -> CapacityProbeStart {
        CapacityProbeStart {
            probe_id: 7,
            origin: endpoint(1),
            destination: endpoint(4),
            packet_count: 32,
            payload_size: 1_000,
            hop_limit: 16,
            traversed_hops: vec![endpoint(1), endpoint(2)],
        }
    }

    fn messages() -> Vec<CapacityProbeMessage> {
        vec![
            CapacityProbeMessage::Start(start()),
            CapacityProbeMessage::Ready(CapacityProbeReady {
                probe_id: 7,
                origin: endpoint(1),
                destination: endpoint(4),
                traversed_hops: vec![endpoint(1), endpoint(2), endpoint(4)],
            }),
            CapacityProbeMessage::Packet(CapacityProbePacket {
                probe_id: 7,
                origin: endpoint(1),
                destination: endpoint(4),
                sequence: 3,
                packet_count: 32,
                planned_gap_micros: 500,
                forward_hops: vec![endpoint(1), endpoint(2), endpoint(4)],
                payload: Bytes::from(vec![9; 1_000]),
            }),
            CapacityProbeMessage::Report(CapacityProbeReport {
                probe_id: 7,
                origin: endpoint(1),
                destination: endpoint(4),
                received_packets: 31,
                received_bytes: 31_000,
                first_to_last_arrival_micros: 17_000,
                gap_expansion_per_mille: 1_100,
                loss_ppm: 31_250,
                traversed_hops: vec![endpoint(1), endpoint(2), endpoint(4)],
            }),
        ]
    }

    #[test]
    fn all_messages_round_trip() {
        for message in messages() {
            assert_eq!(
                decode_probe(&encode_probe(&message).unwrap()).unwrap(),
                message
            );
        }
    }

    #[test]
    fn decoder_rejects_truncated_and_trailing_messages() {
        for message in messages() {
            let encoded = encode_probe(&message).unwrap();
            assert!(decode_probe(&encoded[..encoded.len() - 1]).is_err());
            let mut trailing = encoded.to_vec();
            trailing.push(0);
            assert!(decode_probe(&trailing).is_err());
        }
    }

    #[test]
    fn budgets_and_sequence_are_enforced() {
        let mut invalid = start();
        invalid.packet_count = 0;
        assert!(validate_probe(&CapacityProbeMessage::Start(invalid)).is_err());
        let mut packet = match messages().remove(2) {
            CapacityProbeMessage::Packet(packet) => packet,
            _ => unreachable!(),
        };
        packet.sequence = packet.packet_count;
        assert!(validate_probe(&CapacityProbeMessage::Packet(packet)).is_err());

        let mut oversized_train = match messages().remove(2) {
            CapacityProbeMessage::Packet(packet) => packet,
            _ => unreachable!(),
        };
        oversized_train.sequence = 0;
        oversized_train.packet_count = MAX_PROBE_PACKET_COUNT;
        oversized_train.payload = Bytes::from(vec![0; usize::from(MAX_PROBE_PAYLOAD_SIZE)]);
        assert!(validate_probe(&CapacityProbeMessage::Packet(oversized_train)).is_err());
    }

    #[test]
    fn loop_and_hop_limit_are_rejected() {
        let mut probe = start();
        assert!(append_probe_hop(&mut probe, endpoint(2)).is_err());
        probe.hop_limit = 0;
        assert!(append_probe_hop(&mut probe, endpoint(3)).is_err());
    }

    #[test]
    fn fixed_hop_list_has_forward_and_reverse_neighbors() {
        let hops = vec![endpoint(1), endpoint(2), endpoint(4)];
        assert_eq!(forward_next_hop(&hops, endpoint(1)), Some(endpoint(2)));
        assert_eq!(forward_next_hop(&hops, endpoint(2)), Some(endpoint(4)));
        assert_eq!(reverse_next_hop(&hops, endpoint(4)), Some(endpoint(2)));
        assert_eq!(reverse_next_hop(&hops, endpoint(2)), Some(endpoint(1)));
    }

    #[test]
    fn receiver_deduplicates_and_reports_arrival_span() {
        let start = Instant::now();
        let mut receiver = ProbeReceiver::new(4, 1_000, Duration::from_millis(1)).unwrap();
        assert!(receiver.observe(0, 1_000, start).unwrap());
        assert!(!receiver.observe(0, 1_000, start).unwrap());
        assert!(
            receiver
                .observe(2, 1_000, start + Duration::from_millis(3))
                .unwrap()
        );
        let report = receiver.report(
            7,
            endpoint(1),
            endpoint(4),
            vec![endpoint(1), endpoint(2), endpoint(4)],
        );
        assert_eq!(report.received_packets, 2);
        assert_eq!(report.received_bytes, 2_000);
        assert_eq!(report.first_to_last_arrival_micros, 3_000);
        assert_eq!(report.loss_ppm, 500_000);
        assert_eq!(report.gap_expansion_per_mille, 3_000);
    }

    #[test]
    fn scheduler_runs_bounded_parallel_probes_and_skips_busy_routes() {
        let now = Instant::now();
        let route_a = RouteKey {
            destination: endpoint(4),
            first_hop: endpoint(2),
        };
        let route_b = RouteKey {
            destination: endpoint(4),
            first_hop: endpoint(3),
        };
        let mut scheduler = ActiveProbeScheduler::new(8);
        scheduler.register(route_a, now);
        scheduler.register(route_b, now);
        let request = scheduler
            .next(now, |route| route == route_a, false, false)
            .unwrap();
        assert_eq!(request.route, route_b);
        let second = scheduler
            .next(now + BUSY_RETRY, |_| false, false, false)
            .unwrap();
        assert_eq!(second.route, route_a);
        assert!(scheduler.active_succeeded(request, now));
        assert!(scheduler.active_succeeded(second, now));
    }

    #[test]
    fn scheduler_caps_parallelism_and_serializes_each_first_hop() {
        let now = Instant::now();
        let mut scheduler = ActiveProbeScheduler::new(8);
        for index in 1..=6 {
            scheduler.register(
                RouteKey {
                    destination: endpoint(index),
                    first_hop: endpoint(index + 10),
                },
                now,
            );
        }
        let requests = (0..MAX_CONCURRENT_PROBES)
            .map(|_| scheduler.next(now, |_| false, false, false).unwrap())
            .collect::<Vec<_>>();
        assert!(scheduler.next(now, |_| false, false, false).is_none());
        assert_eq!(scheduler.in_flight.len(), MAX_CONCURRENT_PROBES);
        for request in requests {
            assert!(scheduler.active_succeeded(request, now));
        }

        let shared_hop = endpoint(30);
        let routes = [
            RouteKey {
                destination: endpoint(20),
                first_hop: shared_hop,
            },
            RouteKey {
                destination: endpoint(21),
                first_hop: shared_hop,
            },
        ];
        let mut scheduler = ActiveProbeScheduler::new(2);
        for route in routes {
            scheduler.register(route, now);
        }
        let first = scheduler.next(now, |_| false, false, false).unwrap();
        assert!(scheduler.next(now, |_| false, false, false).is_none());
        assert!(scheduler.active_succeeded(first, now));
    }

    #[test]
    fn scheduler_failure_uses_bounded_exponential_backoff() {
        let now = Instant::now();
        let route = RouteKey {
            destination: endpoint(4),
            first_hop: endpoint(2),
        };
        let mut scheduler = ActiveProbeScheduler::new(8);
        scheduler.register(route, now);
        let first = scheduler.next(now, |_| false, false, false).unwrap();
        assert!(scheduler.failed(first, now));
        assert_eq!(
            scheduler.bookkeeping(&route).unwrap().next_due,
            now + INITIAL_RETRY
        );
        assert!(
            scheduler
                .next(
                    now + INITIAL_RETRY - Duration::from_nanos(1),
                    |_| false,
                    false,
                    false
                )
                .is_none()
        );
        let second = scheduler
            .next(now + INITIAL_RETRY, |_| false, false, false)
            .unwrap();
        assert!(scheduler.failed(second, now + INITIAL_RETRY));
        assert_eq!(
            scheduler.bookkeeping(&route).unwrap().next_due,
            now + INITIAL_RETRY + INITIAL_RETRY * 2
        );
        let snapshot = scheduler.snapshot(now + INITIAL_RETRY);
        let route_status = snapshot.routes.get(&route).unwrap();
        assert_eq!(route_status.attempts_total, 2);
        assert_eq!(route_status.failures_total, 2);
        assert_eq!(snapshot.attempts_total, 2);
        assert_eq!(snapshot.failures_total, 2);
    }

    #[test]
    fn scheduler_accounts_probe_bytes_only_for_the_in_flight_request() {
        let now = Instant::now();
        let route = RouteKey {
            destination: endpoint(4),
            first_hop: endpoint(2),
        };
        let mut scheduler = ActiveProbeScheduler::new(1);
        scheduler.register(route, now);
        let request = scheduler.next(now, |_| false, false, false).unwrap();
        assert!(scheduler.record_bytes(request, 64_000));
        assert!(!scheduler.record_bytes(
            ProbeRequest {
                probe_id: request.probe_id + 1,
                ..request
            },
            64_000
        ));
        assert_eq!(scheduler.snapshot(now).bytes_total, 64_000);
    }

    #[test]
    fn recent_passive_sample_suppresses_active_probe() {
        let now = Instant::now();
        let route = RouteKey {
            destination: endpoint(4),
            first_hop: endpoint(2),
        };
        let mut scheduler = ActiveProbeScheduler::new(8);
        scheduler.observe_passive(route, now);
        scheduler.invalidate(route, now + Duration::from_secs(1));
        scheduler.observe_passive(route, now + Duration::from_secs(1));
        assert!(
            scheduler
                .next(now + crate::capacity::STALE_TTL, |_| false, false, false,)
                .is_some()
        );
    }

    #[test]
    fn scheduler_table_is_bounded() {
        let now = Instant::now();
        let mut scheduler = ActiveProbeScheduler::new(2);
        for index in 1..=8 {
            scheduler.register(
                RouteKey {
                    destination: endpoint(index),
                    first_hop: endpoint(index + 20),
                },
                now + Duration::from_secs(u64::from(index)),
            );
            assert!(scheduler.len() <= 2);
        }
    }

    #[test]
    fn scheduler_refuses_to_evict_the_only_in_flight_route() {
        let now = Instant::now();
        let first = RouteKey {
            destination: endpoint(1),
            first_hop: endpoint(2),
        };
        let second = RouteKey {
            destination: endpoint(3),
            first_hop: endpoint(4),
        };
        let mut scheduler = ActiveProbeScheduler::new(1);
        assert!(scheduler.register(first, now));
        assert!(scheduler.next(now, |_| false, false, false).is_some());
        assert!(!scheduler.register(second, now));
        assert_eq!(scheduler.len(), 1);
        assert!(scheduler.bookkeeping(&first).is_some());
    }

    #[test]
    fn successful_cold_route_is_reprobed_quickly_three_times() {
        let now = Instant::now();
        let route = RouteKey {
            destination: endpoint(4),
            first_hop: endpoint(2),
        };
        let mut scheduler = ActiveProbeScheduler::new(1);
        assert!(scheduler.register(route, now));
        for sample in 1..=3 {
            let at = now + COLD_REPROBE * (sample - 1);
            let request = scheduler.next(at, |_| false, false, false).unwrap();
            assert!(scheduler.active_succeeded(request, at));
            let expected = if sample < 3 {
                at + COLD_REPROBE
            } else {
                at + STABLE_REPROBE
            };
            assert_eq!(scheduler.bookkeeping(&route).unwrap().next_due, expected);
        }
    }

    #[test]
    fn scheduler_survives_a_simulated_24_hour_soak_with_bounded_work() {
        const ROUTES: u8 = 64;
        const SOAK_SECONDS: u64 = 24 * 60 * 60;
        const TRAIN_BYTES: u64 = 64_000;

        let started_at = Instant::now();
        let routes = (1..=ROUTES)
            .map(|index| RouteKey {
                destination: endpoint(index),
                first_hop: endpoint(index.wrapping_add(96)),
            })
            .collect::<Vec<_>>();
        let mut scheduler = ActiveProbeScheduler::new(usize::from(ROUTES));
        for route in &routes {
            assert!(scheduler.register(*route, started_at));
        }

        let mut completed = 0_u64;
        for second in 0..=SOAK_SECONDS {
            let now = started_at + Duration::from_secs(second);
            // Exercise passive suppression and LRU timestamp updates throughout
            // the accelerated soak rather than only the active-success path.
            if second > 0 && second % 997 == 0 {
                let index = (second as usize / 997) % routes.len();
                scheduler.observe_passive(routes[index], now);
            }
            for _ in 0..MAX_CONCURRENT_PROBES {
                let Some(request) = scheduler.next(now, |_| false, false, false) else {
                    break;
                };
                assert!(scheduler.record_bytes(request, TRAIN_BYTES));
                completed += 1;
                if completed.is_multiple_of(17) {
                    assert!(scheduler.failed(request, now));
                } else {
                    assert!(scheduler.active_succeeded(request, now));
                }
            }

            assert_eq!(scheduler.len(), usize::from(ROUTES));
            assert!(!scheduler.snapshot(now).global_in_flight);
        }

        let snapshot = scheduler.snapshot(started_at + Duration::from_secs(SOAK_SECONDS));
        assert!(snapshot.attempts_total > u64::from(ROUTES) * 100);
        assert_eq!(snapshot.failures_total, snapshot.attempts_total / 17);
        assert_eq!(snapshot.bytes_total, snapshot.attempts_total * TRAIN_BYTES);
        assert!(
            snapshot.attempts_total
                <= (SOAK_SECONDS + 1) * u64::try_from(MAX_CONCURRENT_PROBES).unwrap()
        );
        assert!(snapshot.routes.values().all(|route| !route.in_flight));
    }
}

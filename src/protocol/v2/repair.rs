use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

use anyhow::{Result, ensure};
use bytes::{BufMut, Bytes, BytesMut};
use rustc_hash::FxHashMap as HashMap;

use super::cell::{CellBody, CellV2, MAX_CELL_BYTES, TrafficClass};

const REQUEST_MAGIC: &[u8; 4] = b"FRQ2";
const RESPONSE_MAGIC: &[u8; 4] = b"FRS2";
const FIXED_KEY_BYTES: usize = 25;
pub const MAX_REPAIR_CELLS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RepairKeyV2 {
    pub class: TrafficClass,
    pub session_epoch: u32,
    pub route_label: u32,
    pub train_id: u64,
    pub stripe_id: u32,
}

impl RepairKeyV2 {
    fn encode_into(self, output: &mut BytesMut) {
        output.put_u8(self.class as u8);
        output.put_u32(self.session_epoch);
        output.put_u32(self.route_label);
        output.put_u64(self.train_id);
        output.put_u32(self.stripe_id);
        output.put_u32(0);
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() >= FIXED_KEY_BYTES, "truncated V2 Repair key");
        let class = match bytes[0] {
            1 => TrafficClass::Latency,
            2 => TrafficClass::Bulk,
            value => anyhow::bail!("unknown V2 Repair traffic class {value}"),
        };
        let key = Self {
            class,
            session_epoch: u32::from_be_bytes(bytes[1..5].try_into().unwrap()),
            route_label: u32::from_be_bytes(bytes[5..9].try_into().unwrap()),
            train_id: u64::from_be_bytes(bytes[9..17].try_into().unwrap()),
            stripe_id: u32::from_be_bytes(bytes[17..21].try_into().unwrap()),
        };
        ensure!(bytes[21..25] == [0; 4], "unsupported V2 Repair key flags");
        ensure!(key.session_epoch != 0, "V2 Repair epoch zero is reserved");
        ensure!(
            key.route_label != 0,
            "V2 Repair route label zero is reserved"
        );
        ensure!(key.train_id != 0, "V2 Repair train id zero is reserved");
        ensure!(key.stripe_id != 0, "V2 Repair stripe id zero is reserved");
        Ok(key)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairRequestV2 {
    pub key: RepairKeyV2,
    pub request_id: u64,
    pub missing_sequences: Vec<u16>,
}

impl RepairRequestV2 {
    pub fn encode(&self) -> Result<Bytes> {
        validate_sequences(&self.missing_sequences)?;
        ensure!(
            self.request_id != 0,
            "V2 Repair request id zero is reserved"
        );
        let mut output =
            BytesMut::with_capacity(4 + FIXED_KEY_BYTES + 12 + self.missing_sequences.len() * 2);
        output.extend_from_slice(REQUEST_MAGIC);
        self.key.encode_into(&mut output);
        output.put_u64(self.request_id);
        output.put_u16(self.missing_sequences.len() as u16);
        output.put_u16(0);
        for sequence in &self.missing_sequences {
            output.put_u16(*sequence);
        }
        Ok(output.freeze())
    }

    pub fn decode(bytes: Bytes) -> Result<Self> {
        ensure!(
            bytes.len() >= 4 + FIXED_KEY_BYTES + 12,
            "truncated V2 Repair request"
        );
        ensure!(
            &bytes[..4] == REQUEST_MAGIC,
            "invalid V2 Repair request magic"
        );
        let key = RepairKeyV2::decode(&bytes[4..4 + FIXED_KEY_BYTES])?;
        let cursor = 4 + FIXED_KEY_BYTES;
        let request_id = u64::from_be_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
        ensure!(request_id != 0, "V2 Repair request id zero is reserved");
        let count = usize::from(u16::from_be_bytes(
            bytes[cursor + 8..cursor + 10].try_into().unwrap(),
        ));
        ensure!(
            bytes[cursor + 10..cursor + 12] == [0; 2],
            "unsupported V2 Repair request flags"
        );
        ensure!(
            bytes.len() == cursor + 12 + count * 2,
            "invalid V2 Repair request length"
        );
        let missing_sequences = bytes[cursor + 12..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|value| u16::from_be_bytes(*value))
            .collect::<Vec<_>>();
        validate_sequences(&missing_sequences)?;
        Ok(Self {
            key,
            request_id,
            missing_sequences,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairResponseV2 {
    pub key: RepairKeyV2,
    pub request_id: u64,
    pub cells: Vec<Bytes>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepairControlV2 {
    Request(RepairRequestV2),
    Response(RepairResponseV2),
}

impl RepairControlV2 {
    pub fn is_request(bytes: &[u8]) -> bool {
        bytes.starts_with(REQUEST_MAGIC)
    }

    pub fn is_response(bytes: &[u8]) -> bool {
        bytes.starts_with(RESPONSE_MAGIC)
    }

    pub fn decode(bytes: Bytes) -> Result<Self> {
        ensure!(bytes.len() >= 4, "truncated V2 Repair control record");
        match &bytes[..4] {
            magic if magic == REQUEST_MAGIC => Ok(Self::Request(RepairRequestV2::decode(bytes)?)),
            magic if magic == RESPONSE_MAGIC => {
                Ok(Self::Response(RepairResponseV2::decode(bytes)?))
            }
            _ => anyhow::bail!("unknown V2 Repair control record"),
        }
    }
}

impl RepairResponseV2 {
    pub fn encode(&self) -> Result<Bytes> {
        ensure!(
            self.request_id != 0,
            "V2 Repair response id zero is reserved"
        );
        ensure!(
            self.cells.len() <= MAX_REPAIR_CELLS,
            "too many V2 Repair response Cells"
        );
        let capacity = self
            .cells
            .iter()
            .try_fold(4 + FIXED_KEY_BYTES + 12, |total, cell| {
                total
                    .checked_add(2 + cell.len())
                    .ok_or_else(|| anyhow::anyhow!("V2 Repair response length overflow"))
            })?;
        let mut output = BytesMut::with_capacity(capacity);
        output.extend_from_slice(RESPONSE_MAGIC);
        self.key.encode_into(&mut output);
        output.put_u64(self.request_id);
        output.put_u16(self.cells.len() as u16);
        output.put_u16(0);
        for bytes in &self.cells {
            ensure!(
                !bytes.is_empty() && bytes.len() <= MAX_CELL_BYTES,
                "invalid repaired V2 Cell length"
            );
            validate_cell(self.key, bytes)?;
            output.put_u16(bytes.len() as u16);
            output.extend_from_slice(bytes);
        }
        Ok(output.freeze())
    }

    pub fn decode(bytes: Bytes) -> Result<Self> {
        ensure!(
            bytes.len() >= 4 + FIXED_KEY_BYTES + 12,
            "truncated V2 Repair response"
        );
        ensure!(
            &bytes[..4] == RESPONSE_MAGIC,
            "invalid V2 Repair response magic"
        );
        let key = RepairKeyV2::decode(&bytes[4..4 + FIXED_KEY_BYTES])?;
        let mut cursor = 4 + FIXED_KEY_BYTES;
        let request_id = u64::from_be_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
        ensure!(request_id != 0, "V2 Repair response id zero is reserved");
        let count = usize::from(u16::from_be_bytes(
            bytes[cursor + 8..cursor + 10].try_into().unwrap(),
        ));
        ensure!(count <= MAX_REPAIR_CELLS, "too many V2 repaired Cells");
        ensure!(
            bytes[cursor + 10..cursor + 12] == [0; 2],
            "unsupported V2 Repair response flags"
        );
        cursor += 12;
        let mut cells = Vec::with_capacity(count);
        for _ in 0..count {
            ensure!(
                cursor + 2 <= bytes.len(),
                "truncated V2 repaired Cell length"
            );
            let length = usize::from(u16::from_be_bytes(
                bytes[cursor..cursor + 2].try_into().unwrap(),
            ));
            cursor += 2;
            ensure!(
                length > 0 && cursor + length <= bytes.len(),
                "truncated V2 repaired Cell"
            );
            let cell = bytes.slice(cursor..cursor + length);
            validate_cell(key, &cell)?;
            cells.push(cell);
            cursor += length;
        }
        ensure!(cursor == bytes.len(), "trailing V2 Repair response bytes");
        Ok(Self {
            key,
            request_id,
            cells,
        })
    }
}

fn validate_sequences(sequences: &[u16]) -> Result<()> {
    ensure!(
        !sequences.is_empty() && sequences.len() <= MAX_REPAIR_CELLS,
        "invalid V2 Repair missing Cell count"
    );
    ensure!(
        sequences.windows(2).all(|pair| pair[0] < pair[1]),
        "V2 Repair Cell sequences are not strictly increasing"
    );
    Ok(())
}

fn validate_cell(key: RepairKeyV2, bytes: &Bytes) -> Result<()> {
    let cell = CellV2::decode(bytes.clone())?;
    ensure!(
        cell.class == key.class
            && cell.session_epoch == key.session_epoch
            && cell.route_label == key.route_label
            && cell.train_id == key.train_id
            && cell.stripe_id == key.stripe_id
            && matches!(cell.body, CellBody::Records(_)),
        "repaired V2 Cell identity mismatch"
    );
    Ok(())
}

#[derive(Debug)]
struct CachedStripe {
    created: Instant,
    cells: HashMap<u16, Bytes>,
    bytes: usize,
}

#[derive(Debug)]
pub struct RepairCacheV2 {
    ttl: Duration,
    maximum_bytes: usize,
    maximum_stripes: usize,
    stripes: HashMap<RepairKeyV2, CachedStripe>,
    order: VecDeque<(RepairKeyV2, Instant)>,
    bytes: usize,
}

impl RepairCacheV2 {
    pub fn new(ttl: Duration, maximum_bytes: usize, maximum_stripes: usize) -> Result<Self> {
        ensure!(!ttl.is_zero(), "V2 Repair cache TTL is zero");
        ensure!(maximum_stripes > 0, "V2 Repair cache stripe limit is zero");
        Ok(Self {
            ttl,
            maximum_bytes,
            maximum_stripes,
            stripes: HashMap::default(),
            order: VecDeque::new(),
            bytes: 0,
        })
    }

    pub fn insert(&mut self, cells: impl IntoIterator<Item = Bytes>) -> Result<usize> {
        self.insert_at(cells, Instant::now())
    }

    pub fn insert_at(
        &mut self,
        cells: impl IntoIterator<Item = Bytes>,
        now: Instant,
    ) -> Result<usize> {
        self.expire(now);
        let mut grouped = HashMap::<RepairKeyV2, HashMap<u16, Bytes>>::default();
        for bytes in cells {
            let cell = CellV2::decode(bytes.clone())?;
            if cell.stripe_id == 0 || !matches!(cell.body, CellBody::Records(_)) {
                continue;
            }
            let key = RepairKeyV2 {
                class: cell.class,
                session_epoch: cell.session_epoch,
                route_label: cell.route_label,
                train_id: cell.train_id,
                stripe_id: cell.stripe_id,
            };
            grouped
                .entry(key)
                .or_default()
                .insert(cell.cell_sequence, bytes);
        }
        let mut inserted = 0;
        for (key, cells) in grouped {
            let bytes = cells.values().map(Bytes::len).sum::<usize>();
            if bytes > self.maximum_bytes {
                continue;
            }
            self.remove(key);
            while (self.bytes.saturating_add(bytes) > self.maximum_bytes
                || self.stripes.len() >= self.maximum_stripes)
                && self.evict_oldest()
            {}
            if self.bytes.saturating_add(bytes) > self.maximum_bytes
                || self.stripes.len() >= self.maximum_stripes
            {
                continue;
            }
            self.stripes.insert(
                key,
                CachedStripe {
                    created: now,
                    cells,
                    bytes,
                },
            );
            self.order.push_back((key, now));
            self.bytes += bytes;
            inserted += 1;
        }
        Ok(inserted)
    }

    pub fn respond(&mut self, request: &RepairRequestV2) -> RepairResponseV2 {
        self.expire(Instant::now());
        let cells = self
            .stripes
            .get(&request.key)
            .map_or_else(Vec::new, |stripe| {
                request
                    .missing_sequences
                    .iter()
                    .filter_map(|sequence| stripe.cells.get(sequence).cloned())
                    .collect()
            });
        RepairResponseV2 {
            key: request.key,
            request_id: request.request_id,
            cells,
        }
    }

    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn stripes(&self) -> usize {
        self.stripes.len()
    }

    pub fn resize(&mut self, maximum_bytes: usize) {
        self.expire(Instant::now());
        self.maximum_bytes = maximum_bytes;
        // A lower automatic target governs new admission, but Cells already
        // advertised as repairable must survive their original TTL. Eagerly
        // evicting them when FEC is disabled turns every in-flight request
        // into an empty response and creates a loss-correlated control burst.
        // The cache remains bounded by its previous limit and converges to the
        // new target through expiry or the next protected insertion.
    }

    /// Change the retention horizon. Entries keep their original admission
    /// instant, so the new TTL applies to everything cached on the next
    /// `expire` pass: a shorter horizon evicts sooner, a longer one relaxes
    /// expiry for existing and future entries alike.
    pub fn set_ttl(&mut self, ttl: Duration) {
        if !ttl.is_zero() {
            self.ttl = ttl;
        }
    }

    pub fn expire(&mut self, now: Instant) -> usize {
        let mut expired = 0;
        while let Some(&(key, generation)) = self.order.front() {
            let stale = self.stripes.get(&key).is_none_or(|stripe| {
                stripe.created != generation
                    || now.saturating_duration_since(stripe.created) >= self.ttl
            });
            if !stale {
                break;
            }
            self.order.pop_front();
            if self
                .stripes
                .get(&key)
                .is_some_and(|stripe| stripe.created == generation)
            {
                self.remove(key);
                expired += 1;
            }
        }
        expired
    }

    fn evict_oldest(&mut self) -> bool {
        while let Some((key, generation)) = self.order.pop_front() {
            if self
                .stripes
                .get(&key)
                .is_some_and(|stripe| stripe.created == generation)
            {
                self.remove(key);
                return true;
            }
        }
        false
    }

    fn remove(&mut self, key: RepairKeyV2) {
        if let Some(stripe) = self.stripes.remove(&key) {
            self.bytes = self.bytes.saturating_sub(stripe.bytes);
        }
        self.order.retain(|(candidate, _)| candidate != &key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::v2::{
        fec::{CellStripeEncoder, FecGeometryV2, protected_cell_maximum},
        train::{TrainContext, TrainRecord, build_packet_train},
    };

    fn systematic() -> Vec<Bytes> {
        let maximum = protected_cell_maximum(1382, 4).unwrap();
        let train = build_packet_train(
            TrainContext {
                class: TrafficClass::Bulk,
                session_epoch: 7,
                route_label: 9,
                overlay_hop_limit: 64,
                train_id: 11,
                maximum_datagram_size: maximum,
                maximum_cells: 64,
            },
            (1..=4).map(|record_id| TrainRecord {
                record_id,
                metadata: Bytes::new(),
                data: Bytes::from(vec![record_id as u8; 1200]),
            }),
        )
        .unwrap();
        CellStripeEncoder::new(FecGeometryV2 {
            data_cells: 4,
            parity_cells: 1,
        })
        .unwrap()
        .encode(train.cells, 1382)
        .unwrap()
        .systematic
    }

    #[test]
    fn request_and_response_round_trip_strictly() {
        let cells = systematic();
        let first = CellV2::decode(cells[0].clone()).unwrap();
        let key = RepairKeyV2 {
            class: first.class,
            session_epoch: first.session_epoch,
            route_label: first.route_label,
            train_id: first.train_id,
            stripe_id: first.stripe_id,
        };
        let request = RepairRequestV2 {
            key,
            request_id: 5,
            missing_sequences: vec![1, 2],
        };
        let encoded_request = request.encode().unwrap();
        assert!(RepairControlV2::is_request(&encoded_request));
        assert!(!RepairControlV2::is_response(&encoded_request));
        assert_eq!(RepairRequestV2::decode(encoded_request).unwrap(), request);
        let response = RepairResponseV2 {
            key,
            request_id: 5,
            cells: cells[1..=2].to_vec(),
        };
        let encoded_response = response.encode().unwrap();
        assert!(!RepairControlV2::is_request(&encoded_response));
        assert!(RepairControlV2::is_response(&encoded_response));
        assert_eq!(
            RepairResponseV2::decode(encoded_response).unwrap(),
            response
        );
        assert!(!RepairControlV2::is_request(b"FRQ"));
        assert!(!RepairControlV2::is_response(b"FRS"));
    }

    #[test]
    fn cache_is_stripe_scoped_bounded_and_expires() {
        let cells = systematic();
        let first = CellV2::decode(cells[0].clone()).unwrap();
        let key = RepairKeyV2 {
            class: first.class,
            session_epoch: first.session_epoch,
            route_label: first.route_label,
            train_id: first.train_id,
            stripe_id: first.stripe_id,
        };
        let now = Instant::now();
        let mut cache = RepairCacheV2::new(Duration::from_millis(10), 64 * 1024, 2).unwrap();
        assert_eq!(cache.insert_at(cells.clone(), now).unwrap(), 1);
        let response = cache.respond(&RepairRequestV2 {
            key,
            request_id: 9,
            missing_sequences: vec![1, 3],
        });
        assert_eq!(response.cells.len(), 2);
        assert!(cache.bytes() > 0);
        assert_eq!(cache.expire(now + Duration::from_millis(10)), 1);
        assert_eq!(cache.bytes(), 0);
        assert_eq!(cache.stripes(), 0);
    }

    #[test]
    fn cache_shrink_preserves_already_advertised_cells_until_ttl() {
        let cells = systematic();
        let first = CellV2::decode(cells[0].clone()).unwrap();
        let key = RepairKeyV2 {
            class: first.class,
            session_epoch: first.session_epoch,
            route_label: first.route_label,
            train_id: first.train_id,
            stripe_id: first.stripe_id,
        };
        let now = Instant::now();
        let mut cache = RepairCacheV2::new(Duration::from_millis(10), 64 * 1024, 2).unwrap();
        cache.insert_at(cells, now).unwrap();
        let retained_bytes = cache.bytes();

        cache.resize(0);
        assert_eq!(cache.bytes(), retained_bytes);
        assert_eq!(
            cache
                .respond(&RepairRequestV2 {
                    key,
                    request_id: 10,
                    missing_sequences: vec![1],
                })
                .cells
                .len(),
            1
        );
        assert_eq!(cache.expire(now + Duration::from_millis(10)), 1);
        assert_eq!(cache.bytes(), 0);
    }

    #[test]
    fn cache_set_ttl_applies_on_the_next_expire_pass() {
        let cells = systematic();
        let now = Instant::now();
        let mut cache = RepairCacheV2::new(Duration::from_millis(10), 64 * 1024, 2).unwrap();
        cache.insert_at(cells, now).unwrap();
        // A longer horizon retains what the old TTL would have dropped.
        cache.set_ttl(Duration::from_secs(30));
        assert_eq!(cache.expire(now + Duration::from_millis(10)), 0);
        assert!(cache.bytes() > 0);
        // A shorter horizon evicts on the next sweep, and a zero TTL is
        // rejected as meaningless for a repair cache.
        cache.set_ttl(Duration::from_millis(20));
        cache.set_ttl(Duration::ZERO);
        assert_eq!(cache.expire(now + Duration::from_millis(20)), 1);
        assert_eq!(cache.bytes(), 0);
    }

    #[test]
    fn malformed_or_cross_stripe_repair_is_rejected() {
        let request = RepairRequestV2 {
            key: RepairKeyV2 {
                class: TrafficClass::Bulk,
                session_epoch: 1,
                route_label: 2,
                train_id: 3,
                stripe_id: 4,
            },
            request_id: 1,
            missing_sequences: vec![2, 2],
        };
        assert!(request.encode().is_err());

        let cells = systematic();
        let cell = CellV2::decode(cells[0].clone()).unwrap();
        let response = RepairResponseV2 {
            key: RepairKeyV2 {
                class: cell.class,
                session_epoch: cell.session_epoch,
                route_label: cell.route_label,
                train_id: cell.train_id + 1,
                stripe_id: cell.stripe_id,
            },
            request_id: 1,
            cells: vec![cells[0].clone()],
        };
        assert!(response.encode().is_err());
    }
}

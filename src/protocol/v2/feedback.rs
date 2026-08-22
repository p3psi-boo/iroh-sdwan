use anyhow::{Result, ensure};
use bytes::{BufMut, Bytes, BytesMut};

const MAGIC: &[u8; 4] = b"FBV2";
const LEGACY_WIRE_LEN: usize = 84;
const WIRE_LEN: usize = 148;

/// Authenticated cumulative receive-side effectiveness counters. The peer
/// uses deltas between reports to tune protection for the direction it sends;
/// local RX measurements are never incorrectly applied to the opposite path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FecFeedbackV2 {
    pub sequence: u64,
    pub parity_received: u64,
    pub recovered_cells: u64,
    pub wasted_parity: u64,
    pub repair_requested_cells: u64,
    pub repair_received_cells: u64,
    /// Number of Repair responses matched to an outstanding request. Empty
    /// responses count too: they are essential evidence that the sender's
    /// Repair cache could not satisfy the request.
    pub repair_completed_requests: u64,
    /// Requested Cell count belonging only to matched responses. Unlike the
    /// total request counter, this denominator is interval-aligned with
    /// `repair_received_cells` even when a response crosses a feedback tick.
    pub repair_completed_requested_cells: u64,
    /// Cumulative request-to-response latency for matched Repair responses.
    pub repair_latency_micros: u64,
    pub expired_stripes: u64,
    pub delivered_payload_bytes: u64,
    pub reorder_cells: u64,
    pub missing_cells: u64,
    pub loss_run_1: u64,
    pub loss_run_2: u64,
    pub loss_run_3_4: u64,
    pub loss_run_5_plus: u64,
    pub reassembly_expired_trains: u64,
}

impl FecFeedbackV2 {
    pub fn is_record(bytes: &[u8]) -> bool {
        bytes.starts_with(MAGIC)
    }

    pub fn encode(self) -> Result<Bytes> {
        ensure!(
            self.sequence != 0,
            "V2 FEC feedback sequence zero is reserved"
        );
        let mut output = BytesMut::with_capacity(WIRE_LEN);
        output.extend_from_slice(MAGIC);
        output.put_u64(self.sequence);
        output.put_u64(self.parity_received);
        output.put_u64(self.recovered_cells);
        output.put_u64(self.wasted_parity);
        output.put_u64(self.repair_requested_cells);
        output.put_u64(self.repair_received_cells);
        output.put_u64(self.repair_completed_requests);
        output.put_u64(self.repair_completed_requested_cells);
        output.put_u64(self.repair_latency_micros);
        output.put_u64(self.expired_stripes);
        output.put_u64(self.delivered_payload_bytes);
        output.put_u64(self.reorder_cells);
        output.put_u64(self.missing_cells);
        output.put_u64(self.loss_run_1);
        output.put_u64(self.loss_run_2);
        output.put_u64(self.loss_run_3_4);
        output.put_u64(self.loss_run_5_plus);
        output.put_u64(self.reassembly_expired_trains);
        debug_assert_eq!(output.len(), WIRE_LEN);
        Ok(output.freeze())
    }

    pub fn decode(bytes: Bytes) -> Result<Self> {
        ensure!(
            matches!(bytes.len(), LEGACY_WIRE_LEN | WIRE_LEN),
            "invalid V2 FEC feedback length"
        );
        ensure!(&bytes[..4] == MAGIC, "invalid V2 FEC feedback magic");
        let mut cursor = 4;
        let mut next = || {
            let value = u64::from_be_bytes(bytes[cursor..cursor + 8].try_into().unwrap());
            cursor += 8;
            value
        };
        let mut feedback = Self {
            sequence: next(),
            parity_received: next(),
            recovered_cells: next(),
            wasted_parity: next(),
            repair_requested_cells: next(),
            repair_received_cells: next(),
            repair_completed_requests: next(),
            repair_completed_requested_cells: next(),
            repair_latency_micros: next(),
            expired_stripes: next(),
            ..Self::default()
        };
        if bytes.len() == WIRE_LEN {
            feedback.delivered_payload_bytes = next();
            feedback.reorder_cells = next();
            feedback.missing_cells = next();
            feedback.loss_run_1 = next();
            feedback.loss_run_2 = next();
            feedback.loss_run_3_4 = next();
            feedback.loss_run_5_plus = next();
            feedback.reassembly_expired_trains = next();
        }
        ensure!(
            feedback.sequence != 0,
            "V2 FEC feedback sequence zero is reserved"
        );
        Ok(feedback)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feedback_round_trips_and_is_identifiable() {
        let expected = FecFeedbackV2 {
            sequence: 9,
            parity_received: 100,
            recovered_cells: 7,
            wasted_parity: 81,
            repair_requested_cells: 4,
            repair_received_cells: 3,
            repair_completed_requests: 2,
            repair_completed_requested_cells: 4,
            repair_latency_micros: 54_321,
            expired_stripes: 2,
            delivered_payload_bytes: 8_000_000,
            reorder_cells: 11,
            missing_cells: 13,
            loss_run_1: 3,
            loss_run_2: 2,
            loss_run_3_4: 1,
            loss_run_5_plus: 4,
            reassembly_expired_trains: 5,
        };
        let encoded = expected.encode().unwrap();
        assert!(FecFeedbackV2::is_record(&encoded));
        assert_eq!(FecFeedbackV2::decode(encoded).unwrap(), expected);
    }

    #[test]
    fn legacy_feedback_decodes_with_zeroed_receiver_metrics() {
        let current = FecFeedbackV2 {
            sequence: 7,
            parity_received: 10,
            recovered_cells: 2,
            delivered_payload_bytes: 99,
            reorder_cells: 3,
            ..FecFeedbackV2::default()
        };
        let legacy = current.encode().unwrap().slice(..LEGACY_WIRE_LEN);
        let decoded = FecFeedbackV2::decode(legacy).unwrap();
        assert_eq!(decoded.sequence, 7);
        assert_eq!(decoded.parity_received, 10);
        assert_eq!(decoded.recovered_cells, 2);
        assert_eq!(decoded.delivered_payload_bytes, 0);
        assert_eq!(decoded.reorder_cells, 0);
        assert_eq!(decoded.reassembly_expired_trains, 0);
    }

    #[test]
    fn feedback_rejects_reserved_sequence_and_trailing_bytes() {
        assert!(FecFeedbackV2::default().encode().is_err());
        let mut encoded = FecFeedbackV2 {
            sequence: 1,
            ..FecFeedbackV2::default()
        }
        .encode()
        .unwrap()
        .to_vec();
        encoded.push(0);
        assert!(FecFeedbackV2::decode(Bytes::from(encoded)).is_err());
    }
}

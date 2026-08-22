#![no_main]

use std::time::{Duration, Instant};

use bytes::Bytes;
use ironet::protocol::v2::{
    cell::{CellRouteHeaderV2, CellV2, MAX_RECORD_BYTES},
    fec::CellStripeDecoder,
    reassembly::{ReassemblyLimits, ReassemblyTableLimits, ReassemblyTableV2},
};
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_DATAGRAMS: usize = 64;
const MAX_FUZZ_DATAGRAM_BYTES: usize = 2_048;

fuzz_target!(|input: &[u8]| {
    let mut decoder = CellStripeDecoder::with_limits(1, Duration::from_millis(100), 32, 256 * 1024)
        .expect("constant FEC limits are valid");
    let mut reassembly = ReassemblyTableV2::new(ReassemblyTableLimits {
        session_epoch: 1,
        maximum_active_trains: 32,
        maximum_buffered_bytes: 256 * 1024,
        train_timeout: Duration::from_millis(100),
        per_train: ReassemblyLimits {
            maximum_cells: 256,
            maximum_active_records: 256,
            maximum_buffered_bytes: MAX_RECORD_BYTES,
        },
    })
    .expect("constant reassembly limits are valid");

    // Interpret the first two bytes of every item as a bounded length. This
    // exercises duplicate, reorder, partial-stripe, timeout, and pressure
    // paths in one persistent state machine without allowing the fuzzer to
    // manufacture unbounded work from a tiny input.
    let started = Instant::now();
    let mut cursor = 0;
    for index in 0..MAX_FUZZ_DATAGRAMS {
        if cursor + 2 > input.len() {
            break;
        }
        let length = usize::from(u16::from_be_bytes([input[cursor], input[cursor + 1]]))
            .min(MAX_FUZZ_DATAGRAM_BYTES)
            .min(input.len() - cursor - 2);
        cursor += 2;
        let bytes = Bytes::copy_from_slice(&input[cursor..cursor + length]);
        cursor += length;
        let now = started + Duration::from_millis(index as u64 * 4);

        let _ = CellRouteHeaderV2::decode(&bytes);
        if let Ok(cell) = CellV2::decode(bytes.clone()) {
            let _ = reassembly.accept_at(cell, now);
        }
        if let Ok(output) = decoder.push_at(bytes, now) {
            for cell in output.cells {
                let _ = reassembly.accept_at(cell, now);
            }
        }
    }
    let _ = decoder.expire(started + Duration::from_secs(1));
    let _ = reassembly.expire(started + Duration::from_secs(1));
});

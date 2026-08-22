use std::{hint::black_box, time::Instant};

use bytes::Bytes;
use ironet::{
    packet::inspect_ip_packet,
    protocol::v2::{
        cell::{CellV2, TrafficClass},
        reassembly::{ReassemblyLimits, TrainReassembler},
        train::{TrainContext, TrainRecord, build_packet_train},
    },
};

const CELL_MAXIMUM: usize = 1_382;

fn measure(name: &str, iterations: usize, mut operation: impl FnMut()) {
    let started = Instant::now();
    for _ in 0..iterations {
        operation();
    }
    let elapsed = started.elapsed();
    let nanos = elapsed.as_nanos() as f64 / iterations as f64;
    println!(
        "{name:34} {nanos:10.1} ns/op  {:12.0} op/s",
        1_000_000_000_f64 / nanos
    );
}

fn ipv4_tcp_packet() -> Vec<u8> {
    let mut packet = vec![0_u8; 1_500];
    let packet_len = packet.len() as u16;
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
    packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
    packet[20..22].copy_from_slice(&40_000_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
    packet
}

fn train(records: Vec<TrainRecord>) -> Vec<CellV2> {
    build_packet_train(
        TrainContext {
            class: TrafficClass::Bulk,
            session_epoch: 1,
            route_label: 1,
            overlay_hop_limit: 64,
            train_id: 1,
            maximum_datagram_size: CELL_MAXIMUM,
            maximum_cells: 256,
        },
        records,
    )
    .unwrap()
    .cells
}

fn main() {
    let iterations = std::env::args()
        .nth(1)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1_000_000)
        .max(1);
    println!("Ironet Protocol V2 dataplane microbench; iterations={iterations}");

    let packet = ipv4_tcp_packet();
    measure("inspect IPv4/TCP packet", iterations, || {
        black_box(inspect_ip_packet(black_box(&packet)).unwrap());
    });

    let single = train(vec![TrainRecord {
        record_id: 1,
        metadata: Bytes::new(),
        data: Bytes::copy_from_slice(&packet),
    }]);
    let wire = single[0].encode(CELL_MAXIMUM).unwrap();
    measure("decode V2 Cell", iterations, || {
        black_box(CellV2::decode(black_box(wire.clone())).unwrap());
    });

    let build_iterations = (iterations / 100).max(100);
    let records = (1..=44)
        .map(|record_id| TrainRecord {
            record_id,
            metadata: Bytes::new(),
            data: Bytes::copy_from_slice(&packet),
        })
        .collect::<Vec<_>>();
    measure("build 44-record PacketTrain", build_iterations, || {
        black_box(train(black_box(records.clone())));
    });

    let jumbo = train(vec![TrainRecord {
        record_id: 1,
        metadata: Bytes::new(),
        data: Bytes::from(vec![0x5a; u16::MAX as usize]),
    }]);
    let reassembly_iterations = (iterations / 10_000).max(10);
    measure(
        "64KiB reverse Cell reassembly",
        reassembly_iterations,
        || {
            let mut reassembler = TrainReassembler::new(ReassemblyLimits {
                maximum_cells: 256,
                maximum_active_records: 256,
                maximum_buffered_bytes: 2 * 1024 * 1024,
            })
            .unwrap();
            let mut complete = 0;
            for cell in jumbo.iter().rev().cloned() {
                complete += reassembler.accept(cell).unwrap().records.len();
            }
            black_box(complete);
        },
    );
}

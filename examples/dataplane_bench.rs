use std::{
    hint::black_box,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::{Duration, Instant},
};

use bytes::Bytes;
use iroh::SecretKey;
use ironet::{
    flow_router::{FlowRouter, RouteCandidate, RouteId},
    observability::PeerCounters,
    packet::{FlowKey, inspect_ip_packet},
    transport::{OutboundPacket, OutboundQueue},
    wire::{Reassembler, encode_packet_tagged},
};

fn measure(name: &str, iterations: usize, mut operation: impl FnMut()) {
    let started = Instant::now();
    for _ in 0..iterations {
        operation();
    }
    let elapsed = started.elapsed();
    let nanos = elapsed.as_nanos() as f64 / iterations as f64;
    let operations_per_second = 1_000_000_000_f64 / nanos;
    println!("{name:32} {nanos:10.1} ns/op  {operations_per_second:12.0} op/s");
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

fn main() {
    let iterations = std::env::args()
        .nth(1)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1_000_000)
        .max(1);
    println!("ironet data-plane microbench; iterations={iterations}");

    let packet = ipv4_tcp_packet();
    measure("inspect IPv4/TCP packet", iterations, || {
        black_box(inspect_ip_packet(black_box(&packet)).unwrap());
    });

    let queue_counters = Arc::new(PeerCounters::new(
        "bench".into(),
        SecretKey::from_bytes(&[0x42; 32]).public(),
        "none".into(),
    ));
    let queue = OutboundQueue::new(queue_counters);
    let mut queue_consumer = queue.take_consumer().unwrap();
    let queue_payload = Bytes::from_static(&[0x5a; 256]);
    measure("single-writer queue roundtrip", iterations, || {
        queue.push(OutboundPacket::new(queue_payload.clone(), false));
        black_box(queue_consumer.try_pop(Duration::from_secs(1)).unwrap());
    });

    let candidates = [
        RouteCandidate {
            id: RouteId(1),
            startup_latency: Duration::from_millis(10),
            capacity_bps: 100_000_000,
            queued_bytes: 0,
            loss_penalty: Duration::ZERO,
        },
        RouteCandidate {
            id: RouteId(2),
            startup_latency: Duration::from_millis(40),
            capacity_bps: 1_000_000_000,
            queued_bytes: 0,
            loss_penalty: Duration::ZERO,
        },
    ];
    let mut router = FlowRouter::default();
    let mut flow = 0_u16;
    measure("FlowRouter two-route select", iterations, || {
        flow = flow.wrapping_add(1);
        let key = FlowKey {
            source: IpAddr::V4(Ipv4Addr::new(10, 0, (flow >> 8) as u8, flow as u8)),
            destination: IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1)),
            protocol: 6,
            source_port: Some(flow),
            destination_port: Some(443),
        };
        black_box(
            router
                .select_projected(
                    key,
                    1_500,
                    0,
                    &candidates,
                    |candidate| candidate,
                    Instant::now(),
                )
                .unwrap(),
        );
    });

    let jumbo = vec![0x5a_u8; u16::MAX as usize];
    let frames = encode_packet_tagged(&jumbo, 1_200, 1, None).unwrap();
    let reassembly_iterations = (iterations / 10_000).max(10);
    measure(
        "64KiB out-of-order reassembly",
        reassembly_iterations,
        || {
            let mut reassembler = Reassembler::default();
            let mut complete = None;
            for frame in frames.iter().rev() {
                complete = reassembler.push(frame).unwrap().or(complete);
            }
            black_box(complete.unwrap());
        },
    );
}

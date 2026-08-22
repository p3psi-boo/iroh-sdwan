#![no_main]

use bytes::Bytes;
use ironet::protocol::v2::{
    cell::{CellRouteHeaderV2, CellV2},
    cover::CoverPaddingV2,
    feedback::FecFeedbackV2,
    gso::{GsoMetadataV2, decode_virtio_record},
    presence::SignedPresenceV2,
    repair::{RepairControlV2, RepairRequestV2, RepairResponseV2},
    routing::{OamControlV2, OamTtlExpiredV2, RouteAdvertisementV2},
    session::SessionHelloV2,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    // Every decoder receives independently owned immutable storage, matching
    // the production QUIC DATAGRAM/control-stream boundary. No decoder may
    // panic, index out of bounds, or reserve memory from unvalidated counts.
    let bytes = || Bytes::copy_from_slice(input);
    let _ = SessionHelloV2::decode(bytes());
    let _ = CellV2::decode(bytes());
    let _ = CellRouteHeaderV2::decode(input);
    let _ = CoverPaddingV2::decode(input, 1);
    let _ = FecFeedbackV2::decode(bytes());
    let _ = SignedPresenceV2::decode(bytes());
    let _ = RepairControlV2::decode(bytes());
    let _ = RepairRequestV2::decode(bytes());
    let _ = RepairResponseV2::decode(bytes());
    let _ = OamControlV2::decode(bytes());
    let _ = OamTtlExpiredV2::decode(bytes());
    let _ = RouteAdvertisementV2::decode(bytes(), false);
    let _ = RouteAdvertisementV2::decode(bytes(), true);
    let _ = decode_virtio_record(bytes());

    let split = input
        .first()
        .map_or(0, |value| usize::from(*value))
        .min(input.len());
    let _ = GsoMetadataV2::decode(Bytes::copy_from_slice(&input[..split]), &input[split..]);
});

#!/usr/bin/env python3
"""Generate small valid V2 seeds before mutation-based decoder fuzzing."""

from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parent
WIRE = ROOT / "corpus" / "v2_wire_decoders"
STATEFUL = ROOT / "corpus" / "v2_stateful_receive"
WIRE.mkdir(parents=True, exist_ok=True)
STATEFUL.mkdir(parents=True, exist_ok=True)


def write(name: str, payload: bytes) -> None:
    (WIRE / name).write_bytes(payload)


local_id = bytes.fromhex(
    "d0bd46270954e095ad8becf1292f0484286c775a68a5b5ca05066d2732c8ee50"
)
remote_id = bytes.fromhex(
    "c6d21e0b985631768a3e35426a0328e1116c4ead517fc3e6d97a1c414ebec415"
)
network = b"fuzz-network"
session = b"".join(
    (
        b"ISV2",
        struct.pack(">HBBQHHIIIHHI", 2, 1, 0, 0x7F, len(network), 1382,
                    1024 * 1024, 64 * 1024, 65535, 256, 1024, 1),
        local_id,
        remote_id,
        bytes([1]) * 32,
        bytes([2]) * 32,
        bytes([3]) * 32,
        network,
    )
)
assert len(session) == 200 + len(network)
write("session-hello", session)

segment = struct.pack(">BBHIIHH", 1, 0, 1, 4, 0, 4, 0) + b"test"
cell = b"".join(
    (
        b"ICV2",
        struct.pack(">BBBBIIQHIHHBB", 2, 1, 2, 3, 1, 1, 1, 0, 0, 1,
                    len(segment), 64, 0),
        segment,
    )
)
assert len(cell) == 36 + len(segment)
write("cell-full-record", cell)
(STATEFUL / "one-valid-cell").write_bytes(struct.pack(">H", len(cell)) + cell)

write("cover-padding", b"PCV2" + struct.pack(">BBHIQ", 1, 2, 0, 1, 7))
write("fec-feedback", b"FBV2" + struct.pack(">7Q", 1, 10, 1, 9, 2, 1, 0))

oam = b"".join(
    (
        b"OEV2",
        struct.pack(">BBHQIIQHBBI", 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1),
        local_id,
    )
)
assert len(oam) == 72
write("ttl-oam", oam)

route = b"".join(
    (
        b"RAV2",
        struct.pack(">BBHQ", 1, 0, 1, 1),
        struct.pack(">BBH4s12s", 4, 24, 0, bytes((10, 0, 0, 0)), bytes(12)),
    )
)
write("route-advertisement", route)

repair_key = struct.pack(">BIIQII", 2, 1, 1, 1, 0x01000001, 0)
repair = b"FRQ2" + repair_key + struct.pack(">QHHH", 1, 1, 0, 0)
write("repair-request", repair)

# --- v2_policy_guardrails seeds -------------------------------------------
# postcard-encoded CandidateActionV1 followed by the 40 context bytes the
# harness reads from the tail. postcard uses LEB128 varints; Option::None is
# 0x00, Option::Some(x) is 0x01 followed by the value, an enum is its
# discriminant varint, and a Vec is a varint length plus items.
GUARDRAILS = ROOT / "corpus" / "v2_policy_guardrails"
GUARDRAILS.mkdir(parents=True, exist_ok=True)


def varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


CONTEXT_LEN = 40
calm_context = bytes(CONTEXT_LEN)
# cpu_emergency + latency_queue_active set, modest rates.
pressure_context = bytes((0, 0, 0, 1, 0, 1, 0, 0)) + (10_000_000).to_bytes(8, "big") + (
    30_000
).to_bytes(8, "big") + (10_000_000).to_bytes(8, "big") + (9_000_000).to_bytes(8, "big")
assert len(pressure_context) == CONTEXT_LEN

NONE = b"\x00"


def guardrails_seed(candidate: bytes, context: bytes) -> bytes:
    assert len(context) == CONTEXT_LEN
    return candidate + context


# Every domain absent, empty extension bag.
empty = NONE * 8 + varint(0)
(GUARDRAILS / "candidate-empty").write_bytes(guardrails_seed(empty, calm_context))

# FEC preset family without explicit cells resolves through the host table.
fec_family = b"".join(
    (
        NONE,  # bbr
        NONE,  # scheduler
        b"\x01" + b"\x01\x01" + NONE + NONE + b"\x01" + varint(2),  # fec: on, Balanced
        NONE,  # repair
        NONE,  # tx
        NONE,  # rx
        NONE,  # cover
        NONE,  # egress_request
        varint(0),
    )
)
(GUARDRAILS / "candidate-fec-family").write_bytes(
    guardrails_seed(fec_family, calm_context)
)

# RX reassembly/active-train budgets plus a Repair retention target.
rx_repair = b"".join(
    (
        NONE,  # bbr
        NONE,  # scheduler
        NONE,  # fec
        b"\x01" + NONE + b"\x01" + varint(5_000) + b"\x01" + varint(3) + NONE,  # repair
        NONE,  # tx
        b"\x01"
        + b"\x01" + varint(16 * 1024 * 1024)  # receive_buffer_bytes
        + NONE  # receive_batch
        + b"\x01" + varint(4 * 1024 * 1024)  # reassembly_budget_bytes
        + b"\x01" + varint(64),  # active_train_budget
        NONE,  # cover
        NONE,  # egress_request
        varint(0),
    )
)
(GUARDRAILS / "candidate-rx-repair").write_bytes(
    guardrails_seed(rx_repair, pressure_context)
)

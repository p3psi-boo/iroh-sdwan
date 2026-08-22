#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)
FIXTURE_DIR="$ROOT/tests/fixtures/policy/malicious"
TARGET_DIR="$FIXTURE_DIR/target"
CORE="$TARGET_DIR/wasm32-unknown-unknown/release/ironet_policy_malicious_fixture.wasm"

append_manifest() {
    local component=$1
    local policy_name=$2
    local fuel=$3
    python3 - "$component" "$policy_name" "$fuel" <<'PY'
import json
import pathlib
import struct
import sys

path = pathlib.Path(sys.argv[1])
name = sys.argv[2]
fuel = int(sys.argv[3])
manifest = {
    "format_version": 1,
    "policy_id": f"fixture-{name}",
    "policy_version": 1,
    "abi_world": "ironet:policy/policy@1.0.0",
    "extensions_supported": [],
    "state_schema": 1,
    "state_schema_accepts": [1],
    "capabilities": [],
    "minimum_host_version": "0.1.0",
    "maximum_state_bytes": 65536,
    "requested_memory_bytes": 8388608,
    "requested_fuel": fuel,
    "built_at": "fixture",
    "source_revision": name,
}

def uleb(value):
    out = bytearray()
    while True:
        byte = value & 0x7f
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)

body = uleb(len(b"ironet.manifest.v1")) + b"ironet.manifest.v1"
body += json.dumps(manifest, separators=(",", ":"), sort_keys=True).encode()
section = b"\x00" + uleb(len(body)) + body
path.write_bytes(path.read_bytes() + section)
PY
}

mkdir -p "$FIXTURE_DIR"
for name in \
    echo loop fuel-burn memory-grow trap oversized-state oversized-output invalid-enum \
    overflow-action all-maximums non-deterministic-attempt; do
    nix develop -c cargo build \
        --manifest-path "$FIXTURE_DIR/Cargo.toml" \
        --target wasm32-unknown-unknown \
        --release \
        --no-default-features \
        --features "$name"
    output="$FIXTURE_DIR/$name.wasm"
    nix develop -c wasm-tools component new "$CORE" -o "$output"
    if [[ "$name" == fuel-burn ]]; then
        # Keep the fuel budget below the epoch deadline so this fixture
        # deterministically exercises the fuel limiter rather than timeout.
        append_manifest "$output" "$name" 1000
    else
        append_manifest "$output" "$name" 1000000
    fi
done

echo "built policy fixtures in $FIXTURE_DIR"

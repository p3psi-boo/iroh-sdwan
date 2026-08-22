#!/usr/bin/env bash
# Build the repository's policy guests as reproducible WebAssembly components.
# Run this from `nix develop` (the shell supplies Rust, wasm-tools and b3sum).

set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
TARGET_TRIPLE=wasm32-unknown-unknown
TARGET_DIR=${CARGO_TARGET_DIR:-"$ROOT/target"}
BUILTIN_WASM="$ROOT/crates/ironet-policy-builtin/builtin.wasm"
BUILTIN_DIGEST="$ROOT/crates/ironet-policy-builtin/builtin.wasm.blake3"
FIXTURE_DIR="$ROOT/tests/fixtures/policy/guests"

usage() {
    cat <<'EOF'
Usage: scripts/build-policy-guest.sh [--check]

Builds the builtin, echo and conservative policy components.  Normal mode
writes crates/ironet-policy-builtin/builtin.wasm and its BLAKE3 sidecar, plus
tests/fixtures/policy/guests/{echo,conservative}.wasm.  --check rebuilds into
a temporary directory and compares the builtin digest with the checked-in
sidecar without changing repository outputs.
EOF
}

CHECK=0
case "${1:-}" in
    "") ;;
    --check) CHECK=1 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac

die() {
    printf 'build-policy-guest.sh: %s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "missing $1; run inside nix develop"
}

require_command cargo
require_command wasm-tools
require_command b3sum
require_command python3
require_command date

cd "$ROOT"

# Cargo's release profile is intentionally overridden here instead of relying
# on a developer's local profile.  CARGO_INCREMENTAL=0 avoids embedding
# incremental compilation state in any object that reaches the final module.
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_RELEASE_OPT_LEVEL=s
export CARGO_PROFILE_RELEASE_PANIC=abort
export CARGO_PROFILE_RELEASE_LTO=true
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
export CARGO_PROFILE_RELEASE_DEBUG=0
export CARGO_PROFILE_RELEASE_STRIP=symbols
export TZ=UTC
export LC_ALL=C

if [[ -z "${SOURCE_DATE_EPOCH:-}" ]]; then
    SOURCE_DATE_EPOCH=$(git show -s --format=%ct HEAD 2>/dev/null || printf '0')
fi
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]] || die "SOURCE_DATE_EPOCH must be an integer"
export SOURCE_DATE_EPOCH
BUILT_AT=$(date -u -d "@$SOURCE_DATE_EPOCH" '+%Y-%m-%dT%H:%M:%SZ')

# The normal build records the checked-out revision.  `--check` below reuses
# the checked-in manifest's built_at/source_revision pair; this avoids a
# self-reference where committing the artifact would itself change HEAD.
SOURCE_REVISION=${SOURCE_REVISION:-$(git rev-parse HEAD 2>/dev/null || printf 'dirty')}

if (( CHECK )) && [[ -s "$BUILTIN_WASM" ]]; then
    mapfile -t checked_in_metadata < <(python3 - "$BUILTIN_WASM" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
data = path.read_bytes()

def read_uleb(offset):
    value = 0
    shift = 0
    while offset < len(data):
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7f) << shift
        if byte < 0x80:
            return value, offset
        shift += 7
        if shift > 35:
            raise ValueError("overlong section length")
    raise ValueError("truncated section length")

if data[:8] != b"\x00asm\x0d\x00\x01\x00":
    raise ValueError("not a component")
offset = 8
while offset < len(data):
    section_start = offset
    section_id = data[offset]
    offset += 1
    size, payload_start = read_uleb(offset)
    payload_end = payload_start + size
    if payload_end > len(data):
        raise ValueError("truncated section")
    if section_id == 0:
        cursor = payload_start
        name_len, cursor = read_uleb(cursor)
        name_end = cursor + name_len
        if name_end <= payload_end and data[cursor:name_end] == b"ironet.manifest.v1":
            manifest = json.loads(data[name_end:payload_end])
            print(manifest["built_at"])
            print(manifest["source_revision"])
            break
    offset = payload_end
else:
    raise ValueError("manifest section not found")
PY
    ) || true
    if (( ${#checked_in_metadata[@]} == 2 )); then
        SOURCE_DATE_EPOCH=$(date -u -d "${checked_in_metadata[0]}" +%s)
        SOURCE_REVISION=${checked_in_metadata[1]}
        export SOURCE_DATE_EPOCH
        BUILT_AT=${checked_in_metadata[0]}
    fi
fi

metadata=$(
    cargo run --locked --quiet --release \
        -p ironet-policy-builtin --example spec-metadata
)
metadata_value() {
    local key=$1
    printf '%s\n' "$metadata" | sed -n "s/^${key}=//p" | head -n1
}

POLICY_ID=$(metadata_value policy_id)
POLICY_VERSION=$(metadata_value policy_version)
BUILTIN_STATE_SCHEMA=$(metadata_value state_schema)
EXTENSION_TAG=$(metadata_value extension_tag)
[[ -n "$POLICY_ID" && -n "$POLICY_VERSION" && -n "$BUILTIN_STATE_SCHEMA" ]] \
    || die "builtin spec metadata is incomplete"

write_manifest() {
    local path=$1
    python3 - "$path" "$POLICY_ID" "$POLICY_VERSION" "$BUILTIN_STATE_SCHEMA" \
        "$EXTENSION_TAG" "$BUILT_AT" "$SOURCE_REVISION" <<'PY'
import json
import pathlib
import sys

path, policy_id, policy_version, state_schema, extension_tag, built_at, source_revision = sys.argv[1:]
manifest = {
    "format_version": 1,
    "policy_id": policy_id,
    "policy_version": int(policy_version),
    "abi_world": "ironet:policy/policy@1.0.0",
    "extensions_supported": [int(extension_tag)],
    "state_schema": int(state_schema),
    "state_schema_accepts": [int(state_schema)],
    "capabilities": [
        "bbr.preset",
        "scheduler.train",
        "fec.geometry",
        "repair.cache",
        "cover.padding",
    ],
    "minimum_host_version": "0.1.0",
    "maximum_state_bytes": 65536,
    "requested_memory_bytes": 8388608,
    "requested_fuel": 1000000,
    "built_at": built_at,
    "source_revision": source_revision,
}
pathlib.Path(path).write_bytes(
    json.dumps(manifest, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
)
PY
}

append_manifest() {
    local component=$1
    local manifest=$2
    python3 - "$component" "$manifest" <<'PY'
import pathlib
import sys

component_path, manifest_path = map(pathlib.Path, sys.argv[1:])
data = component_path.read_bytes()
if data[:8] != b"\x00asm\x0d\x00\x01\x00":
    raise SystemExit(f"{component_path} is not a WebAssembly component")
name = b"ironet.manifest.v1"
payload = name + manifest_path.read_bytes()

def uleb(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7f
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)

body = uleb(len(name)) + payload
component_path.write_bytes(data + b"\x00" + uleb(len(body)) + body)
PY
}

digest() {
    b3sum --no-names "$1" | tr -d '[:space:]'
}

build_components() {
    local out=$1
    local raw_builtin="$TARGET_DIR/$TARGET_TRIPLE/release/ironet_policy_builtin.wasm"
    local raw_echo="$TARGET_DIR/$TARGET_TRIPLE/release/examples/echo.wasm"
    local raw_conservative="$TARGET_DIR/$TARGET_TRIPLE/release/examples/conservative.wasm"
    local manifest="$out/builtin.manifest.json"

    mkdir -p "$out"
    cargo build --locked -p ironet-policy-builtin --release --target "$TARGET_TRIPLE"
    cargo build --locked -p ironet-policy-sdk --release --target "$TARGET_TRIPLE" \
        --example echo --example conservative

    test -s "$raw_builtin" || die "builtin guest was not produced: $raw_builtin"
    test -s "$raw_echo" || die "echo guest was not produced: $raw_echo"
    test -s "$raw_conservative" || die "conservative guest was not produced: $raw_conservative"

    wasm-tools component new "$raw_builtin" -o "$out/builtin.wasm"
    write_manifest "$manifest"
    append_manifest "$out/builtin.wasm" "$manifest"

    wasm-tools component new "$raw_echo" -o "$out/echo.wasm"
    wasm-tools component new "$raw_conservative" -o "$out/conservative.wasm"
}

if (( CHECK )); then
    test -s "$BUILTIN_WASM" || die "missing checked-in $BUILTIN_WASM"
    test -s "$BUILTIN_DIGEST" || die "missing checked-in $BUILTIN_DIGEST"
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/ironet-policy-guest.check.XXXXXX")
    trap 'rm -rf "$tmp"' EXIT
    build_components "$tmp"
    actual=$(digest "$tmp/builtin.wasm")
    expected=$(sed -n 's/^blake3://p' "$BUILTIN_DIGEST" | tr -d '[:space:]')
    [[ "$expected" =~ ^[0-9a-f]{64}$ ]] || die "invalid builtin digest sidecar"
    if [[ "$actual" != "$expected" ]]; then
        printf 'builtin.wasm digest mismatch: expected %s, got %s\n' \
            "$expected" "$actual" >&2
        exit 1
    fi
    printf 'builtin.wasm digest OK: blake3:%s\n' "$actual"
    exit 0
fi

tmp=$(mktemp -d "${TMPDIR:-/tmp}/ironet-policy-guest.build.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
build_components "$tmp"

mkdir -p "$(dirname -- "$BUILTIN_WASM")" "$FIXTURE_DIR"
cp "$tmp/builtin.wasm" "$BUILTIN_WASM"
builtin_hash=$(digest "$BUILTIN_WASM")
printf 'blake3:%s\n' "$builtin_hash" >"$BUILTIN_DIGEST"
cp "$tmp/echo.wasm" "$FIXTURE_DIR/echo.wasm"
cp "$tmp/conservative.wasm" "$FIXTURE_DIR/conservative.wasm"

printf 'built %s (%s bytes)\n' "$BUILTIN_WASM" "$(wc -c <"$BUILTIN_WASM")"
printf 'digest blake3:%s\n' "$builtin_hash"
printf 'built %s\n' "$FIXTURE_DIR/echo.wasm"
printf 'built %s\n' "$FIXTURE_DIR/conservative.wasm"

#!/usr/bin/env bash
# Reproduce the historical Phase 0 runtime spike without retaining generated assets.
# Run via:
#   nix develop ./tools/phase0-spike/nix-wasm-shell -c ./tools/phase0-spike/run.sh
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
OUT=${OUT:-"$ROOT/out"}
ITERS=${ITERS:-1000}
INPUT_BYTES=${INPUT_BYTES:-1024}

require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        printf 'phase0-spike: missing %s; run inside nix develop ./tools/phase0-spike/nix-wasm-shell\n' "$1" >&2
        exit 1
    }
}

require_command cargo
require_command wasm-tools

mkdir -p "$OUT"
GUEST_TARGET="$OUT/target-guest"
COMPONENT="$OUT/guest-component.wasm"
PULLEY_COMPONENT="$OUT/guest-pulley64.cwasm"

printf 'Phase 0 reproduction output: %s\n' "$OUT"
printf 'iterations=%s input_bytes=%s\n' "$ITERS" "$INPUT_BYTES" | tee "$OUT/metadata.txt"

cargo build --locked \
    --manifest-path "$ROOT/guest/Cargo.toml" \
    --release \
    --target wasm32-unknown-unknown \
    --target-dir "$GUEST_TARGET"
RAW_GUEST="$GUEST_TARGET/wasm32-unknown-unknown/release/phase0_guest.wasm"
test -s "$RAW_GUEST"
wasm-tools component new "$RAW_GUEST" -o "$COMPONENT"
wasm-tools validate --features component-model "$COMPONENT"

run_host() {
    local name=$1
    local features=$2
    shift 2
    local target="$OUT/target-host-$name"
    CARGO_TARGET_DIR="$target" cargo run --locked \
        --manifest-path "$ROOT/host/Cargo.toml" \
        --release \
        --no-default-features \
        --features "$features" \
        -- "$@"
    stat --format='host_binary_bytes[%s]=%n' "$target/release/phase0-host" \
        | tee -a "$OUT/metadata.txt"
}

# Runtime compilation to host machine code and to the Pulley target.
run_host cranelift cranelift run "$COMPONENT" \
    --iters "$ITERS" --input-bytes "$INPUT_BYTES" \
    | tee "$OUT/run-cranelift.txt"
run_host cranelift-pulley cranelift,pulley run "$COMPONENT" \
    --target pulley64 --iters "$ITERS" --input-bytes "$INPUT_BYTES" \
    | tee "$OUT/run-cranelift-pulley.txt"

# Build an AOT Pulley component with the compiler-enabled build, then load it
# with the compiler-free Pulley build.
run_host cranelift-pulley cranelift,pulley precompile "$COMPONENT" "$PULLEY_COMPONENT" \
    --target pulley64 \
    | tee "$OUT/precompile-pulley64.txt"
run_host pulley pulley load "$PULLEY_COMPONENT" \
    --target pulley64 --iters "$ITERS" --input-bytes "$INPUT_BYTES" \
    | tee "$OUT/load-pulley64.txt"

printf 'Phase 0 reproduction complete. Generated assets remain under %s.\n' "$OUT"

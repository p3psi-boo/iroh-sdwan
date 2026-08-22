#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
IMAGE=${IRONET_V2_CAPTURE_IMAGE:-ironet:v2-sni-capture}
OUT=${IRONET_V2_CAPTURE_OUT:-$ROOT/target/v2-sni-capture}

# Keep the published integration entrypoint self-contained on Nix hosts. The
# container suites otherwise run for minutes before this final capture suite
# discovers that Cargo is available only inside the repository dev shell.
if ! command -v cargo >/dev/null 2>&1; then
  if [[ ${IRONET_V2_CAPTURE_DEV_SHELL:-0} == 0 ]] && command -v nix >/dev/null 2>&1; then
    exec env IRONET_V2_CAPTURE_DEV_SHELL=1 nix develop "$ROOT" -c "$0" "$@"
  fi
  echo "cargo is required to build the V2 capture binaries" >&2
  exit 127
fi

cd "$ROOT"
cargo build --profile profiling --bin ironet --bin ironetd
is_elf() {
  [[ $(od -An -tx1 -N4 "$1" | tr -d ' \n') == 7f454c46 ]]
}
if ! is_elf "$ROOT/target/profiling/ironet" \
  || ! is_elf "$ROOT/target/profiling/ironetd"; then
  # An interrupted linker can leave a sparse output while Cargo's fingerprint
  # still looks fresh. Never launch or capture anything except verified ELF
  # production binaries.
  cargo clean --profile profiling -p ironet
  cargo build --profile profiling --bin ironet --bin ironetd
  is_elf "$ROOT/target/profiling/ironet"
  is_elf "$ROOT/target/profiling/ironetd"
fi
docker build --network=host -t "$IMAGE" "$ROOT/tests/docker-v2-sni"
mkdir -p "$OUT"

mounts=(
  -v "$ROOT/target/profiling/ironet:/bin/ironet:ro"
  -v "$ROOT/target/profiling/ironetd:/bin/ironetd:ro"
  -v "$ROOT/tests/docker-v2-sni/lab.sh:/lab.sh:ro"
  -v "$OUT:/out"
)
if [[ -d /nix/store ]]; then
  mounts+=(-v /nix/store:/nix/store:ro)
fi

exec docker run --rm --privileged \
  "${mounts[@]}" \
  "$IMAGE" /lab.sh

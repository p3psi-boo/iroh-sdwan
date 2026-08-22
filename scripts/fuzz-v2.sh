#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

runs="${IRONET_FUZZ_RUNS:-10000}"
max_len="${IRONET_FUZZ_MAX_LEN:-8192}"
artifact_root="${IRONET_FUZZ_ARTIFACTS:-target/fuzz-artifacts}"
mkdir -p "$artifact_root"
python3 fuzz/generate_corpus.py

for target in v2_wire_decoders v2_stateful_receive v2_policy_guardrails; do
  cargo fuzz run "$target" --fuzz-dir fuzz -- \
    -runs="$runs" \
    -max_len="$max_len" \
    -artifact_prefix="$artifact_root/$target-"
done

#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
MATRIX_SCRIPT="$ROOT/scripts/profile-v2-netns-matrix.sh"
STAMP=$(date -u +%Y%m%d-%H%M%S)
OUT=${IRONET_V2_ORACLE_OUT:-$ROOT/target/v2-autotune-oracle-$STAMP}
SCENARIOS=${IRONET_V2_ORACLE_SCENARIOS:-wifi-lan-light,p2-wuwei-lossy-upload,cross-carrier-cn-upload}
DURATION=${IRONET_V2_ORACLE_SECONDS:-20}
PERF_ENABLED=${IRONET_V2_ORACLE_PERF:-0}
OBJECTIVE=${IRONET_V2_ORACLE_OBJECTIVE:-balanced}
RESUME=${IRONET_V2_ORACLE_RESUME:-0}
INCLUDE_BASELINE=${IRONET_V2_ORACLE_INCLUDE_BASELINE:-1}
FEC_GRID=${IRONET_V2_ORACLE_FEC_GRID:-off,4+1,8+1,8+2}
TRAIN_GRID=${IRONET_V2_ORACLE_TRAIN_GRID:-8192,32768,65536}
QUANTUM_GRID=${IRONET_V2_ORACLE_QUANTUM_GRID:-1,2,4}
COVER_GRID=${IRONET_V2_ORACLE_COVER_GRID:-0}
COVER_PROFILE_GRID=${IRONET_V2_ORACLE_COVER_PROFILE_GRID:-inherit}
BBR_GRID=${IRONET_V2_ORACLE_BBR_GRID:-rule}
ACTIONS_JSON=${IRONET_V2_ORACLE_ACTIONS_JSON:-}
BIN=${IRONETD_BIN:-$ROOT/target/profiling/ironetd}
CLI=${IRONET_BIN:-$ROOT/target/profiling/ironet}

[[ -x $MATRIX_SCRIPT ]] || { echo "missing matrix script: $MATRIX_SCRIPT" >&2; exit 1; }
[[ -x $BIN ]] || { echo "missing profiling daemon: $BIN" >&2; exit 1; }
[[ -x $CLI ]] || { echo "missing profiling CLI: $CLI" >&2; exit 1; }
[[ $DURATION =~ ^[1-9][0-9]*$ ]] || { echo "invalid oracle duration" >&2; exit 1; }
[[ $PERF_ENABLED == 0 || $PERF_ENABLED == 1 ]] || { echo "oracle perf must be 0 or 1" >&2; exit 1; }
[[ $OBJECTIVE == balanced || $OBJECTIVE == throughput || $OBJECTIVE == latency ]] \
  || { echo "oracle objective must be balanced, throughput, or latency" >&2; exit 1; }
[[ $RESUME == 0 || $RESUME == 1 ]] || { echo "oracle resume must be 0 or 1" >&2; exit 1; }
[[ $INCLUDE_BASELINE == 0 || $INCLUDE_BASELINE == 1 ]] || {
  echo "oracle baseline flag must be 0 or 1" >&2
  exit 1
}

if [[ -e $OUT && $RESUME == 0 ]]; then
  echo "oracle output already exists: $OUT" >&2
  exit 1
fi
mkdir -p "$OUT/candidates"
OUT=$(realpath "$OUT")

generate_actions() {
  python3 - "$FEC_GRID" "$TRAIN_GRID" "$QUANTUM_GRID" "$COVER_GRID" "$COVER_PROFILE_GRID" "$BBR_GRID" "$ACTIONS_JSON" <<'PY'
import hashlib
import itertools
import json
import sys

def values(text):
    result = [item.strip() for item in text.split(",") if item.strip()]
    if not result:
        raise SystemExit("oracle grid dimension is empty")
    return result

def validate(action):
    allowed = {
        "bbr_preset", "fec", "train_target_bytes", "bulk_quantum_cells",
        "cover_overhead_per_mille", "cover_profile",
    }
    unknown = set(action) - allowed
    if unknown:
        raise SystemExit(f"unknown oracle action fields: {sorted(unknown)}")
    required = {
        "bbr_preset", "fec", "train_target_bytes", "bulk_quantum_cells",
        "cover_overhead_per_mille",
    }
    missing = required - set(action)
    if missing:
        raise SystemExit(f"missing oracle action fields: {sorted(missing)}")
    bbr = action["bbr_preset"]
    if bbr not in {
        None, "shared-conservative", "private-aggressive", "lossy-radio",
        "policer", "long-fat", "relay-reliable", "low-rtt-host",
    }:
        raise SystemExit(f"unknown oracle BBR preset: {bbr}")
    fec = action["fec"]
    if fec not in {None, "4+1", "8+1", "8+2"}:
        raise SystemExit(f"unknown oracle FEC layout: {fec}")
    for name in ("train_target_bytes", "bulk_quantum_cells", "cover_overhead_per_mille"):
        if isinstance(action[name], bool) or not isinstance(action[name], int):
            raise SystemExit(f"oracle action {name} must be an integer")
    if action["train_target_bytes"] <= 0 or action["bulk_quantum_cells"] <= 0:
        raise SystemExit("oracle train target and bulk quantum must be positive")
    if not 0 <= action["cover_overhead_per_mille"] <= 1000:
        raise SystemExit("oracle cover overhead must be in 0..1000")
    cover_profile = action.get("cover_profile", "inherit")
    if cover_profile not in {
        "inherit", "idle", "live-broadcast", "interactive-video", "generic-h3-bulk",
    }:
        raise SystemExit(f"unknown oracle cover profile: {cover_profile}")

def emit(action):
    validate(action)
    if action.get("cover_profile") == "inherit":
        action.pop("cover_profile")
    encoded = json.dumps(action, separators=(",", ":"), sort_keys=True)
    digest = hashlib.sha256(encoded.encode()).hexdigest()[:12]
    print(f"action-{digest}\t{encoded}")

if sys.argv[7]:
    actions = json.loads(sys.argv[7])
    if not isinstance(actions, list) or not actions:
        raise SystemExit("IRONET_V2_ORACLE_ACTIONS_JSON must be a non-empty JSON array")
    for action in actions:
        if not isinstance(action, dict):
            raise SystemExit("each explicit oracle action must be a JSON object")
        emit(dict(action))
    raise SystemExit(0)

for fec, train, quantum, cover, cover_profile, bbr in itertools.product(
    *(values(value) for value in sys.argv[1:7])
):
    action = {
        "bbr_preset": None if bbr == "rule" else bbr,
        "fec": None if fec == "off" else fec,
        "train_target_bytes": int(train),
        "bulk_quantum_cells": int(quantum),
        "cover_overhead_per_mille": int(cover),
    }
    if cover_profile != "inherit":
        action["cover_profile"] = cover_profile
    emit(action)
PY
}

if [[ ${1:-} == --list-actions ]]; then
  generate_actions
  exit 0
fi

run_candidate() {
  local id=$1 action=$2 candidate matrix
  candidate="$OUT/candidates/$id"
  matrix="$candidate/matrix"
  if [[ $RESUME == 1 && -s $matrix/aggregate.json ]]; then
    printf 'skipping completed oracle candidate %s\n' "$id"
    return
  fi
  rm -rf "$candidate"
  mkdir -p "$candidate"
  printf '%s\n' "$action" >"$candidate/action.json"
  printf 'running oracle candidate %s: %s\n' "$id" "$action"
  local -a command=(
    env
    "IRONETD_BIN=$BIN"
    "IRONET_BIN=$CLI"
    "IRONET_V2_MATRIX_OUT=$matrix"
    "IRONET_V2_MATRIX_SCENARIOS=$SCENARIOS"
    "IRONET_V2_MATRIX_SECONDS=$DURATION"
    "IRONET_V2_MATRIX_PERF=$PERF_ENABLED"
    "IRONET_V2_PROFILE_AUTOTUNE_OBJECTIVE=$OBJECTIVE"
    "IRONET_V2_MATRIX_SETTLE_SECONDS=1"
  )
  if [[ $action == null ]]; then
    command=(env -u IRONET_AUTOTUNE_FORCE "${command[@]:1}")
  else
    command+=( "IRONET_AUTOTUNE_FORCE=$action" )
  fi
  command+=( bash "$MATRIX_SCRIPT" )
  if ! "${command[@]}" >"$candidate/run.log" 2>&1; then
    tail -n 80 "$candidate/run.log" >&2
    return 1
  fi
}

if [[ $INCLUDE_BASELINE == 1 ]]; then
  run_candidate baseline null
fi
while IFS=$'\t' read -r id action; do
  run_candidate "$id" "$action"
done < <(generate_actions)

python3 - "$OUT" "$SCENARIOS" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
requested = [value for value in sys.argv[2].split(",") if value]
by_scenario = {scenario: [] for scenario in requested}
objectives = set()
for candidate in sorted((root / "candidates").iterdir()):
    aggregate = candidate / "matrix" / "aggregate.json"
    action_path = candidate / "action.json"
    if not aggregate.exists() or not action_path.exists():
        continue
    action = json.loads(action_path.read_text())
    for row in json.loads(aggregate.read_text()):
        objective = row.get("autotune_objective") or "balanced"
        if objective not in {"balanced", "throughput", "latency"}:
            raise SystemExit(f"unknown autotune objective in aggregate: {objective}")
        objectives.add(objective)
        utility = row.get("utility_last10_mean")
        if not isinstance(utility, (int, float)):
            continue
        by_scenario.setdefault(row["scenario"], []).append({
            "candidate_id": candidate.name,
            "action": action,
            "utility_last10_mean": utility,
            "utility_mean": row.get("utility_mean"),
            "utility_p10": row.get("utility_p10"),
            "overlay_mbit": row.get("overlay_mbit"),
            "overlay_ping_p95_ms": row.get("overlay_ping_p95_ms"),
            "output": row.get("output"),
        })

scenarios = {}
for scenario, candidates in by_scenario.items():
    if not candidates:
        scenarios[scenario] = {"candidates": [], "oracle": None, "baseline": None}
        continue
    baseline = next((item for item in candidates if item["candidate_id"] == "baseline"), None)
    forced = [item for item in candidates if item["candidate_id"] != "baseline"]
    forced.sort(key=lambda item: item["utility_last10_mean"], reverse=True)
    candidates.sort(key=lambda item: item["utility_last10_mean"], reverse=True)
    oracle = forced[0] if forced else None
    comparison = None
    if baseline is not None and oracle is not None:
        absolute = oracle["utility_last10_mean"] - baseline["utility_last10_mean"]
        # U is signed and has an arbitrary zero, so a raw 1-U/Uoracle ratio is
        # undefined or misleading for non-positive samples. Keep an additive
        # delta and normalize it by a stable unit-or-oracle magnitude instead.
        comparison = {
            "regret_absolute": absolute,
            "regret": absolute / max(1.0, abs(oracle["utility_last10_mean"])),
            "ratio_regret": (
                1.0 - baseline["utility_last10_mean"] / oracle["utility_last10_mean"]
                if oracle["utility_last10_mean"] > 0 else None
            ),
        }
    scenarios[scenario] = {
        "candidates": candidates,
        "oracle": oracle,
        "baseline": baseline,
        "comparison": comparison,
    }

output = {
    "schema_version": 1,
    "objective": next(iter(objectives)) if len(objectives) == 1 else None,
    "selection_metric": "utility_last10_mean",
    "regret_definition": "(U_oracle-U_baseline)/max(1,abs(U_oracle))",
    "scenarios": scenarios,
}
if len(objectives) != 1:
    raise SystemExit(f"oracle candidates mix autotune objectives: {sorted(objectives)}")
(root / "oracle.json").write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n")
print(json.dumps(output, ensure_ascii=False, indent=2))
PY

echo "$OUT"

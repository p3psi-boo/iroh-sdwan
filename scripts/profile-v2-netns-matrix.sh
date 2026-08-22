#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
PROFILE_SCRIPT="$ROOT/scripts/profile-v2-netns.sh"
STAMP=$(date -u +%Y%m%d-%H%M%S)
MATRIX_OUT=${IRONET_V2_MATRIX_OUT:-$ROOT/target/v2-netns-matrix-$STAMP}
MATRIX_OUT=$(realpath -m "$MATRIX_OUT")
DURATION=${IRONET_V2_MATRIX_SECONDS:-15}
STREAMS=${IRONET_V2_MATRIX_STREAMS:-4}
FREQUENCY=${IRONET_V2_MATRIX_FREQUENCY:-99}
CALL_GRAPH=${IRONET_V2_MATRIX_CALL_GRAPH:-lbr}
PING_INTERVAL_MS=${IRONET_V2_MATRIX_PING_INTERVAL_MS:-20}
FAIRNESS_SECONDS=${IRONET_V2_MATRIX_FAIRNESS_SECONDS:-0}
FAIRNESS_PER_STREAM_MBIT=${IRONET_V2_MATRIX_FAIRNESS_PER_STREAM_MBIT:-10}
SETTLE_SECONDS=${IRONET_V2_MATRIX_SETTLE_SECONDS:-2}
SCENARIO_FILTER=${IRONET_V2_MATRIX_SCENARIOS:-all}
RESUME=${IRONET_V2_MATRIX_RESUME:-0}
# 1 = perf + FlameGraph per scenario (CPU profiling matrix). 0 = tuner
# behaviour only; much cheaper and the right mode for dynamic timelines.
PERF_ENABLED=${IRONET_V2_MATRIX_PERF:-1}
PROFILE_RUST_LOG=${IRONET_V2_PROFILE_RUST_LOG:-info,ironet::autotune=debug}
PROFILE_NICE=${IRONET_V2_PROFILE_NICE:-10}
AUTOTUNE_FORCE=${IRONET_AUTOTUNE_FORCE:-}
AUTOTUNE_MODE=${IRONET_V2_PROFILE_AUTOTUNE_MODE:-shadow}
AUTOTUNE_OBJECTIVE=${IRONET_V2_PROFILE_AUTOTUNE_OBJECTIVE:-balanced}
AUTOTUNE_MEMORY=${IRONET_V2_PROFILE_AUTOTUNE_MEMORY:-0}
AUTOTUNE_POLICY=${IRONET_V2_PROFILE_AUTOTUNE_POLICY:-builtin}
AUTOTUNE_SHADOW_POLICY=${IRONET_V2_PROFILE_AUTOTUNE_SHADOW_POLICY:-}
COVER_SECONDS=${IRONET_V2_PROFILE_COVER_SECONDS:-0}
COVER_RATE_MBIT=${IRONET_V2_PROFILE_COVER_RATE_MBIT:-4}
SECOND_PATH=${IRONET_V2_PROFILE_SECOND_PATH:-0}
SECOND_PATH_DELAY_MS=${IRONET_V2_PROFILE_SECOND_PATH_DELAY_MS:-30}
SECOND_PATH_LOSS_PERCENT=${IRONET_V2_PROFILE_SECOND_PATH_LOSS_PERCENT:-0}
SECOND_PATH_RATE_MBIT=${IRONET_V2_PROFILE_SECOND_PATH_RATE_MBIT:-0}
SECOND_PATH_QUEUE_PACKETS=${IRONET_V2_PROFILE_SECOND_PATH_QUEUE_PACKETS:-1000}
DEFAULT_BIN=$ROOT/target/x86_64-unknown-linux-musl/profiling/ironetd
DEFAULT_CLI=$ROOT/target/x86_64-unknown-linux-musl/profiling/ironet
BIN=${IRONETD_BIN:-$DEFAULT_BIN}
CLI=${IRONET_BIN:-$DEFAULT_CLI}
CARGO=${CARGO:-cargo}

if [[ -v IRONETD_BIN && -z $IRONETD_BIN ]] || [[ -v IRONET_BIN && -z $IRONET_BIN ]]; then
  echo "IRONETD_BIN and IRONET_BIN must be non-empty when explicitly set" >&2
  exit 1
fi
if [[ -v IRONETD_BIN && ! -v IRONET_BIN ]] || [[ ! -v IRONETD_BIN && -v IRONET_BIN ]]; then
  echo "set both IRONETD_BIN and IRONET_BIN, or neither for a fresh default build" >&2
  exit 1
fi

source_identity() {
  local revision output_relative path content_hash
  revision=$(git -C "$ROOT" rev-parse --verify HEAD 2>/dev/null) || return
  printf '%s:' "$revision"
  git -C "$ROOT" diff --binary HEAD | git hash-object --stdin
  printf ':'
  # Include every untracked source path and its content hash. The matrix
  # output itself is not source input, so exclude it when it lives inside
  # this checkout.
  if [[ $MATRIX_OUT == "$ROOT/"* ]]; then
    output_relative=${MATRIX_OUT#"$ROOT/"}
    while IFS= read -r -d '' path; do
      [[ $path == "$output_relative" || $path == "$output_relative/"* ]] && continue
      content_hash=$(git -C "$ROOT" hash-object -- "$path")
      printf '%s\0%s\0' "$path" "$content_hash"
    done < <(git -C "$ROOT" ls-files --others --exclude-standard -z) \
      | git hash-object --stdin
  else
    while IFS= read -r -d '' path; do
      content_hash=$(git -C "$ROOT" hash-object -- "$path")
      printf '%s\0%s\0' "$path" "$content_hash"
    done < <(git -C "$ROOT" ls-files --others --exclude-standard -z) \
      | git hash-object --stdin
  fi
}

expand_cpu_list() {
  local list=$1 part first last cpu
  local -a parts
  IFS=, read -r -a parts <<<"$list"
  for part in "${parts[@]}"; do
    if [[ $part == *-* ]]; then
      first=${part%-*}
      last=${part#*-}
      for ((cpu = first; cpu <= last; cpu++)); do
        printf '%s\n' "$cpu"
      done
    else
      printf '%s\n' "$part"
    fi
  done
}

policy_content_sha256() {
  local policy=$1
  if [[ -z $policy || $policy == builtin || ! -f $policy ]]; then
    return 0
  fi
  sha256sum "$policy" | awk '{print $1}'
}

# A matrix is meaningful only when the daemon and CLI were built from the
# source being measured.  The previous implementation merely accepted any
# executable at the default target path, which let an old profiling build
# survive a source update unnoticed.  Build the default pair incrementally on
# every run: Cargo makes this a no-op when it is already current, while a
# changed source tree gets a matching pair before netns setup starts.  An
# explicit binary path is a deliberate caller-owned artifact and is left
# untouched for release/remote build workflows.
ensure_profiling_binaries() {
  if [[ -z ${IRONETD_BIN+x} && -z ${IRONET_BIN+x} ]]; then
    MATRIX_BINARY_FRESHNESS=built-current-source
    command -v "$CARGO" >/dev/null 2>&1 \
      || { echo "missing cargo for fresh profiling build: $CARGO" >&2; exit 1; }
    SOURCE_IDENTITY_BEFORE_BUILD=$(source_identity) \
      || { echo "matrix requires a Git checkout to verify profiling-build freshness" >&2; exit 1; }
    echo "building profiling binaries for $SOURCE_IDENTITY_BEFORE_BUILD"
    "$CARGO" build --profile profiling --target x86_64-unknown-linux-musl \
      --locked --bin ironetd --bin ironet
    SOURCE_IDENTITY_AFTER_BUILD=$(source_identity) \
      || { echo "matrix source revision disappeared while building" >&2; exit 1; }
    [[ $SOURCE_IDENTITY_BEFORE_BUILD == "$SOURCE_IDENTITY_AFTER_BUILD" ]] \
      || { echo "source changed while building profiling binaries; rerun the matrix" >&2; exit 1; }
  else
    MATRIX_BINARY_FRESHNESS=caller-supplied-unverified
    echo "using caller-supplied profiling binaries; source freshness is caller-owned" >&2
  fi
}

[[ $DURATION =~ ^[1-9][0-9]*$ ]] || { echo "invalid matrix duration" >&2; exit 1; }
[[ $STREAMS =~ ^[1-9][0-9]*$ ]] || { echo "invalid matrix stream count" >&2; exit 1; }
[[ $FREQUENCY =~ ^[1-9][0-9]*$ ]] || { echo "invalid matrix frequency" >&2; exit 1; }
[[ $PING_INTERVAL_MS =~ ^[1-9][0-9]*$ ]] || { echo "invalid ping interval" >&2; exit 1; }
[[ $FAIRNESS_SECONDS =~ ^[0-9]+$ ]] || { echo "invalid matrix fairness duration" >&2; exit 1; }
[[ $FAIRNESS_PER_STREAM_MBIT =~ ^[0-9]+([.][0-9]+)?$ ]] \
  || { echo "invalid matrix fairness per-stream rate" >&2; exit 1; }
[[ $SETTLE_SECONDS =~ ^[0-9]+$ ]] || { echo "invalid matrix settle duration" >&2; exit 1; }
[[ $RESUME == 0 || $RESUME == 1 ]] || { echo "matrix resume must be 0 or 1" >&2; exit 1; }
[[ $PERF_ENABLED == 0 || $PERF_ENABLED == 1 ]] || { echo "matrix perf must be 0 or 1" >&2; exit 1; }

scenario_selected() {
  local name=$1 item
  [[ $SCENARIO_FILTER == all ]] && return 0
  IFS=, read -r -a selected <<<"$SCENARIO_FILTER"
  for item in "${selected[@]}"; do
    [[ $item == "$name" ]] && return 0
  done
  return 1
}

# Columns: name|direction|a_delay|a_jitter|a_delay_corr|a_loss|a_loss_corr|
# a_rate|a_queue|b_delay|b_jitter|b_delay_corr|b_loss|b_loss_corr|b_rate|
# b_queue|seconds|timeline|description. `seconds` 0 uses the matrix duration;
# dynamic scenarios declare their own so every timeline step is observed.
# `timeline` uses the profile script's IRONET_V2_PROFILE_TIMELINE grammar.
catalog() {
  cat <<'EOF'
host-local-clean|forward|0|0|0|0|0|100|1000|0|0|0|0|0|100|1000|0||同机房/宿主机级无附加时延链路，用于验证包含 userspace 调度开销后 min RTT <2 ms 的专用 cwnd floor
wifi-lan-light|forward|2|1|25|0.2|25|300|1000|2|1|25|0.2|25|300|1000|0||轻度局域网 Wi-Fi 干扰，约 4 ms 基础 RTT
wifi-lan-interference|forward|4|4|50|2.5|60|150|1000|4|4|50|2.5|60|150|1000|0||拥挤 Wi-Fi，相关抖动和成串丢包
p2-p6-capacity|forward|1.5|0.2|10|0|0|110|1000|1.5|0.2|10|0|0|110|1000|0||p2→p6 实测约 110M 容量、无显式随机丢包
p2-p6-shallow-policer|forward|1.5|0.2|10|0|0|110|20|1.5|0.2|10|0|0|110|20|0||p2→p6 型浅队列限速，验证超速诱发丢包而非随机丢包
p2-wuwei-lossy-upload|forward|42|8|50|12|70|50|2500|42|4|25|0.5|20|500|5000|0||p2→wuwei-ws 型约 85 ms RTT、前向 12% 成串丢包
cross-carrier-cn-upload|forward|18|4|25|1.2|35|100|1500|18|4|25|0.3|20|500|3000|0||国内跨运营商，家庭侧 100M 上行/500M 下行
cross-carrier-cn-download|reverse|18|4|25|1.2|35|100|1500|18|4|25|0.3|20|500|3000|0||国内跨运营商，家庭侧 100M 上行/500M 下行：下载
cross-carrier-cn-high-rtt-upload|forward|42|6|30|2.5|40|100|1800|42|4|25|0.5|20|500|3500|0||国内远距离跨运营商，约 85 ms RTT、100M 上行/500M 下行，作为 r2 留出集
intercontinental-upload|forward|90|12|25|1.5|40|100|2500|90|12|25|0.5|20|500|5000|0||约 180 ms RTT 的洲际非对称链路
intercontinental-download|reverse|90|12|25|1.5|40|100|2500|90|12|25|0.5|20|500|5000|0||约 180 ms RTT 的洲际非对称链路：下载
home-100d-50u-upload|forward|8|2|20|0.2|10|50|1000|8|2|20|0.1|10|100|1500|0||中国家庭 100M 下行/50M 上行：上传
home-100d-50u-download|reverse|8|2|20|0.2|10|50|1000|8|2|20|0.1|10|100|1500|0||中国家庭 100M 下行/50M 上行：下载
home-200d-50u-upload|forward|8|2|20|0.2|10|50|1000|8|2|20|0.1|10|200|2000|0||中国家庭 200M 下行/50M 上行：上传
home-200d-50u-download|reverse|8|2|20|0.2|10|50|1000|8|2|20|0.1|10|200|2000|0||中国家庭 200M 下行/50M 上行：下载
home-500d-100u-upload|forward|8|2|20|0.2|10|100|1500|8|2|20|0.1|10|500|4000|0||中国家庭 500M 下行/100M 上行：上传
home-500d-100u-download|reverse|8|2|20|0.2|10|100|1500|8|2|20|0.1|10|500|4000|0||中国家庭 500M 下行/100M 上行：下载
home-1000d-100u-upload|forward|8|2|20|0.2|10|100|1500|8|2|20|0.1|10|1000|8000|0||中国家庭 1000M 下行/100M 上行：上传
home-1000d-100u-download|reverse|8|2|20|0.2|10|100|1500|8|2|20|0.1|10|1000|8000|0||中国家庭 1000M 下行/100M 上行：下载
step-bw-100-20-100|forward|8|2|20|0.2|10|100|1500|8|2|20|0.1|10|100|1500|60|20:a_rate=20,a_queue=300;40:a_rate=100,a_queue=1500|动态：家庭 100M 上行在 20 s 跌到 20M（浅队列），40 s 恢复
burst-loss-0-5-0|forward|42|8|50|0|0|50|2500|42|4|25|0|0|500|5000|60|20:a_loss=5,a_loss_corr=70;40:a_loss=0,a_loss_corr=0|动态：85 ms RTT 路径在 20 s 出现 5% 成串丢包，40 s 消失
rtt-shift-40-120|forward|20|2|20|0|0|100|2000|20|2|20|0|0|100|2000|60|20:a_delay=60,b_delay=60;40:a_delay=20,b_delay=20|动态：RTT 在 20 s 从 40 ms 跳到 120 ms，40 s 回落
policer-onset|forward|1.5|0.2|10|0|0|110|1000|1.5|0.2|10|0|0|110|1000|45|20:a_queue=20|动态：110M 路径在 20 s 变成浅队列限速
wifi-degrade|forward|2|1|25|0.2|25|300|1000|2|1|25|0.2|25|300|1000|60|20:a_rate=60,a_jitter=4,a_loss=2.5,a_loss_corr=60;40:a_rate=300,a_jitter=1,a_loss=0.2,a_loss_corr=25|动态：Wi-Fi 在 20 s 受干扰（限速、抖动、成串丢包），40 s 恢复
EOF
}

if [[ ${1:-} == --list ]]; then
  catalog
  exit 0
fi

if [[ -e $MATRIX_OUT && $RESUME == 0 ]]; then
  echo "matrix output already exists: $MATRIX_OUT" >&2
  exit 1
fi

ensure_profiling_binaries
[[ -x $PROFILE_SCRIPT ]] || { echo "missing profile script: $PROFILE_SCRIPT" >&2; exit 1; }
[[ -x $BIN ]] || { echo "missing profiling daemon: $BIN" >&2; exit 1; }
[[ -x $CLI ]] || { echo "missing profiling CLI: $CLI" >&2; exit 1; }
mkdir -p "$MATRIX_OUT"
SOURCE_REVISION=$(git -C "$ROOT" rev-parse --verify HEAD 2>/dev/null || printf 'unknown')
SOURCE_IDENTITY=$(source_identity 2>/dev/null || printf 'unknown')
if [[ $MATRIX_BINARY_FRESHNESS == built-current-source \
  && $SOURCE_IDENTITY != "$SOURCE_IDENTITY_AFTER_BUILD" ]]; then
  echo "source changed after profiling build; rerun the matrix" >&2
  exit 1
fi
BIN_SHA256=$(sha256sum "$BIN" | awk '{print $1}')
CLI_SHA256=$(sha256sum "$CLI" | awk '{print $1}')
MATRIX_SCRIPT_SHA256=$(sha256sum "$ROOT/scripts/profile-v2-netns-matrix.sh" | awk '{print $1}')
PROFILE_SCRIPT_SHA256=$(sha256sum "$PROFILE_SCRIPT" | awk '{print $1}')
CATALOG_SHA256=$(catalog | sha256sum | awk '{print $1}')
AUTOTUNE_POLICY_SHA256=$(policy_content_sha256 "$AUTOTUNE_POLICY")
AUTOTUNE_SHADOW_POLICY_SHA256=$(policy_content_sha256 "$AUTOTUNE_SHADOW_POLICY")
PROFILE_ALLOWED_CPU_LIST=$(awk '/^Cpus_allowed_list:/ { print $2 }' /proc/self/status)
mapfile -t PROFILE_ALLOWED_CPUS < <(expand_cpu_list "$PROFILE_ALLOWED_CPU_LIST")
(( ${#PROFILE_ALLOWED_CPUS[@]} > 0 )) \
  || { echo "no CPUs available to the profiler" >&2; exit 1; }
PROFILE_DEFAULT_CPU_FIRST=$((${#PROFILE_ALLOWED_CPUS[@]} / 2))
PROFILE_DEFAULT_CPUSET=$(IFS=,; echo "${PROFILE_ALLOWED_CPUS[*]:$PROFILE_DEFAULT_CPU_FIRST}")
PROFILE_CPUSET=${IRONET_V2_PROFILE_CPUSET:-$PROFILE_DEFAULT_CPUSET}
RUN_CONFIG_JSON=$(python3 - "$DURATION" "$STREAMS" "$PERF_ENABLED" "$FREQUENCY" \
  "$CALL_GRAPH" "$PING_INTERVAL_MS" "$FAIRNESS_SECONDS" "$FAIRNESS_PER_STREAM_MBIT" \
  "$SETTLE_SECONDS" "$MATRIX_SCRIPT_SHA256" "$PROFILE_SCRIPT_SHA256" "$CATALOG_SHA256" \
  "$AUTOTUNE_FORCE" "$AUTOTUNE_MODE" "$AUTOTUNE_OBJECTIVE" "$AUTOTUNE_MEMORY" \
  "$AUTOTUNE_POLICY" "$AUTOTUNE_POLICY_SHA256" "$AUTOTUNE_SHADOW_POLICY" \
  "$AUTOTUNE_SHADOW_POLICY_SHA256" "$COVER_SECONDS" "$COVER_RATE_MBIT" "$SECOND_PATH" \
  "$SECOND_PATH_DELAY_MS" "$SECOND_PATH_LOSS_PERCENT" "$SECOND_PATH_RATE_MBIT" \
  "$SECOND_PATH_QUEUE_PACKETS" "$PROFILE_RUST_LOG" "$PROFILE_NICE" "$PROFILE_CPUSET" \
  "$PROFILE_ALLOWED_CPU_LIST" <<'PY'
import json
import sys

keys = (
    "duration_seconds", "streams", "perf_enabled", "sampling_frequency_hz",
    "call_graph", "ping_interval_ms", "fairness_seconds", "fairness_per_stream_mbit",
    "settle_seconds", "matrix_script_sha256", "profile_script_sha256", "catalog_sha256",
    "autotune_force", "autotune_mode", "autotune_objective", "autotune_memory",
    "autotune_policy", "autotune_policy_sha256", "autotune_shadow_policy",
    "autotune_shadow_policy_sha256", "cover_seconds", "cover_rate_mbit", "second_path",
    "second_path_delay_ms", "second_path_loss_percent", "second_path_rate_mbit",
    "second_path_queue_packets", "profile_rust_log", "profile_nice", "profile_cpuset",
    "allowed_cpu_list",
)
print(json.dumps(dict(zip(keys, sys.argv[1:])), sort_keys=True, separators=(",", ":")))
PY
)
if [[ $RESUME == 1 && -e $MATRIX_OUT/build.json ]]; then
  python3 - "$MATRIX_OUT/build.json" "$SOURCE_IDENTITY" "$BIN_SHA256" "$CLI_SHA256" \
    "$RUN_CONFIG_JSON" <<'PY'
import json
import pathlib
import sys

recorded = json.loads(pathlib.Path(sys.argv[1]).read_text())
expected = {
    "source_identity": sys.argv[2],
    "ironetd": sys.argv[3],
    "ironet": sys.argv[4],
    "run_config": json.loads(sys.argv[5]),
}
actual = {
    "source_identity": recorded.get("source_identity"),
    "ironetd": (recorded.get("ironetd") or {}).get("sha256"),
    "ironet": (recorded.get("ironet") or {}).get("sha256"),
    "run_config": recorded.get("run_config"),
}
if actual != expected:
    raise SystemExit(
        "cannot resume matrix with different source or profiling binaries; choose a new output directory"
    )
PY
elif [[ $RESUME == 1 ]] && find "$MATRIX_OUT" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
  echo "cannot resume matrix without build.json provenance; choose a new output directory" >&2
  exit 1
else
  python3 - "$MATRIX_OUT/build.json" "$MATRIX_BINARY_FRESHNESS" "$SOURCE_REVISION" \
  "$SOURCE_IDENTITY" "$BIN" "$BIN_SHA256" "$CLI" "$CLI_SHA256" "$RUN_CONFIG_JSON" <<'PY'
import json
import pathlib
import sys

pathlib.Path(sys.argv[1]).write_text(json.dumps({
    "binary_freshness": sys.argv[2],
    "source_revision": sys.argv[3],
    "source_identity": sys.argv[4],
    "ironetd": {"path": sys.argv[5], "sha256": sys.argv[6]},
    "ironet": {"path": sys.argv[7], "sha256": sys.argv[8]},
    "run_config": json.loads(sys.argv[9]),
}, indent=2) + "\n")
PY
fi
if [[ ! -s $MATRIX_OUT/manifest.tsv ]]; then
  printf 'scenario\tdirection\tdescription\toutput\n' >"$MATRIX_OUT/manifest.tsv"
fi

while IFS='|' read -r name direction \
    a_delay a_jitter a_delay_corr a_loss a_loss_corr a_rate a_queue \
    b_delay b_jitter b_delay_corr b_loss b_loss_corr b_rate b_queue \
    seconds timeline description; do
  scenario_selected "$name" || continue
  scenario_seconds=$DURATION
  [[ $seconds == 0 ]] || scenario_seconds=$seconds
  out="$MATRIX_OUT/$name"
  if [[ $RESUME == 1 && -s $out/summary.json ]]; then
    if python3 - "$out/summary.json" "$name" <<'PY'
import json
import pathlib
import sys

summary = json.loads(pathlib.Path(sys.argv[1]).read_text())
if summary.get("scenario") != sys.argv[2]:
    raise SystemExit(1)
PY
    then
      printf 'skipping completed %s\n' "$name"
      continue
    fi
    printf 'completed summary for %s is invalid; rerunning it\n' "$name" >&2
  fi
  if [[ -e $out ]]; then
    interrupted="$MATRIX_OUT/.interrupted-$name-$(date -u +%Y%m%d-%H%M%S)"
    printf 'preserving interrupted %s as %s\n' "$name" "$interrupted"
    mv "$out" "$interrupted"
  fi
  printf 'running %s (%s)\n' "$name" "$description"
  env \
    IRONETD_BIN="$BIN" \
    IRONET_BIN="$CLI" \
    IRONET_V2_PROFILE_OUT="$out" \
    IRONET_V2_PROFILE_SCENARIO_NAME="$name" \
    IRONET_V2_PROFILE_DIRECTION="$direction" \
    IRONET_V2_PROFILE_SECONDS="$scenario_seconds" \
    IRONET_V2_PROFILE_TIMELINE="$timeline" \
    IRONET_V2_PROFILE_PERF="$PERF_ENABLED" \
    IRONET_V2_PROFILE_STREAMS="$STREAMS" \
    IRONET_V2_PROFILE_FREQUENCY="$FREQUENCY" \
    IRONET_V2_PROFILE_CALL_GRAPH="$CALL_GRAPH" \
    IRONET_V2_PROFILE_DISABLE_TUN_OFFLOAD=0 \
    IRONET_V2_PROFILE_CONCURRENT_PING_INTERVAL_MS="$PING_INTERVAL_MS" \
    IRONET_V2_PROFILE_FAIRNESS_SECONDS="$FAIRNESS_SECONDS" \
    IRONET_V2_PROFILE_FAIRNESS_PER_STREAM_MBIT="$FAIRNESS_PER_STREAM_MBIT" \
    IRONET_V2_PROFILE_A_TO_B_DELAY_MS="$a_delay" \
    IRONET_V2_PROFILE_A_TO_B_JITTER_MS="$a_jitter" \
    IRONET_V2_PROFILE_A_TO_B_DELAY_CORRELATION_PERCENT="$a_delay_corr" \
    IRONET_V2_PROFILE_A_TO_B_LOSS_PERCENT="$a_loss" \
    IRONET_V2_PROFILE_A_TO_B_LOSS_CORRELATION_PERCENT="$a_loss_corr" \
    IRONET_V2_PROFILE_A_TO_B_RATE_MBIT="$a_rate" \
    IRONET_V2_PROFILE_A_TO_B_QUEUE_PACKETS="$a_queue" \
    IRONET_V2_PROFILE_B_TO_A_DELAY_MS="$b_delay" \
    IRONET_V2_PROFILE_B_TO_A_JITTER_MS="$b_jitter" \
    IRONET_V2_PROFILE_B_TO_A_DELAY_CORRELATION_PERCENT="$b_delay_corr" \
    IRONET_V2_PROFILE_B_TO_A_LOSS_PERCENT="$b_loss" \
    IRONET_V2_PROFILE_B_TO_A_LOSS_CORRELATION_PERCENT="$b_loss_corr" \
    IRONET_V2_PROFILE_B_TO_A_RATE_MBIT="$b_rate" \
    IRONET_V2_PROFILE_B_TO_A_QUEUE_PACKETS="$b_queue" \
    bash "$PROFILE_SCRIPT"
  printf '%s\t%s\t%s\t%s\n' "$name" "$direction" "$description" "$out" \
    >>"$MATRIX_OUT/manifest.tsv"
  # perf/daemon descendants are fully joined by the scenario script, but the
  # host flock file descriptor can remain alive for a final scheduler tick on
  # some sudo/perf process trees. Avoid a false overlap rejection.
  sleep "$SETTLE_SECONDS"
done < <(catalog)

python3 - "$MATRIX_OUT" <<'PY'
import csv
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
rows = []
for summary_path in sorted(root.glob("*/summary.json")):
    if summary_path.parent.name.startswith("."):
        continue
    data = json.loads(summary_path.read_text())
    netem = data["netem"]
    active_rate = (
        netem["a_to_b_rate_mbit"]
        if data["direction"] == "forward"
        else netem["b_to_a_rate_mbit"]
    )
    segments = data.get("segments") or []
    settle = [
        segment["settle_seconds"] for segment in segments[1:]
        if segment.get("settle_seconds") is not None
    ]
    unsettled = sum(
        1 for segment in segments[1:] if segment.get("settle_seconds") is None
    )
    active_side = "a" if data["direction"] == "forward" else "b"
    autotune = (data.get("autotune") or {}).get(active_side) or {}
    fairness = data.get("overlay_udp_fairness") or {}
    admission_shed = (data.get("tun_admission_shed") or {}).get(active_side) or {}
    controller = data.get("controller_alignment") or {}
    rows.append({
        "scenario": data["scenario"],
        "direction": data["direction"],
        "seconds": data.get("duration_seconds"),
        "autotune_objective": data.get("autotune_objective"),
        "timeline_steps": len(data.get("timeline") or []),
        "max_settle_seconds": max(settle) if settle else None,
        "unsettled_segments": unsettled if segments else None,
        "path_rate_mbit": active_rate,
        "underlay_mbit": data["underlay_received_bits_per_second"] / 1e6,
        "overlay_mbit": data["overlay_received_bits_per_second"] / 1e6,
        "overlay_underlay_ratio": data["overlay_to_underlay_ratio"],
        "underlay_ping_p95_ms": (data.get("underlay_concurrent_ping") or {}).get("p95_ms"),
        "overlay_ping_p95_ms": (data.get("overlay_concurrent_ping") or {}).get("p95_ms"),
        "utility_mean": autotune.get("utility_mean"),
        "utility_last10_mean": autotune.get("utility_last10_mean"),
        "utility_p10": autotune.get("utility_p10"),
        "preset_switches": autotune.get("preset_switches"),
        "rollbacks": autotune.get("rollbacks"),
        "convergence_seconds": autotune.get("convergence_seconds"),
        "residual_loss_ppm_mean": autotune.get("residual_loss_ppm_mean"),
        "latency_sojourn_p95_mean": autotune.get("latency_sojourn_p95_mean"),
        "shadow_policy_id": (autotune.get("shadow") or {}).get("policy_id"),
        "shadow_final_preset": (autotune.get("shadow") or {}).get("final_proposed_preset"),
        "shadow_advantage_mean": (autotune.get("shadow") or {}).get("predicted_advantage_mean"),
        "shadow_advantage_last10_mean": (autotune.get("shadow") or {}).get("predicted_advantage_last10_mean"),
        "fairness_streams": fairness.get("streams"),
        "fairness_jain": fairness.get("jain_fairness"),
        "fairness_spread_percent": fairness.get("spread_percent"),
        "fairness_maximum_deviation_percent": fairness.get("maximum_deviation_percent"),
        "tun_admission_shed_records": admission_shed.get("records"),
        "tun_admission_shed_bytes": admission_shed.get("bytes"),
        "controller_alignment_samples": controller.get("samples"),
        "controller_alignment_steady_samples": controller.get("steady_samples"),
        "path_identity_switches": controller.get("path_identity_switches"),
        "path_epoch_switches": controller.get("path_epoch_switches"),
        "overlay_controller_bw_correlation": controller.get("overlay_controller_bw_correlation"),
        "overlay_cwnd_correlation": controller.get("overlay_cwnd_correlation"),
        "overlay_cwnd_floor_correlation": controller.get("overlay_cwnd_floor_correlation"),
        "final5_controller_bw_bytes_per_second_mean": controller.get("final5_controller_bw_bytes_per_second_mean"),
        "final5_controller_cwnd_bytes_mean": controller.get("final5_controller_cwnd_bytes_mean"),
        "final5_adaptive_cwnd_floor_bytes_mean": controller.get("final5_adaptive_cwnd_floor_bytes_mean"),
        "final5_packet_train_queue_bytes_mean": controller.get("final5_packet_train_queue_bytes_mean"),
        "a_perf_lost_samples": data["a_perf_lost_samples"],
        "b_perf_lost_samples": data["b_perf_lost_samples"],
        "output": str(summary_path.parent),
    })
(root / "aggregate.json").write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n")
with (root / "aggregate.csv").open("w", newline="") as handle:
    writer = csv.DictWriter(handle, fieldnames=list(rows[0]) if rows else ["scenario"])
    writer.writeheader()
    writer.writerows(rows)
print(json.dumps(rows, ensure_ascii=False, indent=2))
PY

echo "$MATRIX_OUT"

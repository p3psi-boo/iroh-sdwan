#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${IRONETD_BIN:-$ROOT/target/profiling/ironetd}
CLI=${IRONET_BIN:-$ROOT/target/profiling/ironet}
OUT=${IRONET_V2_PROFILE_OUT:-$ROOT/target/v2-subnet-netns-profile-$(date -u +%Y%m%d-%H%M%S)}
DURATION=${IRONET_V2_PROFILE_SECONDS:-20}
PARALLEL=${IRONET_V2_PROFILE_STREAMS:-4}
PERF_FREQUENCY=${IRONET_V2_PROFILE_FREQUENCY:-99}
CALL_GRAPH=${IRONET_V2_PROFILE_CALL_GRAPH:-dwarf}
PERF=${PERF:-$(command -v perf || true)}
CPU_CORE_CPUS_FILE=${CPU_CORE_CPUS_FILE:-/sys/bus/event_source/devices/cpu_core/cpus}
CPU_ATOM_CPUS_FILE=${CPU_ATOM_CPUS_FILE:-/sys/bus/event_source/devices/cpu_atom/cpus}
IPERF3=${IPERF3:-$(command -v iperf3 || true)}
STACKCOLLAPSE=${STACKCOLLAPSE:-$(command -v stackcollapse-perf.pl || true)}
FLAMEGRAPH=${FLAMEGRAPH:-$(command -v flamegraph.pl || true)}
SHA256SUM=${SHA256SUM:-$(command -v sha256sum || true)}
DISABLE_TUN_OFFLOAD=${IRONET_V2_PROFILE_DISABLE_TUN_OFFLOAD:-0}
ETHTOOL=${ETHTOOL:-$(command -v ethtool || true)}
TC=${TC:-$(command -v tc || true)}
A_TO_B_DELAY_MS=${IRONET_V2_PROFILE_A_TO_B_DELAY_MS:-0}
A_TO_B_LOSS_PERCENT=${IRONET_V2_PROFILE_A_TO_B_LOSS_PERCENT:-0}
B_TO_A_DELAY_MS=${IRONET_V2_PROFILE_B_TO_A_DELAY_MS:-0}
B_TO_A_LOSS_PERCENT=${IRONET_V2_PROFILE_B_TO_A_LOSS_PERCENT:-0}
SUBNET_NAT=${IRONET_V2_PROFILE_SUBNET_NAT:-0}
RELOAD_MATRIX=${IRONET_V2_PROFILE_RELOAD:-0}
TASKSET=${TASKSET:-$(command -v taskset || true)}
NICE=${NICE:-$(command -v nice || true)}
FLOCK=${FLOCK:-$(command -v flock || true)}
TIMEOUT=${TIMEOUT:-$(command -v timeout || true)}
PROFILE_NICE=${IRONET_V2_PROFILE_NICE:-10}
PREFLIGHT_ONLY=${IRONET_V2_PROFILE_PREFLIGHT_ONLY:-0}
STARTUP_CANARY_ONLY=${IRONET_V2_PROFILE_STARTUP_CANARY_ONLY:-0}
QUEUE_DRAIN_TIMEOUT_SECONDS=${IRONET_V2_PROFILE_QUEUE_DRAIN_TIMEOUT_SECONDS:-15}

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

ALLOWED_CPU_LIST=$(awk '/^Cpus_allowed_list:/ { print $2 }' /proc/self/status)
mapfile -t ALLOWED_CPUS < <(expand_cpu_list "$ALLOWED_CPU_LIST")
CPU_COUNT=${#ALLOWED_CPUS[@]}
((CPU_COUNT > 0)) || { echo "no CPUs available to the profiler" >&2; exit 1; }
DEFAULT_CPU_FIRST=$((CPU_COUNT / 2))
DEFAULT_CPUSET=$(IFS=,; echo "${ALLOWED_CPUS[*]:$DEFAULT_CPU_FIRST}")
PROFILE_CPUSET=${IRONET_V2_PROFILE_CPUSET:-$DEFAULT_CPUSET}

[[ -x $BIN ]] || { echo "missing profiling binary: $BIN" >&2; exit 1; }
[[ -x $CLI ]] || { echo "missing product CLI: $CLI" >&2; exit 1; }
[[ -x $SHA256SUM ]] || { echo "set SHA256SUM to sha256sum" >&2; exit 1; }
[[ -x $TASKSET ]] || { echo "set TASKSET to the taskset executable" >&2; exit 1; }
[[ -x $NICE ]] || { echo "set NICE to the nice executable" >&2; exit 1; }
[[ -x $FLOCK ]] || { echo "set FLOCK to the flock executable" >&2; exit 1; }
[[ -x $TIMEOUT ]] || { echo "set TIMEOUT to the timeout executable" >&2; exit 1; }
[[ -x $TC ]] || { echo "set TC to the tc executable" >&2; exit 1; }
[[ $PREFLIGHT_ONLY == 0 || $PREFLIGHT_ONLY == 1 ]] \
  || { echo "IRONET_V2_PROFILE_PREFLIGHT_ONLY must be 0 or 1" >&2; exit 1; }
[[ $STARTUP_CANARY_ONLY == 0 || $STARTUP_CANARY_ONLY == 1 ]] \
  || { echo "IRONET_V2_PROFILE_STARTUP_CANARY_ONLY must be 0 or 1" >&2; exit 1; }
[[ $QUEUE_DRAIN_TIMEOUT_SECONDS =~ ^[1-9][0-9]*$ ]] \
  || { echo "invalid class queue drain timeout" >&2; exit 1; }
[[ $PREFLIGHT_ONLY == 0 || $STARTUP_CANARY_ONLY == 0 ]] \
  || { echo "preflight-only and startup-canary-only are mutually exclusive" >&2; exit 1; }
if [[ $PREFLIGHT_ONLY == 0 && $STARTUP_CANARY_ONLY == 0 ]]; then
  [[ -x $PERF ]] || { echo "set PERF to the perf executable" >&2; exit 1; }
  [[ -x $IPERF3 ]] || { echo "set IPERF3 to the iperf3 executable" >&2; exit 1; }
  [[ -x $STACKCOLLAPSE ]] || { echo "set STACKCOLLAPSE to stackcollapse-perf.pl" >&2; exit 1; }
  [[ -x $FLAMEGRAPH ]] || { echo "set FLAMEGRAPH to flamegraph.pl" >&2; exit 1; }
fi
[[ $PERF_FREQUENCY =~ ^[1-9][0-9]*$ ]] || { echo "invalid perf sampling frequency" >&2; exit 1; }
[[ $CALL_GRAPH == dwarf || $CALL_GRAPH == fp || $CALL_GRAPH == lbr ]] \
  || { echo "invalid perf call graph mode: $CALL_GRAPH" >&2; exit 1; }
[[ $SUBNET_NAT == 0 || $SUBNET_NAT == 1 ]] \
  || { echo "IRONET_V2_PROFILE_SUBNET_NAT must be 0 or 1" >&2; exit 1; }
[[ $RELOAD_MATRIX == 0 || $RELOAD_MATRIX == 1 ]] \
  || { echo "IRONET_V2_PROFILE_RELOAD must be 0 or 1" >&2; exit 1; }
[[ $PROFILE_NICE =~ ^(0|[1-9]|1[0-9])$ ]] \
  || { echo "profile nice level must be between 0 and 19" >&2; exit 1; }
"$TASKSET" -c "$PROFILE_CPUSET" true 2>/dev/null \
  || { echo "invalid or unavailable profile CPU set: $PROFILE_CPUSET" >&2; exit 1; }
for value in "$A_TO_B_DELAY_MS" "$A_TO_B_LOSS_PERCENT" \
  "$B_TO_A_DELAY_MS" "$B_TO_A_LOSS_PERCENT"; do
  [[ $value =~ ^[0-9]+([.][0-9]+)?$ ]] \
    || { echo "invalid netem delay/loss value: $value" >&2; exit 1; }
done
if [[ $PREFLIGHT_ONLY == 0 && $DISABLE_TUN_OFFLOAD == 1 ]]; then
  [[ -x $ETHTOOL ]] || { echo "set ETHTOOL when disabling TUN offload" >&2; exit 1; }
fi
sudo -n true
exec 9>"${TMPDIR:-/tmp}/ironet-v2-profile.lock"
"$FLOCK" -n 9 || { echo "another Ironet V2 profile is active" >&2; exit 1; }

mkdir -p "$OUT"
OUT=$(realpath "$OUT")
BINARY_SHA256=$($SHA256SUM "$BIN" | awk '{print $1}')
CLI_SHA256=$($SHA256SUM "$CLI" | awk '{print $1}')
printf '%s  %s\n' "$BINARY_SHA256" "$(realpath "$BIN")" >"$OUT/binary.sha256"
printf '%s  %s\n' "$CLI_SHA256" "$(realpath "$CLI")" >>"$OUT/binary.sha256"
printf 'cpuset=%s\nnice=%s\nperf_frequency_hz=%s\n' \
  "$PROFILE_CPUSET" "$PROFILE_NICE" "$PERF_FREQUENCY" >"$OUT/resource-isolation.txt"
NS="v2-prof-$$"
NSA="$NS-a"
NSB="$NS-b"
NSC="$NS-lan"
LINK="v2p$(( $$ % 100000 ))"
LAN_LINK="v2l$(( $$ % 100000 ))"
LAN_GATEWAY_V4=11.6.1.1
LAN_HOST_V4=11.6.1.48
LAN_GATEWAY_V6=fd11:6:1::1
LAN_HOST_V6=fd11:6:1::48
PORT=$((20000 + $$ % 20000))
printf -v UNDERLAY_A 'fd76::%x' "$((($$ % 30000) + 1))"
printf -v UNDERLAY_B 'fd76::%x' "$((($$ % 30000) + 2))"
A_PID=
B_PID=
A_LAUNCH=
B_LAUNCH=
GUARD_BEFORE="$OUT/management-plane.before"
GUARD_AFTER="$OUT/management-plane.after"

capture_management_plane() {
  local output=$1
  {
    echo '[route-200]'
    ip -6 route show table all 200::/7 2>/dev/null || true
    echo '[tun-ygg-link]'
    ip -details link show dev tun-ygg 2>/dev/null || true
    echo '[tun-ygg-addresses]'
    ip -6 address show dev tun-ygg 2>/dev/null || true
    echo '[tun-ygg-qdisc]'
    "$TC" qdisc show dev tun-ygg 2>/dev/null || true
  } >"$output"
}

verify_management_plane() {
  capture_management_plane "$GUARD_AFTER"
  if ! cmp -s "$GUARD_BEFORE" "$GUARD_AFTER"; then
    diff -u "$GUARD_BEFORE" "$GUARD_AFTER" >"$OUT/management-plane.diff" || true
    echo "management-plane invariant changed; see $OUT/management-plane.diff" >&2
    return 1
  fi
}

run_limited() {
  local namespace=$1
  shift
  sudo ip netns exec "$namespace" "$TASKSET" -c "$PROFILE_CPUSET" \
    "$NICE" -n "$PROFILE_NICE" "$@"
}

run_limited_host() {
  "$TASKSET" -c "$PROFILE_CPUSET" "$NICE" -n "$PROFILE_NICE" "$@"
}

# A broken overlay must not leave iperf holding a namespace, profiler, or SSH
# management resources indefinitely. Every client and one-shot server gets a
# hard wall-clock bound beyond the requested sample window.
run_iperf() {
  local namespace=$1
  shift
  run_limited "$namespace" "$TIMEOUT" --signal=INT --kill-after=5s \
    "$((DURATION + 30))s" "$IPERF3" "$@"
}

capture_management_plane "$GUARD_BEFORE"

profile_pid_is_safe() {
  local pid=${1:-}
  [[ $pid =~ ^[0-9]+$ && $pid -gt 2 ]] || return 1
  [[ -r /proc/$pid/cmdline ]] || return 1
  # Require both the profiler and this exact benchmark binary in argv before
  # any privileged signal is sent to a host PID.
  if [[ $STARTUP_CANARY_ONLY == 1 ]]; then
    tr '\0' '\n' <"/proc/$pid/cmdline" | grep -Fqx -- "$BIN"
  else
    tr '\0' '\n' <"/proc/$pid/cmdline" | grep -Fqx -- "$PERF" \
      && tr '\0' '\n' <"/proc/$pid/cmdline" | grep -Fqx -- "$BIN"
  fi
}

stop_profiled() {
  local perf_pid=${1:-} launch_pid=${2:-}
  [[ -n $perf_pid ]] || return 0
  if ! sudo kill -0 "$perf_pid" 2>/dev/null; then
    [[ -n $launch_pid ]] && wait "$launch_pid" 2>/dev/null || true
    return 0
  fi
  if ! profile_pid_is_safe "$perf_pid"; then
    echo "refusing to signal unverified host PID: $perf_pid" >&2
    return 1
  fi
  local children
  children=$(pgrep -P "$perf_pid" 2>/dev/null || true)
  for _ in $(seq 1 100); do
    sudo kill -0 "$perf_pid" 2>/dev/null || break
    sleep 0.1
  done
  if sudo kill -0 "$perf_pid" 2>/dev/null; then
    sudo kill -TERM -- "$perf_pid" $children 2>/dev/null || true
    sleep 0.2
  fi
  if sudo kill -0 "$perf_pid" 2>/dev/null; then
    sudo kill -KILL -- "$perf_pid" $children 2>/dev/null || true
  fi
  [[ -n $launch_pid ]] && wait "$launch_pid" 2>/dev/null || true
}

stop_profiled_pair() {
  # Signal both endpoints before waiting for either one. A graceful close from
  # one side otherwise makes its peer report a dataplane failure at shutdown.
  local a_children= b_children=
  # Never substitute PID 0 here: `pgrep -P 0` selects host init/kernel
  # processes and a following privileged kill would hit the management plane.
  if [[ -n ${A_PID:-} ]] && profile_pid_is_safe "$A_PID"; then
    if [[ $STARTUP_CANARY_ONLY == 1 ]]; then
      a_children=$A_PID
    else
      a_children=$(pgrep -P "$A_PID" 2>/dev/null || true)
    fi
  fi
  if [[ -n ${B_PID:-} ]] && profile_pid_is_safe "$B_PID"; then
    if [[ $STARTUP_CANARY_ONLY == 1 ]]; then
      b_children=$B_PID
    else
      b_children=$(pgrep -P "$B_PID" 2>/dev/null || true)
    fi
  fi
  if [[ -n $a_children || -n $b_children ]]; then
    # One kill(2) request makes the delivery window materially smaller than
    # two sequential sudo invocations.
    sudo kill -INT -- $a_children $b_children 2>/dev/null || true
  fi
  stop_profiled "$A_PID" "$A_LAUNCH"
  stop_profiled "$B_PID" "$B_LAUNCH"
}

cleanup() {
  set +e
  stop_profiled_pair
  sudo ip netns del "$NSA" 2>/dev/null
  sudo ip netns del "$NSB" 2>/dev/null
  sudo ip netns del "$NSC" 2>/dev/null
}

on_exit() {
  local status=$?
  trap - EXIT INT TERM HUP
  cleanup
  verify_management_plane || status=97
  exit "$status"
}
trap on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

sudo ip netns add "$NSA"
sudo ip netns add "$NSB"
sudo ip netns add "$NSC"
sudo ip link add "$LINK-a" type veth peer name "$LINK-b"
sudo ip link add "$LAN_LINK-b" type veth peer name "$LAN_LINK-c"
sudo ip link set "$LINK-a" netns "$NSA"
sudo ip link set "$LINK-b" netns "$NSB"
sudo ip link set "$LAN_LINK-b" netns "$NSB"
sudo ip link set "$LAN_LINK-c" netns "$NSC"
sudo ip -n "$NSA" link set lo up
sudo ip -n "$NSB" link set lo up
sudo ip -n "$NSC" link set lo up
sudo ip -n "$NSA" -6 addr add "$UNDERLAY_A/64" dev "$LINK-a" nodad
sudo ip -n "$NSB" -6 addr add "$UNDERLAY_B/64" dev "$LINK-b" nodad
sudo ip -n "$NSA" link set "$LINK-a" up
sudo ip -n "$NSB" link set "$LINK-b" up
sudo ip -n "$NSB" addr add "$LAN_GATEWAY_V4/24" dev "$LAN_LINK-b"
sudo ip -n "$NSC" addr add "$LAN_HOST_V4/24" dev "$LAN_LINK-c"
sudo ip -n "$NSB" -6 addr add "$LAN_GATEWAY_V6/64" dev "$LAN_LINK-b" nodad
sudo ip -n "$NSC" -6 addr add "$LAN_HOST_V6/64" dev "$LAN_LINK-c" nodad
sudo ip -n "$NSB" link set "$LAN_LINK-b" up
sudo ip -n "$NSC" link set "$LAN_LINK-c" up
sudo ip netns exec "$NSB" sysctl -q -w net.ipv4.ip_forward=1

apply_netem() {
  local namespace=$1 device=$2 delay_ms=$3 loss_percent=$4
  [[ $delay_ms != 0 || $loss_percent != 0 ]] || return 0
  [[ $namespace == "$NSA" || $namespace == "$NSB" ]] \
    || { echo "refusing netem outside the profile namespaces" >&2; return 1; }
  [[ $device == "$LINK-a" || $device == "$LINK-b" ]] \
    || { echo "refusing netem on a non-profile interface" >&2; return 1; }
  local args=(netem)
  [[ $delay_ms == 0 ]] || args+=(delay "${delay_ms}ms")
  [[ $loss_percent == 0 ]] || args+=(loss "${loss_percent}%")
  sudo ip netns exec "$namespace" "$TC" qdisc replace dev "$device" root "${args[@]}"
}

# netem is attached to each sender's egress. These names therefore describe
# actual direction rather than the receiving namespace, which is critical for
# reproducing asymmetric p2 -> wuwei-ws loss.
apply_netem "$NSA" "$LINK-a" "$A_TO_B_DELAY_MS" "$A_TO_B_LOSS_PERCENT"
apply_netem "$NSB" "$LINK-b" "$B_TO_A_DELAY_MS" "$B_TO_A_LOSS_PERCENT"

if [[ $PREFLIGHT_ONLY == 1 ]]; then
  printf 'preflight_only=1\nstatus=namespace_scope_verified\n' \
    >>"$OUT/resource-isolation.txt"
  exit 0
fi

B_NAT_ARGS=()
if [[ $SUBNET_NAT == 1 ]]; then
  command -v iptables >/dev/null
  command -v ip6tables >/dev/null
fi
if [[ $RELOAD_MATRIX == 1 ]]; then
  command -v iptables-save >/dev/null
  command -v ip6tables-save >/dev/null
fi

A_STATE="$OUT/a-state"
B_STATE="$OUT/b-state"
A_CONFIG="$A_STATE/config.toml"
B_CONFIG="$B_STATE/config.toml"
A_SOCKET="$A_STATE/control.sock"
B_SOCKET="$B_STATE/control.sock"
mkdir -p "$A_STATE" "$B_STATE"

run_product() {
  local namespace=$1 config=$2 state=$3 socket=$4
  shift 4
  run_limited "$namespace" "$CLI" \
    --config "$config" --state-dir "$state" --socket "$socket" "$@"
}

status_queues_are_drained() {
  python3 - "$@" <<'PY'
import json
import pathlib
import sys

for name in sys.argv[1:]:
    status = json.loads(pathlib.Path(name).read_text())
    for peer in status.get("peers", []):
        traffic = peer.get("traffic") or {}
        if traffic.get("packet_train_queue_bytes", 0) != 0:
            raise SystemExit(1)
        if traffic.get("latency_queue_bytes", 0) != 0:
            raise SystemExit(1)
PY
}

wait_for_class_queues_to_drain() {
  local attempts=$((QUEUE_DRAIN_TIMEOUT_SECONDS * 10)) attempt
  local a_tmp="$OUT/a-final-status.json.tmp"
  local b_tmp="$OUT/b-final-status.json.tmp"
  for attempt in $(seq 1 "$attempts"); do
    if run_product "$NSA" "$A_CONFIG" "$A_STATE" "$A_SOCKET" \
        status --output json >"$a_tmp" \
      && run_product "$NSB" "$B_CONFIG" "$B_STATE" "$B_SOCKET" \
        status --output json >"$b_tmp" \
      && status_queues_are_drained "$a_tmp" "$b_tmp"; then
      mv "$a_tmp" "$OUT/a-final-status.json"
      mv "$b_tmp" "$OUT/b-final-status.json"
      printf 'drained=true\nattempts=%s\nelapsed_milliseconds=%s\n' \
        "$attempt" "$((attempt * 100))" >"$OUT/queue-drain.txt"
      return 0
    fi
    sleep 0.1
  done
  [[ -s $a_tmp ]] && mv "$a_tmp" "$OUT/a-final-status.json"
  [[ -s $b_tmp ]] && mv "$b_tmp" "$OUT/b-final-status.json"
  printf 'drained=false\nattempts=%s\nelapsed_milliseconds=%s\n' \
    "$attempts" "$((attempts * 100))" >"$OUT/queue-drain.txt"
  echo "V2 class queues did not drain within ${QUEUE_DRAIN_TIMEOUT_SECONDS}s" >&2
  return 1
}

run_product "$NSB" "$B_CONFIG" "$B_STATE" "$B_SOCKET" \
  network create profile-v2-subnet --node-name b \
  --address-pool 198.18.0.0/16 --ipv6-address-pool fd42:6972:6f68::/64 \
  --listen "[$UNDERLAY_B]:$PORT" --no-dns --no-start --output json \
  >"$OUT/b-network.json"
run_product "$NSB" "$B_CONFIG" "$B_STATE" "$B_SOCKET" \
  invite create --address "[$UNDERLAY_B]:$PORT" --output json \
  >"$OUT/invite.json"
TOKEN=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["token"])' \
  "$OUT/invite.json")
run_product "$NSA" "$A_CONFIG" "$A_STATE" "$A_SOCKET" \
  join "$TOKEN" --node-name a --no-start --output json >"$OUT/a-network.json"
run_product "$NSB" "$B_CONFIG" "$B_STATE" "$B_SOCKET" \
  subnet publish "$LAN_HOST_V4/32" --output json >"$OUT/subnet-v4.json"
run_product "$NSB" "$B_CONFIG" "$B_STATE" "$B_SOCKET" \
  subnet publish "$LAN_HOST_V6/128" --output json >"$OUT/subnet-v6.json"
if [[ $SUBNET_NAT == 0 ]]; then
  if sudo grep -q '^nat_enabled = ' "$B_CONFIG"; then
    sudo sed -i 's/^nat_enabled = .*$/nat_enabled = false/' "$B_CONFIG"
  elif sudo grep -q '^\[routing\]$' "$B_CONFIG"; then
    sudo sed -i '/^\[routing\]$/a nat_enabled = false' "$B_CONFIG"
  else
    printf '\n[routing]\nnat_enabled = false\n' | sudo tee -a "$B_CONFIG" >/dev/null
  fi
  run_product "$NSB" "$B_CONFIG" "$B_STATE" "$B_SOCKET" seal-config >/dev/null
fi
A_OVERLAY=$(python3 -c \
  'import json,sys; print(next(x.split("/")[0] for x in json.load(open(sys.argv[1]))["network"]["addresses"] if "." in x))' \
  "$OUT/a-network.json")
A_OVERLAY_V6=$(python3 -c \
  'import json,sys; print(next(x.split("/")[0] for x in json.load(open(sys.argv[1]))["network"]["addresses"] if ":" in x))' \
  "$OUT/a-network.json")
B_OVERLAY=$(python3 -c \
  'import json,sys; print(next(x.split("/")[0] for x in json.load(open(sys.argv[1]))["network"]["addresses"] if "." in x))' \
  "$OUT/b-network.json")
B_OVERLAY_V6=$(python3 -c \
  'import json,sys; print(next(x.split("/")[0] for x in json.load(open(sys.argv[1]))["network"]["addresses"] if ":" in x))' \
  "$OUT/b-network.json")

launch_profiled() {
  local output_variable=$1 namespace=$2 log=$3 data=$4 pidfile=$5
  shift 5
  if [[ $STARTUP_CANARY_ONLY == 1 ]]; then
    sudo ip netns exec "$namespace" sh -c \
      'echo $$ > "$1"; shift; exec "$@"' sh "$pidfile" \
      "$TASKSET" -c "$PROFILE_CPUSET" "$NICE" -n "$PROFILE_NICE" \
      env RUST_LOG=info "$BIN" "$@" >"$log" 2>&1 &
  else
    sudo ip netns exec "$namespace" sh -c \
      'echo $$ > "$1"; shift; exec "$@"' sh "$pidfile" \
      "$TASKSET" -c "$PROFILE_CPUSET" "$NICE" -n "$PROFILE_NICE" \
      env RUST_LOG=info "$PERF" record --sample-cpu -F "$PERF_FREQUENCY" -g \
      --call-graph "$CALL_GRAPH" -o "$data" -- "$BIN" "$@" \
      >"$log" 2>&1 &
  fi
  printf -v "$output_variable" '%s' "$!"
}

launch_profiled B_LAUNCH "$NSB" "$OUT/b.log" "$OUT/b.perf.data" "$OUT/b.pid" \
  --config "$B_CONFIG" --socket "$B_SOCKET" "${B_NAT_ARGS[@]}"
for _ in $(seq 1 100); do
  [[ -s $OUT/b.pid ]] && grep -q 'V2 endpoint ready' "$OUT/b.log" && break
  sleep 0.1
done
[[ -s $OUT/b.pid ]] && grep -q 'V2 endpoint ready' "$OUT/b.log"
B_PID=$(cat "$OUT/b.pid")
launch_profiled A_LAUNCH "$NSA" "$OUT/a.log" "$OUT/a.perf.data" "$OUT/a.pid" \
  --config "$A_CONFIG" --socket "$A_SOCKET"
for _ in $(seq 1 200); do
  [[ -s $OUT/a.pid ]] && grep -Eq 'V2 (mesh )?TUN configured' "$OUT/a.log" \
    && grep -Eq 'V2 (mesh )?TUN configured' "$OUT/b.log" && break
  sleep 0.1
done
[[ -s $OUT/a.pid ]] && grep -Eq 'V2 (mesh )?TUN configured' "$OUT/a.log"
grep -Eq 'V2 (mesh )?TUN configured' "$OUT/b.log"
A_PID=$(cat "$OUT/a.pid")

# Pure-routing reverse traffic must return through the gateway rather than a
# host default route. NAT mode deliberately leaves both routes absent so its
# forward ping/iperf can only receive replies through conntrack translation.
if [[ $SUBNET_NAT == 0 ]]; then
  sudo ip -n "$NSC" route add "$A_OVERLAY/32" via "$LAN_GATEWAY_V4"
  sudo ip -n "$NSC" -6 route add "$A_OVERLAY_V6/128" via "$LAN_GATEWAY_V6"
else
  ! sudo ip -n "$NSC" route get "$A_OVERLAY" >/dev/null 2>&1
  ! sudo ip -n "$NSC" -6 route get "$A_OVERLAY_V6" >/dev/null 2>&1
fi
for destination in "$LAN_HOST_V4" "$LAN_HOST_V6"; do
  for _ in $(seq 1 100); do
    sudo ip -n "$NSA" route get "$destination" 2>/dev/null | grep -q 'dev ironet0' && break
    sleep 0.1
  done
  sudo ip -n "$NSA" route get "$destination" | grep -q 'dev ironet0'
done
if [[ $STARTUP_CANARY_ONLY == 1 ]]; then
  run_product "$NSA" "$A_CONFIG" "$A_STATE" "$A_SOCKET" \
    status --output json >"$OUT/a-status.json"
  run_product "$NSB" "$B_CONFIG" "$B_STATE" "$B_SOCKET" \
    status --output json >"$OUT/b-status.json"
  printf 'startup_canary_only=1\nstatus=official_v2_subnet_routes_ready\n' \
    >>"$OUT/resource-isolation.txt"
  stop_profiled_pair
  A_PID=
  B_PID=
  A_LAUNCH=
  B_LAUNCH=
  sudo chown -R "$(id -u):$(id -g)" "$OUT"
  exit 0
fi
run_limited "$NSA" ping -q -c 3 -W 2 "$LAN_HOST_V4" \
  >"$OUT/subnet-v4-forward-ping.txt"
run_limited "$NSA" ping -6 -q -c 3 -W 2 "$LAN_HOST_V6" \
  >"$OUT/subnet-v6-forward-ping.txt"
if [[ $SUBNET_NAT == 0 ]]; then
  run_limited "$NSC" ping -q -c 3 -W 2 "$A_OVERLAY" \
    >"$OUT/subnet-v4-reverse-ping.txt"
  run_limited "$NSC" ping -6 -q -c 3 -W 2 "$A_OVERLAY_V6" \
    >"$OUT/subnet-v6-reverse-ping.txt"
fi

capture_nat_rules() {
  local suffix=$1
  for family in iptables ip6tables; do
    sudo ip netns exec "$NSB" "${family}-save" -t mangle \
      >"$OUT/${family}-mangle-${suffix}.rules"
    sudo ip netns exec "$NSB" "${family}-save" -t nat \
      >"$OUT/${family}-nat-${suffix}.rules"
  done
}

assert_nat_generation() {
  local suffix=$1 expected=$2 family definitions jumps
  for family in iptables ip6tables; do
    definitions=$(awk '/^:IRONET_V2_NAT_(IN|OUT)(_[AB])? / { count++ } \
      END { print count + 0 }' \
      "$OUT/${family}-mangle-${suffix}.rules" \
      "$OUT/${family}-nat-${suffix}.rules")
    jumps=$(awk '/-j IRONET_V2_NAT_(IN|OUT)(_[AB])?( |$)/ { count++ } \
      END { print count + 0 }' \
      "$OUT/${family}-mangle-${suffix}.rules" \
      "$OUT/${family}-nat-${suffix}.rules")
    if [[ $expected == present ]]; then
      [[ $definitions == 2 && $jumps == 2 ]]
    else
      [[ $definitions == 0 && $jumps == 0 ]]
    fi
  done
}

normalize_nat_rules() {
  local input=$1 output=$2
  # iptables-save adds timestamps and live packet counters. Compare only the
  # owned chain topology so traffic between snapshots cannot create a false
  # reload failure.
  awk '/^:IRONET_V2_NAT_/ || /-j IRONET_V2_NAT_/ || \
    /^-A IRONET_V2_NAT_/' "$input" \
    | sed -E 's/(IRONET_V2_NAT_(IN|OUT))_[AB]/\1_GEN/g' >"$output"
}

if [[ $RELOAD_MATRIX == 1 ]]; then
  capture_nat_rules before-reload
  if [[ $SUBNET_NAT == 1 ]]; then
    assert_nat_generation before-reload present
  else
    assert_nat_generation before-reload absent
  fi

  run_product "$NSB" "$B_CONFIG" "$B_STATE" "$B_SOCKET" reload \
    >"$OUT/b-reload.txt"
  run_product "$NSA" "$A_CONFIG" "$A_STATE" "$A_SOCKET" reload \
    >"$OUT/a-reload.txt"
  for destination in "$LAN_HOST_V4" "$LAN_HOST_V6"; do
    for _ in $(seq 1 100); do
      sudo ip -n "$NSA" route get "$destination" 2>/dev/null \
        | grep -q 'dev ironet0' && break
      sleep 0.1
    done
    sudo ip -n "$NSA" route get "$destination" | grep -q 'dev ironet0'
  done
  run_limited "$NSA" ping -q -c 3 -W 2 "$LAN_HOST_V4" \
    >"$OUT/subnet-v4-after-reload-ping.txt"
  run_limited "$NSA" ping -6 -q -c 3 -W 2 "$LAN_HOST_V6" \
    >"$OUT/subnet-v6-after-reload-ping.txt"

  capture_nat_rules after-reload
  if [[ $SUBNET_NAT == 1 ]]; then
    assert_nat_generation after-reload present
  else
    assert_nat_generation after-reload absent
  fi
  for family in iptables ip6tables; do
    for table in mangle nat; do
      normalize_nat_rules "$OUT/${family}-${table}-before-reload.rules" \
        "$OUT/${family}-${table}-before-reload.normalized"
      normalize_nat_rules "$OUT/${family}-${table}-after-reload.rules" \
        "$OUT/${family}-${table}-after-reload.normalized"
      diff -u "$OUT/${family}-${table}-before-reload.normalized" \
        "$OUT/${family}-${table}-after-reload.normalized" \
        >"$OUT/${family}-${table}-reload.diff"
    done
  done
  printf 'reload=true\nsubnet_nat=%s\nrules_stable=true\nipv4_ping=true\nipv6_ping=true\n' \
    "$SUBNET_NAT" >"$OUT/reload-verification.txt"
fi

if [[ $DISABLE_TUN_OFFLOAD == 1 ]]; then
  # Exercise the ordinary near-MTU/two-Cell path separately from the default
  # end-to-end GSO profile. This is a benchmark switch, never a product knob.
  sudo ip netns exec "$NSA" "$ETHTOOL" -K ironet0 tso off gso off gro off
  sudo ip netns exec "$NSB" "$ETHTOOL" -K ironet0 tso off gso off gro off
fi

run_iperf "$NSB" -s -1 --json >"$OUT/underlay-server.json" &
UNDERLAY_SERVER=$!
sleep 0.2
run_iperf "$NSA" -6 -c "$UNDERLAY_B" -t 5 -P "$PARALLEL" --json \
  >"$OUT/underlay.json"
wait "$UNDERLAY_SERVER"

run_iperf "$NSB" -s -1 --json >"$OUT/overlay-server.json" &
OVERLAY_SERVER=$!
sleep 0.2
run_iperf "$NSA" -4 -c "$B_OVERLAY" -t "$DURATION" -P "$PARALLEL" --json \
  >"$OUT/overlay.json"
wait "$OVERLAY_SERVER"

run_iperf "$NSA" -s -1 --json >"$OUT/overlay-reverse-server.json" &
OVERLAY_REVERSE_SERVER=$!
sleep 0.2
run_iperf "$NSB" -4 -c "$A_OVERLAY" -t "$DURATION" -P "$PARALLEL" --json \
  >"$OUT/overlay-reverse.json"
wait "$OVERLAY_REVERSE_SERVER"

run_iperf "$NSC" -s -1 --json >"$OUT/subnet-forward-server.json" &
SUBNET_FORWARD_SERVER=$!
sleep 0.2
run_iperf "$NSA" -4 -c "$LAN_HOST_V4" -t "$DURATION" -P "$PARALLEL" --json \
  >"$OUT/subnet-forward.json"
wait "$SUBNET_FORWARD_SERVER"

if [[ $SUBNET_NAT == 0 ]]; then
  run_iperf "$NSA" -s -1 --json >"$OUT/subnet-reverse-server.json" &
  SUBNET_REVERSE_SERVER=$!
  sleep 0.2
  run_iperf "$NSC" -4 -c "$A_OVERLAY" -t "$DURATION" -P "$PARALLEL" --json \
    >"$OUT/subnet-reverse.json"
  wait "$SUBNET_REVERSE_SERVER"
fi

run_iperf "$NSB" -s -1 --json >"$OUT/overlay-v6-server.json" &
OVERLAY_V6_SERVER=$!
sleep 0.2
run_iperf "$NSA" -6 -c "$B_OVERLAY_V6" -t "$DURATION" -P "$PARALLEL" --json \
  >"$OUT/overlay-v6.json"
wait "$OVERLAY_V6_SERVER"

run_iperf "$NSA" -s -1 --json >"$OUT/overlay-v6-reverse-server.json" &
OVERLAY_V6_REVERSE_SERVER=$!
sleep 0.2
run_iperf "$NSB" -6 -c "$A_OVERLAY_V6" -t "$DURATION" -P "$PARALLEL" --json \
  >"$OUT/overlay-v6-reverse.json"
wait "$OVERLAY_V6_REVERSE_SERVER"

run_iperf "$NSC" -s -1 --json >"$OUT/subnet-v6-forward-server.json" &
SUBNET_V6_FORWARD_SERVER=$!
sleep 0.2
run_iperf "$NSA" -6 -c "$LAN_HOST_V6" -t "$DURATION" -P "$PARALLEL" --json \
  >"$OUT/subnet-v6-forward.json"
wait "$SUBNET_V6_FORWARD_SERVER"

if [[ $SUBNET_NAT == 0 ]]; then
  run_iperf "$NSA" -s -1 --json >"$OUT/subnet-v6-reverse-server.json" &
  SUBNET_V6_REVERSE_SERVER=$!
  sleep 0.2
  run_iperf "$NSC" -6 -c "$A_OVERLAY_V6" -t "$DURATION" -P "$PARALLEL" --json \
    >"$OUT/subnet-v6-reverse.json"
  wait "$SUBNET_V6_REVERSE_SERVER"
else
  # Dump the whole NAT table: the daemon swaps between generation-owned A/B
  # chains during reload, so a fixed chain name is intentionally not stable.
  sudo ip netns exec "$NSB" iptables -t nat -L -nvx \
    >"$OUT/iptables-nat.txt"
  sudo ip netns exec "$NSB" ip6tables -t nat -L -nvx \
    >"$OUT/ip6tables-nat.txt"
  awk '$3 == "MASQUERADE" && $1 + 0 > 0 { found = 1 } END { exit !found }' \
    "$OUT/iptables-nat.txt"
  awk '$3 == "MASQUERADE" && $1 + 0 > 0 { found = 1 } END { exit !found }' \
    "$OUT/ip6tables-nat.txt"
fi
wait_for_class_queues_to_drain

stop_profiled_pair
A_PID=
B_PID=
A_LAUNCH=
B_LAUNCH=
sudo chown -R "$(id -u):$(id -g)" "$OUT"

for side in a b; do
  run_limited_host "$PERF" report --stdio -i "$OUT/$side.perf.data" \
    >"$OUT/$side.report.txt"
  run_limited_host "$PERF" script -i "$OUT/$side.perf.data" \
    >"$OUT/$side.perf.script"
  run_limited_host "$STACKCOLLAPSE" "$OUT/$side.perf.script" >"$OUT/$side.folded"
  # Record sample CPUs so hybrid PMUs can be split without discarding leaf
  # symbols or call stacks. The primary flamegraph prefers P-core samples.
  if "$PERF" evlist -i "$OUT/$side.perf.data" | grep -q '^cpu_core/cycles' \
      && [[ -r $CPU_CORE_CPUS_FILE && -r $CPU_ATOM_CPUS_FILE ]]; then
    CORE_CPUS=$(<"$CPU_CORE_CPUS_FILE")
    ATOM_CPUS=$(<"$CPU_ATOM_CPUS_FILE")
    run_limited_host "$PERF" script -C "$CORE_CPUS" \
      -i "$OUT/$side.perf.data" >"$OUT/$side.core.perf.script"
    run_limited_host "$STACKCOLLAPSE" "$OUT/$side.core.perf.script" \
      >"$OUT/$side.core.folded"
    run_limited_host "$PERF" script -C "$ATOM_CPUS" \
      -i "$OUT/$side.perf.data" >"$OUT/$side.atom.perf.script"
    run_limited_host "$STACKCOLLAPSE" "$OUT/$side.atom.perf.script" \
      >"$OUT/$side.atom.folded"
    if [[ -s $OUT/$side.core.folded ]]; then
      cp "$OUT/$side.core.folded" "$OUT/$side.folded"
    elif [[ -s $OUT/$side.atom.folded ]]; then
      cp "$OUT/$side.atom.folded" "$OUT/$side.folded"
    fi
  fi
  run_limited_host "$FLAMEGRAPH" --title "Ironet V2 $side" "$OUT/$side.folded" \
    >"$OUT/$side.svg"
done

python3 - "$OUT" "$PERF_FREQUENCY" \
  "$A_TO_B_DELAY_MS" "$A_TO_B_LOSS_PERCENT" \
  "$B_TO_A_DELAY_MS" "$B_TO_A_LOSS_PERCENT" "$SUBNET_NAT" "$CALL_GRAPH" \
  "$BINARY_SHA256" "$RELOAD_MATRIX" <<'PY'
import json, pathlib, re, sys
out = pathlib.Path(sys.argv[1])
sampling_frequency_hz = int(sys.argv[2])
def rate(name):
    data = json.loads((out / name).read_text())
    return data["end"]["sum_received"]["bits_per_second"]
def optional_rate(name):
    return rate(name) if (out / name).exists() else None
def ratio(numerator, denominator):
    return numerator / denominator if numerator is not None and denominator else None
def lost_samples(side):
    report = (out / f"{side}.report.txt").read_text(errors="replace")
    values = [int(value) for value in re.findall(r"Total Lost Samples:\s*(\d+)", report)]
    return sum(values)
def final_class_queues(side):
    data = json.loads((out / f"{side}-final-status.json").read_text())
    peers = data.get("peers", [])
    train = sum(int((peer.get("traffic") or {}).get("packet_train_queue_bytes", 0)) for peer in peers)
    latency = sum(int((peer.get("traffic") or {}).get("latency_queue_bytes", 0)) for peer in peers)
    return {
        "peers": len(peers),
        "packet_train_queue_bytes": train,
        "latency_queue_bytes": latency,
        "drained": train == 0 and latency == 0,
    }
underlay = rate("underlay.json")
overlay = rate("overlay.json")
overlay_reverse = rate("overlay-reverse.json")
subnet_forward = rate("subnet-forward.json")
subnet_reverse = optional_rate("subnet-reverse.json")
overlay_v6 = rate("overlay-v6.json")
overlay_v6_reverse = rate("overlay-v6-reverse.json")
subnet_v6_forward = rate("subnet-v6-forward.json")
subnet_v6_reverse = optional_rate("subnet-v6-reverse.json")
summary = {
    "subnet_nat": bool(int(sys.argv[7])),
    "sampling_frequency_hz": sampling_frequency_hz,
    "call_graph": sys.argv[8],
    "binary_sha256": sys.argv[9],
    "reload_matrix": bool(int(sys.argv[10])),
    "underlay_received_bits_per_second": underlay,
    "overlay_received_bits_per_second": overlay,
    "overlay_to_underlay_ratio": overlay / underlay if underlay else 0,
    "overlay_reverse_received_bits_per_second": overlay_reverse,
    "subnet_forward_received_bits_per_second": subnet_forward,
    "subnet_forward_to_overlay_ratio": subnet_forward / overlay if overlay else 0,
    "subnet_reverse_received_bits_per_second": subnet_reverse,
    "subnet_reverse_to_overlay_reverse_ratio": ratio(subnet_reverse, overlay_reverse),
    "overlay_v6_received_bits_per_second": overlay_v6,
    "overlay_v6_reverse_received_bits_per_second": overlay_v6_reverse,
    "subnet_v6_forward_received_bits_per_second": subnet_v6_forward,
    "subnet_v6_forward_to_overlay_v6_ratio": (
        subnet_v6_forward / overlay_v6 if overlay_v6 else 0
    ),
    "subnet_v6_reverse_received_bits_per_second": subnet_v6_reverse,
    "subnet_v6_reverse_to_overlay_v6_reverse_ratio": ratio(
        subnet_v6_reverse, overlay_v6_reverse
    ),
    "a_perf_lost_samples": lost_samples("a"),
    "b_perf_lost_samples": lost_samples("b"),
    "final_class_queues": {
        side: final_class_queues(side) for side in ("a", "b")
    },
    "netem": {
        "a_to_b_delay_ms": float(sys.argv[3]),
        "a_to_b_loss_percent": float(sys.argv[4]),
        "b_to_a_delay_ms": float(sys.argv[5]),
        "b_to_a_loss_percent": float(sys.argv[6]),
    },
}
(out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
print(json.dumps(summary, indent=2))
PY

cleanup
verify_management_plane
trap - EXIT INT TERM HUP
echo "$OUT"

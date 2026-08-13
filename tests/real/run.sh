#!/usr/bin/env bash
set -euo pipefail

NAT_HOST=${NAT_HOST:-nat-sjw0}
SYMMETRIC_HOST=${SYMMETRIC_HOST:-txy-claw}
STATE_DIR=${STATE_DIR:-/var/lib/ironet-trial}
NAT_V4=${NAT_V4:-10.250.12.2}
SYMMETRIC_V4=${SYMMETRIC_V4:-10.250.12.1}
NAT_V6=${NAT_V6:-fd73:9db8:4212::2}
SYMMETRIC_V6=${SYMMETRIC_V6:-fd73:9db8:4212::1}
IPERF_PORT=${IPERF_PORT:-55201}
IPERF_SECONDS=${IPERF_SECONDS:-10}
RUN_IPERF=${RUN_IPERF:-1}
MIN_IPERF_MBPS=${MIN_IPERF_MBPS:-10}
MAX_LOADED_PING_MS=${MAX_LOADED_PING_MS:-200}

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
RESULT_DIR="$ROOT/target/real-tests/$STAMP"
mkdir -p "$RESULT_DIR"

remote() {
  local host=$1
  shift
  ssh -o BatchMode=yes "$host" "$@"
}

health() {
  local host=$1 expected_peer=$2
  remote "$host" "
    set -eu
    test \"\$(systemctl is-active ironet-trial.service)\" = active
    '$STATE_DIR/bin/ironet' health --config '$STATE_DIR/config.toml'
    grep -q 'forbidden_underlay_prefixes = \\[\"200::/7\"\\]' '$STATE_DIR/config.toml'
    python3 - '$STATE_DIR/status.json' '$expected_peer' <<'PY'
import json, sys
status = json.load(open(sys.argv[1]))
assert status['ready'] is True
assert status['peers'][0]['name'] == sys.argv[2]
assert status['peers'][0]['connected'] is True
assert status['peers'][0]['frame_drops'] == 0
assert status['peers'][0]['tun_mtu'] == 1280
assert status['peers'][0]['selected_path_transport'] in ('direct', 'relay')
assert status['peers'][0]['selected_path_remote']
assert status['peers'][0]['open_paths'] >= 1
print(status['endpoint_id'], status['peers'][0]['effective_frame_size'], status['peers'][0]['path_mtu'], status['peers'][0]['tun_mtu'])
PY
  "
}

echo "checking $NAT_HOST <-> $SYMMETRIC_HOST"
health "$NAT_HOST" "$SYMMETRIC_HOST"
health "$SYMMETRIC_HOST" "$NAT_HOST"

NAT_SHA=$(remote "$NAT_HOST" "sha256sum '$STATE_DIR/bin/ironet'" | awk '{print $1}')
SYMMETRIC_SHA=$(remote "$SYMMETRIC_HOST" "sha256sum '$STATE_DIR/bin/ironet'" | awk '{print $1}')
test "$NAT_SHA" = "$SYMMETRIC_SHA"
echo "binary sha256: $NAT_SHA"

remote "$SYMMETRIC_HOST" "grep -q '111.62.241.102:10119' '$STATE_DIR/config.toml'"
remote "$SYMMETRIC_HOST" "ip route get 111.62.241.102 | grep -q 'dev eth0'"

remote "$NAT_HOST" "ping -n -q -c 20 -i 0.1 '$SYMMETRIC_V4'"
remote "$SYMMETRIC_HOST" "ping -n -q -c 20 -i 0.1 '$NAT_V4'"
remote "$NAT_HOST" "ping -n -q -c 20 -i 0.1 -M do -s 1200 '$SYMMETRIC_V4'"
remote "$SYMMETRIC_HOST" "ping -n -6 -q -c 20 -i 0.1 -s 1200 '$NAT_V6'"

remote "$NAT_HOST" "'$STATE_DIR/bin/ironet' trace --config '$STATE_DIR/config.toml' '$SYMMETRIC_V4'" \
  | tee "$RESULT_DIR/trace-nat-to-symmetric.txt"
remote "$SYMMETRIC_HOST" "'$STATE_DIR/bin/ironet' trace --config '$STATE_DIR/config.toml' '$NAT_V6'" \
  | tee "$RESULT_DIR/trace-symmetric-to-nat.txt"

if [[ $RUN_IPERF == 1 ]]; then
  remote "$NAT_HOST" "nohup iperf3 -s -1 -B '$NAT_V4' -p '$IPERF_PORT' >'/tmp/ironet-iperf-$IPERF_PORT.log' 2>&1 </dev/null &"
  sleep 1
  remote "$SYMMETRIC_HOST" "ping -n -q -i 0.1 -c '$((IPERF_SECONDS * 10))' '$NAT_V4'" \
    > "$RESULT_DIR/ping-under-load-symmetric-to-nat.txt" &
  PING_PID=$!
  remote "$SYMMETRIC_HOST" "iperf3 -c '$NAT_V4' -B '$SYMMETRIC_V4' -p '$IPERF_PORT' -P 4 -t '$IPERF_SECONDS' -J" \
    > "$RESULT_DIR/tcp-symmetric-to-nat.json"
  wait "$PING_PID"

  remote "$SYMMETRIC_HOST" "nohup iperf3 -s -1 -B '$SYMMETRIC_V4' -p '$IPERF_PORT' >'/tmp/ironet-iperf-$IPERF_PORT.log' 2>&1 </dev/null &"
  sleep 1
  remote "$NAT_HOST" "ping -n -q -i 0.1 -c '$((IPERF_SECONDS * 10))' '$SYMMETRIC_V4'" \
    > "$RESULT_DIR/ping-under-load-nat-to-symmetric.txt" &
  PING_PID=$!
  remote "$NAT_HOST" "iperf3 -c '$SYMMETRIC_V4' -B '$NAT_V4' -p '$IPERF_PORT' -P 4 -t '$IPERF_SECONDS' -J" \
    > "$RESULT_DIR/tcp-nat-to-symmetric.json"
  wait "$PING_PID"

  python3 - "$RESULT_DIR" "$MIN_IPERF_MBPS" "$MAX_LOADED_PING_MS" <<'PY'
import json, pathlib, re, sys
minimum_mbps = float(sys.argv[2])
maximum_ping_ms = float(sys.argv[3])
for path in sorted(pathlib.Path(sys.argv[1]).glob('tcp-*.json')):
    result = json.load(open(path))
    sent = result['end']['sum_sent']
    received = result['end']['sum_received']
    received_mbps = received['bits_per_second'] / 1e6
    print(
        path.name,
        f"sent={sent['bits_per_second'] / 1e6:.2f} Mbit/s",
        f"received={received_mbps:.2f} Mbit/s",
        f"retransmits={sent.get('retransmits', 0)}",
    )
    assert received_mbps >= minimum_mbps, (path, received_mbps, minimum_mbps)
for path in sorted(pathlib.Path(sys.argv[1]).glob('ping-under-load-*.txt')):
    summary = path.read_text().strip().splitlines()[-1]
    print(path.name, summary)
    match = re.search(r'= [^/]+/([^/]+)/', summary)
    assert match, (path, summary)
    assert float(match.group(1)) <= maximum_ping_ms, (path, match.group(1), maximum_ping_ms)
PY
fi

echo "real NAT test passed; results: $RESULT_DIR"

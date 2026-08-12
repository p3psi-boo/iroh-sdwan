#!/usr/bin/env bash
set -euo pipefail
source /tests/netns/common.sh

PID_A=
PID_B=
PID_DERP=
PID_DERP_2=
cleanup() {
  local status=$?
  stop_process "$PID_A"
  stop_process "$PID_B"
  stop_process "$PID_DERP"
  stop_process "$PID_DERP_2"
  delete_namespaces derp-a derp-server derp-server-2 derp-b
  rm -rf /etc/netns/derp-a /etc/netns/derp-b
  exit "$status"
}
trap cleanup EXIT

extract_value() {
  local name=$1
  local output=$2
  sed -n "s/^${name} = //p" <<<"$output"
}

route_epoch() {
  jq -r --arg destination "${IDS[node-b]}" \
    '[.capacities[] | select(.destination == $destination) | .path_epoch] | max // 0' \
    /state/node-a/status.json
}

route_epoch_exceeds() {
  local previous=$1
  test "$(route_epoch)" -gt "$previous"
}

probe_attempts_exceed() {
  local previous=$1
  test "$(jq -r '.capacity_probe_attempts' /state/node-a/status.json)" -gt "$previous"
}

write_config() {
  local node=$1
  local address_v4=$2
  local address_v6=$3
  local peer_name=$4
  local peer_id=$5
  local peer_derp_key=$6
  local peer_v4=$7
  local peer_v6=$8
  local direct=$9
  cat >"/state/$node/config.toml" <<EOF
network_id = "netns-derp-two-node"
identity_file = "/state/$node/identity.key"
discovery_enabled = false
tun_mtu = 1280
max_frame_size = 1400
node_interface = "isw0"
node_addresses = ["$address_v4/32", "$address_v6/128"]
advertised_prefixes = []

[node_info]
name = "$node"
description = "DERP network-namespace fixture"

[node_info.metadata]
topology = "two-isolated-netns"

[relay]
mode = "derp"
servers = ["http://derp", "http://derp2"]

[routing]
isolate_overlay = true
transit_enabled = false
rule_priority = 10000
table = 100
allow_default_routes = false

[mesh]
enabled = false
max_peers = 12

[packet_policy]
enforce_overlay_prefixes = true

[fec]
enabled = true
data_shards = 4
recovery_shards = 2
block_timeout_millis = 20
decoder_ttl_millis = 2000

[observability]
status_file = "/state/$node/status.json"
metrics_file = "/state/$node/metrics.prom"
report_interval_secs = 1

[[peers]]
name = "$peer_name"
endpoint_id = "$peer_id"
derp_public_key = "$peer_derp_key"
direct_addresses = ["$direct"]
allowed_source_prefixes = ["$peer_v4/32", "$peer_v6/128"]

[[route_origins]]
endpoint_id = "$peer_id"
prefixes = ["$peer_v4/32", "$peer_v6/128"]
EOF
}

echo "==> creating A -> DERP <- B and a blocked direct link"
for namespace in derp-a derp-server derp-server-2 derp-b; do create_namespace "$namespace"; done
create_veth derp-a ad-a 172.31.10.2/24 derp-server ad-d 172.31.10.10/24
create_veth derp-b bd-b 172.31.20.2/24 derp-server bd-d 172.31.20.10/24
create_veth derp-a ab-a 172.31.30.2/24 derp-b ab-b 172.31.30.3/24
create_veth derp-a ad2-a 172.31.11.2/24 derp-server-2 ad2-d 172.31.11.10/24
create_veth derp-b bd2-b 172.31.21.2/24 derp-server-2 bd2-d 172.31.21.10/24
ip -n derp-a route add blackhole 172.31.30.3/32
ip -n derp-b route add blackhole 172.31.30.2/32
mkdir -p /etc/netns/derp-a /etc/netns/derp-b
printf '127.0.0.1 localhost\n172.31.10.10 derp\n172.31.11.10 derp2\n' >/etc/netns/derp-a/hosts
printf '127.0.0.1 localhost\n172.31.20.10 derp\n172.31.21.10 derp2\n' >/etc/netns/derp-b/hosts
for interface in ad2-d bd2-d; do
  ip netns exec derp-server-2 tc qdisc replace dev "$interface" root netem delay 40ms 2ms
done

ip netns exec derp-server derper -a :80 -http-port -1 -stun=false \
  >/state/derper.log 2>&1 &
PID_DERP=$!
ip netns exec derp-server-2 derper -a :80 -http-port -1 -stun=false \
  >/state/derper-2.log 2>&1 &
PID_DERP_2=$!
sleep 1
kill -0 "$PID_DERP"
kill -0 "$PID_DERP_2"

echo "==> creating node and DERP identities"
declare -A IDS DERP_KEYS
for node in node-a node-b; do
  output=$(iroh-sdwan init \
    --config "/state/$node/config.toml" \
    --state-dir "/state/$node" \
    --network-id netns-derp-two-node \
    --derp-server http://derp \
    --derp-server http://derp2)
  IDS[$node]=$(extract_value endpoint_id "$output")
  DERP_KEYS[$node]=$(extract_value derp_public_key "$output")
  test -n "${IDS[$node]}" && test -n "${DERP_KEYS[$node]}"
done
write_config node-a 10.211.0.1 fd73:9db8:4211::1 \
  node-b "${IDS[node-b]}" "${DERP_KEYS[node-b]}" \
  10.211.0.2 fd73:9db8:4211::2 172.31.30.3:4000
write_config node-b 10.211.0.2 fd73:9db8:4211::2 \
  node-a "${IDS[node-a]}" "${DERP_KEYS[node-a]}" \
  10.211.0.1 fd73:9db8:4211::1 172.31.30.2:4000
seal_node node-a
seal_node node-b
start_daemon derp-a node-a PID_A
start_daemon derp-b node-b PID_B

echo "==> verifying isolated DERP path"
wait_until "node-a DERP path" sh -c \
  'grep -q '\''"ready": true'\'' /state/node-a/status.json && grep -q '\''"selected_path_transport": "derp"'\'' /state/node-a/status.json'
wait_until "node-b DERP path" sh -c \
  'grep -q '\''"ready": true'\'' /state/node-b/status.json && grep -q '\''"selected_path_transport": "derp"'\'' /state/node-b/status.json'
wait_until "node-a DERP path metrics" grep -Eq \
  'iroh_sdwan_peer_selected_path_info\{.*transport="derp".*remote=".*server=derp.*"\} 1$' \
  /state/node-a/metrics.prom
for node in node-a node-b; do
  wait_until "$node bidirectional DERP congestion window" sh -c \
    'awk '\''$1 ~ /iroh_sdwan_peer_path_cwnd_bytes/ && $NF >= 8192 { ready=1 } END { exit !ready }'\'' "$1"' \
    sh "/state/$node/metrics.prom"
done
if ip netns exec derp-a ping -c 1 -W 1 172.31.20.2 >/dev/null 2>&1; then
  echo "A unexpectedly reached B DERP-side underlay" >&2
  exit 1
fi
ctl derp-a node-a ping --count 2 --timeout-ms 5000 10.211.0.2 | grep -q '2 transmitted, 2 received'
ctl derp-a node-a ping --count 2 --timeout-ms 5000 fd73:9db8:4211::2 | grep -q '2 transmitted, 2 received'
ip netns exec derp-a ping -c 4 -W 3 -I 10.211.0.1 10.211.0.2
ip netns exec derp-b ping -c 4 -W 3 -I 10.211.0.2 10.211.0.1
ip netns exec derp-a ping -6 -c 4 -W 3 -I fd73:9db8:4211::1 fd73:9db8:4211::2
ip netns exec derp-a ping -c 2 -W 3 -M do -s 1200 -I 10.211.0.1 10.211.0.2
ip netns exec derp-a ping -q -c 128 -i 0.005 -W 3 -I 10.211.0.1 10.211.0.2
grep -Eq 'iroh_sdwan_peer_fec_tx_recovery_shards_total\{.*\} 0$' /state/node-a/metrics.prom
trace=$(ctl derp-a node-a trace --timeout-ms 5000 10.211.0.2)
grep -q 'node-b (10.211.0.2)' <<<"$trace"
if ctl derp-a node-a doctor --config /state/node-a/config.toml \
  >/state/doctor-blocked.log 2>&1; then
  echo "doctor unexpectedly accepted a black-holed direct candidate" >&2
  exit 1
fi
grep -q 'no underlay route to peer node-b' /state/doctor-blocked.log
initial_epoch=$(route_epoch)
initial_probe_attempts=$(jq -r '.capacity_probe_attempts' /state/node-a/status.json)
test "$initial_epoch" -gt 0

echo "==> failing over between independent DERP regions"
wait_until "primary DERP region selection" grep -q 'server=derp"' /state/node-a/status.json
stop_process "$PID_DERP"
PID_DERP=
wait_until "secondary DERP region" grep -q 'server=derp2' /state/node-a/status.json
wait_until "new capacity path epoch after DERP region switch" route_epoch_exceeds "$initial_epoch"
wait_until "new probe after DERP region switch" probe_attempts_exceed "$initial_probe_attempts"
secondary_epoch=$(route_epoch)
ctl derp-a node-a ping --count 3 --timeout-ms 5000 10.211.0.2 \
  | grep -q '3 transmitted, 3 received'
ip netns exec derp-server derper -a :80 -http-port -1 -stun=false \
  >/state/derper-restarted.log 2>&1 &
PID_DERP=$!

echo "==> enabling direct path, then continuously falling back to DERP"
ip -n derp-a route del blackhole 172.31.30.3/32
ip -n derp-b route del blackhole 172.31.30.2/32
wait_until "direct path" grep -q '"selected_path_transport": "direct"' /state/node-a/status.json
wait_until "new capacity path epoch on direct recovery" route_epoch_exceeds "$secondary_epoch"
direct_epoch=$(route_epoch)
ctl derp-a node-a doctor --config /state/node-a/config.toml
ctl derp-b node-b doctor --config /state/node-b/config.toml

stop_file=/state/stop-derp-switch
switch_log=/state/derp-switch.jsonl
rm -f "$stop_file" "$switch_log"
(
  while [[ ! -e $stop_file ]]; do
    if ! ctl derp-a node-a ping --count 1 --timeout-ms 5000 --output jsonl 10.211.0.2; then
      echo '{"switch_ping_failed":true}'
    fi
    sleep 0.1
  done
) >"$switch_log" &
switch_pid=$!
sleep 1
ip -n derp-a route add blackhole 172.31.30.3/32
ip -n derp-b route add blackhole 172.31.30.2/32
wait_until "DERP fallback" grep -q '"selected_path_transport": "derp"' /state/node-a/status.json
wait_until "new capacity path epoch on DERP fallback" route_epoch_exceeds "$direct_epoch"
sleep 1
touch "$stop_file"
wait "$switch_pid"
switch_failures=$(grep -c switch_ping_failed "$switch_log" || true)
test "$switch_failures" -le 6
test "$(grep -c '"received":1' "$switch_log")" -ge 4
ctl derp-a node-a ping --count 2 --timeout-ms 5000 10.211.0.2 \
  | grep -q '2 transmitted, 2 received'

echo "==> losing every DERP region and recovering without daemon restart"
stop_process "$PID_DERP"
PID_DERP=
stop_process "$PID_DERP_2"
PID_DERP_2=
if ctl derp-a node-a ping --count 2 --timeout-ms 500 10.211.0.2 >/dev/null 2>&1; then
  echo "overlay unexpectedly survived loss of all direct and DERP paths" >&2
  exit 1
fi
ip netns exec derp-server-2 derper -a :80 -http-port -1 -stun=false \
  >/state/derper-2-restarted.log 2>&1 &
PID_DERP_2=$!
wait_until "DERP reconnect after total relay outage" ctl derp-a node-a ping --count 1 --timeout-ms 5000 10.211.0.2

if grep -Eq 'frame .* exceeds maximum size|DERP reader task stopped unexpectedly' \
  /state/node-a/daemon.log /state/node-b/daemon.log; then
  cat /state/node-a/daemon.log /state/node-b/daemon.log >&2
  exit 1
fi

echo "DERP network-namespace integration test passed"

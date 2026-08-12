#!/usr/bin/env bash
set -euo pipefail
source /tests/netns/common.sh

WAIT_ATTEMPTS=120
PID_A=
PID_P=
PID_C=
PID_X=
cleanup() {
  local status=$?
  stop_process "$PID_A"
  stop_process "$PID_P"
  stop_process "$PID_C"
  stop_process "$PID_X"
  delete_namespaces mesh-a mesh-public mesh-c mesh-x
  exit "$status"
}
trap cleanup EXIT

write_config() {
  local node=$1
  local address=$2
  local transit=$3
  local max_peers=$4
  local peer=${5:-}
  cat >"/state/$node/config.toml" <<EOF
network_id = "netns-bounded-mesh"
identity_file = "/state/$node/identity.key"
bind_addresses = ["0.0.0.0:4000"]
discovery_enabled = true
tun_mtu = 65535
max_frame_size = 1400
node_interface = "isw0"
node_addresses = ["$address/32"]
advertised_prefixes = []

[node_info]
name = "$node"

[node_info.metadata]
site = "netns-mesh"

[routing]
isolate_overlay = true
transit_enabled = $transit
rule_priority = 10000
table = 100
allow_default_routes = false

[mesh]
enabled = true
max_peers = $max_peers

[packet_policy]
enforce_overlay_prefixes = true

[observability]
status_file = "/state/$node/status.json"
metrics_file = "/state/$node/metrics.prom"
report_interval_secs = 1

$peer
EOF
}

echo "==> creating A -> Public <- C plus a blocked direct A-C link"
for namespace in mesh-a mesh-public mesh-c mesh-x; do create_namespace "$namespace"; done
create_veth mesh-a ap-a 172.31.1.2/24 mesh-public ap-p 172.31.1.1/24
create_veth mesh-c cp-c 172.31.2.2/24 mesh-public cp-p 172.31.2.1/24
create_veth mesh-a ac-a 172.31.3.2/24 mesh-c ac-c 172.31.3.3/24
create_veth mesh-x xp-x 172.31.4.2/24 mesh-public xp-p 172.31.4.1/24
ip -n mesh-a route add blackhole 172.31.3.3/32
ip -n mesh-c route add blackhole 172.31.3.2/32
ip netns exec mesh-public sysctl -qw net.ipv4.ip_forward=1
for interface in ap-p cp-p; do
  ip netns exec mesh-public tc qdisc replace dev "$interface" root netem delay 20ms
done

declare -A IDS
IDS[node-a]=$(initialize_identity node-a netns-bounded-mesh)
IDS[public]=$(initialize_identity public netns-bounded-mesh)
IDS[node-c]=$(initialize_identity node-c netns-bounded-mesh)
IDS[node-x]=$(initialize_identity node-x netns-bounded-mesh)
public_peer="[[peers]]
name = \"public\"
endpoint_id = \"${IDS[public]}\"
direct_addresses = [\"172.31.1.1:4000\"]"
write_config node-a 10.210.0.1 false 3 "$public_peer"
write_config public 10.210.0.2 true 8
public_peer="[[peers]]
name = \"public\"
endpoint_id = \"${IDS[public]}\"
direct_addresses = [\"172.31.2.1:4000\"]"
write_config node-c 10.210.0.3 false 3 "$public_peer"
public_peer="[[peers]]
name = \"public\"
endpoint_id = \"${IDS[public]}\"
direct_addresses = [\"172.31.4.1:4000\"]"
write_config node-x 10.210.0.3 false 3 "$public_peer"
for node in node-a public node-c node-x; do seal_node "$node"; done

start_daemon mesh-a node-a PID_A
start_daemon mesh-public public PID_P
start_daemon mesh-c node-c PID_C

echo "==> waiting for signed Presence and Public transit fallback"
wait_until "Public directory" grep -q '"directory_entries": 2' /state/public/status.json
wait_until "A directory" grep -q '"directory_entries": 2' /state/node-a/status.json
wait_until "C directory" grep -q '"directory_entries": 2' /state/node-c/status.json
wait_until "A received Public-observed C rendezvous candidate" jq -e \
  '.mesh.nodes[] | select(.node_info.name == "node-c") | .assisted_addresses | length > 0' \
  /state/node-a/status.json
wait_until "C received Public-observed A rendezvous candidate" jq -e \
  '.mesh.nodes[] | select(.node_info.name == "node-a") | .assisted_addresses | length > 0' \
  /state/node-c/status.json
if ip netns exec mesh-a ping -c 1 -W 1 172.31.3.3 >/dev/null 2>&1; then
  echo "A unexpectedly reached the blocked C direct underlay" >&2
  exit 1
fi
wait_until "A-C fallback ping" ctl mesh-a node-a ping --count 1 --timeout-ms 3000 10.210.0.3
fallback_trace=$(ctl mesh-a node-a trace --timeout-ms 3000 10.210.0.3)
grep -Eq '^[[:space:]]*1[[:space:]]+public ' <<<"$fallback_trace"
grep -Eq '^[[:space:]]*2[[:space:]]+node-c ' <<<"$fallback_trace"

echo "==> continuous ping across transit-to-direct switching"
stop_file=/state/stop-switch-ping
switch_log=/state/switch-ping.jsonl
rm -f "$stop_file" "$switch_log"
(
  while [[ ! -e $stop_file ]]; do
    if ! ctl mesh-a node-a ping --count 1 --timeout-ms 3000 --output jsonl 10.210.0.3; then
      echo '{"switch_ping_failed":true}'
    fi
    sleep 0.1
  done
) >"$switch_log" &
switch_pid=$!
sleep 1
ip -n mesh-a route del blackhole 172.31.3.3/32
ip -n mesh-c route del blackhole 172.31.3.2/32
wait_until "direct A-C adjacency" sh -c \
  'ip netns exec mesh-a iroh-sdwan --socket /state/node-a/control.sock trace --timeout-ms 3000 10.210.0.3 | grep -Eq "^[[:space:]]*1[[:space:]]+node-c "'
sleep 1
touch "$stop_file"
wait "$switch_pid"
if grep -q switch_ping_failed "$switch_log"; then
  cat "$switch_log" >&2
  exit 1
fi
grep -Eq '"avg_ms":([2-9][0-9]|[1-9][0-9][0-9])\.' "$switch_log"
grep -Eq '"avg_ms":[0-9]\.' "$switch_log"
direct_trace=$(ctl mesh-a node-a trace --timeout-ms 3000 10.210.0.3)
grep -Eq '^[[:space:]]*1[[:space:]]+node-c ' <<<"$direct_trace"

echo "==> restarting Public and partitioning/merging the direct mesh"
stop_process "$PID_P"
PID_P=
ctl mesh-a node-a ping --count 3 --timeout-ms 3000 10.210.0.3 \
  | grep -q '3 transmitted, 3 received'
ip -n mesh-a route add blackhole 172.31.3.3/32
ip -n mesh-c route add blackhole 172.31.3.2/32
if ctl mesh-a node-a ping --count 2 --timeout-ms 300 10.210.0.3 >/dev/null 2>&1; then
  echo "partition unexpectedly retained a usable path" >&2
  exit 1
fi
start_daemon mesh-public public PID_P
wait_until "Public recovery after restart" grep -q '"directory_entries": 2' /state/public/status.json
wait_until "transit recovery after partition" ctl mesh-a node-a ping --count 1 --timeout-ms 3000 10.210.0.3
partition_trace=$(ctl mesh-a node-a trace --timeout-ms 3000 10.210.0.3)
grep -Eq '^[[:space:]]*1[[:space:]]+public ' <<<"$partition_trace"
ip -n mesh-a route del blackhole 172.31.3.3/32
ip -n mesh-c route del blackhole 172.31.3.2/32
wait_until "direct path after merge" sh -c \
  'ip netns exec mesh-a iroh-sdwan --socket /state/node-a/control.sock trace --timeout-ms 3000 10.210.0.3 | grep -Eq "^[[:space:]]*1[[:space:]]+node-c "'

echo "==> bounded resources, peers output, and dynamic-target failure"
ctl mesh-a node-a peers --output jsonl | grep -q '"connected":true'
grep -q '"name": "node-c"' /state/node-a/status.json
test "$(grep -c '"connected":' /state/node-a/status.json)" -le 3
test "$(grep -c '"connected":' /state/node-c/status.json)" -le 3
test "$(grep -c '"connected":' /state/public/status.json)" -le 8
grep -q 'iroh_sdwan_mesh_directory_entries 2' /state/node-a/metrics.prom
grep -q 'iroh_sdwan_mesh_quarantined_entries 0' /state/node-a/metrics.prom

ip netns exec mesh-c tc qdisc replace dev ac-c root netem loss 100%
if unreachable=$(ctl mesh-a node-a ping --count 3 --timeout-ms 250 10.210.0.3 2>&1); then
  echo "dynamic target unexpectedly survived 100% direct loss" >&2
  exit 1
fi
ip netns exec mesh-c tc qdisc del dev ac-c root
grep -q '3 transmitted, 0 received, 100.0% loss' <<<"$unreachable"
wait_until "dynamic target recovery" ctl mesh-a node-a ping --count 1 --timeout-ms 3000 10.210.0.3

echo "==> quarantining conflicting signed prefix owners"
start_daemon mesh-x node-x PID_X
wait_until "conflicting Presence quarantine" sh -c \
  'awk '\''$1 == "iroh_sdwan_mesh_quarantined_entries" && ($NF + 0) >= 2 {ok=1} END {exit !ok}'\'' /state/node-a/metrics.prom'
grep -q '"quarantined": true' /state/node-a/status.json
test "$(grep -c '"connected":' /state/public/status.json)" -le 8

echo "bounded mesh network-namespace integration test passed"

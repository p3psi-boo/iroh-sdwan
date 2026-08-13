#!/usr/bin/env bash
set -euo pipefail
source /tests/netns/common.sh

PID_A=
PID_T=
PID_C=
cleanup() {
  local status=$?
  stop_process "$PID_A"
  stop_process "$PID_T"
  stop_process "$PID_C"
  delete_namespaces v1-a v1-t v1-c
  exit "$status"
}
trap cleanup EXIT

write_config() {
  local node=$1 attachment=$2 address=$3 transit=$4 peers=$5 origins=$6
  cat >"/state/$node/config.toml" <<EOF
network_id = "netns-v1-transit"
identity_file = "/state/$node/identity.key"
bind_addresses = ["0.0.0.0:4000"]
discovery_enabled = false
attachment = "$attachment"
tun_mtu = 65535
max_frame_size = 1200
node_interface = "ironet0"
node_addresses = [$address]

[node_info]
name = "$node"

[routing]
transit_enabled = $transit
table = 100

[mesh]
enabled = false
max_peers = 8

[packet_policy]
enforce_overlay_prefixes = true

[observability]
status_file = "/state/$node/status.json"
metrics_file = "/state/$node/metrics.prom"
report_interval_secs = 1

$peers

$origins
EOF
}

echo "==> creating V1 A -> userspace-only transit -> C topology"
for namespace in v1-a v1-t v1-c; do create_namespace "$namespace"; done
create_veth v1-a at-a 172.40.10.2/24 v1-t at-t 172.40.10.3/24
create_veth v1-t tc-t 172.40.20.2/24 v1-c tc-c 172.40.20.3/24

declare -A IDS
for node in node-a node-transit node-c; do
  IDS[$node]=$(initialize_identity "$node" netns-v1-transit)
done

write_config node-a tun '"10.246.0.1/32", "fd73:9db8:4246::1/128"' false "
[[peers]]
name = \"node-transit\"
endpoint_id = \"${IDS[node-transit]}\"
transit_enabled = true
direct_addresses = [\"172.40.10.3:4000\"]
allowed_source_prefixes = [\"10.246.0.3/32\", \"fd73:9db8:4246::3/128\"]" "
[[route_origins]]
endpoint_id = \"${IDS[node-c]}\"
prefixes = [\"10.246.0.3/32\", \"fd73:9db8:4246::3/128\"]"

write_config node-transit none '' true "
[[peers]]
name = \"node-a\"
endpoint_id = \"${IDS[node-a]}\"
direct_addresses = [\"172.40.10.2:4000\"]
allowed_source_prefixes = [\"10.246.0.1/32\", \"fd73:9db8:4246::1/128\"]

[[peers]]
name = \"node-c\"
endpoint_id = \"${IDS[node-c]}\"
direct_addresses = [\"172.40.20.3:4000\"]
allowed_source_prefixes = [\"10.246.0.3/32\", \"fd73:9db8:4246::3/128\"]" "
[[route_origins]]
endpoint_id = \"${IDS[node-a]}\"
prefixes = [\"10.246.0.1/32\", \"fd73:9db8:4246::1/128\"]

[[route_origins]]
endpoint_id = \"${IDS[node-c]}\"
prefixes = [\"10.246.0.3/32\", \"fd73:9db8:4246::3/128\"]"

write_config node-c tun '"10.246.0.3/32", "fd73:9db8:4246::3/128"' false "
[[peers]]
name = \"node-transit\"
endpoint_id = \"${IDS[node-transit]}\"
transit_enabled = true
direct_addresses = [\"172.40.20.2:4000\"]
allowed_source_prefixes = [\"10.246.0.1/32\", \"fd73:9db8:4246::1/128\"]" "
[[route_origins]]
endpoint_id = \"${IDS[node-a]}\"
prefixes = [\"10.246.0.1/32\", \"fd73:9db8:4246::1/128\"]"

for node in node-a node-transit node-c; do seal_node "$node"; done
start_daemon v1-a node-a PID_A
start_daemon v1-t node-transit PID_T
start_daemon v1-c node-c PID_C

wait_until "V1 userspace transit" ip netns exec v1-a ping -c 1 -W 3 -I 10.246.0.1 10.246.0.3
wait_until "V1 IPv6 userspace transit" ip netns exec v1-a ping -6 -c 1 -W 3 -I fd73:9db8:4246::1 fd73:9db8:4246::3
ip netns exec v1-c ping -c 3 -W 3 -I 10.246.0.3 10.246.0.1
ip netns exec v1-c ping -6 -c 3 -W 3 -I fd73:9db8:4246::3 fd73:9db8:4246::1

echo "==> proving transit node has no TUN or kernel overlay routes"
test "$(ip -n v1-t -o link show | grep -c 'ironet0' || true)" -eq 0
test "$(ip -n v1-t route show table 100 2>/dev/null | wc -l)" -eq 0
grep -q 'userspace-only transit node without a TUN attachment' /state/node-transit/daemon.log
jq -e '.ready and (.routes | length == 0) and all(.peers[]; .interface == "none")' \
  /state/node-transit/status.json >/dev/null

echo "==> proving V1 negotiation and unified wire operation"
for node in node-a node-transit node-c; do
  wait_until "$node V1 status" jq -e \
    '(.peers | length > 0) and all(.peers[]; .connected and .protocol_major == 1 and .protocol_minor == 0 and .negotiated_features >= 3)' \
    "/state/$node/status.json"
  grep -q 'ironet_peer_protocol_info.*major="1"' "/state/$node/metrics.prom"
done
ctl v1-a node-a ping --count 3 --timeout-ms 3000 10.246.0.3 | grep -q '3 transmitted, 3 received'
ctl v1-a node-a ping --count 3 --timeout-ms 3000 fd73:9db8:4246::3 | grep -q '3 transmitted, 3 received'

echo "==> breaking and recovering one side of userspace transit"
ip netns exec v1-t tc qdisc replace dev tc-t root netem loss 100%
if ctl v1-a node-a ping --count 2 --timeout-ms 250 10.246.0.3 >/dev/null 2>&1; then
  echo "broken userspace transit unexpectedly remained reachable" >&2
  exit 1
fi
if ctl v1-a node-a ping --count 2 --timeout-ms 250 fd73:9db8:4246::3 >/dev/null 2>&1; then
  echo "broken IPv6 userspace transit unexpectedly remained reachable" >&2
  exit 1
fi
ip netns exec v1-t tc qdisc del dev tc-t root
wait_until "V1 transit recovery" ctl v1-a node-a ping --count 1 --timeout-ms 3000 10.246.0.3
wait_until "V1 IPv6 transit recovery" ctl v1-a node-a ping --count 1 --timeout-ms 3000 fd73:9db8:4246::3

echo "V1 userspace-only transit network-namespace test passed"

#!/usr/bin/env bash
set -euo pipefail
source /tests/netns/common.sh

WAIT_ATTEMPTS=150
PID_A=
PID_B=
PID_RELAY_1=
PID_RELAY_2=
PID_IPERF=
cleanup() {
  local status=$?
  stop_process "$PID_IPERF"
  stop_process "$PID_A"
  stop_process "$PID_B"
  stop_process "$PID_RELAY_1"
  stop_process "$PID_RELAY_2"
  delete_namespaces relay-a relay-b relay-1 relay-2
  rm -rf /etc/netns/relay-a /etc/netns/relay-b
  exit "$status"
}
trap cleanup EXIT

write_config() {
  local node=$1 address4=$2 address6=$3 peer=$4 peer4=$5 peer6=$6 peer_id=$7
  cat >"/state/$node/config.toml" <<EOF
network_id = "netns-iroh-relay"
identity_file = "/state/$node/identity.key"
bind_addresses = ["0.0.0.0:4000"]
discovery_enabled = false
tun_mtu = 65535
max_frame_size = 1400
node_interface = "isw0"
node_addresses = ["$address4/32", "$address6/128"]
advertised_prefixes = []

[node_info]
name = "$node"
ipv4 = "$address4"
ipv6 = "$address6"

[relay]
mode = "custom"
urls = ["http://relay1:3340", "http://relay2:3340"]

[routing]
isolate_overlay = true
transit_enabled = false
rule_priority = 10000
table = 100
allow_default_routes = false

[mesh]
enabled = false
max_peers = 4

[packet_policy]
enforce_overlay_prefixes = true

[observability]
status_file = "/state/$node/status.json"
metrics_file = "/state/$node/metrics.prom"
report_interval_secs = 1

[[peers]]
name = "$peer"
endpoint_id = "$peer_id"
relay_urls = ["http://relay1:3340", "http://relay2:3340"]
allowed_source_prefixes = ["$peer4/32", "$peer6/128"]

[[route_origins]]
endpoint_id = "$peer_id"
prefixes = ["$peer4/32", "$peer6/128"]
EOF
}

route_epoch() {
  jq -r '[.capacities[].path_epoch] | max // 0' /state/node-a/status.json
}

route_epoch_exceeds() {
  local previous=$1
  test "$(route_epoch)" -gt "$previous"
}

probe_attempts_exceed() {
  local previous=$1
  test "$(jq -r '.capacity_probe_attempts' /state/node-a/status.json)" -gt "$previous"
}

echo "==> creating two isolated clients and two local iroh relay servers"
for namespace in relay-a relay-b relay-1 relay-2; do create_namespace "$namespace"; done
create_veth relay-a ar1-a 172.36.10.2/24 relay-1 ar1-r 172.36.10.10/24
create_veth relay-b br1-b 172.36.20.2/24 relay-1 br1-r 172.36.20.10/24
create_veth relay-a ar2-a 172.36.11.2/24 relay-2 ar2-r 172.36.11.10/24
create_veth relay-b br2-b 172.36.21.2/24 relay-2 br2-r 172.36.21.10/24
mkdir -p /etc/netns/relay-a /etc/netns/relay-b
printf '127.0.0.1 localhost\n172.36.10.10 relay1\n172.36.11.10 relay2\n' >/etc/netns/relay-a/hosts
printf '127.0.0.1 localhost\n172.36.20.10 relay1\n172.36.21.10 relay2\n' >/etc/netns/relay-b/hosts

ip netns exec relay-1 iroh-relay --dev >/state/iroh-relay-1.log 2>&1 &
PID_RELAY_1=$!
ip netns exec relay-2 iroh-relay --dev >/state/iroh-relay-2.log 2>&1 &
PID_RELAY_2=$!
wait_until "first iroh relay" ip netns exec relay-a nc -z -w 2 relay1 3340
wait_until "second iroh relay" ip netns exec relay-a nc -z -w 2 relay2 3340

IDS_A=$(initialize_identity node-a netns-iroh-relay)
IDS_B=$(initialize_identity node-b netns-iroh-relay)
write_config node-a 10.244.0.1 fd73:9db8:4244::1 node-b 10.244.0.2 fd73:9db8:4244::2 "$IDS_B"
write_config node-b 10.244.0.2 fd73:9db8:4244::2 node-a 10.244.0.1 fd73:9db8:4244::1 "$IDS_A"
seal_node node-a
seal_node node-b
start_daemon relay-a node-a PID_A
start_daemon relay-b node-b PID_B

wait_until "node-a iroh relay path" sh -c \
  'grep -q '\''"ready": true'\'' /state/node-a/status.json && grep -q '\''"selected_path_transport": "relay"'\'' /state/node-a/status.json'
wait_until "node-b iroh relay path" grep -q '"selected_path_transport": "relay"' /state/node-b/status.json
if ip netns exec relay-a ping -c 1 -W 1 172.36.20.2 >/dev/null 2>&1; then
  echo "relay clients unexpectedly have direct underlay reachability" >&2
  exit 1
fi
ctl relay-a node-a ping --count 3 --timeout-ms 5000 10.244.0.2 | grep -q '3 transmitted, 3 received'
ctl relay-a node-a ping --count 3 --timeout-ms 5000 fd73:9db8:4244::2 | grep -q '3 transmitted, 3 received'
wait_until "relay route capacity sample" jq -e 'any(.capacities[]; .measured_capacity_bps != null)' /state/node-a/status.json

ip netns exec relay-b iperf3 -s -B 10.244.0.2 -p 5244 >/state/relay-iperf.log 2>&1 &
PID_IPERF=$!
wait_until "relay iperf service" ip netns exec relay-a nc -z -w 2 10.244.0.2 5244
ip netns exec relay-a iperf3 -c 10.244.0.2 -p 5244 -t 5 -J >/state/relay-bulk.json
test "$(jq '.end.sum_received.bytes > 1000000' /state/relay-bulk.json)" = true
wait_until "receiver-confirmed relay sample" jq -e 'any(.capacities[]; .passive_samples > 0)' /state/node-a/status.json

echo "==> failing the selected iroh relay and checking capacity epoch invalidation"
epoch_before=$(route_epoch)
attempts_before=$(jq -r '.capacity_probe_attempts' /state/node-a/status.json)
selected=$(jq -r '.peers[0].selected_path_remote' /state/node-a/status.json)
if [[ $selected == *relay1* ]]; then
  stop_process "$PID_RELAY_1"
  PID_RELAY_1=
else
  stop_process "$PID_RELAY_2"
  PID_RELAY_2=
fi
wait_until "backup iroh relay path" ctl relay-a node-a ping --count 1 --timeout-ms 5000 10.244.0.2
wait_until "relay failover path epoch" route_epoch_exceeds "$epoch_before"
wait_until "relay failover capacity probe" probe_attempts_exceed "$attempts_before"
grep -Eq 'iroh_sdwan_route_path_epoch\{.*\} [1-9][0-9]*$' /state/node-a/metrics.prom

echo "iroh relay network-namespace integration test passed"

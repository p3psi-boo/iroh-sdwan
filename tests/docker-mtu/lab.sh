#!/usr/bin/env bash
set -euo pipefail
source /tests/netns/common.sh

WAIT_ATTEMPTS=120
PID_A=
PID_B=
PID_IPERF=
cleanup() {
  local status=$?
  stop_process "$PID_IPERF"
  stop_process "$PID_A"
  stop_process "$PID_B"
  delete_namespaces mtu-a mtu-b
  exit "$status"
}
trap cleanup EXIT

write_config() {
  local node=$1 overlay4=$2 overlay6=$3 peer=$4 peer4=$5 peer6=$6 peer_id=$7 direct=$8
  cat >"/state/$node/config.toml" <<EOF
network_id = "netns-ipv6-mtu"
identity_file = "/state/$node/identity.key"
bind_addresses = ["[::]:4000"]
discovery_enabled = false
tun_mtu = 65535
max_frame_size = 1400
node_interface = "isw0"
node_addresses = ["$overlay4/32", "$overlay6/128"]
advertised_prefixes = []
[node_info]
name = "$node"
[relay]
mode = "disabled"
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
direct_addresses = ["$direct"]
allowed_source_prefixes = ["$peer4/32", "$peer6/128"]
[[route_origins]]
endpoint_id = "$peer_id"
prefixes = ["$peer4/32", "$peer6/128"]
EOF
}

metric() {
  local node=$1 name=$2
  awk -v metric="iroh_sdwan_peer_${name}" '$1 ~ ("^" metric "\\{") {print $NF; exit}' "/state/$node/metrics.prom"
}

echo "==> creating an IPv6 underlay for PTB and black-hole MTU tests"
create_namespace mtu-a
create_namespace mtu-b
ip link add ma0 type veth peer name mb0
ip link set ma0 netns mtu-a
ip link set mb0 netns mtu-b
ip -n mtu-a -6 address add 2001:db8:34::2/64 dev ma0
ip -n mtu-b -6 address add 2001:db8:34::3/64 dev mb0
ip -n mtu-a link set ma0 up
ip -n mtu-b link set mb0 up
IDS_A=$(initialize_identity node-a netns-ipv6-mtu)
IDS_B=$(initialize_identity node-b netns-ipv6-mtu)
write_config node-a 10.242.0.1 fd73:9db8:4242::1 node-b 10.242.0.2 fd73:9db8:4242::2 "$IDS_B" '[2001:db8:34::3]:4000'
write_config node-b 10.242.0.2 fd73:9db8:4242::2 node-a 10.242.0.1 fd73:9db8:4242::1 "$IDS_A" '[2001:db8:34::2]:4000'
seal_node node-a
seal_node node-b
start_daemon mtu-a node-a PID_A
start_daemon mtu-b node-b PID_B
wait_until "IPv6-underlay overlay" ctl mtu-a node-a ping --count 1 --timeout-ms 3000 fd73:9db8:4242::2

ip netns exec mtu-b iperf3 -s -B 10.242.0.2 -p 5242 >/state/mtu-iperf-server.log 2>&1 &
PID_IPERF=$!
wait_until "MTU iperf service" ip netns exec mtu-a nc -z -w 2 10.242.0.2 5242

echo "==> changing PMTU during an established bulk flow"
ip netns exec mtu-a iperf3 -c 10.242.0.2 -p 5242 -t 8 -J >/state/mtu-midflow.json &
flow_pid=$!
sleep 2
ip -n mtu-a link set ma0 mtu 1280
ip -n mtu-b link set mb0 mtu 1280
wait "$flow_pid"
test "$(jq '.end.sum_received.bytes > 1000000' /state/mtu-midflow.json)" = true
wait_until "ICMPv6 PTB frame adaptation" sh -c \
  'awk '\''$1 ~ /iroh_sdwan_peer_effective_frame_size_bytes/ && $NF <= 1200 {ok=1} END {exit !ok}'\'' /state/node-a/metrics.prom'
wait_until "post-PTB bulk queue drain" ip netns exec mtu-a \
  ping -6 -c 1 -W 3 -s 4096 -I fd73:9db8:4242::1 fd73:9db8:4242::2
ip netns exec mtu-a ping -6 -c 3 -W 3 -s 4096 -I fd73:9db8:4242::1 fd73:9db8:4242::2

echo "==> applying an asymmetric silent UDP MTU black hole"
stop_process "$PID_A"
PID_A=
stop_process "$PID_B"
PID_B=
ip -n mtu-a link set ma0 mtu 1500
ip -n mtu-b link set mb0 mtu 1500
start_daemon mtu-a node-a PID_A
start_daemon mtu-b node-b PID_B
wait_until "fresh high-MTU connection" sh -c \
  'awk '\''$1 ~ /iroh_sdwan_peer_effective_frame_size_bytes/ && $NF >= 1300 {ok=1} END {exit !ok}'\'' /state/node-a/metrics.prom'
# IPv6 total length is about 48 bytes above noq's UDP payload size.  Drop the
# high-MTU packets while leaving the QUIC-required 1200-byte fallback usable.
ip netns exec mtu-a ip6tables -I OUTPUT 1 -p udp -m length --length 1301:65535 -j DROP
before_a=$(metric node-a effective_frame_size_bytes)
before_b=$(metric node-b effective_frame_size_bytes)
wait_until "silent black-hole traffic recovery" \
  ip netns exec mtu-a ping -6 -c 1 -W 3 -s 4096 -I fd73:9db8:4242::1 fd73:9db8:4242::2
wait_until "silent black-hole frame floor" sh -c \
  'awk '\''$1 ~ /iroh_sdwan_peer_effective_frame_size_bytes/ && $NF <= 1200 {ok=1} END {exit !ok}'\'' /state/node-a/metrics.prom'
after_a=$(metric node-a effective_frame_size_bytes)
after_b=$(metric node-b effective_frame_size_bytes)
test "$after_a" -le "$before_a"
test "$after_b" -ge "$after_a"
ip netns exec mtu-b ping -6 -c 3 -W 3 -s 4096 -I fd73:9db8:4242::2 fd73:9db8:4242::1
ip netns exec mtu-a ip6tables -D OUTPUT -p udp -m length --length 1301:65535 -j DROP
ctl mtu-a node-a ping --count 3 --timeout-ms 3000 10.242.0.2 | grep -q '3 transmitted, 3 received'

echo "IPv6 MTU network-namespace integration test passed"

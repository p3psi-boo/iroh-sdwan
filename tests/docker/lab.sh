#!/usr/bin/env bash
set -euo pipefail
source /tests/netns/common.sh

PID_A=
PID_B=
PID_C=
cleanup() {
  local status=$?
  stop_process "$PID_A"
  stop_process "$PID_B"
  stop_process "$PID_C"
  delete_namespaces ns-a ns-b ns-c
  exit "$status"
}
trap cleanup EXIT

write_config() {
  local node=$1
  local address_v4=$2
  local address_v6=$3
  local description=$4
  local peers=$5
  local origins=$6
  local transit=false
  if [[ $node == node-b ]]; then transit=true; fi
  cat >"/state/$node/config.toml" <<EOF
network_id = "netns-static-three-node"
identity_file = "/state/$node/identity.key"
bind_addresses = ["0.0.0.0:4000"]
discovery_enabled = false
tun_mtu = 65535
max_frame_size = 1000
node_interface = "isw0"
node_addresses = ["$address_v4/32", "$address_v6/128"]
advertised_prefixes = []

[node_info]
name = "$node"
description = "$description"

[node_info.metadata]
topology = "netns-a-b-c"

[routing]
isolate_overlay = true
transit_enabled = $transit
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

$peers

$origins
EOF
}

echo "==> creating static A <-> B <-> C namespaces"
for namespace in ns-a ns-b ns-c; do create_namespace "$namespace"; done
create_veth ns-a ab-a 172.30.10.2/24 ns-b ab-b 172.30.10.3/24
create_veth ns-b bc-b 172.30.20.2/24 ns-c bc-c 172.30.20.3/24
ip netns exec ns-b sysctl -qw net.ipv4.ip_forward=1
ip netns exec ns-b sysctl -qw net.ipv6.conf.all.forwarding=1

declare -A IDS
for node in node-a node-b node-c; do
  IDS[$node]=$(initialize_identity "$node" netns-static-three-node)
  test -n "${IDS[$node]}"
done

write_config node-a 10.200.0.1 fd73:9db8:4200::1 "left endpoint" "
[[peers]]
name = \"node-b\"
endpoint_id = \"${IDS[node-b]}\"
transit_enabled = true
direct_addresses = [\"172.30.10.3:4000\"]
allowed_source_prefixes = [\"10.200.0.2/32\", \"fd73:9db8:4200::2/128\", \"10.200.0.3/32\", \"fd73:9db8:4200::3/128\"]" "
[[route_origins]]
endpoint_id = \"${IDS[node-b]}\"
prefixes = [\"10.200.0.2/32\", \"fd73:9db8:4200::2/128\"]

[[route_origins]]
endpoint_id = \"${IDS[node-c]}\"
prefixes = [\"10.200.0.3/32\", \"fd73:9db8:4200::3/128\"]"

write_config node-b 10.200.0.2 fd73:9db8:4200::2 "transit router" "
[[peers]]
name = \"node-a\"
endpoint_id = \"${IDS[node-a]}\"
direct_addresses = [\"172.30.10.2:4000\"]
allowed_source_prefixes = [\"10.200.0.1/32\", \"fd73:9db8:4200::1/128\"]

[[peers]]
name = \"node-c\"
endpoint_id = \"${IDS[node-c]}\"
direct_addresses = [\"172.30.20.3:4000\"]
allowed_source_prefixes = [\"10.200.0.3/32\", \"fd73:9db8:4200::3/128\"]" "
[[route_origins]]
endpoint_id = \"${IDS[node-a]}\"
prefixes = [\"10.200.0.1/32\", \"fd73:9db8:4200::1/128\"]

[[route_origins]]
endpoint_id = \"${IDS[node-c]}\"
prefixes = [\"10.200.0.3/32\", \"fd73:9db8:4200::3/128\"]"

write_config node-c 10.200.0.3 fd73:9db8:4200::3 "right endpoint" "
[[peers]]
name = \"node-b\"
endpoint_id = \"${IDS[node-b]}\"
transit_enabled = true
direct_addresses = [\"172.30.20.2:4000\"]
allowed_source_prefixes = [\"10.200.0.1/32\", \"fd73:9db8:4200::1/128\", \"10.200.0.2/32\", \"fd73:9db8:4200::2/128\"]" "
[[route_origins]]
endpoint_id = \"${IDS[node-a]}\"
prefixes = [\"10.200.0.1/32\", \"fd73:9db8:4200::1/128\"]

[[route_origins]]
endpoint_id = \"${IDS[node-b]}\"
prefixes = [\"10.200.0.2/32\", \"fd73:9db8:4200::2/128\"]"

for node in node-a node-b node-c; do seal_node "$node"; done
start_daemon ns-a node-a PID_A
start_daemon ns-b node-b PID_B
start_daemon ns-c node-c PID_C

wait_until "A-C IPv4 overlay" ip netns exec ns-a ping -c 1 -W 2 -I 10.200.0.1 10.200.0.3
wait_until "A-C IPv6 overlay" ip netns exec ns-a ping -6 -c 1 -W 2 -I fd73:9db8:4200::1 fd73:9db8:4200::3

echo "==> validating isolation, fragmentation, status, peers, ping, and trace"
if ip netns exec ns-a ping -c 1 -W 1 172.30.20.3 >/dev/null 2>&1; then
  echo "A unexpectedly reached C underlay" >&2
  exit 1
fi
ip -n ns-a route show table 100 10.200.0.3/32 | grep -q 'dev isw0'
ip -n ns-a -6 route show table 100 fd73:9db8:4200::3/128 | grep -q 'dev isw0'
ip -n ns-a route show table 100 10.200.0.3/32 | grep -q 'src 10.200.0.1'
ip -n ns-a -6 route show table 100 fd73:9db8:4200::3/128 | grep -q 'src fd73:9db8:4200::1'
if ip -n ns-a route show table main 10.200.0.3/32 | grep -q .; then
  echo "overlay route leaked into the main table" >&2
  exit 1
fi
ip netns exec ns-a ping -c 1 -W 2 10.200.0.3
ip netns exec ns-a ping -6 -c 1 -W 2 fd73:9db8:4200::3
ip netns exec ns-a ping -q -l 256 -c 256 -W 2 -I 10.200.0.1 10.200.0.3
wait_until "small-packet aggregation" grep -Eq \
  'iroh_sdwan_peer_tx_batches_total\{.*\} [1-9][0-9]*$' \
  /state/node-a/metrics.prom
wait_until "aggregation flood queue drain" ip netns exec ns-a \
  ping -c 1 -W 2 -M do -s 1200 -I 10.200.0.1 10.200.0.3
ip netns exec ns-a ping -c 2 -W 2 -M do -s 1200 -I 10.200.0.1 10.200.0.3
ip netns exec ns-a ping -6 -c 2 -W 2 -s 1200 -I fd73:9db8:4200::1 fd73:9db8:4200::3
ctl ns-a node-a health --quiet
ctl ns-a node-a status --output json | grep -q '"ready": true'
ctl ns-a node-a peers --output json | grep -q '"name": "node-b"'
timeout 3s script -qec \
  'ip netns exec ns-a iroh-sdwan --config /state/node-a/config.toml --socket /state/node-a/control.sock tui --interval-ms 200' \
  /state/node-a/tui.typescript >/dev/null 2>&1 || test "$?" -eq 124
grep -q 'iroh-sdwan' /state/node-a/tui.typescript
ctl ns-a node-a ping --count 2 --timeout-ms 2000 10.200.0.3 | grep -q '2 transmitted, 2 received'
ctl ns-a node-a ping --count 2 --timeout-ms 2000 fd73:9db8:4200::3 | grep -q '2 transmitted, 2 received'
trace_v4=$(ctl ns-a node-a trace --timeout-ms 3000 10.200.0.3)
grep -Eq '^[[:space:]]*1[[:space:]]+node-b ' <<<"$trace_v4"
grep -Eq '^[[:space:]]*2[[:space:]]+node-c ' <<<"$trace_v4"
trace_v6=$(ctl ns-a node-a trace --timeout-ms 3000 fd73:9db8:4200::3)
grep -Eq '^[[:space:]]*1[[:space:]]+node-b ' <<<"$trace_v6"
grep -Eq '^[[:space:]]*2[[:space:]]+node-c ' <<<"$trace_v6"
trace_reverse=$(ctl ns-c node-c trace --timeout-ms 3000 10.200.0.1)
grep -Eq '^[[:space:]]*1[[:space:]]+node-b ' <<<"$trace_reverse"
grep -Eq '^[[:space:]]*2[[:space:]]+node-a ' <<<"$trace_reverse"
test "$(find /sys/class/net -maxdepth 1 -name 'isw*' | wc -l)" -eq 0
test "$(ip -n ns-a -o link show | grep -c 'isw0')" -eq 1

echo "==> validating doctor, metrics, fragmentation, and source policy"
for entry in 'ns-a node-a' 'ns-b node-b' 'ns-c node-c'; do
  read -r namespace node <<<"$entry"
  ctl "$namespace" "$node" doctor --config "/state/$node/config.toml"
done
for metric in \
  iroh_sdwan_peer_tx_packets_total \
  iroh_sdwan_peer_effective_frame_size_bytes \
  iroh_sdwan_peer_path_mtu_bytes \
  iroh_sdwan_peer_path_cwnd_bytes \
  iroh_sdwan_peer_selected_path_info \
  iroh_sdwan_peer_open_paths \
  iroh_sdwan_peer_tun_mtu_bytes \
  iroh_sdwan_peer_heartbeats_sent_total \
  iroh_sdwan_peer_heartbeats_received_total; do
  grep -q "$metric" /state/node-a/metrics.prom
done
grep -q 'iroh_sdwan_routes_ready 1' /state/node-a/metrics.prom
grep -q 'iroh_sdwan_route_present.*10.200.0.3/32.* 1' /state/node-a/metrics.prom
tx_packets=$(sed -n 's/.*iroh_sdwan_peer_tx_packets_total[^ ]* //p' /state/node-a/metrics.prom)
tx_fragments=$(sed -n 's/.*iroh_sdwan_peer_tx_fragments_total[^ ]* //p' /state/node-a/metrics.prom)
test "$tx_fragments" -gt "$tx_packets"

ip -n ns-a address add 10.200.0.3/32 dev isw0
ip netns exec ns-a ping -c 32 -i 0.01 -W 1 -I 10.200.0.3 10.200.0.2 \
  >/dev/null 2>&1 || true
ip -n ns-a address del 10.200.0.3/32 dev isw0
wait_until "node-b adjacency-policy drop" sh -c \
  'grep -q "dropping inbound packet rejected" /state/node-b/daemon.log && grep -q "10.200.0.3" /state/node-b/daemon.log && awk '\''$1 ~ /iroh_sdwan_peer_policy_drops_total/ && $0 ~ /peer="node-a"/ && $NF > 0 { found=1 } END { exit !found }'\'' /state/node-b/metrics.prom'

echo "==> transactional and concurrent reload"
cp /state/node-a/config.toml /state/node-a/config.valid.toml
printf '\n# invalidate digest\n' >>/state/node-a/config.toml
if ctl ns-a node-a reload; then
  echo "tampered reload unexpectedly succeeded" >&2
  exit 1
fi
mv /state/node-a/config.valid.toml /state/node-a/config.toml
ctl ns-a node-a reload | grep -q 'generation=2'
ctl ns-a node-a ping --count 20 --timeout-ms 2000 10.200.0.3 \
  >/state/reload-ping.log &
reload_ping_pid=$!
sleep 0.5
ctl ns-a node-a reload | grep -q 'generation=3'
wait "$reload_ping_pid"
grep -Eq '20 transmitted, ([1-9]|1[0-9]|20) received' /state/reload-ping.log

echo "==> concurrent control load and descriptor recovery"
fd_before=$(find "/proc/$PID_A/fd" -mindepth 1 -maxdepth 1 | wc -l)
control_pids=()
for index in $(seq 1 8); do
  ctl ns-a node-a status --output json >"/state/status-$index.json" & control_pids+=("$!")
  ctl ns-a node-a peers --output jsonl >"/state/peers-$index.jsonl" & control_pids+=("$!")
done
for index in $(seq 1 4); do
  ctl ns-a node-a ping --count 20 --timeout-ms 2000 --output json 10.200.0.3 \
    >"/state/ping-$index.json" & control_pids+=("$!")
  ctl ns-a node-a trace --max-hops 3 --timeout-ms 2000 --output json 10.200.0.3 \
    >"/state/trace-$index.json" & control_pids+=("$!")
done
for pid in "${control_pids[@]}"; do wait "$pid"; done
sleep 1
fd_after=$(find "/proc/$PID_A/fd" -mindepth 1 -maxdepth 1 | wc -l)
test "$fd_after" -le "$((fd_before + 2))"

echo "==> enforcing Unix control-socket group permissions"
groupadd --force sdwanctl
id -u ctl-allowed >/dev/null 2>&1 || useradd --no-create-home --gid sdwanctl ctl-allowed
id -u ctl-denied >/dev/null 2>&1 || useradd --no-create-home ctl-denied
chgrp sdwanctl /state/node-a/control.sock
chmod 0660 /state/node-a/control.sock
chgrp sdwanctl /state/node-a
chmod 0750 /state/node-a
ip netns exec ns-a runuser -u ctl-allowed -- \
  iroh-sdwan --socket /state/node-a/control.sock health --quiet
if ip netns exec ns-a runuser -u ctl-denied -- \
  iroh-sdwan --socket /state/node-a/control.sock status >/state/denied-control.log 2>&1; then
  echo "unprivileged non-group user accessed the control socket" >&2
  exit 1
fi
grep -Eq 'Permission denied|failed connecting' /state/denied-control.log

echo "==> client cancellation and daemon restart during ping"
timeout 0.5s bash -c 'ip netns exec ns-a iroh-sdwan --socket /state/node-a/control.sock ping --count 20 --timeout-ms 2000 10.200.0.3' >/dev/null 2>&1 || true
ctl ns-a node-a health --quiet
ctl ns-a node-a ping --count 20 --timeout-ms 2000 10.200.0.3 >/state/restart-ping.log 2>&1 &
restart_ping_pid=$!
sleep 0.5
stop_process "$PID_A"
PID_A=
if wait "$restart_ping_pid"; then
  echo "ping unexpectedly survived daemon restart" >&2
  exit 1
fi
wait_until "node-a graceful stopped status" grep -q '"ready": false' /state/node-a/status.json
start_daemon ns-a node-a PID_A
wait_until "node-a health after restart" ctl ns-a node-a health --quiet

echo "==> partial loss, total loss, and broken transit"
ip netns exec ns-c tc qdisc replace dev bc-c root netem loss 35%
partial=$(ctl ns-a node-a ping --count 20 --timeout-ms 500 --output json 10.200.0.3)
ip netns exec ns-c tc qdisc del dev bc-c root
received=$(sed -n 's/^[[:space:]]*"received": \([0-9][0-9]*\),/\1/p' <<<"$partial")
loss=$(sed -n 's/^[[:space:]]*"loss_ppm": \([0-9][0-9]*\),/\1/p' <<<"$partial")
test "$received" -gt 0 && test "$received" -lt 20
test "$loss" -gt 0 && test "$loss" -lt 1000000
grep -q '"avg_ms":' <<<"$partial"

ip netns exec ns-c tc qdisc replace dev bc-c root netem loss 100%
if unreachable=$(ctl ns-a node-a ping --count 3 --timeout-ms 250 10.200.0.3 2>&1); then
  echo "100% loss ping unexpectedly succeeded" >&2
  exit 1
fi
ip netns exec ns-c tc qdisc del dev bc-c root
grep -q '3 transmitted, 0 received, 100.0% loss' <<<"$unreachable"

for interface in ab-b bc-b; do ip netns exec ns-b tc qdisc replace dev "$interface" root netem loss 100%; done
if broken=$(ctl ns-a node-a ping --count 2 --timeout-ms 250 10.200.0.3 2>&1); then
  echo "broken transit ping unexpectedly succeeded" >&2
  exit 1
fi
for interface in ab-b bc-b; do ip netns exec ns-b tc qdisc del dev "$interface" root || true; done
grep -q '2 transmitted, 0 received, 100.0% loss' <<<"$broken"
wait_until "recovery after fault injection" ctl ns-a node-a ping --count 1 --timeout-ms 2000 10.200.0.3

echo "static network-namespace integration test passed"

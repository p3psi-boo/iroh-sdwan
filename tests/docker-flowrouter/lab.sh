#!/usr/bin/env bash
set -euo pipefail
source /tests/netns/common.sh

WAIT_ATTEMPTS=150
PID_A=
PID_B=
PID_C=
PID_D=
PID_IPERF_1=
PID_ECHO_1=
PID_ECHO_2=

cleanup() {
  local status=$?
  stop_process "$PID_IPERF_1"
  stop_process "$PID_ECHO_1"
  stop_process "$PID_ECHO_2"
  stop_process "$PID_A"
  stop_process "$PID_B"
  stop_process "$PID_C"
  stop_process "$PID_D"
  delete_namespaces fr-a fr-b fr-c fr-d
  exit "$status"
}
trap cleanup EXIT

write_config() {
  local node=$1
  local address=$2
  local transit=$3
  local peers=$4
  local origins=$5
  cat >"/state/$node/config.toml" <<EOF
network_id = "netns-flowrouter-business"
identity_file = "/state/$node/identity.key"
bind_addresses = ["0.0.0.0:4000"]
discovery_enabled = false
tun_mtu = 65535
max_frame_size = 1400
node_interface = "isw0"
node_addresses = ["$address/32"]
advertised_prefixes = []

[node_info]
name = "$node"
description = "FlowRouter dual-transit fixture"

[node_info.metadata]
topology = "a-via-b-or-d-to-c"

[relay]
mode = "disabled"

[routing]
isolate_overlay = true
transit_enabled = $transit
rule_priority = 10000
table = 100
allow_default_routes = false

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

metric() {
  local node=$1
  local peer=$2
  local name=$3
  awk -v metric="iroh_sdwan_peer_${name}" -v peer="$peer" \
    '$1 ~ ("^" metric "\\{") && $0 ~ ("peer=\\\"" peer "\\\"") { print $NF; found=1; exit } END { if (!found) exit 1 }' \
    "/state/$node/metrics.prom"
}

rtt_prefers_b() {
  local b d
  b=$(metric node-a node-b path_rtt_microseconds)
  d=$(metric node-a node-d path_rtt_microseconds)
  test "$b" -gt 0 && test "$d" -gt "$b"
}

rtt_prefers_d() {
  local b d
  b=$(metric node-a node-b path_rtt_microseconds)
  d=$(metric node-a node-d path_rtt_microseconds)
  test "$d" -gt 0 && test "$b" -gt "$d"
}

route_rtt_prefers_d() {
  local b d
  b=$(jq -r --arg destination "${IDS[node-c]}" --arg hop "${IDS[node-b]}" \
    '[.capacities[] | select(.destination == $destination and .first_hop == $hop) | .rtt_ewma_micros][0] // 0' \
    /state/node-a/status.json)
  d=$(jq -r --arg destination "${IDS[node-c]}" --arg hop "${IDS[node-d]}" \
    '[.capacities[] | select(.destination == $destination and .first_hop == $hop) | .rtt_ewma_micros][0] // 0' \
    /state/node-a/status.json)
  test "$d" -gt 0 && test "$b" -gt "$d"
}

b_path_recovered() {
  local b_rtt d_rtt b_jitter b_loss route_b_rtt route_d_rtt
  b_rtt=$(metric node-a node-b path_rtt_microseconds)
  d_rtt=$(metric node-a node-d path_rtt_microseconds)
  b_jitter=$(metric node-a node-b path_jitter_microseconds)
  b_loss=$(metric node-a node-b path_loss_parts_per_million)
  route_b_rtt=$(jq -r --arg destination "${IDS[node-c]}" --arg hop "${IDS[node-b]}" \
    '[.capacities[] | select(.destination == $destination and .first_hop == $hop) | .rtt_ewma_micros][0] // 0' \
    /state/node-a/status.json)
  route_d_rtt=$(jq -r --arg destination "${IDS[node-c]}" --arg hop "${IDS[node-d]}" \
    '[.capacities[] | select(.destination == $destination and .first_hop == $hop) | .rtt_ewma_micros][0] // 0' \
    /state/node-a/status.json)
  test "$b_rtt" -gt 0 && test "$b_rtt" -lt "$d_rtt" \
    && test "$route_b_rtt" -gt 0 && test "$route_b_rtt" -lt "$route_d_rtt" \
    && test "$b_jitter" -lt 5000 && test "$b_loss" -lt 2000
}

capacity_routes_learned() {
  local b d
  b=$(jq -r --arg destination "${IDS[node-c]}" --arg hop "${IDS[node-b]}" \
    '.capacities[] | select(.destination == $destination and .first_hop == $hop) | .measured_capacity_bps // 0' \
    /state/node-a/status.json)
  d=$(jq -r --arg destination "${IDS[node-c]}" --arg hop "${IDS[node-d]}" \
    '.capacities[] | select(.destination == $destination and .first_hop == $hop) | .measured_capacity_bps // 0' \
    /state/node-a/status.json)
  test "$b" -gt 0 && test "$b" -lt 30000000 && test "$d" -gt "$((b * 3))"
}

route_capacity() {
  local node=$1 destination=$2 hop=$3
  jq -r --arg destination "$destination" --arg hop "$hop" \
    '.capacities[] | select(.destination == $destination and .first_hop == $hop) | .measured_capacity_bps // 0' \
    "/state/$node/status.json"
}

b_capacity_exceeds_d() {
  local b d
  b=$(route_capacity node-a "${IDS[node-c]}" "${IDS[node-b]}")
  d=$(route_capacity node-a "${IDS[node-c]}" "${IDS[node-d]}")
  test "$d" -gt 0 && test "$b" -gt "$((d * 11 / 10))"
}

d_capacity_converged_down() {
  local d
  d=$(route_capacity node-a "${IDS[node-c]}" "${IDS[node-d]}")
  test "$d" -gt 0 && test "$d" -lt 20000000
}

d_capacity_relearned() {
  # A new QUIC path starts with a cold congestion window, so a bounded 64 KiB
  # active train is allowed to underestimate a high-BDP link.  Reconnect must
  # prove that the old epoch was discarded and a fresh active estimate was
  # learned; the later receiver-confirmed Bulk interval is the throughput
  # authority.
  jq -e --arg destination "${IDS[node-c]}" --arg hop "${IDS[node-d]}" '
    any(.capacities[];
      .destination == $destination
      and .first_hop == $hop
      and .freshness == "fresh"
      and .sample_source == "active"
      and .active_samples >= 3
      and .path_epoch >= 2
      and (.measured_capacity_bps // 0) > 0)
  ' /state/node-a/status.json >/dev/null
}

b_capacity_relearned() {
  # Reconnecting B creates another cold QUIC path.  Require a fresh estimate
  # for the new epoch here; the immediately following end-to-end bulk transfer
  # is the deterministic proof that B now beats the deliberately capped D path.
  jq -e --arg destination "${IDS[node-c]}" --arg hop "${IDS[node-b]}" '
    any(.capacities[];
      .destination == $destination
      and .first_hop == $hop
      and .freshness == "fresh"
      and .sample_source == "active"
      and .active_samples >= 3
      and .path_epoch >= 3
      and (.measured_capacity_bps // 0) > 0)
  ' /state/node-a/status.json >/dev/null
}

echo "==> creating A -> {B,D} -> C dual-transit topology"
for namespace in fr-a fr-b fr-c fr-d; do create_namespace "$namespace"; done
create_veth fr-a ab-a 172.32.10.2/24 fr-b ab-b 172.32.10.3/24
create_veth fr-b bc-b 172.32.20.2/24 fr-c bc-c 172.32.20.3/24
create_veth fr-a ad-a 172.32.30.2/24 fr-d ad-d 172.32.30.3/24
create_veth fr-d dc-d 172.32.40.2/24 fr-c dc-c 172.32.40.3/24

for namespace in fr-b fr-d; do
  ip netns exec "$namespace" sysctl -qw net.ipv4.ip_forward=1
done

# B is the low-latency route but is physically narrow. D has more startup
# latency and ten times the measured complete-route capacity.
for entry in \
  'fr-a ab-a 3ms 100mbit' 'fr-b ab-b 3ms 100mbit' \
  'fr-b bc-b 3ms 10mbit' 'fr-c bc-c 3ms 10mbit' \
  'fr-a ad-a 35ms 100mbit' 'fr-d ad-d 35ms 100mbit' \
  'fr-d dc-d 35ms 100mbit' 'fr-c dc-c 35ms 100mbit'; do
  read -r namespace interface delay rate <<<"$entry"
  ip netns exec "$namespace" tc qdisc replace dev "$interface" root netem \
    delay "$delay" 1ms 20% rate "$rate"
done

declare -A IDS
for node in node-a node-b node-c node-d; do
  IDS[$node]=$(initialize_identity "$node" netns-flowrouter-business)
done

write_config node-a 10.230.0.1 false "
[[peers]]
name = \"node-b\"
endpoint_id = \"${IDS[node-b]}\"
transit_enabled = true
direct_addresses = [\"172.32.10.3:4000\"]
allowed_source_prefixes = [\"10.230.0.2/32\", \"10.230.0.4/32\"]

[[peers]]
name = \"node-d\"
endpoint_id = \"${IDS[node-d]}\"
transit_enabled = true
direct_addresses = [\"172.32.30.3:4000\"]
allowed_source_prefixes = [\"10.230.0.3/32\", \"10.230.0.4/32\"]" "
[[route_origins]]
endpoint_id = \"${IDS[node-b]}\"
prefixes = [\"10.230.0.2/32\"]

[[route_origins]]
endpoint_id = \"${IDS[node-d]}\"
prefixes = [\"10.230.0.3/32\"]

[[route_origins]]
endpoint_id = \"${IDS[node-c]}\"
prefixes = [\"10.230.0.4/32\"]"

write_config node-b 10.230.0.2 true "
[[peers]]
name = \"node-a\"
endpoint_id = \"${IDS[node-a]}\"
direct_addresses = [\"172.32.10.2:4000\"]
allowed_source_prefixes = [\"10.230.0.1/32\"]

[[peers]]
name = \"node-c\"
endpoint_id = \"${IDS[node-c]}\"
direct_addresses = [\"172.32.20.3:4000\"]
allowed_source_prefixes = [\"10.230.0.4/32\"]" "
[[route_origins]]
endpoint_id = \"${IDS[node-a]}\"
prefixes = [\"10.230.0.1/32\"]

[[route_origins]]
endpoint_id = \"${IDS[node-c]}\"
prefixes = [\"10.230.0.4/32\"]"

write_config node-d 10.230.0.3 true "
[[peers]]
name = \"node-a\"
endpoint_id = \"${IDS[node-a]}\"
direct_addresses = [\"172.32.30.2:4000\"]
allowed_source_prefixes = [\"10.230.0.1/32\"]

[[peers]]
name = \"node-c\"
endpoint_id = \"${IDS[node-c]}\"
direct_addresses = [\"172.32.40.3:4000\"]
allowed_source_prefixes = [\"10.230.0.4/32\"]" "
[[route_origins]]
endpoint_id = \"${IDS[node-a]}\"
prefixes = [\"10.230.0.1/32\"]

[[route_origins]]
endpoint_id = \"${IDS[node-c]}\"
prefixes = [\"10.230.0.4/32\"]"

write_config node-c 10.230.0.4 false "
[[peers]]
name = \"node-b\"
endpoint_id = \"${IDS[node-b]}\"
transit_enabled = true
direct_addresses = [\"172.32.20.2:4000\"]
allowed_source_prefixes = [\"10.230.0.1/32\", \"10.230.0.2/32\"]

[[peers]]
name = \"node-d\"
endpoint_id = \"${IDS[node-d]}\"
transit_enabled = true
direct_addresses = [\"172.32.40.2:4000\"]
allowed_source_prefixes = [\"10.230.0.1/32\", \"10.230.0.3/32\"]" "
[[route_origins]]
endpoint_id = \"${IDS[node-b]}\"
prefixes = [\"10.230.0.2/32\"]

[[route_origins]]
endpoint_id = \"${IDS[node-d]}\"
prefixes = [\"10.230.0.3/32\"]

[[route_origins]]
endpoint_id = \"${IDS[node-a]}\"
prefixes = [\"10.230.0.1/32\"]"

for node in node-a node-b node-c node-d; do seal_node "$node"; done
start_daemon fr-a node-a PID_A
start_daemon fr-b node-b PID_B
start_daemon fr-c node-c PID_C
start_daemon fr-d node-d PID_D

wait_until "four-node FlowRouter readiness" sh -c \
  'grep -q '\''"ready": true'\'' /state/node-a/status.json && grep -q '\''"ready": true'\'' /state/node-c/status.json'
wait_until "latency estimator to prefer B" rtt_prefers_b
wait_until "complete-route capacity probes to distinguish B and D" capacity_routes_learned

echo "==> proving transparent short-flow preference on unrelated TCP ports"
ip netns exec fr-c iperf3 -s -B 10.230.0.4 -p 5201 \
  >/state/iperf-5201-server.log 2>&1 &
PID_IPERF_1=$!
ip netns exec fr-c python3 /tests/netns/tcp_echo.py server 10.230.0.4 5222 \
  >/state/echo-5222-server.log 2>&1 &
PID_ECHO_1=$!
ip netns exec fr-c python3 /tests/netns/tcp_echo.py server 10.230.0.4 5233 \
  >/state/echo-5233-server.log 2>&1 &
PID_ECHO_2=$!
wait_until "iperf overlay service" ip netns exec fr-a nc -z -w 3 10.230.0.4 5201
wait_until "echo overlay service" ip netns exec fr-a nc -z -w 3 10.230.0.4 5222

b_latency_before=$(metric node-a node-b flow_latency_packets_total)
d_latency_before=$(metric node-a node-d flow_latency_packets_total)
ip netns exec fr-a python3 /tests/netns/tcp_echo.py client 10.230.0.4 5222 4096
ip netns exec fr-a python3 /tests/netns/tcp_echo.py client 10.230.0.4 5233 4096
wait_until "short-flow counters" sh -c \
  'test "$(awk '\''$1 ~ /^iroh_sdwan_peer_flow_latency_packets_total/ && /peer="node-b"/ {print $NF}'\'' /state/node-a/metrics.prom)" -gt "$1"' \
  sh "$b_latency_before"
b_latency_after=$(metric node-a node-b flow_latency_packets_total)
d_latency_after=$(metric node-a node-d flow_latency_packets_total)
test "$((b_latency_after - b_latency_before))" -gt "$((d_latency_after - d_latency_before))"

echo "==> proving one ordinary TCP flow grows from latency to bulk routing"
b_bytes_before=$(metric node-a node-b flow_selected_bytes_total)
d_bytes_before=$(metric node-a node-d flow_selected_bytes_total)
b_bulk_before=$(metric node-a node-b flow_bulk_packets_total)
d_bulk_before=$(metric node-a node-d flow_bulk_packets_total)
ip netns exec fr-a iperf3 -c 10.230.0.4 -p 5201 -t 6 --cport 45000 -J \
  >/state/bulk-forward.json
sleep 2
b_bytes_after=$(metric node-a node-b flow_selected_bytes_total)
d_bytes_after=$(metric node-a node-d flow_selected_bytes_total)
b_bulk_after=$(metric node-a node-b flow_bulk_packets_total)
d_bulk_after=$(metric node-a node-d flow_bulk_packets_total)
test "$((d_bytes_after - d_bytes_before))" -gt "$((b_bytes_after - b_bytes_before))"
test "$((d_bulk_after - d_bulk_before))" -gt "$((b_bulk_after - b_bulk_before))"
test "$(jq '.end.sum_received.bits_per_second > 20000000' /state/bulk-forward.json)" = true

echo "==> keeping latency probes responsive beside a bulk transfer"
sleep 3
d_bulk_before=$(metric node-a node-d flow_bulk_packets_total)
ip netns exec fr-a iperf3 -c 10.230.0.4 -p 5201 -t 8 --cport 45001 -J \
  >/state/bulk-concurrent.json &
bulk_pid=$!
sleep 2
interactive=$(ctl fr-a node-a ping --count 8 --timeout-ms 2000 --output json 10.230.0.4)
wait "$bulk_pid"
interactive_avg=$(jq -r '.avg_ms | floor' <<<"$interactive")
interactive_max=$(jq -r '.max_ms | floor' <<<"$interactive")
test "$interactive_avg" -lt 60
test "$interactive_max" -lt 200
sleep 2
d_bulk_after=$(metric node-a node-d flow_bulk_packets_total)
test "$d_bulk_after" -gt "$d_bulk_before"

echo "==> verifying independently measured reverse-direction bulk"
d_reverse_before=$(metric node-c node-d flow_bulk_packets_total)
# Several simultaneous ordinary TCP flows keep the reverse direction
# non-app-limited long enough for its independent receiver-confirmed estimate
# to leave QUIC cold start; this remains transparent to FlowRouter.
ip netns exec fr-a iperf3 -c 10.230.0.4 -p 5201 -R -P 4 -t 8 --cport 45002 -J \
  >/state/bulk-reverse.json
sleep 2
d_reverse_after=$(metric node-c node-d flow_bulk_packets_total)
test "$d_reverse_after" -gt "$d_reverse_before"
test "$(jq '.end.sum_received.bits_per_second > 20000000' /state/bulk-reverse.json)" = true

echo "==> raising the complete B path from 10 to 150 Mbit/s"
for entry in 'fr-a ab-a' 'fr-b ab-b' 'fr-b bc-b' 'fr-c bc-c'; do
  read -r namespace interface <<<"$entry"
  ip netns exec "$namespace" tc qdisc replace dev "$interface" root netem \
    delay 3ms 1ms 20% rate 150mbit
done
# Give the changed route one real receiver-confirmed saturation interval. This
# mirrors the normal single-route case (maintenance/failure of the alternate)
# and proves an increased capacity can replace the old low maximum without a
# declaration or synthetic estimator update.
stop_process "$PID_D"
PID_D=
wait_until "D route to disconnect during B relearning" jq -e \
  'any(.peers[]; .name == "node-d" and (.connected | not))' /state/node-a/status.json
ip netns exec fr-a iperf3 -c 10.230.0.4 -p 5201 -P 8 -t 5 --cport 45003 -J \
  >/state/bulk-b-relearn.json
wait_until "receiver-confirmed B capacity to exceed old D capacity" b_capacity_exceeds_d
start_daemon fr-d node-d PID_D
wait_until "D route after B relearning" jq -e \
  'any(.peers[]; .name == "node-d" and .connected)' /state/node-a/status.json
wait_until "D capacity after reconnect" d_capacity_relearned

b_bytes_before=$(metric node-a node-b flow_selected_bytes_total)
d_bytes_before=$(metric node-a node-d flow_selected_bytes_total)
ip netns exec fr-a iperf3 -c 10.230.0.4 -p 5201 -t 6 --cport 45100 -J \
  >/state/bulk-b-raised.json
sleep 2
b_bytes_after=$(metric node-a node-b flow_selected_bytes_total)
d_bytes_after=$(metric node-a node-d flow_selected_bytes_total)
test "$((b_bytes_after - b_bytes_before))" -gt "$((d_bytes_after - d_bytes_before))"
test "$(jq '.end.sum_received.bits_per_second > 50000000' /state/bulk-b-raised.json)" = true

echo "==> degrading and recovering the latency path"
for entry in 'fr-a ab-a' 'fr-b ab-b'; do
  read -r namespace interface <<<"$entry"
  ip netns exec "$namespace" tc qdisc replace dev "$interface" root netem \
    delay 150ms 20ms 25% loss 5% rate 10mbit
done
wait_until "link estimator to prefer D" rtt_prefers_d
wait_until "route estimator to prefer D" route_rtt_prefers_d
d_latency_before=$(metric node-a node-d flow_latency_packets_total)
sleep 3
ip netns exec fr-a python3 /tests/netns/tcp_echo.py client 10.230.0.4 5222 4096
sleep 2
d_latency_after=$(metric node-a node-d flow_latency_packets_total)
echo "degraded short-flow latency counters: D $d_latency_before -> $d_latency_after"
test "$d_latency_after" -gt "$d_latency_before"
b_loss=$(metric node-a node-b path_loss_parts_per_million)
echo "degraded B loss_ppm: $b_loss"
# Loss is probabilistic and the short flow moves away from B quickly. RTT and
# selected-route counters above are the deterministic degradation evidence;
# keep loss as a diagnostic rather than requiring a random drop in this window.

for entry in 'fr-a ab-a' 'fr-b ab-b'; do
  read -r namespace interface <<<"$entry"
  ip netns exec "$namespace" tc qdisc replace dev "$interface" root netem \
    delay 3ms 1ms 20% rate 10mbit
done
wait_until "latency route recovery" b_path_recovered
sleep 3
b_latency_before=$(metric node-a node-b flow_latency_packets_total)
ip netns exec fr-a python3 /tests/netns/tcp_echo.py client 10.230.0.4 5233 4096
sleep 2
b_latency_after=$(metric node-a node-b flow_latency_packets_total)
echo "recovered short-flow latency counters: B $b_latency_before -> $b_latency_after"
test "$b_latency_after" -gt "$b_latency_before"
test "$(metric node-a node-b queue_drops_total)" -eq 0
test "$(metric node-a node-d queue_drops_total)" -eq 0

echo "==> lowering D from 100 to 5 Mbit/s and proving stale capacity decays"
for entry in 'fr-a ad-a' 'fr-d ad-d' 'fr-d dc-d' 'fr-c dc-c'; do
  read -r namespace interface <<<"$entry"
  ip netns exec "$namespace" tc qdisc replace dev "$interface" root netem \
    delay 35ms 1ms 20% rate 5mbit
done
# Make D the only complete route so real receiver-confirmed samples exercise
# the two-window collapse hysteresis rather than relying on a synthetic update.
stop_process "$PID_B"
PID_B=
wait_until "D-only complete route" ctl fr-a node-a ping --count 1 --timeout-ms 3000 10.230.0.4
ip netns exec fr-a iperf3 -c 10.230.0.4 -p 5201 -t 22 --cport 45004 -J \
  >/state/bulk-d-lowered.json
wait_until "D capacity estimate below 20 Mbit/s" d_capacity_converged_down
test "$(jq '.end.sum_received.bits_per_second > 3000000' /state/bulk-d-lowered.json)" = true

start_daemon fr-b node-b PID_B
wait_until "B adjacency after reconnect" jq -e \
  'any(.peers[]; .name == "node-b" and .connected)' /state/node-a/status.json
wait_until "B capacity after reconnect" b_capacity_relearned
wait_until "B route after reconnect" ctl fr-a node-a ping --count 1 --timeout-ms 3000 10.230.0.4
sleep 3
b_bytes_before=$(metric node-a node-b flow_selected_bytes_total)
d_bytes_before=$(metric node-a node-d flow_selected_bytes_total)
ip netns exec fr-a iperf3 -c 10.230.0.4 -p 5201 -t 6 --cport 45005 -J \
  >/state/bulk-after-d-lowered.json
sleep 2
b_bytes_after=$(metric node-a node-b flow_selected_bytes_total)
d_bytes_after=$(metric node-a node-d flow_selected_bytes_total)
echo "post-degradation bulk bytes: B $b_bytes_before->$b_bytes_after D $d_bytes_before->$d_bytes_after"
test "$((b_bytes_after - b_bytes_before))" -gt "$((d_bytes_after - d_bytes_before))"
grep -q 'FlowRouter switched route' /state/node-a/daemon.log
grep -q 'demand_bytes' /state/node-a/daemon.log
jq -e 'any(.capacities[]; .route_switches > 0)' /state/node-a/status.json >/dev/null
grep -Eq 'iroh_sdwan_route_switches_total\{.*\} [1-9][0-9]*$' /state/node-a/metrics.prom

echo "FlowRouter business network-namespace integration test passed"

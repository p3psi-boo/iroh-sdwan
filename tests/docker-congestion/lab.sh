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
  delete_namespaces congestion-a congestion-b
  exit "$status"
}
trap cleanup EXIT

write_config() {
  local node=$1 address=$2 peer=$3 peer_address=$4 peer_id=$5 direct=$6
  cat >"/state/$node/config.toml" <<EOF
network_id = "netns-congestion-isolation"
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
description = "single-peer bulk and interactive congestion fixture"

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
allowed_source_prefixes = ["$peer_address/32"]

[[route_origins]]
endpoint_id = "$peer_id"
prefixes = ["$peer_address/32"]
EOF
}

metric() {
  local node=$1 name=$2
  awk -v metric="iroh_sdwan_peer_${name}" \
    '$1 ~ ("^" metric "\\{") { print $NF; found=1; exit } END { if (!found) exit 1 }' \
    "/state/$node/metrics.prom"
}

ping_percentile() {
  local file=$1 percentile=$2
  jq -r --argjson percentile "$percentile" '
    [.samples[] | select(.reached and .elapsed_ms != null) | .elapsed_ms] as $samples
    | ($samples | sort) as $sorted
    | (($sorted | length) * $percentile / 100 | ceil) as $rank
    | $sorted[([$rank - 1, 0] | max)]
  ' "$file"
}

echo "==> creating one constrained adjacency for congestion-isolation testing"
create_namespace congestion-a
create_namespace congestion-b
create_veth congestion-a ca0 172.36.10.2/24 congestion-b cb0 172.36.10.3/24

# Keep the netem backlog itself small.  This exercises iroh-sdwan's application
# queue and QUIC backpressure rather than manufacturing hundreds of
# milliseconds in an oversized host qdisc which the overlay cannot preempt.
for entry in 'congestion-a ca0' 'congestion-b cb0'; do
  read -r namespace interface <<<"$entry"
  ip netns exec "$namespace" tc qdisc replace dev "$interface" root netem \
    delay 12ms 1ms 20% rate 12mbit limit 64
done

IDS_A=$(initialize_identity node-a netns-congestion-isolation)
IDS_B=$(initialize_identity node-b netns-congestion-isolation)
write_config node-a 10.244.0.1 node-b 10.244.0.2 "$IDS_B" 172.36.10.3:4000
write_config node-b 10.244.0.2 node-a 10.244.0.1 "$IDS_A" 172.36.10.2:4000
seal_node node-a
seal_node node-b
start_daemon congestion-a node-a PID_A
start_daemon congestion-b node-b PID_B
wait_until "congestion overlay" ctl congestion-a node-a ping --count 1 --timeout-ms 3000 10.244.0.2

ip netns exec congestion-b iperf3 -s -B 10.244.0.2 -p 5244 \
  >/state/congestion-iperf-server.log 2>&1 &
PID_IPERF=$!
wait_until "congestion iperf service" ip netns exec congestion-a nc -z -w 2 10.244.0.2 5244

echo "==> measuring idle interactive RTT"
ctl congestion-a node-a ping --count 12 --timeout-ms 2000 --output json 10.244.0.2 \
  >/state/congestion-idle-ping.json
idle_p95=$(ping_percentile /state/congestion-idle-ping.json 95)

latency_before=$(metric node-a flow_latency_packets_total)
bulk_before=$(metric node-a flow_bulk_packets_total)
drops_before=$(metric node-a queue_drops_total)
expired_before=$(metric node-a queue_expired_drops_total)

echo "==> saturating the adjacency while continuously probing interactive RTT"
ip netns exec congestion-a iperf3 -c 10.244.0.2 -p 5244 \
  -P 8 -t 16 --cport 45400 -J >/state/congestion-bulk.json &
bulk_pid=$!
sleep 2
ctl congestion-a node-a ping --count 20 --timeout-ms 1000 --output json 10.244.0.2 \
  >/state/congestion-loaded-ping.json
# Capture the saturated state before allowing the queue to drain. Bulk expiry
# is disabled because throwing away old TCP segments causes retransmission
# feedback; the byte bound is the sole Bulk overload limit.
priority_loaded=$(metric node-a priority_queue_bytes)
bulk_loaded=$(metric node-a bulk_queue_bytes)
queue_loaded=$(metric node-a queue_bytes)
active_tx_loaded=$(metric node-a active_tx_bytes)
quic_buffer_loaded=$(metric node-a quic_send_buffer_used_bytes)
wait "$bulk_pid"
sleep 2

loaded_p95=$(ping_percentile /state/congestion-loaded-ping.json 95)
loaded_max=$(jq -r '.max_ms' /state/congestion-loaded-ping.json)
received=$(jq -r '.received' /state/congestion-loaded-ping.json)
throughput=$(jq -r '.end.sum_received.bits_per_second | floor' /state/congestion-bulk.json)
latency_after=$(metric node-a flow_latency_packets_total)
bulk_after=$(metric node-a flow_bulk_packets_total)
drops_after=$(metric node-a queue_drops_total)
expired_after=$(metric node-a queue_expired_drops_total)
queue_peak=$(metric node-a queue_peak_bytes)
queue_now=$(metric node-a queue_bytes)
priority_queue_now=$(metric node-a priority_queue_bytes)
bulk_queue_now=$(metric node-a bulk_queue_bytes)
active_tx_now=$(metric node-a active_tx_bytes)
quic_buffer_now=$(metric node-a quic_send_buffer_used_bytes)
bulk_preemptions=$(metric node-a bulk_preemptions_total)

printf 'congestion idle_p95_ms=%s loaded_p95_ms=%s loaded_max_ms=%s received=%s/20 throughput_bps=%s queue_peak=%s queue_now=%s priority_now=%s bulk_now=%s active_tx=%s quic_buffer=%s loaded_queue=%s loaded_priority=%s loaded_bulk=%s loaded_active=%s loaded_quic=%s preemptions=%s drops=%s->%s expired=%s->%s\n' \
  "$idle_p95" "$loaded_p95" "$loaded_max" "$received" "$throughput" \
  "$queue_peak" "$queue_now" "$priority_queue_now" "$bulk_queue_now" \
  "$active_tx_now" "$quic_buffer_now" "$queue_loaded" "$priority_loaded" "$bulk_loaded" \
  "$active_tx_loaded" "$quic_buffer_loaded" "$bulk_preemptions" \
  "$drops_before" "$drops_after" \
  "$expired_before" "$expired_after" \
  | tee /state/congestion-summary.log

failures=()
check() {
  local description=$1
  shift
  if ! "$@"; then
    failures+=("$description")
  fi
}

# The regression target is class isolation, not merely eventual recovery:
# at least 90% of the unreliable overlay probes remain close to the idle
# distribution while eight ordinary TCP flows keep useful bulk throughput on
# that same peer. Two lost probes are tolerated because the test deliberately
# drives a short tail-drop underlay and QUIC DATAGRAM does not retransmit it.
# Queue expiry/drop counters below separately detect scheduler loss.
check "interactive probes received=$received expected>=18" test "$received" -ge 18
check "loaded p95 ${loaded_p95}ms exceeds idle+80ms" \
  awk -v idle="$idle_p95" -v loaded="$loaded_p95" 'BEGIN { exit !(loaded <= idle + 80) }'
check "loaded max ${loaded_max}ms exceeds idle+180ms" \
  awk -v idle="$idle_p95" -v loaded="$loaded_max" 'BEGIN { exit !(loaded <= idle + 180) }'
# Large TCP super-packets are split across unreliable QUIC datagrams, so this
# tail-drop fixture has intentionally variable TCP goodput. The assertion
# guards against starvation rather than claiming the fixture's raw 12 Mbit/s.
check "bulk throughput ${throughput}bps is below 3Mbps" test "$throughput" -gt 3000000
check "no latency-class packets observed" test "$latency_after" -gt "$latency_before"
check "no bulk-class packets observed" test "$bulk_after" -gt "$bulk_before"

# The application queue is preemptible, unlike the sender-local active packet
# and noq's FIFO. It may absorb TCP's burst during a congestion-window probe,
# but must remain within the hard budget and drain after load stops.
check "application queue peak ${queue_peak}B exceeds 8MiB" test "$queue_peak" -le 8388608
check "loaded split queue counters disagree (${priority_loaded}+${bulk_loaded} != ${queue_loaded})" \
  test "$((priority_loaded + bulk_loaded))" -eq "$queue_loaded"
check "sender-local active work ${active_tx_loaded}B exceeds one TUN super-packet" \
  test "$active_tx_loaded" -le 65535
check "non-preemptible QUIC buffer ${quic_buffer_loaded}B exceeds 8KiB" \
  test "$quic_buffer_loaded" -le 8192
check "application queue did not drain (${queue_now}B remain)" test "$queue_now" -eq 0
check "split queue counters disagree (${priority_queue_now}+${bulk_queue_now} != ${queue_now})" \
  test "$((priority_queue_now + bulk_queue_now))" -eq "$queue_now"
check "queue drops increased $drops_before->$drops_after" test "$drops_after" -eq "$drops_before"
check "expired drops increased $expired_before->$expired_after" \
  test "$expired_after" -eq "$expired_before"
check "bulk sender was never preempted by urgent traffic" test "$bulk_preemptions" -gt 0
ctl congestion-a node-a ping --count 4 --timeout-ms 2000 10.244.0.2 \
  | grep -q '4 transmitted, 4 received'

if ((${#failures[@]})); then
  printf 'congestion-isolation regression: %s\n' "${failures[@]}" >&2
  exit 1
fi

echo "bulk/interactive congestion-isolation network-namespace test passed"

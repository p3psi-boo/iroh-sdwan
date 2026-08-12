#!/usr/bin/env bash
set -euo pipefail
source /tests/netns/common.sh

PID_A=
PID_B=
PID_ECHO=
cleanup() {
  local status=$?
  stop_process "$PID_ECHO"
  stop_process "$PID_A"
  stop_process "$PID_B"
  delete_namespaces soak-a soak-b
  exit "$status"
}
trap cleanup EXIT

write_config() {
  local node=$1 address=$2 peer=$3 peer_address=$4 peer_id=$5 direct=$6
  cat >"/state/$node/config.toml" <<EOF
network_id = "netns-soak"
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
ipv4 = "$address"
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

echo "==> starting bounded flow-churn soak for ${SOAK_SECONDS:-20}s"
create_namespace soak-a
create_namespace soak-b
create_veth soak-a sa0 172.35.10.2/24 soak-b sb0 172.35.10.3/24
IDS_A=$(initialize_identity node-a netns-soak)
IDS_B=$(initialize_identity node-b netns-soak)
write_config node-a 10.243.0.1 node-b 10.243.0.2 "$IDS_B" 172.35.10.3:4000
write_config node-b 10.243.0.2 node-a 10.243.0.1 "$IDS_A" 172.35.10.2:4000
seal_node node-a
seal_node node-b
start_daemon soak-a node-a PID_A
start_daemon soak-b node-b PID_B
wait_until "soak overlay" ctl soak-a node-a ping --count 1 --timeout-ms 3000 10.243.0.2
ip netns exec soak-b python3 /tests/netns/tcp_echo.py server 10.243.0.2 5243 >/state/soak-echo.log 2>&1 &
PID_ECHO=$!
wait_until "soak echo" ip netns exec soak-a nc -z -w 2 10.243.0.2 5243

fd_before=$(find "/proc/$PID_A/fd" -mindepth 1 -maxdepth 1 | wc -l)
rss_before=$(awk '/VmRSS:/ {print $2}' "/proc/$PID_A/status")
cpu_before=$(awk '{print $14 + $15}' "/proc/$PID_A/stat")
started_at=$SECONDS
deadline=$((SECONDS + ${SOAK_SECONDS:-20}))
flows=0
while (( SECONDS < deadline )); do
  clients=()
  for _ in $(seq 1 16); do
    ip netns exec soak-a python3 /tests/netns/tcp_echo.py client 10.243.0.2 5243 4096 &
    clients+=("$!")
  done
  for pid in "${clients[@]}"; do wait "$pid"; done
  ctl soak-a node-a ping --count 1 --timeout-ms 2000 --output json 10.243.0.2 >/dev/null
  ctl soak-a node-a status --output json >/dev/null
  flows=$((flows + 16))
done
sleep 3

fd_after=$(find "/proc/$PID_A/fd" -mindepth 1 -maxdepth 1 | wc -l)
rss_after=$(awk '/VmRSS:/ {print $2}' "/proc/$PID_A/status")
cpu_after=$(awk '{print $14 + $15}' "/proc/$PID_A/stat")
elapsed=$((SECONDS - started_at))
cpu_ticks=$((cpu_after - cpu_before))
echo "soak flows=$flows elapsed_s=$elapsed cpu_ticks=$cpu_ticks fd=$fd_before->$fd_after rss_kib=$rss_before->$rss_after"
test "$flows" -ge 32
test "$cpu_ticks" -ge 0
test "$fd_after" -le "$((fd_before + 8))"
test "$rss_after" -le "$((rss_before + 262144))"
test "$(awk '$1 ~ /iroh_sdwan_peer_queue_drops_total/ {print $NF}' /state/node-a/metrics.prom)" -eq 0
test "$(awk '$1 ~ /iroh_sdwan_peer_queue_expired_drops_total/ {print $NF}' /state/node-a/metrics.prom)" -eq 0
tagged=$(awk '$1 ~ /iroh_sdwan_peer_delivery_tagged_packets_total/ {sum += $NF} END {print sum + 0}' /state/node-a/metrics.prom)
headers=$(awk '$1 ~ /iroh_sdwan_peer_delivery_header_bytes_total/ {sum += $NF} END {print sum + 0}' /state/node-a/metrics.prom)
registers=$(awk '$1 ~ /iroh_sdwan_peer_delivery_registers_sent_total/ {sum += $NF} END {print sum + 0}' /state/node-a/metrics.prom)
reports=$(awk '$1 ~ /iroh_sdwan_peer_delivery_reports_sent_total/ {sum += $NF} END {print sum + 0}' /state/node-b/metrics.prom)
control_bytes=$(awk '$1 ~ /iroh_sdwan_peer_delivery_control_bytes_total/ {sum += $NF} END {print sum + 0}' /state/node-a/metrics.prom /state/node-b/metrics.prom)
echo "delivery tagged=$tagged header_bytes=$headers registers=$registers reports=$reports control_bytes=$control_bytes"
test "$tagged" -gt 0
test "$headers" -eq "$((tagged * 12))"
test "$registers" -gt 0
test "$reports" -gt 0
test "$tagged" -gt "$reports"
test "$control_bytes" -gt 0
ctl soak-a node-a health --quiet
ctl soak-a node-a ping --count 10 --timeout-ms 2000 10.243.0.2 | grep -q '10 transmitted, 10 received'

echo "soak network-namespace integration test passed"

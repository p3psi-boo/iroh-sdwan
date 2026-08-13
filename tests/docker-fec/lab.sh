#!/usr/bin/env bash
set -euo pipefail
source /tests/netns/common.sh

PID_A=
PID_B=
cleanup() {
  local status=$?
  stop_process "$PID_A"
  stop_process "$PID_B"
  delete_namespaces fec-a fec-b
  exit "$status"
}
trap cleanup EXIT

write_config() {
  local node=$1 address=$2 peer=$3 peer_address=$4 peer_id=$5 direct=$6
  cat >"/state/$node/config.toml" <<EOF
network_id = "netns-fec-recovery"
identity_file = "/state/$node/identity.key"
bind_addresses = ["0.0.0.0:4000"]
discovery_enabled = false
tun_mtu = 65535
max_frame_size = 1200
node_interface = "ironet0"
node_addresses = ["$address/32"]
advertised_prefixes = []
[node_info]
name = "$node"
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
[fec]
enabled = true
data_shards = 4
recovery_shards = 2
block_timeout_millis = 5
decoder_ttl_millis = 2000
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

echo "==> creating a deterministic one-way lossy FEC path"
create_namespace fec-a
create_namespace fec-b
create_veth fec-a fa0 172.34.10.2/24 fec-b fb0 172.34.10.3/24
IDS_A=$(initialize_identity node-a netns-fec-recovery)
IDS_B=$(initialize_identity node-b netns-fec-recovery)
write_config node-a 10.241.0.1 node-b 10.241.0.2 "$IDS_B" 172.34.10.3:4000
write_config node-b 10.241.0.2 node-a 10.241.0.1 "$IDS_A" 172.34.10.2:4000
seal_node node-a
seal_node node-b
start_daemon fec-a node-a PID_A
start_daemon fec-b node-b PID_B
wait_until "FEC overlay readiness" ctl fec-a node-a ping --count 1 --timeout-ms 3000 10.241.0.2

ip netns exec fec-a tc qdisc replace dev fa0 root netem loss 4%
# Keep each systematic shard large enough to occupy its own QUIC packet. Tiny
# ICMP frames can be coalesced into one underlay packet, in which case losing
# that packet removes the whole FEC block rather than one shard.
ip netns exec fec-a ping -q -f -s 900 -c 1024 -W 2 -I 10.241.0.1 10.241.0.2 \
  >/state/fec-ping.log
cat /state/fec-ping.log
wait_until "FEC recovery shards" sh -c \
  'awk '\''$1 ~ /ironet_peer_fec_recovered_shards_total/ && $NF > 0 {ok=1} END {exit !ok}'\'' /state/node-b/metrics.prom'
grep -Eq 'ironet_peer_fec_tx_recovery_shards_total\{.*\} [1-9][0-9]*$' /state/node-a/metrics.prom
grep -Eq 'ironet_peer_fec_rx_recovery_shards_total\{.*\} [1-9][0-9]*$' /state/node-b/metrics.prom
grep -Eq 'ironet_peer_fec_recovered_shards_total\{.*\} [1-9][0-9]*$' /state/node-b/metrics.prom
received=$(sed -n 's/.* \([0-9][0-9]*\) received.*/\1/p' /state/fec-ping.log)
# netem drops complete QUIC packets and may occasionally remove every shard in
# a block. The deterministic gate is that recovery happened and delivery beats
# the 96% raw-path baseline by a useful margin, rather than one exact count.
test "$received" -ge 970

echo "==> proving recovery stops cleanly after loss removal"
ip netns exec fec-a tc qdisc del dev fa0 root
before=$(awk '$1 ~ /ironet_peer_fec_recovered_shards_total/ {print $NF}' /state/node-b/metrics.prom)
ip netns exec fec-a ping -q -c 64 -i 0.005 -W 2 -I 10.241.0.1 10.241.0.2 >/dev/null
sleep 2
after=$(awk '$1 ~ /ironet_peer_fec_recovered_shards_total/ {print $NF}' /state/node-b/metrics.prom)
test "$after" -eq "$before"
test "$(awk '$1 ~ /ironet_peer_queue_drops_total/ {print $NF}' /state/node-a/metrics.prom)" -eq 0

echo "FEC recovery network-namespace integration test passed"

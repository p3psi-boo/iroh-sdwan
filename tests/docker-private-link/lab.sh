#!/usr/bin/env bash
set -euo pipefail
source /tests/netns/common.sh

PID_A=
PID_B=
cleanup() {
  local status=$?
  stop_process "$PID_A"
  stop_process "$PID_B"
  delete_namespaces private-a private-b
  exit "$status"
}
trap cleanup EXIT

write_config() {
  local node=$1 address=$2 peer_name=$3 peer_id=$4 remote=$5 local_bind=$6 dial=$7 key=$8
  cat >"/state/$node/config.toml" <<EOF
network_id = "netns-v4-private-link"
identity_file = "/state/$node/identity.key"
discovery_enabled = false
max_frame_size = 1200
node_addresses = ["$address/32"]

[node_info]
name = "$node"

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
name = "$peer_name"
endpoint_id = "$peer_id"
allowed_source_prefixes = ["$([[ $node == node-a ]] && echo 10.247.0.2/32 || echo 10.247.0.1/32)"]

[[links]]
id = "iepl-ab-01"
name = "iepl-ab"
peer_id = "$peer_id"
class = "private-circuit"
visibility = "pairwise"
dial = "$dial"
exclusive = true
fallback = false
local_bind = "$local_bind"
remote_addresses = ["$remote"]
allowed_local_prefixes = ["${local_bind%:*}/32"]
allowed_remote_prefixes = ["${remote%:*}/32"]
auth_key = "$key"

[[route_origins]]
endpoint_id = "$peer_id"
prefixes = ["$([[ $node == node-a ]] && echo 10.247.0.2/32 || echo 10.247.0.1/32)"]
EOF
}

echo "==> creating a pairwise IEPL-style delivery network"
create_namespace private-a
create_namespace private-b
create_veth private-a pa-private 10.255.47.1/30 private-b pb-private 10.255.47.2/30
# A second, independently working underlay represents each node's public
# Internet path. The pairwise link contract must never advertise or use it.
create_veth private-a pa-public 198.51.100.1/24 private-b pb-public 198.51.100.2/24
ip netns exec private-a ping -c 1 -W 1 198.51.100.2 >/dev/null

ID_A=$(initialize_identity node-a netns-v4-private-link)
ID_B=$(initialize_identity node-b netns-v4-private-link)
PAIR_KEY=$(printf '47%.0s' $(seq 1 32))

write_config node-a 10.247.0.1 node-b "$ID_B" 10.255.47.2:4000 10.255.47.1:4000 active "$PAIR_KEY"
write_config node-b 10.247.0.2 node-a "$ID_A" 10.255.47.1:4000 10.255.47.2:4000 passive "$PAIR_KEY"
seal_node node-a
seal_node node-b
start_daemon private-a node-a PID_A
start_daemon private-b node-b PID_B

wait_until "pairwise v4 overlay" ctl private-a node-a ping --count 1 --timeout-ms 3000 10.247.0.2
ip netns exec private-b ping -c 3 -W 3 -I 10.247.0.2 10.247.0.1

echo "==> asserting pairwise authentication, dial role and locator secrecy"
wait_until "private link status" jq -e \
  '(.peers | length == 1) and all(.peers[]; .connected and .protocol_major == 4 and .private_link and .selected_path_transport == "direct")' \
  /state/node-a/status.json
jq -e '.peers[0].selected_path_remote | contains("10.255.47.2")' /state/node-a/status.json >/dev/null
test "$(grep -c 'peer connection active' /state/node-b/daemon.log)" -ge 1
ip netns exec private-a ss -uln | grep -Eq '10\.255\.47\.1:4000'
if ip netns exec private-a ss -uln | grep -Eq '198\.51\.100\.1:4000'; then
  echo "private-link endpoint also bound the public address" >&2
  exit 1
fi
if grep -R -E '198\.51\.100\.[12]|10\.255\.47\.[12]' \
  /state/node-a/status.json /state/node-b/status.json | grep -E 'mesh|direct_addresses|assisted_addresses'; then
  echo "pairwise locator leaked into mesh status" >&2
  exit 1
fi
if grep -R -qE '198\.51\.100\.[12]' /state/node-a/status.json /state/node-b/status.json; then
  echo "public locator appeared in private-link runtime status" >&2
  exit 1
fi

echo "==> proving no migration or public fallback"
ip netns exec private-a tc qdisc replace dev pa-private root netem loss 100%
if ctl private-a node-a ping --count 2 --timeout-ms 250 10.247.0.2 >/dev/null 2>&1; then
  echo "private link unexpectedly escaped its exclusive locator" >&2
  exit 1
fi
# The independent public path is still healthy while the exclusive delivery
# circuit is down, so a successful overlay ping above would be a real escape.
ip netns exec private-a ping -c 1 -W 1 198.51.100.2 >/dev/null
if grep -q 'selected_path_remote.*198.51.100.2' /state/node-a/status.json; then
  echo "private link selected the public-looking address" >&2
  exit 1
fi
ip netns exec private-a tc qdisc del dev pa-private root
wait_until "private link recovery" ctl private-a node-a ping --count 1 --timeout-ms 3000 10.247.0.2

echo "==> proving pairwise secret mismatch fails the v4 session"
stop_process "$PID_B"
PID_B=
sed -i "s/auth_key = \"$PAIR_KEY\"/auth_key = \"$(printf '48%.0s' $(seq 1 32))\"/" /state/node-b/config.toml
seal_node node-b
start_daemon private-b node-b PID_B
sleep 3
if ctl private-a node-a ping --count 2 --timeout-ms 300 10.247.0.2 >/dev/null 2>&1; then
  echo "private link authenticated with the wrong pairwise key" >&2
  exit 1
fi
grep -Eq 'pairwise link|session negotiation' /state/node-a/daemon.log /state/node-b/daemon.log

echo "pairwise private-link network-namespace test passed"

#!/usr/bin/env bash
set -euo pipefail
source /tests/netns/common.sh

PID_A=
PID_C=
cleanup() {
  local status=$?
  stop_process "$PID_A"
  stop_process "$PID_C"
  delete_namespaces lan-host-a lan-node-a lan-node-c lan-host-c
  exit "$status"
}
trap cleanup EXIT

write_config() {
  local node=$1 overlay4=$2 overlay6=$3 lan4=$4 lan6=$5
  local peer=$6 peer_id=$7 peer_overlay4=$8 peer_overlay6=$9
  shift 9
  local peer_lan4=$1 peer_lan6=$2 direct=$3
  cat >"/state/$node/config.toml" <<EOF
network_id = "netns-routed-lan"
identity_file = "/state/$node/identity.key"
bind_addresses = ["0.0.0.0:4000"]
discovery_enabled = false
tun_mtu = 65535
max_frame_size = 1200
node_interface = "ironet0"
node_addresses = ["$overlay4/32", "$overlay6/128"]
advertised_prefixes = ["$lan4", "$lan6"]

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

[observability]
status_file = "/state/$node/status.json"
metrics_file = "/state/$node/metrics.prom"
report_interval_secs = 1

[[peers]]
name = "$peer"
endpoint_id = "$peer_id"
direct_addresses = ["$direct"]
allowed_source_prefixes = ["$peer_overlay4/32", "$peer_overlay6/128", "$peer_lan4", "$peer_lan6"]

[[route_origins]]
endpoint_id = "$peer_id"
prefixes = ["$peer_overlay4/32", "$peer_overlay6/128", "$peer_lan4", "$peer_lan6"]
EOF
}

echo "==> creating two routed dual-stack LANs"
for namespace in lan-host-a lan-node-a lan-node-c lan-host-c; do create_namespace "$namespace"; done
create_veth lan-host-a ha0 192.168.10.10/24 lan-node-a la0 192.168.10.1/24
create_veth lan-node-a ac-a 172.33.10.2/24 lan-node-c ac-c 172.33.10.3/24
create_veth lan-node-c lc0 192.168.20.1/24 lan-host-c hc0 192.168.20.10/24
ip -n lan-host-a -6 address add fd20:10::10/64 dev ha0
ip -n lan-node-a -6 address add fd20:10::1/64 dev la0
ip -n lan-node-c -6 address add fd20:20::1/64 dev lc0
ip -n lan-host-c -6 address add fd20:20::10/64 dev hc0
ip -n lan-host-a route add default via 192.168.10.1
ip -n lan-host-c route add default via 192.168.20.1
ip -n lan-host-a -6 route add default via fd20:10::1
ip -n lan-host-c -6 route add default via fd20:20::1
for namespace in lan-node-a lan-node-c; do
  ip netns exec "$namespace" sysctl -qw net.ipv4.ip_forward=1
  ip netns exec "$namespace" sysctl -qw net.ipv6.conf.all.forwarding=1
  ip netns exec "$namespace" sysctl -qw net.ipv4.conf.all.rp_filter=0
done

declare -A IDS
IDS[node-a]=$(initialize_identity node-a netns-routed-lan)
IDS[node-c]=$(initialize_identity node-c netns-routed-lan)
write_config node-a 10.240.0.1 fd73:9db8:4240::1 192.168.10.0/24 fd20:10::/64 \
  node-c "${IDS[node-c]}" 10.240.0.2 fd73:9db8:4240::2 192.168.20.0/24 fd20:20::/64 172.33.10.3:4000
write_config node-c 10.240.0.2 fd73:9db8:4240::2 192.168.20.0/24 fd20:20::/64 \
  node-a "${IDS[node-a]}" 10.240.0.1 fd73:9db8:4240::1 192.168.10.0/24 fd20:10::/64 172.33.10.2:4000
seal_node node-a
seal_node node-c
start_daemon lan-node-a node-a PID_A
start_daemon lan-node-c node-c PID_C

wait_until "IPv4 routed LAN" ip netns exec lan-host-a ping -c 1 -W 3 192.168.20.10
wait_until "IPv6 routed LAN" ip netns exec lan-host-a ping -6 -c 1 -W 3 fd20:20::10
ip netns exec lan-host-c ping -c 3 -W 3 192.168.10.10
ip netns exec lan-host-c ping -6 -c 3 -W 3 fd20:10::10
ip netns exec lan-host-a ping -c 2 -W 3 -M dont -s 4000 192.168.20.10
ip netns exec lan-node-c iptables -t nat -L IRONET_NAT_POSTROUTING -n -v -x \
  | awk '$3 == "MASQUERADE" && $1 > 0 { found=1 } END { exit !found }'
ip netns exec lan-node-c ip6tables -t nat -L IRONET_NAT_POSTROUTING -n -v -x \
  | awk '$3 == "MASQUERADE" && $1 > 0 { found=1 } END { exit !found }'
ip -n lan-node-a route show table 100 192.168.20.0/24 | grep -q 'dev ironet0'
ip -n lan-node-c -6 route show table 100 fd20:10::/64 | grep -q 'dev ironet0'

echo "==> proving prefix policy and default-route guardrails"
ip -n lan-host-a route add 198.18.0.0/24 via 192.168.10.1
if ip netns exec lan-host-a ping -c 1 -W 1 198.18.0.1 >/dev/null 2>&1; then
  echo "unadvertised routed prefix unexpectedly crossed the overlay" >&2
  exit 1
fi
cp /state/node-a/config.toml /state/node-a/default-invalid.toml
sed -i 's#advertised_prefixes = \["192.168.10.0/24", "fd20:10::/64"\]#advertised_prefixes = ["0.0.0.0/0"]#' /state/node-a/default-invalid.toml
if ironet seal-config --config /state/node-a/default-invalid.toml >/state/default-route.log 2>&1; then
  echo "default route was accepted without allow_default_routes" >&2
  exit 1
fi
grep -q 'allow_default_routes' /state/default-route.log
test "$(awk '$1 ~ /ironet_peer_policy_drops_total/ {sum += $NF} END {print sum+0}' /state/node-a/metrics.prom)" -eq 0

echo "routed LAN network-namespace integration test passed"

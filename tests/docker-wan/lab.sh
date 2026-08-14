#!/usr/bin/env bash
set -euo pipefail

STATE_DIR=/state
PID_A=
PID_B=

cleanup() {
  local status=$?
  if [[ -n $PID_A ]]; then kill "$PID_A" >/dev/null 2>&1 || true; fi
  if [[ -n $PID_B ]]; then kill "$PID_B" >/dev/null 2>&1 || true; fi
  ip netns del ns-a >/dev/null 2>&1 || true
  ip netns del ns-nat >/dev/null 2>&1 || true
  ip netns del ns-b >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

wait_until() {
  local description=$1
  shift
  for _ in $(seq 1 90); do
    if "$@" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "timed out waiting for $description" >&2
  return 1
}

endpoint_id() {
  sed -n 's/^[[:space:]]*"endpoint_id": "\([^"]*\)",*$/\1/p' <<<"$1"
}

ctl_a() {
  ip netns exec ns-a ironet --socket "$STATE_DIR/node-a/control.sock" "$@"
}

ctl_b() {
  ip netns exec ns-b ironet --socket "$STATE_DIR/node-b/control.sock" "$@"
}

write_config() {
  local node=$1
  local overlay=$2
  local peer_name=$3
  local peer_overlay=$4
  local peer_id=$5
  local nat_address=$6
  cat >"$STATE_DIR/$node/config.toml" <<EOF
network_id = "docker-nat-wan"
identity_file = "$STATE_DIR/$node/identity.key"
bind_addresses = ["0.0.0.0:4000"]
discovery_enabled = false
tun_mtu = 65535
max_frame_size = 1400
node_interface = "ironet0"
node_addresses = ["$overlay/32"]
advertised_prefixes = []

[node_info]
name = "$node"
description = "NAT and impaired WAN fixture"

[node_info.metadata]
topology = "netns-dual-lan-nat"

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
status_file = "$STATE_DIR/$node/status.json"
metrics_file = "$STATE_DIR/$node/metrics.prom"
report_interval_secs = 1

[[peers]]
name = "$peer_name"
endpoint_id = "$peer_id"
direct_addresses = ["$nat_address"]
allowed_source_prefixes = ["$peer_overlay/32"]

[[route_origins]]
endpoint_id = "$peer_id"
prefixes = ["$peer_overlay/32"]
EOF
}

echo "==> creating ns-a <-> ns-nat <-> ns-b"
rm -rf "$STATE_DIR/node-a" "$STATE_DIR/node-b"
mkdir -p "$STATE_DIR/node-a" "$STATE_DIR/node-b"
for namespace in ns-a ns-nat ns-b; do
  ip netns del "$namespace" >/dev/null 2>&1 || true
  ip netns add "$namespace"
  ip -n "$namespace" link set lo up
done

ip link add a-wan type veth peer name nat-a
ip link set a-wan netns ns-a
ip link set nat-a netns ns-nat
ip link add b-wan type veth peer name nat-b
ip link set b-wan netns ns-b
ip link set nat-b netns ns-nat

ip -n ns-a address add 172.28.10.2/24 dev a-wan
ip -n ns-a link set a-wan up
ip -n ns-nat address add 172.28.10.254/24 dev nat-a
ip -n ns-nat link set nat-a up
ip -n ns-b address add 172.28.20.2/24 dev b-wan
ip -n ns-b link set b-wan up
ip -n ns-nat address add 172.28.20.254/24 dev nat-b
ip -n ns-nat link set nat-b up

ip netns exec ns-nat sysctl -qw net.ipv4.ip_forward=1
ip netns exec ns-nat iptables -P FORWARD ACCEPT
ip netns exec ns-nat iptables -t nat -A PREROUTING \
  -d 172.28.10.254 -p udp --dport 41002 \
  -j DNAT --to-destination 172.28.20.2:4000
ip netns exec ns-nat iptables -t nat -A POSTROUTING \
  -p udp -d 172.28.20.2 --dport 4000 \
  -j SNAT --to-source 172.28.20.254
ip netns exec ns-nat iptables -t nat -A PREROUTING \
  -d 172.28.20.254 -p udp --dport 41001 \
  -j DNAT --to-destination 172.28.10.2:4000
ip netns exec ns-nat iptables -t nat -A POSTROUTING \
  -p udp -d 172.28.10.2 --dport 4000 \
  -j SNAT --to-source 172.28.10.254

echo "==> creating identities and sealed configurations"
declare -A IDS
for node in node-a node-b; do
  output=$(ironet network create docker-nat-wan \
    --config "$STATE_DIR/$node/config.toml" \
    --state-dir "$STATE_DIR/$node" \
    --node-name "$node" \
    --no-start \
    --output json)
  IDS[$node]=$(endpoint_id "$output")
  test -n "${IDS[$node]}"
  rm -f "$STATE_DIR/$node/network.toml" "$STATE_DIR/$node/network-authority.key"
done
write_config node-a 10.220.0.1 node-b 10.220.0.2 \
  "${IDS[node-b]}" 172.28.10.254:41002
write_config node-b 10.220.0.2 node-a 10.220.0.1 \
  "${IDS[node-a]}" 172.28.20.254:41001
ironet seal-config --config "$STATE_DIR/node-a/config.toml"
ironet seal-config --config "$STATE_DIR/node-b/config.toml"

echo "==> starting both daemons inside their network namespaces"
ip netns exec ns-a ironetd \
  --config "$STATE_DIR/node-a/config.toml" \
  --socket "$STATE_DIR/node-a/control.sock" \
  >"$STATE_DIR/node-a/daemon.log" 2>&1 &
PID_A=$!
ip netns exec ns-b ironetd \
  --config "$STATE_DIR/node-b/config.toml" \
  --socket "$STATE_DIR/node-b/control.sock" \
  >"$STATE_DIR/node-b/daemon.log" 2>&1 &
PID_B=$!

wait_until "node-a NAT overlay path" ctl_a ping \
  --count 1 --timeout-ms 3000 10.220.0.2
wait_until "node-b NAT overlay path" ctl_b ping \
  --count 1 --timeout-ms 3000 10.220.0.1

echo "==> proving DNAT/SNAT rather than direct LAN reachability"
if ip netns exec ns-a ping -c 1 -W 1 172.28.20.2 >/dev/null 2>&1; then
  echo "ns-a unexpectedly reached ns-b without NAT" >&2
  exit 1
fi
ip netns exec ns-nat iptables -t nat -L PREROUTING -n -v \
  | grep -Eq '[1-9][0-9]*.*udp.*dpt:4100[12]'
grep -q '"selected_path_transport": "direct"' "$STATE_DIR/node-a/status.json"

echo "==> expiring conntrack state and rotating the public UDP mapping"
ip netns exec ns-nat conntrack -F >/dev/null
wait_until "path after conntrack expiry" ctl_a ping --count 1 --timeout-ms 3000 10.220.0.2
ip netns exec ns-nat iptables -t nat -D PREROUTING \
  -d 172.28.10.254 -p udp --dport 41002 \
  -j DNAT --to-destination 172.28.20.2:4000
ip netns exec ns-nat iptables -t nat -A PREROUTING \
  -d 172.28.10.254 -p udp --dport 42002 \
  -j DNAT --to-destination 172.28.20.2:4000
sed -i 's/172.28.10.254:41002/172.28.10.254:42002/' "$STATE_DIR/node-a/config.toml"
ironet seal-config --config "$STATE_DIR/node-a/config.toml" >/dev/null
ctl_a reload >/dev/null
ip netns exec ns-nat conntrack -F >/dev/null
wait_until "overlay after NAT mapping rotation" ctl_a ping --count 1 --timeout-ms 3000 10.220.0.2
grep -q '172.28.10.254:42002' "$STATE_DIR/node-a/config.toml"

echo "==> injecting high RTT, jitter, loss, and reordering"
for interface in nat-a nat-b; do
  ip netns exec ns-nat tc qdisc replace dev "$interface" root netem \
    delay 60ms 15ms 25% loss 5% reorder 20% 50%
done
ip netns exec ns-nat tc qdisc show | grep -q netem
wan_ping=$(ctl_a ping --count 20 --timeout-ms 3000 --output json 10.220.0.2)
echo "$wan_ping"
wan_received=$(sed -n 's/^[[:space:]]*"received": \([0-9][0-9]*\),/\1/p' <<<"$wan_ping")
wan_avg=$(sed -n 's/^[[:space:]]*"avg_ms": \([0-9][0-9]*\)\..*/\1/p' <<<"$wan_ping")
test "$wan_received" -gt 0
test "$wan_avg" -ge 60
for interface in nat-a nat-b; do
  ip netns exec ns-nat tc qdisc del dev "$interface" root
done

echo "==> forcing a UDP MTU black hole"
ip netns exec ns-nat iptables -I FORWARD 1 \
  -p udp -m length --length 1281:65535 -j DROP
wait_until "large packet after MTU black-hole adaptation" \
  ip netns exec ns-a ping -c 1 -W 3 -M do -s 1200 \
  -I 10.220.0.1 10.220.0.2
wait_until "safe effective frame size" sh -c \
  'awk '\''/ironet_peer_effective_frame_size_bytes/ { ok = ($NF <= 1200) } END { exit !ok }'\'' "$1"' \
  sh "$STATE_DIR/node-a/metrics.prom"
ip netns exec ns-nat iptables -D FORWARD \
  -p udp -m length --length 1281:65535 -j DROP

echo "==> repeated max-count probes release descriptors"
fd_before=$(find "/proc/$PID_A/fd" -mindepth 1 -maxdepth 1 | wc -l)
ping_pids=()
for index in $(seq 1 4); do
  ctl_a ping --count 20 --timeout-ms 3000 10.220.0.2 \
    >"$STATE_DIR/final-ping-$index.log" &
  ping_pids+=("$!")
done
for pid in "${ping_pids[@]}"; do
  wait "$pid"
done
sleep 1
fd_after=$(find "/proc/$PID_A/fd" -mindepth 1 -maxdepth 1 | wc -l)
test "$fd_after" -le "$((fd_before + 2))"
grep -q '20 transmitted, 20 received' "$STATE_DIR/final-ping-1.log"

echo "network-namespace NAT/WAN integration test passed"

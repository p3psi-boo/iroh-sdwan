#!/usr/bin/env bash

wait_until() {
  local description=$1
  shift
  for _ in $(seq 1 "${WAIT_ATTEMPTS:-90}"); do
    if "$@" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "timed out waiting for $description" >&2
  return 1
}

endpoint_id() {
  sed -n 's/^endpoint_id = //p' <<<"$1"
}

create_namespace() {
  local namespace=$1
  ip netns del "$namespace" >/dev/null 2>&1 || true
  ip netns add "$namespace"
  ip -n "$namespace" link set lo up
}

create_veth() {
  local namespace_a=$1
  local interface_a=$2
  local address_a=$3
  local namespace_b=$4
  local interface_b=$5
  local address_b=$6
  ip link add "$interface_a" type veth peer name "$interface_b"
  ip link set "$interface_a" netns "$namespace_a"
  ip link set "$interface_b" netns "$namespace_b"
  ip -n "$namespace_a" address add "$address_a" dev "$interface_a"
  ip -n "$namespace_b" address add "$address_b" dev "$interface_b"
  ip -n "$namespace_a" link set "$interface_a" up
  ip -n "$namespace_b" link set "$interface_b" up
}

initialize_identity() {
  local node=$1
  local network_id=$2
  shift 2
  mkdir -p "/state/$node"
  local output
  output=$(ironet init \
    --config "/state/$node/config.toml" \
    --state-dir "/state/$node" \
    --network-id "$network_id" \
    "$@")
  endpoint_id "$output"
}

seal_node() {
  local node=$1
  ironet seal-config --config "/state/$node/config.toml" >/dev/null
}

start_daemon() {
  local namespace=$1
  local node=$2
  local variable=$3
  ip netns exec "$namespace" ironetd \
    --config "/state/$node/config.toml" \
    --socket "/state/$node/control.sock" \
    >"/state/$node/daemon.log" 2>&1 &
  printf -v "$variable" '%s' "$!"
}

ctl() {
  local namespace=$1
  local node=$2
  shift 2
  ip netns exec "$namespace" ironet \
    --socket "/state/$node/control.sock" "$@"
}

stop_process() {
  local pid=${1:-}
  if [[ -n $pid ]]; then
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
  fi
}

delete_namespaces() {
  local namespace
  for namespace in "$@"; do
    ip netns del "$namespace" >/dev/null 2>&1 || true
  done
}

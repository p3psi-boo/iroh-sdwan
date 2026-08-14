#!/usr/bin/env bash
set -euo pipefail
source /tests/netns/common.sh

PID_A=
PID_B=
cleanup() {
  local status=$?
  stop_process "$PID_A"
  stop_process "$PID_B"
  delete_namespaces product-a product-b
  exit "$status"
}
trap cleanup EXIT

product_cli() {
  local namespace=$1 node=$2
  shift 2
  ip netns exec "$namespace" ironet \
    --config "/state/$node/config.toml" \
    --socket "/state/$node/control.sock" \
    --state-dir "/state/$node" \
    "$@"
}

ping_fails() {
  ! ip netns exec product-b ping -c 1 -W 1 -I "$ADDRESS_B" "$ADDRESS_A" >/dev/null 2>&1
}

echo "==> creating a two-machine underlay"
create_namespace product-a
create_namespace product-b
create_veth product-a product-a0 172.31.50.1/24 product-b product-b0 172.31.50.2/24
mkdir -p /state/node-a /state/node-b

echo "==> creating a network through the product CLI"
CREATE_JSON=$(product_cli product-a node-a network create production-demo \
  --node-name edge-a \
  --address-pool 198.23.0.0/16 \
  --listen 0.0.0.0:4000 \
  --no-start \
  --output json)
jq -e '
  .service_started == false and
  .network.created == true and
  .network.network == "production-demo" and
  .network.node == "edge-a" and
  (.network.endpoint_id | length > 0) and
  (.network.address | endswith("/32"))
' <<<"$CREATE_JSON" >/dev/null
NETWORK_ID=$(jq -r '.network.network_id' <<<"$CREATE_JSON")
ADDRESS_A=$(jq -r '.network.address | split("/")[0]' <<<"$CREATE_JSON")

echo "==> issuing and consuming a signed invite"
INVITE_JSON=$(product_cli product-a node-a invite create \
  --address 172.31.50.1:4000 \
  --expires 10m \
  --output json)
INVITE_ID=$(jq -r '.id' <<<"$INVITE_JSON")
INVITE_TOKEN=$(jq -r '.token' <<<"$INVITE_JSON")
test -n "$INVITE_ID"
[[ $INVITE_TOKEN == ironet://join/v1/* ]]

JOIN_JSON=$(product_cli product-b node-b join "$INVITE_TOKEN" \
  --node-name edge-b \
  --no-start \
  --output json)
jq -e --arg network_id "$NETWORK_ID" '
  .service_started == false and
  .network.created == false and
  .network.network == "production-demo" and
  .network.network_id == $network_id and
  .network.node == "edge-b" and
  (.network.address | endswith("/32"))
' <<<"$JOIN_JSON" >/dev/null
ADDRESS_B=$(jq -r '.network.address | split("/")[0]' <<<"$JOIN_JSON")
test "$ADDRESS_A" != "$ADDRESS_B"

echo "==> starting both daemons from generated state"
start_daemon product-a node-a PID_A
start_daemon product-b node-b PID_B
wait_until "creator readiness" ctl product-a node-a health
wait_until "joiner readiness" ctl product-b node-b health
wait_until "product overlay connectivity" \
  ip netns exec product-b ping -c 1 -W 3 -I "$ADDRESS_B" "$ADDRESS_A"
ip netns exec product-a ping -c 3 -W 3 -I "$ADDRESS_A" "$ADDRESS_B"

echo "==> verifying that product vocabulary exposes the live network"
product_cli product-a node-a network show --output json \
  | tee /state/node-a/network-show.json \
  | jq -e --arg network_id "$NETWORK_ID" '.network.network_id == $network_id' >/dev/null
product_cli product-a node-a node list --output json \
  | tee /state/node-a/node-list.json \
  | jq -e '
      length == 2 and
      any(.[]; .name == "edge-a" and .local == true) and
      any(.[]; .name == "edge-b" and .local == false and .removed == false)
    ' >/dev/null
product_cli product-b node-b node list --output json \
  | tee /state/node-b/node-list.json \
  | jq -e '
      length == 2 and
      any(.[]; .name == "edge-b" and .local == true) and
      any(.[]; .name == "edge-a" and .local == false and .removed == false)
    ' >/dev/null

echo "==> revoking the joining credential and proving reconnect is denied"
product_cli product-a node-a invite revoke "$INVITE_ID" --output json \
  | jq -e '.changed == true and .applied == true' >/dev/null
product_cli product-a node-a invite list --output json \
  | jq -e --arg id "$INVITE_ID" 'any(.[]; .id == $id and .revoked == true)' >/dev/null

stop_process "$PID_B"
PID_B=
wait_until "joiner disconnect" ping_fails
start_daemon product-b node-b PID_B
sleep 3
ping_fails

echo "product create/invite/join network-namespace test passed"

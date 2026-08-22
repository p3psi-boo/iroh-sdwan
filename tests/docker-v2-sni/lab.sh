#!/usr/bin/env bash
set -euo pipefail

OUT=/out
CLI=/bin/ironet
DAEMON=/bin/ironetd
NSA=v2-sni-a
NSB=v2-sni-b
PA=
PB=
CAP=

cleanup() {
  set +e
  [[ -n ${PA:-} ]] && kill -INT "$PA" 2>/dev/null
  [[ -n ${PB:-} ]] && kill -INT "$PB" 2>/dev/null
  [[ -n ${CAP:-} ]] && kill -INT "$CAP" 2>/dev/null
  wait "$PA" 2>/dev/null || true
  wait "$PB" 2>/dev/null || true
  wait "$CAP" 2>/dev/null || true
  ip netns del "$NSA" 2>/dev/null
  ip netns del "$NSB" 2>/dev/null
  rm -rf /state
}
trap cleanup EXIT

product() {
  local namespace=$1 node=$2
  shift 2
  ip netns exec "$namespace" "$CLI" \
    --config "/state/$node/config.toml" \
    --socket "/state/$node/control.sock" \
    --state-dir "/state/$node" "$@"
}

seal() {
  local namespace=$1 node=$2
  product "$namespace" "$node" seal-config >/dev/null
}

set_cover() {
  local namespace=$1 node=$2
  cat >>"/state/$node/config.toml" <<'TOML'

[cover]
sni_pool = ["cdn.live.example"]
profile_id = 7
TOML
  seal "$namespace" "$node"
}

stop_pair() {
  set +e
  [[ -n ${PA:-} ]] && kill -INT "$PA" 2>/dev/null
  [[ -n ${PB:-} ]] && kill -INT "$PB" 2>/dev/null
  [[ -n ${PA:-} ]] && wait "$PA" 2>/dev/null
  [[ -n ${PB:-} ]] && wait "$PB" 2>/dev/null
  PA=
  PB=
  set -e
}

rm -rf "$OUT"/* /state
mkdir -p /state/a /state/b /state/c
ip netns add "$NSA"
ip netns add "$NSB"
ip link add v2-sni-a type veth peer name v2-sni-b
ip link set v2-sni-a netns "$NSA"
ip link set v2-sni-b netns "$NSB"
ip -n "$NSA" addr add 10.160.0.1/24 dev v2-sni-a
ip -n "$NSB" addr add 10.160.0.2/24 dev v2-sni-b
ip -n "$NSA" link set lo up
ip -n "$NSB" link set lo up
ip -n "$NSA" link set v2-sni-a up
ip -n "$NSB" link set v2-sni-b up

# Generate the exact sealed product configuration consumed by ironetd.
product "$NSB" b network create sni-production \
  --node-name server --address-pool 198.27.0.0/16 \
  --ipv6-address-pool fd42:6972:6f70::/64 \
  --listen 10.160.0.2:45000 --no-dns --no-start --output json \
  >"$OUT/server-network.json"
product "$NSB" b invite create --address 10.160.0.2:45000 --output json \
  >"$OUT/invite.json"
TOKEN=$(jq -r .token "$OUT/invite.json")
product "$NSA" a join "$TOKEN" --node-name client --no-start --output json \
  >"$OUT/client-network.json"
product "$NSA" c network create identity-c \
  --node-name wrong-peer --address-pool 198.28.0.0/16 \
  --ipv6-address-pool fd42:6972:6f71::/64 \
  --listen 10.160.0.1:45001 --no-dns --no-start --output json \
  >"$OUT/wrong-network.json"
BID=$(jq -r '.network.endpoint_id' "$OUT/server-network.json")
CID=$(jq -r '.network.endpoint_id' "$OUT/wrong-network.json")
set_cover "$NSA" a
set_cover "$NSB" b

grep -Fq "endpoint_id = \"$BID\"" /state/a/config.toml
grep -Fq 'sni_pool = ["cdn.live.example"]' /state/a/config.toml

# Capture all interfaces in A's namespace. Iroh may migrate the same logical
# QUIC connection between its configured IP sockets; binding the verifier to
# one veth can miss a legitimate Initial while the endpoint is still healthy.
ip netns exec "$NSA" tcpdump -U -i any -s 0 \
  -w "$OUT/initial.pcap" 'udp port 45000' >"$OUT/tcpdump.log" 2>&1 &
CAP=$!
for _ in $(seq 1 50); do
  grep -q 'listening on' "$OUT/tcpdump.log" 2>/dev/null && break
  sleep 0.1
done
grep -q 'listening on' "$OUT/tcpdump.log"
ip netns exec "$NSB" env RUST_LOG=info "$DAEMON" \
  --config /state/b/config.toml --socket /state/b/control.sock \
  >"$OUT/b.log" 2>&1 &
PB=$!
ip netns exec "$NSA" env RUST_LOG=info "$DAEMON" \
  --config /state/a/config.toml --socket /state/a/control.sock \
  >"$OUT/a.log" 2>&1 &
PA=$!
for _ in $(seq 1 150); do
  grep -q 'V2 authenticated mesh adjacencies active' "$OUT/a.log" 2>/dev/null \
    && grep -q 'V2 authenticated mesh adjacencies active' "$OUT/b.log" 2>/dev/null \
    && break
  sleep 0.1
done
grep -q 'V2 authenticated mesh adjacencies active' "$OUT/a.log"
grep -q 'V2 authenticated mesh adjacencies active' "$OUT/b.log"
product "$NSA" a status --output json >"$OUT/a-status.json"
jq -e '.ready == true and .peers[0].protocol_major == 2 and .peers[0].connected == true' \
  "$OUT/a-status.json" >/dev/null
stop_pair
kill -INT "$CAP" 2>/dev/null || true
wait "$CAP" 2>/dev/null || true
CAP=

# Keep the same visible SNI and socket address, but make the client expect C's
# EndpointId while the server still presents B's raw public key.
sed -i "s/endpoint_id = \"$BID\"/endpoint_id = \"$CID\"/" /state/a/config.toml
seal "$NSA" a
ip netns exec "$NSA" tcpdump -U -i any -s 0 \
  -w "$OUT/wrong-peer.pcap" 'udp port 45000' >"$OUT/tcpdump-wrong.log" 2>&1 &
CAP=$!
for _ in $(seq 1 50); do
  grep -q 'listening on' "$OUT/tcpdump-wrong.log" 2>/dev/null && break
  sleep 0.1
done
grep -q 'listening on' "$OUT/tcpdump-wrong.log"
ip netns exec "$NSB" env RUST_LOG=info "$DAEMON" \
  --config /state/b/config.toml --socket /state/b/control.sock \
  >"$OUT/b-wrong.log" 2>&1 &
PB=$!
set +e
timeout -s INT 5 ip netns exec "$NSA" env RUST_LOG=info "$DAEMON" \
  --config /state/a/config.toml --socket /state/a/control.sock \
  >"$OUT/a-wrong.log" 2>&1
WRONG_RC=$?
set -e
[[ $WRONG_RC -ne 0 ]]
stop_pair
kill -INT "$CAP" 2>/dev/null || true
wait "$CAP" 2>/dev/null || true
CAP=

for capture in initial wrong-peer; do
  tshark -r "$OUT/$capture.pcap" -d udp.port==45000,quic \
    -Y 'tls.handshake.extensions_server_name' -T fields \
    -e frame.number -e ip.src -e tls.handshake.extensions_server_name \
    -e tls.handshake.extensions_alpn_str -e udp.length -e quic.version \
    -e quic.dcid -e quic.scid >"$OUT/$capture-client-hello.tsv"
  # Each half of the matrix must independently contain a real ClientHello.
  # The previous aggregate-only assertion could pass using retries from the
  # negative case even when the legitimate-session pcap was empty.
  awk -F '\t' '
    $3 == "cdn.live.example" && $4 == "h3" && $5 + 0 >= 1208 &&
    $6 == "0x00000001" && length($7) == 40 && length($8) == 16 { found = 1 }
    END { exit !found }
  ' "$OUT/$capture-client-hello.tsv"
  tshark -r "$OUT/$capture.pcap" -d udp.port==45000,quic \
    -Y 'quic.long.packet_type == 0' -T fields \
    -e frame.number -e quic.version -e udp.length \
    >"$OUT/$capture-quic-initials.tsv"
done
cat "$OUT/initial-client-hello.tsv" "$OUT/wrong-peer-client-hello.tsv" \
  >"$OUT/client-hellos.tsv"
cat "$OUT/initial-quic-initials.tsv" "$OUT/wrong-peer-quic-initials.tsv" \
  >"$OUT/quic-initials.tsv"

! grep -Eq '\.iroh\.invalid|ironet/ip/1|ironet/probe' "$OUT/client-hellos.tsv"
! grep -q 'V2 authenticated mesh adjacencies active' "$OUT/a-wrong.log"
grep -Eq 'UnknownIssuer|unknown issuer|certificate|identity' "$OUT/a-wrong.log"

printf 'production_daemon=ok\nlegitimate_session=ok\nwrong_peer_rejected=ok\nwrong_rc=%s\n' \
  "$WRONG_RC" >"$OUT/verification.txt"
cat "$OUT/verification.txt"
cat "$OUT/client-hellos.tsv"

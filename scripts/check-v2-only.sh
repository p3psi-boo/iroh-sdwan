#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"

removed=(
  src/runtime.rs src/runtime src/wire.rs src/transport.rs src/delivery.rs
  src/fec.rs src/capacity.rs src/capacity_probe.rs src/flow_router.rs
  src/link_metrics.rs src/path_selection.rs src/mesh.rs src/observability.rs
  src/protocol/envelope.rs src/protocol/feature.rs src/protocol/node_record.rs
  src/protocol/routing.rs src/protocol/session.rs docs/protocol-v1.md tests/docker-v1
)
for path in "${removed[@]}"; do
  if [[ -e $path ]]; then
    echo "removed protocol surface exists: $path" >&2
    exit 1
  fi
done

if rg -n '(ironet/ip/1|IRN1|ironet-v1)' src --glob '*.rs'; then
  echo 'old application-protocol marker remains in compiled source' >&2
  exit 1
fi

if rg -n '(tls::name|name::encode|iroh\.invalid)' crates/iroh-v2/src --glob '*.rs'; then
  echo 'EndpointId-derived or legacy iroh SNI remains in the V2 QUIC client' >&2
  exit 1
fi

if rg -n 'pub mod (runtime|wire|transport|delivery|fec|mesh|observability);' src/lib.rs; then
  echo 'old application-protocol module remains exported' >&2
  exit 1
fi

if rg -n '(delivery_tagged_packets|tx_fragments|fec_tx_recovery_shards|capacity_probe_)' \
  src/status.rs src/main.rs src/tui.rs src/control.rs; then
  echo 'old V1-shaped status field remains in the production control surface' >&2
  exit 1
fi

if rg -n '^(discovery_enabled|attachment|max_frame_size|udp_segmentation_offload|quic_|forbidden_underlay_prefixes)|^\[(fec|packet_policy|path_selection|observability)\]' config/example.toml; then
  echo 'removed configuration surface remains in the V2 example' >&2
  exit 1
fi

if rg -n '^metrics_file[[:space:]]*=' config/example.toml; then
  echo 'removed V1 metrics file remains in the V2 example' >&2
  exit 1
fi

if ! grep -Fxq 'pub mod v2;' src/protocol/mod.rs; then
  echo 'V2 protocol module is not the sole protocol export' >&2
  exit 1
fi

if [[ $(find src/bin -maxdepth 1 -type f -printf '%f\n' | sort) != ironetd.rs ]]; then
  echo 'production source contains a second daemon entry point' >&2
  exit 1
fi

echo 'V2-only source/configuration gate passed'

#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

for suite in docker docker-v4 docker-private-link docker-lan docker-flowrouter docker-fec docker-mesh docker-relay docker-derp docker-wan docker-mtu docker-congestion docker-soak; do
  echo "==> running network-namespace suite: $suite"
  "$ROOT/tests/netns/run.sh" "$suite"
done

echo "all network-namespace integration suites passed"

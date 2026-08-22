#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

"$ROOT/scripts/check-v2-only.sh"

# Protocol V2 has no inherited protocol-generation suites. Product lifecycle
# and the repeatable QUIC Initial/SNI capture are the published container gates.
for suite in docker-product docker-v2-sni; do
  echo "==> running V2 suite: $suite"
  "$ROOT/tests/$suite/run.sh"
done

echo "all Ironet Protocol V2 integration suites passed"

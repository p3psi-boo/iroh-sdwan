#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
export SOAK_SECONDS=${SOAK_SECONDS:-20}
exec "$ROOT/tests/netns/run.sh" docker-soak

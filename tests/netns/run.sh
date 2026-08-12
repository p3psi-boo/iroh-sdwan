#!/usr/bin/env bash
set -euo pipefail

SUITE=${1:?usage: tests/netns/run.sh SUITE}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
LAB_SCRIPT="$ROOT/tests/$SUITE/lab.sh"
STATE_DIR="$ROOT/target/$SUITE-test"
IMAGE=iroh-sdwan:netns-test
HOST_UID=$(id -u)
HOST_GID=$(id -g)

if [[ ! -x $LAB_SCRIPT ]]; then
  echo "network-namespace lab is missing or not executable: $LAB_SCRIPT" >&2
  exit 2
fi

mkdir -p "$STATE_DIR"

echo "==> building shared network-namespace test image"
docker build \
  --file "$ROOT/tests/docker/Dockerfile" \
  --tag "$IMAGE" \
  "$ROOT"

docker run --rm \
  --volume "$STATE_DIR:/state" \
  --entrypoint sh \
  "$IMAGE" -c 'rm -rf /state/*'

status=0
docker run --rm \
  --name "iroh-sdwan-${SUITE}-netns" \
  --privileged \
  --device /dev/net/tun:/dev/net/tun \
  --env SOAK_SECONDS="${SOAK_SECONDS:-20}" \
  --env RUST_LOG="${RUST_LOG:-info}" \
  --volume "$STATE_DIR:/state" \
  --volume "$ROOT/tests:/tests:ro" \
  --entrypoint bash \
  "$IMAGE" "/tests/$SUITE/lab.sh" || status=$?

docker run --rm \
  --volume "$STATE_DIR:/state" \
  --entrypoint chown \
  "$IMAGE" -R "$HOST_UID:$HOST_GID" /state >/dev/null

exit "$status"

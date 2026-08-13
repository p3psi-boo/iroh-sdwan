#!/usr/bin/env bash
set -euo pipefail

: "${FORGEJO_API_URL:?FORGEJO_API_URL is required}"
: "${FORGEJO_REPOSITORY:?FORGEJO_REPOSITORY is required}"
: "${FORGEJO_REF_NAME:?FORGEJO_REF_NAME is required}"
: "${FORGEJO_TOKEN:?FORGEJO_TOKEN is required}"

for command in curl jq; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "required command not found: $command" >&2
    exit 2
  fi
done

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VERSION=$(
  sed -n '/^\[package\]$/,/^\[/s/^version = "\([^"]*\)"/\1/p' "$ROOT/Cargo.toml" \
    | head -n1
)
EXPECTED_TAG="v$VERSION"
if [[ "$FORGEJO_REF_NAME" != "$EXPECTED_TAG" ]]; then
  echo "release tag $FORGEJO_REF_NAME does not match Cargo version $EXPECTED_TAG" >&2
  exit 1
fi
if (($# == 0)); then
  echo "usage: $0 ASSET [ASSET ...]" >&2
  exit 2
fi

API="${FORGEJO_API_URL%/}/repos/$FORGEJO_REPOSITORY"
AUTH_HEADER="Authorization: token $FORGEJO_TOKEN"
RESPONSE=$(mktemp "${TMPDIR:-/tmp}/forgejo-release.XXXXXX")
trap 'rm -f "$RESPONSE"' EXIT

STATUS=$(curl --silent --show-error \
  --output "$RESPONSE" \
  --write-out '%{http_code}' \
  --header "$AUTH_HEADER" \
  "$API/releases/tags/$FORGEJO_REF_NAME")

case "$STATUS" in
  200)
    ;;
  404)
    PRERELEASE=false
    [[ "$VERSION" == *-* ]] && PRERELEASE=true
    PAYLOAD=$(jq -n \
      --arg tag "$FORGEJO_REF_NAME" \
      --arg name "ironet $VERSION" \
      --arg body "Automated musl Debian package release for ironet $VERSION." \
      --argjson prerelease "$PRERELEASE" \
      '{tag_name: $tag, name: $name, body: $body, draft: false, prerelease: $prerelease}')
    curl --fail-with-body --silent --show-error \
      --output "$RESPONSE" \
      --request POST \
      --header "$AUTH_HEADER" \
      --header 'Content-Type: application/json' \
      --data "$PAYLOAD" \
      "$API/releases"
    ;;
  *)
    cat "$RESPONSE" >&2
    echo "Forgejo returned HTTP $STATUS while looking up the release" >&2
    exit 1
    ;;
esac

RELEASE_ID=$(jq -er '.id' "$RESPONSE")
for asset in "$@"; do
  if [[ ! -f "$asset" ]]; then
    echo "release asset does not exist: $asset" >&2
    exit 2
  fi
  name=$(basename "$asset")
  existing_id=$(jq -r --arg name "$name" '.assets[]? | select(.name == $name) | .id' "$RESPONSE" | head -n1)
  if [[ -n "$existing_id" ]]; then
    curl --fail-with-body --silent --show-error \
      --output /dev/null \
      --request DELETE \
      --header "$AUTH_HEADER" \
      "$API/releases/$RELEASE_ID/assets/$existing_id"
  fi
  curl --fail-with-body --silent --show-error \
    --output /dev/null \
    --request POST \
    --header "$AUTH_HEADER" \
    --form "attachment=@$asset" \
    "$API/releases/$RELEASE_ID/assets"
  echo "uploaded $name"
done

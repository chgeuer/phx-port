#!/usr/bin/env bash
set -euo pipefail

SAMPLE="${1:?sample directory is required}"
LABEL="${2:?sample label is required}"
HOST="${3:?TLS hostname is required}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cd "$ROOT/samples/$SAMPLE"
HTTP_PORT="${HTTP_PORT:-$(phx-port)}"
HTTPS_PORT="${HTTPS_PORT:-$(phx-port https)}"
PUBLIC_HTTPS_PORT="${PUBLIC_HTTPS_PORT:-443}"
EXPECTED="phxp $LABEL handoff example"

request() {
  local title="$1"
  local marker="$2"
  shift 2

  echo "=== $title ==="
  local response
  response="$(curl --fail --silent --show-error "$@")"
  if [[ "$response" != *"$EXPECTED"* || "$response" != *"$marker"* ]]; then
    echo "$SAMPLE is not serving the expected response for $title." >&2
    echo "Run 'just start-$SAMPLE' and check that no previous server owns its ports." >&2
    exit 1
  fi
  printf '%s\n' "$response"
}

request "Direct HTTP :$HTTP_PORT" "listener=http" \
  "http://127.0.0.1:$HTTP_PORT/"
request "Direct HTTPS :$HTTPS_PORT" "listener=https" \
  --resolve "$HOST:$HTTPS_PORT:127.0.0.1" \
  "https://$HOST:$HTTPS_PORT/"
request "Public HTTPS handoff :$PUBLIC_HTTPS_PORT" "listener=phxp-handoff-https" \
  --resolve "$HOST:$PUBLIC_HTTPS_PORT:127.0.0.1" \
  "https://$HOST:$PUBLIC_HTTPS_PORT/"

#!/usr/bin/env bash
set -euo pipefail

SAMPLE="${1:?sample directory is required}"
LABEL="${2:?sample label is required}"
HOST="${3:?TLS hostname is required}"
EXPECTED="${4:?response marker is required}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cd "$ROOT/samples/$SAMPLE"
HTTPS_PORT="${HTTPS_PORT:-$(phx-port https)}"
PUBLIC_HTTPS_PORT="${PUBLIC_HTTPS_PORT:-443}"

request() {
  local title="$1"
  local port="$2"
  echo "=== $title ==="
  local response
  response="$(
    curl --fail --silent --show-error \
      --resolve "$HOST:$port:127.0.0.1" \
      "https://$HOST:$port/"
  )"
  if [[ "$response" != *"$EXPECTED"* ]]; then
    echo "$LABEL sample did not return its framework response for $title." >&2
    exit 1
  fi
  printf '%s\n' "$response"
}

request "Direct HTTPS :$HTTPS_PORT" "$HTTPS_PORT"
request "Public HTTPS handoff :$PUBLIC_HTTPS_PORT" "$PUBLIC_HTTPS_PORT"

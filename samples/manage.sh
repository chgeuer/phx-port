#!/usr/bin/env bash
set -euo pipefail

ACTION="${1:?status or stop is required}"
SAMPLE="${2:?sample directory is required}"
LABEL="${3:?sample label is required}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cd "$ROOT/samples/$SAMPLE"
HTTP_PORT="$(phx-port)"
EXPECTED="phxp $LABEL handoff example"

if ! RESPONSE="$(curl --fail --silent --show-error --max-time 2 "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null)"; then
  echo "$SAMPLE sample is not running on port $HTTP_PORT." >&2
  exit 1
fi

if [[ "$RESPONSE" != *"$EXPECTED"* || "$RESPONSE" != *"listener=http"* ]]; then
  echo "Port $HTTP_PORT is owned by a different server; refusing to manage it." >&2
  exit 2
fi

PID="$(
  ss -H -ltnp "sport = :$HTTP_PORT" 2>/dev/null |
    grep -o 'pid=[0-9]*' |
    head -n 1 |
    cut -d= -f2 ||
    true
)"

if [[ -z "$PID" ]]; then
  echo "Could not identify the $SAMPLE listener process on port $HTTP_PORT." >&2
  exit 1
fi

if [[ "$(ps -o uid= -p "$PID" | tr -d ' ')" != "$(id -u)" ]]; then
  echo "Process $PID is owned by another user; refusing to manage it." >&2
  exit 1
fi

case "$ACTION" in
  status)
    echo "$SAMPLE sample is running on HTTP port $HTTP_PORT (PID $PID)."
    ;;
  stop)
    kill "$PID"
    for _ in $(seq 1 40); do
      if ! kill -0 "$PID" 2>/dev/null; then
        echo "$SAMPLE sample stopped."
        exit 0
      fi
      sleep 0.1
    done
    echo "$SAMPLE sample did not stop within four seconds." >&2
    exit 1
    ;;
  *)
    echo "Unknown action '$ACTION'; expected status or stop." >&2
    exit 2
    ;;
esac

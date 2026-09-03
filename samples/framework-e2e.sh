#!/usr/bin/env bash
set -euo pipefail

SAMPLE="${1:?sample name is required}"
HOST="${2:?TLS hostname is required}"
EXPECTED="${3:?response marker is required}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/debug/phx-port"
CERT_DIR="${PHXP_CERT_DIR:-$HOME/.dns/production}"
if [[ "$(uname -s)" == "Darwin" ]]; then
  TEMP_ROOT="/private/tmp"
else
  TEMP_ROOT="/tmp"
fi
STATE="$(mktemp -d "$TEMP_ROOT/px.XXXXXX")"
WORKLOAD_PID=""
DAEMON_PID=""

cleanup() {
  local status=$?
  if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    kill "$DAEMON_PID"
    wait "$DAEMON_PID" 2>/dev/null || true
  fi
  if [[ -n "$WORKLOAD_PID" ]] && kill -0 "$WORKLOAD_PID" 2>/dev/null; then
    kill "$WORKLOAD_PID"
    wait "$WORKLOAD_PID" 2>/dev/null || true
  fi
  if [[ "$status" -ne 0 ]]; then
    echo "Framework end-to-end test failed; diagnostics follow." >&2
    for log in "$STATE/workload.log" "$STATE/daemon.log"; do
      if [[ -f "$log" ]]; then
        echo "=== $(basename "$log") ===" >&2
        sed -n '1,120p' "$log" >&2
      fi
    done
  fi
  rm -rf "$STATE"
  return "$status"
}
trap cleanup EXIT INT TERM

test -x "$BIN" || {
  echo "Build phx-port before running the framework end-to-end test." >&2
  exit 1
}
test -r "$CERT_DIR/$HOST.crt"
test -r "$CERT_DIR/$HOST.key"

export PHX_PORT_CONFIG="$STATE/p.toml"
export PHX_PORT_RUNTIME_DIR="$STATE/r"
export XDG_RUNTIME_DIR="$STATE"
read -r HTTPS_PORT AVAILABLE_INGRESS_PORT < <(
  python3 -c '
import socket

sockets = [socket.socket() for _ in range(2)]
for listener in sockets:
    listener.bind(("127.0.0.1", 0))
print(*(listener.getsockname()[1] for listener in sockets))
for listener in sockets:
    listener.close()
'
)
INGRESS_PORT="${PHXP_E2E_INGRESS_PORT:-$AVAILABLE_INGRESS_PORT}"
python3 - "$PHX_PORT_CONFIG" "$ROOT/samples/$SAMPLE" "$HTTPS_PORT" <<'PY'
import json
import os
from pathlib import Path
import sys

config, project, port = sys.argv[1:]
Path(config).write_text(f"[ports.{json.dumps(project)}]\nhttps = {port}\n")
os.chmod(config, 0o600)
PY

(
  cd "$ROOT/samples/$SAMPLE"
  export PHXP_TLS_CERT="$CERT_DIR/$HOST.crt"
  export PHXP_TLS_KEY="$CERT_DIR/$HOST.key"
  case "$SAMPLE" in
    go)
      exec "$ROOT/target/samples/phxp-http" -https "127.0.0.1:$HTTPS_PORT"
      ;;
    python)
      exec .venv/bin/phxp-fastapi --https "127.0.0.1:$HTTPS_PORT"
      ;;
    node)
      export HOST=127.0.0.1 PORT="$HTTPS_PORT"
      exec node src/sample.js
      ;;
    *)
      echo "Unsupported framework sample: $SAMPLE" >&2
      exit 2
      ;;
  esac
) >"$STATE/workload.log" 2>&1 &
WORKLOAD_PID=$!

for _ in $(seq 1 100); do
  if curl --fail --silent --show-error --max-time 1 \
    --resolve "$HOST:$HTTPS_PORT:127.0.0.1" \
    "https://$HOST:$HTTPS_PORT/" >"$STATE/direct.out" 2>/dev/null; then
    break
  fi
  sleep 0.05
done
grep -Fq "$EXPECTED" "$STATE/direct.out"

"$BIN" daemon --listen "127.0.0.1:$INGRESS_PORT" \
  >"$STATE/daemon.log" 2>&1 &
DAEMON_PID=$!

for _ in $(seq 1 200); do
  if curl --fail --silent --show-error --max-time 1 \
    --resolve "$HOST:$INGRESS_PORT:127.0.0.1" \
    "https://$HOST:$INGRESS_PORT/" >"$STATE/handoff.out" 2>/dev/null; then
    break
  fi
  sleep 0.05
done
grep -Fq "$EXPECTED" "$STATE/handoff.out"

STATUS="$("$BIN" proxy status --json)"
python3 -c '
import json
import sys

status = json.load(sys.stdin)
counters = status["counters"]
assert counters["successful_handoffs"] == 1, status
assert counters["relayed_connections"] == 0, status
' <<<"$STATUS"

echo "$SAMPLE: direct and PHXP requests reached the framework; handoffs=1 relays=0"

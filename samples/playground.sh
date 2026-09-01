#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
SCRIPT_PATH="${SCRIPT_DIR}/playground.sh"

USER_ID="$(id -u)"
STATE_DIR="${PHX_PORT_PLAY_STATE_DIR:-/tmp/phx-port-play-${USER_ID}}"
HANDOFF_DIR="${PHX_PORT_PLAY_HANDOFF_DIR:-/tmp/phxp-h-${USER_ID}}"
CERT_DIR="${PHX_PORT_PLAY_CERT_DIR:-${HOME}/.dns/production}"
LOG_DIR="${STATE_DIR}/logs"
PID_DIR="${STATE_DIR}/pids"
CONTROL_RUNTIME="${STATE_DIR}/control"
CONFIG_FILE="${PHX_PORT_CONFIG:-${HOME}/.config/phx-ports.toml}"
SETTINGS_FILE="${STATE_DIR}/settings.env"
RELAY_CHAIN_FILE="${STATE_DIR}/relay-chain.pem"

DAEMON_BIN="${ROOT_DIR}/target/debug/phx-port"
RUST_BIN="${ROOT_DIR}/samples/rust/target/debug/phxp-handoff-server"
ELIXIR_DIR="${ROOT_DIR}/samples/elixir"
RUST_DIR="${ROOT_DIR}/samples/rust"
RELAY_DIR="${ROOT_DIR}/samples/relay"

ELIXIR_HOST="a.pollmann.rocks"
RUST_HOST="b.pollmann.rocks"
RELAY_HOST="c.pollmann.rocks"
SERVICES=(daemon elixir rust relay)

die() {
  printf 'playground: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

secure_dir() {
  python3 - "$1" <<'PY'
import os
import stat
import sys

path = os.path.abspath(sys.argv[1])
if path == os.path.sep:
    raise SystemExit("refusing to use the filesystem root as playground state")

try:
    current = os.lstat(path)
except FileNotFoundError:
    os.mkdir(path, 0o700)
    current = os.lstat(path)

if stat.S_ISLNK(current.st_mode) or not stat.S_ISDIR(current.st_mode):
    raise SystemExit(f"{path} must be a real directory, not a symlink")
if current.st_uid != os.geteuid():
    raise SystemExit(f"{path} must be owned by uid {os.geteuid()}")
if stat.S_IMODE(current.st_mode) != 0o700:
    os.chmod(path, 0o700)
PY
}

ensure_state_dirs() {
  require_command python3
  secure_dir "${STATE_DIR}"
  secure_dir "${LOG_DIR}"
  secure_dir "${PID_DIR}"
  secure_dir "${CONTROL_RUNTIME}"
  secure_dir "${HANDOFF_DIR}"
}

pid_file() {
  printf '%s/%s.pid\n' "${PID_DIR}" "$1"
}

log_file() {
  printf '%s/%s.log\n' "${LOG_DIR}" "$1"
}

read_pid() {
  local file
  file="$(pid_file "$1")"
  [[ -f "${file}" ]] || return 1

  local pid
  pid="$(<"${file}")"
  [[ "${pid}" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "${pid}"
}

service_running() {
  local service="$1"
  local pid
  pid="$(read_pid "${service}")" || return 1
  kill -0 "${pid}" 2>/dev/null || return 1

  local command_line
  command_line="$(ps -p "${pid}" -o command= 2>/dev/null || true)"
  [[ "${command_line}" == *"${SCRIPT_PATH} __run ${service}"* ]]
}

supervise() {
  local service="$1"
  shift

  set +e
  printf '[playground] starting %s:' "${service}"
  printf ' %q' "$@"
  printf '\n'

  "$@" &
  local child_pid=$!

  terminate_child() {
    trap - TERM INT HUP
    if kill -0 "${child_pid}" 2>/dev/null; then
      kill -TERM "${child_pid}" 2>/dev/null || true
      local attempt
      for ((attempt = 0; attempt < 50; attempt++)); do
        kill -0 "${child_pid}" 2>/dev/null || break
        sleep 0.1
      done
      if kill -0 "${child_pid}" 2>/dev/null; then
        kill -KILL "${child_pid}" 2>/dev/null || true
      fi
    fi
    wait "${child_pid}" 2>/dev/null
    exit 0
  }

  trap terminate_child TERM INT HUP
  wait "${child_pid}"
  local status=$?
  trap - TERM INT HUP
  printf '[playground] %s exited with status %s\n' "${service}" "${status}"
  return "${status}"
}

start_service() {
  local service="$1"
  local working_dir="$2"
  shift 2

  local pid_path
  local pid_tmp
  local output
  pid_path="$(pid_file "${service}")"
  pid_tmp="${pid_path}.tmp"
  output="$(log_file "${service}")"
  rm -f "${pid_path}" "${pid_tmp}"
  : >"${output}"
  chmod 600 "${output}"

  (
    cd -- "${working_dir}"
    nohup bash "${SCRIPT_PATH}" __run "${service}" "$@" \
      >>"${output}" 2>&1 </dev/null &
    printf '%s\n' "$!" >"${pid_tmp}"
  )
  chmod 600 "${pid_tmp}"
  mv "${pid_tmp}" "${pid_path}"

  local attempt
  for ((attempt = 0; attempt < 20; attempt++)); do
    service_running "${service}" && return 0
    sleep 0.05
  done

  printf 'playground: %s did not stay running; log follows\n' "${service}" >&2
  tail -n 40 "${output}" >&2 || true
  return 1
}

stop_service() {
  local service="$1"
  if ! service_running "${service}"; then
    rm -f "$(pid_file "${service}")"
    printf '%-8s stopped\n' "${service}"
    return 0
  fi

  local pid
  pid="$(read_pid "${service}")"
  kill -TERM "${pid}"

  local attempt
  for ((attempt = 0; attempt < 70; attempt++)); do
    kill -0 "${pid}" 2>/dev/null || break
    sleep 0.1
  done
  if kill -0 "${pid}" 2>/dev/null; then
    kill -KILL "${pid}" 2>/dev/null || true
  fi
  rm -f "$(pid_file "${service}")"
  printf '%-8s stopped\n' "${service}"
}

check_certificates() {
  require_command openssl

  local hostname
  for hostname in "${ELIXIR_HOST}" "${RUST_HOST}" "${RELAY_HOST}"; do
    local cert="${CERT_DIR}/${hostname}.crt"
    local key="${CERT_DIR}/${hostname}.key"
    [[ -r "${cert}" ]] || die "missing readable certificate: ${cert}"
    [[ -r "${key}" ]] || die "missing readable private key: ${key}"
    openssl x509 -in "${cert}" -checkend 0 -noout >/dev/null 2>&1 ||
      die "certificate is invalid or expired: ${cert}"
  done
}

write_relay_chain() {
  python3 - "${CERT_DIR}/${RELAY_HOST}.crt" "${RELAY_CHAIN_FILE}" <<'PY'
import os
import re
import sys

source, destination = sys.argv[1:]
with open(source, "r", encoding="ascii") as certificate_file:
    pem = certificate_file.read()

certificates = re.findall(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\s*",
    pem,
    flags=re.DOTALL,
)
if len(certificates) < 2:
    raise SystemExit(f"{source} does not contain an issuer chain")

temporary = destination + ".tmp"
with open(temporary, "w", encoding="ascii") as chain_file:
    chain_file.write("".join(certificates[1:]))
os.chmod(temporary, 0o600)
os.replace(temporary, destination)
PY
}

check_public_listeners() {
  python3 - "$1" "$2" "$3" <<'PY'
import socket
import sys

bind4, bind6, raw_port = sys.argv[1:]
port = int(raw_port)
listeners = []

try:
    ipv4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ipv4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ipv4.bind((bind4, port))
    listeners.append(ipv4)

    ipv6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    ipv6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ipv6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    ipv6.bind((bind6, port))
    listeners.append(ipv6)
except OSError as error:
    raise SystemExit(
        f"cannot reserve {bind4}:{port} and [{bind6}]:{port}: {error}"
    )
PY
}

register_port() {
  local project="$1"
  local role="$2"
  local port
  port="$(
    cd -- "${project}"
    PHX_PORT_CONFIG="${CONFIG_FILE}" "${DAEMON_BIN}" register "${role}"
  )"
  [[ "${port}" =~ ^[0-9]+$ ]] ||
    die "phx-port returned an invalid ${role} port for ${project}: ${port}"
  printf '%s\n' "${port}"
}

register_playground_ports() {
  PLAY_ELIXIR_HTTP="$(register_port "${ELIXIR_DIR}" main)"
  PLAY_ELIXIR_HTTPS="$(register_port "${ELIXIR_DIR}" https)"
  PLAY_RUST_HTTP="$(register_port "${RUST_DIR}" main)"
  PLAY_RUST_HTTPS="$(register_port "${RUST_DIR}" https)"
  PLAY_RELAY_HTTPS="$(register_port "${RELAY_DIR}" https)"
}

write_settings() {
  local temporary="${SETTINGS_FILE}.tmp"
  {
    printf 'PLAY_CONFIG_FILE=%q\n' "${CONFIG_FILE}"
    printf 'PLAY_PUBLIC_PORT=%q\n' "${PLAY_PUBLIC_PORT}"
    printf 'PLAY_BIND4=%q\n' "${PLAY_BIND4}"
    printf 'PLAY_BIND6=%q\n' "${PLAY_BIND6}"
    printf 'PLAY_ELIXIR_HTTP=%q\n' "${PLAY_ELIXIR_HTTP}"
    printf 'PLAY_ELIXIR_HTTPS=%q\n' "${PLAY_ELIXIR_HTTPS}"
    printf 'PLAY_RUST_HTTP=%q\n' "${PLAY_RUST_HTTP}"
    printf 'PLAY_RUST_HTTPS=%q\n' "${PLAY_RUST_HTTPS}"
    printf 'PLAY_RELAY_HTTPS=%q\n' "${PLAY_RELAY_HTTPS}"
  } >"${temporary}"
  chmod 600 "${temporary}"
  mv "${temporary}" "${SETTINGS_FILE}"
}

load_settings() {
  [[ -f "${SETTINGS_FILE}" ]] ||
    die "playground has not been initialized; run 'just play-up'"
  # The settings file is generated in the private, owner-only state directory.
  source "${SETTINGS_FILE}"
  CONFIG_FILE="${PLAY_CONFIG_FILE}"
}

daemon_cli() {
  env \
    PHX_PORT_CONFIG="${CONFIG_FILE}" \
    PHX_PORT_RUNTIME_DIR="${HANDOFF_DIR}" \
    XDG_RUNTIME_DIR="${CONTROL_RUNTIME}" \
    "${DAEMON_BIN}" "$@"
}

wait_for_url() {
  local service="$1"
  local label="$2"
  local expected="$3"
  shift 3

  local response
  local attempt
  for ((attempt = 0; attempt < 300; attempt++)); do
    if response="$(curl --noproxy '*' --silent --show-error --fail \
      --max-time 2 "$@" 2>/dev/null)" &&
      grep -Fq "${expected}" <<<"${response}"; then
      return 0
    fi
    service_running "${service}" || break
    sleep 0.1
  done

  printf 'playground: %s did not become ready\n' "${label}" >&2
  tail -n 50 "$(log_file "${service}")" >&2 || true
  return 1
}

require_all_running() {
  local service
  for service in "${SERVICES[@]}"; do
    service_running "${service}" ||
      die "${service} is not running; run 'just play-up'"
  done
}

build_playground() {
  require_command cargo
  require_command mix

  printf 'Building phx-port daemon...\n'
  (cd -- "${ROOT_DIR}" && cargo build --quiet)
  printf 'Building Rust handoff sample...\n'
  (cd -- "${RUST_DIR}" && cargo build --quiet)
  printf 'Building Elixir/Bandit handoff sample...\n'
  (cd -- "${ELIXIR_DIR}" && MIX_ENV=dev mix deps.get --quiet && MIX_ENV=dev mix compile)
  printf 'Playground binaries are ready.\n'
}

start_playground() {
  ensure_state_dirs

  local desired_port="${PHX_PORT_PLAY_PORT:-443}"
  local desired_bind4="${PHX_PORT_PLAY_BIND4:-0.0.0.0}"
  local desired_bind6="${PHX_PORT_PLAY_BIND6:-::}"
  local desired_config="${PHX_PORT_CONFIG:-${HOME}/.config/phx-ports.toml}"
  [[ "${desired_port}" =~ ^[0-9]+$ ]] ||
    die "PHX_PORT_PLAY_PORT must be a numeric TCP port"
  ((desired_port >= 1 && desired_port <= 65535)) ||
    die "PHX_PORT_PLAY_PORT must be between 1 and 65535"

  local live=0
  local service
  for service in "${SERVICES[@]}"; do
    service_running "${service}" && ((live += 1))
  done
  if ((live == ${#SERVICES[@]})); then
    load_settings
    if [[ "${PLAY_PUBLIC_PORT}" != "${desired_port}" ||
      "${PLAY_BIND4}" != "${desired_bind4}" ||
      "${PLAY_BIND6}" != "${desired_bind6}" ||
      "${PLAY_CONFIG_FILE}" != "${desired_config}" ]]; then
      die "playground is already running with different listeners or registry; run 'just play-down' before changing them"
    fi
    printf 'Playground is already running.\n'
    show_status
    return 0
  fi
  if ((live > 0)); then
    die "only ${live} of ${#SERVICES[@]} services are running; run 'just play-down' before restarting"
  fi

  [[ -x "${DAEMON_BIN}" ]] ||
    die "daemon binary is missing; run 'just play-build'"
  [[ -x "${RUST_BIN}" ]] ||
    die "Rust sample binary is missing; run 'just play-build'"
  [[ -d "${RELAY_DIR}" ]] ||
    die "relay sample directory is missing: ${RELAY_DIR}"
  require_command curl
  require_command mix
  require_command openssl
  check_certificates
  write_relay_chain
  check_public_listeners "${desired_bind4}" "${desired_bind6}" "${desired_port}" ||
    die "public playground listener is unavailable"

  PLAY_PUBLIC_PORT="${desired_port}"
  PLAY_BIND4="${desired_bind4}"
  PLAY_BIND6="${desired_bind6}"
  CONFIG_FILE="${desired_config}"
  register_playground_ports
  write_settings

  for service in "${SERVICES[@]}"; do
    rm -f "$(pid_file "${service}")"
  done

  if ! start_service elixir "${ELIXIR_DIR}" \
    env \
    PORT="${PLAY_ELIXIR_HTTP}" \
    HTTPS_PORT="${PLAY_ELIXIR_HTTPS}" \
    PHXP_TLS_CERT="${CERT_DIR}/${ELIXIR_HOST}.crt" \
    PHXP_TLS_KEY="${CERT_DIR}/${ELIXIR_HOST}.key" \
    PHXP_PROJECT="${ELIXIR_DIR}" \
    PHXP_ROLE="https" \
    PHX_PORT_RUNTIME_DIR="${HANDOFF_DIR}" \
    mix run --no-halt; then
    stop_playground
    die "failed to start the Elixir sample"
  fi

  if ! start_service rust "${RUST_DIR}" \
    env PHX_PORT_RUNTIME_DIR="${HANDOFF_DIR}" \
    "${RUST_BIN}" \
    --http "127.0.0.1:${PLAY_RUST_HTTP}" \
    --https "127.0.0.1:${PLAY_RUST_HTTPS}" \
    --cert "${CERT_DIR}/${RUST_HOST}.crt" \
    --key "${CERT_DIR}/${RUST_HOST}.key" \
    --project "${RUST_DIR}" \
    --role "https"; then
    stop_playground
    die "failed to start the Rust sample"
  fi

  if ! start_service relay "${RELAY_DIR}" \
    openssl s_server \
    -accept "127.0.0.1:${PLAY_RELAY_HTTPS}" \
    -cert "${CERT_DIR}/${RELAY_HOST}.crt" \
    -cert_chain "${RELAY_CHAIN_FILE}" \
    -key "${CERT_DIR}/${RELAY_HOST}.key" \
    -www; then
    stop_playground
    die "failed to start the relay-only TLS sample"
  fi

  if ! wait_for_url elixir "Elixir HTTP listener" "listener=http" \
    "http://127.0.0.1:${PLAY_ELIXIR_HTTP}/"; then
    stop_playground
    die "Elixir HTTP listener failed"
  fi
  if ! wait_for_url elixir "Elixir HTTPS listener" "listener=https" \
    --resolve "${ELIXIR_HOST}:${PLAY_ELIXIR_HTTPS}:127.0.0.1" \
    "https://${ELIXIR_HOST}:${PLAY_ELIXIR_HTTPS}/"; then
    stop_playground
    die "Elixir HTTPS listener failed"
  fi
  if ! wait_for_url rust "Rust HTTP listener" "phxp Rust handoff example" \
    "http://127.0.0.1:${PLAY_RUST_HTTP}/"; then
    stop_playground
    die "Rust HTTP listener failed"
  fi
  if ! wait_for_url rust "Rust HTTPS listener" "phxp Rust handoff example" \
    --resolve "${RUST_HOST}:${PLAY_RUST_HTTPS}:127.0.0.1" \
    "https://${RUST_HOST}:${PLAY_RUST_HTTPS}/"; then
    stop_playground
    die "Rust HTTPS listener failed"
  fi
  if ! wait_for_url relay "relay-only HTTPS listener" "s_server" \
    --resolve "${RELAY_HOST}:${PLAY_RELAY_HTTPS}:127.0.0.1" \
    "https://${RELAY_HOST}:${PLAY_RELAY_HTTPS}/"; then
    stop_playground
    die "relay-only HTTPS listener failed"
  fi

  if ! start_service daemon "${ROOT_DIR}" \
    env \
    PHX_PORT_CONFIG="${CONFIG_FILE}" \
    PHX_PORT_RUNTIME_DIR="${HANDOFF_DIR}" \
    XDG_RUNTIME_DIR="${CONTROL_RUNTIME}" \
    "${DAEMON_BIN}" daemon \
    --listen "${PLAY_BIND4}:${PLAY_PUBLIC_PORT}" \
    --listen "[${PLAY_BIND6}]:${PLAY_PUBLIC_PORT}"; then
    stop_playground
    die "failed to start phx-port"
  fi

  if ! wait_for_url daemon "Elixir handoff route" "listener=phxp-handoff-https" \
    --resolve "${ELIXIR_HOST}:${PLAY_PUBLIC_PORT}:127.0.0.1" \
    "https://${ELIXIR_HOST}:${PLAY_PUBLIC_PORT}/"; then
    stop_playground
    die "Elixir handoff route failed"
  fi
  if ! wait_for_url daemon "Rust handoff route" "phxp Rust handoff example" \
    --resolve "${RUST_HOST}:${PLAY_PUBLIC_PORT}:127.0.0.1" \
    "https://${RUST_HOST}:${PLAY_PUBLIC_PORT}/"; then
    stop_playground
    die "Rust handoff route failed"
  fi
  if ! wait_for_url daemon "relay fallback route" "s_server" \
    --resolve "${RELAY_HOST}:${PLAY_PUBLIC_PORT}:127.0.0.1" \
    "https://${RELAY_HOST}:${PLAY_PUBLIC_PORT}/"; then
    stop_playground
    die "relay fallback route failed"
  fi

  printf 'Playground started successfully.\n'
  show_status
}

stop_playground() {
  ensure_state_dirs

  if service_running daemon; then
    daemon_cli proxy stop >/dev/null 2>&1 || true
    local attempt
    local daemon_pid
    daemon_pid="$(read_pid daemon)"
    for ((attempt = 0; attempt < 30; attempt++)); do
      kill -0 "${daemon_pid}" 2>/dev/null || break
      sleep 0.1
    done
  fi

  local service
  for service in daemon elixir rust relay; do
    stop_service "${service}"
  done
}

show_status() {
  ensure_state_dirs
  load_settings

  printf 'Services\n'
  printf '%-8s %-8s %s\n' NAME STATE PID
  local service
  for service in "${SERVICES[@]}"; do
    if service_running "${service}"; then
      printf '%-8s %-8s %s\n' "${service}" running "$(read_pid "${service}")"
    else
      printf '%-8s %-8s %s\n' "${service}" stopped -
    fi
  done

  printf '\nListeners\n'
  printf '  public IPv4:  %s:%s\n' "${PLAY_BIND4}" "${PLAY_PUBLIC_PORT}"
  printf '  public IPv6:  [%s]:%s\n' "${PLAY_BIND6}" "${PLAY_PUBLIC_PORT}"
  printf '  Elixir HTTP:  127.0.0.1:%s\n' "${PLAY_ELIXIR_HTTP}"
  printf '  Elixir HTTPS: 127.0.0.1:%s\n' "${PLAY_ELIXIR_HTTPS}"
  printf '  Rust HTTP:     127.0.0.1:%s\n' "${PLAY_RUST_HTTP}"
  printf '  Rust HTTPS:    127.0.0.1:%s\n' "${PLAY_RUST_HTTPS}"
  printf '  relay HTTPS:   127.0.0.1:%s\n' "${PLAY_RELAY_HTTPS}"

  printf '\nPublic routes\n'
  printf '  https://%s:%s/  Elixir/Bandit handoff\n' \
    "${ELIXIR_HOST}" "${PLAY_PUBLIC_PORT}"
  printf '  https://%s:%s/  Rust/Axum handoff\n' \
    "${RUST_HOST}" "${PLAY_PUBLIC_PORT}"
  printf '  https://%s:%s/  TLS relay fallback\n' \
    "${RELAY_HOST}" "${PLAY_PUBLIC_PORT}"

  if service_running daemon; then
    printf '\nDaemon status\n'
    daemon_cli proxy status | sed 's/^/  /'
    printf '\nDaemon routes\n'
    daemon_cli proxy routes | sed 's/^/  /'
  fi
}

perform_request() {
  local label="$1"
  local expected="$2"
  local expected_http="$3"
  shift 3

  local body
  body="$(mktemp "${STATE_DIR}/response.XXXXXX")"
  local metadata
  if ! metadata="$(curl --noproxy '*' --silent --show-error --fail \
    --max-time 10 --output "${body}" \
    --write-out '%{http_code} HTTP/%{http_version}' "$@")"; then
    rm -f "${body}"
    die "${label} request failed"
  fi
  if ! grep -Fq "${expected}" "${body}"; then
    sed -n '1,20p' "${body}" >&2
    rm -f "${body}"
    die "${label} returned an unexpected response"
  fi
  if [[ "${expected_http}" != "any" &&
    "${metadata}" != *"HTTP/${expected_http}" ]]; then
    rm -f "${body}"
    die "${label} negotiated ${metadata}, expected HTTP/${expected_http}"
  fi

  printf '\n%s — %s\n' "${label}" "${metadata}"
  sed -n '1,8p' "${body}" | sed 's/^/  /'
  rm -f "${body}"
}

try_playground() {
  ensure_state_dirs
  load_settings
  require_command curl
  require_all_running

  perform_request "Elixir direct HTTP" "listener=http" "1.1" \
    --http1.1 "http://127.0.0.1:${PLAY_ELIXIR_HTTP}/direct"
  perform_request "Elixir direct HTTPS" "listener=https" "1.1" \
    --http1.1 \
    --resolve "${ELIXIR_HOST}:${PLAY_ELIXIR_HTTPS}:127.0.0.1" \
    "https://${ELIXIR_HOST}:${PLAY_ELIXIR_HTTPS}/direct"
  perform_request "Elixir handoff HTTP/1.1" "listener=phxp-handoff-https" "1.1" \
    --http1.1 \
    --resolve "${ELIXIR_HOST}:${PLAY_PUBLIC_PORT}:127.0.0.1" \
    "https://${ELIXIR_HOST}:${PLAY_PUBLIC_PORT}/handoff-http1"
  perform_request "Elixir handoff HTTP/2" "listener=phxp-handoff-https" "2" \
    --http2 \
    --resolve "${ELIXIR_HOST}:${PLAY_PUBLIC_PORT}:127.0.0.1" \
    "https://${ELIXIR_HOST}:${PLAY_PUBLIC_PORT}/handoff-http2"
  perform_request "Elixir handoff over IPv6" "listener=phxp-handoff-https" "1.1" \
    --http1.1 \
    --resolve "${ELIXIR_HOST}:${PLAY_PUBLIC_PORT}:[::1]" \
    "https://${ELIXIR_HOST}:${PLAY_PUBLIC_PORT}/handoff-ipv6"

  perform_request "Rust direct HTTP" "phxp Rust handoff example" "1.1" \
    --http1.1 "http://127.0.0.1:${PLAY_RUST_HTTP}/direct"
  perform_request "Rust direct HTTPS" "phxp Rust handoff example" "1.1" \
    --http1.1 \
    --resolve "${RUST_HOST}:${PLAY_RUST_HTTPS}:127.0.0.1" \
    "https://${RUST_HOST}:${PLAY_RUST_HTTPS}/direct"
  perform_request "Rust handoff HTTP/1.1" "phxp Rust handoff example" "1.1" \
    --http1.1 \
    --resolve "${RUST_HOST}:${PLAY_PUBLIC_PORT}:127.0.0.1" \
    "https://${RUST_HOST}:${PLAY_PUBLIC_PORT}/handoff-http1"
  perform_request "Rust handoff HTTP/2" "phxp Rust handoff example" "2" \
    --http2 \
    --resolve "${RUST_HOST}:${PLAY_PUBLIC_PORT}:127.0.0.1" \
    "https://${RUST_HOST}:${PLAY_PUBLIC_PORT}/handoff-http2"

  perform_request "Relay fallback" "s_server" "any" \
    --http1.1 \
    --resolve "${RELAY_HOST}:${PLAY_PUBLIC_PORT}:127.0.0.1" \
    "https://${RELAY_HOST}:${PLAY_PUBLIC_PORT}/relay"

  printf '\nDaemon counters\n'
  daemon_cli proxy status | sed 's/^/  /'
}

show_logs() {
  ensure_state_dirs
  local requested="${1:-all}"
  local selected=()
  case "${requested}" in
  all)
    selected=("${SERVICES[@]}")
    ;;
  daemon | elixir | rust | relay)
    selected=("${requested}")
    ;;
  *)
    die "unknown service '${requested}'; use daemon, elixir, rust, relay, or all"
    ;;
  esac

  local service
  for service in "${selected[@]}"; do
    printf '==> %s <==\n' "${service}"
    if [[ -f "$(log_file "${service}")" ]]; then
      tail -n 80 "$(log_file "${service}")"
    else
      printf '(no log yet)\n'
    fi
    printf '\n'
  done
}

case "${1:-}" in
__run)
  [[ $# -ge 3 ]] || die "internal service runner requires a name and command"
  service="$2"
  shift 2
  supervise "${service}" "$@"
  ;;
build)
  build_playground
  ;;
up)
  start_playground
  ;;
down)
  stop_playground
  ;;
status)
  show_status
  ;;
try)
  try_playground
  ;;
logs)
  show_logs "${2:-all}"
  ;;
*)
  die "usage: $0 <build|up|down|status|try|logs [service]>"
  ;;
esac

#!/usr/bin/env bash
set -euo pipefail

units=(phx-port.service phx-port-ipv4.socket phx-port-ipv6.socket)
public_environment=(
    PHX_PORT_INGRESS_CONFIG=/etc/phx-port/ingress.toml
    PHX_PORT_CONFIG=/var/lib/phx-port/ports.toml
    PHX_PORT_RUNTIME_DIR=/run/phx-port
)

fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

service_cli() {
    sudo -u phx-port -g phx-port -- env "${public_environment[@]}" \
        /usr/local/bin/phx-port "$@"
}

control_cli() {
    sudo -n -- env "${public_environment[@]}" /usr/local/bin/phx-port "$@"
}

configuration_check() {
    service_cli proxy config check --file /etc/phx-port/ingress.toml
}

wait_live() {
    local attempt
    for attempt in {1..50}; do
        if control_cli proxy check --live >/dev/null 2>&1; then
            printf 'Public ingress is live; use just public-check to require route readiness.\n'
            return
        fi
        if ! sudo -n systemctl is-active --quiet phx-port.service; then
            sudo -n journalctl --no-pager -u phx-port.service -n 30 >&2
            fail "public ingress stopped before its control endpoint became live"
        fi
        sleep 0.2
    done
    control_cli proxy check --live
}

action="${1:-}"
if (( $# > 0 )); then
    shift
fi
case "$action" in
    on)
        (( $# == 0 )) || fail "on takes no arguments"
        configuration_check
        sudo systemctl enable --now "${units[@]}"
        wait_live
        ;;
    off)
        (( $# == 0 )) || fail "off takes no arguments"
        sudo systemctl disable --now "${units[@]}"
        ;;
    restart)
        (( $# == 0 )) || fail "restart takes no arguments"
        if ! sudo systemctl is-active --quiet phx-port.service; then
            fail "public ingress is not running; use just public-on to activate it"
        fi
        configuration_check
        sudo systemctl try-restart phx-port.service
        wait_live
        ;;
    status)
        (( $# == 0 )) || fail "status takes no arguments"
        sudo systemctl --no-pager show "${units[@]}" \
            --property=Id,LoadState,ActiveState,SubState,UnitFileState
        ;;
    check)
        (( $# == 0 )) || fail "check takes no arguments"
        sudo -v
        control_cli proxy check --live
        control_cli proxy check --ready
        control_cli proxy routes
        ;;
    logs)
        (( $# == 0 )) || fail "logs takes no arguments"
        sudo journalctl --no-pager -u phx-port.service -n 100
        ;;
    port)
        (( $# == 2 )) || fail "usage: port WORKLOAD ROLE"
        service_cli --workload-id "$1" "$2" | cat
        ;;
    *)
        fail "usage: public-service.sh on|off|restart|status|check|logs|port WORKLOAD ROLE"
        ;;
esac

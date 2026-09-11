#!/usr/bin/env bash
set -euo pipefail

fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

require_regular_destination() {
    if [[ -L "$1" || ( -e "$1" && ! -f "$1" ) ]]; then
        fail "refusing non-regular installation target: $1"
    fi
}

atomic_install() (
    local source="$1" destination="$2" mode="$3" owner="$4" group="$5" staged
    require_regular_destination "$destination"
    staged="$(mktemp -- "$destination.XXXXXX")"
    trap 'rm -f -- "$staged"' EXIT
    install -o "$owner" -g "$group" -m "$mode" -- "$source" "$staged"
    if (( $# == 6 )); then
        "$6" "$staged"
    fi
    mv -fT -- "$staged" "$destination"
)

bootstrap_policy() (
    local source="$1" destination="$2" state="$3" owner="$4" group="$5" entry staged
    require_regular_destination "$destination"
    if [[ -f "$destination" ]]; then
        printf 'Keeping existing policy: %s\n' "$destination"
        return
    fi
    for entry in ports.toml routes.toml route-claims.toml; do
        if [[ -e "$state/$entry" || -L "$state/$entry" ]]; then
            fail "public state exists but ingress.toml is missing; restore the policy instead of bootstrapping"
        fi
    done
    staged="$(mktemp -- "$destination.XXXXXX")"
    trap 'rm -f -- "$staged"' EXIT
    install -o "$owner" -g "$group" -m 0640 -- "$source" "$staged"
    # Exclusive publication preserves a policy created by another operator.
    ln -- "$staged" "$destination"
    rm -- "$staged"
    printf 'Created certificate-discovery policy: %s\n' "$destination"
)

validate_release() {
    sudo -n -u phx-port -g phx-port -- env \
        PHX_PORT_INGRESS_CONFIG=/etc/phx-port/ingress.toml \
        PHX_PORT_CONFIG=/var/lib/phx-port/ports.toml \
        PHX_PORT_RUNTIME_DIR=/run/phx-port \
        "$1" proxy config check --file /etc/phx-port/ingress.toml
}

install_public() (
    (( $# == 1 )) || fail "usage: install-public.sh RELEASE_BINARY"
    (( EUID == 0 )) || fail "run through 'just install-public' (installation requires sudo)"
    [[ -f "$1" && -x "$1" ]] || fail "release binary is missing or not executable: $1; run 'just deploy-public'"
    local package unit
    package="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
    umask 077
    exec 9>/etc/phx-port/.deploy.lock
    flock --exclusive 9
    install -d -o root -g root -m 0755 /usr/local/bin /etc/systemd/system

    require_regular_destination /usr/local/bin/phx-port
    for unit in phx-port.service phx-port-ipv4.socket phx-port-ipv6.socket; do
        require_regular_destination "/etc/systemd/system/$unit"
        [[ -f "$package/$unit" ]] || fail "missing packaged unit: $unit"
    done

    bootstrap_policy "$package/ingress.toml" /etc/phx-port/ingress.toml \
        /var/lib/phx-port root phx-port
    atomic_install "$1" /usr/local/bin/phx-port 0755 root root validate_release
    systemd-analyze verify --man=no "$package/phx-port.service" \
        "$package/phx-port-ipv4.socket" "$package/phx-port-ipv6.socket"
    for unit in phx-port.service phx-port-ipv4.socket phx-port-ipv6.socket; do
        atomic_install "$package/$unit" "/etc/systemd/system/$unit" 0644 root root
    done
    systemctl daemon-reload
    printf '%s\n' \
        'Public release and units installed; service running/enabled state was not changed.' \
        'Use just public-on to activate, or just public-restart to load the release if already running.'
)

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    install_public "$@"
fi

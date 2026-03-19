#!/bin/bash
set -euo pipefail

# Omarchy desktop integration for phx-port
# Installs the "Disco" app launcher (phx-port discover) with a disco ball icon.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ICONS_DIR="$HOME/.local/share/applications/icons"
APPS_DIR="$HOME/.local/share/applications"

PHX_PORT="$(command -v phx-port 2>/dev/null || echo "")"
if [ -z "$PHX_PORT" ]; then
    echo "Error: phx-port not found on PATH. Install it first with: cargo install --path ."
    exit 1
fi

mkdir -p "$ICONS_DIR"

cp "$SCRIPT_DIR/Disco.svg" "$ICONS_DIR/Disco.svg"

cat > "$APPS_DIR/Disco.desktop" <<EOF
[Desktop Entry]
Version=1.0
Name=Disco
Comment=Discover Phoenix LiveView ports
Exec=$PHX_PORT discover
Terminal=false
Type=Application
Icon=$ICONS_DIR/Disco.svg
StartupNotify=true
Categories=Development;
EOF

update-desktop-database "$APPS_DIR" 2>/dev/null || true

echo "Installed Disco app launcher (using $PHX_PORT)"

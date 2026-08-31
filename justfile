default:
    @just --list

build:
    cargo build

release:
    cargo build --release

install:
    cargo install --path .

test:
    cargo test

check:
    cargo clippy -- -D warnings

fmt:
    cargo fmt

fmt-check:
    cargo fmt -- --check

# PHXP socket-handoff samples

# Start the Rust sample with the Alpha certificate
start-rust:
    #!/usr/bin/env bash
    set -euo pipefail
    cd samples/rust
    CERT_DIR="${PHXP_CERT_DIR:-$HOME/.dns/production}"
    HOST="${PHXP_HOST:-alpha.phx-port.pollmann.rocks}"
    HTTP_PORT="${HTTP_PORT:-$(phx-port)}"
    HTTPS_PORT="${HTTPS_PORT:-$(phx-port https)}"
    echo "Rust: http://localhost:$HTTP_PORT, https://$HOST:$HTTPS_PORT/"
    exec cargo run -- \
      --http "127.0.0.1:$HTTP_PORT" \
      --https "127.0.0.1:$HTTPS_PORT" \
      --cert "$CERT_DIR/$HOST.crt" \
      --key "$CERT_DIR/$HOST.key" \
      --role https

# Show all Rust sample ingress paths
show-rust:
    @samples/show.sh rust Rust "${PHXP_HOST:-alpha.phx-port.pollmann.rocks}"

# Report whether the Rust sample is running
status-rust:
    @samples/manage.sh status rust Rust

# Stop the Rust sample
stop-rust:
    @samples/manage.sh stop rust Rust

# Start the .NET 10 sample with the Beta certificate
start-dotnet:
    #!/usr/bin/env bash
    set -euo pipefail
    cd samples/dotnet
    CERT_DIR="${PHXP_CERT_DIR:-$HOME/.dns/production}"
    HOST="${PHXP_HOST:-beta.phx-port.pollmann.rocks}"
    HTTP_PORT="${HTTP_PORT:-$(phx-port)}"
    HTTPS_PORT="${HTTPS_PORT:-$(phx-port https)}"
    echo ".NET: http://localhost:$HTTP_PORT, https://$HOST:$HTTPS_PORT/"
    exec dotnet run -- \
      --project "$PWD" \
      --role https \
      --http-port "$HTTP_PORT" \
      --https-port "$HTTPS_PORT" \
      --cert "$CERT_DIR/$HOST.crt" \
      --key "$CERT_DIR/$HOST.key"

# Show all .NET sample ingress paths
show-dotnet:
    @samples/show.sh dotnet ".NET 10" "${PHXP_HOST:-beta.phx-port.pollmann.rocks}"

# Report whether the .NET sample is running
status-dotnet:
    @samples/manage.sh status dotnet ".NET 10"

# Stop the .NET sample
stop-dotnet:
    @samples/manage.sh stop dotnet ".NET 10"

# Start the minimal Elixir/Bandit sample with the Alias Alpha certificate
start-elixir:
    #!/usr/bin/env bash
    set -euo pipefail
    cd samples/elixir
    CERT_DIR="${PHXP_CERT_DIR:-$HOME/.dns/production}"
    HOST="${PHXP_HOST:-alias-alpha.phx-port.pollmann.rocks}"
    export PORT="${PORT:-$(phx-port)}"
    export HTTPS_PORT="${HTTPS_PORT:-$(phx-port https)}"
    echo "Elixir: http://localhost:$PORT, https://$HOST:$HTTPS_PORT/"
    exec mix run --no-halt -- \
      --cert "$CERT_DIR/$HOST.crt" \
      --key "$CERT_DIR/$HOST.key"

# Show all Elixir sample ingress paths
show-elixir:
    @samples/show.sh elixir Elixir "${PHXP_HOST:-alias-alpha.phx-port.pollmann.rocks}"

# Report whether the Elixir sample is running
status-elixir:
    @samples/manage.sh status elixir Elixir

# Stop the Elixir sample
stop-elixir:
    @samples/manage.sh stop elixir Elixir

# Show the stable ports assigned to every language sample
ports-samples:
    #!/usr/bin/env bash
    set -euo pipefail
    for sample in samples/rust samples/dotnet samples/elixir; do
      (
        cd "$sample"
        printf '%-20s http=%s https=%s\n' "$sample" "$(phx-port)" "$(phx-port https)"
      )
    done

# VS Code extension tasks

vscode-compile:
    cd vscode-extension && npm install --quiet && npm run compile

vscode-package: vscode-compile
    cd vscode-extension && npx @vscode/vsce package --no-dependencies

vscode-install: vscode-package
    code --install-extension vscode-extension/phx-port-*.vsix

vscode-uninstall:
    code --uninstall-extension chgeuer.phx-port

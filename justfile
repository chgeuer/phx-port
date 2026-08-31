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

# PHXP socket-handoff examples

# Start the Rust HTTP/HTTPS and PHXP handoff server with the Alpha certificate
start-rust:
    #!/usr/bin/env bash
    set -euo pipefail
    MANIFEST="$PWD/integrations/rust/phxp_handoff_server/Cargo.toml"
    cd /home/chgeuer/src_work/phx_port_alpha
    HTTP_PORT="${HTTP_PORT:-$(phx-port)}"
    HTTPS_PORT="${HTTPS_PORT:-$(phx-port https)}"
    echo "Rust: http://localhost:$HTTP_PORT, https://alpha.phx-port.pollmann.rocks:$HTTPS_PORT/"
    exec cargo run --manifest-path "$MANIFEST" -- \
      --http "127.0.0.1:$HTTP_PORT" \
      --https "127.0.0.1:$HTTPS_PORT" \
      --cert /home/chgeuer/src_work/phx_port_alpha/priv/certs/production/alpha.phx-port.pollmann.rocks.crt \
      --key /home/chgeuer/src_work/phx_port_alpha/priv/certs/production/alpha.phx-port.pollmann.rocks.key \
      --role https

# Show direct HTTP, direct HTTPS, and public handoff responses from the Rust server
show-rust:
    #!/usr/bin/env bash
    set -euo pipefail
    cd /home/chgeuer/src_work/phx_port_alpha
    HTTP_PORT="${HTTP_PORT:-$(phx-port)}"
    HTTPS_PORT="${HTTPS_PORT:-$(phx-port https)}"
    PUBLIC_HTTPS_PORT="${PUBLIC_HTTPS_PORT:-443}"
    echo "=== Direct HTTP :$HTTP_PORT ==="
    curl --fail --silent --show-error "http://127.0.0.1:$HTTP_PORT/"
    echo "=== Direct HTTPS :$HTTPS_PORT ==="
    curl --fail --silent --show-error \
      --resolve "alpha.phx-port.pollmann.rocks:$HTTPS_PORT:127.0.0.1" \
      "https://alpha.phx-port.pollmann.rocks:$HTTPS_PORT/"
    echo "=== Public HTTPS handoff :$PUBLIC_HTTPS_PORT ==="
    curl --fail --silent --show-error \
      --resolve "alpha.phx-port.pollmann.rocks:$PUBLIC_HTTPS_PORT:127.0.0.1" \
      "https://alpha.phx-port.pollmann.rocks:$PUBLIC_HTTPS_PORT/"

# Start the .NET 10 HTTP/HTTPS and PHXP handoff server with the Beta certificate
start-dotnet:
    #!/usr/bin/env bash
    set -euo pipefail
    PROJECT="$PWD/integrations/dotnet/phxp-handoff-server/PhxpHandoffServer.csproj"
    cd /home/chgeuer/src_work/phx_port_beta
    HTTP_PORT="${HTTP_PORT:-$(phx-port)}"
    HTTPS_PORT="${HTTPS_PORT:-$(phx-port https)}"
    echo ".NET: http://localhost:$HTTP_PORT, https://beta.phx-port.pollmann.rocks:$HTTPS_PORT/"
    exec dotnet run --project "$PROJECT" -- \
      --project "$PWD" \
      --role https \
      --http-port "$HTTP_PORT" \
      --https-port "$HTTPS_PORT" \
      --cert /home/chgeuer/src_work/phx_port_beta/priv/certs/production/beta.phx-port.pollmann.rocks.crt \
      --key /home/chgeuer/src_work/phx_port_beta/priv/certs/production/beta.phx-port.pollmann.rocks.key

# Show direct HTTP, direct HTTPS, and public handoff responses from the .NET server
show-dotnet:
    #!/usr/bin/env bash
    set -euo pipefail
    cd /home/chgeuer/src_work/phx_port_beta
    HTTP_PORT="${HTTP_PORT:-$(phx-port)}"
    HTTPS_PORT="${HTTPS_PORT:-$(phx-port https)}"
    PUBLIC_HTTPS_PORT="${PUBLIC_HTTPS_PORT:-443}"
    echo "=== Direct HTTP :$HTTP_PORT ==="
    curl --fail --silent --show-error "http://127.0.0.1:$HTTP_PORT/"
    echo "=== Direct HTTPS :$HTTPS_PORT ==="
    curl --fail --silent --show-error \
      --resolve "beta.phx-port.pollmann.rocks:$HTTPS_PORT:127.0.0.1" \
      "https://beta.phx-port.pollmann.rocks:$HTTPS_PORT/"
    echo "=== Public HTTPS handoff :$PUBLIC_HTTPS_PORT ==="
    curl --fail --silent --show-error \
      --resolve "beta.phx-port.pollmann.rocks:$PUBLIC_HTTPS_PORT:127.0.0.1" \
      "https://beta.phx-port.pollmann.rocks:$PUBLIC_HTTPS_PORT/"

# Show the stable ports assigned to both cross-language examples
ports-examples:
    #!/usr/bin/env bash
    set -euo pipefail
    for example in \
      /home/chgeuer/src_work/phx_port_alpha \
      /home/chgeuer/src_work/phx_port_beta
    do
      (
        cd "$example"
        printf '%-50s http=%s https=%s\n' "$example" "$(phx-port)" "$(phx-port https)"
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

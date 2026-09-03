rust_hostname := "alpha.phx-port.pollmann.rocks"
dotnet_hostname := "beta.phx-port.pollmann.rocks"
elixir_hostname := "alias-alpha.phx-port.pollmann.rocks"
go_hostname := "a.pollmann.rocks"
python_hostname := "b.pollmann.rocks"
node_hostname := "c.pollmann.rocks"

default:
    @just --list

build:
    cargo build --locked

release:
    cargo build --release --locked

install:
    cargo install --path . --locked

test:
    cargo test --locked

check:
    cargo clippy --locked -- -D warnings

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
    HOST="${PHXP_HOST:-{{ rust_hostname }}}"
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
    @samples/show.sh rust Rust "${PHXP_HOST:-{{ rust_hostname }}}"

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
    HOST="${PHXP_HOST:-{{ dotnet_hostname }}}"
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
    @samples/show.sh dotnet ".NET 10" "${PHXP_HOST:-{{ dotnet_hostname }}}"

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
    HOST="${PHXP_HOST:-{{ elixir_hostname }}}"
    export PORT="${PORT:-$(phx-port)}"
    export HTTPS_PORT="${HTTPS_PORT:-$(phx-port https)}"
    echo "Elixir: http://localhost:$PORT, https://$HOST:$HTTPS_PORT/"
    exec mix run --no-halt -- \
      --cert "$CERT_DIR/$HOST.crt" \
      --key "$CERT_DIR/$HOST.key"

# Show all Elixir sample ingress paths
show-elixir:
    @samples/show.sh elixir Elixir "${PHXP_HOST:-{{ elixir_hostname }}}"

# Report whether the Elixir sample is running
status-elixir:
    @samples/manage.sh status elixir Elixir

# Stop the Elixir sample
stop-elixir:
    @samples/manage.sh stop elixir Elixir

# Build the Go net/http PHXP sample
build-go:
    mkdir -p target/samples
    cd samples/go && go build -o ../../target/samples/phxp-http ./cmd/phxp-http

# Test the Go PHXP adapter, including descriptor races
test-go:
    cd samples/go && go vet ./... && go test -race ./...

# Start the Go net/http sample with the a.pollmann.rocks certificate
start-go:
    #!/usr/bin/env bash
    set -euo pipefail
    cd samples/go
    CERT_DIR="${PHXP_CERT_DIR:-$HOME/.dns/production}"
    HOST="${PHXP_HOST:-{{ go_hostname }}}"
    HTTPS_PORT="${HTTPS_PORT:-$(phx-port https)}"
    echo "Go: https://$HOST:$HTTPS_PORT/"
    exec ../../target/samples/phxp-http \
      -https "127.0.0.1:$HTTPS_PORT" \
      -cert "$CERT_DIR/$HOST.crt" \
      -key "$CERT_DIR/$HOST.key"

# Show direct and PHXP-ingress responses from the Go sample
show-go:
    @bash samples/show-tls.sh go Go "${PHXP_HOST:-{{ go_hostname }}}" "phxp Go handoff example"

# Create the Python environment and install the FastAPI PHXP sample
setup-python:
    python3 -m venv samples/python/.venv
    samples/python/.venv/bin/python -m pip install --quiet -e 'samples/python[test]'

# Build-check the Python/FastAPI PHXP sample
build-python: setup-python
    samples/python/.venv/bin/python -m compileall -q samples/python/src samples/python/tests

# Test and lint the Python/FastAPI PHXP adapter
test-python: setup-python
    cd samples/python && .venv/bin/ruff format --check . && .venv/bin/ruff check . && .venv/bin/pytest -q

# Start the Python/FastAPI sample with the b.pollmann.rocks certificate
start-python:
    #!/usr/bin/env bash
    set -euo pipefail
    cd samples/python
    test -x .venv/bin/phxp-fastapi || {
      echo "Python sample is not installed; run 'just setup-python'." >&2
      exit 1
    }
    CERT_DIR="${PHXP_CERT_DIR:-$HOME/.dns/production}"
    HOST="${PHXP_HOST:-{{ python_hostname }}}"
    HTTPS_PORT="${HTTPS_PORT:-$(phx-port https)}"
    echo "Python: https://$HOST:$HTTPS_PORT/"
    exec .venv/bin/phxp-fastapi \
      --https "127.0.0.1:$HTTPS_PORT" \
      --cert "$CERT_DIR/$HOST.crt" \
      --key "$CERT_DIR/$HOST.key"

# Show direct and PHXP-ingress responses from the Python sample
show-python:
    @bash samples/show-tls.sh python Python "${PHXP_HOST:-{{ python_hostname }}}" "phxp Python handoff example"

# Install and build the Node/Fastify native PHXP addon from its lockfile
build-node:
    cd samples/node && npm ci --no-audit --no-fund

# Test the Node/Fastify PHXP adapter
test-node: build-node
    cd samples/node && npm test

# Start the Node/Fastify sample with the c.pollmann.rocks certificate
start-node:
    #!/usr/bin/env bash
    set -euo pipefail
    cd samples/node
    test -f build/Release/phxp_native.node || {
      echo "Node sample is not built; run 'just build-node'." >&2
      exit 1
    }
    CERT_DIR="${PHXP_CERT_DIR:-$HOME/.dns/production}"
    HOST="${PHXP_HOST:-{{ node_hostname }}}"
    export PORT="${PORT:-$(phx-port https)}"
    export PHXP_TLS_CERT="$CERT_DIR/$HOST.crt"
    export PHXP_TLS_KEY="$CERT_DIR/$HOST.key"
    echo "Node: https://$HOST:$PORT/"
    exec node src/sample.js

# Show direct and PHXP-ingress responses from the Node sample
show-node:
    @bash samples/show-tls.sh node Node "${PHXP_HOST:-{{ node_hostname }}}" "shared Fastify HTTPS pipeline"

# Build all Go, Python, and Node framework adapters
build-frameworks: build-go build-python build-node

# Test all Go, Python, and Node framework adapters
test-frameworks: test-go test-python test-node

# Exercise each framework through a real phx-port daemon and require zero relay
e2e-frameworks: build build-frameworks
    @bash samples/framework-e2e.sh go "{{ go_hostname }}" "phxp Go handoff example"
    @bash samples/framework-e2e.sh python "{{ python_hostname }}" "phxp Python handoff example"
    @bash samples/framework-e2e.sh node "{{ node_hostname }}" "shared Fastify HTTPS pipeline"

# Show the stable ports assigned to every language sample
ports-samples:
    #!/usr/bin/env bash
    set -euo pipefail
    for sample in samples/rust samples/dotnet samples/elixir samples/go samples/python samples/node; do
      (
        cd "$sample"
        printf '%-20s http=%s https=%s\n' "$sample" "$(phx-port)" "$(phx-port https)"
      )
    done

# Build the daemon plus the Rust and Elixir handoff samples
play-build:
    @bash samples/playground.sh build

# Start the trusted playground on 0.0.0.0/[::]:443
play-up: play-build
    @bash samples/playground.sh up

# Start the playground and exercise its direct, handoff, and relay paths
play: play-up
    @bash samples/playground.sh try

# Show playground processes, listeners, routes, and daemon counters
play-status:
    @bash samples/playground.sh status

# Exercise HTTP/1.1, HTTP/2, IPv6, handoff, and relay paths
play-try:
    @bash samples/playground.sh try

# Show recent playground logs: all, daemon, elixir, rust, or relay
play-logs service="all":
    @bash samples/playground.sh logs "{{ service }}"

# Stop only the processes managed by the playground
play-down:
    @bash samples/playground.sh down

# VS Code extension tasks

vscode-compile:
    cd vscode-extension && npm install --quiet && npm run compile

vscode-package: vscode-compile
    cd vscode-extension && npx @vscode/vsce package --no-dependencies

vscode-install: vscode-package
    code --install-extension vscode-extension/phx-port-*.vsix

vscode-uninstall:
    code --uninstall-extension chgeuer.phx-port

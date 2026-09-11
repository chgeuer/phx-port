# Local development

Development mode needs no daemon, root account, ingress file, or service
manager.

## Install

```bash
cargo install --git https://github.com/chgeuer/phx-port --locked
phx-port --version
```

## Allocate stable ports

Run the command from the project directory:

```bash
PORT="$(phx-port)" exec your-server
```

Named roles give one project multiple stable ports:

```bash
PORT="$(phx-port)" \
METRICS_PORT="$(phx-port metrics)" \
DEBUG_PORT="$(phx-port debug)" \
exec your-server
```

The default registry is `~/.config/phx-ports.toml`. Override it only when you
intentionally want a separate registry:

```bash
export PHX_PORT_CONFIG="$HOME/.config/work-phx-ports.toml"
```

Port `4000` remains unallocated. New assignments start at `4001` and reuse
gaps.

## Use with common stacks

```bash
# Phoenix
PORT="$(phx-port)" iex -S mix phx.server

# Node
PORT="$(phx-port)" npm run dev

# Python
uvicorn app:app --host 127.0.0.1 --port "$(phx-port)"

# Go
PORT="$(phx-port)" go run ./cmd/server
```

The application must actually read the supplied port. `phx-port` allocates and
prints a number; it does not start or configure the application.

## Inspect and manage local assignments

```bash
phx-port list
phx-port list --flat
phx-port running
phx-port discover
phx-port open
phx-port open metrics
```

Explicit registration and deletion:

```bash
phx-port register
phx-port register metrics
phx-port delete . metrics
phx-port delete .
```

Deleting an assignment does not stop a process already using that port.

## Optional local TLS/SNI daemon

Start HTTPS Workloads on stable loopback ports:

```bash
HTTPS_PORT="$(phx-port https)" exec your-tls-server
```

Start the development daemon:

```bash
PHX_PORT_BIN="$(command -v phx-port)"
sudo env \
  HOME="$HOME" \
  XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" \
  PHX_PORT_CONFIG="${PHX_PORT_CONFIG:-$HOME/.config/phx-ports.toml}" \
  "$PHX_PORT_BIN" daemon --run-as "$USER" \
  --listen 0.0.0.0:443 \
  --listen '[::]:443'
```

The explicit environment is required because `sudo` commonly changes `HOME`
to `/root` and removes `XDG_RUNTIME_DIR`. `--run-as` changes process identity;
it does not reconstruct the target user's development environment.

The Workload owns its certificate and private key. The daemon peeks at SNI,
verifies the Workload certificate, and either hands off the original socket to
a compatible PHXP receiver or relays encrypted bytes. It never terminates TLS.

### Wildcard certificates

A new `https` listener's no-SNI default certificate can announce an entire
development wildcard route, such as `*.dev.example.com`, before any browser
request. The daemon first treats SANs as candidates, then verifies a trusted
TLS handshake for `a.dev.example.com` and checks that the returned certificate
contains that same wildcard DNS SAN. An untrusted certificate or an exact-only
certificate for the probe hostname cannot authorize the pattern.

One verified pattern serves every single nonempty label beneath its suffix:
`foo.dev.example.com` and `bar.dev.example.com` use the same Workload. It does
not match `dev.example.com`, `deep.foo.dev.example.com`, or suffix lookalikes.
The Workload must present a valid certificate for those concrete SNI names;
the daemon does not alter SNI, enumerate subdomains, configure DNS, or renew
certificates. Strictly SNI-only listeners and compatibility `main` HTTPS roles
learn the same kind of pattern lazily from a verified concrete request.

Verified exact routes take precedence. Duplicate wildcard owners fail closed
without an incumbent; an existing valid incumbent remains selected and the
contender is reported as a conflict. Cached patterns are only hints and need a
fresh trusted proof after daemon restart. Certificate revalidation, expiry,
TCP failure, and registration removal apply to the whole pattern.
`proxy routes` shows `*.dev.example.com`; `discover` shows a pattern label,
not a clickable wildcard URL.

**Public mode defaults to exact operator Route Declarations.** Production
automatic exact/wildcard routing requires the explicit
[`certificate_discovery` policy](public-server.md#opt-in-certificate-driven-production-routing),
which uses logical HTTPS registrations and durable claims, rejects
same-specificity incumbents on conflict, and never falls through an inactive
exact ownership claim to a wildcard. Development's incumbent and lifecycle
rules above are not the production automatic-policy contract.

For an unprivileged high-port exercise:

```bash
phx-port daemon --listen 127.0.0.1:8443
```

Inspect it:

```bash
phx-port proxy status
phx-port proxy routes
phx-port proxy stop
```

On Linux, the convenience user service is development-only:

```bash
phx-port proxy install-service
phx-port proxy uninstall-service
```

It is not the hardened public `systemd` deployment.

## PHXP integrations

Reference integrations and runnable Workloads:

- Elixir/Bandit: `phx_port_handoff/`
- Rust/Axum: `samples/rust/`
- .NET 10 on Linux: `samples/dotnet/`
- Go `net/http`: `samples/go/`
- Python FastAPI/Uvicorn: `samples/python/`
- Node/Fastify: `samples/node/`

The Go, Python, and Node samples use the ordinary framework server for both
their loopback listener and handed-off sockets. Their application middleware,
router, handlers, and TLS behavior therefore do not branch on PHXP.

Build and test them:

```bash
just build-frameworks
just test-frameworks
```

Run one sample in the foreground, then inspect its direct and ingress paths:

```bash
just start-go       # or start-python / start-node
just show-go        # or show-python / show-node
```

The defaults use `a.pollmann.rocks`, `b.pollmann.rocks`, and
`c.pollmann.rocks`, respectively, with keys under
`~/.dns/production`. Override `PHXP_HOST` or `PHXP_CERT_DIR` when using another
trusted local certificate. `start-python` requires `just setup-python`;
`start-node` requires `just build-node`.

Exercise all three against a real high-port daemon:

```bash
just e2e-frameworks
```

This requires the three local certificate fixtures. It uses isolated temporary
registry/runtime state, requires exactly one successful handoff and zero
relays per framework, stops only the PIDs it starts, and removes its state.

## Native regression tests

```bash
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

CI runs the native suite and framework adapters on Linux and macOS, both x64
and ARM64. Separate regressions exercise aliased temporary roots and long
platform `TMPDIR` paths. Unix socket fixtures use short, canonical `/tmp`
paths because macOS's default temporary path can exceed the socket address
limit. A `PHX_PORT_TEST_TMPDIR` override must likewise stay short when running
socket-based fixtures.

Functional eager-discovery tests wait for bounded reconciliation to complete,
including retries after transient probe timeouts. Deadline regressions still
exercise individual passes with unchanged production timeout limits.

The Rust/Elixir local playground separately exercises handoff and relay:

```bash
just play
just play-status
just play-logs daemon
just play-down
```

It expects the test certificates described in the main README.

## Troubleshooting

| Symptom | Action |
|---|---|
| Application still uses its default port | Confirm its command or config reads the variable passed by the shell. |
| Port belongs to the wrong project | Run from the intended directory and inspect `phx-port list --flat`. |
| A stale assignment appears active | `phx-port running` checks listeners; delete only after confirming the old process is stopped. |
| TLS route is absent | Confirm the Workload listens on its registered `https` role and presents a system-trusted certificate for the requested SNI. |
| Port 443 bind fails | Find the existing listener or use a high port; do not run two ingress daemons on the same address. |

Do not set `PHX_PORT_WORKLOAD_ID` for ordinary development. It switches
allocator identity from the project path to a logical production-style ID.

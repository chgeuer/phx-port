# PHXP Rust handoff server

This Linux and macOS standalone example runs three listeners:

- ordinary HTTP,
- ordinary HTTPS,
- the repository's PHXP v1 Unix-domain endpoint.

The PHXP listener performs the `HELLO`/`READY` handshake, receives exactly one
connected TCP descriptor with `SCM_RIGHTS`, acknowledges adoption, performs
server-side TLS on the untouched socket, and feeds it into the same Axum router
as the ordinary listeners. The response includes `peer` and `local`;
on a handed-off socket these are the original client and daemon listener
addresses. The handoff SNI is returned only as diagnostic response metadata; rustls
processes the original ClientHello and does not trust that field for TLS.

The example directly includes the repository's `src/handoff_protocol.rs`, so
its packet codec stays identical to the daemon implementation. It also shares
the native handoff package's nonblocking endpoint liveness probe.

## Build and test

From the repository root:

```bash
cargo build --manifest-path samples/rust/Cargo.toml
cargo test --manifest-path samples/rust/Cargo.toml
```

On Linux, run the endpoint liveness regressions as an unprivileged user under
an external watchdog. The full-queue fixture has only two queued connections
and asserts a 2.5-second startup bound; the permission fixture must not run as root.

```bash
timeout --kill-after=10s 180s cargo test --locked --manifest-path samples/rust/Cargo.toml handoff::
```

## Run

The repository root `justfile` uses the Alpha certificate by default:

```bash
$HOME/.dns/production/alpha.phx-port.pollmann.rocks.crt
$HOME/.dns/production/alpha.phx-port.pollmann.rocks.key
```

From the repository root:

```bash
just start-rust
# In another terminal:
just show-rust
```

For a manual invocation:

```bash
cd samples/rust
export PHXP_TLS_CERT="${PHXP_TLS_CERT:-$HOME/.dns/production/alpha.phx-port.pollmann.rocks.crt}"
export PHXP_TLS_KEY="${PHXP_TLS_KEY:-$HOME/.dns/production/alpha.phx-port.pollmann.rocks.key}"
export HTTP_PORT="${HTTP_PORT:-$(phx-port)}"
export HTTPS_PORT="${HTTPS_PORT:-$(phx-port https)}"

cargo run -- \
  --http "127.0.0.1:$HTTP_PORT" \
  --https "127.0.0.1:$HTTPS_PORT" \
  --role https
```

Then start the daemon (privileged port 443 may require the existing service or
appropriate capabilities):

```bash
phx-port daemon --listen 0.0.0.0:443 --listen '[::]:443'
```

Direct checks:

```bash
curl http://127.0.0.1:HTTP_PORT/
curl --resolve 'alpha.phx-port.pollmann.rocks:HTTPS_PORT:127.0.0.1' \
  https://alpha.phx-port.pollmann.rocks:HTTPS_PORT/
```

A request to `https://alpha.phx-port.pollmann.rocks/` through the daemon uses
handoff once the daemon has discovered that the ordinary HTTPS listener's
certificate validates for that hostname.

All settings have CLI and environment forms:

| CLI | Environment | Default |
|---|---|---|
| `--http ADDR` | `PHXP_HTTP_ADDR` | `127.0.0.1:8080` |
| `--https ADDR` | `PHXP_HTTPS_ADDR` | `127.0.0.1:8443` |
| `--cert PATH` | `PHXP_TLS_CERT` | required |
| `--key PATH` | `PHXP_TLS_KEY` | required |
| `--project PATH` | `PHXP_PROJECT` | current directory |
| `--workload-id ID` | `PHXP_WORKLOAD_ID` | unset |
| `--role NAME` | `PHXP_ROLE` | `https` |
| `--handoff-socket PATH` | `PHXP_HANDOFF_SOCKET` | PHXP-derived path |
| `--max-connections N` | `PHXP_MAX_CONNECTIONS` | `128` |
| `--max-control-workers N` | `PHXP_MAX_CONTROL_WORKERS` | `16` |

Without `PHXP_WORKLOAD_ID`, the derived development endpoint is
`$XDG_RUNTIME_DIR/phx-port/handoff/<hash>.sock` on Linux and
`/tmp/phx-port-<euid>/handoff/<hash>.sock` on macOS. Set
`PHX_PORT_RUNTIME_DIR` to use `<runtime>/handoff/<hash>.sock`, or use
`--handoff-socket` for a complete path override. Derived endpoints validate
both the runtime root and its `handoff` child as private directories. A
complete path override validates only its immediate parent, so it may live
beneath a normally accessible project directory as long as the socket
directory itself is owned by the current user with mode `0700`.

Set `PHXP_WORKLOAD_ID` explicitly to the same value as the allocator's
`PHX_PORT_WORKLOAD_ID` when using a public Route Declaration. The hash then
uses that validated logical Workload ID and role instead of the project path.
This production endpoint defaults to
`/run/phx-port/handoff/<hash>.sock`; `PHX_PORT_RUNTIME_DIR` may override
`/run/phx-port` for a nonstandard deployment, macOS host, or test. The
production runtime root may be group-traversable, but its `handoff` child
remains owned by the service identity with mode `0700`.

Startup probes an existing endpoint without blocking and with a two-second
absolute deadline. Full queues, pending connections, timeouts, and operational
errors fail startup without unlinking the endpoint. Only a refused connection
confirms a stale socket for removal.

## Admission and shutdown

The sample shares one active-connection budget across direct HTTP, direct
HTTPS, and PHXP. A PHXP negotiation reserves a connection permit before
starting a control worker, then transfers that permit with the adopted
socket. Queuing, TLS handshakes, HTTP keep-alive, and serving all retain the
permit until the socket closes, including failures and cancellation.
Draining the adoption channel does not release capacity.

Control workers have an additional independent limit, acquired before
spawning a native thread. When either limit is full, newly accepted sockets
close without another worker or TLS handshake. Existing connections continue
serving; capacity becomes available when they close. Limits must be positive
integers; CLI values override their environment equivalents.

The listeners and connection tasks are supervised. Listener errors, worker
spawn failures, and panics stop serving with a reported error. Ordinary
connection/negotiation failures and overload are counted in fixed-category
summaries at most once per second, plus a final shutdown summary; these logs
do not include SNI, client addresses, or arbitrary error payloads.

Ctrl-C or SIGTERM stops admission, interrupts and joins PHXP control workers,
closes queued adoptions, aborts and reaps active connection tasks, and removes
only this receiver's socket endpoint. Cancellation interrupts Unix control
sockets, never the delivered TCP descriptor from the sender side. Active
connections are closed immediately rather than gracefully drained.

These are bounded example defaults, not a production capacity claim or a
replacement for Workload-specific request, stream, idle, and rate policies.
No privileged setup or ingress service is needed for this admission policy.

The isolated admission regressions generate temporary localhost certificates
with OpenSSL, use ephemeral loopback listeners, and clean up their child
processes. They cover both direct listeners, real PHXP descriptor adoption,
slow negotiations, failure cleanup, and shutdown:

```bash
timeout --kill-after=10s 180s cargo test --locked --manifest-path samples/rust/Cargo.toml --test admission
```

## Scope and limitations

- Linux uses `SOCK_SEQPACKET`, `SO_PEERCRED`, and atomic close-on-exec flags.
  macOS uses `SOCK_STREAM`, `getpeereid`, bounded frame assembly, and explicit
  `FD_CLOEXEC`.
- Axum and Hyper handle HTTP/1.1, HTTP/2, keep-alive, upgrades, request bodies,
  and response framing on all three ingress paths.
- One configured certificate chain/private key is used for both ordinary and
  handed-off TLS. There is no multi-certificate SNI resolver or client auth.
- The PHXP control protocol uses bounded blocking worker threads; adopted TCP
  connections run as supervised Tokio tasks with lifetime permits.
- The sample hostname and certificate directory are configurable through the
  root `justfile`.

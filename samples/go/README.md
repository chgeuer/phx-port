# PHXP Go handoff server

This sample contains an idiomatic, reusable `phxp` package and a `net/http`
TLS server for Linux and macOS. It implements PHXP v1 exactly as used by the
daemon:

- Linux `AF_UNIX` `SOCK_SEQPACKET`; macOS `AF_UNIX` `SOCK_STREAM` with
  explicit, bounded frame accumulation.
- Same-effective-UID authentication with `SO_PEERCRED` on Linux and Darwin
  peer credentials equivalent to `getpeereid(3)`.
- Exactly one `SCM_RIGHTS` connected TCP descriptor per `HANDOFF`.
- `CLOEXEC`, nonblocking, TCP type, connected peer, and local-address checks.
- Duplicate active connection-ID rejection and bounded adoption queues.
- `ADOPTED` only when `Accept` transfers the sole usable Go `net.Conn` to the
  consuming server. Queue saturation or shutdown before that point returns
  `REJECTED`.
- Secure endpoint creation, stale-socket handling, and identity-safe cleanup.

The executable keeps an ordinary loopback HTTPS listener for daemon
certificate verification, direct debugging, and relay fallback. That listener
and the PHXP listener feed one joined `net.Listener`, which is served by one
`net/http.Server` and one Handler/middleware/router stack. The application
pipeline cannot distinguish the ingress path unless it explicitly inspects
ordinary request or connection socket metadata. Handed-off connections retain
their original TCP peer and local addresses. HTTP/1.1 is supported; HTTP/2 is
enabled through standard Go TLS/HTTP negotiation.

## Build and test

```bash
cd samples/go
go vet ./...
go test ./...
go build ./cmd/phxp-http
```

There are no third-party dependencies.

## Run

```bash
cd samples/go
export PHXP_TLS_CERT="$HOME/.dns/production/alpha.phx-port.pollmann.rocks.crt"
export PHXP_TLS_KEY="$HOME/.dns/production/alpha.phx-port.pollmann.rocks.key"
export PHXP_HTTPS_ADDR="127.0.0.1:8443"
go run ./cmd/phxp-http
```

Options have matching environment variables:

| Option | Environment | Default |
|---|---|---|
| `-https` | `PHXP_HTTPS_ADDR` | `127.0.0.1:8443` |
| `-cert` | `PHXP_TLS_CERT` | required |
| `-key` | `PHXP_TLS_KEY` | required |
| `-project` | `PHXP_PROJECT` | current project |
| `-workload-id` | `PHXP_WORKLOAD_ID` | unset |
| `-role` | `PHXP_ROLE` | `https` |
| `-handoff-socket` | `PHXP_HANDOFF_SOCKET` | derived |

Development identities canonicalize the project path before hashing
`project + NUL + role` with SHA-256. On Linux, the default is
`$XDG_RUNTIME_DIR/phx-port/handoff/<hash>.sock`; on macOS it is
`/tmp/phx-port-<euid>/handoff/<hash>.sock`. `PHX_PORT_RUNTIME_DIR` changes the
runtime root.

Production mode requires `PHXP_WORKLOAD_ID` to equal the allocator's
`PHX_PORT_WORKLOAD_ID`. Its logical workload ID and role are hashed. Linux
defaults to `/run/phx-port/handoff/<hash>.sock`; production on macOS requires
an explicit `PHX_PORT_RUNTIME_DIR`.

An explicit endpoint validates only its immediate private parent. A derived
development endpoint validates both its private product runtime root and
`handoff` child. A production runtime root may be group-traversable, but its
`handoff` child remains owned by the effective user with no group/other access.

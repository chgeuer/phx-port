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
addresses. The handoff SNI is printed only as diagnostic metadata; rustls
processes the original ClientHello and does not trust that field for TLS.

The example directly includes the repository's `src/handoff_protocol.rs`, so
its packet codec stays identical to the daemon implementation.

## Build and test

From the repository root:

```bash
cargo build --manifest-path samples/rust/Cargo.toml
cargo test --manifest-path samples/rust/Cargo.toml
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
| `--role NAME` | `PHXP_ROLE` | `https` |
| `--handoff-socket PATH` | `PHXP_HANDOFF_SOCKET` | PHXP-derived path |

The derived endpoint is
`$XDG_RUNTIME_DIR/phx-port/handoff/<hash>.sock` on Linux and
`/tmp/phx-port-<euid>/handoff/<hash>.sock` on macOS. Set
`PHX_PORT_RUNTIME_DIR` to use `<runtime>/handoff/<hash>.sock`, or use
`--handoff-socket` for a complete path override.

## Scope and limitations

- Linux uses `SOCK_SEQPACKET`, `SO_PEERCRED`, and atomic close-on-exec flags.
  macOS uses `SOCK_STREAM`, `getpeereid`, bounded frame assembly, and explicit
  `FD_CLOEXEC`.
- Axum and Hyper handle HTTP/1.1, HTTP/2, keep-alive, upgrades, request bodies,
  and response framing on all three ingress paths.
- One configured certificate chain/private key is used for both ordinary and
  handed-off TLS. There is no multi-certificate SNI resolver or client auth.
- The PHXP control protocol uses blocking worker threads; adopted TCP
  connections run as Tokio tasks.
- The sample hostname and certificate directory are configurable through the
  root `justfile`.

# PHXP Rust handoff server

This Linux-only standalone example runs three listeners:

- ordinary HTTP,
- ordinary HTTPS,
- the repository's PHXP v1 `AF_UNIX` `SOCK_SEQPACKET` endpoint.

The PHXP listener performs the `HELLO`/`READY` handshake, receives exactly one
connected TCP descriptor with `SCM_RIGHTS`, acknowledges adoption, performs
server-side TLS on the untouched socket, and returns the same small HTTP/1.1
response as the ordinary listeners. The response includes `peer` and `local`;
on a handed-off socket these are the original client and daemon listener
addresses. The handoff SNI is printed only as diagnostic metadata; rustls
processes the original ClientHello and does not trust that field for TLS.

The example directly includes the repository's `src/handoff_protocol.rs`, so
its packet codec stays identical to the daemon implementation.

## Build and test

From the repository root:

```bash
cargo build --manifest-path integrations/rust/phxp_handoff_server/Cargo.toml
cargo test --manifest-path integrations/rust/phxp_handoff_server/Cargo.toml
```

## Run

The default certificate and key are the Alpha files:

```bash
/home/chgeuer/src_work/phx_port_alpha/priv/certs/production/alpha.phx-port.pollmann.rocks.crt
/home/chgeuer/src_work/phx_port_alpha/priv/certs/production/alpha.phx-port.pollmann.rocks.key
```

Use the same project path and role registered with `phx-port`. To run this
example as the Alpha workload:

```bash
cd /home/chgeuer/src_work/phx_port_alpha

cargo run \
  --manifest-path /home/chgeuer/github/chgeuer/phx-port/integrations/rust/phxp_handoff_server/Cargo.toml \
  -- \
  --http "127.0.0.1:$(phx-port)" \
  --https "127.0.0.1:$(phx-port https)" \
  --cert /home/chgeuer/src_work/phx_port_alpha/priv/certs/production/alpha.phx-port.pollmann.rocks.crt \
  --key /home/chgeuer/src_work/phx_port_alpha/priv/certs/production/alpha.phx-port.pollmann.rocks.key \
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

`XDG_RUNTIME_DIR` is required unless the handoff socket is overridden.

## Scope and limitations

- Linux only; the handoff transport depends on `SCM_RIGHTS` and
  `SO_PEERCRED`.
- HTTP/1.1 only. Each connection serves one request and closes; there is no
  HTTP/2, keep-alive, WebSocket, graceful shutdown, or production hardening.
- One configured certificate chain/private key is used for both ordinary and
  handed-off TLS. There is no multi-certificate SNI resolver or client auth.
- It uses a thread per TCP connection and is intended as a protocol example,
  not a benchmark or production server.
- The Alpha certificate paths in the test command are machine-specific. Supply
  another certificate and key when running elsewhere.

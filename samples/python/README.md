# PHXP Python handoff server

This sample provides a reusable, typed `phxp` package and a runnable
FastAPI/Uvicorn HTTPS application for Linux and macOS. It implements PHXP v1
without a parallel HTTP parser or response path:

- Linux uses `AF_UNIX/SOCK_SEQPACKET`.
- macOS uses `AF_UNIX/SOCK_STREAM` with explicit fixed-header framing and
  bounded accumulation.
- Control peers must have the same effective UID (`SO_PEERCRED` on Linux,
  `getpeereid(3)` through `ctypes` on macOS).
- Every `HANDOFF` must carry exactly one `SCM_RIGHTS` descriptor.
- Received descriptors must be connected IPv4/IPv6 TCP streams and are made
  nonblocking and close-on-exec before adoption.
- Active connection IDs are unique until Uvicorn reports connection loss.
- Control timeouts, packet size, ancillary data, pending controls, listen
  backlog, and the adoption queue are bounded.
- Endpoint directories and sockets are checked with `lstat`, effective-UID
  ownership, `0700`/`0600` modes, symlink rejection, live-listener detection,
  identity-checked stale replacement, and identity-safe cleanup.
- `ADOPTED` is deferred until the event-loop adoption pump takes irreversible
  ownership, immediately before Uvicorn's TLS transport can consume bytes.
  Queue saturation or shutdown before that point returns `REJECTED`; later
  TLS/application failure closes the adopted socket without relay fallback.
  No descriptor is duplicated during Python adoption.

`PHXPUvicornServer` keeps Uvicorn's ordinary loopback listener and sends PHXP
sockets through `asyncio.loop.connect_accepted_socket`. Both paths use the
same `Config.http_protocol_class`, `ServerState`, ASGI application, lifespan
state, TLS context, FastAPI/Starlette middleware, router, and handlers.
Uvicorn obtains normal `peername` and `sockname` metadata from the original
socket, so PHXP ingress is not exposed to application code except through the
ordinary ASGI `client` and `server` scope values it could already inspect.

TLS and HTTP/1.1 are supported on both paths. Uvicorn does not implement
HTTP/2, so this integration does not claim HTTP/2 support. Adding a separate
HTTP/2 implementation would violate the goal of retaining Uvicorn's normal
protocol machinery.

## Install and test

```bash
cd samples/python
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
.venv/bin/ruff format --check .
.venv/bin/ruff check .
.venv/bin/python -m compileall -q src tests
.venv/bin/pytest -q
```

The pytest base directory and virtual environment are local and ignored.

## Run

```bash
cd samples/python
export PHXP_TLS_CERT="$HOME/.dns/production/alpha.phx-port.pollmann.rocks.crt"
export PHXP_TLS_KEY="$HOME/.dns/production/alpha.phx-port.pollmann.rocks.key"
export PHXP_HTTPS_ADDR="127.0.0.1:8443"
.venv/bin/phxp-fastapi
```

The root route returns the normal ASGI client/server addresses and the
middleware adds `X-PHXP-Pipeline: fastapi-starlette`. `/health` is available
through the same application.

Options have matching environment variables:

| Option | Environment | Default |
|---|---|---|
| `--https` | `PHXP_HTTPS_ADDR` | `127.0.0.1:8443` |
| `--cert` | `PHXP_TLS_CERT` | required |
| `--key` | `PHXP_TLS_KEY` | required |
| `--project` | `PHXP_PROJECT` | current directory |
| `--workload-id` | `PHXP_WORKLOAD_ID` | unset |
| `--role` | `PHXP_ROLE` | `https` |
| `--handoff-socket` | `PHXP_HANDOFF_SOCKET` | derived |

Development identity canonicalizes the project path, then hashes
`project-path + NUL + role` with SHA-256:

```text
Linux: $XDG_RUNTIME_DIR/phx-port/handoff/<hash>.sock
macOS: /tmp/phx-port-<euid>/handoff/<hash>.sock
```

Production identity is selected only by `PHXP_WORKLOAD_ID`; the allocator's
`PHX_PORT_WORKLOAD_ID` is intentionally not consulted:

```text
/run/phx-port/handoff/<sha256(workload-id NUL role)>.sock
```

`PHX_PORT_RUNTIME_DIR` replaces the runtime root in either profile. Production
use on macOS therefore needs that override. An explicit handoff socket checks
its immediate private parent. A derived development endpoint additionally
checks the product runtime root. A production runtime root may be
group-traversable, but its `handoff` child must be owned by the effective user
and grant no group or other permissions.

The sample is intentionally single-process: multiple Uvicorn workers cannot
simultaneously own one PHXP endpoint. The reusable `PHXPListener` can also be consumed directly. After transferring
the socket into a framework, call `adopt()` before that framework can consume
bytes, then arrange for `release()` on connection close. Calling `release()`
without `adopt()` rejects the pending handoff.

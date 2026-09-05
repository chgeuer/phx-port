# PHXP language samples

These intentionally small servers expose three ingress paths:

1. Ordinary HTTP on the sample's stable `main` port.
2. Ordinary HTTPS on its stable `https` port.
3. Original port-443 sockets received from `phx-port` over PHXP.

| Sample | Platforms | TLS implementation | HTTP implementation |
|---|---|---|---|
| [`elixir`](elixir) | Linux, macOS | Erlang/OTP SSL through `PhxPortHandoff` | Bandit and a minimal Plug |
| [`rust`](rust) | Linux, macOS | tokio-rustls | Axum through Hyper, with HTTP/1.1 and HTTP/2 |
| [`dotnet`](dotnet) | Linux | Kestrel | ASP.NET Core middleware through Kestrel, with HTTP/1.1 and HTTP/2 |
| [`go`](go) | Linux, macOS | Go `crypto/tls` | `net/http`, with HTTP/1.1 and HTTP/2 |
| [`python`](python) | Linux, macOS | Python `ssl` through Uvicorn | FastAPI/Starlette through Uvicorn, with HTTP/1.1 |
| [`node`](node) | Linux, macOS | Node.js TLS | Fastify through Node.js HTTP/HTTPS |

Each sample confines PHXP-specific code to authenticating the local control
connection, receiving and validating the descriptor, and adapting that
connected socket to its web server's transport abstraction. Direct and
handed-off requests then use the same application pipeline.

The examples load certificates from `${PHXP_CERT_DIR:-$HOME/.dns/production}`.
Certificates and private keys stay outside the repository. Override
`PHXP_HOST`, `PHXP_CERT_DIR`, or the language-specific certificate variables
documented in each sample to use another hostname.

From the repository root:

```bash
just ports-samples

just start-rust
just show-rust
just status-rust
just stop-rust

just start-dotnet
just show-dotnet
just status-dotnet
just stop-dotnet

just start-elixir
just show-elixir
just status-elixir
just stop-elixir

just start-go
just show-go

just setup-python
just start-python
just show-python

just build-node
just start-node
just show-node
```

Run each `start-*` recipe in its own terminal. The corresponding `show-*`
recipe requests direct HTTP, direct HTTPS, and the public handoff path.

Run the focused tests for the Go, Python, and Node adapters with
`just test-frameworks`. With the local certificate fixtures available,
`just e2e-frameworks` exercises all three against a real daemon and requires
one successful handoff with zero relay fallbacks per framework.

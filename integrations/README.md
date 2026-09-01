# Socket handoff integrations

`phx-port` can pass an accepted Linux or macOS TCP socket to a cooperating
workload over PHXP v1. Linux uses `AF_UNIX/SOCK_SEQPACKET`; macOS uses
`AF_UNIX/SOCK_STREAM` with bounded PHXP frame assembly. The daemon sends the
descriptor with `SCM_RIGHTS`; the workload keeps ownership of TLS and serves
the client on the original connection.

| Integration | Platforms | Handed-off protocol surface |
|---|---|---|
| [`elixir/phx_port_handoff`](elixir/phx_port_handoff) | Linux, macOS | HTTP/1.1, HTTP/2, WebSocket, and the normal Plug pipeline |
| [`../samples/elixir`](../samples/elixir) | Linux, macOS | Plug over ordinary and handed-off Bandit listeners |
| [`../samples/rust`](../samples/rust) | Linux, macOS | Tokio/tokio-rustls transport feeding one Axum router through Hyper |
| [`../samples/dotnet`](../samples/dotnet) | Linux | Custom connection listener feeding direct and handed-off sockets through Kestrel |

All receivers:

- derive the endpoint from the canonical project path and role;
- answer the PHXP `HELLO`/`READY` capability handshake;
- verify the sender is the same user;
- accept exactly one connected stream descriptor per `HANDOFF`;
- preserve the original peer and local addresses;
- perform TLS in the workload with its configured certificate; and
- acknowledge descriptor adoption without making the PHXP SNI field
  authoritative for TLS.

See [`../docs/socket-forwarding-design.md`](../docs/socket-forwarding-design.md)
for the protocol, ownership boundary, security model, and fallback behavior.

The root [`../samples`](../samples) directory and `justfile` provide runnable
cross-language examples.

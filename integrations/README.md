# Socket handoff integrations

`phx-port` can pass an accepted Linux TCP socket to a cooperating workload over
the PHXP v1 `AF_UNIX` `SOCK_SEQPACKET` protocol. The daemon sends the descriptor
with `SCM_RIGHTS`; the workload keeps ownership of TLS and serves the client on
the original connection.

| Integration | Purpose | Handed-off protocol surface |
|---|---|---|
| [`elixir/phx_port_handoff`](elixir/phx_port_handoff) | Reusable Phoenix/Bandit integration | HTTP/1.1, HTTP/2, WebSocket, and the normal Plug pipeline |
| [`../samples/elixir`](../samples/elixir) | Minimal Elixir/Bandit example | Plug over ordinary and handed-off Bandit listeners |
| [`../samples/rust`](../samples/rust) | Standalone Rust interoperability example | Minimal HTTP/1.1 over rustls |
| [`../samples/dotnet`](../samples/dotnet) | Standalone .NET 10 interoperability example | Minimal HTTP/1.1 over `SslStream`; ordinary listeners use Kestrel |

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

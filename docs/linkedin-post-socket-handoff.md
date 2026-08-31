# LinkedIn post: TLS routing with real socket handoff

I extended `phx-port` from stable local port allocation into a dynamic TLS/SNI
router.

The setup:

- Each application gets stable `main` and `https` ports.
- Each application obtains, owns, and reloads its own TLS certificate and
  private key.
- `phx-port` listens on TCP 443 and discovers routes by probing live HTTPS
  workloads.
- A route is activated only when exactly one backend presents a trusted
  certificate valid for the requested SNI hostname.
- Unknown hostnames trigger a bounded lazy scan; verified mappings are
  persisted as derived state.

The generic path is layer-4 TLS passthrough. `phx-port` forwards the untouched
ClientHello and relays encrypted bytes. It never terminates TLS and works with
any TLS server.

For Phoenix/Bandit on Linux, there is now a second path. `phx-port` reads SNI
with `MSG_PEEK`, then passes the accepted port-443 socket to the application
over `SOCK_SEQPACKET` using `SCM_RIGHTS`. The receiver adopts the descriptor
with `:gen_tcp.fdopen/2`, Thousand Island performs server-side TLS, and Bandit
continues through its normal HTTP pipeline.

After the transfer:

- There is no second backend TCP connection.
- There is no lifetime byte relay.
- Phoenix sees the original client address.
- The application remains the TLS endpoint.
- HTTP/1.1, HTTP/2, and LiveView WebSockets use the normal Bandit path.

This relies heavily on the extensibility of Matt Trudel's Thousand Island and
Bandit projects. A custom transport can introduce an externally accepted
socket without forking Bandit or implementing another HTTP stack.

The relay remains the compatibility fallback. Descriptor handoff currently
targets Linux. The Phoenix adapter requires OTP 29+ and the end-to-end verified
Rustler 0.36.2 line; standalone Rust and .NET 10 receivers now exercise the
same protocol without the BEAM.

Implementation and diagrams:
https://github.com/chgeuer/phx-port/blob/master/docs/proxying-without-the-proxy.md

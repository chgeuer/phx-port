# Proxying Without the Proxy: Handing a Live TLS Socket to Phoenix

Most local reverse proxies solve one problem by creating another connection.
They accept traffic on a well-known port, choose a backend, connect to that
backend, and relay bytes between the two sockets:

```text
browser <-- connection A --> proxy <-- connection B --> application
```

That is a perfectly good default. It works with almost any server, it keeps
application changes to a minimum, and TLS passthrough lets the application
retain its certificate and private key. It does, however, mean that the proxy
stays in the data path for the entire connection. The application sees the
proxy as its TCP peer, not the browser, and every byte crosses an additional
local connection.

While extending `phx-port` into a dynamic TLS router, we built a second path
for cooperative Phoenix applications. `phx-port` still accepts the connection
and decides where it belongs, but instead of proxying its bytes, it passes the
already-connected TCP socket to the selected Bandit server. After that
handoff, `phx-port` is gone from the connection.

It is a proxy for connection establishment, but not a proxy for the
established connection.

## From predictable ports to predictable hostnames

`phx-port` originally had a deliberately small job: assign a stable local port
to each project directory. Two applications that would both normally use port
4000 instead receive persistent, collision-free ports:

```bash
PORT="$(phx-port)" mix phx.server
```

Named roles extend the same registry to applications that need more than one
listener:

```bash
PORT="$(phx-port)" \
HTTPS_PORT="$(phx-port https)" \
mix phx.server
```

The `main` role can serve clear HTTP while the `https` role runs the
application's real production-style TLS configuration. Each project owns its
certificate, private key, SNI callback, ALPN configuration, and renewal
lifecycle.

The `phx-port` daemon binds public TCP port 443. When a new connection arrives,
it inspects the TLS ClientHello, extracts the requested SNI hostname, and maps
that hostname to a live registered project. For example:

```text
www.contoso.com  -> /srv/contoso  (https) :4008
www.fabrikam.com -> /srv/fabrikam (https) :4012
```

There is no central certificate configuration in `phx-port`. Instead, the
daemon probes live HTTPS roles and accepts a route only when the backend
completes a system-trusted, hostname-valid TLS handshake. Certificate SANs
support eager discovery, while an unknown incoming SNI name can trigger a
bounded lazy scan. Verified routes are persisted as derived state and removed
from active service when their workload disappears.

This keeps certificate ownership where it belongs: inside the application
that requested and renews the certificate.

## The universal path: opaque TLS relay

Once `phx-port` knows that `www.contoso.com` belongs to port 4008, the portable
implementation is straightforward:

```text
browser
   |
   | TLS for www.contoso.com
   v
phx-port :443
   |
   | opaque TLS bytes
   v
Contoso :4008
```

`phx-port` does not terminate TLS. It forwards the original ClientHello and
then copies encrypted bytes in both directions. The backend performs the
handshake and selects its own certificate. This works for Phoenix, another web
framework, or any TLS-capable process.

The relay is therefore the compatibility path and the safe fallback. Its
tradeoffs are inherent in the two-connection shape:

- The backend's TCP peer is the local proxy.
- The daemon remains active for the lifetime of the connection.
- Traffic traverses two TCP connections and two relay loops.

Headers such as `Forwarded` or `X-Forwarded-For` cannot solve this at layer 4
without terminating and understanding the higher-level protocol. PROXY
protocol could carry peer metadata, but it would require support on both ends
and would still leave the relay in the data path.

## The cooperative path: transfer the real socket

Linux can pass an open file descriptor between processes over a Unix-domain
socket using `sendmsg(2)` and `SCM_RIGHTS`. The descriptor received by the
application refers to the same kernel TCP socket that `phx-port` accepted on
port 443.

For a handoff-enabled backend, the topology becomes:

```text
                            routing only
browser ---> phx-port :443 -------------+
                                           \
                                            v
                                      Bandit / Phoenix
                                           |
                         original TCP socket, direct to browser
```

The sequence is:

1. `phx-port` accepts a client connection on port 443.
2. It peeks at the ClientHello and resolves the SNI route.
3. It connects to the selected application's private Unix
   `SOCK_SEQPACKET` endpoint.
4. The daemon and receiver negotiate the versioned PHXP protocol and verify
   that both processes run as the same user.
5. `phx-port` sends the connected client descriptor with `SCM_RIGHTS`.
6. The receiver adopts it as an Erlang TCP socket and acknowledges ownership.
7. `phx-port` closes its descriptor without calling `shutdown(2)`.
8. Bandit performs TLS and serves HTTP directly over the original connection.

No application bytes are relayed after step 7. Phoenix sees the browser's real
source address through `Plug.Conn.remote_ip`, and the socket still has local
port 443 because it really is the socket accepted on port 443.

## Peeking is the crucial trick

Routing requires reading the SNI hostname before deciding where the connection
goes. TLS also requires the backend to receive the complete, original
ClientHello. A normal `recv(2)` would consume those bytes, leaving the
application with a stream that starts in the middle of the TLS handshake.

`phx-port` instead uses `MSG_PEEK`. Peeking copies bytes out of the kernel
receive queue without advancing it:

```text
kernel receive queue: [ ClientHello ][ later TLS records ... ]
                              |
                              +---- MSG_PEEK ----> SNI parser
```

The parser repeats bounded peeks until it has a complete ClientHello, reaches
the configured size limit, times out, or rejects malformed input. When the
descriptor reaches Phoenix, the ClientHello is still first in the receive
queue. The application's normal TLS stack reads it and remains authoritative
for SNI selection, cipher negotiation, client authentication, and ALPN.

This is also why certificate probing remains necessary even with socket
handoff. Descriptor transfer answers *how* to deliver a connection. A
certificate-validated TLS probe answers *which application* is entitled to
receive a hostname.

## Making an imported descriptor look ordinary to Bandit

Passing an FD is only the kernel-level half of the problem. Bandit normally
expects Thousand Island to accept a socket from a TCP listener, establish
ownership, gather peer metadata, perform the TLS handshake, and then start the
HTTP connection lifecycle.

The `PhxPortHandoff` package provides a custom
`ThousandIsland.Transport`. Its native Rustler receiver:

- binds a private `SOCK_SEQPACKET` endpoint;
- authenticates the daemon with `SO_PEERCRED`;
- receives exactly one connected stream descriptor per handoff;
- imports it through `:gen_tcp.fdopen/2`; and
- transfers ownership to the normal Thousand Island connection process.

The transport caches the kernel peer and local addresses before upgrading the
socket to TLS. It then performs server-side TLS with the same options used by
the application's ordinary HTTPS endpoint and returns a normal SSL socket to
Thousand Island.

After the handshake, there is no special Phoenix request path. HTTP/1.1,
HTTP/2, LiveView WebSockets, Plug, telemetry, and endpoint routing all proceed
through Bandit's usual machinery.

The Phoenix application runs two cooperating listeners:

```text
assigned HTTPS port ----> ordinary Bandit TLS listener
                          - certificate discovery
                          - health checks
                          - direct debugging

private Unix socket ----> handoff-only Bandit listener
                          - original port-443 sockets
                          - same TLS configuration
                          - same Phoenix endpoint
```

Keeping the ordinary HTTPS listener matters. It gives the daemon a
framework-independent way to prove hostname ownership and provides a direct
diagnostic path even if handoff is unavailable.

## Capability detection and safe fallback

Socket handoff is an optimization, not a requirement for joining the routing
system. Each `(project path, role)` pair maps deterministically to a private
Unix socket:

```text
$XDG_RUNTIME_DIR/phx-port/handoff/
  <sha256(canonical-project-path NUL role)>.sock
```

If a compatible receiver is live, `phx-port` attempts handoff. If it is
missing, stale, incompatible, or rejects the connection before descriptor
delivery, the daemon opens the backend's registered HTTPS port and uses the
ordinary TLS relay.

The ownership boundary is intentionally strict. Before a successful
`sendmsg`, relay fallback is safe because the daemon still owns the only client
descriptor. After descriptor delivery, fallback is forbidden: the receiver
may already be using the same kernel socket. A post-delivery failure closes
the connection rather than creating two competing owners.

The receiver's endpoint is also lifecycle-bound to its owning BEAM process.
When that process exits, the native broker closes and unlinks the Unix socket,
so the daemon stops treating the backend as handoff-capable until its
supervisor brings the listener back.

## Security boundaries

The handoff channel is local and deliberately narrow:

- Its parent directory is mode `0700`.
- Each receiver socket is mode `0600`.
- Both peers verify same-user credentials with `SO_PEERCRED`.
- Protocol messages have fixed bounds and a versioned binary format.
- The receiver accepts exactly one connected TCP stream descriptor.
- Duplicate connection identifiers are rejected.
- A live receiver socket is never silently unlinked or replaced.

Private keys never cross this channel. They stay in the Phoenix application,
just as they do on the relay path.

## What this buys us

The combined design supports two kinds of workload behind the same dynamic SNI
router:

| Workload | Delivery | TLS owner | Backend peer address |
|---|---|---|---|
| Any TLS server | Opaque byte relay | Backend | `phx-port` loopback |
| Handoff-enabled Phoenix/Bandit | `SCM_RIGHTS` socket transfer | Backend | Original client |

Both paths preserve end-to-end TLS ownership. The cooperative path additionally
removes the daemon from steady-state traffic and preserves the kernel's real
connection metadata.

In end-to-end testing, independently certificated Phoenix applications served
HTTP/1.1, HTTP/2, and LiveView WebSocket upgrades through the same port-443
daemon. Concurrent traffic crossed applications without relay fallback, and
Phoenix observed the original caller address.

## Where the boundary is

The current handoff implementation is intentionally Linux- and
Phoenix-specific:

- Descriptor passing uses Linux/Unix socket facilities.
- The receiver requires Erlang/OTP 29 or later.
- The tested integration pins Rustler 0.36.2.
- A second, handoff-only Bandit supervisor is used beside the ordinary
  endpoint.
- The native receive path currently uses one serialized acceptor.

Other runtimes can implement the PHXP receiver protocol, but they do not need
to. The generic TLS relay remains the baseline behavior.

That separation is the useful architectural result: dynamic certificate-based
routing does not depend on application cooperation, while applications that
do cooperate can receive the real connection rather than a convincing copy of
it.


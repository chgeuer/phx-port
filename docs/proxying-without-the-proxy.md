# Proxying Without the Proxy: Handing a Live TLS Socket to Phoenix

I love developing and running several web applications on my laptop. I also
want those applications to behave like the real thing: real hostnames, real
production certificates, and real TLS termination inside the application.
What I do not want is a spreadsheet of port numbers, a second configuration
database in a reverse proxy, or an extra TCP connection shoveling bytes around
for no useful reason.

That combination of preferences took a small port-allocation utility somewhere
unexpected: all the way from choosing port 4001 instead of 4000 to passing a
live port-443 socket into the BEAM.

## It started with too many projects and one default port

Phoenix applications normally start on TCP port 4000. That is convenient until
the second application starts. Then one project moves to 4001, another to
4002, and before long I am maintaining arbitrary port choices in project
configuration and trying to remember which application owns which number.

I wrote [`phx-port`](https://github.com/chgeuer/phx-port) to remove that
bookkeeping. It is a small Rust utility that assigns a stable port to a
canonical project directory and persists the mapping. The project does not
need a hard-coded development port; it just reads an environment variable:

```bash
PORT="$(phx-port)" mix phx.server
```

The same project gets the same port next time, while different projects do not
collide. Named roles extend the registry when an application needs more than
one listener:

```bash
PORT="$(phx-port)" \
HTTPS_PORT="$(phx-port https)" \
mix phx.server
```

That solved port allocation. It did not solve the URL in my browser.

## I wanted real TLS, not `localhost` with a fancy port

I prefer to enable security features early instead of discovering their
assumptions during deployment. My development applications use Let's Encrypt
production certificates obtained through the DNS-01 ACME challenge. Each
application can request and renew its own certificate without exposing a
temporary HTTP challenge endpoint.

At that point, opening this felt wrong:

```text
https://www.contoso.com:4017/
```

The certificate is real and the hostname is real, but the URL still advertises
the local port-allocation problem. I wanted the ordinary URL:

```text
https://www.contoso.com/
```

Multiple TLS sites can share port 443 because the ClientHello carries the
requested hostname in its Server Name Indication (SNI) extension. A
conventional answer would be to configure NGINX, HAProxy, or another reverse
proxy with every hostname and certificate.

That was precisely the configuration I wanted to avoid. The applications
already know their hostnames. They already obtain and renew their certificates.
They already have the correct TLS policy. Copying all of that into a central
proxy would create a second source of truth and concentrate every private key
in one process.

So I added a different constraint: `phx-port` may route TLS, but it must not
terminate it. Certificate and key material stay inside the application that
owns them.

## Discover the routes from the applications themselves

The `main` role serves ordinary HTTP, while the `https` role runs the
application's real production-style TLS configuration on its assigned local
port. Each project remains responsible for its private key, certificate
renewal, SNI callback, ALPN configuration, cipher policy, and optional client
authentication.

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

In other words, I do not configure `www.contoso.com -> 4008` manually.
`phx-port` learns that mapping by asking every live TLS workload, "Can you prove
that this hostname is yours?" The certificate is both the application's
identity and the source of the routing fact.

## The first working version still looked like a proxy

Knowing the route is only half the job. The portable way to deliver the
connection is TLS passthrough. Once `phx-port` knows that `www.contoso.com`
belongs to port 4008, the implementation is straightforward:

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

This met the important security goal: the proxy never sees a private key or
plaintext HTTP. It also works with an unmodified TLS server, so it remains the
compatibility path and safe fallback.

But it still creates the classic proxy shape:

```text
browser <-- connection A --> phx-port <-- connection B --> application
```

Its costs are inherent in those two connections:

- The backend's TCP peer is the local proxy.
- The daemon remains active for the lifetime of the connection.
- Traffic traverses two TCP connections and two relay loops.

Headers such as `Forwarded` or `X-Forwarded-For` cannot solve this at layer 4
without terminating and understanding the higher-level protocol. PROXY
protocol could carry peer metadata, but it would require support on both ends
and would still leave the relay in the data path.

This is not an argument that a loopback TCP connection is catastrophically
slow. It is an argument against paying for work the architecture does not
need. Every proxied connection adds another socket, another TCP handshake to
the backend, two copy loops, more scheduling, more buffers, and another
process that must remain healthy until the client disconnects.

The more I looked at it, the more that second TCP connection bothered me.
`phx-port` had already accepted exactly the connection the application needed.
After reading just enough of its ClientHello to choose a destination, why
should it create another connection and spend the rest of its life copying
encrypted bytes between the two?

Or, less politely: why do all that unnecessary TCP shit?

## The old idea that unlocked the new path

I remembered a Twitter conversation with Chris McCord about
[blue/green deployments](https://github.com/chgeuer/blue_green). The key idea
was that on Linux, one process can hand an existing socket to another process
using `SCM_RIGHTS`.

Linux can pass an open file descriptor between processes over a Unix-domain
socket using `sendmsg(2)` and `SCM_RIGHTS`. The descriptor received by the
application refers to the same kernel TCP socket that `phx-port` accepted on
port 443.

That turns `phx-port` into a proxy only during connection establishment. It
accepts the connection, identifies the application, transfers the socket, and
gets out of the way:

```text
                            routing only
browser ---> phx-port :443 -------------+
                                           \
                                            v
                                      Bandit / Phoenix
                                           |
                         original TCP socket, direct to browser
```

For a handoff-enabled Phoenix application, the sequence is:

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

That is the distinction in the title. `phx-port` is a proxy while it makes the
routing decision, and only a "proxy" afterward: it does not impersonate either
endpoint or remain between them once the decision is made.

## Peeking is the crucial trick

The appealing one-line version is "just pass the FD." The catch is that
`phx-port` must inspect the connection before it knows where to pass it.
Routing requires the SNI hostname, while the backend's TLS stack requires the
complete, original ClientHello. A normal `recv(2)` would consume those bytes,
leaving the application with a stream that starts in the middle of the TLS
handshake.

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

Preserving the bytes solved the routing half of the problem. Making an
arbitrary imported file descriptor behave like a connection accepted normally
by Phoenix was the other half. Bandit expects Thousand Island to accept a
socket from a listener, establish ownership, gather peer metadata, perform the
TLS handshake, and then start the HTTP connection lifecycle.

This is where
[Matt Trudel's](https://github.com/mtrudel)
[Thousand Island](https://github.com/mtrudel/thousand_island) and
[Bandit](https://github.com/mtrudel/bandit) deserve special praise. Their
extensibility is what makes this stunt possible without forking the web server
or building a parallel HTTP stack. Thousand Island exposes transport behavior
as a real abstraction, and Bandit cleanly builds its HTTP lifecycle on top of
it. That lets a handed-off descriptor enter through a custom transport and,
after TLS setup, become an otherwise ordinary Bandit connection.

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

The resulting Phoenix application deliberately runs two cooperating
listeners:

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

At first, keeping an ordinary TCP listener alongside the handoff listener can
look redundant. It is actually what keeps discovery independent of Phoenix.
The daemon can prove hostname ownership using an ordinary TLS handshake,
perform health checks, and offer a direct diagnostic path even if handoff is
unavailable. The Unix listener is then an advertised optimization for traffic
whose route is already trusted.

## Cooperation is optional

I did not want the clever path to become the only path. Socket handoff is an
optimization, not a requirement for joining the routing system. Each
`(project path, role)` pair maps deterministically to a private Unix socket:

```text
$XDG_RUNTIME_DIR/phx-port/handoff/
  <sha256(canonical-project-path NUL role)>.sock
```

If a compatible receiver is live, `phx-port` attempts handoff. If it is
missing, stale, incompatible, or rejects the connection before descriptor
delivery, the daemon opens the backend's registered HTTPS port and uses the
ordinary TLS relay.

This fallback has one non-negotiable ownership boundary. Before a successful
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

## The result

The combined design supports two kinds of workload behind the same dynamic SNI
router:

| Workload | Delivery | TLS owner | Backend peer address |
|---|---|---|---|
| Any TLS server | Opaque byte relay | Backend | `phx-port` loopback |
| Handoff-enabled Phoenix/Bandit | `SCM_RIGHTS` socket transfer | Backend | Original client |

Both paths preserve end-to-end TLS ownership. The cooperative path also
removes the daemon from steady-state traffic. There is no downstream TLS
connection, no relay loop, and no proxy peer address to repair at the HTTP
layer. The application talks directly to the browser over the socket that
arrived on port 443.

In end-to-end testing, independently certificated Phoenix applications served
HTTP/1.1, HTTP/2, and LiveView WebSocket upgrades through the same port-443
daemon. Concurrent traffic crossed applications without relay fallback, and
Phoenix observed the original caller address.

That completes the progression that motivated the work:

1. Multiple local projects get stable ports without per-project bookkeeping.
2. Each project runs its real TLS configuration and owns its private keys.
3. Real hostnames use ordinary `https://hostname/` URLs on shared port 443.
4. Routes appear and disappear with the live applications instead of a
   separately maintained reverse-proxy configuration.
5. Cooperative Phoenix applications receive the original socket, eliminating
   the extra TCP connection and byte-copying path.

## Current boundaries

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

For me, that separation is the important architectural result. Dynamic,
certificate-based routing does not depend on application cooperation. It
works with any TLS workload through passthrough. But an application that does
cooperate no longer receives a proxy's reconstruction of the connection. It
receives the real one.

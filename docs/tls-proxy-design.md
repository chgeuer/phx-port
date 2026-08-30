# Dynamic TLS/SNI Proxy Design

## Status

Chosen design for implementation.

## Context

`phx-port` assigns stable, collision-free ports to local projects and can
probe the registry to identify which assigned ports are currently listening.
Several applications may need to run concurrently with their production TLS
configuration while remaining reachable through the standard TLS port:

```text
https://www.contoso.com:443  -> https://127.0.0.1:4001
https://contoso.com:443      -> https://127.0.0.1:4001
https://www.fabrikam.com:443 -> https://127.0.0.1:4002
```

Only one process can bind TCP port 443. `phx-port` will therefore gain a
long-running daemon that routes incoming TLS connections to active registered
workloads according to Server Name Indication (SNI).

For example, a workload at `/home/user/projects/contoso_web` may serve two
hostnames using two certificates selected by its TLS SNI callback:

- `www.contoso.com`
- `contoso.com`

The design is not specific to Elixir, Phoenix, Bandit, or HTTP.

## Requirements

### Functional requirements

1. `phx-port` can run as a long-lived daemon listening on TCP port 443.
2. Registered workloads continue to receive stable ports from the existing
   port registry.
3. Backends use HTTPS and retain ownership of their certificates and private
   keys.
4. The daemon discovers when registered HTTPS workloads start and stop.
5. The daemon eagerly discovers hostnames from each new workload's default
   certificate when that workload supports a TLS handshake without SNI.
6. When a client requests an unknown SNI hostname, the daemon probes all
   active HTTPS workloads using that hostname as SNI.
7. A hostname is routed only when exactly one backend presents a valid,
   matching certificate.
8. Successful lazy discoveries are cached persistently.
9. Cached routes are revalidated before activation after daemon or workload
   restart.
10. New connections stop routing to a workload after that workload stops.
11. Existing proxied connections may drain naturally.
12. Workloads may be implemented in any language or framework.
13. LiveView, WebSockets, HTTP/2, gRPC, and other SNI-bearing TLS protocols
    pass through without protocol-specific proxy support.
14. Certificate rotation at a backend does not require restarting or
    reconfiguring the phx-port daemon.

### Operational requirements

- No backend certificate or private-key paths are stored in the phx-port
  configuration.
- Private-key material is never read, copied, or held by phx-port.
- The first connection for an unknown hostname incurs a bounded discovery
  delay.
- Unknown-host discovery is concurrency-limited and resistant to abuse.
- Route conflicts, activation, deactivation, and certificate changes are
  observable.
- The daemon can run as an unprivileged user where the operating system permits
  binding port 443.
- Each workload controls whether its backend port binds to loopback or other
  interfaces. Loopback remains the safer default when direct LAN access is not
  required.

## Goals

- Preserve production-equivalent TLS behavior in each workload.
- Require no duplicate list of certificate and key paths.
- Make hostname routing self-configuring for active workloads.
- Keep the proxy independent of application language and application protocol.
- Minimize the amount of TLS and HTTP behavior implemented by phx-port.
- Fail closed for unknown, invalid, expired, or ambiguous hostnames.
- Keep the existing stable-port workflow intact.

## Non-goals

- Terminating TLS in phx-port.
- Managing or renewing certificates.
- Reading Phoenix or other framework configuration files.
- Discovering private keys from process state, source trees, environment
  variables, or open file descriptors.
- Acting as an HTTP reverse proxy or modifying HTTP requests and responses.
- Routing plaintext protocols through the port 443 listener.
- Routing TLS clients that provide neither SNI nor another configured routing
  identity.
- Replacing public DNS. DNS must still direct each public hostname to the
  machine running the daemon.

## Chosen architecture: SNI passthrough

The daemon is a layer-4 TCP proxy with TLS ClientHello inspection. It does not
terminate TLS:

```text
Client
  |
  | TLS ClientHello, SNI=www.contoso.com
  v
phx-port daemon, 0.0.0.0:443
  |
  | inspect SNI, select active route, forward original bytes
  v
contoso_web, 127.0.0.1:4001
  |
  | terminate TLS and select the certificate
  v
Application
```

The daemon buffers a bounded ClientHello, extracts its SNI hostname, selects a
route, opens the backend TCP connection, writes the original buffered bytes
unchanged, and then copies bytes bidirectionally until either side closes.

Because the original handshake reaches the backend:

- The backend proves possession of the certificate's private key directly to
  the client.
- Application TLS versions, cipher suites, ALPN, client-certificate policy,
  OCSP behavior, and session handling remain authoritative.
- phx-port has no certificates to reload. Backend certificate hot reloading is
  immediately effective for new connections.
- phx-port does not need HTTP, WebSocket, or HTTP/2 proxy implementations.

The daemon maintains an **SNI route table**, not an SNI certificate list.

## Commands and port roles

The daemon entry point is an explicit, foreground command:

```bash
phx-port daemon --listen 0.0.0.0:443 --listen '[::]:443'
```

`daemon` is preferable to a global `--daemon` option because it has its own
lifecycle, configuration, status, and diagnostics. The IPv4 and IPv6 listeners
are separate; the IPv6 listener uses IPv6-only mode to avoid
platform-dependent dual-stack behavior.

The daemon does not self-background. An installable systemd user service owns
restart policy, startup, logging, and supervision. On systems that do not
permit an unprivileged process to bind port 443, startup fails with a clear
privilege diagnostic rather than attempting privilege escalation.

HTTPS workloads use a conventional named role:

```bash
export SSL_PORT="${SSL_PORT:-$(phx-port https)}"
exec application-server
```

For example, a Phoenix endpoint may bind its assigned HTTPS listener to
loopback:

```elixir
https: [
  port: String.to_integer(System.fetch_env!("SSL_PORT")),
  ip: {127, 0, 0, 1},
  certfile: ...,
  keyfile: ...
]
```

The initial implementation probes both `https` and `main` roles for TLS.
`https` is preferred when both roles in one project validly serve the same
hostname; `main` provides compatibility for projects that already use their
default role for HTTPS. Matching roles in different projects still invoke the
hostname-conflict policy.

Additional inspection commands should include:

```text
phx-port proxy status
phx-port proxy routes
```

The exact command names may be adjusted to remain consistent with the final
CLI structure, but operators must be able to inspect active, inactive,
conflicting, and cached routes.

## Workload discovery

The daemon watches the existing port registry and also reconciles it
periodically. Filesystem notifications reduce activation latency, while
periodic reconciliation covers missed events, atomic file replacement, and
platform differences.

For each registered `https` or `main` role, the daemon tracks:

- Canonical project path.
- Assigned port.
- TCP listener availability.
- TLS readiness.
- Last successful probe.
- Hostnames currently verified for the workload.
- Current leaf-certificate fingerprints and validity periods.

A TCP connect alone is insufficient for routing. A workload becomes eligible
for a hostname after one complete TLS probe for that hostname succeeds with
certificate and hostname validation. Failure to present a no-SNI default
certificate disables eager discovery for that workload but does not prevent
exact-SNI lazy discovery.

The daemon must connect only to loopback addresses derived from registered
ports. Discovery data must never be able to turn the daemon into a proxy for
arbitrary network destinations.

## Eager hostname discovery

When an HTTPS workload becomes ready, the daemon attempts to connect without
SNI and examine the default certificate presented by that workload. This is
opportunistic: strictly SNI-only servers may reject that handshake, in which
case the workload remains discoverable through the lazy path.

Every exact DNS Subject Alternative Name (SAN) in the certificate becomes a
candidate. The daemon then performs an SNI-specific TLS probe for each
candidate. A route is activated only if:

1. The TLS handshake demonstrates possession of the corresponding private key.
2. The certificate chain is trusted according to the daemon's trust policy.
3. The certificate is currently valid.
4. The certificate covers the candidate hostname according to standard TLS
   hostname-verification rules.
5. No other active backend owns the same hostname.

The Common Name is not used when the certificate contains DNS SANs.

A wildcard SAN cannot enumerate all hostnames that an application intends to
serve. It may validate a concrete hostname during lazy discovery, but it does
not eagerly create an unbounded set of routes.

## Lazy discovery for unknown SNI

A backend may select additional certificates that are not visible in its
default handshake. TLS provides no operation that enumerates all SNI names
supported by a server. Unknown incoming names therefore trigger targeted
discovery.

For an incoming ClientHello with an unknown hostname:

1. Validate and normalize the requested DNS hostname.
2. Buffer the original ClientHello without replying to the client.
3. Join any discovery already in progress for that hostname.
4. Concurrently probe all active HTTPS workloads, using the requested hostname
   as SNI.
5. Validate each returned certificate and handshake against that hostname.
6. If exactly one backend matches, atomically add the route.
7. Connect to that backend and forward the original ClientHello unchanged.
8. Persist the successful mapping as derived cache state.

The original client socket waits for at most 250 milliseconds while discovery
runs. At most 64 client connections may wait for discovery, and at most 32
backend TLS probes may run concurrently. Simultaneous discoveries for the same
normalized hostname share one single-flight operation.

Applied to the motivating example:

1. A default probe may discover `www.contoso.com`; an SNI-only backend simply
   skips this optimization.
2. The first client requesting `contoso.com` causes an exact-SNI
   fan-out.
3. `contoso_web` selects and presents its apex certificate.
4. phx-port validates it and records the apex hostname route.
5. Later connections use the route without another fan-out.

If no backend matches within the discovery deadline, the daemon closes the
connection. Because phx-port does not terminate TLS, it cannot return an HTTPS
error page.

## Route persistence

Discovered routes are stored in a clearly separated
`[discovered_routes]` table within the existing phx-port TOML registry. The
`[ports]` table remains authoritative configuration; discovered routes remain
derived, disposable state.

Conceptual cache entry:

```toml
[discovered_routes."contoso.com"]
project = "/home/user/projects/contoso_web"
role = "https"
certificate_fingerprint = "A7:9A:77:DA:F6:4F:21:0E:..."
last_verified_unix = 1788114730
```

The cache stores a project identity and role rather than only a socket address.
Stable port allocation remains authoritative for resolving the current
backend address.

Cached entries are hints, not authorization. On daemon startup or workload
restart, a cached route remains inactive until an SNI-specific probe verifies
it again. If revalidation fails, the cache entry may remain available for
diagnostics but cannot receive connections.

Every daemon and CLI read-modify-write operation takes an advisory lock on a
sibling lock file. Writes use a temporary file, `fsync`, and atomic rename so a
route discovery cannot overwrite a simultaneous port registration or deletion.

A positive route remains cached while its project and role remain registered,
even when the workload is stopped. Removing that registration removes its
derived routes. A newly presented valid certificate that no longer covers a
cached hostname also removes the route.

## Route lifecycle

Routes have the following conceptual states:

```text
cached -> probing -> active -> unhealthy -> inactive
                     |
                     +-> conflict
```

- **Cached:** Persisted mapping has not yet been verified in this daemon
  lifetime.
- **Probing:** TLS readiness or hostname ownership is being checked.
- **Active:** New connections may use the route.
- **Unhealthy:** One or more recent checks failed, but the failure threshold
  has not been reached.
- **Inactive:** New connections are rejected because the workload is stopped
  or verification failed.
- **Conflict:** More than one active workload validly presents a certificate
  for the hostname.

One complete, valid TLS handshake activates a workload. Active workloads
receive a TCP liveness probe once per second and deactivate after three
consecutive failures. Hostname-specific TLS revalidation runs every 30 seconds
and immediately after a stopped workload returns. A successful liveness probe
resets the failure count.

Route-table replacement must be atomic. Each accepted connection uses a
snapshot of the selected route:

- New connections stop using a route immediately after deactivation.
- Existing connections continue until either endpoint closes.
- Workload restart does not forcibly terminate unrelated connections.

TLS revalidation uses the known hostname as SNI, allowing the daemon to detect
certificate expiration, hostname removal, or certificate rotation without
performing a full handshake every second. Rotated certificates are served
immediately by the backend because phx-port does not terminate TLS.

## Conflicts

If multiple active workloads present valid certificates for the same requested
hostname, discovery is ambiguous. The daemon must:

- Preserve an already active, still-valid incumbent.
- Quarantine a newly discovered contender for that hostname.
- Activate no route if multiple contenders appear without an incumbent, such
  as during daemon startup.
- Record all conflicting project identities and ports.
- Emit a clear diagnostic.
- Retry after workload or certificate state changes.

Response order, port number, project path ordering, or most-recent startup must
never be used as an implicit tie-breaker.

## Trust policy

By default, probe validation should use the operating system's trusted root
store and standard DNS hostname verification. This proves that a local
workload holds a certificate trusted for the requested public name.

Support for private development certificate authorities may be added through
an explicit daemon trust-store option. Disabling certificate verification is
not an acceptable discovery mode because any local process could then claim
any hostname.

The probe must validate the complete chain presented by the backend while
tolerating conventional extra certificates after the usable chain.

## Abuse resistance and resource limits

Lazy discovery turns an unknown SNI value into fan-out work and therefore
requires strict bounds:

- Reject malformed, non-DNS, oversized, or missing SNI values.
- Limit the ClientHello size and handshake read time.
- Give discovery a 250 millisecond deadline.
- Permit at most 64 waiting clients and 32 concurrent backend probes.
- Use single-flight discovery per normalized hostname.
- Maintain a bounded negative cache for names with no match.
- Cache misses for 30 seconds.
- Invalidate negative entries when a new TLS workload activates or a backend
  certificate fingerprint changes.
- Rate-limit unknown-host discoveries globally and per source address.
- Bound the number of buffered client connections awaiting discovery.
- Bound positive and negative cache sizes.
- Do not follow backend redirects or make HTTP requests during discovery.
- Never expose certificate contents, key material, or sensitive paths in
  routine logs.

Once a route exists, forwarding does not require additional TLS parsing beyond
the initial ClientHello.

A wildcard certificate may validate a concrete hostname during lazy
discovery, but the daemon caches only that observed hostname. It never creates
an implicit wildcard route from the certificate.

## Failure behavior

| Condition | Behavior |
|---|---|
| Missing SNI | Close the connection |
| Malformed ClientHello | Close the connection and record a bounded diagnostic |
| Known active hostname | Connect and proxy immediately |
| Cached but inactive hostname | Revalidate the cached backend, then fan out if needed |
| Unknown hostname | Run bounded lazy discovery |
| No matching backend | Negative-cache and close |
| Multiple matching backends | Mark conflict and close |
| Backend stops | Deactivate its routes after the failure threshold |
| Backend restarts | Revalidate cached routes and reactivate |
| Certificate rotates validly | Update fingerprint and retain the route |
| Certificate expires or drops hostname | Deactivate the affected route |

## Implementation outline

The daemon should be implemented natively in Rust. The expected components are:

- An asynchronous runtime for listener, probe, timer, and signal handling.
- A registry watcher plus periodic reconciler.
- A TLS probe client using the system trust roots.
- A bounded ClientHello reader and SNI parser.
- An immutable route table published through an atomic swap.
- Single-flight lazy discovery with bounded parallel probes.
- Bidirectional TCP copying after forwarding the buffered ClientHello.
- Atomic persistent-cache reads and writes.
- Graceful shutdown and structured diagnostics.

The ingress parser may feed a copy of the buffered bytes to a TLS ClientHello
parser while retaining the original bytes for the backend. It must never
complete a server-side handshake or synthesize a replacement ClientHello.

Implementation should be split into independently testable modules rather than
extending the existing single source file indefinitely:

```text
src/
  main.rs
  registry.rs
  daemon.rs
  client_hello.rs
  discovery.rs
  probe.rs
  routes.rs
  route_cache.rs
```

## Validation strategy

Automated tests should cover:

- ClientHello fragmentation across TCP reads.
- SNI extraction and hostname normalization.
- Oversized and malformed ClientHello rejection.
- Eager SAN discovery.
- Lazy discovery of a non-default SNI certificate.
- No match, one match, and multiple-match outcomes.
- Single-flight behavior under concurrent first requests.
- Positive and negative cache expiration.
- Route removal and reactivation as a backend stops and starts.
- Certificate rotation, expiration, and hostname removal.
- Preservation of original TLS bytes.
- Long-lived connection draining after route deactivation.
- Registry and route-cache concurrent updates.
- WebSocket, HTTP/2, gRPC, and non-HTTP TLS passthrough.

An end-to-end fixture should start at least two local TLS servers with distinct
SNI certificates and prove that a single daemon listener routes each hostname
to the correct backend.

## Limitations

- TLS clients without SNI cannot be routed.
- Encrypted ClientHello can hide the inner hostname. Unless a usable outer name
  maps to a route, such connections cannot be dynamically routed by this
  design.
- A backend requiring mutual TLS may prevent generic discovery if the probe
  cannot complete enough of the handshake to verify the server. Such workloads
  may require a future explicit hostname announcement mechanism.
- The first request for a non-default hostname waits for discovery and may time
  out under a large or unhealthy workload set.
- A valid wildcard certificate can prove authority for a requested matching
  name, but it cannot reveal which concrete names the application intends to
  serve.
- DNS and certificate renewal remain external responsibilities.

## Decision summary

`phx-port` will become a dynamic, framework-independent SNI passthrough proxy.
Applications continue to terminate TLS on stable, loopback-bound HTTPS ports.
The daemon discovers default certificate names eagerly and discovers
non-default certificate names lazily by probing every active backend with the
unknown hostname as SNI. Verified routes are cached as derived state and are
activated only while their workloads remain healthy.

This design provides dynamic routing and certificate hot-reloading without
centralizing private keys, parsing application configuration, depending on
nginx, or implementing an HTTP reverse proxy.

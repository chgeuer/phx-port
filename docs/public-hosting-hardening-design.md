# Public Hosting Hardening Design

## Status

Accepted on 2026-09-02. The
[decision register](#decision-register) is complete. Implementation has not
started.

This document defines the changes required to operate `phx-port` as an
Internet-facing TLS ingress for multiple independently deployed web projects
on one Linux host and one public IP address.

The corresponding delivery sequence is in
[`public-hosting-hardening-implementation-plan.md`](public-hosting-hardening-implementation-plan.md).

## Intended product position

The hardened mode is a **single-host TLS ingress**:

```text
public DNS
    |
    v
one Linux host, TCP 443
    |
    v
phx-port ingress
    |
    +-- socket handoff --> cooperating loopback workload
    |
    +-- encrypted relay --> ordinary loopback TLS workload
```

It is not a general HTTP reverse proxy. `phx-port` inspects only enough of the
TLS ClientHello to obtain SNI. Each workload remains the TLS endpoint and owns
its certificates, private keys, HTTP server, request limits, authentication,
and application logs.

The initial target is an operator hosting their own projects with a common
administrative trust boundary. It must nevertheless tolerate hostile public
traffic without unbounded resource use.

## Canonical terms

The interview and implementation should use these terms consistently:

- **Ingress**: the long-running `phx-port daemon` process accepting public TLS
  connections.
- **Workload**: one registered application listener identified by logical ID
  and role in production, or canonical project path and role in development.
- **Route declaration**: operator configuration stating which exact hostname
  is expected to belong to which workload.
- **Verified route**: a route declaration or discovered candidate whose
  workload has presented a system-trusted certificate valid for the exact
  hostname.
- **Dynamic discovery**: probing multiple live workloads to find the unique
  certificate-valid owner of an otherwise unknown hostname.
- **Handoff connection**: a connection whose original accepted descriptor is
  transferred to a cooperating workload.
- **Relay connection**: a connection whose encrypted bytes are copied between
  the public socket and a second loopback TCP socket.
- **Pre-routing connection**: an accepted connection that has not yet selected
  a verified route.
- **Admission permit**: bounded capacity granted before work is allocated to
  an accepted connection.
- **Control plane**: local status, route inspection, reload, and shutdown
  operations. It is never exposed on a public listener.
- **Public-hosting mode**: explicit configuration that enables the hardened
  defaults in this document. Development behavior must not silently become
  more restrictive.

## Existing behavior

The current daemon already provides:

- separate IPv4 and IPv6 public listeners;
- bounded, non-consuming ClientHello inspection;
- DNS hostname normalization;
- system-trusted certificate and hostname verification;
- eager and lazy route discovery;
- single-flight unknown-host discovery;
- at most 64 clients waiting for discovery;
- at most 32 concurrent certificate probes;
- at most 32 candidate workloads per discovery;
- 1,024 negative routes with a 30-second TTL;
- fail-closed route conflict handling;
- loopback-only backend connections;
- route liveness and certificate revalidation;
- encrypted relay and optional descriptor handoff;
- atomic route-cache updates;
- current-user Unix control socket;
- status counters; and
- graceful waiting for up to 30 seconds during shutdown.

The current implementation is not yet an Internet-grade resource boundary:

- every accepted connection creates an unbounded OS thread;
- every relay creates a second copy thread;
- there is no global active-connection limit;
- there is no per-source admission or connection-rate limit;
- random public SNI can still invoke bounded but nontrivial discovery work;
- positive route persistence is unbounded;
- service installation is a user unit without port-binding capabilities,
  systemd sandboxing, or resource limits;
- configuration and derived route state share one development-oriented file;
- status is human-readable only;
- logs are unstructured and may be amplified by hostile input;
- no readiness or metrics interface is suitable for automated operations;
- no zero-downtime binary upgrade contract exists; and
- same-UID handoff conflicts with strong per-workload Unix-user isolation.

## Goals

1. Bound memory, threads/tasks, file descriptors, probes, pending handshakes,
   and persisted route state under hostile traffic.
2. Reject overload cheaply before spawning per-connection work.
3. Make production routes deterministic while retaining certificate proof of
   hostname ownership.
4. Preserve application-owned TLS and private keys.
5. Keep all backend traffic on loopback.
6. Run ingress with least privilege and a hardened service sandbox.
7. Define an explicit workload isolation and handoff policy.
8. Provide machine-readable health, metrics, and diagnostics without exposing
   a public administration API.
9. Support graceful restart and a documented rollback.
10. Preserve current development behavior unless public-hosting mode is
    explicitly enabled.
11. Supply repeatable load, abuse, failure, and recovery tests.
12. State the single-host availability boundary honestly.

## Non-goals

- TLS termination in `phx-port`.
- Central certificate issuance, storage, or renewal.
- HTTP header manipulation, caching, compression, WAF rules, or request-level
  routing.
- Cross-host service discovery.
- A distributed control plane.
- Multi-region or multi-host high availability in the first production mode.
- Protecting one same-UID workload from another same-UID workload.
- Supporting TLS clients without a usable SNI routing identity.
- Defeating volumetric denial-of-service beyond the host or VPC capacity.
- Replacing workload-level connection, request, authentication, and rate
  limits.

## Production invariants

The implementation must preserve these invariants:

1. No public input can create an unbounded number of threads, tasks, probes,
   cache entries, log messages, or queued connections in user space.
2. An accepted socket obtains an admission permit before expensive parsing,
   discovery, logging, or worker allocation.
3. Unknown SNI cannot fan out across workloads in public-hosting mode unless
   the operator explicitly enables dynamic discovery.
4. A hostname routes only to its declared workload after exact-hostname TLS
   certificate verification.
5. Route cache state is never authorization by itself.
6. A malformed configuration reload leaves the previous valid snapshot active.
7. Backends are always addressed through loopback and a registered port.
8. Descriptor handoff retains its existing irreversible ownership boundary.
9. The control plane is local, authenticated by operating-system identity, and
   never bound to `0.0.0.0`.
10. Ingress runs without UID 0 and receives only the capabilities it needs.
11. Sensitive TLS payload, private key material, raw descriptors, and full
    unbounded attacker-controlled values are not logged.
12. Development mode remains backwards compatible.

### Development compatibility invariant

Public-hosting hardening is an additive hosting profile, not a migration of the
existing laptop workflow.

Without an explicit production ingress configuration:

- `PORT="$(phx-port)" command` behaves exactly as today;
- workload identity is the canonical current project path plus role;
- the registry remains per-user under the home/config directory;
- runtime and handoff sockets remain in the user's runtime/home locations;
- no `/etc/phx-port`, `/var/lib/phx-port`, system service, service account, or
  privileged bootstrap is required;
- dynamic certificate discovery remains available to the development daemon;
- no logical production workload ID is required; and
- existing project startup scripts remain valid.

Production paths and behavior are activated explicitly. The binary must not
auto-select production because `/etc/phx-port` exists, because it is running on
Linux, or because effective UID is zero. A developer may run the production
profile on a laptop for testing by passing explicit temporary paths.

**Profile activation decision: Accepted — production requires
`--ingress-config PATH` or `PHX_PORT_INGRESS_CONFIG`.**

The supplied ingress file must explicitly declare `mode = "public"`.
Production systemd/launchd definitions pass `/etc/phx-port/ingress.toml`;
tests and local production-profile exercises may pass temporary paths. The
existing `PHX_PORT_CONFIG` continues to override only the development/stable
port registry and is not overloaded with ingress policy. No command
automatically reads `/etc/phx-port`.

`PHX_PORT_WORKLOAD_ID` (or its explicit CLI equivalent) selects the allocator
identity only; it does not activate the production ingress profile. This is an
intentional opt-in for workload startup automation and never changes the
default canonical-path identity when absent.

Shared internals may improve safety in both profiles, including bounded
parsing, Tokio-based daemon I/O, and bug fixes. Production-only declarations,
permissions, service management, and filesystem layout do not leak into the
default allocator workflow.

## Threat model

### Protected assets

- Availability of the ingress and co-hosted workloads.
- Workload private keys and application secrets.
- Integrity of hostname-to-workload routing.
- Original client and connection metadata.
- Ingress configuration and derived route state.
- Host CPU, memory, file descriptors, process/task slots, disk, and logs.
- Local control-plane authority.

### Adversaries

The design assumes:

- arbitrary Internet clients can open TCP connections and send malformed,
  fragmented, slow, or high-volume TLS-like traffic;
- clients can choose arbitrary SNI values and source addresses;
- clients may keep valid TLS connections or WebSockets open for a long time;
- an unprivileged local user may inspect predictable filesystem paths and race
  unsafe temporary-file behavior;
- a compromised workload may control its listener and certificate material;
  and
- operators can make configuration mistakes.

### Trust assumptions

Unless the interview changes them:

- the Linux kernel, systemd, host firewall, package source, and operator are
  trusted;
- workloads are owned by one operator and share the dedicated production
  service identity as one explicit trust domain;
- public CA validation is authoritative for hostname ownership;
- compromise of a same-UID process compromises every secret readable by that
  UID; and
- volumetric attacks are handled by the VPC/cloud firewall or an upstream L4
  service, not solely by this process.

## Target architecture

### Data plane

The data plane has four bounded stages:

```text
kernel listen backlog
    |
    v
global + source admission
    |
    v
bounded ClientHello/SNI parsing
    |
    v
declared route lookup + certificate-verified activation
    |
    +-- PHXP handoff --> release ingress permit after transfer
    |
    +-- relay --------> retain permit until relay closes
```

Admission occurs immediately after `accept`. If capacity is unavailable, close
the socket without parsing SNI and increment a rate-limited overload counter.

Handoff and relay capacity have different lifetimes:

- A relay consumes ingress sockets, loopback sockets, and an ingress task for
  its full lifetime.
- A handoff consumes ingress capacity only until successful descriptor
  transfer. After transfer, the workload owns and limits the live connection.

Therefore `active_ingress_connections` is not the same as the number of live
handed-off application connections. Workloads must enforce their own active
connection limits.

### Route control

Public-hosting mode should prefer explicit exact-host declarations:

```toml
[ingress]
mode = "public"
unknown_sni = "reject"

[ingress.hosts."app1.example.com"]
workload = "app1"
role = "https"
required = true

[ingress.hosts."app2.example.com"]
workload = "app2"
role = "https"
required = false
```

A declaration identifies logical workload ID and role, not a path or mutable
port. Optional workload paths are diagnostic metadata only. The stable port
registry remains authoritative for resolving the host-local loopback port.

The ingress activates a declaration only after the selected workload presents
a trusted certificate valid for that exact hostname. A declaration cannot
override certificate validation.

Recommended public default:

- exact declared hosts are allowed;
- undeclared SNI is closed without workload fan-out;
- optional development-style dynamic discovery can be enabled explicitly;
- wildcard certificates may validate declared concrete names but do not create
  implicit wildcard routes; and
- route declarations have a configured maximum.

This removes attacker-controlled discovery fan-out and the 32-candidate
correctness ceiling from normal production routing.

### Configuration and state

Production configuration should be separated from derived state:

```text
/etc/phx-port/ingress.toml       operator-owned declarative configuration
/var/lib/phx-port/routes.toml    daemon-owned disposable verified-route state
/run/phx-port/                   service-owned, group-traversable runtime root
/run/phx-port/handoff/           private shared-UID PHXP endpoints
/run/phx-port/control/           group-readable local control
```

The existing project port registry may remain a separate input:

```text
/var/lib/phx-port/ports.toml
```

### Production workload self-registration

Production retains the defining `phx-port` workload-startup property: a
workload may start after ingress and atomically obtain its stable local ports
without an administrator editing route or port files.

The production service environment supplies:

```text
PHX_PORT_CONFIG=/var/lib/phx-port/ports.toml
PHX_PORT_WORKLOAD_ID=contoso-web
```

The workload startup script remains:

```bash
PORT="$(phx-port)" \
HTTPS_PORT="$(phx-port https)" \
exec application-server
```

In production, `PHX_PORT_WORKLOAD_ID` replaces canonical working directory as
the registry key. It is required whenever logical production identity is
selected and must not silently fall back to the current directory. IDs are
lowercase ASCII, 1-128 characters, start and end alphanumeric, and contain only
alphanumerics, `.`, `_`, and `-`.

The shared trust-domain service UID owns and may write:

```text
/var/lib/phx-port/                 0700 directory
/var/lib/phx-port/ports.toml       0600 regular file
/var/lib/phx-port/ports.toml.lock  0600 regular file
```

Allocator requirements:

- validate every path component without following unexpected symlinks;
- require service-UID ownership and private modes;
- take the existing exclusive advisory lock before reading or assigning;
- allocate and atomically persist one `(workload ID, role)` mapping;
- preserve unrelated assignments and derived files;
- return the existing assignment idempotently;
- prevent two concurrent first starts from receiving one port;
- permit the same workload ID on different hosts to receive different local
  ports;
- avoid any dependency on the ingress control socket or process availability;
  and
- leave route declarations and verified-route state untouched.

The running ingress reconciles the registry and detects a workload that starts
later. A root-owned exact route declaration remains inactive until its logical
workload/role has a port, is reachable, and proves the declared certificate.
Reconciliation fails closed for malformed entries, duplicate logical keys, or
one port assigned to multiple workload/role keys. Registry entries not
referenced by any declaration remain inactive and increment one bounded
aggregate diagnostic rather than creating routes.

Production PHXP endpoints live at:

```text
/run/phx-port/handoff/<sha256(workload-id, role)>.sock
```

The service manager creates `/run/phx-port` as mode `0750`, owned by the
service UID and `phx-port-admin` group. The service-owned `handoff` directory
is mode `0700`; each workload owns the lifecycle of its endpoint under that
directory. Ingress restart must neither remove the directory nor unlink
workload endpoints. Endpoint derivation uses logical workload ID and role in
production and retains canonical path and role in development. A canary and
the load harness must assert successful handoff, not infer it merely from
successful request delivery.

Because all workloads intentionally share one UID, a compromised workload can
alter the entire port registry. This is inside the accepted ingress trust
domain. Moving to separate workload UIDs would require a brokered registration
protocol and a new authorization design.

All configuration is loaded into one typed, validated immutable snapshot.
Reload performs:

1. read all files under bounded sizes;
2. parse and reject unknown production keys;
3. validate limits and route references;
4. resolve registrations;
5. compare with the active snapshot;
6. atomically replace the snapshot only on complete success; and
7. asynchronously verify changed routes before serving them.

The previous snapshot remains active after a failed reload. Status and logs
must expose the rejected generation and reason.

### Runtime model

The production target should use a bounded asynchronous runtime for public TCP
connections and relay copying. Tokio is the recommended Rust ecosystem choice
because it supplies:

- bounded task scheduling without one native thread per socket;
- asynchronous TCP listeners and streams;
- cancellation and timeout primitives;
- semaphore-based admission;
- signal handling; and
- mature bidirectional copying.

TLS probes may initially remain blocking `native-tls` operations inside a
strictly bounded pool of at most 32 workers. PHXP Unix descriptor operations
may use a separate pool of at most 256 workers until represented safely
through async file descriptor readiness. Startup validates these pools,
runtime workers, and auxiliary threads together against `TasksMax`; neither
pool may queue unbounded work.

A transitional release may retain the current thread-per-connection model only
behind a low global admission limit. That is a safety milestone, not the final
high-density architecture.

### Admission control

Admission combines independent limits:

- maximum accepted connections being processed by ingress;
- maximum pre-routing connections;
- maximum relay connections;
- maximum concurrent handoff negotiations;
- maximum new connections per second globally;
- maximum new connections per source bucket;
- maximum concurrent pre-routing connections per source bucket;
- existing waiting-discovery and probe limits; and
- systemd/kernel file-descriptor, task, and memory ceilings.

Recommended initial defaults for a modest 2-4 vCPU host are deliberately
conservative and configurable:

| Limit | Initial default |
|---|---:|
| Ingress-owned connection state machines | 8,192 after async migration |
| Transitional threaded active connections | 256 |
| Pre-routing connections | 1,024 |
| Relay connections | 5,000 |
| Concurrent handoff negotiations | 256 |
| Global accepts | 500/second, burst 1,000 |
| Per IPv4 source accepts | 20/second, burst 40 |
| Per IPv6 `/64` accepts | 20/second, burst 40 |
| Concurrent pre-routing per source bucket | 16 |
| ClientHello bytes | existing 64 KiB |
| ClientHello deadline | existing 2 seconds initially |
| Waiting dynamic discoveries | existing 64 |
| Concurrent certificate probes | existing 32 |
| Declared hostnames | 1,000 |
| Dynamic negative routes | existing 1,024 |

These are starting points, not universal constants. Every value must be
validated against memory, FD, task, and expected traffic budgets.

When overloaded, ingress closes newly accepted sockets immediately. It cannot
send a meaningful HTTP response because TLS has not been terminated.

### Source identity

Direct Internet ingress uses the TCP peer address.

Recommended source buckets:

- one bucket per IPv4 address;
- one bucket per IPv6 `/64`; and
- bounded LRU/TTL storage for source buckets.

If deployed behind an L4 load balancer that does not preserve source
addresses, all clients may appear as one source and per-source limits become
harmful. PROXY protocol support is not currently designed and must not be
enabled by trusting arbitrary public bytes. The deployment topology must
therefore be decided before source limiting is finalized.

### Timeouts and long-lived connections

Separate lifecycle timeouts:

- TCP ClientHello deadline;
- route lookup/discovery deadline;
- loopback backend-connect deadline;
- PHXP negotiation deadline;
- graceful shutdown deadline; and
- optional relay idle timeout.

Do not impose a short maximum connection lifetime: WebSockets, HTTP/2, gRPC,
and streaming are intended workloads. If relay idle timeout is enabled, it
must measure bidirectional application inactivity and default high enough not
to break expected long-lived traffic. Handoff lifetime is controlled by the
workload after transfer.

### Workload isolation and handoff

The accepted first deployment uses one operator-controlled ingress trust
domain:

- ingress and all PHXP-enabled workloads run under one dedicated production
  service UID;
- handoff is preferred automatically after certificate-verified route
  selection;
- encrypted loopback relay remains the compatibility and safe pre-delivery
  fallback;
- compromise of one workload may expose every secret and socket available to
  the shared UID; and
- the model must never be described as multi-tenant isolation.

Development uses the login user's identity but retains the same same-UID
handoff semantics. Cross-UID handoff is not part of this design and must never
be approximated by removing peer authentication. Adding an untrusted workload
requires revisiting this trust-domain decision. See
[`ADR 0004`](adr/0004-use-one-production-ingress-trust-domain.md).

### Privilege and systemd

Ingress must not run as root.

Recommended final deployment uses a system-level `.socket` and `.service`:

- systemd owns public TCP 443;
- the service receives inherited listener descriptors;
- ingress runs as a dedicated non-login user;
- restart does not require rebinding the public port;
- no executable file capability must be persisted across upgrades; and
- queued connections can survive a short process restart.

If socket activation is deferred, use a system service with:

```ini
User=phx-port
Group=phx-port
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
```

The final unit should also define, after compatibility testing:

```ini
Restart=on-failure
RestartSec=2s
LimitNOFILE=65536
TasksMax=1024
MemoryMax=<host-specific>
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictRealtime=true
SystemCallArchitectures=native
```

`ReadOnlyPaths`, `ReadWritePaths`, `RestrictAddressFamilies`, and syscall
filters must be derived from actual daemon and handoff requirements and tested
instead of copied blindly.

### Network policy

The host or VPC firewall should expose only:

- TCP 443 publicly;
- TCP 80 only if an explicit redirect or ACME design is accepted; and
- administrative access from restricted source networks.

Backend ports must bind loopback and must not be admitted by the public
firewall. Ingress connects only to `127.0.0.1`; IPv6 loopback backend support
may be added explicitly but must never accept arbitrary route destinations.

### Availability and restart

The first hardened mode remains one process on one host. It cannot survive host,
kernel, network-interface, or availability-zone failure.

Within that boundary:

- systemd restarts a failed process;
- socket activation preserves the public listen socket;
- configuration reload is atomic;
- handed-off connections survive ingress exit;
- relay connections currently do not survive process exit;
- shutdown stops admission, drains relays to a deadline, then exits; and
- the process may run while required routes are unavailable, but readiness
  remains false and names each bounded failure reason until they verify.

Zero-downtime relay migration between ingress processes is out of scope.
Operators requiring host-level high availability should place two hosts behind
an L4 load balancer or use a mature HA ingress until a multi-host design exists.

### Health

Expose separate semantics:

- **Liveness**: process event loop is responsive.
- **Readiness**: listeners are active, configuration snapshot is valid, and
  all route declarations marked `required = true` are verified.
- **Degraded readiness detail**: optional routes, certificate conflicts,
  expiring certificates, and failed reload generations.

Recommended interfaces:

- preserve the private Unix control socket;
- add `phx-port proxy status --json`;
- add `phx-port proxy check --ready`;
- optionally expose Prometheus text on a loopback-only listener; and
- support systemd watchdog notification after the runtime model is stable.

No health or metrics endpoint binds publicly by default.

### Observability

Required counters:

- accepted, admitted, and overload-rejected connections;
- rejection by global, source-rate, source-concurrency, and state limit;
- ClientHello timeout and parse failure;
- declared-route hit, unknown-SNI rejection, and dynamic discovery;
- probe attempts, latency, timeout, and result;
- active pre-routing and relay connections;
- handoff attempts, successes, pre-delivery fallback, and post-delivery failure;
- relay bytes and duration;
- route activation, deactivation, conflict, and certificate fingerprint change;
- configuration reload success/failure;
- graceful drain result; and
- worker/blocking-pool saturation.

Required histograms:

- time to parse ClientHello;
- route lookup/discovery latency;
- backend connect latency;
- handoff negotiation latency;
- relay duration; and
- graceful drain duration.

Metrics labels must be bounded. Exact hostname labels are allowed only for
declared routes with a configured maximum. Never label by source IP, connection
ID, certificate, arbitrary SNI, or error string.

Logs should be structured, rate-limited, and written to stderr for journald.
Attacker-controlled hostnames must be normalized, length-bounded, and escaped.
Repeated parse failures and unknown SNI should aggregate into counters rather
than one log line per connection.

### Control plane

Production uses `/run/phx-port/control/`, owned by the service UID and
`phx-port-admin` group with mode `0750`, containing a mode `0660` Unix socket.
The endpoint remains local and uses command-aware peer authorization:

- the service UID and `phx-port-admin` members may inspect status, routes, and
  readiness;
- only UID 0 may reload, stop, or perform future mutations; and
- development retains its current-user mode `0600` full-authority socket in
  the existing private runtime directory.

Root-only production mutation is intentional: every workload shares the
service UID, so granting that UID mutation would grant every compromised
workload permission to stop or reconfigure ingress. Harden control handling by:

- validating parent ownership and refusing symlinks;
- checking peer credentials on every accepted connection;
- comparing against the configured operator UID or group policy;
- bounding request and response sizes;
- retaining read/write timeouts;
- making mutating commands explicit;
- adding a configuration reload command only after atomic reload exists; and
- returning a versioned machine-readable response for automation.

`STOP` and future mutation operations require stronger authorization than
read-only status if group-readable administration is introduced.

### Certificate operations

Each workload continues to obtain and renew its own certificate. Recommended
production practice:

- DNS-01 for independently deployed workloads or another renewal method that
  does not depend on central HTTP routing;
- atomic certificate replacement inside each workload;
- route revalidation at least every 30 seconds;
- alerting before certificate expiration;
- exact hostname declarations; and
- no disabling of certificate validation.

Port 80 redirect and HTTP-01 ACME are separate HTTP-routing responsibilities.
They should not be smuggled into the TLS ingress design.

### Encrypted ClientHello

Routing requires a usable plaintext SNI. Encrypted ClientHello may expose only
an outer public name that does not identify the target workload.

Initial policy:

- document ECH as unsupported unless outer SNI maps deterministically;
- do not attempt ClientHello decryption;
- close unknown outer names; and
- monitor deployment requirements before designing an explicit outer-name
  gateway.

### Logging and privacy

The ingress can observe source IP, SNI, timing, byte counts, and route identity
but not application plaintext.

Recommended policy:

- metrics retain only aggregates;
- normal logs omit source IP;
- diagnostic source-IP logging is opt-in and short-lived;
- no ClientHello payload dumps;
- journald retention is host policy;
- route and certificate events may include declared hostname and fingerprint;
  and
- public error strings are never reflected because ingress does not terminate
  TLS.

## Failure behavior

| Failure | Required behavior |
|---|---|
| Global admission exhausted | Close immediately, increment bounded metric |
| Source rate exceeded | Close immediately, increment bounded metric |
| ClientHello deadline | Close and release permit |
| Malformed or missing SNI | Close and release permit |
| Undeclared SNI in public mode | Close without probing workloads |
| Declared workload unavailable | Close; readiness degrades if required |
| Certificate invalid | Keep route inactive and alert |
| Configuration reload invalid | Keep previous snapshot active |
| Handoff unavailable before descriptor delivery | Relay if relay capacity exists |
| Handoff failure after descriptor delivery | Close; never relay |
| Relay capacity exhausted | Close before opening backend socket |
| Metrics sink unavailable | Continue serving; expose local diagnostic |
| Derived state corrupt | Rebuild from declarations and certificates |
| Control socket unauthorized | Close and audit with rate limiting |
| Graceful drain deadline | Force-close remaining relays, report the bounded timeout, and complete the controlled shutdown |

## Capacity model

Operators must size these resources together:

```text
public sockets
  + relay backend sockets
  + control/probe/handoff sockets
  < LimitNOFILE and kernel file-max budget

runtime worker threads
  + bounded blocking probe workers
  + bounded blocking PHXP workers
  + framework/runtime threads
  < TasksMax and host PID budget

connection state
  + relay buffers
  + source-limit table
  + route table
  < MemoryMax with safety margin
```

At least 30% of the daemon's FD and memory limits should remain reserve for
control, probes, handoff, reload, and error handling. Admission limits must be
derived from measured per-connection memory rather than set equal to
`LimitNOFILE`.

Relay mode also consumes loopback ephemeral ports. High relay density requires
monitoring ephemeral-port usage and `TIME_WAIT`; handoff avoids that second TCP
connection.

## Validation requirements

### Unit and property tests

- configuration bounds, unknown keys, and atomic generation replacement;
- route declaration normalization and duplicate/conflict rejection;
- token-bucket refill and burst behavior with a fake clock;
- IPv4 and IPv6 `/64` source bucketing;
- bounded source-table eviction;
- admission permit release on every error path;
- handoff release versus relay-lifetime retention;
- bounded metric label construction;
- log escaping and rate limiting;
- control peer authorization; and
- systemd unit rendering.

### Integration tests

- undeclared SNI does not trigger backend probes;
- declared SNI activates only with a matching trusted certificate;
- invalid reload preserves the previous active route;
- global and source overload fail closed;
- a slow ClientHello cannot exceed pre-routing capacity;
- relay capacity prevents backend connection creation when exhausted;
- handed-off connections survive ingress shutdown;
- relayed connections drain to the configured deadline;
- backend restart deactivates and reactivates a required route;
- control and metrics endpoints are unreachable publicly;
- service runs without UID 0; and
- service cannot read paths outside its allowlist.

### Load and abuse tests

Run on the smallest intended production host:

- connection-rate ramp until admission rejection;
- slowloris ClientHello traffic;
- random valid and malformed SNI;
- long-lived idle and active WebSockets;
- HTTP/2 multiplexing;
- relay and handoff mixes;
- backend outage and restart during load;
- ingress restart during handoff and relay traffic;
- certificate rotation and expiration simulation;
- log-flood attempts;
- FD and memory pressure; and
- IPv4 plus IPv6 source distribution.

Define pass/fail thresholds before testing. No unbounded growth is acceptable
after load returns to zero.

## Rollout policy

Public-hosting mode progresses through:

1. loopback-only functional tests;
2. private VPC/LAN traffic;
3. public canary hostname;
4. low-risk projects;
5. sustained observation through certificate rotation and ingress restart;
6. broader migration; and
7. production-ready declaration only after the acceptance gates pass.

Keep a conventional SNI passthrough proxy configuration or rapid DNS/L4
rollback available during the pilot.

## Decision register

The following questions require operator answers. They are ordered by
dependency: later answers may be revisited when an earlier assumption changes.
Each question includes the recommended production-grade answer.

### Q01 — What reliability target applies?

**Question:** Is this an experimental personal host, a production host with a
best-effort target, or an ingress with a measured availability SLO?

**Decision: Accepted — single-host production pilot first, while preserving a
straightforward symmetric active-active path.**

The first deployment intentionally accepts one host as its availability
boundary. The architecture must not introduce a dependency on singleton live
state that would prevent later deployment of equivalent ingress nodes and
workloads behind external health-based traffic distribution.

**Recommendation:** Start as a production pilot for noncritical personal
projects with a documented single-host target of 99.5-99.9%, not a contractual
HA service.

**Trade-off:** A higher SLO immediately requires at least two hosts, external
health-based traffic distribution, and a different implementation scope.

**Blocks:** Q04, Q05, Q24, Q27.

**Multi-host consequence:** Nothing in certificate-derived routing requires a
shared runtime route database. Each ingress node can load the same route
declarations, resolve its own loopback workload ports, verify certificates
locally, and keep disposable local route state. A later symmetric deployment
does require:

- health-aware L4 traffic distribution rather than unmonitored DNS round-robin;
- identical logical project identities, roles, and route declarations on every
  node, without relying accidentally on host-specific filesystem paths;
- each workload and certificate to be present and ready on every serving node;
- coordinated configuration and binary rollout;
- application sessions, databases, uploads, queues, and other mutable state to
  tolerate requests reaching any node;
- certificate renewal that does not race shared DNS-01 records or storage;
- per-node admission limits understood as aggregate cluster capacity;
- per-node control, metrics, and readiness aggregation; and
- graceful node removal before maintenance.

PHXP handoff remains entirely host-local and needs no cross-node protocol.
Relayed and handed-off connections both remain pinned to the node that accepted
them.

### Q02 — Are workloads inside one trust domain?

**Question:** If one project is compromised, is it acceptable to assume the
attacker can access other projects running under the same Unix identity?

**Decision: Accepted — all hosted projects belong to one shared trust
domain.**

The ingress and workloads may run under one dedicated service UID so existing
same-UID PHXP authentication remains valid. This is suitable only for projects
owned and trusted by the same operator. The production threat model explicitly
accepts that remote code execution in one workload may expose the files,
environment, certificates, control endpoints, and connections available to
that shared UID.

**Pre-decision recommendation (superseded):** Use a dedicated UID per
production workload and treat shared-UID handoff as an explicit opt-in trust
group. The accepted shared trust domain deliberately chose the opposite
trade-off.

**Blocks:** Q03, Q19, Q23.

**Accepted trade-off:** Operational simplicity, original-peer preservation,
and zero-copy steady-state handoff are prioritized over containment between
these operator-owned workloads. This mode must not later be described as
multi-tenant isolation. Adding untrusted third-party workloads requires a new
trust-boundary decision before onboarding them.

### Q03 — Is handoff or Unix-user isolation the default?

**Question:** Should production optimize first for original-socket handoff or
for separate workload identities?

**Decision: Accepted — prefer handoff automatically and retain relay as the
compatibility fallback.**

All workloads are inside the accepted shared trust domain, so same-UID peer
authentication is compatible with the deployment model. A compatible receiver
gets the original socket. Missing, incompatible, or pre-delivery-failing
handoff falls back to encrypted loopback relay. Handoff is never required to
establish hostname ownership.

**Recommendation:** Given the accepted shared trust domain, prefer handoff
automatically and retain relay for incompatible workloads and safe
pre-delivery fallback.

**Trade-off:** Relay consumes more CPU, sockets, threads/tasks, and loopback
ephemeral ports and reports the proxy as peer unless another metadata mechanism
is added.

**Blocks:** capacity defaults, service identity, deployment layout.

**Accepted trade-off:** Runtime adapters and PHXP become production-critical
for the optimized path. The generic relay remains tested and operational for
non-cooperating workloads and safe pre-delivery failures. Existing
post-descriptor-delivery failures still close rather than relay.

### Q04 — Does traffic arrive directly or through an L4 load balancer?

**Question:** Will public clients connect directly to the host IP, or will a
cloud L4 load balancer/NAT sit in front?

**Decision: Accepted — direct public IP for the single-host pilot.**

Public DNS resolves to the host's public address. The VPC or cloud firewall
admits TCP 443, and `phx-port` receives the original client TCP peer address.
No PROXY protocol is accepted. A health-aware L4 load balancer is introduced
only with a later symmetric multi-host deployment.

**Recommendation:** For a single-host pilot, connect directly through the VPC
firewall. For higher availability, use an L4 load balancer that preserves
source addresses.

**Trade-off:** A non-preserving load balancer breaks meaningful per-source
limits unless trusted PROXY protocol support is separately designed.

**Blocks:** Q05, Q13, Q14, health interfaces.

**Accepted trade-off:** Host and public-IP failure cause total ingress outage
during the pilot. In return, source admission is based on authentic kernel
peer addresses and the first deployment has no external load-balancer
dependency.

### Q05 — Is host-level high availability in scope?

**Question:** Must service continue through host or availability-zone failure?

**Decision: Accepted — preserve active-active as a later milestone, excluded
from the first hardened release.**

The initial implementation remains single-host. It must keep authoritative
configuration portable, verified-route state disposable and host-local, and
readiness suitable for a future health-aware L4 balancer. It does not implement
distributed route state, leader election, or coordinated failover.

**Recommendation:** Not in the first pilot. State the single-host boundary and
design a two-host/L4 phase only after one-host operations are stable.

**Trade-off:** Deferring HA is much simpler but accepts total outage during host
failure.

**Blocks:** route-state coordination, external health, SLO.

**Accepted trade-off:** Some multi-host-friendly constraints are paid now even
though failover is deferred. Host or zone failure remains a complete outage
until the later milestone is delivered.

### Q06 — What is authoritative for production routing?

**Question:** Should unknown SNI dynamically scan workloads, or must every
public hostname be declared?

**Decision: Accepted — exact route declarations are authoritative in public-
hosting mode.**

Every public hostname maps explicitly to one logical workload ID and role. The
declared workload must still present a system-trusted certificate valid for
that exact hostname before the route activates. Undeclared SNI is closed
without candidate probing. Development mode retains fully dynamic discovery.

**Recommendation:** Require exact route declarations in public-hosting mode and
set `unknown_sni = "reject"`. Continue certificate verification before
activation.

**Trade-off:** Declarations add configuration but remove attacker-triggered
fan-out, discovery ambiguity, and the 32-candidate ceiling.

**Blocks:** config schema, positive route limits, readiness.

**Accepted trade-off:** Production adds a hostname inventory and deployment
step, but public input can no longer invoke workload fan-out and routing remains
deterministic beyond 32 workloads. Declarations express operator intent;
certificates remain cryptographic proof rather than being replaced by config.

### Q07 — What scale must one host support?

**Question:** How many workloads, hostnames, concurrent connections, new
connections per second, and long-lived connections are expected?

**Decision: Accepted — design each ingress node for 100 workloads, 1,000
declared hostnames, 20,000 concurrent public connections, 500 newly accepted
connections per second, and 5,000 long-lived connections.**

The concurrency target includes connections ultimately transferred to
workloads. The ingress resource budget still depends on the accepted worst-case
relay fraction because each relay retains two ingress-owned sockets and an
async relay task, while a handed-off connection leaves ingress after setup.

**Recommendation:** Design for the accepted 100 workloads, 1,000 declared
hosts, 20,000 concurrent public connections, 500 accepts/second, and 5,000
long-lived connections, then qualify the ingress at the Q26 safety margin.

**Trade-off:** Overprovisioned defaults consume memory and weaken abuse limits;
underprovisioned defaults reject legitimate bursts.

**Blocks:** Q11-Q17, systemd limits, load-test thresholds.

**Accepted trade-off:** The 20,000-connection target makes a bounded async data
plane a production prerequisite. The current native-thread implementation may
be hardened as an interim safety baseline but cannot satisfy this scale.
`LimitNOFILE`, system-wide FD capacity, relay ephemeral ports, memory, and
workload-level limits must be measured against the accepted relay fraction.

**Relay capacity decision: Accepted — remain safe at 100% relay and meet the
performance target through 25% relay.**

At the 20,000-connection ceiling, the sustained performance target covers
5,000 concurrent relays and 15,000 handed-off connections. If handoff becomes
unavailable more broadly, ingress may reject new relay work above its relay
capacity while remaining responsive, observable, and within all resource
ceilings. Correctness at 100% relay means bounded overload behavior, not a
promise to admit all 20,000 relays.

Capacity planning must reserve at least:

- 10,000 data-plane FDs for 5,000 admitted relays;
- public sockets during pre-routing and handoff negotiation;
- probe, control, listener, state, and error-handling FDs;
- a 30% operational reserve; and
- host-level ephemeral-port capacity for at least 5,000 loopback connections
  plus turnover.

The load harness must also force 100% relay attempts and verify deterministic
admission shedding without unbounded resource growth.

### Q08 — How are certificates issued and renewed?

**Question:** Does each workload already perform DNS-01, HTTP-01, TLS-ALPN-01,
or externally managed certificate deployment?

**Decision: Accepted — every workload independently owns DNS-01 issuance and
atomic certificate renewal.**

Ingress never receives DNS-provider credentials, certificate private keys, or
renewal authority. It validates the certificate presented by the declared
workload, records bounded expiry/fingerprint telemetry, and automatically
revalidates rotations.

**Recommendation:** Keep independent workload-owned DNS-01 renewal.

**Trade-off:** DNS-01 needs DNS API credentials but avoids adding port-80 or
ACME routing to ingress.

**Blocks:** Q10, readiness, certificate alerting.

**Accepted trade-off:** DNS API credentials exist in each workload's security
boundary. A later symmetric deployment must prevent replicas from racing DNS
challenge cleanup or certificate storage, using each application's issuer
coordination rather than centralizing that responsibility in `phx-port`.

### Q09 — What is the ECH policy?

**Question:** Are target clients or domains expected to enable Encrypted
ClientHello?

**Decision: Accepted — ECH is unsupported during the production pilot.**

Hosted DNS names must not publish ECH configuration that hides the SNI needed
for route selection. Ingress does not decrypt ClientHello and does not
terminate TLS to recover routing identity.

**Recommendation:** Explicitly declare ECH unsupported for the pilot and avoid
publishing ECH DNS configuration.

**Trade-off:** This delays ECH privacy benefits; supporting it later may require
outer-name grouping or TLS termination.

**Blocks:** public DNS documentation and future architecture.

**Accepted trade-off:** Clients retain ordinary TLS 1.3 security but not ECH
hostname privacy. ECH support requires a later outer-name or termination
design and is not an implicit compatibility promise.

**Client activation detail:** ECH is not something a conforming client can use
unilaterally to hide SNI from this ingress. The client first needs an ECH
configuration published for the hostname through a DNS HTTPS/SVCB record and
an ECH-capable frontend holding the corresponding private key. Without that
DNS configuration, clients send an ordinary visible SNI. Some clients may send
an ECH GREASE extension to prevent protocol ossification, but GREASE does not
hide the real routing SNI and must not be mistaken for negotiated ECH.

Known client families include Firefox, Chromium-derived browsers when enabled
by their platform/policy, ECH-capable TLS libraries and command-line tools, and
custom Apple applications that explicitly enable Apple's experimental Security
framework option. Apple documents that API as default-false; Safari-wide
default behavior must not be assumed from the API's existence. The decisive
operator control remains: do not publish an `ech` DNS HTTPS/SVCB parameter for
pilot hostnames.

### Q10 — What should happen on public port 80?

**Question:** Close it, redirect all HTTP to HTTPS, or use it for ACME?

**Decision: Accepted — keep public TCP port 80 closed for the first pilot.**

DNS-01 certificate issuance does not need port 80. The VPC firewall does not
admit it, and `phx-port` does not add an HTTP parser or redirect service.

**Recommendation:** Keep port 80 closed initially. Add a separate minimal
redirect service only if user experience requires it.

**Trade-off:** Closing is smallest and safest but `http://` URLs do not redirect.

**Blocks:** firewall and service unit scope.

**Accepted trade-off:** Explicit `http://` visits fail instead of redirecting.
If operational evidence later requires redirects, add a separately supervised,
minimal redirector rather than expanding the TLS ingress implicitly.

### Q11 — Is an async runtime migration accepted?

**Question:** May the ingress data plane migrate from native thread-per-
connection code to Tokio?

**Decision: Accepted — migrate the production ingress data plane to Tokio.**

Listeners, ClientHello socket readiness, relay copying, task ownership,
cancellation, and graceful drain become asynchronous. Certificate probes and
PHXP operations may initially use the explicitly sized, semaphore-bounded
blocking pools defined by Q12.
Strict admission is added to the existing threaded implementation first, but
that implementation is only a transitional safety baseline.

**Recommendation:** Yes. First add a low admission ceiling to the threaded
implementation, then migrate listeners and relay to Tokio before claiming
high-density readiness.

**Trade-off:** Tokio adds dependencies and a material refactor but removes the
native-thread scaling ceiling and improves cancellation.

**Blocks:** implementation phases, target concurrency, shutdown design.

**Accepted trade-off:** Tokio becomes a durable runtime dependency and the
data-plane migration is a material refactor. In return, native thread count is
decoupled from the accepted 20,000 concurrent sockets and cancellation,
timeouts, and draining gain one coherent model. See
[`ADR 0001`](adr/0001-use-tokio-for-public-ingress.md).

### Q12 — What global concurrency policy is desired?

**Question:** Should limits be fixed, automatically derived from system limits,
or both?

**Decision: Accepted — production limits are explicit and startup-validated
against host resources.**

The daemon does not silently derive admission behavior from ambient limits.
`preflight` may calculate and print recommendations, but the accepted values
live in authoritative configuration and are identical across symmetric hosts.
Startup fails if FD reserve, limit relationships, arithmetic, or supported
ranges are unsafe.

Startup may raise its own soft `RLIMIT_NOFILE` to the minimum required by the
configured ceilings when the existing hard limit permits it, then must re-read
and validate the effective limit. This is capacity-to-host preparation, not
ambient derivation of capacity: configured ceilings never change, a failed or
partial raise fails startup, and service definitions still declare their
resource limits explicitly.

**Recommendation:** Explicit configured maxima validated against
`RLIMIT_NOFILE`, with startup failure if unsafe. Use the accepted 256 cap while
threaded and the benchmark ceilings above for the async pilot.

**Trade-off:** Fixed values are predictable but need host tuning; automatic
values can surprise operators after environment changes.

**Blocks:** overload tests and systemd `LimitNOFILE`.

**Accepted trade-off:** Host resizing or workload growth requires an explicit
configuration change. In return, overload behavior is reviewable,
deterministic, and cannot drift because a systemd or shell limit changed.

**Initial benchmark ceilings: Accepted.**

The first async load campaign uses:

| Resource | Ceiling |
|---|---:|
| Workload-facing public connection target | 20,000 |
| Ingress-owned connection state machines | 8,192 |
| Pre-routing ClientHellos | 1,024 |
| Concurrent relays | 5,000 |
| Concurrent PHXP negotiations | 256 |
| Concurrent certificate probes | 32 |
| Transitional threaded active connections | 256 |
| Process `LimitNOFILE` | 65,536 |
| Calculated FD reserve | at least 30% |

These are benchmark inputs. They become shipped defaults only after the
smallest accepted target VM meets latency and resource gates. Startup computes
worst-case FD demand from configured sublimits and rejects a configuration
that leaves less than the required reserve.

### Q13 — What per-source admission policy is acceptable?

**Question:** What legitimate NAT/shared-client bursts must not be rejected?

**Decision: Accepted — enforce 20 new connections/second with burst 40 and 16
simultaneous pre-routing connections per source bucket.**

The limiter applies while ingress owns or negotiates a connection. After PHXP
handoff, the workload is responsible for its own source and active-connection
policy. The source table is bounded, TTL-evicted, and never emits source-
cardinality metric labels.

**Recommendation:** Token bucket per IPv4 or IPv6 `/64`, initially 20 new
connections/second with burst 40 and 16 concurrent pre-routing connections.

**Trade-off:** Strict limits blunt abuse but can penalize offices, mobile
carrier NAT, CI fleets, and monitoring systems.

**Blocks:** Q04 and measured traffic.

**Accepted trade-off:** Large NAT populations may be throttled. Explicit
operator-configured CIDR exemptions may adjust the policy for trusted monitors
or networks, but client-provided SNI and headers can never bypass it.

### Q14 — How should IPv6 clients be grouped?

**Question:** Per address, `/64`, or configurable prefix?

**Decision: Accepted — group IPv6 clients by `/64` and IPv4 clients by exact
address.**

The global IPv6 prefix length remains configurable, and operator-declared CIDR
policy may override it for known network allocation models.

**Recommendation:** `/64` default with a configurable prefix length.

**Trade-off:** Per-address is easily bypassed through IPv6 address rotation;
`/64` can combine many legitimate users on unusual networks.

**Blocks:** source limiter key format and metrics.

**Accepted trade-off:** A provider placing many legitimate clients behind one
`/64` shares a bucket. In return, clients controlling many addresses inside a
normal subscriber prefix cannot multiply their admission allowance.

### Q15 — What ClientHello deadline is acceptable?

**Question:** Retain two seconds or allow slower clients?

**Decision: Accepted — retain a two-second total ClientHello deadline,
configurable from 500 milliseconds through 10 seconds.**

The deadline begins at accept and is not reset by fragment progress.

**Recommendation:** Retain two seconds for direct public ingress, configurable
between 500 ms and 10 seconds.

**Trade-off:** Longer deadlines help poor networks but multiply slowloris
capacity requirements.

**Blocks:** pre-routing capacity and abuse tests.

**Accepted trade-off:** Extremely slow or lossy clients may fail before
routing. In return, fragment trickling cannot extend occupancy indefinitely,
and the 1,024-slot pre-routing budget has a predictable worst-case duration.

### Q16 — May idle relays be closed?

**Question:** Should ingress enforce a bidirectional relay idle timeout?

**Decision: Accepted — default to a 30-minute bidirectional relay idle
timeout, with per-route override or disable.**

Any payload progress in either direction resets the timer. The policy applies
only while ingress owns a fallback relay; handed-off connections follow the
workload's timeout and heartbeat policy.

**Recommendation:** Default to 30 minutes in public-hosting mode, configurable
or disabled per declared route for known long-lived protocols.

**Trade-off:** An idle timeout bounds dead connections but can break quiet
WebSockets, gRPC streams, and application heartbeats.

**Blocks:** route schema and async copy implementation.

**Accepted trade-off:** A genuinely quiet relay may disconnect unless its
declaration opts out or extends the duration. In return, dead relays cannot
retain two FDs and an ingress task forever.

### Q17 — What overload behavior should operators observe?

**Question:** Silent TCP close, TCP reset, or delayed admission?

**Decision: Accepted — immediately close newly accepted sockets when admission
is exhausted.**

Ingress adds no user-space waiting queue. Existing admitted connections
continue. A bounded reason counter and rate-limited aggregate warning expose
global, source, pre-routing, relay, or handoff saturation.

**Recommendation:** Immediate close without user-space queueing, plus counters
and a rate-limited warning.

**Trade-off:** Clients receive an opaque network/TLS error, but ingress remains
available to admitted traffic.

**Blocks:** listener implementation and operational runbook.

**Accepted trade-off:** Rejected clients receive an opaque connection or TLS
failure and must retry. This is preferable to hidden queue growth, stale
ClientHello deadlines, and cascading resource exhaustion.

### Q18 — How should port 443 privilege be granted?

**Question:** systemd socket activation, ambient capability, executable
`setcap`, or root?

**Decision: Accepted — use service-manager socket activation on Linux and
macOS.**

One internal activated-listener abstraction adopts and validates:

- named descriptors supplied through systemd `LISTEN_FDS` on Linux; and
- named descriptors returned by `launch_activate_socket()` for a launchd
  `Sockets` entry on macOS.

The service manager owns public port 443 and the ingress process runs
unprivileged. Explicit `--listen` binding remains available for foreground and
development use.

**Recommendation:** systemd socket activation on Linux and launchd socket
activation on macOS. Use ambient `CAP_NET_BIND_SERVICE` only as an intermediate
Linux step. Never run as root.

**Trade-off:** Socket activation requires inherited-listener support but gives
clean privilege separation and better restart behavior.

**Blocks:** service implementation and restart semantics.

**Accepted trade-off:** Two platform adapters and service definitions must be
implemented and tested. In return, listener ownership, privilege separation,
and short-restart behavior share one architecture without relying on
executable `setcap` or macOS wildcard-bind behavior. See
[`ADR 0002`](adr/0002-use-service-manager-socket-activation.md).

**Manual startup decision: Accepted — support
`sudo phx-port daemon --run-as USER`.**

Service-manager activation is not mandatory for foreground operation. The
manual privileged path:

1. requires an explicit target user when effective UID is zero;
2. resolves the account and its primary/supplementary groups before dropping;
3. binds only the explicitly requested public listeners while privileged;
4. clears supplementary groups and establishes the target group set;
5. permanently sets target GID and UID using platform-appropriate calls;
6. verifies real/effective identity and that privilege cannot be regained;
7. applies Linux `no_new_privs` where available;
8. only then reads mutable state, creates runtime/control/handoff paths, starts
   worker/runtime threads, and accepts public input; and
9. fails closed if any transition cannot be proven.

Bare `sudo phx-port` retains its existing no-argument behavior. The daemon
never remains UID 0. Files created after the drop belong to the same identity
used by PHXP workloads.

`--run-as` requires explicit `--listen` arguments. After dropping privilege,
the daemon loads the ingress configuration and fails startup if its declared
listener set does not exactly match the already-bound listeners. It never
parses mutable state or accepts public input as root.

### Q19 — Which identity owns ingress files and processes?

**Question:** Dedicated `phx-port` user, operator login user, or shared web UID?

**Decision: Accepted — identity follows the hosting profile.**

- Production hosts use one dedicated, non-login `phx-port` service account for
  ingress and all PHXP-enabled workloads in the accepted trust domain.
- Development laptops use the interactive login user for ingress and
  workloads.
- Production `/etc/phx-port` configuration is root-owned and read-only to the
  service account.
- Production runtime and derived state are owned by the service account.
- Manual production startup uses `--run-as phx-port`; manual development runs
  directly as the login user or explicitly drops back to it after privileged
  binding.

**Recommendation:** Use the accepted dedicated non-login `phx-port` identity
for ingress and all workloads in this operator-controlled trust domain, with
read-only production configuration and writable derived-state/runtime
directories.

**Blocks:** filesystem paths, control authorization, deployment tooling.

**Accepted trade-off:** Production avoids coupling service uptime and files to
an operator login account while preserving same-UID handoff. It intentionally
does not isolate production workloads from one another. Development remains
frictionless and does not require creating a machine-wide service identity.

### Q20 — May production configuration be split from the dev registry?

**Question:** Keep one TOML file or introduce declarative config plus disposable
state?

**Decision: Accepted — split production configuration, stable assignments,
derived state, and runtime endpoints.**

The production profile uses:

```text
/etc/phx-port/ingress.toml       root-owned declarations, limits, and policy
/var/lib/phx-port/ports.toml     service-owned stable workload/role ports
/var/lib/phx-port/routes.toml    service-owned disposable verification cache
/run/phx-port/                   service-owned runtime sockets
```

Development retains the existing per-user registry unless the operator
explicitly enables public-hosting configuration.

**Recommendation:** Split `/etc/phx-port/ingress.toml`,
`/var/lib/phx-port/ports.toml`, and `/var/lib/phx-port/routes.toml`, with an
explicit import/migration command.

**Trade-off:** More files and migration logic produce clearer ownership,
backups, permissions, and atomic reload behavior.

**Blocks:** config implementation and systemd sandbox.

**Accepted trade-off:** Production gains explicit ownership, backup, reload,
and sandbox boundaries at the cost of migration and multiple files. Derived
certificate state is never copied back into root-owned operator intent.

**Development compatibility requirement:** The split applies only to an
explicit production profile. Default CLI allocation and startup-script
integration retain one per-user registry and home/runtime-directory state.
They never require `/etc`, `/var/lib`, a service account, or administrative
bootstrap.

Production profile activation is explicit through `--ingress-config PATH` or
`PHX_PORT_INGRESS_CONFIG`. The file itself must declare public mode. Presence of
system configuration never changes default development behavior.

**Production workload identity decision: Accepted — use an explicit logical
workload ID plus role.**

Production route declarations, stable port assignments, and PHXP endpoint
derivation reference a stable logical ID such as `contoso-web`, not a
filesystem path:

```toml
[workloads.contoso-web]
path = "/srv/releases/contoso/current" # optional diagnostic metadata

[ingress.hosts."www.contoso.com"]
workload = "contoso-web"
role = "https"
required = true
```

Every symmetric host deploys the same logical IDs and roles but may use
different local paths. Development continues to derive identity from canonical
project path for its zero-configuration workflow. Migration must detect
duplicate IDs and explicitly map existing paths. See
[`ADR 0003`](adr/0003-use-logical-production-workload-identities.md).

**Production port registration decision: Accepted — workloads update the
shared service-owned port registry directly.**

Each production workload receives `PHX_PORT_CONFIG` pointing at the shared
registry and its unique `PHX_PORT_WORKLOAD_ID`, then continues using ordinary
`phx-port` command substitution. Ingress need not be live. Existing lock and
atomic-write semantics become production invariants. Workloads cannot edit
root-owned route declarations through this path.

### Q21 — Which observability interface is preferred?

**Question:** journald plus CLI JSON, Prometheus, OpenTelemetry, or a
combination?

**Decision: Accepted — structured journald events, stable JSON CLI health and
status, and an optional loopback-only Prometheus endpoint.**

OpenTelemetry is deferred until a concrete collector or tracing use case
exists. Metric labels may include bounded declared hostname/workload identity
within the configured route ceiling. They never include source addresses,
arbitrary SNI, connection IDs, certificate contents, or error strings.

**Recommendation:** Structured journald logs, `status --json`, and an optional
loopback Prometheus endpoint. Defer OpenTelemetry.

**Trade-off:** Prometheus adds an operational endpoint and metric-schema
commitment but is broadly usable and low coupling.

**Blocks:** metric library and health integration.

**Accepted trade-off:** Prometheus creates an endpoint and long-lived metric
schema commitment, but supplies the time-series evidence needed for admission,
capacity, certificate, and drain operation. The endpoint is disabled unless
configured and never binds publicly.

### Q22 — What source-data logging policy applies?

**Question:** May normal logs contain source IPs and requested hostnames, and
for how long?

**Decision: Accepted — privacy-preserving normal logs with temporary sampled
diagnostics.**

Normal production events may name bounded declared hostname/workload identity
but omit source IP. Unknown SNI, parse errors, and admission rejection are
aggregate counters and rate-limited summaries rather than one event per
connection. A diagnostic mode may sample source IP and normalized SNI only
with an explicit expiry.

**Recommendation:** Log declared hostname and route events, omit source IP at
normal level, and enable sampled source diagnostics temporarily.

**Trade-off:** Privacy and low cardinality reduce forensic detail.

**Blocks:** event schema and runbook.

**Accepted trade-off:** Routine logs contain less forensic detail. In return,
client privacy, label cardinality, disk use, and resistance to attacker-driven
log amplification improve. Journald remains responsible for retention.

### Q23 — Who may use the local control plane?

**Question:** Only ingress UID, one operator UID, or an administration group?

**Decision: Accepted — split read-only and mutation authorization.**

- The service UID and `phx-port-admin` group may inspect status, routes,
  readiness, and metrics.
- Only UID 0 may reload, stop, or perform future mutations.
- Peer credentials are checked for every control connection.
- Production may use separate socket modes/endpoints or one command-aware
  credential policy, provided a monitoring principal cannot invoke mutation.
- Development retains one current-user socket with full authority.

**Recommendation:** Read-only status for the service UID and a dedicated
`phx-port-admin` group; production mutation restricted to root because
workloads share the ingress owner identity.

**Trade-off:** Split authorization complicates control handling but prevents a
monitoring user from stopping or reloading ingress.

**Blocks:** socket ownership, peer-credential checks, CLI behavior.

**Accepted trade-off:** Control handling and installation gain group/credential
policy. Monitoring automation and compromised same-UID workloads cannot stop
or reconfigure ingress; mutation is performed through root-authorized service
management.

### Q24 — What restart and drain contract is required?

**Question:** Maximum drain time, behavior at timeout, and whether relays may be
cut during upgrades?

**Decision: Accepted — stop admission immediately and drain relays for at most
60 seconds.**

Shutdown closes the process copy of activated listeners, cancels pre-routing
work, lets PHXP negotiations resolve descriptor ownership safely, and waits up
to 60 seconds for relays. Handed-off connections continue under workload
ownership. Remaining relays close at the deadline. Planned forced closure is
reported but does not turn a controlled shutdown into an endless failure loop.

**Recommendation:** Stop admission immediately, drain relays for 60 seconds,
then close them and exit; handed-off connections continue. Use socket
activation for queued new connections.

**Trade-off:** Long-lived relays may be interrupted at deploy time. Waiting
indefinitely prevents reliable upgrades.

**Blocks:** service timeout, cancellation model, deployment runbook.

**Accepted trade-off:** Long-lived fallback relays may be interrupted during
deploys, and a non-overlapping service restart may leave new connects in the
bounded kernel backlog during drain. Indefinite drain and relay migration are
out of scope for the first release.

### Q25 — What state must be backed up?

**Question:** Are port assignments configuration, and is derived route state
disposable?

**Decision: Accepted — back up declarations and stable port assignments only.**

Backups preserve root-owned ingress configuration, service-owned stable
workload/role ports, and their ownership/mode metadata. Verified-route cache
and runtime endpoints are disposable and rebuilt locally. Deployment
automation remains the authoritative source for `/etc/phx-port`.

**Recommendation:** Back up declarative ingress configuration and stable port
assignments; rebuild certificate-derived route state.

**Trade-off:** Rebuilding causes a short verification warm-up after disaster
recovery but avoids treating cache data as authority.

**Blocks:** file split and recovery runbook.

**Accepted trade-off:** Cold restore remains unready during local certificate
verification. In return, stale route cache never becomes restored authority
and runtime sockets are never treated as portable state.

### Q26 — What load-test target gates production?

**Question:** Which smallest VM shape and workload mix define success?

**Decision: Accepted — qualify ingress on a 4 vCPU / 8 GiB Linux host at the
recommended safety-margin load.**

The isolated ingress gate runs for 30 minutes with:

- 30,000 live public connections: 25,000 successfully handed off to lightweight
  harness receivers and 5,000 admitted relays;
- 1,000 newly accepted connections per second;
- a separate 7,500-simultaneous-relay attempt in which exactly the configured
  maximum of 5,000 remains admitted and excess attempts are deterministically
  shed;
- 7,500 long-lived connections distributed across handoff and admitted relay;
- correct service for admitted traffic;
- configured shedding beyond admission ceilings;
- bounded FD, task, memory, source-table, and log use; and
- return to baseline after load ends.

A separate whole-host soak uses representative workloads so application
resource consumption is visible without weakening the ingress-specific gate.

**Recommendation:** Choose the actual smallest intended VM and require twice
the expected peak connection rate plus 1.5 times expected concurrency for 30
minutes, with bounded memory/FD/task counts and no route errors for admitted
traffic.

**Trade-off:** A meaningful gate costs test automation and cloud time but turns
capacity settings into evidence.

**Blocks:** final defaults and promotion.

**Accepted trade-off:** The gate may force tuning or a larger operational host
even though the benchmark machine remains the qualification floor. Testing
ingress separately proves its budget; it does not claim 100 real workloads fit
inside the same 8 GiB alongside application state.

### Q27 — What is the pilot and rollback?

**Question:** Which hostname is safe to canary, how long should it run, and how
quickly must rollback complete?

**Decision: Accepted — canary one low-risk hostname through a full automated
DNS-01 renewal cycle with two independent rollback paths.**

The canary also exercises ingress restart, workload restart, handoff endpoint
loss with relay recovery, and certificate rotation. DNS TTL remains 60 seconds
during onboarding.

Rollback must complete in under five minutes through either:

1. the previously proven `phx-port` binary and configuration, using a registry
   schema readable by the preceding release or a pre-rollout registry snapshot;
   or
2. an independently tested HAProxy or NGINX-stream TCP/SNI configuration
   generated from exact declarations and the stable port registry without
   application private keys.

**Recommendation:** One low-risk hostname for at least one certificate renewal
cycle, with DNS TTL at 60 seconds during onboarding and a tested conventional
SNI-proxy or DNS rollback under five minutes.

**Trade-off:** A full renewal cycle slows promotion but exercises one of the
architecture's central promises.

**Blocks:** production-ready declaration.

**Accepted trade-off:** Promotion waits for a real renewal and maintains an
independent fallback implementation. In return, certificate lifecycle and
rollback do not depend only on the new ingress code.

## Accepted decision summary

```text
single-host production pilot; symmetric active-active later
one operator-controlled trust domain
handoff preferred; encrypted relay fallback
direct public IP for the pilot
health-aware L4 balancing deferred to the multi-host milestone
exact declared production routes
100 workloads / 1,000 hosts / 20,000 public connections
500 accepts/second / 5,000 long-lived connections
safe bounded behavior at 100% relay; performance through 25% relay
workload-owned DNS-01 certificates
ECH unsupported
port 80 closed
Tokio production data plane
explicit validated capacity limits
8,192 ingress states / 1,024 pre-routing / 5,000 relays
256 PHXP negotiations / 32 probes / LimitNOFILE 65,536
20 connections/second, burst 40, 16 pre-routing per source
IPv4 address and IPv6 /64 source buckets
2-second ClientHello deadline
30-minute default relay idle timeout with route override
immediate close on overload
systemd activation on Linux / launchd activation on macOS
manual sudo daemon startup with mandatory permanent privilege drop
dedicated shared production service user / login user in development
split declarative configuration and derived state
logical production workload IDs / canonical development paths
explicit --ingress-config or PHX_PORT_INGRESS_CONFIG activation
journald + JSON status + optional loopback Prometheus
privacy-preserving logs with expiring sampled diagnostics
service/admin read-only control; root-only production mutation
60-second relay drain
back up declarations and port assignments only
4 vCPU / 8 GiB qualification at 30k live (25k handoff + 5k relay) and 1k accepts/s
one-renewal-cycle canary with previous-binary and independent SNI rollback
```

## Acceptance criteria

Public-hosting mode is ready for a canary when:

1. Every decision register item has an accepted answer or explicit deferral.
2. No public input creates unbounded user-space work or state.
3. Exact declarations route only after certificate verification.
4. Undeclared SNI causes no workload probes by default.
5. Limits are configurable, validated, observable, and tested.
6. The current threaded runtime is capped before public exposure.
7. High-density claims require the async data-plane migration and load proof.
8. Ingress runs non-root with tested systemd and launchd production service
   definitions.
9. Workload UID and handoff policy is explicit.
10. Configuration reload is atomic and preserves the last valid generation.
11. Health distinguishes liveness, readiness, and degradation.
12. Metrics have bounded cardinality and logs are rate-limited.
13. Control operations authenticate local peer identity.
14. Shutdown and rollback behavior is rehearsed.
15. Load and abuse tests meet the accepted gate on the target VM.

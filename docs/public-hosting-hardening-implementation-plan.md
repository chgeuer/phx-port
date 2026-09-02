# Public Hosting Hardening Implementation Plan

## Status

Ready for implementation. The
[public-hosting decision register](public-hosting-hardening-design.md#decision-register)
was accepted on 2026-09-02.

## Delivery strategy

Use vertical safety milestones rather than one runtime rewrite:

1. make the existing threaded daemon predictably bounded;
2. make production routes explicit and configuration atomic;
3. establish least-privilege service operation and observability;
4. migrate the bounded data plane to async;
5. prove behavior under hostile load; and
6. canary before claiming production readiness.

Every phase must preserve:

- development-mode behavior;
- the zero-bootstrap `PORT="$(phx-port)" workload` laptop workflow;
- per-user home/runtime storage when no production profile is explicit;
- Linux and macOS handoff tests;
- generic TLS relay compatibility;
- certificate-based route authorization;
- safe pre/post-descriptor fallback semantics; and
- the ability to revert to the preceding release and configuration.

## Phase 0 — Resolve operator decisions

### Deliverables

- Interview Q01-Q27 from the design in order.
- Record accepted answers inline in the decision register.
- Record the four hard-to-reverse architectural decisions in ADRs: async
  runtime migration, cross-platform service-manager socket activation, logical
  production workload identities, and the shared production trust domain.
- Establish the smallest target Linux VM shape and expected workload profile.
- Define canary hostname, observation period, and rollback.

### Accepted decisions

- **Q01:** Start with a single-host production pilot, but avoid singleton live
  state that would block a later symmetric active-active deployment. Verified
  route state remains disposable and host-local; external health-based traffic
  distribution and application-state concerns belong to the later multi-host
  deployment layer.
- **Q02:** All hosted workloads and ingress belong to one operator-controlled
  trust domain and may share one dedicated service UID. This intentionally
  enables existing same-UID PHXP handoff and does not provide compromise
  containment between workloads.
- **Q03:** Prefer PHXP handoff automatically for compatible workloads and use
  encrypted loopback relay for incompatible receivers or safe pre-delivery
  failures. Handoff remains an optimization after certificate-verified route
  selection, not a route-authorization requirement.
- **Q04:** Point public DNS directly at the pilot host and admit TCP 443 through
  the cloud firewall. Do not accept PROXY protocol. Introduce a source-
  preserving, health-aware L4 load balancer only for later symmetric
  multi-host deployment.
- **Q05:** Keep host-level active-active HA as a later milestone. The first
  hardened release is single-host but must use portable authoritative
  configuration, host-local disposable verification state, and an L4-usable
  readiness contract.
- **Q06:** Require exact hostname-to-workload/role declarations in public mode,
  reject undeclared SNI without probing, and continue requiring exact-hostname
  system-trusted certificate verification before activation. Keep dynamic
  discovery as the development default.
- **Q07:** Design each ingress node for 100 workloads, 1,000 exact host
  declarations, 20,000 concurrent public connections, 500 accepts/second, and
  5,000 long-lived connections. Tokio is required for the production target;
  the bounded threaded phase is only an interim safety baseline. Final FD,
  memory, and ephemeral-port budgets assume a performance target of 25% relay.
  The node must remain bounded and shed excess relay admission safely at 100%
  relay rather than promising full all-relay throughput.
- **Q08:** Keep DNS-01 certificate issuance, renewal, private keys, and DNS
  credentials inside each workload. Ingress verifies exact hostname trust,
  expiry, and rotations but never becomes a certificate authority or
  distribution service.
- **Q09:** Do not publish ECH configuration for pilot hostnames. Ingress
  requires visible SNI and will not decrypt ClientHello or terminate TLS to
  support ECH in the first hardened release.
- **Q10:** Keep public TCP port 80 closed. DNS-01 renewal needs no HTTP
  challenge path, and the first release adds neither HTTP parsing nor redirect
  behavior to ingress.
- **Q11:** Migrate the production data plane to Tokio. Add strict admission to
  the threaded implementation first as a safety baseline, then port listeners,
  ClientHello readiness, relay I/O, cancellation, and graceful drain. Keep
  blocking probes and PHXP behind explicit bounded capacity during migration.
- **Q12:** Store explicit capacity ceilings in production configuration and
  fail startup when they are unsafe relative to `RLIMIT_NOFILE`, reserve, or
  each other. `preflight` recommends but never silently chooses production
  values. Benchmark 8,192 ingress-owned states, 1,024 pre-routing sockets,
  5,000 relays, 256 PHXP negotiations, 32 probes, `LimitNOFILE=65536`, and at
  least 30% calculated FD reserve. Cap the transitional threaded build at 256.
- **Q13:** Enforce a bounded, expiring token bucket of 20 new connections per
  second with burst 40 and 16 concurrent pre-routing connections per source
  bucket. Permit only operator-configured CIDR policy overrides, and delegate
  post-handoff source limits to each workload.
- **Q14:** Key IPv4 source buckets by exact address and IPv6 buckets by `/64`.
  Keep the IPv6 prefix configurable and permit explicit CIDR overrides for
  known allocation models.
- **Q15:** Apply a two-second total ClientHello deadline from accept, never
  reset by fragment progress. Permit explicit configuration only from 500
  milliseconds through 10 seconds.
- **Q16:** Close fallback relays after 30 minutes without bytes in either
  direction. Reset on progress and allow an exact route declaration to extend
  or disable the timeout. Handed-off connection lifetime remains workload-
  owned.
- **Q17:** On any exhausted admission limit, close the new socket immediately
  without user-space queueing. Preserve admitted traffic and expose only
  bounded reason counters plus rate-limited aggregate warnings.
- **Q18:** Use one activated-listener abstraction backed by systemd
  `LISTEN_FDS` on Linux and launchd `launch_activate_socket()` on macOS.
  Service managers own port 443; ingress runs unprivileged. Keep explicit
  direct binding for foreground/development use. Also support
  `sudo phx-port daemon --run-as USER`: bind first, permanently drop groups,
  GID, and UID, verify the drop, and only then initialize writable state and
  accept traffic. Never run the data plane as root or overload bare
  `sudo phx-port`.
- **Q19:** Select identity by hosting profile. Production uses one dedicated
  non-login `phx-port` account for ingress and PHXP-enabled workloads, with
  root-owned read-only configuration and service-owned runtime/state.
  Development laptops continue under the interactive login user.
- **Q20:** Split production files into root-owned
  `/etc/phx-port/ingress.toml`, service-owned stable
  `/var/lib/phx-port/ports.toml`, disposable
  `/var/lib/phx-port/routes.toml`, and `/run/phx-port` runtime endpoints.
  Preserve the existing per-user development registry outside public mode.
- **Q20a:** Identify production workloads by explicit stable logical ID plus
  role. Use that identity for declarations, local stable port assignments, and
  PHXP endpoint derivation; retain canonical paths for development and optional
  diagnostics only.
- **Q20b:** Activate production only with `--ingress-config PATH` or
  `PHX_PORT_INGRESS_CONFIG`; require that file to declare `mode = "public"`.
  Keep `PHX_PORT_CONFIG` scoped to the existing port registry and never
  auto-detect production from `/etc`, UID, or operating system.
- **Q20c:** Let production workloads self-register through the shared writable
  `/var/lib/phx-port/ports.toml`. Each service sets that `PHX_PORT_CONFIG` and
  a required `PHX_PORT_WORKLOAD_ID`, then retains existing `phx-port` command
  substitution. Preserve exclusive locking, atomic writes, private modes, and
  ingress-independent allocation.
- **Q21:** Emit structured stderr events for journald, provide stable JSON
  status/readiness CLI output, and support an optional loopback-only Prometheus
  endpoint. Defer OpenTelemetry and enforce bounded metric labels.
- **Q22:** Omit source IP from normal logs, retain bounded declared route
  identity, and aggregate unknown SNI/parse/admission failures. Allow sampled
  source diagnostics only in an explicitly expiring debug mode.
- **Q23:** Permit service UID and `phx-port-admin` members to read production
  status/routes/health, but restrict reload/stop/mutation to root because every
  workload shares the service UID. Authenticate peer credentials per
  connection. Keep the development
  current-user socket fully authorized.
- **Q24:** Stop admission on shutdown, cancel pre-routing work, resolve PHXP
  ownership safely, and drain relays for at most 60 seconds before closing
  them. Handed-off connections survive. Keep the service-manager listener
  available for a bounded restart backlog.
- **Q25:** Back up root-owned ingress declarations and service-owned stable
  workload/role port assignments with permissions. Rebuild verified-route cache
  and runtime endpoints after restore, remaining unready until required routes
  verify.
- **Q26:** Gate ingress on 4 vCPU / 8 GiB Linux for 30 minutes at 30,000 live
  public connections (25,000 handed off to harness receivers and 5,000
  relayed), 1,000 accepts/second, and 7,500 long-lived connections. Separately
  attempt 7,500 simultaneous relays and require exactly the configured maximum
  to remain admitted with deterministic shedding above it. Require correct
  admitted traffic, bounded resources, and recovery to baseline. Run a
  separate representative whole-host workload soak.
- **Q27:** Canary one low-risk hostname through a complete automated DNS-01
  renewal while exercising restarts, handoff loss, relay recovery, and
  rotation. Keep DNS TTL at 60 seconds during onboarding and prove sub-five-
  minute rollback to both the previous binary and an independent generated
  HAProxy/NGINX-stream SNI configuration.

### Exit gate

- Complete: all register questions and dependent sub-decisions are accepted.
- Complete: capacity numbers have units and a named qualification VM.
- Complete: durable architectural decisions are recorded in ADRs.

## Phase 1 — Bound the existing daemon

This is the minimum prerequisite for any public canary. It deliberately keeps
the current blocking implementation while preventing unbounded thread and FD
growth.

### 1.1 Typed ingress limits

Add a typed configuration structure, initially populated by CLI flags or an
`[ingress.limits]` table:

```toml
[ingress.limits]
active_connections = 256
pre_routing_connections = 128
relay_connections = 128
handoff_negotiations = 64
accepts_per_second = 200
accept_burst = 400
client_hello_timeout_ms = 2000
```

Validate:

- nonzero required limits;
- relationship between sublimits and global limit;
- timeout ranges;
- estimated FD demand against `RLIMIT_NOFILE`;
- thread demand against configured/systemd task budget; and
- arithmetic overflow.

Startup fails with an actionable error for unsafe limits.

### 1.2 Admission permits

Introduce RAII permit types:

```text
GlobalIngressPermit
PreRoutingPermit
RelayPermit
HandoffNegotiationPermit
SourcePermit
```

Acquire global and source admission directly after `accept` and before
`thread::spawn`. If admission fails, close in the listener thread.

State transitions:

```text
accepted
  -> global + source permit
  -> pre-routing permit
  -> route selected
      -> handoff permit -> descriptor delivered -> release all ingress permits
      -> release source + pre-routing permits
      -> relay permit   -> retain global/relay until closure
```

Tests must prove permit release under every error and panic boundary that can
be represented safely.

### 1.3 Bounded worker pool

Replace one `thread::spawn` per accepted connection with a fixed worker pool
and bounded queue, or use permits that guarantee a hard maximum before spawn.
The preferred transitional implementation is a fixed pool because it makes
`TasksMax` meaningful.

Do not add an unbounded channel. Queue capacity should be zero or small;
accepted sockets should fail fast rather than wait while their ClientHello
deadline silently expires.

### 1.4 Source limiter

Implement a sharded or mutex-protected bounded source table with:

- token bucket using `Instant`;
- IPv4 address key;
- IPv6 configurable-prefix key, default `/64`;
- concurrent pre-routing count;
- TTL eviction;
- fixed maximum entries;
- no source IP metric labels; and
- fake-clock deterministic tests.

Source admission must be disableable for deployments behind a source-obscuring
load balancer.

### 1.5 Log suppression

Replace per-connection rejection logging with:

- counters by bounded reason enum;
- rate-limited aggregate warnings;
- escaped, bounded hostname fields only after successful normalization; and
- debug-only sampled detail.

### Likely files

- `src/proxy.rs`
- new `src/admission.rs`
- new `src/ingress_config.rs`
- `src/main.rs`
- `docs/tls-proxy-design.md`

### Tests

- limit parsing and invalid relationships;
- no thread allocation after admission failure;
- exact global and sublimit boundaries;
- concurrent permit acquisition/release;
- slow ClientHello saturation and recovery;
- token refill, burst, eviction, IPv6 grouping;
- rate-limited logging; and
- existing proxy and handoff suites.

### Exit gate

- A hostile connection flood cannot exceed configured workers, queue entries,
  pre-routing sockets, relay sockets, or source-table entries.
- Counts return to baseline after clients disconnect.
- Existing development commands remain compatible.

## Phase 2 — Declarative public routing

### 2.1 Public-hosting mode

Add an explicit mode:

```toml
[ingress]
mode = "public"
unknown_sni = "reject"
```

Development mode retains current dynamic behavior. Public mode defaults to
rejecting undeclared SNI without candidate fan-out.

Profile selection must be explicit. Do not select production based on operating
system, effective UID, hostname, or the presence of `/etc/phx-port`.
`PHX_PORT_WORKLOAD_ID` or its CLI equivalent selects allocator identity only
and does not activate the production ingress profile.

### 2.2 Exact host declarations

Implement:

```toml
[workloads.example]
path = "/srv/apps/example" # optional diagnostic metadata

[ingress.hosts."www.example.com"]
workload = "example"
role = "https"
required = true
relay_idle_timeout_seconds = 1800
handoff = "disabled"
```

Validation:

- normalize hostnames at load;
- require exact DNS hostnames;
- reject duplicates after normalization;
- reject IP literals and empty labels;
- validate logical workload IDs;
- treat workload paths as optional diagnostic metadata only;
- require existing workload/role registration;
- cap declaration count;
- reject unknown keys in public mode; and
- never permit a declaration to bypass TLS verification.

### 2.3 Direct verification

For each declaration:

1. resolve its registered loopback port;
2. perform one exact-hostname TLS probe;
3. activate only on successful trust and hostname validation;
4. preserve previous generation until changed route verifies according to the
   accepted reload policy;
5. track required versus optional readiness; and
6. revalidate on the existing schedule.

Unknown public SNI must perform no route-cache read that can resurrect an
undeclared hostname and no multi-workload probe.

Phase 2 depends on the logical workload allocation contract in section 3.1a.
Implement that contract before shipping the public declaration schema even if
the filesystem hardening around it lands in Phase 3.

### 2.4 Positive state bounds

Cap:

- declarations;
- verified routes;
- conflicts;
- certificate fingerprints;
- reload diagnostics; and
- any retained dynamic routes when optional discovery is enabled.

### Likely files

- `src/ingress_config.rs`
- `src/proxy.rs`
- `src/route_cache.rs`
- `src/main.rs`
- README and TLS design

### Tests

- exact declared route success;
- declaration with invalid certificate stays inactive;
- undeclared SNI produces zero probes;
- renamed/removed declaration deactivates route;
- required route changes readiness;
- declaration limits;
- normalization collision;
- dynamic development behavior remains unchanged; and
- more than 32 declared workloads route deterministically.

### Exit gate

- Public routing is deterministic for the accepted scale.
- Certificate validation remains mandatory.
- Arbitrary SNI cannot trigger fan-out.

## Phase 3 — Atomic production configuration and state

### 3.1 File model

Implement accepted paths, recommended:

```text
/etc/phx-port/ingress.toml
/var/lib/phx-port/ports.toml
/var/lib/phx-port/routes.toml
/run/phx-port/
```

Support explicit overrides for tests and nonstandard deployments.

These paths apply only to the explicit production profile. Default development
commands continue using the existing per-user registry and runtime paths and
must not probe or create production locations.

### 3.1a Logical workload allocation

Extend the allocator without changing its development interface:

- add `PHX_PORT_WORKLOAD_ID` and an equivalent explicit CLI option for
  production automation;
- validate lowercase 1-128 character logical IDs;
- when logical ID is present, key assignments by `(logical ID, role)` rather
  than canonical current directory;
- when production ingress invokes or validates allocation, require logical ID
  and never fall back to working directory;
- continue honoring `PHX_PORT_CONFIG` as the port-registry path;
- secure and validate the registry directory, file, and sibling lock;
- preserve exclusive lock plus atomic replacement under concurrent workload
  starts;
- fail closed when the registry contains malformed entries, duplicate logical
  keys, or one port assigned to multiple workload/role keys;
- ignore undeclared workload entries for routing and expose only a bounded
  aggregate diagnostic;
- test independent local assignments for identical logical IDs on separate
  temporary host registries; and
- ensure allocator operation never requires a live ingress control socket.

Production unit examples should inject:

```ini
Environment=PHX_PORT_CONFIG=/var/lib/phx-port/ports.toml
Environment=PHX_PORT_WORKLOAD_ID=contoso-web
```

The workload remains responsible for invoking `phx-port` before binding its
listeners. Ingress reconciliation activates a matching declaration only after
the resulting listener and certificate validate.

Production PHXP endpoints use
`/run/phx-port/handoff/<sha256(workload-id, role)>.sock`. The service manager
creates `/run/phx-port` as mode `0750`, owned by the service UID and
`phx-port-admin` group, and creates the service-owned mode `0700` handoff
directory beneath it. Workloads create and remove only their endpoint. Ingress
restart preserves the directory and workload endpoints. Development retains
its existing canonical-path endpoint derivation and runtime location.

### 3.2 Permissions

At startup verify with no-follow metadata:

- configuration is a regular file;
- no symlink is accepted for security-sensitive production files unless an
  explicit policy says otherwise;
- owner and group match accepted deployment identities;
- configuration is not publicly writable;
- state and runtime parents are owned by ingress UID;
- state is mode `0600`;
- handoff and private runtime directories are mode `0700`; and
- `/run/phx-port/control` is service-owned, grouped to `phx-port-admin`, mode
  `0750`, with a mode `0660` socket and command-aware peer authorization.

### 3.3 Immutable snapshots

Build `Arc<IngressSnapshot>` containing:

- generation ID;
- validated limits;
- declarations;
- resolved registrations;
- runtime policy;
- observability policy; and
- readiness requirements.

Reload parses into a new snapshot without mutating live state. Swap only after
complete structural validation. Route verification transitions happen through
an explicit generation-aware state machine.

### 3.4 Migration

Add a dry-run command:

```text
phx-port proxy config check --file ...
phx-port proxy config migrate --from ... --output ...
```

Migration never deletes or overwrites the original without an explicit output
path and atomic write.

### Likely files

- split configuration helpers currently in `src/main.rs`
- new `src/config/`
- `src/route_cache.rs`
- `src/proxy.rs`
- CLI parsing

### Tests

- invalid reload preserves old generation;
- concurrent read during swap;
- route callbacks cannot install stale generations;
- ownership/mode/symlink failures;
- bounded file size;
- migration round trip; and
- crash-safe atomic state update.

### Exit gate

- Production config has one typed schema and atomic generation semantics.
- Derived state is disposable and separately permissioned.

## Phase 4 — Least-privilege service-manager activation

### 4.1 Interim hardened system service

Before socket activation, support rendering/installing a system service with:

- dedicated user/group;
- `CAP_NET_BIND_SERVICE`;
- `NoNewPrivileges`;
- explicit read/write paths;
- `LimitNOFILE`, `TasksMax`, and `MemoryMax`;
- restart and drain deadlines; and
- no dependency on an interactive login session.

Installation is an administrative operation and must clearly require root.
Do not silently replace the current development user unit.

### 4.1a Manual privileged startup

Add `daemon --run-as USER` for deliberate foreground use:

- require it when the daemon starts with effective UID 0;
- reject it for unauthorized identity transitions;
- resolve account and group membership before privilege drop;
- bind only requested listeners before the drop;
- clear and initialize supplementary groups safely;
- set GID before UID;
- use irreversible platform-appropriate UID/GID calls;
- verify real and effective IDs and inability to regain UID 0;
- apply Linux `no_new_privs`;
- defer config/state/runtime/control initialization until after the drop;
- require explicit `--listen` arguments and, after the drop, reject an ingress
  configuration whose listener declarations do not exactly match the bound
  descriptors;
- preserve signal handling and foreground logs; and
- add Linux and macOS integration tests that inspect the running identity and
  ownership of created files.

Bare `sudo phx-port` must retain existing help/piped command behavior.

### 4.2 Socket activation

Add inherited listener support:

- on Linux, detect `LISTEN_PID`/`LISTEN_FDS` and adopt the systemd-named TLS
  descriptors;
- on macOS, retrieve launchd `Sockets` entries through
  `launch_activate_socket()`;
- normalize both through one internal activated-listener interface;
- require named IPv4/IPv6 TLS descriptors;
- validate each descriptor is a listening TCP socket on an allowed address;
- set nonblocking mode;
- reject unexpected descriptors;
- avoid rebinding when activated; and
- preserve explicit `--listen` for foreground/development mode.

Render matching systemd `.socket` units and launchd LaunchDaemon plists for
IPv4 and IPv6 as accepted by the operator.

### 4.3 Sandbox iteration

Apply systemd hardening one directive group at a time. For every directive:

- add a unit rendering assertion;
- launch the real daemon under the unit;
- exercise config read/reload, state write, control socket, relay, handoff if
  enabled, DNS, CA roots, and shutdown; and
- document why any score-reducing permission remains.

Use `systemd-analyze security` as input, not as the acceptance oracle.

### Likely files

- replace or extend `src/systemd_service.rs`
- new platform-neutral socket activation helper
- Linux systemd and macOS launchd adapters
- CLI commands and docs
- integration scripts

### Tests

- unit rendering;
- inherited descriptor validation;
- daemon starts without root;
- no bind capability retained after activation;
- public backend ports remain unreachable;
- sandbox path denial;
- restart retains listener availability; and
- install/uninstall idempotency.

### Exit gate

- Production daemon runs non-root under a reproducible hardened unit.
- Port 443 acquisition is explicit and least-privileged.

## Phase 5 — Health, metrics, and control authorization

### 5.1 Machine-readable status

Add versioned JSON:

```json
{
  "schema_version": 1,
  "live": true,
  "ready": true,
  "generation": 42,
  "degraded_routes": []
}
```

Human output remains available.

### 5.2 Readiness

Implement:

```text
phx-port proxy check --live
phx-port proxy check --ready
```

Exit codes must be stable and documented. Required route failures make
readiness false; optional route failures make detail degraded without making
the whole ingress unready unless accepted otherwise.

### 5.3 Metrics

Add bounded metrics from the design. If Prometheus is accepted:

- bind only loopback or Unix socket;
- use a separate configured address;
- enforce a response-size bound;
- expose no mutation endpoint;
- do not label by arbitrary SNI or source; and
- include build version and config generation.

### 5.4 Control authorization

Harden control parent paths and authenticate peer credentials. Separate
read-only and mutation authorization according to Q23. Add `RELOAD` only after
atomic generation reload exists.

### Likely files

- `src/proxy.rs`
- new `src/observability.rs`
- new `src/control.rs`
- CLI and docs

### Tests

- stable JSON schema;
- required/optional readiness;
- bounded metrics labels and response;
- unauthorized read and mutation;
- control path symlink/ownership attacks;
- metrics unavailable does not stop data plane; and
- log aggregation under malformed traffic.

### Exit gate

- Automation can distinguish live, ready, degraded, overloaded, and stale
  configuration states.
- No public listener exposes control operations.

## Phase 6 — Async data plane

Begin only after phases 1-5 provide behavioral tests that constrain the
refactor.

### 6.1 Runtime boundary

Move into an async `run` function with:

- Tokio multi-thread runtime;
- async TCP accept loops;
- semaphore admission;
- cancellation token or watch channel;
- bounded blocking pool for TLS probes and PHXP where required; and
- at most 32 blocking probe workers and 256 blocking PHXP workers, with their
  combined thread demand validated against `TasksMax`; and
- structured task ownership through a join set.

Do not detach untracked tasks.

### 6.2 ClientHello

Port bounded peeking to async readiness while preserving:

- `MSG_PEEK`;
- 64 KiB maximum;
- total deadline rather than per-read reset;
- no consuming read before route delivery; and
- existing parser tests.

### 6.3 Async relay

Use bounded async bidirectional copy with:

- original peeked bytes forwarded exactly once;
- half-close propagation;
- byte counters;
- idle timeout reset on either-direction progress if accepted;
- cancellation on shutdown deadline;
- relay permit held to completion; and
- no unbounded per-connection buffers.

### 6.4 Discovery and probes

Retain single-flight semantics. Run blocking system-trust TLS probes through a
semaphore and bounded blocking executor, or adopt an async TLS verifier only
as a separately reviewed change.

### 6.5 Handoff

Preserve current PHXP tests and ownership states. A short blocking handoff may
run inside bounded `spawn_blocking`; cancellation after descriptor delivery
must never convert to relay fallback.

### 6.6 Shutdown

On termination:

1. stop pulling activated listener connections;
2. cancel pre-routing tasks;
3. allow handoff negotiations to resolve ownership safely;
4. drain relays to accepted deadline;
5. close remaining relays;
6. flush final metrics/state;
7. remove owned control endpoints; and
8. exit with a diagnostic if drain timed out.

### Likely files

- major refactor of `src/proxy.rs`
- async listener, relay, task, and cancellation modules
- `Cargo.toml`
- handoff adapter boundary

### Tests

- all behavioral tests from phases 1-5 against async runtime;
- no task leak after disconnect;
- cancellation at each handoff ownership state;
- half-close and idle timeout;
- thousands of idle sockets without native-thread growth;
- runtime saturation and recovery; and
- Linux/macOS handoff regression suites.

### Exit gate

- Native thread count remains bounded under accepted peak concurrency.
- FD, task, and memory usage returns to baseline after load.
- No admitted request regression relative to the bounded threaded baseline.

## Phase 7 — Operational hardening

### 7.1 Certificate monitoring

Track verified certificate expiry and emit:

- bounded metrics by declared hostname;
- warning thresholds, recommended 30, 14, 7, and 1 day;
- readiness failure only at actual invalidity unless operator chooses stricter;
  and
- fingerprint-change events.

### 7.2 Kernel and host runbook

Document and inspect:

- `RLIMIT_NOFILE`;
- system-wide file limits;
- listen backlog and `somaxconn`;
- ephemeral port range and `TIME_WAIT` for relay;
- conntrack/security-group limits;
- journald rate and disk limits;
- memory pressure behavior; and
- time synchronization for certificate validity.

Do not auto-tune global kernel settings from `phx-port`.

### 7.3 Backup and recovery

Document:

- files to back up;
- derived files not to back up;
- restore permissions;
- cold-start verification behavior;
- binary rollback;
- DNS/L4 rollback; and
- recovery test frequency.

### 7.4 Deployment

Provide checks:

```text
phx-port proxy config check
phx-port proxy preflight
phx-port proxy check --ready
```

`preflight` should verify listener acquisition, config permissions, CA roots,
backend registrations, route certificates, limits versus rlimits, runtime
directory, and control authorization without accepting public traffic where
possible.

### Exit gate

- A new host can be built from documented configuration and become ready
  without undocumented manual state.
- Operators can diagnose certificate, route, capacity, and sandbox failures.

## Phase 8 — Adversarial validation

### Harness

Extend the existing playground approach into a Linux production harness with:

- generated private CA installed only for the test process;
- several independent TLS backends;
- relay-only and handoff-capable workloads;
- exact declarations;
- controllable malformed PHXP receiver;
- controllable slow ClientHello clients;
- IPv4 and IPv6 traffic generators;
- process, FD, thread, and memory sampling; and
- deterministic assertion of status/metrics.

### Required scenarios

1. Valid declared route over relay.
2. Valid declared route over handoff.
3. Undeclared valid SNI rejected with zero probes.
4. Invalid/missing/oversized/fragmented ClientHello.
5. Global admission saturation.
6. Per-source rate and concurrency saturation.
   After route selection, more than 16 concurrent relays from one source must
   remain possible because the source-concurrency permit protects pre-routing,
   not established relay lifetime.
7. Source-table churn beyond maximum entries.
8. Random-SNI log flood.
9. Backend unavailable, restart, and certificate rotation.
10. Invalid configuration reload during live traffic.
11. Handoff pre-delivery fallback.
12. Handoff post-delivery failure with no fallback.
13. Long HTTP/2 and WebSocket connections.
14. Relay idle timeout and route override.
15. Graceful shutdown below and above drain deadline.
16. systemd process crash and restart.
17. sandbox denial of unrelated filesystem access.
18. metrics/control authorization.
19. FD pressure and recovery.
20. sustained accepted load at the Q26 gate, including 25,000 confirmed
    handoffs, 5,000 admitted relays, and deterministic rejection when 7,500
    relays are attempted simultaneously.

### Exit gate

- No unbounded resource growth.
- All admitted connections meet the accepted correctness threshold.
- Overload is visible and does not destabilize health/control.
- Restart and rollback complete within accepted objectives.

## Phase 9 — Canary and promotion

### Canary

- Deploy on the accepted smallest VM.
- Expose one low-risk declared hostname.
- Keep short DNS TTL and tested rollback.
- Observe normal and synthetic traffic.
- Exercise backend and ingress restart.
- Rotate or renew its certificate.
- Assert PHXP success counters and original-peer behavior so relay success
  cannot masquerade as handoff coverage.
- Review overload, route, latency, FD, memory, task, and log metrics.

### Expansion

Add workloads in small batches. After each batch:

- confirm required routes ready;
- compare capacity budget;
- exercise rollback;
- inspect conflicts and certificate expiry; and
- update expected peak assumptions.

### Production-ready gate

Do not call the ingress production-ready until:

- all design acceptance criteria pass;
- the Q26 load target passes for 30 minutes;
- canary runs for the accepted Q27 period;
- one certificate renewal succeeds;
- one daemon and one workload restart are observed;
- no unresolved critical/high security findings remain;
- rollback is timed and documented; and
- on-call diagnostics are usable from a clean operator session.

## Suggested issue breakdown

Each item should be independently reviewable:

1. Add typed ingress limits and validation.
2. Add global/pre-routing/relay/handoff permits.
3. Add bounded transitional worker pool.
4. Add source token bucket and bounded source table.
5. Add bounded rejection logging and metrics enums.
6. Add logical workload-ID allocation and production PHXP endpoint derivation.
7. Make undeclared public SNI reject without probes.
8. Add public-hosting mode and exact workload/role route declarations.
9. Bound positive route and conflict state.
10. Split production configuration and derived state.
11. Add immutable generation reload.
12. Add config check and migration commands.
13. Add hardened system service rendering.
14. Add systemd and launchd socket activation adapters.
15. Add JSON status and readiness CLI.
16. Add peer-authenticated read-only control with root-only production mutation.
17. Add bounded Prometheus endpoint.
18. Introduce Tokio runtime and task ownership.
19. Port listener and ClientHello peek to async.
20. Port relay with half-close, counters, and idle policy.
21. Bound blocking probe and handoff operations.
22. Implement async graceful drain.
23. Add certificate-expiry monitoring.
24. Add preflight and host runbook.
25. Add adversarial integration harness.
26. Add load and resource-regression gate.
27. Execute and document canary/rollback.

Rollback rehearsal must prove that the preceding binary can read the retained
port-registry schema or restore a permission-preserving pre-rollout snapshot.
The independent HAProxy/NGINX-stream artifact must be generated from both exact
route declarations and the stable port registry.

## Definition of done for every issue

- Exact design invariant identified.
- Production and development behavior stated.
- Existing laptop startup scripts require no edits unless adopting production
  profile features.
- Configuration validation included.
- Bounded failure behavior included.
- Unit or integration regression test included.
- Metrics and logs updated where behavior is operationally relevant.
- Documentation and sample configuration updated.
- Smallest relevant existing test suite passes on Linux.
- Cross-platform handoff code is not regressed.
- No support claim is promoted beyond executable evidence.

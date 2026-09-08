# Adversarial ingress and Elixir handoff audit

Audited revision: `063d3684c6d6853c1156b62b5b4e854c545f5dbc` on `master`.
The audit pass itself changed no tracked files. Remediation of every finding
below was subsequently performed in the working tree; no commits were made.

## Release recommendation

The audited revision was not fit for Internet-facing deployment. This pass
identified one security-availability finding and eight additional
reliability/performance defects; a ninth reliability defect (R9) was found
while remediating them. The most important blockers were unbounded workload
TLS handshakes, SIGTERM bypassing graceful drain, routing locks spanning
blocking persistence, and shutdown/probe work without an effective end-to-end
deadline.

All ten are now fixed in the working tree and each original reproduction has
been replayed and inverted; see "Remediation verification" below. That
establishes that these specific defects are gone. It does not establish that
the implementation is free of vulnerabilities, and the gates listed further
down — advisory scan, descriptor fuzzing, a Darwin adversarial exercise, and
a representative soak — remain outstanding before claiming readiness.

The basic trust-boundary design has useful defenses: exact operator-owned
route declarations, certificate-verified loopback destinations, bounded
ClientHello parsing, kernel-authenticated PHXP peers, descriptor validation,
and no relay fallback after descriptor delivery. Those defenses do not
provide a guarantee that the implementation contains no vulnerabilities.

## Security-availability finding

| ID | Severity | File | Lines | Finding | Confidence |
|---|---|---|---|---|---|
| S1 | HIGH | `phx_port_handoff/lib/phx_port_handoff/transport.ex` | 58-75, especially 63 | Unbounded TLS handshake permits unauthenticated clients to retain workload connection resources | 9/10 |

`Transport.handshake/1` calls `:ssl.handshake(socket, options)`. The installed
OTP 29 implementation delegates that overload to a timeout of `infinity`.
Thousand Island starts its ordinary read timer only after the synchronous
handshake succeeds. A client can send a valid ClientHello for a declared
workload and withhold the remaining handshake indefinitely.

PHXP adoption occurs before the workload TLS handshake. Once transfer is
acknowledged, ingress returns and releases its admission permits
(`src/proxy.rs:3677-3680`). Ingress connection limits and ClientHello
deadlines therefore do not bound the lifetime of these workload-owned
handshakes.

The specialist's bounded live probe used the actual current transport on
an accepted loopback TCP socket, OTP 29.0.6, and a valid 181-byte TLS 1.2
ClientHello. The server returned 1,233 bytes and remained blocked at
1,201 ms until the client closed. The explicit 200-ms handshake overload
returned `{:error, :timeout}` at 202 ms. The infinite default is established
by the OTP implementation, not by extrapolating the short observation.

The default connection ceiling is 16,384 per acceptor. The handoff helper
forces one acceptor, but the ordinary endpoint and other listeners have
separate populations. This is not an aggregate workload/VM resource budget.
An unauthenticated peer population can retain handshake slots rather than
having them reclaimed by the expected read timeout.

Qualification: ordinary Thousand Island 1.5.0 has the same unbounded
handshake default. This is an inherited exposure in the shipped composition,
not a demonstrated regression from its standard SSL transport. The probe
did not fill the quota or reproduce exhaustion through the complete
ingress-to-PHXP path. No authentication, confidentiality, or integrity
bypass is claimed.

Fix direction: impose a finite TLS handshake deadline, explicitly release
the TLS/raw-port/native receipt on failure, and enforce a workload-level
resource budget across direct and handed-off accepts. Include stalled
post-ClientHello clients and recovery after expiry in real imported-FD
integration coverage.

## Reliability and performance findings

| ID | Severity | Location | Finding |
|---|---|---|---|
| R1 | HIGH | `src/proxy.rs:1393-1395`; `Cargo.toml:17` | Normal SIGTERM termination bypasses graceful relay drain |
| R2 | HIGH | `src/proxy.rs:4617-4679`; `src/route_cache.rs:135` | Derived-cache persistence can stall the complete async data plane |
| R3 | HIGH at supported route scale | `src/proxy.rs:1428-1441,1465-1466,4295-4408` | Serial reconciliation outlives shutdown and revalidation budgets |
| R4 | MEDIUM | `src/handoff.rs:251-270`; `src/proxy.rs:3608-3638` | Blocking PHXP connect pins admission even after the public peer closes |
| R5 | MEDIUM | `src/proxy.rs:2803,2852,2865-3009,3422,2034-2043` | Valid mixed route states exceed the status response limit and break health commands |
| R6 | MEDIUM | `phx_port_handoff/native/phx_port_handoff_native/src/lib.rs:187-204` | Idle handoff listeners can exhaust BEAM dirty-I/O schedulers |
| R7 | MEDIUM | `phx_port_handoff/lib/phx_port_handoff.ex:37-50` | Missing `otp_app` propagation breaks relative TLS certificate paths |
| R8 | MEDIUM | `phx_port_handoff/lib/phx_port_handoff.ex:42-50` | `https: false` raises instead of disabling the child |
| R9 | MEDIUM | `phx_port_handoff/native/phx_port_handoff_native/src/lib.rs:124,129,134,310,323` | Blocking socket and filesystem syscalls ran in regular NIFs on normal schedulers |

### R1: supervisor stop does not execute the documented drain

`ctrlc = "3"` does not enable termination-signal handling. The supplied
systemd unit uses the default SIGTERM; a 65-second stop timeout does not
install a handler.

An isolated public-profile daemon with an established TLS echo relay exited
with signal 15 and lost the relay under SIGTERM, without an ingress shutdown
event. The equivalent SIGINT case preserved the relay until client close,
then exited normally.

Fix direction: route SIGTERM through the shutdown coordinator. Exercise the
actual service-manager stop/restart path, not only SIGINT or SIGKILL recovery.
The Darwin build and suites pass, but no Darwin service-manager stop was
executed.

### R2: a slow cache operation blocks unrelated traffic

Route installation holds the global route-table write lock while persisting
the entire derived cache. Persistence takes a blocking file lock and performs
synchronous filesystem operations. Async connection tasks synchronously wait
for a route-table read lock, eventually occupying all Tokio workers.

Holding an isolated `routes.toml.lock` for 1,658 ms while activating a second
healthy route stalled an unrelated established relay and status retrieval.
All eight warm-route clients exceeded 500-ms client deadlines. Direct
workload traffic remained healthy; unlocking restored the relay without
losing its pending bytes.

Fix direction: move persistence outside routing-critical lock scopes, keep
publication generation-safe, and bound persistence work. Avoid full-cache
rewrites for every unchanged certificate: current per-route full rewrites
also make aggregate persistence work quadratic in route count per refresh.

This is an operational availability defect. No public-only attack was
demonstrated by holding a local trusted state lock.

### R3: reconciliation is serial and not cancelled between declarations

The shutdown flag is checked around a whole reconciliation pass, not between
declarations. The main thread later joins the reconciler outside the async
drain deadline.

With eight declared names pointing to a workload that accepted TCP but
stalled TLS, seven more probes began after SIGINT. Shutdown took 1,717 ms
despite zero ingress connections. At 1,000 supported declarations,
approximately 200-ms failures can consume roughly 200 seconds in one pass.
That last number is a code-derived extrapolation, not a large-scale run.

Fix direction: propagate cancellation and absolute deadlines through
reconciliation, stop scheduling after shutdown, and use bounded probe
concurrency. Unhealthy optional declarations must not indefinitely postpone
required-route recovery and certificate revalidation.

### R4: socket-operation timeouts do not bound Unix connect

The sender connects before installing socket read/write timeouts. A full
PHXP listen queue can therefore keep the started blocking job waiting while
it owns the public socket plus global, pre-routing, source, and handoff
permits. Closing the public peer does not cancel this wait.

An isolated backlog-1 receiver with two queued controls pinned two jobs for
3.1-3.4 seconds after the public peers closed. With active/handoff limits of
2/2, a healthy unrelated request was rejected at global admission. With
8/2, spare upstream admission allowed the documented relay fallback.

This used development mode's relative runtime path but the same handoff,
admission, blocking-worker, and shutdown functions. It did not model the
native broker's actual backlog 128. Worker counts remained bounded and the
async reactor stayed responsive. The process has a later drain deadline and
two-second blocking-runtime grace, so this path alone was not shown to hang
process exit forever.

Fix direction: bound connection establishment itself and cancel before
descriptor delivery. An async timeout around `spawn_blocking` alone leaves
the started closure and its resources alive.

### R5: independently bounded diagnostic arrays exceed the wire budget

Status permits 64 degraded-route details and 64 certificate-route details
independently. A valid mixed configuration produced an 80,894-byte response,
exceeding the client's 65,536-byte ceiling. Raw daemon state was
`live=true, ready=true`, but status, liveness, and readiness commands all
exited 1.

Fix direction: bound the complete serialized document, preserve omission
counts, and make health responses small and independent of diagnostic size.

### R6: idle native accept is not free

An idle `Native.accept/1` occupies a dirty-I/O scheduler indefinitely while
polling. On a private OTP 29 node with two dirty-I/O schedulers and two idle
handoff listeners, an unrelated `File.stat!` blocked for at least 500 ms.
Closing one listener released a slot and the operation completed at 503 ms.

This is conditional on listener count reaching the effective dirty-I/O
scheduler count, not a claim that every single-listener deployment is
deadlocked. The 10-ms idle sleep does not imply a 100-handoffs/second ceiling.

Fix direction: use readiness-driven native integration or a bounded broker
worker that does not occupy a dirty scheduler throughout an idle wait.
Raising the scheduler count only moves the threshold.

### R7 and R8: ordinary endpoint configuration is not faithfully preserved

Actual Bandit 1.12.5 startup with relative `keyfile` and `certfile` options
raises: `the :otp_app option is required when setting relative SSL certfiles`.
The ordinary Phoenix adapter adds `otp_app`; the handoff helper consumes it
but does not forward it.

Separately, explicit `https: false` reaches `Keyword.get/3` and raises
`FunctionClauseError`. Only `nil` takes the disabled branch.

Fix direction: retain the endpoint application identity and explicitly
handle supported disabled representations. Do not silently accept arbitrary
malformed configuration.

### R9: blocking syscalls executed on normal BEAM schedulers

Found during remediation, not in the original pass. `adopted/1`, `rejected/1`,
`listen/1`, `listen_derived/1`, and `close_listener/1` were plain
`#[rustler::nif]` functions, so they ran on normal scheduler threads while
performing blocking work.

`adopted/1` and `rejected/1` reach `respond()` and then `send()` on the PHXP
control socket, bounded only by the 2-second `SO_SNDTIMEO`. A slow or hostile
ingress peer that stops reading the control socket can therefore pin a normal
scheduler thread for up to two seconds per response. `listen/1`,
`listen_derived/1`, and `close_listener/1` perform directory creation, chmod,
bind, and unlink, which are unbounded on a stalled filesystem.

Normal schedulers must never block: unlike the dirty-I/O pool, they run all
ordinary Erlang processes, so pinning them stalls unrelated application work
and delays timers across the whole node.

Fix direction: schedule every NIF that can block on I/O as `DirtyIo`. The
adversarial reproductions were run on Linux; Darwin was covered by build and
suite execution only.

## Remediation verification

Every finding was remediated in the working tree and re-verified by replaying
the original reproductions against the fixed build. The audit harnesses assert
the *broken* behaviour, so each one now fails its original assertion; the table
records the values actually observed after the fix.

| ID | Original reproduction | After remediation |
|---|---|---|
| R1 | SIGTERM killed the process (`-15`), relay dropped, no drain logged | exit `0`, relay echoed after signal, `event=ingress_shutdown` logged, 184 ms — identical to SIGINT |
| R2 | Cache lock stalled unrelated relays and status | lock held 409 ms, `unrelated_live_relay_stalled: false`, `status_stalled: false`, 8/8 warmed-route clients succeeded |
| R3 | Probes kept starting after shutdown; stop took > 1 s | `probes_started_after_shutdown: 0`, `stop_elapsed_ms: 63.5` |
| R4 | Full PHXP accept queue pinned all admission permits | `active_connections`, `pre_routing_connections`, `handoff_negotiations` all `in_use: 0`; unrelated connection still served (`relay_fallback_succeeds`); `handoff_attempts: 3` / `handoff_fallbacks: 3`; fds 8 before and 8 during the block (no descriptor leak); recovery 50.6 ms after listener release |
| R5 | 80,894-byte status document exceeded the 65,536 limit; `status`, `check --live`, `check --ready` all exited 1 | `status_wire_bytes: 65092` within budget; all three commands exit `0` with `live` and `ready` true |
| S1, R6-R9 | Elixir/native package | Covered by the ExUnit and Rust suites below |

Two behavioural notes fell out of the R4 replay. Bounded connect means the
capacity-exhaustion branch of the queue harness is no longer reachable, because
permits are released rather than pinned — the harness case that depended on
exhausted capacity is obsolete rather than failing. And an unreachable handoff
endpoint now surfaces as `handoff_fallbacks` rather than
`handoff_capacity_skips`. The two counters remain distinct and always were:
`handoff_capacity_skips` counts exhausted handoff-negotiation permits, which
the fix stops producing in this scenario, while `handoff_fallbacks` counts a
bounded connect that gave up and relayed instead. Nothing was renamed.

Suite status after remediation, on Linux x86_64: 203 Rust tests in the ingress
crate, 9 Rust tests in the native NIF crate, and 19 ExUnit tests, all passing,
with the ExUnit suite confirmed stable across 12 consecutive full runs.
`mix compile --force --warnings-as-errors` is clean.

The same tree was then built and run on macOS 26.6.2 arm64 (Elixir 1.20.2,
OTP 29.0.3): every Rust suite passes, `mix compile --force
--warnings-as-errors` is clean, and 19 ExUnit tests pass. Darwin coverage is
build-and-suite only — the adversarial reproductions and the service-manager
stop path were exercised on Linux.

## Deployment assumptions that must be explicit

- Ingress and workloads intentionally share one service UID and compromise
  boundary. This is not isolation for mutually hostile tenants.
- Use explicit production/public configuration, exact route declarations,
  private control/handoff endpoints, and loopback-only workload listeners.
- Successful handoff moves connection ownership and TLS/HTTP resource policy
  to the workload. Ingress is neither an HTTP security gateway nor a WAF.
- Relay fallback makes the workload see loopback as its TCP peer. Do not
  authorize a request merely because its peer is loopback, and do not trust
  arbitrary client-supplied forwarding headers.
- SNI selects a route; it does not authenticate an HTTP Host header or user.

## Gates needed before claiming Internet-facing readiness

Gate 1 is met; gates 2-6 remain open.

1. ~~Resolve the findings above, preserving exact route authority and the
   irreversible descriptor-delivery boundary.~~ **Done** — all ten findings
   are fixed and each reproduction was replayed and inverted. Independent
   review confirmed lock ordering, SCM_RIGHTS irreversibility, and descriptor
   ownership are intact.
2. Add required real OTP/Bandit integration coverage for FD import/closure,
   SNI policy, client certificates, TLS stalls, HTTP/1 keep-alive, HTTP/2,
   WebSockets, queue saturation, and workload/supervisor restart.
3. Run bounded parser/PHXP fuzzing and resource-lifetime fault injection.
   Monitor OS FDs, Erlang ports/processes, dirty schedulers, permits, and
   recovery, not only successful HTTP responses.
4. Make the exact tagged release artifact depend on required Rust/native
   and real Elixir gates. The current tag workflow builds and publishes
   independently, and the ordinary workflow lacks OTP/Elixir integration.
5. Continuously scan locked dependencies/advisories, record dependency
   provenance, and obtain independent review of the unsafe FD/NIF boundary.
6. Qualify the release build with representative real workloads and declared
   route counts on the intended host limits. Include degraded workloads,
   resource contention, actual SIGTERM stop, and recovery.
7. Exercise Darwin beyond build and suites. The tree now builds cleanly and
   passes every Rust and ExUnit suite on macOS 26.6.2 arm64, but the
   adversarial reproductions, the SIGTERM drain, and R4 (`connect_until`)
   under contention were only executed on Linux.

No audit, fuzzer, or passing suite can prove the absence of vulnerabilities.
The practical objective is explicit invariants, bounded resources at every
ownership stage, reproducible adversarial cases, enforced release gates,
and a vulnerability-response process.

## Evidence and limits

Reproduction harnesses and captured results are in `evidence/`:

| Artifact | Covers |
|---|---|
| `evidence/runtime_audit.py` | R1, R2, R3, R5 — signal drain, cache lock, serial reconciler shutdown, status wire budget |
| `evidence/handoff_queue_audit.py` | R4 — saturated PHXP accept queue and admission permits |
| `evidence/runtime-audit-results.jsonl` | Recorded ingress results from the audited revision |
| `evidence/handoff-queue-audit-results.jsonl` | Recorded PHXP queue results from the audited revision |
| `evidence/handoff-reliability-evidence.md` | Detailed Elixir/native handoff findings |
| `evidence/freeze_repro.exs` | The in-VM PHXP sender that wedges the node on Linux |
| `evidence/invm_peer_sender.py` + `evidence/invm_peer_starvation.exs` | Out-of-VM sender, in-VM stalled peer — stays healthy |
| `evidence/invm_peer_sender.py` + `evidence/invm_tls_starvation.exs` | Out-of-VM sender, in-VM TLS handshake — stays healthy |
| `evidence/stalled_handoff_sender.py` + `evidence/out_of_vm_starvation.exs` | Fully out-of-VM production topology — stays healthy |

The four starvation probes run under `ELIXIR_ERL_OPTIONS="+S 2:2" mix run`
from `phx_port_handoff/` and take `<count> <blocking>` arguments; they write a
verdict to `/tmp/oov-verdict` and print scheduler tick counts. A missing
verdict means the VM wedged. Use `ELIXIR_ERL_OPTIONS` rather than
`elixir --erl`, which mangles `System.argv/0`.

Both harnesses expect a debug binary at `runtime-target/debug/phx-port`
relative to the working directory and create their own scratch state. They
assert the *broken* behaviour of the audited revision, so against a fixed
build they fail by design; that inversion is the verification signal recorded
above. Bulky per-run stderr captures were not retained.

Existing focused Rust/native and ExUnit coverage was exercised, along with
isolated loopback runtime probes. Counts overlap and should not be added as
unique tests. The sample's own `mix test` remained blocked by its dependency
lock mismatch; its lock was not changed. Existing Bandit dependency sources
were compiled separately for the parent runtime probe.

The suspected normal HTTP/1 process-dictionary FD leak was not reproduced:
three actual handed-off TLS connections each completed two HTTP/1.1
requests, then all handler processes exited and imported raw ports closed.
Do not promote that suspicion to a confirmed finding.

Other unproven leads include discovery-flight deadline cleanup, trickled
workload TLS probe duration, and mandatory-mTLS route activation. They are
not counted as vulnerabilities here.

## Observation: an in-VM PHXP sender freezes the node (not a shipped defect)

While building an end-to-end handoff regression test, a VM-wide freeze
reproduced at roughly 25-50%. It is recorded here as an observation because it
is not reachable from a production topology, but it will mislead the next
person who writes a test like this. The mechanism is now fully attributed.

Symptom: every Erlang process stops, timers never fire, and distribution stops
accepting (`Recv-Q` grows on the listener while the node never accepts).
`code_server` sits in status `suspended` inside `handle_loader` with the TLS
client process blocked in `code:ensure_loaded/1`, and exactly one normal
scheduler thread sits in kernel `wait_woken`. Healthy nodes never show that.

### Root cause

With `kernel.yama.ptrace_scope=0` the blocked thread was finally named. Thread
`erts_sched_4` was stopped in `recvfrom` (syscall 45) with kernel stack
`sk_wait_data -> tcp_recvmsg` and userspace stack `recv -> tcp_recv ->
inet_ctl -> tcp_inet_ctl -> erts_port_control -> erts_internal_port_control_3`.
That is the legacy `inet_drv` performing a *synchronous* `recv(2)` on a
**normal** scheduler thread. The chain is:

1. `SCM_RIGHTS` does not duplicate the open file description, it *shares* it.
   `O_NONBLOCK` lives on that description, so sender and receiver see one
   another's `fcntl(F_SETFL)` through different descriptor numbers.
2. `:gen_tcp.fdopen/2` already normalizes the adopted descriptor. Traced with
   the receiver's own normalization compiled out, `inet_drv` itself issues
   `fcntl(fd, F_GETFL) = O_RDWR` followed by
   `fcntl(fd, F_SETFL, O_RDWR|O_NONBLOCK)`.
3. When the PHXP *sender* lives in the same BEAM, its `socket` NIF later runs
   `fcntl(fd, F_SETFL, O_RDWR)` on that shared description — observed under
   `strace` on a different thread — clearing `O_NONBLOCK` behind `inet_drv`'s
   back, after the driver has committed to non-blocking semantics.
4. `inet_drv` then blocks in `recv(2)` on a normal scheduler. Because the peer
   is also in-VM, no scheduler is left to produce the bytes it waits for, so
   the wait is circular and the whole VM stops.

### Why it is not a production risk

The ingress runs as a separate OS process, so step 3 cannot occur. This was
tested directly rather than assumed, with an out-of-process Python PHXP sender
handing off genuinely stalled clients, `+S 2:2`, and a heartbeat counting
scheduler ticks over a 3 s window inside the 5 s handshake deadline. **The
receiver-side normalization was compiled out for these runs**, so they measure
unmitigated behaviour:

| Sender | Public peer | Result |
| --- | --- | --- |
| out of VM | out of VM, stalled | `schedulers_healthy ticks=59/60` |
| out of VM | in VM, stalled | `schedulers_healthy ticks=59/60` |
| out of VM | in VM, real TLS handshake | `schedulers_healthy ticks=59/60` |
| **in VM** | in VM | **VM wedged, no verdict** |

Only the in-VM sender wedges. Sender location, not client location, is the
discriminating variable — which supersedes the earlier attribution to the
client, made before the syscall could be named. Both earlier repro harnesses
(`freeze_repro.exs`, `scheduler_starvation.exs`) used an in-VM `:socket`
sender, which is why both wedged.

macOS is unaffected: 10/10 clean runs of the in-VM harness on macOS 26.6.2
arm64, consistent with this being `inet_drv`-on-Linux behaviour.

### Fix considered and rejected

A receiver-side fix was implemented and then reverted: normalizing the
descriptor in `try_accept` plus a `restore_nonblocking/1` NIF re-applying
`O_NONBLOCK` after `fdopen`. The `strace` evidence in step 2 shows `inet_drv`
already does exactly this, so the NIF was redundant; it also could not fix the
in-VM case, because the sender clobbers the shared description *afterwards*.
It added a new public NIF and a new failure path that closed the socket and
rejected the connection if `fcntl` failed. Redundant code with a novel failure
mode is a net loss, so it was removed.

The original regression moved only the TLS client to a separate OS process,
leaving the in-VM PHXP sender and therefore the freezing topology intact. The
transport regressions now use `phx_port_handoff/test/support/phxp_sender.py`
outside the receiving VM for both stalled-peer and complete-TLS scenarios.
They check the sender's OS identity, readiness, adoption acknowledgement, and
exit status; the stalled TCP peer intentionally remains in-VM. Run them under
the external Linux watchdog documented in the handoff package README.

This repairs the regression topology, not the underlying VM behavior. It was
verified against unmodified `063d368` that the freeze is pre-existing and was
not introduced by any fix in this pass. Do not record the VM freeze as fixed.

Debugging notes for whoever revisits this. `:erlang.display/1` still writes
from the emulator when the IO system is wedged, whereas `IO.puts` starves;
`Process.info/2` blocks against a process stuck in a NIF, so print the pid
before probing it; `ptrace_scope` must be 0 for `gdb`, `eu-stack`, and
`/proc/*/stack` to name the blocked frame; and descriptor numbers are reused
aggressively, so correlate `fcntl` traces with the `recvmsg` that delivered the
`SCM_RIGHTS` payload rather than with a bare fd number.

There was no current advisory-database scan, exhaustive native-descriptor
fuzzing, Darwin adversarial exercise beyond build and suites, or new
30-minute qualification in this pass. Historical Q26 evidence covers an
ingress harness with two routes, synthetic traffic, customized limits, and a
debug/test build on a constrained larger host. It explicitly does not
establish a representative whole-host BEAM workload soak, 1,000-route
behavior, or release-build bulk throughput.

The parent and runtime reviewer stopped their audit-owned processes and
removed their generated runtime fixtures and secrets. The security
specialist also stopped its probe node; cleanup of two existing tests'
hardcoded temporary directories was expected from TempDir but not
independently inspected. No unrelated services were targeted.

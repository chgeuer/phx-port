# Adversarial public-ingress harness

`tests/phase8-harness.sh` is the deterministic Linux Phase 8 harness. It uses
an ephemeral private CA, exact Route Declarations, relay-only and PHXP-capable
Workloads, raw malformed and fragmented clients, IPv4 and IPv6 listeners,
bounded observability assertions, and `/proc` resource sampling. Every
scenario emits one JSON line naming its profile and evidence status.

Run the complete functional and real-systemd gate:

```bash
tests/phase8-harness.sh --all
```

The default smoke profile uses the production binary and production code paths
at bounded local scale. The systemd profile creates transient per-user
`.socket` and `.service` units, crashes the service process, proves automatic
restart through the activated listener, and has the service itself assert that
an `InaccessiblePaths` mount sandbox denies access to an unrelated repository
file. The transient units and all temporary files are removed after the test.

| Phase 8 scenario | Machine-checkable evidence |
|---:|---|
| 1-3 | Declared relay, confirmed original-descriptor handoff, and undeclared SNI with unchanged Workload accept counts |
| 4 | Invalid, missing, oversized, fragmented, slow, IPv4, and IPv6 ClientHello traffic |
| 5-7 | Exact global/source limits, post-route source-permit release, and bounded source-table churn |
| 8-10 | Random-SNI log bound, Workload outage/restart/certificate rotation, and invalid reload during live traffic |
| 11-12 | PHXP pre-delivery relay fallback and post-delivery failure with no fallback |
| 13-15 | Long HTTP/2/WebSocket-shaped streams, virtual-time relay idle policy, and ownership-aware drain deadline |
| 16-17 | Real systemd crash/restart and real mount-namespace sandbox denial |
| 18 | Loopback read-only metrics and peer-authenticated local control |
| 19-20 | Initial, sustained, and shedding high-water FD/task/RSS sampling; exact relay shedding; admitted-byte integrity; and return to baseline |

The smoke result marks scenario 20 as `exercised`, not `passed`: it executes
the same mixed handoff/relay and overload assertions at local scale but is not
Q26 capacity evidence. Consequently, `--all` reports 19 passed scenarios, 20
exercised scenarios, and `q26_qualified: false`.

`--qualification` selects the accepted Q26 values: 25,000 confirmed handoffs,
5,000 admitted relays, 7,500 unchanged long-lived connections distributed
across both ownership modes, at least 1,000 newly accepted connections per
second throughout a 30-minute hold, and a separate simultaneous 7,500-relay
shedding attempt. To keep the kernel listen backlog from discarding evidence,
the shedding clients first establish all 7,500 TCP connections at the measured
generator rate, then release every ClientHello from one barrier. Route
selection starts with that barrier release, so all 7,500 relay attempts are
simultaneous while every outcome remains attributable to ingress. The
qualification-only ClientHello timeout is 10 seconds so the bounded
preconnection phase can complete; the production default is unchanged.

The generator uses one percent scheduling headroom and reports the measured
initial and sustained accept rates. Independent 25-millisecond samplers compute
component-wise FD/task/RSS high-water marks during initial generation, the
30-minute hold, and the simultaneous shedding attempt. A direct resource
snapshot is also taken immediately before the original live connections close.
Each high-water record includes its sample count, and qualification requires at
least ten samples per elapsed second in every sampled phase. The stderr ceiling
is derived from elapsed ten-second aggregation windows and the fixed
delivery/admission event types, so the soak proves bounded logging without
rejecting valid periodic summaries.

The qualification entry point fails closed unless it is running unprivileged
on Linux with exactly four CPUs in the process's `sched_getaffinity` mask and
effective memory within ten percent of 8 GiB. OpenMP environment hints and
`nproc` output are not qualification authority. On cgroup v2, the memory gate
uses the smallest finite `memory.max` in the process cgroup ancestry, bounded
by physical memory; without a finite cgroup limit it uses physical memory. The
`qualification_host` evidence records the exact affinity CPU list, effective
and physical resources, environment shape, and whether it is equivalent to a
dedicated VM.

Running on a larger host with CPU affinity and a finite cgroup memory limit
constrains userspace CPU and memory, but does not reproduce a dedicated VM's
kernel-wide conntrack, ephemeral-port, system file-table, or kernel-memory
limits. Record that distinction with the resulting evidence. The harness also
verifies that exactly one Linux qualification test executed before emitting
passing evidence. Qualification is intentionally not part of ordinary
`cargo test`; issue `phx-3o3` owns execution on the approved host and
preservation of its machine-readable evidence. Only a successful qualification
profile emits scenario 20 as `passed` and sets `q26_qualified: true`. Do not
infer production capacity from the smoke profile. The qualification summary
also records that this ingress-process gate does **not** complete the separate
representative whole-host Workload soak.

The accepted `phx-3o3` qualification transcript is preserved at
[`evidence/phx-3o3-q26-qualification-2026-09-03.log`](evidence/phx-3o3-q26-qualification-2026-09-03.log).

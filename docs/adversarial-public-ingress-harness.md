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
shedding attempt. The generator uses one percent scheduling headroom and
reports the measured initial and sustained accept rates. Resource bounds are
sampled during the hold, immediately before live connections close, and while
the shedding attempt is in flight. The stderr ceiling is derived from elapsed
ten-second aggregation windows and the fixed delivery/admission event types,
so the soak proves bounded logging without rejecting valid periodic summaries.

The qualification entry point fails closed unless it is running unprivileged
on Linux with exactly four available vCPUs and host memory within ten percent
of 8 GiB. It also verifies that exactly one Linux qualification test executed
before emitting passing evidence. Qualification is intentionally not part of
ordinary `cargo test`; issue `phx-3o3` owns execution on the named host and
preservation of its machine-readable evidence. Only a successful qualification
profile emits scenario 20 as `passed` and sets `q26_qualified: true`. Do not
infer production capacity from the smoke profile.

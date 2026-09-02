# phx-port Public Ingress Implementation Campaign

This campaign is resumable: all authoritative progress lives in the `br`
tracker. Each run takes exactly one ready, non-epic issue to Done, commits it,
closes that issue, writes a handoff, and stops. Never begin a second issue in
the same run.

`phx-port` allocates stable development ports and can route encrypted TLS by
visible SNI without terminating TLS. The campaign adds a bounded,
production-grade public-ingress profile while preserving the existing
zero-bootstrap development workflow.

## Mission

Implement one ready `implementation-2026-09` work item end to end. Treat the
issue as a requirement to confirm against current code and accepted design,
not permission to force a speculative change. If the issue is already
satisfied, close it only with concrete code and test evidence. If it requires
a human environment or decision, leave a precise comment, release the claim,
and stop.

## Read first

Before choosing or changing code, read:

- `CONTEXT.md`;
- `docs/public-hosting-hardening-design.md`;
- `docs/public-hosting-hardening-implementation-plan.md`;
- the applicable ADRs under `docs/adr/`;
- `docs/macos-socket-handoff-design.md` for PHXP, Darwin, runtime-path, or
  cross-platform service changes; and
- the complete selected issue from `br show <id>`.

The accepted design and ADRs outrank incidental implementation shortcuts. Use
the glossary's canonical terms in code, tests, documentation, and issue
updates.

## Elixir navigation

For every `.ex` or `.exs` file, use
`/home/chgeuer/github/pnezis/probex/probex` for structural navigation:

- run `outline <file>` the first time the file is inspected;
- use `body <file> <name>/<arity>`, `body <test> preamble`, or `body <file>
  L<n>` for complete blocks;
- use `clauses` for ambiguous functions and `directives` for name provenance;
- batch targets and selectors where practical; and
- use `--head` or `--tail` instead of piping a structural block through
  `head` or `tail`.

If that exact executable reports `command not found`, confirm with
`command -v probex`, record the unavailable tool in the handoff, and fall back
to ordinary file reading. Do not guess another path. Do not edit vendored
`deps/` sources.

## Environment and verification

The repository is a Rust 2024 crate. `cargo`, `rustfmt`, `clippy`, `br`, Git,
and GitHub Copilot CLI are available. The clean campaign baseline on
2026-09-02 is 38 passing Rust tests with clean formatting and no clippy
warnings.

Every implementation issue must pass all of:

```bash
cargo fmt -- --check
cargo test
cargo clippy --all-targets --all-features -- -D warnings
```

Add a focused regression test that demonstrably fails without the change and
passes with it. Run focused tests while iterating, then all three commands
above before closing.

If the issue changes `integrations/elixir/phx_port_handoff`, also run its full
existing `mix test`. If it changes a language sample, service definition,
playground, or production harness, run that component's existing build/test
path and every issue-specific platform or integration gate. Do not substitute
Linux evidence for macOS/launchd evidence, a mock for a required real systemd
unit, or local synthetic output for the accepted qualification/canary proof.
If the required platform or operator environment is unavailable, stop with the
issue open.

Do not install a new verification tool merely to satisfy an issue. Add
dependencies only when the implementation itself requires them.

## Campaign scope

All work is in the repository-root `.beads` tracker under
`implementation-2026-09`.

Epics:

- `phx-1nl` — Bound hostile public ingress
- `phx-2dv` — Establish deterministic production routing
- `phx-z3w` — Operate least-privilege ingress services
- `phx-1ir` — Migrate the bounded data plane to Tokio
- `phx-3vs` — Prove and release public hosting

Dependencies encode the implementation order. Prefer AFK work over HITL work
when both are ready. The qualification and real canary issues are HITL and
must not be attempted without their named VM, DNS, certificate, and rollback
environment.

## Orient from the previous run

If earlier completed runs left handoffs, skim the newest one:

```bash
grep -l '## Next-agent prompt' .campaign/logs/*.log 2>/dev/null |
  xargs -r ls -t | head -1
```

It is only a hint. `br` and the current repository are authoritative.

## Pick and claim exactly one issue

```bash
br ready -l implementation-2026-09 --limit 0
```

Ignore epics. Choose one ready non-epic issue, preferring an AFK issue and then
the lowest dependency tier. Claim it atomically:

```bash
br update <id> --claim
br show <id>
br comments <id>
```

If no non-epic issue is ready, stop. If the selected issue is HITL and its
operator environment has not explicitly been supplied, do not claim it.

## Complete the issue end to end

1. **Confirm** — trace the current behavior and restate the exact missing
   acceptance criterion. Check recent commits and neighboring tests so work is
   not duplicated.
2. **Implement** — make the smallest coherent change that delivers the issue's
   complete behavior through configuration, runtime, observability, tests, and
   directly related documentation. Preserve type safety and existing
   conventions.
3. **Prove** — add focused regression coverage that fails before and passes
   after. Do not weaken an assertion or bypass a real trust/resource boundary.
4. **Verify** — run the complete Definition of Done and all issue-specific
   gates. Any failure blocks closure.
5. **Commit code** — stage explicit paths only; never use `git add .` or
   `git add -A`. Use a concise imperative commit subject containing the issue
   ID. Do not add `Co-authored-by` trailers.
6. **Close only this issue**:

   ```bash
   br close <id> -r "Resolved in <hash>. <behavior delivered>. Regression: <test>."
   ```

7. **Commit tracker state** — explicitly stage `.beads/issues.jsonl` and commit
   the closure separately with the issue ID. Do not close or modify a peer
   work item. Container epics are closed separately only after their children
   and exit gate are complete.

## Non-negotiable guardrails

- Preserve the default `PORT="$(phx-port)" command` workflow, canonical-path
  development identity, per-user registry/runtime paths, and dynamic
  development discovery unless public mode is explicitly activated.
- Public mode activates only through an explicit ingress config declaring
  `mode = "public"`.
- A public hostname routes only to its exact declared logical Workload and
  role after system-trusted exact-hostname certificate verification.
- Never terminate TLS, centralize workload private keys, consume ClientHello
  before delivery, or route a backend anywhere except registered loopback.
- Never weaken PHXP peer authentication, descriptor validation, framing, or
  its irreversible ownership boundary. Post-descriptor failure never relays.
- No public input may create unbounded threads, tasks, sockets, probes, cache
  entries, source buckets, queue entries, metric labels, or log messages.
- Production data-plane execution never remains UID 0. Production mutation is
  root-only because Workloads share the service UID; control stays local and
  authenticates every peer.
- Keep source IP, arbitrary SNI, certificate material, TLS payload, and
  unbounded error strings out of metric labels and routine logs.
- Preserve Linux and macOS handoff behavior. Never claim launchd, systemd,
  capacity, or canary support without the required executable evidence.
- Never revert unrelated worktree changes. Stay inside this repository.
- Never dismiss failures as flaky or pre-existing. If an unrelated baseline
  failure appears, record it in `br`, leave the selected issue open, release
  the claim, and stop for supervision.

## Stop after one issue

A run ends after exactly one selected issue is closed, or immediately when
there is no ready non-epic work, a required human environment/decision is
missing, verification fails, or a safe implementation cannot be completed.

Before stopping, append these headings to the active campaign log:

```text
## Session summary
<issue ID, behavior, commits, regression test, verification>

## Next-agent prompt
<next ready issue, relevant neighboring code, and blockers>
```

Then stop. Do not start another issue.

## Progress

```bash
br epic status
br list -l implementation-2026-09 --status open --limit 0
br ready -l implementation-2026-09 --limit 0
```

The automated campaign is complete when no non-epic AFK item with the campaign
label remains open. HITL qualification and canary work remain explicit human
gates; the public-hosting feature is not production-ready until those issues
also close.

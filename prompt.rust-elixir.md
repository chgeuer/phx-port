# Supervised Rust and Elixir Audit Campaign

All authoritative progress lives in `br`, under epic **phx-27e** and common
label `audit-rust-elixir-2026-09`. Take exactly ONE initially-ready, non-epic
issue from the selected execution queue to a defensible Done state, commit
it, close only that issue, write a handoff, and STOP. The driver and parent
supervisor decide whether another run starts.

## Mission and authority

Resolve the approved 32-item follow-up to the file-by-file review of 61 Rust
and Elixir files, 33,180 lines, at revision
`3a2a2b102e64478efd36cfe9426042321e07dcf9`. The tracker contains the complete
located audit evidence and a durable agent brief for every item. No worker
depends on the originating chat or session-local report files.

The scope is 24 formal findings, four maintenance observations, and four
explicitly unconfirmed qualification questions. SEC-1/phx-107 was already
implemented before campaign launch and is closed only after its source fix
is committed. Do not repeat it or claim that source remediation deployed a
production change.

Findings are hypotheses, not permission to force changes. Re-confirm the
current behavior and distinguish executed reproductions from code-derived
predictions. If a prerequisite already satisfies an item, prove that and
close it with evidence instead of manufacturing another edit. Investigation
items may finish without a code change only when their actual acceptance
criteria are satisfied by concrete evidence. A missing policy decision or
required platform is a blocker, not a no-change success.

The user approved this backlog and its dependency split, scoped local
commits **without Co-authored-by trailers**, and isolated validation on the
documented Mac host. No GitHub push, production deployment, canary work,
service-manager mutation, private-key copying, or destructive cleanup is
authorized. Preserve `.campaign.conf`, `prompt.md`, and the existing reusable
`campaign.sh` mechanism.

## Read first

Read `CONTEXT.md`, the applicable ADRs in `docs/adr/`, and the entire selected
issue plus its agent brief/comments. For public routing and host paths,
consult `docs/public-hosting-hardening-design.md`; for PHXP/Darwin, consult
`docs/macos-socket-handoff-design.md`. For the harness issues, read the
attributed sender/descriptor explanation in `docs/adversarial-audit.md`.

Use the canonical terms Workload, Ingress Node, Ingress Trust Domain, Hosting
Profile, Route Declaration, Verified Route, Port Registry, and Delivery
Policy. Do not reinterpret a shared service UID as tenant isolation.

## Execution queue and models

The selected configuration exports `PHX_AUDIT_QUEUE` and `PHX_AUDIT_MODEL`.
Require them; stop rather than infer a queue from unrelated open work.

| Configuration | Queue suffix | Model | Effort |
|---|---|---|---|
| `.campaign.rust-elixir.conf` | `-astra` | `gpt-6-astra` | `max` |
| `.campaign.rust-elixir-opus.conf` | `-opus` | `claude-opus-5` | `max` |

The full queue prefix is `audit-rust-elixir-2026-09`. Astra is the default.
Security work is selected for the Opus queue before execution; initially
SEC-1 and the mandatory-mTLS investigation ING-Q1 use that queue. Automatic
refusal fallback is deliberately disabled. Never retry a provider refusal
with another model or change labels to conceal one. Surface it to the
supervisor. If newly discovered scope needs security specialization, stop
before that work for an explicit supervisor routing decision.

Prefer direct tools to delegation. Any necessary implementation delegation
must use the selected queue's model and max effort explicitly. Do not start a
factory or another campaign, parallelize issue mutations, or claim a peer.

## Inspect and select one item

```bash
test -n "$PHX_AUDIT_QUEUE" && test -n "$PHX_AUDIT_MODEL"
git status --short
br list --status in_progress --limit 0 --json
br ready -l "$PHX_AUDIT_QUEUE" --limit 0 --json
```

Ignore epics, closed work, other queues, and issues lacking
`ready-for-agent`. A pre-existing claim or unexpected dirty/untracked source
is a stop; do not adopt or discard another run's work. The driver's tracked
dirty guard does not account for untracked files, so inspect those yourself.

Real dependency edges are authoritative. Among ready issues in your queue,
prefer higher severity, then these leverage points:

1. E5/phx-324 first: establish the safe out-of-VM regression harness.
2. CP-01 and CP-02: private write bounds and bounded preflight lock access.
3. ING-R1, ING-R2, ING-R3, and ING-R4: bounded/fallible operations and safe
   route/descriptor state transitions.
4. E1, E2, E3, E4, E6, CP-03, ING-P1, and CP-04.
5. Remaining low-severity corrections and maintenance, respecting CP-06
   before CP-05, MAINT-04 before MAINT-02, and E7 before MAINT-03.
6. Qualification questions after their prerequisites.

This is preference ordering, not permission to skip a ready prerequisite or
cross into another queue. The legacy phx-1pq canary and phx-3vs epic are
never eligible.

```bash
br update <selected-id> --claim
br show <selected-id>
br comments <selected-id>
```

Confirm the claim succeeded before editing. Read only the relevant prior
completed handoff in `.campaign/logs` when useful; a handoff is a hint and
never overrides tracker state.

## Elixir structural navigation and runtime safety

Use `/home/chgeuer/github/pnezis/probex/probex` for every `.ex`/`.exs` file:
`outline` on first inspection, then `body`/`clauses` for complete blocks,
`preamble` for setup, and `directives` for name provenance. Batch selectors.
Use structural line selectors for diagnostics; do not guess grep/head/tail
windows. If the exact executable is unavailable, confirm with
`command -v probex`, record that limitation, and fall back to file reading.
Do not guess another path or edit `deps/`.

The user explicitly authorizes direct repository-file reading when the CLI
denies access only to the external `probex` executable. Record that utility
limitation and use the file-reading fallback; do not retry the denied
executable, invoke an alternate copy, or request broader paths. This does not
authorize reading an excluded or denied source file through another tool.
A source-file denial or any different permission requirement remains a stop.

Invoke the `beam-introspection` skill for live BEAM observations and the
`diagnose` skill for bug diagnosis when relevant. Use isolated nodes, fresh
private fixture directories, explicit process identities, and external
deadlines. Do not attach to an unrelated user's running node.

The Linux freezing topology is an **in-VM PHXP sender** changing shared
`O_NONBLOCK` state after descriptor import. Moving only the TLS client out of
the VM does not fix it. Before E5 closes, do not run the existing transport
suite as an unbounded baseline. Build a safe topology assertion or bounded
external-process reproduction first. An ExUnit timeout is not an external
watchdog. Intentionally freezing evidence scripts are not normal tests.

Retain OTP's externally owned imported descriptor receipt until the raw port
closes. Preserve Rustler 0.36 support; 0.38 is explicitly unsupported.

## End-to-end workflow and Definition of Done

1. **Confirm:** Read enough current code and neighboring tests to identify the
   actual failing contract. Establish a bounded, deterministic feedback loop
   at the real call-site/integration seam. For performance, measure operation
   counts or relevant elapsed behavior before claiming improvement.
2. **Regress:** Add the smallest appropriate failing regression before the
   fix. Show that it fails for the audited behavior and passes afterward.
   For E5, a safe topology check is preferable to deliberately freezing a VM.
   Do not revert unrelated code, weaken assertions, or substitute a shallow
   mock for a required integration/platform gate.
3. **Implement:** Make the smallest coherent change through every relevant
   configuration, runtime, cleanup, observability, documentation, and sample
   surface. Reuse existing helpers and preserve error/type safety.
4. **Validate:** Run existing targeted tests together when they share a
   runner, affected-component compilation, formatting for edited files, and
   scoped existing linting. Expand only when shared behavior or a targeted
   failure requires it. Record exact commands, outcomes, and platform.
5. **Review:** Check the complete diff, whitespace, generated/untracked files,
   trust/resource invariants, and every acceptance criterion. Stop all owned
   fixture processes and remove only specifically identified scratch paths.
6. **Commit source:** Stage explicit owned paths, never `git add .` or
   `git add -A`. Commit with the selected issue ID in the subject. Do not
   include Co-authored-by trailers. Do not amend, push to GitHub, or include
   unrelated changes. Include the originating Copilot session trailer when
   required by the CLI's commit policy.
7. **Close only this issue:** Add evidence including the source commit,
   failing/passing regression, exact required commands, remaining limitations,
   and any justified no-change disposition. Then:

   ```bash
   br close <selected-id> -r "Resolved in <commit>. <behavior and evidence>."
   br sync --flush-only
   git add -- .beads/issues.jsonl
   git commit -m "chore: close <selected-id> with remediation evidence"
   ```

8. **Stop:** Leave no claim or uncommitted owned source. Write the two handoff
   sections below and end the run. Never close the container epic or a peer.

Every issue comment begins `> *This was generated by AI during triage.*`.
Do not report success from a command that failed, was killed, skipped a
required gate, or exercised another dependency revision.

### Existing component commands

The audited revision is the baseline, not a claim that every full suite was
green. Known gates were the unsafe E5 harness and E7's unlocked sample
dependency. Use the current manifests/lockfiles; only restore dependencies
after changing a manifest or encountering an actual missing-dependency
failure. Do not install speculative test frameworks.

| Affected component | Existing commands; narrow selectors while iterating |
|---|---|
| Root Rust crate | `cargo test --locked <selector>` or `cargo test --locked --test <target>`; `cargo check --locked`; scoped `cargo clippy --locked -- -D warnings` |
| Rust sample | `cargo test --locked --manifest-path samples/rust/Cargo.toml <selector>`; corresponding `cargo check`/`cargo clippy` |
| Native broker | `cargo test --locked --manifest-path phx_port_handoff/native/phx_port_handoff_native/Cargo.toml <selector>`; corresponding `cargo check`/`cargo clippy` |
| Rust formatting | `rustfmt --edition 2024 --check <edited-files>`; use the applicable `cargo fmt -- --check` when the complete component is affected |
| Handoff package | From `phx_port_handoff`: `mix compile --warnings-as-errors`, `mix format --check-formatted <edited-files>`, and watchdog-bounded `mix test <affected-tests>` |
| Elixir sample | From `samples/elixir`: `mix compile --warnings-as-errors`, `mix format --check-formatted <edited-files>`, and `mix test test/config_test.exs test/plug_test.exs` as applicable |
| Packaging | `cargo test --locked --test runtime_initialization`; actual Darwin `plutil -lint` for changed plists |

For the handoff suite on this Linux host, use `timeout --kill-after=10s 180s
mix test ...` as an external initial watchdog; choose a justified bound if a
specific existing gate requires longer. Do not retry a hang blindly. Invoke
`mix` directly, not `elixir -S mix`, because the latter can read a mise ELF
shim as Elixir source. Linux review used Elixir 1.20.4/OTP 29; record actual
versions rather than assuming them elsewhere.

If an unrelated pre-existing formatter/lint failure is encountered, establish
that baseline with the same targeted command and record it. Do not fix
unrelated code or suppress diagnostics. New warnings/errors, failing related
tests, or an unmet acceptance criterion block closure.

### Required Darwin evidence

CP-10/phx-1xx and ING-R4/phx-2ww require executable Darwin evidence.
`mini.geuer-pollmann.de` is authorized for isolated validation. Its existing
`~/phx-port` checkout was dirty at setup, on master at
`80b361dfa5720e9fe608a35e3cb9f90849fc87c3`; **never overwrite, clean, switch,
or reset it**.

Before use, re-inspect its worktree/branch. Transport committed source through
Git into a uniquely named campaign validation ref and detached worktree,
outside the existing checkout. Direct Git transport to this user-owned host
is allowed; no GitHub push is authorized. Inspect any pre-existing
destination and stop on a collision rather than deleting it.

Use the login environment for tools: `/bin/zsh -lc` resolved Cargo/Rust to
`/opt/homebrew/bin` and Mix to the installed Elixir 1.20.2/OTP 28 directory.
GNU `timeout`/`gtimeout` was not found in the inspected Mac environment;
bound the SSH command from Linux and explicitly track/clean remote fixture
PIDs rather than assuming disconnect kills them. Do not install tools until
an actual required command fails for a missing dependency.

The user subsequently authorized `--add-dir /bin` for required Darwin worker
sessions only. The CLI path checker can mistake a quoted remote
`/bin/zsh -lc ...` command for an out-of-repository local path. The supervisor
may resume ING-R4 or CP-10 with that specific additional-directory flag after
restoring its agent-ready state. This is not authorization for
`--allow-all-paths`, other directories, or broader permissions on ordinary
workers. Preserve the original model and all host guardrails; surface any
different authorization denial rather than evading it.

Use unprivileged ephemeral listeners and generated certificates. Do not
bootstrap launchd, invoke production control sockets, use real private keys,
or alter installed services. Record the exact Git commit, architecture,
toolchain, command, result, and owned-process cleanup. Linux source review
or cross-compilation cannot stand in for the required Darwin behavior.

## Non-negotiable guardrails

- One shared service-UID Ingress Trust Domain, not tenant isolation.
- Exact operator-owned Route Declarations and independently certificate-
  verified Verified Routes; preserve chain and exact-hostname verification.
- Workload-owned TLS/private keys, no ingress TLS termination, loopback-only
  backends, and untouched ClientHello delivery.
- Kernel-authenticated PHXP peers, validated descriptors, bounded framing,
  and **no relay fallback after descriptor delivery**, including timeout.
- Rootless production data plane, local authenticated control, bounded
  threads/tasks/connections/queues/probes/cache and logging cardinality.
- Default zero-bootstrap development allocation/discovery remains intact.
- No secrets, arbitrary SNI/source IPs, payloads, or unbounded error strings
  in ordinary metrics/logs. Use generated fixture credentials only.
- Never kill processes by name, broadly delete directories, reset/check out
  away user changes, or silently recover from failed I/O as valid empty state.

## Blockers and handoff

On a genuine environment/policy blocker, leave a precise issue comment with
the evidence and required next action. If no source was changed, release the
claim and mark `ready-for-human` instead of `ready-for-agent`; then stop. If
partial source exists, preserve it and its claim for the pinned session's
supervised recovery. Do not commit broken work as a finished fix, close the
issue, start another issue, or alter the campaign's model/configuration.

End every run with:

```markdown
## Session summary
Issue and finding ID; confirmed cause or investigation disposition; source
and tracker commits; exact validation evidence and limitations; clean state
or precise blocker; any owned resources requiring cleanup.

## Next-agent prompt
One useful suggested next item in the same queue, subject to br readiness;
relevant stable interfaces and caveats. This is a hint, not a claim.
```

## Supervisor-only operation

The parent supervisor owns the recurring monitor and epic closure. Workers
must not execute this section.

Run one queue at a time under the shared repository-local lock:

```bash
flock --nonblock --close .campaign/rust-elixir.lock \
  env CAMPAIGN_CONF=.campaign.rust-elixir.conf ./campaign.sh
```

Use `.campaign.rust-elixir-opus.conf` for the preselected security queue.
First run the chosen configuration with `--dry-run`. Defaults are bounded
batches of 30 runs and 1,800 seconds per run. A cap exit is not overall
completion. After inspecting a clean stop, launch another bounded batch or
the other queue if ready. Never run both concurrently.

At each supervision tick, inspect process/lock ownership, latest run header
and log, all campaign statuses/dependencies, recent commits, working tree,
and claims. Review closed issue evidence and meaningful diffs; do not edit
the active worker's scope. An ordinary timeout/crash may be recovered by
resuming the pinned session with its original model and owned issue after
inspection, under the same lock. A provider refusal is a stop, not a
cross-model retry. Do not repeatedly restart unchanged failures.

Track the complete epic, not one queue's completion banner:

```bash
br list -l audit-rust-elixir-2026-09 --status open --limit 0 --json
br list -l audit-rust-elixir-2026-09 --status closed --limit 0 --json
br list --status in_progress --limit 0 --json
br ready -l audit-rust-elixir-2026-09-astra --limit 0 --json
br ready -l audit-rust-elixir-2026-09-opus --limit 0 --json
br epic status --json
```

Only when all 32 children have evidence-backed closed dispositions and no
claims, dirty owned source, missing Darwin gate, or unresolved acceptance
remain, perform the final cross-component exit checks: root Rust tests and
lint/format, Rust sample and native broker tests, the now-safe full handoff
package tests, Elixir sample tests, and issue-required platform gates. These
are campaign exit checks, not a blanket full-suite tax on every issue.
Then close phx-27e separately, flush/commit tracker state, and stop recurring
supervision. Never close or modify the legacy canary/epic.

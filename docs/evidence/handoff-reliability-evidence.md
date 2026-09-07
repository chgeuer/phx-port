# Elixir handoff reliability evidence

Baseline: `chgeuer/phx-port`, `master`, `063d368`, initially clean.
No tracked files were changed. This is the parent reviewer's reliability
evidence, not the separately delegated security assessment.

## Confirmed: idle accepts consume the entire dirty-I/O pool

- Category: conditional availability / performance.
- Severity: medium; the deployment condition matters.
- Source: `phx_port_handoff/native/phx_port_handoff_native/src/lib.rs:187-204`.
- Related configuration: `phx_port_handoff/lib/phx_port_handoff.ex:89`.

`Native.accept/1` runs as a dirty-I/O NIF and loops indefinitely, sleeping
10 milliseconds whenever there is no accepted control connection. Every
idle handoff listener therefore holds one dirty-I/O scheduler continuously.
When a VM has at least as many handoff listeners as dirty-I/O schedulers,
unrelated dirty-I/O work can stop making progress. One acceptor per listener
does not bound the aggregate per-VM cost.

The isolated, loopback-only OTP 29 node was started with `+S 2:2 +SDio 2`.
`beam-scheduler-probe.exs` created two idle native accepts. Both process
snapshots reported `current_function: {PhxPortHandoff.Native, :accept, 1}`.
An unrelated `File.stat!` did not finish during a 500 ms observation window.
Closing one listener released a scheduler and the file operation completed
at 503 ms. Closing both listeners released both accepts and removed the
temporary directory.

This is not evidence of a remote exploit, nor a claim that one-listener
deployments are already deadlocked. The threshold is the effective
`dirty_io_schedulers` value, ordinarily 10 unless configured otherwise.
Likewise, the 10 ms idle poll does not imply a 100-connections/second ceiling:
an already nonempty accept queue does not require a sleep between accepts.

Fix direction: readiness-driven native integration, or a bounded broker
worker delivering messages to Elixir, without holding a dirty-I/O scheduler
across indefinite idle waits. Merely raising `+SDio` moves the threshold.

## Confirmed: relative TLS certificate paths break Phoenix startup

- Category: deployment reliability.
- Severity: medium.
- Source: `phx_port_handoff/lib/phx_port_handoff.ex:37-50`.
- Related builder: `phx_port_handoff/lib/phx_port_handoff.ex:91-100`.

`start_link/1` consumes the caller's `otp_app` to read the endpoint
configuration, but passes only the endpoint's HTTPS keyword list to
`bandit_child_spec/4`. The application identity is not added to Bandit's
options.

The ordinary Bandit Phoenix adapter adds `otp_app` from the endpoint
configuration (`samples/elixir/deps/bandit/lib/bandit/phoenix_adapter.ex:95-103`).
Plug requires that option for relative keyfile/certfile/cacertfile paths
(`samples/elixir/deps/plug/lib/plug/ssl.ex:224-257`).

With the current handoff module loaded from the repository's
`phx_port_handoff/_build/dev`, actual Bandit 1.12.5, and OTP 29:

```elixir
Application.put_env(:phx_port_handoff, PhxpAudit.ProbePlug,
  https: [keyfile: "priv/tls/key.pem", certfile: "priv/tls/cert.pem"]
)

PhxPortHandoff.start_link(
  otp_app: :phx_port_handoff,
  endpoint: PhxpAudit.ProbePlug
)
```

Result:

```text
RuntimeError: Plug.SSL.configure/1 encountered error:
the :otp_app option is required when setting relative SSL certfiles
```

This fails before listener startup; it is not dependent on current working
directory or whether those relative filenames exist.

Fix direction: retain and pass the endpoint application identity through
the handoff child builder, preserving explicit supported endpoint options.
Cover real Phoenix-style relative certificate configuration.

## Confirmed: `https: false` raises instead of disabling the handoff child

- Category: deployment reliability.
- Severity: medium.
- Source: `phx_port_handoff/lib/phx_port_handoff.ex:42-50`.

Only `nil` takes the disabled branch. Explicit `false` reaches the builder
and causes `Keyword.get/3` to raise a `FunctionClauseError`. The ordinary
Bandit Phoenix adapter skips false-valued protocol configurations.

Live-node reproduction:

```elixir
Application.put_env(:phx_port_handoff, PhxpAudit.DisabledEndpoint, https: false)
PhxPortHandoff.start_link(
  otp_app: :phx_port_handoff,
  endpoint: PhxpAudit.DisabledEndpoint
)
```

Result: `FunctionClauseError: no function clause matching in Keyword.get/3`.

Fix direction: handle both supported disabled representations explicitly;
do not turn arbitrary malformed options into silent success.

## Investigated but not established: HTTP/1 dictionary clearing leaks FDs

The transport records raw-port cleanup metadata in the process dictionary.
Bandit 1.12.5 clears most process-dictionary entries after a keep-alive
request. That looked suspicious but was not enough to establish a leak.

An actual Bandit server on the isolated node used the current repository
handoff NIF and Elixir code. Three original TCP descriptors were transferred
over PHXP. Each TLS connection performed two HTTP/1.1 requests: first
keep-alive, then `Connection: close`. All six responses were 200 with the
expected body. Afterwards all three handler processes had exited and all
three imported raw ports returned `:undefined` from `:erlang.port_info/1`.
Do not report this hypothesis as a confirmed FD leak.

## Coverage and release-process observations

- Native broker: 9 existing Rust tests passed.
- Package: 14 existing ExUnit tests passed.
- Root handoff selector: 20 unit and 5 integration tests passed.
- Package tests do not exercise the real FD-import/TLS/Bandit ownership path.
- `samples/elixir` initially could not run because its git dependency was
  missing. Restoring with `mix deps.get --check-locked` fetched it but failed
  because the lock needed updating. The lock was left unchanged. Existing
  Bandit dependency sources were built separately to support the live probe;
  the sample test suite was not reported as passing.
- The workflow in `.github/workflows/rust.yml` builds the Rustler crate but
  does not install OTP/Elixir or run the Elixir package/sample.
- `.github/workflows/release.yml` builds and publishes tag artifacts without
  a dependency on the separate test workflow.
- Repository Q26 evidence qualifies the ingress-process harness, explicitly
  not the representative whole-host workload soak. This audit did not run
  the 30-minute qualification or establish real BEAM workload capacity.

The audit-owned Bandit server and BEAM node were stopped. The temporary
Unix-listener directory, TLS certificate/key, and distribution cookie were
removed. The repository remained clean.

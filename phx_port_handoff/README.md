# PhxPortHandoff

`PhxPortHandoff` lets a Linux or macOS Phoenix/Bandit application accept the
original TCP sockets routed by `phx-port`. The application terminates TLS with
its own certificate configuration, sees the client's real source address, and
talks directly to the client without a byte relay.

The integration requires Linux or macOS, Erlang/OTP 29 or later, Rustler 0.36,
Bandit, and Thousand Island. Applications without this package continue to use
phx-port's generic TLS passthrough relay. Rustler 0.38 is not currently
supported because end-to-end testing exposed incompatible imported-descriptor
ownership behavior.

## Installation

Until the package is published, install it from the package directory with
Igniter:

```bash
mix igniter.install \
  phx_port_handoff@path:/absolute/path/to/phx-port/phx_port_handoff \
  --yes
```

The installer adds the path dependency and inserts the handoff child
immediately before the selected Phoenix endpoint. It matches existing children
by endpoint and role (`"https"`, including an omitted default role), so a
different endpoint or role does not prevent installation. Rerunning for the
same target leaves its child and options unchanged and does not announce a new
configuration. A configuration notice appears only when a child was inserted;
custom supervision trees requiring a manual edit produce a warning instead.
If an existing child's endpoint or role cannot be determined statically, the
installer requests a manual check rather than risking a duplicate.

## Phoenix integration

The installer adds a handoff-only Bandit child before the ordinary Phoenix
endpoint child:

```elixir
def start(_type, _args) do
  children = [
    {PhxPortHandoff,
     otp_app: :my_app,
     endpoint: MyAppWeb.Endpoint,
     role: "https"},
    MyAppWeb.Endpoint
  ]

  Supervisor.start_link(children,
    strategy: :one_for_one,
    name: MyApp.Supervisor
  )
end
```

The child reads the endpoint's existing HTTPS options unchanged so both
listeners use the same certificate, SNI callback, ALPN, cipher, and
client-authentication policy. Relative `:certfile` and `:keyfile` paths resolve
against the configured `:otp_app`. It returns `:ignore` when HTTPS is unset or
explicitly `false`.

A handed-off connection must complete its TLS handshake within
`:handshake_timeout` milliseconds, which defaults to `5_000`. A peer that
stalls mid-handshake is disconnected and its descriptor closed rather than
holding an accepted slot. Override it on the handoff child only:

```elixir
{PhxPortHandoff,
 otp_app: :my_app,
 endpoint: MyAppWeb.Endpoint,
 role: "https",
 handshake_timeout: 250}
```

The value must be a positive integer; `:infinity`, zero, negative, and
non-integer values fail listener startup. Do not put this key in the
endpoint's `https:` options or its shared `thousand_island_options:
[transport_options: ...]`: Bandit rejects it at the top level, and the
ordinary OTP SSL listener does not accept it as a TLS option. The helper
forwards it exclusively to `PhxPortHandoff.Transport`, which removes it
before the TLS handshake. Direct callers of `bandit_child_spec/4` can pass
`handshake_timeout: 250` as an optional fifth argument instead.

The ordinary endpoint still listens on its assigned phx-port HTTPS port for
certificate verification, health checks, and direct access. The additional
child listens only on the convention-derived Unix socket. Development uses:

```text
Linux: $XDG_RUNTIME_DIR/phx-port/handoff/<hash>.sock
macOS: /tmp/phx-port-<euid>/handoff/<hash>.sock
```

`<hash>` is `sha256(canonical-project-path NUL role)`. Set
`PHX_PORT_RUNTIME_DIR` to derive the endpoint as
`<runtime>/handoff/<hash>.sock` on either platform.

Use the same canonical project path and role that the workload registered with
phx-port. The helper uses public port `443` in Bandit's connection metadata and
does not bind TCP port 443 itself. It configures one Thousand Island acceptor
because the current native receive path is deliberately serialized.
Serialization is local to the broker's BEAM node, without involving connected
nodes.

In the explicit production Hosting Profile, set the same logical
`PHX_PORT_WORKLOAD_ID` used by the Port Registry. The configured child reads
the variable and uses it as the Workload identity automatically.

The helper hashes `workload-id NUL role` without expanding it as a path and
defaults to:

```text
/run/phx-port/handoff/<hash>.sock
```

`PHX_PORT_RUNTIME_DIR` overrides `/run/phx-port` for both the Workload and
ingress and is required for a macOS production runtime root. The production
runtime root may be mode `0750`; its service-owned `handoff` child remains mode
`0700`. The Workload owns its endpoint lifecycle, so ingress restart does not
remove it. Merely setting `PHX_PORT_WORKLOAD_ID` does not change the existing
development path-based PHXP behavior.

## Security and ownership

The native broker creates a `0600` endpoint in a user-owned `0700` directory.
Linux uses `SOCK_SEQPACKET` and `SO_PEERCRED`; macOS uses `SOCK_STREAM`,
length-delimited reads, explicit `FD_CLOEXEC`, and `getpeereid`. Both require
exactly one connected TCP descriptor and reject duplicate connection
identifiers. The broker refuses to replace non-socket paths or a live receiver.
Its nonblocking liveness probe has a two-second absolute deadline; a full
queue, pending connection, timeout, or operational error preserves the endpoint
and fails startup. Only a refused connection confirms a stale socket for removal.
It monitors its owning Thousand Island listener process so supervisor shutdown
stops its polling accept and releases only the endpoint it bound before an in-VM
restart.

Owner-death and resource-drop callbacks only mark the broker closed; they do
not inspect or unlink filesystem paths. The package's Application supervisor
runs one cleanup process, polling a native registry every 10 ms and performing
cleanup in a dirty-I/O NIF. The registry reserves capacity before binding and
allows at most 1,024 starting, live, or cleanup-pending endpoints per BEAM node.
Capacity exhaustion explicitly rejects new listeners rather than dropping
cleanup work or spawning more workers.

Explicit close waits for cleanup, and same-path startup finishes any pending
predecessor cleanup before binding. Both serialize with deferred cleanup and
retain socket-type, device, inode, and UID checks, so a retired broker cannot
unlink a replacement endpoint. Cleanup failures retain their capacity slot.
The worker retries at most once per second and reports a bounded aggregate
warning once per failed endpoint, without logging its path. Explicit close and
startup retry immediately and report their own cleanup errors. No real
stalled-filesystem behavior is claimed by the deterministic callback regressions.

`phx-port` inspects ClientHello with `MSG_PEEK`; the backend's TLS stack still
reads the original bytes and performs authoritative SNI certificate selection.
After successful descriptor delivery, failures close the client connection
rather than falling back to relay.

OTP's legacy `inet` driver treats an FD imported with `:gen_tcp.fdopen/2` as
externally owned. A dedicated Elixir process therefore retains the native
receipt and monitors the imported Erlang port. The transport closes the raw
port after TLS closes, and only then does the monitor release the native
descriptor. This ordering prevents descriptor reuse while the driver still has
the old FD registered. The import forces `{:inet_backend, :inet}` even when the
VM-wide default is OTP's newer `socket` backend, and selects `:inet` or
`:inet6` from the received descriptor's address family. Active receipts retain
only the duplicate-ID registry, so they do not pin retired listener
descriptors across restarts.

## Current limitations

- Linux or macOS and OTP 29 are required.
- The package starts a second, handoff-only Bandit supervisor. A future hybrid
  accept broker may combine direct TCP and handed-off accepts under one
  Thousand Island server.
- One serialized accept call is used. The native listener is nonblocking, so
  shutdown and supervised restart work consistently on Darwin. The dirty-I/O
  NIF returns `{:error, :eagain}` immediately when no connection is pending
  and the retry delay is taken on an ordinary scheduler, so idle acceptors do
  not occupy a dirty-I/O scheduler and starve unrelated file or port work.

## Regression tests

The default `mix format --check-formatted` inputs include the shipped
`priv/installer/igniter.exs`. Installer tests verify that those inputs reject
an intentionally unformatted installer in a private fixture directory.

On Linux, run the installer, startup, and transport tests as an unprivileged
user with an external OS-process watchdog:

```bash
cd phx_port_handoff
mix format --check-formatted
timeout --kill-after=10s 180s mix test test/phx_port_handoff_install_test.exs
timeout --kill-after=10s 180s mix test test/phx_port_handoff_test.exs test/phx_port_handoff_transport_test.exs
timeout --kill-after=10s 180s mix test test/scheduler_probe_test.exs
```

The startup tests use private fixture sockets and two queued connections to
exercise a full accept queue, with a 2.5-second elapsed bound. Permission-error
coverage requires an unprivileged effective UID.
Cleanup coverage also exercises resource collection while the owner remains
alive, cleanup-worker restart, immediate same-path listener restart, replacement
socket preservation, fixed-capacity admission, and explicit cleanup errors.

The transport tests require Python 3 (standard library only) in addition to the
package toolchain. Both the stalled-peer and complete-TLS scenarios use an external
Python PHXP sender, assert its reported OS PID against the spawned process,
and require an `ADOPTED` reply and successful process exit. The complete-TLS
client also reports readiness and must exit successfully. Fixture callbacks
reap unfinished child processes on failure; the sender has its own 15-second
OS alarm. Listeners use ephemeral loopback ports and generated test certificates.

Accept-locality coverage starts two isolated loopback BEAM peers with a generated
cookie, pauses one peer's global lock server, and verifies closed-broker accepts
do not wait for it. Concurrent direct callers also exercise serialized handoff
and distinct socket ownership through the external sender.

Scheduler-evidence coverage runs the three external-sender probes in fresh
two-scheduler VMs with an additional 20-second external watchdog per run. It
requires real PHXP adoption, matching receiver connection counts and live peers
through the complete heartbeat window, followed by successful sender exit.
Missing, failed, or stalled senders, false adoption counts, premature closure,
and unsuccessful completion must be inconclusive, not healthy. Artifacts use
private per-run directories and unfinished child processes are reaped. The
deliberately freezing in-VM-sender evidence script is never executed by this
suite. See `docs/adversarial-audit.md` in the repository root for probe usage
and the distinction between current automated evidence and historical results.

An ExUnit timeout alone cannot stop a frozen VM. Do not move the PHXP sender
back into the receiving BEAM: its socket operations can change the shared
`O_NONBLOCK` flag after descriptor import. Moving only the TCP/TLS client does
not remove that topology. The stalled TCP peer intentionally remains in-VM.

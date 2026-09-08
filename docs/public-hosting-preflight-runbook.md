# Public Hosting Host Preflight Runbook

This runbook prepares one public-ingress host without serving public
connections. It applies only to the explicit public Hosting Profile. The
default development workflow remains `PORT="$(phx-port)" command` and needs no
service account, production paths, or preflight.

Do not publish DNS or open the public firewall until preflight passes and the
running daemon later reports `ready=true`. A preflight success is host
configuration evidence, not load qualification or canary evidence.

## What the command proves

`phx-port proxy preflight` performs bounded checks and exits. It does not start
the Tokio runtime, control socket, metrics endpoint, reconciliation loop, or
accept loop.

| Check | Pass condition |
|---|---|
| Execution identity | The process effective UID is not 0. |
| Ingress configuration | An explicitly supplied file declares `mode = "public"` and its exact listener set matches the command. |
| Production paths | Intent, Port Registry, disposable route state, runtime root, and optional handoff directory pass the same no-follow ownership, type, mode, link-count, size, and schema checks used at startup. |
| Sandbox access | The service identity creates, writes, and removes one bounded probe in the state directory and runtime root. |
| Control authorization | A non-loopback production runtime root is grouped to `phx-port-admin`; the control directory is created or validated as mode `0750`, and any existing control socket has the exact service owner, runtime group, socket type, and mode `0660`. |
| Capacity | The supplied limits fit their relationships, the current soft `RLIMIT_NOFILE` with 30% reserve, and the supplied or detected task ceiling. The check never raises a limit or changes a configured ceiling. |
| Listener acquisition | The ordinary direct, systemd, or launchd adapter acquires every exact listener and immediately releases it without calling `accept`. |
| System trust roots | The platform TLS verifier initializes with hostname verification enabled. |
| Registrations | Every required Route Declaration resolves to one logical Workload/role port; absent optional registrations are warnings. |
| Route certificates | Each registered loopback Workload completes system-trusted TLS verification for its exact declared hostname; optional failures are warnings. |

Failure details are bounded to 16 Route Declarations and 256 characters per
underlying probe error. The command still checks independent categories after
one category fails so one maintenance pass can expose multiple blockers.

Production-path validation shares a one-second access deadline across its
Port Registry and derived-state reads. The later registration read gets a
fresh one-second deadline. A held registry lock therefore produces a
registry-related `FAIL` instead of indefinitely delaying the report;
independent categories still run. Normal Workload allocation retains its
blocking, exclusive locking.

### Route-scale duration

Registered Route Declarations are checked **serially**, each with a fresh
200 ms TCP/TLS probe deadline. Hostnames sharing a Workload/role still require
independent exact-hostname certificate verification. A reachable Workload
that accepts TCP but never responds to TLS can therefore consume roughly
200 ms per declaration: about 20 seconds for 100 declarations or 200 seconds
for the supported 1,000-declaration maximum, before configuration, filesystem,
trust initialization, scheduling, and report overhead.

This is finite accumulated probe cost, not CP-02's former indefinite registry
lock wait. The one-second registry-access deadlines are not whole-command
deadlines. The report is emitted after all checks finish; limiting displayed
failure details does not stop the remaining probes. No whole-command latency
target has been accepted. Do not infer one from the phrase "bounded checks",
skip certificate verification, or assume the daemon's concurrent probe pool
also runs preflight.

The Linux CLI fixture measures this without starting an Ingress Node or using
production Workloads:

```bash
timeout --kill-after=10s 600s \
  cargo test --locked --test preflight_cli \
    preflight_stalled_routes_at_supported_scale -- --exact --ignored --nocapture
```

It exercises 1, 100, and 1,000 exact declarations across 1, 10, and 100
loopback-only Workloads, respectively, in fresh private temporary directories.
One fixture thread polls at most 100 ephemeral listeners and 100 accepted
sockets, receives only bounded ClientHello data, and sends no TLS response.
It needs neither certificates nor private keys. Each CLI child has a parent
process watchdog of `5 seconds + 400 ms * declaration count` (twice the
per-probe budget plus setup slack), with the separate 600-second shell
watchdog covering the complete run. These are fixture safety limits, not a
production latency promise. The children are killed and reaped on expiry;
fixture sockets, worker, and temporary directories are cleaned up.

The fixture reports per-probe minimum, mean, median, maximum, summed
accept-to-peer-close observations, peak observed open probes, and whole CLI
elapsed time. Server-side observations can differ from the client's deadline
because acceptance, close notification, and process observation are scheduled
separately. Assertions require every declaration to be probed, complete
required/optional failure counts and bounded omission details, independent
diagnostics, an ordinary failing exit rather than a watchdog kill, unchanged
Port Registry contents, and release of the non-serving listener. The existing
ready-host TLS and held-lock tests separately cover trusted exact-hostname
success and bounded registry failure.

The scale fixture is ignored by default because it takes approximately 221
seconds. `preflight_stalled_routes_complete_all_diagnostics` covers the same
integration path with four declarations in the ordinary suite. Include the
scale fixture when collecting duration evidence; the small test alone is not
supported-scale qualification.

Executed CP-Q1 characterization on 2026-09-08 used Linux 7.1.9-arch1-2 x86_64,
rustc 1.95.0-nightly (`f134bbc78`), the locked debug build, and unchanged
production source from `0dd1f926bd516d887baaf17999ad247d7c84f3e5`:

| Workloads | Declarations / completed probes | Mean per probe (ms) | Sum of probe observations (s) | Whole command (s) |
|---|---|---|---|---|
| 1 | 1 / 1 | 200.161 | 0.200161 | 0.222134 |
| 10 | 100 / 100 | 200.176 | 20.017556 | 20.050804 |
| 100 | 1,000 / 1,000 | 200.173 | 200.173373 | 200.285312 |

All three runs observed a peak of one open probe. At 1,000 declarations,
all 500 required and 500 optional failures were counted, each category
displayed 16 details and reported 484 omissions, and every independent
category passed. A preceding full-scale run completed in 200.276104 seconds.
This supports retaining the existing runtime behavior: the accepted bounded
checks complete, and no required whole-command latency contract was violated.
It is not data-plane load qualification, canary evidence, or Darwin evidence.

### Mandatory client authentication

A Workload may demand a client certificate. `phx-port` holds no Workload
private key, so its probe never offers a client identity, and the route
certificate check records the outcome the TLS version dictates.

| Workload TLS version | Route certificates | Verified Route | Workload-side handshake |
|---|---|---|---|
| TLS 1.2 | `FAIL` (`TLS validation failed`, alert 40) | never activates | rejected, `handshake_failure` |
| TLS 1.3 | `PASS` | activates normally | rejected, `certificate_required` |

TLS 1.3 sends the server certificate and its signature before the client
certificate, so the probe completes a chain- and exact-hostname-verified
handshake and holds a complete proof; the Workload then aborts that probe
connection. TLS 1.2 interleaves client authentication into the same
handshake, so the Workload aborts before the probe can inspect anything.
The TLS 1.2 outcome is fail-closed and correct: an unverified backend never
becomes a Verified Route. Do not "fix" it by relaxing verification or by
moving a Workload private key into ingress.

An activated TLS 1.3 mandatory-client-auth route is TCP-liveness checked each
reconciliation pass and fully re-probed every 30 seconds, so expect one
rejected `certificate_required` handshake per revalidation in Workload logs.
That is normal ingress verification, not an attack.

The Linux CLI fixture records the matrix against a real OTP `:ssl` listener
with `verify: :verify_peer` and `fail_if_no_peer_cert: true`, the same
transport options Bandit and Cowboy pass through for a Phoenix endpoint:

```bash
timeout --kill-after=10s 600s \
  cargo test --locked --test preflight_cli \
    preflight_route_certificates_across_mandatory_client_auth_tls_versions \
    -- --exact --ignored --nocapture
```

It generates its own fixture CA, leaf, and key in a fresh private temporary
directory, keeps chain and exact-hostname verification enabled against that
CA through `SSL_CERT_FILE`, and runs 20 real `proxy preflight` invocations per
TLS version. It asserts that every probe reached the Workload, that the
Workload never accepted a handshake, and that each version's ingress verdict
and Workload alert are unanimous across the 20 attempts. The fixture is
ignored by default because it needs an Elixir/OTP toolchain on `PATH`; it
fails loudly rather than skipping when one is absent. Its Workload child is
killed and reaped on drop.

Executed ING-Q1 characterization on 2026-09-08 used Linux 7.1.9-arch1-2
x86_64, rustc 1.95.0-nightly (`f134bbc78`), the locked debug build, Elixir
1.20.4 on OTP 29, and `native-tls` dynamically linked against the system
`libssl.so.3`/`libcrypto.so.3` (the host's `openssl version` reports OpenSSL
3.6.3), from unchanged production source at
`f4f70e243a6dbf216da01f3d13e4219b1e4cd64f`. Five consecutive fixture runs
agreed: TLS 1.2 verified 0/20 with only
`result=rejected alert=handshake_failure`, and TLS 1.3 verified 20/20 with
only `result=rejected alert=certificate_required`. A separate out-of-band run
of the real `daemon`, using the same committed Workload fixture script with
separately generated fixture credentials, confirmed the runtime path: TLS 1.3
logged `event=route result=activated`, and TLS 1.2 logged no activation at
all. That daemon run is corroboration, not a committed regression. This is a
Linux/OpenSSL characterization; the Darwin Security.framework backend was not
measured and remains unqualified.

## Inputs

Run as the same dedicated service identity and with the same environment and
arguments as the eventual daemon:

```bash
PHX_PORT_CONFIG=/var/lib/phx-port/ports.toml
PHX_PORT_RUNTIME_DIR=/run/phx-port
INGRESS_CONFIG=/etc/phx-port/ingress.toml
```

On macOS, use the paths from the shipped LaunchDaemon instead:

```bash
PHX_PORT_CONFIG="/Library/Application Support/phx-port/state/ports.toml"
PHX_PORT_RUNTIME_DIR=/private/var/run/phx-port
INGRESS_CONFIG="/Library/Application Support/phx-port/ingress.toml"
```

The ingress file must be supplied with `--file` or
`PHX_PORT_INGRESS_CONFIG`. `PHX_PORT_CONFIG`,
`PHX_PORT_RUNTIME_DIR`, `PHX_PORT_WORKLOAD_ID`, UID, operating system, and the
presence of `/etc/phx-port` never activate production.

Repeat every nondefault daemon capacity argument during preflight. In
particular, repeat `--active-connections`, `--pre-routing-connections`,
`--relay-connections`, `--handoff-negotiations`, source policy options,
`--client-hello-timeout-ms`, and `--task-budget`. Preflight validates the
values it receives; it does not choose replacements.

## Direct or loopback-only preflight

Use direct acquisition for a foreground deployment or a local public-profile
exercise. Keep the public firewall closed. The service identity must be able
to bind the configured addresses; use an unprivileged port for a loopback-only
exercise.

```bash
sudo -u phx-port env \
  PHX_PORT_CONFIG="$PHX_PORT_CONFIG" \
  PHX_PORT_RUNTIME_DIR="$PHX_PORT_RUNTIME_DIR" \
  /usr/local/bin/phx-port proxy preflight \
    --file "$INGRESS_CONFIG" \
    --listen 127.0.0.1:8443 \
    --active-connections 256 \
    --pre-routing-connections 128 \
    --relay-connections 128 \
    --handoff-negotiations 64 \
    --task-budget 1024
```

Do not use a successful high-port direct bind as evidence that systemd or
launchd will supply the production descriptors. Prove activated listeners in
the applicable service-manager job.

## systemd activated-listener and sandbox preflight

Use the shipped production service environment, identity, socket references,
resource ceilings, and sandbox. Perform this on the clean host while its
public firewall and DNS remain inactive.

1. Install the binary, intent, state/runtime directories, system service, and
   both socket units as documented in the README.
2. Start every declared Workload so its logical assignment and certificate are
   available on loopback.
3. Add a temporary runtime drop-in that replaces `ExecStart`, waits as a
   oneshot, disables restart, and preserves the runtime root across both the
   stop and preflight exit:

   ```ini
   # /run/systemd/system/phx-port.service.d/90-preflight.conf
   [Service]
   Type=oneshot
   ExecStart=
   ExecStart=/usr/local/bin/phx-port proxy preflight --file /etc/phx-port/ingress.toml --listen 0.0.0.0:443 --listen [::]:443
   Restart=no
   RuntimeDirectoryPreserve=yes
   ```

4. Reload systemd, stop the real daemon with the preservation override active,
   and run the preflight:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl stop phx-port.service
   sudo systemctl start phx-port.service
   sudo systemctl show phx-port.service \
     -p Result -p ExecMainCode -p ExecMainStatus
   sudo journalctl -u phx-port.service -n 100 --no-pager
   ```

The report must name `Systemd("tls-ipv4")` and
`Systemd("tls-ipv6")` for listener acquisition. The oneshot process closes its
copies and exits without accepting. `Result=success` and `ExecMainStatus=0`
are mandatory. A nonzero service result means at least one blocking check
failed.

Remove only
`/run/systemd/system/phx-port.service.d/90-preflight.conf`, reload systemd,
and keep the real service stopped until every failure is corrected. The
temporary `RuntimeDirectoryPreserve=yes` is applied before stopping and
remains through the oneshot exit so Workload-owned PHXP endpoints are not
removed. Do not leave the temporary override installed.

The shipped unit's `ReadOnlyPaths`, `ReadWritePaths`,
`RestrictAddressFamilies`, `LimitNOFILE`, `TasksMax`, and identity are active
during this procedure. A sandbox denial therefore appears in the same check
that the real daemon would need. Review the unit separately with:

```bash
systemd-analyze verify \
  /etc/systemd/system/phx-port.service \
  /etc/systemd/system/phx-port-ipv4.socket \
  /etc/systemd/system/phx-port-ipv6.socket
systemd-analyze security phx-port.service
```

The security score is diagnostic input, not an acceptance oracle.

## launchd activated-listener preflight

On a clean macOS host, first install and bootstrap the shipped root one-shot
`packaging/launchd/dev.phx-port.runtime.plist`. Require its last exit code to
be zero and verify that it created `/private/var/run/phx-port` as
`phx-port:phx-port-admin` mode `0750` plus `handoff/` as
`phx-port:phx-port` mode `0700`. The job remains installed so it recreates the
ephemeral tree at every boot.

Then copy the shipped ingress plist to a temporary administrative staging
plist before installing the real ingress LaunchDaemon:

1. Give the copy a unique label such as `dev.phx-port.preflight`.
2. Retain its `UserName`, `GroupName`, environment, resource limits, and
   `tls-ipv4`/`tls-ipv6` `Sockets` entries.
3. Replace `ProgramArguments` with:

   ```text
   /usr/local/bin/phx-port
   proxy
   preflight
   --file
   /Library/Application Support/phx-port/ingress.toml
   --listen
   0.0.0.0:443
   --listen
   [::]:443
   --task-budget
   1024
   ```

4. Replace `1024` with the reviewed production task budget, matching the real
   LaunchDaemon. Remove `KeepAlive` and run the job once with `RunAtLoad=true`.
5. Create a service-owned mode `0700` staging log directory and set
   `StandardOutPath` and `StandardErrorPath` to files beneath it. The bounded
   report is written to stdout and failure summary to stderr; it is not
   automatically a Unified Logging record.
6. Bootstrap the staging plist in the system domain, wait for it to exit, read
   both files, and require launchd's recorded last exit status to be zero.
7. Boot out the exact staging label and remove only its plist and log files before
   installing the real LaunchDaemon.

The listener report must name `Launchd("tls-ipv4")` and
`Launchd("tls-ipv6")`. Keep the host unreachable from public clients throughout
this staging run. Compilation or direct binding is not launchd evidence.

## Host resource budget

Record these values with the preflight report and deployment artifact. Do not
auto-tune global kernel settings from `phx-port`.

### Linux

```bash
ulimit -Sn
ulimit -Hn
systemctl show phx-port.service \
  -p LimitNOFILE -p TasksMax -p MemoryMax -p User -p Group
cat /proc/sys/fs/file-max
cat /proc/sys/net/core/somaxconn
cat /proc/sys/net/ipv4/ip_local_port_range
ss -s
cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null || true
journalctl --disk-usage
timedatectl show -p NTPSynchronized -p TimeUSec
```

The preflight capacity line is authoritative for the binary's current FD/task
arithmetic. The soft `RLIMIT_NOFILE` must fit public sockets, one additional
loopback socket per admitted relay, PHXP/probe/control/state descriptors, and
the mandatory 30% reserve. `TasksMax` must fit runtime, route selection,
certificate probes, bounded PHXP workers, metrics, and auxiliaries.

For relay planning, count the inclusive ephemeral-port range and compare it
with `relay_connections`, expected turnover, existing host consumers, and
`TIME_WAIT`. The accepted performance target is 5,000 simultaneous relays; it
is not a promise that every host's default range or conntrack table is
adequate. Inspect pressure during qualification:

```bash
ss -tan state time-wait | wc -l
ss -tan dst 127.0.0.1 | wc -l
```

### macOS

```bash
launchctl limit maxfiles
sysctl kern.maxfiles kern.maxfilesperproc kern.ipc.somaxconn
sysctl net.inet.ip.portrange.first net.inet.ip.portrange.last
netstat -anv -p tcp
systemsetup -getusingnetworktime
```

Record the launchd soft/hard `NumberOfFiles` values from the installed plist
and the production service account. macOS has no Linux `TasksMax`; pass an
explicit reviewed `--task-budget` so preflight validates the binary's bounded
worker demand.

## Failure diagnosis

| Failed check | Diagnose and correct |
|---|---|
| Execution identity | Run as the dedicated non-login service account. Do not make UID 0 the data-plane identity. |
| Ingress configuration | Run `proxy config check --file ...`; correct mode, exact listener declarations, unknown keys, normalized duplicate names, and root ownership. |
| Production paths | Inspect every ancestor with no symlink following. Restore the documented owners and modes; keep intent, Port Registry, and derived state separate. |
| Sandbox access | Compare the service unit allowlists with the selected state/runtime paths. Correct the unit or paths explicitly; do not broaden the sandbox without testing. |
| Control authorization | Create `phx-port-admin`, group the runtime root to it, and retain mode `0750`. Do not grant service/admin peers mutation. |
| Capacity | Raise the service's explicit FD/task ceilings or lower explicit ingress limits. Never let preflight silently select values. |
| Listener acquisition | For direct mode, find the exact owner of the address/port. For activation, verify descriptor names, count, TCP/listening state, address family, and configured address. |
| System trust roots | Repair the platform CA installation and service sandbox access to it. Do not disable hostname or certificate verification. |
| Registrations | Start the declared Workload with the shared `PHX_PORT_CONFIG`, exact `PHX_PORT_WORKLOAD_ID`, and declared role. Do not edit derived routes as authority. |
| Route certificates | Connect only to the reported loopback port and inspect the Workload-owned chain, SAN, validity window, and SNI selection. Do not move private keys into ingress. A Workload that demands a client certificate fails this check on TLS 1.2 and passes on TLS 1.3; see "Mandatory client authentication". |

After all checks pass, remove any staging service override, start the real
daemon, and require both commands to succeed before exposing traffic:

```bash
phx-port proxy check --live
phx-port proxy check --ready
```

Pass the same `PHX_PORT_INGRESS_CONFIG`, `PHX_PORT_CONFIG`, and
`PHX_PORT_RUNTIME_DIR` used by the daemon to every public control command.

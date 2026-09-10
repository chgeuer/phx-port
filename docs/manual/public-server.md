# Public server setup

This procedure configures one host as a TLS/SNI ingress. Workloads remain TLS
endpoints and listen only on loopback.

Do not expose the host until the final readiness check succeeds.

## Files and ownership

### Linux

| Path | Owner and mode | Purpose |
|---|---|---|
| `/usr/local/bin/phx-port` | `root:root 0755` | Reviewed binary |
| `/etc/phx-port/ingress.toml` | `root:phx-port 0640` | Route and listener policy |
| `/var/lib/phx-port/ports.toml` | `phx-port:phx-port 0600` | Stable Workload ports |
| `/var/lib/phx-port/routes.toml` | `phx-port:phx-port 0600` | Disposable verified routes |
| `/var/lib/phx-port/route-claims.toml` | `phx-port:phx-port 0600` | Durable certificate-discovery ownership |
| `/run/phx-port/handoff/` | `phx-port:phx-port 0700` | Workload PHXP sockets |
| `/run/phx-port/control/` | `phx-port:phx-port-admin 0750` | Local control socket |

Back up `ingress.toml` and `ports.toml`, plus `route-claims.toml` when using
`certificate_discovery`. Do not recreate lost claims from reachable Workloads.

### macOS

Use:

- `/Library/Application Support/phx-port/ingress.toml`
- `/Library/Application Support/phx-port/state/ports.toml`
- `/private/var/run/phx-port`

The shipped LaunchDaemon contains the exact paths and resource limits.

## Trust model

Ingress and all PHXP-capable Workloads run under one dedicated non-login
service UID. A compromised Workload can access resources available to that UID.
This is suitable for one operator-controlled trust domain; it is not hostile
multi-tenant isolation.

Only root may mutate public ingress through the control socket. The service UID
and members of `phx-port-admin` may inspect it.

## Linux installation

From a source checkout on Linux with `systemd-sysusers`, `systemd-tmpfiles`,
and `sudo`, provision the accounts and directories for steps 1 and 2 with:

```bash
just setup-public
```

This creates the missing non-login `phx-port` service account and its group,
the `phx-port-admin` group, and the service account's membership in that group.
It creates or corrects the documented modes/ownership of `/etc/phx-port`,
`/var/lib/phx-port`, `/run/phx-port`, and the runtime `handoff` and `control`
directories. It is safe to rerun: existing accounts, configuration, certificates,
registries, durable ownership claims, and socket files are not replaced.

The task uses `sudo` and makes system-level changes, but does **not** add your
login account to the admin group, install the binary or policy, enable/start
services, or switch the running development ingress to public mode. Continue
with the binary installation in step 2 and the remaining steps below. The
manual account/directory commands are alternatives to the task.

Runtime directories are ephemeral. Rerun the task after a reboot when using
foreground ingress; the shipped systemd service recreates its runtime tree
when used instead.

### 1. Create identities

Adapt account-management syntax to the distribution:

```bash
sudo groupadd --system phx-port
sudo groupadd --system phx-port-admin
sudo useradd --system \
  --gid phx-port \
  --groups phx-port-admin \
  --home-dir /var/lib/phx-port \
  --shell /usr/sbin/nologin \
  phx-port
```

Add read-only operators to `phx-port-admin`. Do not give that group mutation
authority.

### 2. Install binary and directories

```bash
sudo install -o root -g root -m 0755 target/release/phx-port \
  /usr/local/bin/phx-port
sudo install -d -o root -g phx-port -m 0755 /etc/phx-port
sudo install -d -o phx-port -g phx-port -m 0700 /var/lib/phx-port
sudo install -d -o phx-port -g phx-port-admin -m 0750 /run/phx-port
sudo -n -u phx-port -g phx-port -- install -d -o phx-port -g phx-port -m 0700 \
  /run/phx-port/handoff
```

Initialize children of `/run/phx-port` as the service user, including on repeated
provisioning runs. Their parent is service-writable, so a pre-existing child
could be a symlink. Root's `install -o phx-port` does not drop privileges and
could change the symlink target's ownership or permissions. `just setup-public`
uses the service identity for both `handoff` and `control`; otherwise ingress
creates `control` when it starts. If the unprivileged step fails, inspect the
path rather than retrying it as root.

### 3. Write ingress configuration

The default public Routing Policy is `declared`; existing deployments remain
exact declaration-only.

`/etc/phx-port/ingress.toml`:

```toml
[ingress]
mode = "public"
unknown_sni = "reject"
listen = ["0.0.0.0:443", "[::]:443"]

[ingress.metrics]
listen = "127.0.0.1:9464"

[ingress.hosts."www.example.com"]
workload = "example-web"
role = "https"
required = true
relay_idle_timeout_seconds = 1800

[ingress.hosts."api.example.com"]
workload = "example-api"
role = "https"
required = false
relay_idle_timeout_seconds = 1800
```

Install it:

```bash
sudo install -o root -g phx-port -m 0640 ingress.toml \
  /etc/phx-port/ingress.toml
```

Rules:

- Declarations are exact, normalized SNI names; wildcard declarations are not
  accepted.
- `required = true` means an unavailable or invalid route makes readiness
  false.
- A relay idle timeout of `0` disables the timeout for that route.
- Metrics must bind to loopback.
- Changing the metrics listener requires restart; route declarations can
  reload.

#### Opt-in certificate-driven production routing

Instead of the declaration configuration above, choose:

```toml
[ingress]
mode = "public"
routing_policy = "certificate_discovery"
listen = ["0.0.0.0:443", "[::]:443"]

[ingress.metrics]
listen = "127.0.0.1:9464"
```

Do not include `[ingress.hosts]`, even an empty table: mixing policies is
rejected. There are no per-host mappings. This is still the public Hosting
Profile, with the same dedicated service identity, protected logical registry,
admission limits, and Workload-owned TLS termination. Use only within one
shared Ingress Trust Domain; this is not multi-tenant isolation.

Selection applies to the TLS connection's initial SNI, not encrypted HTTP
`Host` or `:authority`. A browser may coalesce HTTP/2 requests onto a wildcard
certificate's existing connection. Workloads must reject misdirected requests
with HTTP 421 or prevent cross-owner coalescing at their TLS/HTTP endpoints;
an opaque SNI ingress cannot route individual encrypted HTTP/2 streams.

Each logical `https` registration announces exact and wildcard DNS SANs from
its no-SNI default certificate. Those hints alone authorize nothing: a separate
trusted TLS/private-key proof must verify the hostname, and a wildcard proof
must return that same wildcard SAN in the verified leaf. An exact-only leaf
for the representative hostname cannot prove wildcard ownership.

- Dedicated exact SAN ownership wins over a wildcard, in either startup order
  and when the exact Workload starts later.
- `*.sub.example.com` covers any **one nonempty label** such as `foo` or `bar`,
  never `sub.example.com`, `deep.foo.sub.example.com`, or a suffix lookalike.
  Client SNI itself must be a concrete DNS hostname.
- Two distinct owners of the same exact name or wildcard pattern fail closed,
  including withdrawing a previously verified incumbent. Other healthy routes
  continue serving.
- Claims survive certificate expiry, backend failure, cache removal, and ingress
  restart. An unavailable exact owner keeps its name: **no wildcard fallback**.
  Restarting that service with the same registration and valid TLS restores its
  route. Removing its logical `https` registration is the release signal.
  Wildcard claims and conflicts use the same registration-scoped lifetime.
- Eager discovery needs usable default-certificate SANs. Cold-SNI discovery can
  learn additional certificates, but a warm wildcard does not search every
  Workload's hidden SNI-only certificate catalog. Advertise dedicated exact
  names in their owner's default certificate. The development `main` fallback
  is not eligible in public automatic discovery.

`route-claims.toml`, beside `ports.toml`, is durable authority, **not a cache**.
Back it up with the registry and retain it across policy changes. A process
never activates cached claims without trusted TLS verification. Damaged claims
fail closed; restore them rather than deleting or rebuilding them from currently
reachable services. Missing state is first-use bootstrap, so never start ingress
after losing this file: restore the authoritative backup first.
Accepted automatic-policy reloads retain claims but reverify positive
activations; inspect readiness before restoring traffic.

Bounds are 32 registered HTTPS Workloads and 1,024 owner-pattern claims.
There is no claim LRU eviction. A registry over the candidate limit blocks
automatic routing. Claim exhaustion records the offending Workload IDs durably
and blocks automatic routing until those HTTPS registrations are removed;
otherwise an unrecorded exact owner could disappear behind a wildcard.
Positive cache, negative cache, conflict diagnostics, probes, and waiting
clients retain their existing bounds. Unknown names still require unique trusted
proof or are rejected; this is not a catch-all default backend.

Readiness requires a completed reconciliation pass, valid registry, at least
one verified route, and no ownership conflicts. `readiness_reason`, claim
counts, and bounded degraded/workload details explain pending or blocked
states. A stopped exact owner can be degraded while unrelated routes remain
ready and usable. Conflicts make readiness false without disabling unrelated
healthy traffic. Metrics label the selected public policy but never dynamic
hostnames or Workload IDs. Automatic routes use the public 1,800-second relay
idle timeout.

`proxy preflight` validates host/configuration/registry/claim storage and warns
that automatic TLS and ownership verification require runtime reconciliation.
After starting ingress, require `proxy check --ready` and inspect
`proxy status --json` and `proxy routes`; preflight alone is not proof of an
automatic route.

### 4. Start each Workload

Every Workload must use the shared stable registry, an explicit logical ID,
and its TLS role (`https` for automatic discovery):

```bash
sudo -u phx-port env \
  PHX_PORT_CONFIG=/var/lib/phx-port/ports.toml \
  PHX_PORT_RUNTIME_DIR=/run/phx-port \
  PHX_PORT_WORKLOAD_ID=example-web \
  sh -c '
    HTTPS_PORT="$(/usr/local/bin/phx-port https)"
    export HTTPS_PORT
    exec /opt/example/bin/server --listen "127.0.0.1:${HTTPS_PORT}"
  '
```

The Workload must present a system-trusted certificate valid for its declared
hostname, or announce and prove its exact/wildcard DNS SANs under automatic
discovery. Keep its certificate, key, and DNS-01 credentials in
Workload-owned storage. Never copy them into `/etc/phx-port`.

Use the PHXP integration for the Workload's runtime when available. Otherwise
ingress relays encrypted TCP to the registered loopback port.

### 5. Validate configuration

```bash
sudo -u phx-port env \
  PHX_PORT_INGRESS_CONFIG=/etc/phx-port/ingress.toml \
  PHX_PORT_CONFIG=/var/lib/phx-port/ports.toml \
  PHX_PORT_RUNTIME_DIR=/run/phx-port \
  /usr/local/bin/phx-port proxy config check \
    --file /etc/phx-port/ingress.toml
```

Then run the complete non-serving
[host preflight](../public-hosting-preflight-runbook.md) inside the production
service context. Preflight must use the same listeners and capacity arguments
as the daemon.

### 6. Install systemd units

```bash
sudo install -o root -g root -m 0644 \
  packaging/systemd/phx-port.service \
  packaging/systemd/phx-port-ipv4.socket \
  packaging/systemd/phx-port-ipv6.socket \
  /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now \
  phx-port-ipv4.socket \
  phx-port-ipv6.socket \
  phx-port.service
```

The socket units own TCP/443. The service runs without capabilities as
`phx-port`, with `LimitNOFILE=65536`, `TasksMax=1024`, a finite memory limit,
and a restricted filesystem/address-family sandbox.

### 7. Require health before exposure

```bash
export PHX_PORT_INGRESS_CONFIG=/etc/phx-port/ingress.toml
export PHX_PORT_CONFIG=/var/lib/phx-port/ports.toml
export PHX_PORT_RUNTIME_DIR=/run/phx-port

phx-port proxy check --live
phx-port proxy check --ready
phx-port proxy routes
curl --fail --silent http://127.0.0.1:9464/metrics >/dev/null
```

Only now publish public DNS and allow inbound TCP/443. Keep TCP/80 closed.

## macOS installation

Build or install the native architecture artifact.

Create a non-login service account, its primary group, and the administrative
read-only group. First choose two unused IDs; do not copy these example IDs
without checking the local directory:

```bash
dscl . -list /Users UniqueID | sort -nk2
dscl . -list /Groups PrimaryGroupID | sort -nk2

SERVICE_ID=499
ADMIN_GROUP_ID=498

sudo dscl . -create /Groups/phx-port
sudo dscl . -create /Groups/phx-port PrimaryGroupID "$SERVICE_ID"
sudo dscl . -create /Groups/phx-port RealName "phx-port service"

sudo dscl . -create /Groups/phx-port-admin
sudo dscl . -create /Groups/phx-port-admin PrimaryGroupID "$ADMIN_GROUP_ID"
sudo dscl . -create /Groups/phx-port-admin RealName "phx-port read-only operators"

sudo dscl . -create /Users/phx-port
sudo dscl . -create /Users/phx-port UniqueID "$SERVICE_ID"
sudo dscl . -create /Users/phx-port PrimaryGroupID "$SERVICE_ID"
sudo dscl . -create /Users/phx-port NFSHomeDirectory /var/empty
sudo dscl . -create /Users/phx-port UserShell /usr/bin/false
sudo dscl . -create /Users/phx-port RealName "phx-port service"
sudo dscl . -create /Users/phx-port IsHidden 1
sudo dscl . -create /Users/phx-port Password '*'
sudo dseditgroup -o edit -a phx-port -t user phx-port-admin

id phx-port
dseditgroup -o checkmember -m phx-port phx-port-admin
```

Add each read-only operator to `phx-port-admin` with `dseditgroup`. Ensure the
selected IDs are unused both locally and in any directory service visible to
the host.

Provision the persistent paths and the initial runtime tree:

```bash
sudo install -o root -g wheel -m 0755 phx-port /usr/local/bin/phx-port
sudo install -d -o root -g phx-port -m 0755 \
  "/Library/Application Support/phx-port"
sudo install -d -o phx-port -g phx-port -m 0700 \
  "/Library/Application Support/phx-port/state"
sudo install -d -o phx-port -g phx-port-admin -m 0750 \
  /private/var/run/phx-port
sudo -n -u phx-port -g phx-port -- install -d -o phx-port -g phx-port -m 0700 \
  /private/var/run/phx-port/handoff
sudo install -o root -g phx-port -m 0640 ingress.toml \
  "/Library/Application Support/phx-port/ingress.toml"
sudo install -o root -g wheel -m 0644 \
  packaging/launchd/dev.phx-port.runtime.plist \
  /Library/LaunchDaemons/
sudo install -o root -g wheel -m 0644 \
  packaging/launchd/dev.phx-port.ingress.plist \
  /Library/LaunchDaemons/
```

`/private/var/run` is cleared at boot. The root one-shot
`dev.phx-port.runtime` job recreates the exact runtime directory on every boot,
then drops to `phx-port` before initializing the service-writable handoff
child. Do not run that child step as root, even during recovery. Bootstrap and
verify the job before running preflight or installing ingress:

```bash
sudo launchctl bootstrap system \
  /Library/LaunchDaemons/dev.phx-port.runtime.plist
sudo launchctl print system/dev.phx-port.runtime
```

Require `last exit code = 0` and recheck owners and modes:

```bash
stat -f '%N uid=%u gid=%g mode=%Lp' \
  /private/var/run/phx-port \
  /private/var/run/phx-port/handoff
```

Run the launchd preflight procedure before installing the live job. Then:

```bash
sudo launchctl bootstrap system \
  /Library/LaunchDaemons/dev.phx-port.ingress.plist
sudo launchctl print system/dev.phx-port.ingress
```

Use `/private/var/run`, not `/var/run`, when strict macOS path validation is
enabled. If ingress starts before the runtime one-shot during a reboot, it
fails closed and launchd retries it after the runtime tree exists. The complete
activation proof is in the
[host preflight runbook](../public-hosting-preflight-runbook.md).

## Capacity options

The packaged defaults are conservative. The daemon accepts explicit limits:

```text
--active-connections
--pre-routing-connections
--relay-connections
--handoff-negotiations
--accepts-per-second
--accept-burst
--source-accepts-per-second
--source-accept-burst
--source-pre-routing-connections
--source-ipv6-prefix
--source-table-capacity
--source-entry-ttl-seconds
--source-policy CIDR=RATE,BURST,PRE_ROUTING[,IPV6_PREFIX]
--client-hello-timeout-ms
--task-budget
```

Repeat the exact chosen limits during preflight. Do not increase limits until
the host's FD, task, memory, ephemeral-port, and conntrack budgets have been
measured. The accepted 4-vCPU/8-GiB qualification evidence is not automatic
proof for a differently configured host.

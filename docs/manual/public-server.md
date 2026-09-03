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
| `/run/phx-port/handoff/` | `phx-port:phx-port 0700` | Workload PHXP sockets |
| `/run/phx-port/control/` | `phx-port:phx-port-admin 0750` | Local control socket |

Back up only `ingress.toml` and `ports.toml`.

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
sudo install -d -o phx-port -g phx-port -m 0700 /run/phx-port/handoff
```

### 3. Write ingress configuration

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

- Hostnames are exact, normalized SNI names; there are no wildcards.
- `required = true` means an unavailable or invalid route makes readiness
  false.
- A relay idle timeout of `0` disables the timeout for that route.
- Metrics must bind to loopback.
- Changing the metrics listener requires restart; route declarations can
  reload.

### 4. Start each Workload

Every Workload must use the shared stable registry, an explicit logical ID,
and a declared role:

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

The Workload must present a system-trusted certificate whose SAN contains its
exact declared hostname. Keep its certificate, key, and DNS-01 credentials in
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
sudo install -d -o phx-port -g phx-port -m 0700 \
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
`dev.phx-port.runtime` job recreates the exact runtime and handoff directories
on every boot. Bootstrap and verify it before running preflight or installing
ingress:

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

# Public Hosting Backup, Recovery, and Restart Runbook

This runbook preserves authoritative public-ingress state and rehearses
restart and rollback without treating derived certificate state as authority.
It does not replace the qualification and canary gates.

## State classification

| Path | Authority | Back up |
|---|---|---|
| `/etc/phx-port/ingress.toml` | Root-owned Route Declarations, listeners, and policy | Yes, with owner/mode |
| `/var/lib/phx-port/ports.toml` | Service-owned stable logical Workload/role assignments | Yes, with owner/mode |
| `/var/lib/phx-port/routes.toml` | Disposable certificate-verified route cache | No |
| `*.lock` | Host-local synchronization | No |
| `/run/phx-port` | Runtime, control, and Workload-owned PHXP endpoints | No |

On macOS, substitute the paths from
`packaging/launchd/dev.phx-port.ingress.plist`. Certificates, private keys, and
DNS credentials remain Workload-owned and follow each Workload's backup
policy; they never enter an ingress backup.

## Consistent backup

The Port Registry can change when a Workload first allocates a role. Take a
shared lock compatible with the registry's advisory lock, or stop Workload
allocation for the short copy window. On Linux with `flock`:

```bash
backup=/srv/backups/phx-port/$(date -u +%Y%m%dT%H%M%SZ)
sudo install -d -o root -g root -m 0700 "$backup"
sudo flock -s /var/lib/phx-port/ports.toml.lock \
  cp --preserve=mode,ownership,timestamps \
    /var/lib/phx-port/ports.toml "$backup/ports.toml"
sudo cp --preserve=mode,ownership,timestamps \
  /etc/phx-port/ingress.toml "$backup/ingress.toml"
sudo stat -c '%n uid=%u gid=%g mode=%a size=%s' \
  "$backup/ingress.toml" "$backup/ports.toml" |
  sudo tee "$backup/metadata.txt" >/dev/null
sudo sha256sum "$backup/ingress.toml" "$backup/ports.toml" |
  sudo tee "$backup/SHA256SUMS" >/dev/null
```

On macOS, quiesce first-time Workload allocation, copy both files with
`cp -p`, and record `stat -f '%N uid=%u gid=%g mode=%Lp size=%z'` plus
`shasum -a 256`. Resume allocation only after both files and metadata are
durable.

Do not copy a live `routes.toml`, lock file, control socket, handoff socket, or
runtime directory. A retained pre-migration combined registry is also a
permission-preserving rollback snapshot; migration never overwrites it.

Test backup restoration on an isolated host at the documented recovery
frequency. A backup that has not completed a cold-start verification is not
recovery evidence.

## Cold restore

Keep DNS and the public firewall withdrawn while restoring.

1. Install the reviewed binary and create the same non-login `phx-port` user,
   service group, and `phx-port-admin` group.
2. Install the ingress intent as UID 0, not group/other writable.
3. Install the Port Registry as the service identity with mode `0600`, under a
   service-owned mode `0700` state directory.
4. Create the runtime root as service-owned, `phx-port-admin`-grouped mode
   `0750`, and the handoff directory as service-owned mode `0700`.
5. Leave `routes.toml`, its lock, control sockets, and PHXP endpoints absent.
6. Start each Workload with the restored `PHX_PORT_CONFIG`, its exact
   `PHX_PORT_WORKLOAD_ID`, and its declared role. Existing assignments must be
   returned idempotently.
7. Run the complete
   [host preflight](public-hosting-preflight-runbook.md) in the target service
   context. On systemd, apply its temporary
   `RuntimeDirectoryPreserve=yes` override before any stop so this step does
   not remove Workload-owned PHXP endpoints.
8. Start ingress and wait for local certificate verification to rebuild
   disposable route state.
9. Require `proxy check --live` and `proxy check --ready`, then exercise one
   exact declared hostname and confirm its handoff-success counter before
   restoring public traffic. Relay success is not PHXP evidence.

Linux installation example:

```bash
sudo install -d -o root -g phx-port -m 0755 /etc/phx-port
sudo install -o root -g phx-port -m 0640 \
  "$backup/ingress.toml" /etc/phx-port/ingress.toml
sudo install -d -o phx-port -g phx-port -m 0700 /var/lib/phx-port
sudo install -o phx-port -g phx-port -m 0600 \
  "$backup/ports.toml" /var/lib/phx-port/ports.toml
sudo install -d -o phx-port -g phx-port-admin -m 0750 /run/phx-port
sudo install -d -o phx-port -g phx-port -m 0700 /run/phx-port/handoff
```

If disposable state already exists on the recovery target, stop ingress and
remove only these exact host-local files before cold start:

```bash
sudo rm -f /var/lib/phx-port/routes.toml \
  /var/lib/phx-port/routes.toml.lock
```

Never reconstruct `ports.toml` from `routes.toml`. The Route Declarations and
stable Port Registry are authority; every Verified Route must be proven again.

## Controlled restart and drain

Before a planned restart:

```bash
phx-port proxy status --json
phx-port proxy check --ready
```

Public shutdown stops admission, cancels pre-routing work, resolves PHXP
ownership, and drains relays for at most 60 seconds. Handed-off connections
remain Workload-owned. Remaining relays close at the deadline. The supplied
systemd and launchd stop deadlines allow five additional seconds for process
cleanup.

On Linux:

```bash
sudo systemctl restart phx-port.service
sudo journalctl -u phx-port.service --since=-2min --no-pager
```

The systemd socket units retain the named public listeners and their bounded
kernel backlog during the process restart. Confirm a new non-root main PID,
`event=ingress_shutdown`, live health, readiness, and an exact declared route.
Do not call this zero-downtime for relays; long-lived relays may close at the
deadline.

On macOS:

```bash
sudo launchctl kickstart -k system/dev.phx-port.ingress
sudo launchctl print system/dev.phx-port.ingress
```

The LaunchDaemon owns the named sockets. Confirm the replacement process runs
as the configured account and repeats live, ready, route, and handoff/relay
checks. Do not claim launchd restart behavior from Linux evidence.

## Binary and configuration rollback

Keep the preceding reviewed binary and either:

- a Port Registry schema it can read directly; or
- the permission-preserving pre-rollout registry snapshot.

Rollback procedure:

1. Withdraw public traffic or enter the documented maintenance window.
2. Record current status, binary version, config checksum, and registry
   checksum.
3. Stop ingress through the service manager and let the bounded drain finish.
4. Install the preceding binary atomically at the configured executable path.
5. Restore the compatible ingress intent and stable Port Registry if the
   preceding binary cannot read the current schema.
6. Leave derived route state absent so it cannot authorize routing.
7. Run that binary's config check and host preflight under its documented
   interface. If the preceding binary predates preflight, run its config check
   plus the preserved release-specific verification procedure.
8. Start the service, require live/ready health, and exercise the canary route.
9. Restore traffic only after the rollback objective is met.

The accepted canary also requires an independently generated and tested
HAProxy or NGINX-stream SNI configuration. That artifact is generated from
exact Route Declarations plus stable Port Registry assignments, never from
private keys or disposable routes. The rollback gate remains incomplete until
both the preceding-binary path and independent SNI path finish in under five
minutes in the named canary environment.

## Local control authorization

Every public control command must use the daemon's exact profile environment:

```bash
export PHX_PORT_INGRESS_CONFIG=/etc/phx-port/ingress.toml
export PHX_PORT_CONFIG=/var/lib/phx-port/ports.toml
export PHX_PORT_RUNTIME_DIR=/run/phx-port
```

The service UID and current members of `phx-port-admin` may read status,
routes, and readiness. Only UID 0 may reload or stop production ingress:

```bash
sudo -u monitoring-user --preserve-env=PHX_PORT_INGRESS_CONFIG,PHX_PORT_CONFIG,PHX_PORT_RUNTIME_DIR \
  phx-port proxy status --json

sudo --preserve-env=PHX_PORT_INGRESS_CONFIG,PHX_PORT_CONFIG,PHX_PORT_RUNTIME_DIR \
  phx-port proxy reload
```

An unauthorized response is a policy success, not a reason to widen socket
modes or remove peer credential checks. The control socket stays local under
the mode `0750` control directory, is mode `0660`, and never binds a public
address.

## Recovery diagnosis

| Symptom | Required investigation |
|---|---|
| Preflight path failure | Compare restored UID/GID/mode/link count and every ancestor; reject symlinks rather than following them. |
| Registry parse or duplicate-port failure | Restore the last known-good authoritative registry. Do not guess assignments from derived routes. |
| `ready=false` after restore | Read bounded degraded Route Declaration detail; verify Workload registration, loopback listener, exact SAN, certificate chain, validity, and platform trust roots. |
| Listener activation failure | Inspect exact descriptor names and configured IPv4/IPv6 addresses in the service-manager definition. Do not fall back silently to a different public bind. |
| Capacity failure | Compare the preflight required FD/task figures with service and host ceilings. Change explicit policy or host provisioning, not runtime assertions. |
| Sandbox denial | Compare selected paths and trust-store access with the shipped allowlists; keep the smallest tested permission set. |
| Control authorization failure | Verify runtime/control ownership, `phx-port-admin` membership, socket modes, and the kernel-reported peer identity. |
| Restart exceeds deadline | Inspect unresolved relay and PHXP counters plus the bounded shutdown event. Never permit post-descriptor relay fallback to shorten shutdown. |

Record the exact binary commit, configuration checksum, backup identifier,
commands, timestamps, and live/ready results for every rehearsal. Capacity,
launchd, systemd, and rollback support claims require this executable evidence.

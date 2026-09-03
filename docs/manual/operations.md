# Inspection and operations

This guide assumes the public server is installed. For local development, use
the inspection commands in [the development guide](development.md).

## Set the profile environment

Every public control command must select the same files and runtime root as the
daemon:

```bash
export PHX_PORT_INGRESS_CONFIG=/etc/phx-port/ingress.toml
export PHX_PORT_CONFIG=/var/lib/phx-port/ports.toml
export PHX_PORT_RUNTIME_DIR=/run/phx-port
```

On macOS, substitute the paths from the installed LaunchDaemon.

## Fast health check

```bash
phx-port proxy check --live
phx-port proxy check --ready
phx-port proxy status --json
phx-port proxy routes
```

Interpretation:

- **live false:** the daemon or authenticated control endpoint is unavailable.
- **ready false:** ingress is alive but cannot safely serve all required Route
  Declarations, or it is draining.
- **degraded optional route:** inspect it, but it does not make readiness false.
- **draining true:** no new connections are admitted.

On Linux:

```bash
systemctl status phx-port.service \
  phx-port-ipv4.socket phx-port-ipv6.socket
journalctl -u phx-port.service --since=-15min --no-pager
ss -ltn '( sport = :443 )'
```

On macOS:

```bash
sudo launchctl print system/dev.phx-port.ingress
sudo lsof -nP -iTCP:443 -sTCP:LISTEN
```

## Metrics

If `[ingress.metrics]` is configured:

```bash
curl --fail --silent http://127.0.0.1:9464/metrics
```

Alert on:

| Condition | Metric or signal |
|---|---|
| Ingress unavailable | health command fails or `phx_port_build_info` disappears |
| Required route unavailable | `phx_port_ready != 1` |
| Drain in progress | `phx_port_draining == 1` |
| Invalid registry snapshot | `phx_port_registry_valid != 1` |
| Capacity pressure | admission in-use approaches its matching limit |
| Rejected traffic | increase in `phx_port_admission_rejections_total` |
| Relay backend failure | increase in `phx_port_relay_backend_connect_failures_total` |
| Rejected reload | increase in `phx_port_config_reloads_total{outcome="rejected"}` |
| Certificate risk | route certificate expiry state is warning or expired |

Choose alert windows from actual traffic. Do not page on a single intentional
overload rejection or planned drain.

## Add or change a route

1. Start the Workload with the shared registry, exact logical ID, and role.
2. Confirm its loopback TLS listener presents a system-trusted certificate for
   the exact hostname.
3. Create a root-owned staging ingress file in `/etc/phx-port`.
4. Validate it before publication.
5. Atomically replace the intent file.
6. Reload and require readiness.

Example:

```bash
sudo install -o root -g phx-port -m 0640 \
  ./ingress.toml /etc/phx-port/ingress.toml.next

sudo --preserve-env=PHX_PORT_CONFIG,PHX_PORT_RUNTIME_DIR \
  phx-port proxy config check \
    --file /etc/phx-port/ingress.toml.next

sudo mv /etc/phx-port/ingress.toml.next /etc/phx-port/ingress.toml

sudo --preserve-env=PHX_PORT_INGRESS_CONFIG,PHX_PORT_CONFIG,PHX_PORT_RUNTIME_DIR \
  phx-port proxy reload

phx-port proxy check --ready
phx-port proxy routes
```

An invalid reload leaves the preceding generation active. Do not edit
`routes.toml`; it is derived state.

To remove a route, remove its declaration, validate, publish, reload, verify
that it disappeared, and then stop the Workload. Keep its stable port
assignment unless you deliberately want that identity to receive a new port.

## Certificate renewal

The Workload owns DNS-01, the private key, and atomic certificate publication.
Ingress only verifies what the Workload presents.

After renewal:

```bash
journalctl -u phx-port.service --since=-15min --no-pager |
  grep 'event=certificate'
phx-port proxy status --json
phx-port proxy check --ready
```

Expect a bounded `result=rotated` event after the replacement certificate
verifies. An expired or untrusted certificate deactivates the route; a required
route then makes readiness false.

Do not copy certificate keys into ingress storage and do not disable hostname
verification to recover readiness.

## Planned restart

```bash
phx-port proxy status --json
phx-port proxy check --ready
sudo systemctl restart phx-port.service
sudo journalctl -u phx-port.service --since=-2min --no-pager
phx-port proxy check --live
phx-port proxy check --ready
```

The socket units retain TCP/443 during restart. Handed-off connections belong
to Workloads. Relays drain for up to 60 seconds and may close at the deadline.

macOS:

```bash
sudo launchctl kickstart -k system/dev.phx-port.ingress
sudo launchctl print system/dev.phx-port.ingress
phx-port proxy check --live
phx-port proxy check --ready
```

## Backup

Back up the root-owned intent and stable Port Registry with metadata and
checksums. Do not back up route cache, lock files, or runtime sockets.

Linux:

```bash
backup="/srv/backups/phx-port/$(date -u +%Y%m%dT%H%M%SZ)"
sudo install -d -o root -g root -m 0700 "$backup"
sudo flock -s /var/lib/phx-port/ports.toml.lock \
  cp --preserve=mode,ownership,timestamps \
    /var/lib/phx-port/ports.toml "$backup/ports.toml"
sudo cp --preserve=mode,ownership,timestamps \
  /etc/phx-port/ingress.toml "$backup/ingress.toml"
sudo sha256sum "$backup/ingress.toml" "$backup/ports.toml" |
  sudo tee "$backup/SHA256SUMS" >/dev/null
```

Use the complete [recovery runbook](../public-hosting-recovery-runbook.md) for
cold restore and permission verification.

## Upgrade and binary rollback

Before an upgrade:

1. Complete a backup.
2. Record current binary hash, config hash, registry hash, and health.
3. Preserve the current executable on the same filesystem.
4. Validate the candidate against current production state.
5. Replace the binary atomically and restart through the service manager.
6. Require live, ready, route, and traffic checks.

Example:

```bash
sudo cp --preserve=mode,ownership,timestamps \
  /usr/local/bin/phx-port /usr/local/bin/phx-port.previous
sudo install -o root -g root -m 0755 \
  ./phx-port /usr/local/bin/phx-port.next

sudo -u phx-port env \
  PHX_PORT_CONFIG=/var/lib/phx-port/ports.toml \
  PHX_PORT_RUNTIME_DIR=/run/phx-port \
  /usr/local/bin/phx-port.next proxy config check \
    --file /etc/phx-port/ingress.toml

sudo systemctl stop phx-port.service
sudo mv /usr/local/bin/phx-port.next /usr/local/bin/phx-port
sudo systemctl start phx-port.service
phx-port proxy check --live
phx-port proxy check --ready
```

Time rollback from the decision to healthy traffic:

```bash
sudo systemctl stop phx-port.service
sudo mv /usr/local/bin/phx-port.previous /usr/local/bin/phx-port
# Restore compatible ingress.toml and ports.toml if their schema changed.
sudo rm -f /var/lib/phx-port/routes.toml \
  /var/lib/phx-port/routes.toml.lock
sudo systemctl start phx-port.service
phx-port proxy check --live
phx-port proxy check --ready
```

On macOS, use the candidate with the installed profile paths, replace the
binary on the same filesystem, and restart the loaded LaunchDaemon:

```bash
sudo cp -p /usr/local/bin/phx-port /usr/local/bin/phx-port.previous
sudo install -o root -g wheel -m 0755 \
  ./phx-port /usr/local/bin/phx-port.next

sudo -u phx-port env \
  PHX_PORT_CONFIG="/Library/Application Support/phx-port/state/ports.toml" \
  PHX_PORT_RUNTIME_DIR=/private/var/run/phx-port \
  /usr/local/bin/phx-port.next proxy config check \
    --file "/Library/Application Support/phx-port/ingress.toml"

sudo mv /usr/local/bin/phx-port.next /usr/local/bin/phx-port
sudo launchctl kickstart -k system/dev.phx-port.ingress
phx-port proxy check --live
phx-port proxy check --ready
phx-port proxy routes
```

macOS rollback:

```bash
sudo mv /usr/local/bin/phx-port.previous /usr/local/bin/phx-port
# Restore compatible ingress.toml and ports.toml if their schema changed.
sudo rm -f \
  "/Library/Application Support/phx-port/state/routes.toml" \
  "/Library/Application Support/phx-port/state/routes.toml.lock"
sudo launchctl kickstart -k system/dev.phx-port.ingress
phx-port proxy check --live
phx-port proxy check --ready
phx-port proxy routes
```

Export the macOS `PHX_PORT_INGRESS_CONFIG`, `PHX_PORT_CONFIG`, and
`PHX_PORT_RUNTIME_DIR` values before those health commands, as described at
the start of this guide.

The release gate requires this path and an independently generated NGINX-stream
or HAProxy SNI fallback to restore the canary in under five minutes. That
public canary has not yet been completed.

## Incident triage

| Symptom | First checks | Do not |
|---|---|---|
| `ready=false` | Status degraded routes, Workload listener, SAN/chain/expiry, registry identity | Disable certificate verification |
| Unknown SNI rejected | Confirm an exact declaration and successful reload | Enable production discovery |
| PHXP success drops | Check Workload endpoint and identity; confirm relay succeeds | Delete the whole runtime root |
| Relay capacity rejects | Compare relay in-use/limit, backend health, FD and ephemeral-port pressure | Raise limits without host evidence |
| Reload rejected | Validate the staged config and inspect bounded reload event | Restart repeatedly with invalid intent |
| Registry invalid | Restore authoritative `ports.toml` backup | Reconstruct it from `routes.toml` |
| Control denied | Check profile environment, group membership, socket owner/mode | Make the socket world-writable |
| Restart hangs | Inspect relay/PHXP counters and shutdown event; wait for bounded deadline | Kill indiscriminately before recording evidence |

For destructive recovery, cold restore, service-manager preflight, and detailed
permission diagnosis, use the
[backup, recovery, and restart runbook](../public-hosting-recovery-runbook.md).

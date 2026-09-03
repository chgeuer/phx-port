# phx-port manual

Pick one mode. Do not combine their state or service setup.

| Goal | Read |
|---|---|
| Compile, test, package, or release `phx-port` | [Build and release](build.md) |
| Give local projects stable ports | [Local development](development.md) |
| Install public TLS/SNI ingress on Linux or macOS | [Public server setup](public-server.md) |
| Inspect, reload, upgrade, back up, or recover public ingress | [Inspection and operations](operations.md) |

## The mode boundary

**Development mode is the default.** It keys ports by project directory, uses
per-user files, dynamically discovers local TLS routes, and can install a user
service. The normal command is:

```bash
PORT="$(phx-port)" exec your-server
```

**Public mode is explicit.** It keys ports by logical Workload ID, routes only
declared hostnames, validates each Workload certificate, uses machine-owned
state, and runs as a dedicated service identity. It activates only through:

```bash
phx-port daemon --ingress-config /etc/phx-port/ingress.toml ...
```

or `PHX_PORT_INGRESS_CONFIG`. The file must contain:

```toml
[ingress]
mode = "public"
```

Neither root execution, `/etc/phx-port`, `PHX_PORT_CONFIG`, nor
`PHX_PORT_WORKLOAD_ID` activates public mode.

## Rules that prevent bad deployments

- Workloads terminate TLS. `phx-port` never receives their private keys.
- Public routes are exact SNI names. Unknown SNI is rejected.
- Bind Workloads to loopback. Only ingress listens publicly.
- Back up `ingress.toml` and `ports.toml`; do not back up `routes.toml` or
  runtime sockets.
- A shared production service UID is one trust domain, not tenant isolation.
- Keep TCP port 80 closed unless another service explicitly needs it.
- Do not publish DNS or open TCP/443 until preflight passes and
  `proxy check --ready` succeeds.

## Deep references

The manual contains procedures. These documents contain rationale and complete
failure semantics:

- [Public-hosting design](../public-hosting-hardening-design.md)
- [Host preflight runbook](../public-hosting-preflight-runbook.md)
- [Backup, recovery, and restart runbook](../public-hosting-recovery-runbook.md)
- [Adversarial and qualification harness](../adversarial-public-ingress-harness.md)
- [macOS socket handoff design](../macos-socket-handoff-design.md)
- [Architecture decisions](../adr/)

Public-ingress implementation and constrained-host qualification are complete.
Production promotion still requires a real publicly reachable canary, one
certificate renewal, and both rollback drills.

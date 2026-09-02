# phx-port

> Stop memorizing port numbers. One command, consistent ports for every project.

When you work on multiple web projects, they often default to the same port. `phx-port` gives each project its own stable port — automatically — so you never have collisions and never have to remember which port goes where. While originally built for [Phoenix](https://www.phoenixframework.org/), it works with any application that accepts a port via environment variable.

```bash
~/projects/my_app $ PORT=$(phx-port) iex -S mix phx.server
# → always starts on the same port, every time

~/github/livebook-dev/livebook $ LIVEBOOK_PORT=$( phx-port ) LIVEBOOK_IFRAME_PORT=$( phx-port iframe ) iex -S mix phx.server
# → The 2 ports necessary to run liveview.dev locally

~/projects/node_api $ PORT=$(phx-port) node server.js
# → works with any framework or language
```

## Install

```bash
cargo install --git https://github.com/chgeuer/phx-port
```

Or build from source:

```bash
git clone https://github.com/chgeuer/phx-port
cd phx-port
cargo build --release
cp target/release/phx-port ~/.local/bin/
```

## How it works

`phx-port` maintains a simple TOML registry at `~/.config/phx-ports.toml`.

Each project directory can have multiple named port roles (default: `main`):

```toml
[ports."/home/user/projects/my_app"]
main = 4001
debug = 4005

[ports."/home/user/projects/api_gateway"]
main = 4002

[ports."/home/user/projects/admin_dashboard"]
main = 4003
metrics = 4004
```

- **First run in a project** → allocates the next available port (starting at 4001, reusing gaps), saves it, and prints it
- **Subsequent runs** → prints the saved port instantly
- **Port 4000 stays free** for ad-hoc or unmanaged projects

Override the config location with the `PHX_PORT_CONFIG` environment variable:

```bash
export PHX_PORT_CONFIG="$HOME/.phx-ports.toml"       # Linux/macOS alternative
export PHX_PORT_CONFIG="C:\Users\me\.phx-ports.toml"  # Windows
```

## Usage

### In scripts and shell wrappers (piped mode)

When stdout is not a terminal, `phx-port` prints just the port number — perfect for command substitution:

```bash
# Default (main) port
PORT=$(phx-port) iex -S mix phx.server
PORT=$(phx-port) mix phx.server

# Named port roles — for debug, metrics, or any purpose
PORT=$(phx-port) PORT_DEBUG=$(phx-port debug) iex -S mix phx.server
PORT=$(phx-port) PORT_METRICS=$(phx-port metrics) node server.js
```

Put this in a project's `run` script and never think about ports again.

### Discovering running projects

```bash
# Show which registered projects are currently running (checks actual TCP connectivity)
phx-port running

# Open a browser page listing running projects — click one to open it
phx-port discover
```

`phx-port running` probes each registered port to check whether something is actually listening, and shows only the ones that are up:

```
$ phx-port running
  http://localhost:4001   /home/user/projects/api
  http://localhost:4003   /home/user/projects/shop
  http://localhost:4004   /home/user/projects/shop (debug)
```

`phx-port discover` starts a temporary local web server on a random free port and opens your default browser with a page listing all running projects. Each project shows its assigned localhost endpoint and any certificate-verified HTTPS hostnames discovered by the TLS daemon:

<p align="center">
  <img src="docs/discover-screenshot.png" alt="phx-port discover — browser view of running projects" width="700">
</p>

The list is rebuilt on every page load, so projects that start or stop between refreshes are always reflected. Links point directly to the target app (for example, `http://localhost:4001` and `https://www.contoso.com/`) — no redirect is involved. HTTPS links appear only when a persisted, certificate-verified route matches that live project's exact role. When you click a link, the browser navigates there naturally while a background `sendBeacon('/shutdown')` call tells the discover server to exit.

On [Omarchy](https://omarchy.com), `phx-port discover` is registered as a desktop application called **Disco**, so you can launch it directly from the app launcher (<kbd>Super</kbd>+<kbd>Space</kbd>):

<p align="center">
  <img src="docs/omarchy-super-space.png" alt="Launching Disco from the Omarchy app launcher" width="550">
</p>

### TLS/SNI proxy

The experimental daemon routes TLS connections to live registered workloads
without terminating TLS or reading their private keys:

```bash
# Workload
HTTPS_PORT="$(phx-port https)" my-https-server

# Foreground proxy; repeat --listen for additional addresses
phx-port daemon --listen 0.0.0.0:443 --listen '[::]:443'
```

The threaded daemon has explicit startup capacity options:

| Option | Default |
|---|---:|
| `--active-connections` | 256 |
| `--pre-routing-connections` | 128 |
| `--relay-connections` | 128 |
| `--handoff-negotiations` | 64 |
| `--accepts-per-second` | 200 |
| `--accept-burst` | 400 |
| `--source-accepts-per-second` | 20 |
| `--source-accept-burst` | 40 |
| `--source-pre-routing-connections` | 16 |
| `--source-ipv6-prefix` | 64 |
| `--source-table-capacity` | 4096 |
| `--source-entry-ttl-seconds` | 300 |
| `--client-hello-timeout-ms` | 2000 |

Before binding any listener, the daemon rejects zero values, sublimits above
the global connection limit, ClientHello timeouts outside 500-10000
milliseconds, arithmetic overflow, and active limits above the threaded
ceiling of 256. It also checks estimated descriptor demand against the process
`RLIMIT_NOFILE` while preserving a 30% reserve. If the process soft limit is
too low but its hard limit permits the configured capacity, startup raises
only the process soft limit to the calculated minimum and verifies the result;
the configured limits never change with the host environment. Otherwise
startup fails with the required and available values. On Linux it also checks
the systemd cgroup task ceiling and its existing occupants when available;
`--task-budget N` supplies an additional operator ceiling on any platform.

The daemon enforces the global accept-rate/burst and active, pre-routing,
relay, handoff, and per-source ceilings at runtime. IPv4 peers use exact-address
buckets; IPv6 peers use the configured prefix. Source buckets default to 20
accepts per second with burst 40 and 16 simultaneous pre-routing connections.
The expiring source table retains at most 4096 entries and evicts the
least-recent idle entry when full; if every entry is active, a new source is
rejected. Source identity comes only from the accepted socket's kernel peer
address, never SNI, headers, or public protocol bytes.

Repeat
`--source-policy CIDR=RATE,BURST,PRE_ROUTING[,IPV6_PREFIX]` to give an
operator-declared network different finite limits. The longest matching CIDR
wins, duplicate normalized CIDRs are rejected, and at most 256 overrides are
accepted. An optional fourth field changes IPv6 bucketing inside that CIDR and
must be at least as specific as the CIDR itself.

The daemon acquires active, source, and pre-routing permits immediately after
`accept` and before dispatching to a fixed worker pool whose only user-space
queue slot is also covered by those permits. Saturation closes the newly
accepted socket immediately. Handoff negotiation uses its own permit; relay
capacity is reserved before opening a backend socket, then source and
pre-routing capacity are released while the active and relay permits remain
held until encrypted copying ends. `proxy status` reports aggregate source
table use, configured limits, and bounded rejection-reason counters without
source-address labels. Saturation also emits a fixed-schema
`event=ingress_overload` stderr record at most once per bounded reason every
ten seconds. Further rejections in that window are suppressed and aggregated
into the next event; neither source addresses nor SNI values appear in the
event. Production load qualification remains a separate milestone; these
threaded bounds are not a public-load support claim.

For an unknown SNI hostname, `phx-port` probes active `https` and `main`
workloads over loopback using that exact hostname. It routes only when exactly
one backend completes a system-trusted, hostname-valid TLS handshake. The
original ClientHello is then relayed unchanged, so the backend remains the TLS
endpoint and retains its own certificate and private key.

Successful discoveries are cached in the registry as derived state and can be
inspected alongside live daemon health:

```bash
phx-port proxy status
phx-port proxy routes
phx-port proxy stop
phx-port proxy install-service
phx-port proxy uninstall-service
```

`proxy routes` uses the daemon's live route table when it is running and falls
back to persisted routes otherwise. The control socket is available only to the
current user at `$XDG_RUNTIME_DIR/phx-port/control.sock`, or under the
configuration directory when `XDG_RUNTIME_DIR` is unavailable.

On Linux, `install-service` writes
`$XDG_CONFIG_HOME/systemd/user/phx-port.service` (or
`~/.config/systemd/user/phx-port.service`), records absolute executable and
registry paths, reloads the user manager, and enables and starts the service.
The unit runs the daemon in the foreground with `Restart=on-failure`,
`LimitNOFILE=65536`, and `TasksMax=1024`. `uninstall-service` disables and
stops the service before removing the unit.

The daemon revalidates a persisted mapping before activating it in a new
process. Newly active `https` workloads that present a no-SNI default
certificate are also discovered eagerly from their exact DNS SANs; strictly
SNI-only workloads and HTTPS servers using the compatibility `main` role
continue to use lazy discovery. This avoids sending speculative TLS handshakes
to ordinary clear-HTTP `main` listeners.

On Linux and macOS, the daemon also checks the route's derived PHXP endpoint
for a version-compatible, same-user socket-handoff receiver. When present, it
passes the untouched client descriptor with `SCM_RIGHTS`; otherwise it uses
the ordinary relay:

| Platform | Control transport | Peer authentication | Default endpoint root |
|---|---|---|---|
| Linux | `AF_UNIX/SOCK_SEQPACKET` | `SO_PEERCRED` | `$XDG_RUNTIME_DIR/phx-port/handoff` |
| macOS | `AF_UNIX/SOCK_STREAM` with PHXP length framing | `getpeereid` | `/tmp/phx-port-<euid>/handoff` |

Set `PHX_PORT_RUNTIME_DIR` to use an explicit runtime root on either platform;
the endpoint is then `<runtime>/handoff/<hash>.sock`. The repository includes
a reusable Phoenix/Bandit integration and minimal Elixir and Rust reference
servers for Linux and macOS. The .NET 10 receiver remains Linux-only:

- [`integrations/elixir/phx_port_handoff`](integrations/elixir/phx_port_handoff)
- [`samples/elixir`](samples/elixir)
- [`samples/rust`](samples/rust)
- [`samples/dotnet`](samples/dotnet)

The handoff design and protocol are described in
[`docs/tls-proxy-design.md`](docs/tls-proxy-design.md) and
[`docs/socket-forwarding-design.md`](docs/socket-forwarding-design.md), with
the Darwin transport profile in
[`docs/macos-socket-handoff-design.md`](docs/macos-socket-handoff-design.md).

### macOS handoff playground

The repository includes a local playground for the Darwin handoff path. It
uses these trusted certificates directly, without copying them into the
repository:

```text
~/.dns/production/a.pollmann.rocks.{crt,key}
~/.dns/production/b.pollmann.rocks.{crt,key}
~/.dns/production/c.pollmann.rocks.{crt,key}
```

Start the Phoenix/Bandit handoff sample, the Rust/Axum handoff sample, a
relay-only OpenSSL backend, and the proxy:

```bash
just play-up
just play-status
just play-try
just play-logs daemon
just play-down
```

The proxy listens on `0.0.0.0:443` and `[::]:443`; all backend listeners stay
on loopback. `a.pollmann.rocks` uses Phoenix/Bandit handoff,
`b.pollmann.rocks` uses Rust/Axum handoff, and `c.pollmann.rocks` deliberately
has no handoff receiver so it exercises TLS relay fallback. `just play`
combines startup and the request suite.

The targets invoke the locally built `phx-port` CLI to register stable
`main`/`https` roles for `samples/elixir` and `samples/rust`, and an `https`
role for `samples/relay`. These are normal project registrations, visible in
`phx-port list`, and use `~/.config/phx-ports.toml` unless
`PHX_PORT_CONFIG` overrides it. `just play-down` stops the processes but keeps
the stable registrations.

External clients must resolve each hostname to this Mac's reachable address,
not `127.0.0.1`, and the macOS firewall and any intervening router must allow
TCP port 443. For a one-off client-side test without changing DNS:

```bash
curl --resolve a.pollmann.rocks:443:192.0.2.10 \
  https://a.pollmann.rocks/
```

Replace `192.0.2.10` with this Mac's LAN or public address. Playground logs and
PID files stay below `/tmp/phx-port-play-<uid>`; private keys remain in
`~/.dns/production`.

If those DNS names resolve to `127.0.0.1` on another machine, forward that
machine's loopback port to the Mac instead:

```bash
sudo ssh -N -o ExitOnForwardFailure=yes \
  -L 127.0.0.1:443:127.0.0.1:443 chgeuer@mini.geuer-pollmann.de
```

With that tunnel running, `curl https://a.pollmann.rocks`,
`curl https://b.pollmann.rocks`, and `curl https://c.pollmann.rocks` use the
standard HTTPS port and retain normal hostname and certificate verification.

### Managing registrations

```bash
# Show ports as a directory tree with clickable URLs (default)
phx-port list

# Flat list of all registered projects and their ports
phx-port list --flat

# Tree view with port numbers instead of URLs
phx-port list --port-only

# Explicitly register the current directory (default role: main)
phx-port register

# Register a named port role
phx-port register debug

# Remove all ports for a project — by port number, directory name, or current directory
phx-port delete 4003
phx-port delete admin_dashboard
phx-port delete .

# Remove a specific port role
phx-port delete . debug
phx-port delete admin_dashboard metrics

# Open the default browser for the current directory's port
phx-port open

# Open the browser for a named port role
phx-port open debug

# 'launch' is an alias for 'open'
phx-port launch
phx-port launch debug
```

### Interactive mode

Running `phx-port` with no arguments in a terminal shows the help text. This way it never accidentally auto-registers when you're just exploring.

## Example workflow

```
~/projects/shop $ phx-port list --flat
 4001  /home/user/projects/api
 4002  /home/user/projects/admin

~/projects/shop $ PORT=$(phx-port) iex -S mix phx.server
Registered /home/user/projects/shop → port 4003    # ← stderr, first time only
[info] Running ShopWeb.Endpoint on http://localhost:4003

~/projects/shop $ PORT=$(phx-port) PORT_DEBUG=$(phx-port debug) iex -S mix phx.server
Registered /home/user/projects/shop (debug) → port 4004    # ← new role
[info] Running ShopWeb.Endpoint on http://localhost:4003

~/projects/shop $ phx-port list --flat
 4001  /home/user/projects/api
 4002  /home/user/projects/admin
 4003  /home/user/projects/shop
 4004  /home/user/projects/shop (debug)
```

### Tree view

With many projects, the tree view (the default) gives a cleaner overview grouped by directory structure. Single-child directories are collapsed automatically, and ports are shown as clickable URLs:

```
$ phx-port list
/home/user
├── projects
│   ├── api ......... http://localhost:4001
│   ├── admin ....... http://localhost:4002
│   └── shop ........ http://localhost:4003, http://localhost:4004 (debug)
└── work/services ... http://localhost:4005
```

Add `--port-only` to show just port numbers instead of URLs:

```
$ phx-port list --port-only
/home/user
├── projects
│   ├── api ......... 4001
│   └── shop ........ 4003, 4004 (debug)
└── work/services ... 4005
```

## VS Code extension

A bundled [VS Code extension](vscode-extension/) adds two commands to the Explorer folder context menu:

- **Open in Browser (phx-port)** — looks up the port for the selected folder and opens `http://localhost:<port>` in your default browser.
- **Show Port (phx-port)** — displays the assigned port number in a notification.

### Install from source

```bash
just vscode-install    # compiles, packages, and installs the .vsix
```

Or manually:

```bash
cd vscode-extension
npm install
npm run compile
npx @vscode/vsce package --no-dependencies
code --install-extension phx-port-*.vsix
```

To uninstall:

```bash
just vscode-uninstall
```

## License

MIT

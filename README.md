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

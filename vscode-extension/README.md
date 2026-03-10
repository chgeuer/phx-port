# phx-port — VS Code Extension

Right-click any folder in the Explorer to look up or open its assigned HTTP port via [`phx-port`](https://github.com/chgeuer/phx-port).

## Features

- **Open in Browser (phx-port)** — Looks up the port for the selected folder and opens `http://localhost:<port>` in your default browser.
- **Show Port (phx-port)** — Displays the assigned port number in a notification.

Both commands appear in the Explorer folder context menu (right-click a folder).

## Prerequisites

The `phx-port` CLI must be installed and available on your `PATH`:

```bash
cargo install --git https://github.com/chgeuer/phx-port
```

## Development

```bash
cd vscode-extension
npm install
npm run compile
```

Press **F5** in VS Code to launch an Extension Development Host for testing.

## Packaging

```bash
npm run package   # produces phx-port-0.1.0.vsix
code --install-extension phx-port-0.1.0.vsix
```

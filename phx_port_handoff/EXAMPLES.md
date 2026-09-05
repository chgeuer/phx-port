# Launcher examples

Prefer a checked-in `justfile` so developers and automation use the same
commands:

```just
default: server

server:
    PORT="${PORT:-$(phx-port | cat)}" HTTPS_PORT="${HTTPS_PORT:-$(phx-port https | cat)}" mix phx.server

server-prod:
    PORT="${PORT:-$(phx-port | cat)}" HTTPS_PORT="${HTTPS_PORT:-$(phx-port https | cat)}" MIX_ENV=prod mix phx.server
```

If the project does not use `just`, apply the equivalent exports in its
existing launcher:

```bash
export PORT="${PORT:-$(phx-port | cat)}"
export HTTPS_PORT="${HTTPS_PORT:-$(phx-port https | cat)}"
MIX_ENV=prod mix phx.server
```

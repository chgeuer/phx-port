# PHXP Elixir socket-handoff sample

This is a minimal OTP application, not a Phoenix application. It starts the
same tiny Plug on three Bandit listeners:

- ordinary HTTP on `PORT`;
- ordinary HTTPS on `HTTPS_PORT`;
- handoff-only HTTPS on the PHXP Unix socket derived from the current project
  directory and role `https`.

The root `justfile` owns stable port assignment. The application only reads
`PORT` and `HTTPS_PORT`; it never invokes `phx-port`.

## Run

From the repository root, use the sample recipes:

```bash
just start-elixir
just show-elixir
```

Or run it directly with already-assigned ports:

```bash
cd samples/elixir
PORT=4100 HTTPS_PORT=4101 mix run --no-halt
```

The root `justfile` passes these certificate paths explicitly:

```text
~/.dns/production/alias-alpha.phx-port.pollmann.rocks.crt
~/.dns/production/alias-alpha.phx-port.pollmann.rocks.key
```

The Elixir source contains no certificate location or hostname. Direct
invocations must provide `--cert` and `--key`, `PHXP_TLS_CERT` and
`PHXP_TLS_KEY`, or application config keys `:tls_cert` and `:tls_key`:

```bash
PORT=4100 HTTPS_PORT=4101 mix run --no-halt -- \
  --cert /path/to/cert.pem --key /path/to/key.pem
```

`PHXP_PROJECT` and `PHXP_ROLE` (or `--project` and `--role`) override the
handoff endpoint identity. The project defaults to the current directory and
the role defaults to `https`. Linux derives the endpoint below
`$XDG_RUNTIME_DIR/phx-port/handoff`; macOS uses
`/tmp/phx-port-<euid>/handoff`. `PHX_PORT_RUNTIME_DIR` overrides the runtime
root on either platform.

Every response is `text/plain` and has this shape:

```text
phxp Elixir handoff example
listener=phxp-handoff-https
peer=127.0.0.1:54321
local=127.0.0.1:443
public_port=443
request=GET /demo?q=socket HTTP/1.1
```

The listener value is `http`, `https`, or `phxp-handoff-https`. `peer` and
`local` come from Bandit's Plug adapter, so handed-off requests retain the
original client and local socket addresses.

## Verify

```bash
mix format --check-formatted
mix test
mix compile --warnings-as-errors
```

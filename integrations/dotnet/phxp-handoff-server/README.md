# .NET 10 PHXP handoff server

This standalone Linux example exposes ordinary ASP.NET Core HTTP and HTTPS
listeners and a PHXP v1 `AF_UNIX` `SOCK_SEQPACKET` receiver. The receiver gets
the original TCP descriptor through `SCM_RIGHTS`, adopts it with
`SafeSocketHandle`/`Socket`, performs server-side TLS with `SslStream`, and
returns one HTTP/1.1 response. The response and log include the original peer
and local addresses.

The PHXP implementation follows
[`docs/socket-forwarding-design.md`](../../../docs/socket-forwarding-design.md):
`HELLO`/`READY`, one bounded `HANDOFF` packet plus exactly one descriptor, then
`ADOPTED` or `REJECTED`. It also verifies the sender UID with `SO_PEERCRED`,
uses a `0700` handoff directory and `0600` socket, validates the connected
stream descriptor, and rejects duplicate active connection IDs.

## Build

```bash
dotnet build integrations/dotnet/phxp-handoff-server/PhxpHandoffServer.csproj
```

The project targets `net10.0` and has no NuGet package dependencies.

Run the focused, dependency-free protocol tests with:

```bash
dotnet run --project integrations/dotnet/phxp-handoff-server-tests/PhxpHandoffServer.ProtocolTests.csproj
```

## Run with phx-port

Run these commands from the project directory that should own the phx-port
registration. `--project` must exactly match the canonical path shown by
`phx-port list`; the role normally must be `https`.

```bash
export HTTP_PORT="$(phx-port)"
export HTTPS_PORT="$(phx-port https)"
export PHXP_CERT_PATH=/home/chgeuer/src_work/phx_port_beta/priv/certs/production/beta.phx-port.pollmann.rocks.crt
export PHXP_KEY_PATH=/home/chgeuer/src_work/phx_port_beta/priv/certs/production/beta.phx-port.pollmann.rocks.key

dotnet run \
  --project /home/chgeuer/github/chgeuer/phx-port/integrations/dotnet/phxp-handoff-server/PhxpHandoffServer.csproj \
  -- \
  --project "$PWD" \
  --role https \
  --http-port "$HTTP_PORT" \
  --https-port "$HTTPS_PORT"
```

The certificate and private key are required through `--cert`/`--key` or
`PHXP_CERT_PATH`/`PHXP_KEY_PATH`. For an explicit CLI-only Beta invocation:

```bash
dotnet run \
  --project /home/chgeuer/github/chgeuer/phx-port/integrations/dotnet/phxp-handoff-server/PhxpHandoffServer.csproj \
  -- \
  --project "$PWD" \
  --http-port "$HTTP_PORT" \
  --https-port "$HTTPS_PORT" \
  --cert /home/chgeuer/src_work/phx_port_beta/priv/certs/production/beta.phx-port.pollmann.rocks.crt \
  --key /home/chgeuer/src_work/phx_port_beta/priv/certs/production/beta.phx-port.pollmann.rocks.key
```

Other equivalent environment variables are `PHXP_CERT_PASSWORD`, `PHXP_PROJECT`,
`PHXP_ROLE`, `PHXP_HTTP_PORT`, `PHXP_HTTPS_PORT`, and `PHXP_HANDOFF_PATH`.
`XDG_RUNTIME_DIR` is required unless the endpoint is overridden with
`--handoff-path`.

Start the phx-port daemon separately, then test all three paths:

```bash
curl http://127.0.0.1:"$HTTP_PORT"/
curl --resolve beta.phx-port.pollmann.rocks:"$HTTPS_PORT":127.0.0.1 \
  https://beta.phx-port.pollmann.rocks:"$HTTPS_PORT"/
curl --resolve beta.phx-port.pollmann.rocks:443:127.0.0.1 \
  https://beta.phx-port.pollmann.rocks/
```

The last request uses handoff when the daemon has selected this route. The
server prints the derived Unix socket path at startup.

## Focused handoff smoke test

While the server is running, copy its logged socket path and run:

```bash
python integrations/dotnet/phxp-handoff-server/test_handoff.py \
  "$XDG_RUNTIME_DIR/phx-port/handoff/<hash>.sock" \
  --sni beta.phx-port.pollmann.rocks
```

The script creates a real connected TCP pair, sends the server side over PHXP,
then performs TLS and HTTP from the client side. It verifies the `ADOPTED`
acknowledgement, response, and preserved peer address.

## Intentional limitations

- Linux x64/arm64 only; the small P/Invoke layer assumes the Linux `recvmsg`,
  `cmsghdr`, `SO_PEERCRED`, and descriptor ABI.
- The handed-off path is a compact HTTP/1.1 example, not a Kestrel transport:
  one request is read, request bodies/upgrades are not supported, and the
  connection is closed after one response. Ordinary listeners are Kestrel.
- One configured PEM certificate/key pair is used. The informational PHXP SNI
  is logged, but `SslStream` independently parses the original ClientHello.
- Accepted handoffs run as independent tasks and do not share Kestrel limits,
  middleware, routing, HTTP/2, or graceful-drain accounting.

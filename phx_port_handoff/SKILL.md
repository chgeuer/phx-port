---
name: phx-port-handoff-phoenix
description: Enables zero-relay original TCP socket handoff from phx-port ingress to Phoenix/Bandit while preserving application-owned TLS and client/server addresses. Use when adding PhxPortHandoff, PHXP socket handoff, or real TCP peer metadata to a Phoenix HTTPS project.
---

# PhxPortHandoff for Phoenix
## Preconditions

Confirm Linux or macOS, Erlang/OTP 29+, Phoenix, Bandit, and a working HTTPS
listener. Register the project with `phx-port` using the `https` role:

```bash
phx-port register https
HTTPS_PORT=$(phx-port https | cat)
```
Do not replace the ordinary HTTPS listener. Handoff adds a second,
Unix-socket-only Bandit child and reuses the endpoint's exact TLS options.

## Add the dependency

Until the package is published, add the Git dependency to `mix.exs`:
```elixir
{:phx_port_handoff,
 github: "chgeuer/phx-port",
 sparse: "phx_port_handoff"}
```
Then run:
```bash
mix deps.get
mix deps.compile phx_port_handoff
```
The package intentionally pins Rustler 0.36. Rustler 0.38 is unsupported.

## Add the handoff child

In the application supervisor, place the handoff child immediately before the
ordinary endpoint. If certificate startup is gated, place it after that gate:

```elixir
children =
  existing_children_before_endpoint() ++
    handoff_children() ++
    [MyAppWeb.Endpoint]

defp handoff_children do
  case Application.fetch_env!(:my_app, MyAppWeb.Endpoint)[:https] do
    nil -> []
    https ->
      [
        PhxPortHandoff.bandit_child_spec(
          MyAppWeb.Endpoint,
          handoff_identity(),
          "https",
          https
        )
      ]
  end
end
defp handoff_identity do
  case System.get_env("PHX_PORT_WORKLOAD_ID") do
    id when is_binary(id) and id != "" -> {:workload, id}
    _other -> File.cwd!()
  end
end
```
Replace `:my_app` and `MyAppWeb.Endpoint`. Preserve the project's actual child
list rather than introducing `existing_children_before_endpoint/0`. Returning
`[]` without HTTPS keeps development and tests working.
For local path identity, always start from the same canonical project directory
registered with `phx-port`. Hosted production must set the registry's logical
`PHX_PORT_WORKLOAD_ID`; set `PHX_PORT_RUNTIME_DIR` when using a non-default
runtime root.

## Wire stable ports

The server launcher must export both roles before Phoenix starts:
```bash
export PORT="${PORT:-$(phx-port | cat)}"
export HTTPS_PORT="${HTTPS_PORT:-$(phx-port https | cat)}"
MIX_ENV=prod mix phx.server
```
Ensure the endpoint HTTPS configuration consumes `HTTPS_PORT`. Keep the normal
HTTPS port available for discovery, health checks, and relay fallback.

## Verify real handoff

1. Start or confirm ingress with `phx-port proxy status --json`.
2. Start Phoenix and check `phx-port proxy routes` for the certificate hostname.
3. Confirm `PhxPortHandoff.endpoint_path(identity, "https")` exists as a socket.
4. Request ingress with the real SNI name:
```bash
curl --resolve "HOST:443:127.0.0.1" "https://HOST/"
```
5. Re-read `phx-port proxy status --json`. Require
   `successful_handoffs` to increase. HTTP 200 alone is insufficient because
   encrypted relay fallback can also succeed.
6. Run the project's formatter, targeted tests, and precommit command.

Use `Plug.Conn.get_peer_data/1` and `Plug.Conn.get_sock_data/1` when validating
that the original client and destination addresses survive the handoff.

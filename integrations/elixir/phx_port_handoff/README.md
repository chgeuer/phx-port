# PhxPortHandoff

`PhxPortHandoff` lets a Linux Phoenix/Bandit application accept the original
TCP sockets routed by `phx-port`. The application terminates TLS with its own
certificate configuration, sees the client's real source address, and talks
directly to the client without a byte relay.

The integration requires Linux, Erlang/OTP 29 or later, Rustler 0.36, Bandit,
and Thousand Island. Applications without this package continue to use
phx-port's generic TLS passthrough relay. Rustler 0.38 is not currently
supported because end-to-end testing exposed incompatible imported-descriptor
ownership behavior.

## Installation

Until the package is published, add it as a path dependency:

```elixir
def deps do
  [
    {:phx_port_handoff,
     path: "/path/to/phx-port/integrations/elixir/phx_port_handoff"}
  ]
end
```

## Phoenix integration

Add a handoff-only Bandit child before the ordinary Phoenix endpoint child.
Pass the endpoint's existing HTTPS options unchanged so both listeners use the
same certificate, SNI callback, ALPN, cipher, and client-authentication policy:

```elixir
def start(_type, _args) do
  project = File.cwd!()
  https = Application.fetch_env!(:my_app, MyAppWeb.Endpoint)[:https]

  children = [
    PhxPortHandoff.bandit_child_spec(MyAppWeb.Endpoint, project, "https", https),
    MyAppWeb.Endpoint
  ]

  Supervisor.start_link(children,
    strategy: :one_for_one,
    name: MyApp.Supervisor
  )
end
```

The ordinary endpoint still listens on its assigned phx-port HTTPS port for
certificate discovery, health checks, and direct access. The additional child
listens only on the convention-derived Unix socket:

```text
$XDG_RUNTIME_DIR/phx-port/handoff/
  <sha256(canonical-project-path NUL role)>.sock
```

Use the same canonical project path and role that the workload registered with
phx-port. The helper uses public port `443` in Bandit's connection metadata and
does not bind TCP port 443 itself. It configures one Thousand Island acceptor
because the current native receive path is deliberately serialized.

## Security and ownership

The native broker creates a `0600` `SOCK_SEQPACKET` endpoint in a `0700`
directory, verifies the daemon with Linux `SO_PEERCRED`, accepts exactly one
connected stream descriptor per handoff, and rejects duplicate connection
identifiers. It refuses to unlink a live receiver endpoint but replaces a
stale filesystem entry. The broker monitors its owning Thousand Island
listener process so supervisor shutdown wakes a blocked native accept and
releases the endpoint before an in-VM restart.

`phx-port` inspects ClientHello with `MSG_PEEK`; the backend's TLS stack still
reads the original bytes and performs authoritative SNI certificate selection.
After successful descriptor delivery, failures close the client connection
rather than falling back to relay.

## Current limitations

- Linux and OTP 29 are required.
- The package starts a second, handoff-only Bandit supervisor. A future hybrid
  accept broker may combine direct TCP and handed-off accepts under one
  Thousand Island server.
- One blocking native accept is used to avoid exhausting dirty I/O schedulers.
  A queued native worker is a future scalability improvement.

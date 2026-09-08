#!/usr/bin/env elixir
# A mandatory-client-authentication workload listener for the ING-Q1 matrix.
#
# Bandit and Cowboy hand their HTTPS transport options straight to OTP's :ssl,
# so an :ssl listener with `verify: :verify_peer` and `fail_if_no_peer_cert:
# true` reproduces the activation contract of a Phoenix endpoint that demands a
# client certificate, without needing the whole framework in a Rust fixture.
#
# Usage: elixir mandatory_client_auth_workload.exs <certfile> <keyfile> \
#          <cacertfile> <tlsv1.2|tlsv1.3>
#
# Writes `LISTENING <port>` once bound, then one `HANDSHAKE <n> ...` line per
# accepted connection. Runs until the parent kills it.

[certfile, keyfile, cacertfile, version] = System.argv()

versions =
  case version do
    "tlsv1.2" -> [:"tlsv1.2"]
    "tlsv1.3" -> [:"tlsv1.3"]
    other -> raise ArgumentError, "unsupported TLS version #{inspect(other)}"
  end

{:ok, _started} = Application.ensure_all_started(:ssl)

:logger.update_primary_config(%{level: :error})

{:ok, listen} =
  :ssl.listen(0, [
    :binary,
    ip: {127, 0, 0, 1},
    active: false,
    reuseaddr: true,
    backlog: 16,
    certfile: certfile,
    keyfile: keyfile,
    cacertfile: cacertfile,
    verify: :verify_peer,
    fail_if_no_peer_cert: true,
    versions: versions
  ])

{:ok, {_address, port}} = :ssl.sockname(listen)

IO.puts("OTP #{:erlang.system_info(:otp_release)} ELIXIR #{System.version()} VERSION #{version}")
IO.puts("LISTENING #{port}")

accept = fn accept, index ->
  with {:ok, transport} <- :ssl.transport_accept(listen, 30_000),
       {:ok, socket} <- :ssl.handshake(transport, 30_000) do
    IO.puts("HANDSHAKE #{index} result=accepted")
    :ssl.close(socket)
  else
    {:error, {:tls_alert, {alert, _detail}}} ->
      IO.puts("HANDSHAKE #{index} result=rejected alert=#{alert}")

    {:error, :timeout} ->
      IO.puts("HANDSHAKE #{index} result=timeout")

    {:error, reason} ->
      IO.puts("HANDSHAKE #{index} result=error reason=#{inspect(reason)}")
  end

  accept.(accept, index + 1)
end

accept.(accept, 1)

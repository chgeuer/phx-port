# Drives one HTTPS request from outside the endpoint's own VM, the way a real
# client reaches an ingress-fronted service. Prints the raw response to stdout.
#
# Running this out of process is a hard requirement, not a stylistic choice. A
# PHXP sender or client inside the endpoint's own BEAM can clear O_NONBLOCK on
# the open file description that SCM_RIGHTS shares with the receiver, after
# which inet_drv blocks in recv(2) on a normal scheduler and freezes the whole
# VM. See docs/adversarial-audit.md.
[port, cacertfile] = System.argv()
{:ok, _} = Application.ensure_all_started(:ssl)

{:ok, client} =
  :ssl.connect(
    {127, 0, 0, 1},
    String.to_integer(port),
    [
      :binary,
      active: false,
      verify: :verify_peer,
      cacertfile: String.to_charlist(cacertfile),
      server_name_indication: :disable
    ],
    10_000
  )

:ok = :ssl.send(client, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")

read = fn read, acc ->
  case :ssl.recv(client, 0, 10_000) do
    {:ok, data} -> read.(read, acc <> data)
    {:error, :closed} -> acc
    {:error, reason} -> acc <> "READ ERROR: #{inspect(reason)}"
  end
end

IO.write(read.(read, ""))

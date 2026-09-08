# Drives one HTTPS request from outside the endpoint's own VM, the way a real
# client reaches an ingress-fronted service. Prints the raw response to stdout.
#
# Moving this client is not sufficient: the PHXP sender must run outside the
# receiving VM too. The sender, not the TCP peer, shares the imported open file
# description and can clear O_NONBLOCK after import. See docs/adversarial-audit.md.
[port, cacertfile] = System.argv()
{:ok, _} = Application.ensure_all_started(:ssl)
IO.puts("READY #{System.pid()}")

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

try do
  :ok = :ssl.send(client, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")

  read = fn read, acc ->
    case :ssl.recv(client, 0, 10_000) do
      {:ok, data} when byte_size(acc) + byte_size(data) <= 65_536 ->
        read.(read, acc <> data)

      {:ok, _data} ->
        raise "TLS response exceeded 64 KiB"

      {:error, :closed} ->
        acc

      {:error, reason} ->
        raise "TLS read failed: #{inspect(reason)}"
    end
  end

  IO.write(read.(read, ""))
after
  :ssl.close(client)
end

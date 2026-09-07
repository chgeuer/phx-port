defmodule PhxPortHandoff.TransportTest do
  use ExUnit.Case, async: false

  alias PhxPortHandoff.Transport

  # A TLS record header announcing a 512 byte ClientHello, followed by two bytes
  # of it. A peer that stops here is indistinguishable from a slow client until
  # the handshake deadline fires.
  @truncated_client_hello <<0x16, 0x03, 0x01, 512::16, 0x01, 0x00>>

  defmodule Endpoint do
    def init(options), do: options
    def call(conn, _options), do: Plug.Conn.send_resp(conn, 200, "handoff")
  end

  # Minimal PHXP ingress: binds a throwaway TCP listener, accepts one
  # connection, and hands its descriptor to a local PHXP endpoint.
  defmodule Sender do
    def listen do
      {:ok, listener} = :socket.open(:inet, :stream, :tcp)
      :ok = :socket.bind(listener, %{family: :inet, addr: {127, 0, 0, 1}, port: 0})
      :ok = :socket.listen(listener)
      {:ok, %{port: port}} = :socket.sockname(listener)
      {listener, port}
    end

    def hand_off(listener, path) do
      {:ok, accepted} = :socket.accept(listener, 10_000)

      try do
        transfer(accepted, path)
      after
        :socket.close(accepted)
      end
    end

    defp transfer(accepted, path) do
      {:ok, fd} = :socket.getopt(accepted, :otp, :fd)
      type = if :os.type() == {:unix, :linux}, do: :seqpacket, else: :stream
      {:ok, control} = :socket.open(:local, type, :default)

      try do
        :ok = :socket.connect(control, %{family: :local, path: path}, 2_000)
        :ok = :socket.send(control, frame(1), 2_000)
        {:ok, ready} = :socket.recv(control, 40, 2_000)
        true = ready == frame(2)
        id = <<System.unique_integer([:positive])::128>>

        :ok =
          :socket.sendmsg(
            control,
            %{
              iov: [frame(3, id, "localhost")],
              ctrl: [%{level: :socket, type: :rights, data: <<fd::native-signed-32>>}]
            },
            2_000
          )

        {:ok, adopted} = :socket.recv(control, 40, 2_000)
        true = adopted == frame(4, id)
        :ok
      after
        :socket.close(control)
      end
    end

    defp frame(type, id \\ <<0::128>>, sni \\ "") do
      <<"PHXP", 1, type, 0::16, id::binary-size(16), 0::32, 0::64, byte_size(sni)::16, 0::16,
        sni::binary>>
    end
  end

  setup_all do
    tls =
      :public_key.pkix_test_data(%{
        root: [key: {:rsa, 2048, 65_537}],
        peer: [key: {:rsa, 2048, 65_537}]
      })

    %{tls: tls}
  end

  @tag timeout: 45_000
  test "configured endpoint resolves TLS files relative to its OTP application", %{tls: tls} do
    runtime = temporary_directory()
    previous_runtime = System.get_env("PHX_PORT_RUNTIME_DIR")
    System.put_env("PHX_PORT_RUNTIME_DIR", runtime)

    relative_directory = "priv/handoff-test-#{:os.getpid()}-#{System.unique_integer([:positive])}"
    certificate_directory = Application.app_dir(:phx_port_handoff, relative_directory)
    File.mkdir!(certificate_directory)
    File.chmod!(certificate_directory, 0o700)
    {key_type, key} = Keyword.fetch!(tls, :key)

    File.write!(
      Path.join(certificate_directory, "key.pem"),
      :public_key.pem_encode([{key_type, key, :not_encrypted}])
    )

    File.write!(
      Path.join(certificate_directory, "cert.pem"),
      :public_key.pem_encode([{:Certificate, Keyword.fetch!(tls, :cert), :not_encrypted}])
    )

    Application.put_env(:phx_port_handoff, Endpoint,
      https: [
        keyfile: Path.join(relative_directory, "key.pem"),
        certfile: Path.join(relative_directory, "cert.pem")
      ]
    )

    on_exit(fn ->
      Application.delete_env(:phx_port_handoff, Endpoint)
      File.rm_rf!(certificate_directory)

      if previous_runtime,
        do: System.put_env("PHX_PORT_RUNTIME_DIR", previous_runtime),
        else: System.delete_env("PHX_PORT_RUNTIME_DIR")
    end)

    start_supervised!(
      {PhxPortHandoff,
       otp_app: :phx_port_handoff, endpoint: Endpoint, identity: {:workload, "relative-tls-test"}}
    )

    assert File.exists?(PhxPortHandoff.endpoint_path({:workload, "relative-tls-test"}, "https"))

    # Proves the relative certfile and keyfile were resolved and actually
    # served, and that :otp_app never leaks into the server-side TLS options.
    path = PhxPortHandoff.endpoint_path({:workload, "relative-tls-test"}, "https")
    assert handoff_request(path, tls) =~ "200 OK"
  end

  test "handshake deadline defaults to five seconds and rejects unbounded values" do
    assert %Transport{}.handshake_timeout == 5_000

    for invalid <- [:infinity, 0, -1, nil, 1.5] do
      assert {:error, {:invalid_handshake_timeout, ^invalid}} =
               Transport.listen(443,
                 handoff_path: Path.join(temporary_directory(), "handoff.sock"),
                 handshake_timeout: invalid
               )
    end
  end

  @tag timeout: 30_000
  test "a stalled peer cannot hold an imported socket past the handshake deadline", %{tls: tls} do
    {listener, port, sender, server} = start_handoff([handshake_timeout: 250] ++ tls)

    {:ok, client} =
      :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false, nodelay: true], 5_000)

    try do
      :ok = :gen_tcp.send(client, @truncated_client_hello)

      assert {:ok, outcome} = Task.yield(server, 20_000)
      assert outcome.accepted_timeout == 250
      assert outcome.result == {:error, :timeout}
      assert outcome.elapsed < 5_000
      assert outcome.closed?
    after
      :gen_tcp.close(client)
      Transport.close(listener)
      Task.shutdown(sender)
      Task.shutdown(server)
    end
  end

  defp start_handoff(listen_options) do
    path = Path.join(temporary_directory(), "handoff.sock")
    {:ok, listener} = Transport.listen(443, [handoff_path: path] ++ listen_options)
    {ingress, port} = Sender.listen()
    on_exit(fn -> :socket.close(ingress) end)

    server =
      Task.async(fn ->
        {:ok, raw} = Transport.accept(listener)
        :ok = Transport.controlling_process(raw, self())
        started = System.monotonic_time(:millisecond)
        result = Transport.handshake(raw)

        %{
          accepted_timeout: raw.handshake_timeout,
          result: result,
          elapsed: System.monotonic_time(:millisecond) - started,
          closed?: :erlang.port_info(raw.socket) == :undefined
        }
      end)

    sender = Task.async(fn -> Sender.hand_off(ingress, path) end)

    {listener, port, sender, server}
  end

  # Drives one connection through the full ingress path: a client connects to a
  # throwaway TCP listener, PHXP hands that descriptor to the endpoint, and the
  # handed-off socket must serve a complete HTTPS request.
  # Drives one connection through the full ingress path: a client outside this
  # VM connects to a throwaway TCP listener, PHXP hands that descriptor to the
  # endpoint, and the handed-off socket must serve a complete HTTPS request.
  defp handoff_request(path, tls) do
    {ingress, port} = Sender.listen()
    cacertfile = certificate_authority_file(tls)
    sender = Task.async(fn -> Sender.hand_off(ingress, path) end)
    client = Task.async(fn -> request(port, cacertfile) end)

    try do
      assert :ok = Task.await(sender, 15_000)
      Task.await(client, 25_000)
    after
      :socket.close(ingress)
    end
  end

  defp request(port, cacertfile) do
    script = Path.expand("support/tls_client.exs", __DIR__)

    {output, status} =
      System.cmd("elixir", [script, Integer.to_string(port), cacertfile], stderr_to_stdout: true)

    assert status == 0, "the out-of-VM TLS client failed:\n#{output}"
    output
  end

  defp certificate_authority_file(tls) do
    path = Path.join(temporary_directory(), "ca.pem")

    File.write!(
      path,
      Enum.map_join(Keyword.fetch!(tls, :cacerts), fn certificate ->
        :public_key.pem_encode([{:Certificate, certificate, :not_encrypted}])
      end)
    )

    path
  end

  defp temporary_directory do
    path = Path.join("/tmp", "phxp-#{:os.getpid()}-#{System.unique_integer([:positive])}")
    File.mkdir!(path)
    File.chmod!(path, 0o700)
    on_exit(fn -> File.rm_rf!(path) end)
    path
  end
end

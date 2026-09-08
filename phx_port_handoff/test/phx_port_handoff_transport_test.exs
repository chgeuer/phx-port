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

  setup_all do
    tls =
      :public_key.pkix_test_data(%{
        root: [key: {:rsa, 2048, 65_537}],
        peer: [key: {:rsa, 2048, 65_537}]
      })

    %{tls: tls}
  end

  @tag :sender_topology
  test "the receiving VM does not run the PHXP descriptor sender" do
    {_source, in_vm_sends} =
      __ENV__.file
      |> File.read!()
      |> Code.string_to_quoted!()
      |> Macro.prewalk([], fn
        {{:., _, [:socket, :sendmsg]}, metadata, _} = node, calls ->
          {node, [Keyword.fetch!(metadata, :line) | calls]}

        node, calls ->
          {node, calls}
      end)

    assert in_vm_sends == [],
           "PHXP sendmsg must run outside the receiving VM; in-VM calls at #{inspect(in_vm_sends, charlists: :as_lists)}"
  end

  @tag :sender_topology
  test "a failed fixture callback terminates and reaps its external sender" do
    reference = make_ref()
    path = Path.join(temporary_directory(), "unused.sock")

    assert_raise RuntimeError, "fixture callback failed", fn ->
      with_sender(path, fn sender, _port ->
        send(self(), {reference, sender})
        raise "fixture callback failed"
      end)
    end

    assert_receive {^reference, sender}
    assert Port.info(sender) == nil
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
    {listener, path, server} = start_handoff([handshake_timeout: 250] ++ tls)

    try do
      with_sender(path, fn sender, port ->
        {:ok, client} =
          :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false, nodelay: true], 5_000)

        try do
          :ok = :gen_tcp.send(client, @truncated_client_hello)
          assert finish_child(sender) == "ADOPTED\n"

          assert {:ok, outcome} = Task.yield(server, 20_000)
          assert outcome.accepted_timeout == 250
          assert outcome.result == {:error, :timeout}
          assert outcome.elapsed < 5_000
          assert outcome.closed?
          assert {:error, :closed} = :gen_tcp.recv(client, 0, 5_000)
        after
          :gen_tcp.close(client)
        end
      end)
    after
      Transport.close(listener)
      Task.shutdown(server)
    end
  end

  defp start_handoff(listen_options) do
    path = Path.join(temporary_directory(), "handoff.sock")
    {:ok, listener} = Transport.listen(443, [handoff_path: path] ++ listen_options)

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

    {listener, path, server}
  end

  # The sender, not the TCP peer, shares the imported open file description.
  # Keep it outside this VM and never change its O_NONBLOCK flags after delivery.
  defp handoff_request(path, tls) do
    cacertfile = certificate_authority_file(tls)
    script = Path.expand("support/tls_client.exs", __DIR__)

    with_sender(path, fn sender, port ->
      with_child(
        "elixir",
        ["--erl", "+S 2:2", script, Integer.to_string(port), cacertfile],
        fn client, os_pid ->
          assert read_child_line(client) == "READY #{os_pid}"
          assert finish_child(sender) == "ADOPTED\n"
          finish_child(client)
        end
      )
    end)
  end

  defp with_sender(path, callback) do
    script = Path.expand("support/phxp_sender.py", __DIR__)

    with_child("python3", [script], fn sender, os_pid ->
      expected_pid = Integer.to_string(os_pid)
      assert ["READY", ^expected_pid, port] = String.split(read_child_line(sender))
      port = String.to_integer(port)
      assert port in 1..65_535
      assert Port.command(sender, path <> "\n")
      callback.(sender, port)
    end)
  end

  defp with_child(executable, arguments, callback) do
    executable =
      System.find_executable(executable) || flunk("missing fixture tool: #{executable}")

    child =
      Port.open({:spawn_executable, executable}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        {:line, 4_096},
        args: arguments
      ])

    {:os_pid, os_pid} = Port.info(child, :os_pid)

    try do
      refute Integer.to_string(os_pid) == System.pid(),
             "the fixture must run outside the receiving BEAM VM"

      callback.(child, os_pid)
    after
      case Port.info(child, :os_pid) do
        nil ->
          :ok

        {:os_pid, ^os_pid} ->
          {output, status} =
            System.cmd("kill", ["-KILL", Integer.to_string(os_pid)], stderr_to_stdout: true)

          # The child may have exited just before kill; its exit notification
          # is the cleanup proof in either case, not kill's status alone.
          assert_receive {^child, {:exit_status, _}},
                         5_000,
                         "fixture #{os_pid} was not reaped (kill status #{status}): #{output}"
      end
    end
  end

  defp read_child_line(child) do
    receive do
      {^child, {:data, {:eol, line}}} ->
        line

      {^child, event} ->
        flunk("fixture did not report readiness: #{inspect(event)}")
    after
      10_000 -> flunk("fixture startup timed out")
    end
  end

  defp finish_child(child) do
    {output, status} = collect_child(child, System.monotonic_time(:millisecond) + 15_000, "")
    assert status == 0, "fixture exited with status #{status}:\n#{output}"
    output
  end

  defp collect_child(child, deadline, output) do
    remaining = max(deadline - System.monotonic_time(:millisecond), 0)

    receive do
      {^child, {:data, {ending, data}}} when ending in [:eol, :noeol] ->
        output = output <> data <> if(ending == :eol, do: "\n", else: "")
        assert byte_size(output) <= 65_536, "fixture output exceeded 64 KiB"
        collect_child(child, deadline, output)

      {^child, {:exit_status, status}} ->
        {output, status}
    after
      remaining -> flunk("fixture completion timed out:\n#{output}")
    end
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

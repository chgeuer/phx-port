defmodule PhxPortHandoff.Evidence.SchedulerProbe do
  @moduledoc false
  @window_ms 3_000
  @tick_ms 50

  defmodule Failure do
    defexception [:reason]
    def message(error), do: "inconclusive scheduler evidence: #{inspect(error.reason)}"
  end

  defmodule Endpoint do
    def init(options), do: options
    def call(conn, _options), do: Plug.Conn.send_resp(conn, 200, "ok")
  end

  def main(mode, arguments) do
    directory =
      System.get_env("PHXP_PROBE_DIRECTORY") ||
        Path.join(System.tmp_dir!(), "pe-" <> Base.encode16(:crypto.strong_rand_bytes(6)))

    File.mkdir!(directory)
    File.chmod!(directory, 0o700)
    IO.puts("PROBE_DIRECTORY #{directory}")

    {verdict, details, status} =
      try do
        {count, blocking} = arguments!(arguments)
        evidence = run(mode, count, blocking, directory)
        verdict = if evidence.ticks < 10, do: :SCHEDULERS_STARVED, else: :schedulers_healthy
        {verdict, inspect(evidence), if(verdict == :schedulers_healthy, do: 0, else: 1)}
      rescue
        error in Failure -> {:inconclusive, inspect(error.reason), 2}
      end

    result = "VERDICT #{verdict} #{details}\n"
    File.write!(Path.join(directory, "verdict"), result)
    IO.write(result)
    if status != 0, do: System.halt(status)
  end

  defp arguments!([count, blocking]) when blocking in ["0", "1"] do
    case Integer.parse(count) do
      {count, ""} when count in 1..64 -> {count, blocking}
      _ -> fail!({:invalid_count, :expected_1_through_64})
    end
  end

  defp arguments!(_arguments), do: fail!({:usage, "<count:1..64> <blocking:0|1>"})

  defp run(mode, count, blocking, directory) do
    tls =
      :public_key.pkix_test_data(%{
        root: [key: {:rsa, 2048, 65_537}],
        peer: [
          key: {:rsa, 2048, 65_537},
          extensions: [{:Extension, {2, 5, 29, 17}, false, [{:dNSName, ~c"localhost"}]}]
        ]
      })

    previous_runtime = System.get_env("PHX_PORT_RUNTIME_DIR")
    System.put_env("PHX_PORT_RUNTIME_DIR", directory)
    reference = make_ref()

    # Each probe owns the only listener in a fresh VM. Its connection events
    # independently confirm the population instead of trusting sender counters.
    :ok =
      :telemetry.attach_many(
        reference,
        [[:thousand_island, :connection, :start], [:thousand_island, :connection, :stop]],
        &__MODULE__.connection_event/4,
        {self(), reference}
      )

    try do
      identity = {:workload, "scheduler-probe"}

      child =
        PhxPortHandoff.bandit_child_spec(Endpoint, identity, "https",
          thousand_island_options: [transport_options: tls]
        )

      case Supervisor.start_link([child], strategy: :one_for_one) do
        {:ok, supervisor} ->
          try do
            path = PhxPortHandoff.endpoint_path(identity, "https")

            File.open!(Path.join(directory, "sender.log"), [:write], fn log ->
              with_sender(mode, path, count, blocking, log, fn sender, port ->
                with_clients(mode, port, count, [], fn clients ->
                  await_adoptions(sender, count)
                  expect_line(sender, "HOLDING #{count}", :holding)
                  population = await_population(reference, count, MapSet.new(), now() + 2_000)

                  with_tls(mode, clients, tls, fn clients ->
                    evidence = measure(sender, clients, reference, population, count)
                    command!(sender, "STOP")
                    expect_line(sender, "STOPPED", :completion)
                    await_exit(sender)

                    Map.merge(evidence, %{
                      mode: mode,
                      normal_schedulers: :erlang.system_info(:schedulers_online),
                      sender_blocking: blocking == "1",
                      adopted: count,
                      receiver_started: count,
                      sender_exit: 0
                    })
                  end)
                end)
              end)
            end)
          after
            Supervisor.stop(supervisor, :normal, 5_000)
          end

        {:error, reason} ->
          fail!({:workload_start, reason})
      end
    after
      :telemetry.detach(reference)

      if previous_runtime,
        do: System.put_env("PHX_PORT_RUNTIME_DIR", previous_runtime),
        else: System.delete_env("PHX_PORT_RUNTIME_DIR")

      File.rm_rf!(Path.join(directory, "handoff"))
    end
  end

  def connection_event([:thousand_island, :connection, event], _measurements, metadata, config) do
    {owner, reference} = config
    send(owner, {reference, event, metadata.telemetry_span_context})
  end

  defp with_sender(mode, path, count, blocking, log, callback) do
    filename = if mode == :out_of_vm, do: "stalled_handoff_sender.py", else: "invm_peer_sender.py"
    script = Path.join(__DIR__, filename)

    case File.stat(script) do
      {:ok, %File.Stat{type: :regular}} -> :ok
      {:error, :enoent} -> fail!(:missing_sender)
      other -> fail!({:sender_file, other})
    end

    python = System.find_executable("python3") || fail!(:missing_python)

    child =
      Port.open({:spawn_executable, python}, [
        :binary,
        :exit_status,
        :stderr_to_stdout,
        {:line, 1_024},
        env: [{~c"PYTHONDONTWRITEBYTECODE", ~c"1"}],
        args: [script, path, Integer.to_string(count), blocking, "20"]
      ])

    {:os_pid, pid} = Port.info(child, :os_pid)
    IO.puts("SENDER_PID #{pid}")
    sender = {child, log}

    try do
      if Integer.to_string(pid) == System.pid(), do: fail!(:in_vm_sender)
      expected_pid = Integer.to_string(pid)

      case String.split(read_line(sender, now() + 2_000, :startup)) do
        ["READY", ^expected_pid, port] ->
          case Integer.parse(port) do
            {port, ""} when port in 1..65_535 -> callback.(sender, port)
            _ -> fail!(:invalid_sender_port)
          end

        _ ->
          fail!(:invalid_sender_identity_or_readiness)
      end
    after
      reap(child, pid)
    end
  end

  defp with_clients(:out_of_vm, _port, _remaining, [], callback), do: callback.([])
  defp with_clients(_mode, _port, 0, clients, callback), do: callback.(Enum.reverse(clients))

  defp with_clients(mode, port, remaining, clients, callback) do
    case :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 2_000) do
      {:ok, client} ->
        try do
          with_clients(mode, port, remaining - 1, [{:gen_tcp, client} | clients], callback)
        after
          :gen_tcp.close(client)
        end

      {:error, reason} ->
        fail!({:peer_connect, reason})
    end
  end

  defp with_tls(:in_vm_tls, clients, tls, callback),
    do: upgrade_clients(clients, tls, [], callback)

  defp with_tls(_mode, clients, _tls, callback), do: callback.(clients)

  defp upgrade_clients([], _tls, clients, callback), do: callback.(Enum.reverse(clients))

  defp upgrade_clients([{:gen_tcp, tcp} | rest], tls, clients, callback) do
    options = [
      :binary,
      active: false,
      verify: :verify_peer,
      cacerts: Keyword.fetch!(tls, :cacerts),
      server_name_indication: ~c"localhost"
    ]

    case :ssl.connect(tcp, options, 2_000) do
      {:ok, client} ->
        try do
          upgrade_clients(rest, tls, [{:ssl, client} | clients], callback)
        after
          :ssl.close(client)
        end

      {:error, reason} ->
        fail!({:peer_tls_handshake, reason})
    end
  end

  defp await_adoptions(sender, count) do
    deadline = now() + 5_000

    for index <- 1..count do
      expected = "ADOPTED #{index}"
      stage = {:adoptions, index - 1, :expected, count}
      if read_line(sender, deadline, stage) != expected, do: fail!(stage)
    end
  end

  defp await_population(reference, count, population, deadline) do
    if MapSet.size(population) > count, do: fail!(:unexpected_receiver_population)

    if MapSet.size(population) == count do
      population
    else
      receive do
        {^reference, :start, connection} ->
          await_population(reference, count, MapSet.put(population, connection), deadline)

        {^reference, :stop, _connection} ->
          fail!(:premature_socket_close)
      after
        max(deadline - now(), 0) ->
          fail!({:receiver_population, MapSet.size(population), :expected, count})
      end
    end
  end

  defp measure(sender, clients, reference, population, count) do
    parent = self()
    tick_ref = make_ref()
    {heartbeat, monitor} = spawn_monitor(fn -> ticker(parent, tick_ref) end)
    started = now()

    try do
      samples = sample(sender, clients, reference, population, count, started + @window_ms, 0)
      %{ticks: collect_ticks(tick_ref, 0), live_samples: samples, window_ms: now() - started}
    after
      Process.exit(heartbeat, :kill)

      receive do
        {:DOWN, ^monitor, :process, ^heartbeat, _reason} -> :ok
      after
        1_000 -> fail!(:heartbeat_cleanup_failed)
      end
    end
  end

  defp sample(sender, clients, reference, population, count, deadline, sequence) do
    command!(sender, "CHECK #{sequence}")
    expect_line(sender, "CHECKED #{sequence}", :live_population)

    for {transport, client} <- clients do
      case transport.recv(client, 0, 0) do
        {:error, :timeout} -> :ok
        other -> fail!({:premature_socket_close_or_data, other})
      end
    end

    check_population(reference, population, count)
    remaining = deadline - now()

    if remaining <= 0 do
      sequence + 1
    else
      Process.sleep(min(@tick_ms, remaining))
      sample(sender, clients, reference, population, count, deadline, sequence + 1)
    end
  end

  defp check_population(reference, population, count) do
    if MapSet.size(population) != count, do: fail!(:insufficient_receiver_population)

    receive do
      {^reference, :stop, _connection} -> fail!(:premature_socket_close)
      {^reference, :start, _connection} -> fail!(:unexpected_receiver_population)
    after
      0 -> :ok
    end
  end

  defp ticker(parent, reference) do
    Process.sleep(@tick_ms)
    send(parent, {reference, :tick})
    ticker(parent, reference)
  end

  defp collect_ticks(reference, count) do
    receive do
      {^reference, :tick} -> collect_ticks(reference, count + 1)
    after
      0 -> count
    end
  end

  defp command!({child, _log}, line) do
    try do
      if not Port.command(child, line <> "\n"), do: fail!(:sender_write_failed)
    rescue
      ArgumentError -> fail!(:sender_closed)
    end
  end

  defp expect_line(sender, expected, stage) do
    if read_line(sender, now() + 2_000, stage) != expected, do: fail!({:sender_protocol, stage})
  end

  defp read_line({child, log}, deadline, stage) do
    receive do
      {^child, {:data, {:eol, line}}} ->
        :ok = IO.binwrite(log, line <> "\n")
        line

      {^child, {:data, {:noeol, _line}}} ->
        fail!(:sender_output_line_too_long)

      {^child, {:exit_status, status}} ->
        fail!({:sender_exit, status, stage})
    after
      max(deadline - now(), 0) -> fail!({:sender_timeout, stage})
    end
  end

  defp await_exit({child, log}) do
    receive do
      {^child, {:exit_status, 0}} -> :ok
      {^child, {:exit_status, status}} -> fail!({:sender_exit, status, :completion})
      {^child, {:data, _data}} -> fail!(:unexpected_sender_output_after_completion)
    after
      2_000 ->
        :ok = IO.binwrite(log, "sender completion timed out\n")
        fail!({:sender_timeout, :completion})
    end
  end

  defp reap(child, pid) do
    case Port.info(child, :os_pid) do
      nil ->
        :ok

      {:os_pid, ^pid} ->
        {output, status} =
          System.cmd("kill", ["-KILL", Integer.to_string(pid)], stderr_to_stdout: true)

        receive do
          {^child, {:exit_status, _status}} -> :ok
        after
          5_000 -> fail!({:sender_cleanup_failed, pid, status, output})
        end
    end
  end

  defp now, do: System.monotonic_time(:millisecond)
  defp fail!(reason), do: raise(Failure, reason: reason)
end

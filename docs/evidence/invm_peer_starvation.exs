# Production-faithful scheduler-starvation probe.
#
# The PHXP sender is a separate OS process (as a real ingress is), so nothing in
# this VM can influence the handed-off descriptor. It reports whether normal BEAM
# scheduler threads keep running while stalled clients hold imported sockets.
#
#   MIX_ENV=test ELIXIR_ERL_OPTIONS="+S 2:2" mix run out_of_vm_starvation.exs <count> <blocking:0|1>

defmodule Probe.Endpoint do
  def init(options), do: options
  def call(conn, _options), do: Plug.Conn.send_resp(conn, 200, "ok")
end

defmodule Probe do
  def say(message), do: :erlang.display({:probe, message})

  def run(count, blocking) do
    schedulers = :erlang.system_info(:schedulers_online)
    say({:normal_schedulers, schedulers, :stalled_clients, count, :sender_blocking, blocking})

    tls =
      :public_key.pkix_test_data(%{
        root: [key: {:rsa, 2048, 65_537}],
        peer: [key: {:rsa, 2048, 65_537}]
      })

    runtime = Path.join("/tmp", "phxp-oov-#{:os.getpid()}")
    File.rm_rf!(runtime)
    File.mkdir_p!(runtime)
    File.chmod!(runtime, 0o700)
    System.put_env("PHX_PORT_RUNTIME_DIR", runtime)

    relative = "priv/oov-#{:os.getpid()}"
    directory = Application.app_dir(:phx_port_handoff, relative)
    File.rm_rf!(directory)
    File.mkdir_p!(directory)
    {key_type, key} = Keyword.fetch!(tls, :key)

    File.write!(
      Path.join(directory, "key.pem"),
      :public_key.pem_encode([{key_type, key, :not_encrypted}])
    )

    File.write!(
      Path.join(directory, "cert.pem"),
      :public_key.pem_encode([{:Certificate, Keyword.fetch!(tls, :cert), :not_encrypted}])
    )

    Application.put_env(:phx_port_handoff, Probe.Endpoint,
      https: [
        keyfile: Path.join(relative, "key.pem"),
        certfile: Path.join(relative, "cert.pem")
      ]
    )

    identity = {:workload, "oov-#{System.unique_integer([:positive])}"}

    {:ok, _supervisor} =
      Supervisor.start_link(
        [{PhxPortHandoff, otp_app: :phx_port_handoff, endpoint: Probe.Endpoint, identity: identity}],
        strategy: :one_for_one
      )

    path = PhxPortHandoff.endpoint_path(identity, "https")
    say({:endpoint_ready, path})

    parent = self()
    heartbeat = spawn(fn -> ticker(parent) end)
    Process.sleep(300)

    sender = Path.expand("invm_peer_sender.py", __DIR__)

    port =
      Port.open({:spawn_executable, "/bin/sh"}, [
        :binary,
        :exit_status,
        args: [
          "-c",
          "python3 #{sender} #{path} #{count} #{blocking} 30 > /tmp/oov-sender.log 2>&1"
        ]
      ])

    say(:sender_started)

    port_number = await_port()
    say({:sender_listening_on, port_number})

    # In-VM stalled clients: connect from this BEAM, then send nothing.
    clients =
      Enum.map(1..count, fn _ ->
        {:ok, socket} = :gen_tcp.connect({127, 0, 0, 1}, port_number, [:binary, active: false])
        socket
      end)

    say({:in_vm_clients_connected, length(clients)})
    Process.sleep(1_500)

    _ = collect_ticks()
    Process.sleep(3_000)
    ticks = collect_ticks()

    # The heartbeat sleeps 50ms per tick, so ~60 ticks are possible in 3s.
    # Anything near zero means normal schedulers are pinned.
    verdict = if ticks < 10, do: :SCHEDULERS_STARVED, else: :schedulers_healthy
    say({:verdict, verdict, :ticks_in_3s, ticks})
    File.write!("/tmp/oov-verdict", "#{verdict} ticks=#{ticks}\n")

    Process.exit(heartbeat, :kill)
    Port.close(port)
    say(:done)
  end

  defp await_port(deadline \\ nil) do
    deadline = deadline || System.monotonic_time(:millisecond) + 15_000

    case File.read("/tmp/oov-sender.log") do
      {:ok, data} ->
        case Regex.run(~r/PORT (\d+)/, data) do
          [_, port] ->
            String.to_integer(port)

          _ ->
            if System.monotonic_time(:millisecond) > deadline,
              do: raise("sender never reported a port"),
              else: (Process.sleep(100); await_port(deadline))
        end

      _ ->
        if System.monotonic_time(:millisecond) > deadline,
          do: raise("sender never started"),
          else: (Process.sleep(100); await_port(deadline))
    end
  end

  defp ticker(parent) do
    send(parent, :tick)
    Process.sleep(50)
    ticker(parent)
  end

  defp collect_ticks(acc \\ 0) do
    receive do
      :tick -> collect_ticks(acc + 1)
    after
      0 -> acc
    end
  end
end

[count, blocking] = System.argv()
Probe.run(String.to_integer(count), blocking)

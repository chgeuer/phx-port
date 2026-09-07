# Reproduces the VM-wide BEAM freeze observed while building the handoff
# end-to-end test: a TLS *client* driven from inside the same VM as the
# handoff server. Progress is printed with :erlang.display/1 because it still
# reaches stderr from the emulator when the IO system itself is wedged.
#
#   mix run freeze_repro.exs <iterations>

defmodule Repro.Endpoint do
  def init(options), do: options
  def call(conn, _options), do: Plug.Conn.send_resp(conn, 200, "ok")
end

defmodule Repro.Sender do
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

defmodule Repro do
  def say(message), do: :erlang.display({:repro, message})

  def run(iterations) do
    File.write!("/tmp/freeze-repro.pid", :os.getpid())
    say({:pid, :os.getpid(), :otp, :erlang.system_info(:otp_release)})

    tls =
      :public_key.pkix_test_data(%{
        root: [key: {:rsa, 2048, 65_537}],
        peer: [key: {:rsa, 2048, 65_537}]
      })

    runtime = Path.join("/tmp", "phxp-freeze-#{:os.getpid()}")
    File.rm_rf!(runtime)
    File.mkdir_p!(runtime)
    File.chmod!(runtime, 0o700)
    System.put_env("PHX_PORT_RUNTIME_DIR", runtime)

    relative = "priv/freeze-#{:os.getpid()}"
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

    cacerts = Keyword.fetch!(tls, :cacerts)

    Application.put_env(:phx_port_handoff, Repro.Endpoint,
      https: [
        keyfile: Path.join(relative, "key.pem"),
        certfile: Path.join(relative, "cert.pem")
      ]
    )

    Enum.each(1..iterations, fn attempt ->
      say({:iteration, attempt})
      iterate(cacerts)
      say({:iteration_done, attempt})
    end)

    say(:all_done)
    File.write!("/tmp/freeze-repro.done", "ok")
  end

  defp iterate(cacerts) do
    identity = {:workload, "freeze-#{System.unique_integer([:positive])}"}

    {:ok, supervisor} =
      Supervisor.start_link(
        [
          {PhxPortHandoff,
           otp_app: :phx_port_handoff, endpoint: Repro.Endpoint, identity: identity}
        ],
        strategy: :one_for_one
      )

    path = PhxPortHandoff.endpoint_path(identity, "https")
    {ingress, port} = Repro.Sender.listen()

    sender = Task.async(fn -> Repro.Sender.hand_off(ingress, path) end)
    say(:client_connecting)
    client = Task.async(fn -> request(port, cacerts) end)

    :ok = Task.await(sender, 15_000)
    say(:handoff_delivered)
    response = Task.await(client, 25_000)
    say({:response, binary_part(response, 0, min(15, byte_size(response)))})

    :socket.close(ingress)
    Supervisor.stop(supervisor)
  end

  # The in-VM client: this is the configuration that wedges the node.
  defp request(port, cacerts) do
    {:ok, client} =
      :ssl.connect(
        {127, 0, 0, 1},
        port,
        [
          :binary,
          active: false,
          verify: :verify_peer,
          cacerts: cacerts,
          server_name_indication: :disable
        ],
        10_000
      )

    :ok = :ssl.send(client, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    read(client, "")
  end

  defp read(client, acc) do
    case :ssl.recv(client, 0, 10_000) do
      {:ok, data} -> read(client, acc <> data)
      {:error, :closed} -> acc
      {:error, reason} -> acc <> "READ ERROR: #{inspect(reason)}"
    end
  end
end

iterations =
  case System.argv() do
    [count] -> String.to_integer(count)
    _ -> 10
  end

Repro.run(iterations)

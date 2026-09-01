defmodule PhxPortHandoff do
  @moduledoc """
  Linux and macOS connected-socket handoff support for phx-port.
  """

  alias PhxPortHandoff.Native

  @type broker :: reference()
  @type receipt :: reference()
  @type address_family :: :inet | :inet6

  @spec endpoint_path(Path.t(), String.t()) :: Path.t()
  def endpoint_path(project, role) do
    hash =
      :crypto.hash(:sha256, [Path.expand(project), <<0>>, role]) |> Base.encode16(case: :lower)

    Path.join(runtime_handoff_directory(), hash <> ".sock")
  end

  @spec listen(Path.t(), String.t()) :: {:ok, broker()} | {:error, term()}
  def listen(project, role) do
    Native.listen_derived(endpoint_path(project, role))
  end

  @spec bandit_child_spec(module(), Path.t(), String.t(), keyword()) :: Supervisor.child_spec()
  def bandit_child_spec(plug, project, role, tls_options) do
    handoff_path = endpoint_path(project, role)
    thousand_island_options = Keyword.get(tls_options, :thousand_island_options, [])
    transport_options = Keyword.get(thousand_island_options, :transport_options, [])

    thousand_island_options =
      thousand_island_options
      |> Keyword.put(:transport_module, PhxPortHandoff.Transport)
      |> Keyword.put(
        :transport_options,
        [handoff_path: handoff_path, derived_handoff_path: true] ++ transport_options
      )
      |> Keyword.put(:num_acceptors, 1)

    options =
      tls_options
      |> Keyword.drop([:port, :ip])
      |> Keyword.merge(
        plug: plug,
        scheme: :https,
        port: 443,
        startup_log: false,
        thousand_island_options: thousand_island_options
      )

    %{
      id: {__MODULE__, Path.expand(project), role},
      start: {Bandit, :start_link, [options]},
      type: :supervisor
    }
  end

  @spec accept(broker()) ::
          {:ok, port(), receipt(), %{sni: String.t(), peeked_length: non_neg_integer()}}
          | {:error, term()}
  def accept(broker) do
    lock = {{__MODULE__, broker}, self()}

    with {:ok, receipt, fd, address_family, sni, peeked_length} <-
           :global.trans(lock, fn -> Native.accept(broker) end),
         {:ok, socket} <- fdopen(receipt, fd, address_family) do
      retain_client_until_socket_closes(socket, receipt)
      {:ok, socket, receipt, %{sni: sni, peeked_length: peeked_length}}
    end
  end

  defp runtime_handoff_directory do
    case nonempty_env("PHX_PORT_RUNTIME_DIR") do
      nil ->
        case :os.type() do
          {:unix, :linux} ->
            Path.join([System.fetch_env!("XDG_RUNTIME_DIR"), "phx-port", "handoff"])

          {:unix, :darwin} ->
            Path.join(["/tmp", "phx-port-#{Native.effective_uid()}", "handoff"])

          platform ->
            raise "socket handoff is unavailable on #{inspect(platform)}"
        end

      runtime ->
        Path.join(runtime, "handoff")
    end
  end

  defp nonempty_env(name) do
    case System.get_env(name) do
      nil -> nil
      "" -> nil
      value -> value
    end
  end

  defp fdopen(receipt, fd, address_family) when address_family in [:inet, :inet6] do
    options = [
      {:inet_backend, :inet},
      address_family,
      :binary,
      active: false,
      packet: :raw,
      nodelay: true
    ]

    case :gen_tcp.fdopen(fd, options) do
      {:ok, socket} ->
        {:ok, socket}

      {:error, reason} ->
        _ = Native.rejected(receipt, 1)
        _ = Native.close_client(receipt)
        {:error, {:fdopen, reason}}
    end
  end

  defp retain_client_until_socket_closes(socket, receipt) do
    spawn(fn ->
      monitor = :erlang.monitor(:port, socket)

      receive do
        {:DOWN, ^monitor, :port, ^socket, _reason} ->
          :ok = Native.close_client(receipt)
      end
    end)
  end
end

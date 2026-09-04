defmodule PhxPortHandoff do
  @moduledoc """
  Linux and macOS connected-socket handoff support for phx-port.
  """

  alias PhxPortHandoff.Native

  @type broker :: reference()
  @type receipt :: reference()
  @type address_family :: :inet | :inet6
  @type endpoint_identity :: Path.t() | {:workload, String.t()}
  @production_runtime_root "/run/phx-port"
  @workload_id_pattern ~r/\A[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?\z/

  @spec endpoint_path(endpoint_identity(), String.t()) :: Path.t()
  def endpoint_path(identity, role) do
    {path, _validate_runtime_root?} = derived_endpoint(identity, role)
    path
  end

  @spec listen(endpoint_identity(), String.t()) :: {:ok, broker()} | {:error, term()}
  def listen(identity, role) do
    {path, validate_runtime_root?} = derived_endpoint(identity, role)

    if validate_runtime_root? do
      Native.listen_derived(path)
    else
      Native.listen(path)
    end
  end

  @spec bandit_child_spec(module(), endpoint_identity(), String.t(), keyword()) ::
          Supervisor.child_spec()
  def bandit_child_spec(plug, identity, role, tls_options) do
    {handoff_path, validate_runtime_root?} = derived_endpoint(identity, role)
    thousand_island_options = Keyword.get(tls_options, :thousand_island_options, [])
    transport_options = Keyword.get(thousand_island_options, :transport_options, [])

    thousand_island_options =
      thousand_island_options
      |> Keyword.put(:transport_module, PhxPortHandoff.Transport)
      |> Keyword.put(
        :transport_options,
        [
          handoff_path: handoff_path,
          derived_handoff_path: validate_runtime_root?
        ] ++ transport_options
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
      id: {__MODULE__, child_identity(identity), role},
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

  defp derived_endpoint({:workload, workload_id}, role) do
    validate_workload_id!(workload_id)
    hash = :crypto.hash(:sha256, [workload_id, <<0>>, role]) |> Base.encode16(case: :lower)
    {Path.join(runtime_handoff_directory(:production), hash <> ".sock"), false}
  end

  defp derived_endpoint(project, role) when is_binary(project) do
    project = Path.expand(project)
    hash = :crypto.hash(:sha256, [project, <<0>>, role]) |> Base.encode16(case: :lower)
    {Path.join(runtime_handoff_directory(:development), hash <> ".sock"), true}
  end

  defp validate_workload_id!(workload_id) do
    unless is_binary(workload_id) and byte_size(workload_id) in 1..128 and
             Regex.match?(@workload_id_pattern, workload_id) do
      raise ArgumentError,
            "logical Workload ID must contain 1 through 128 lowercase ASCII letters, digits, '.', '_', or '-', and start and end with a letter or digit"
    end
  end

  defp child_identity({:workload, workload_id}), do: {:workload, workload_id}
  defp child_identity(project), do: Path.expand(project)

  defp runtime_handoff_directory(profile) do
    case nonempty_env("PHX_PORT_RUNTIME_DIR") do
      nil -> default_runtime_handoff_directory(profile, :os.type())
      runtime -> Path.join(runtime, "handoff")
    end
  end

  defp default_runtime_handoff_directory(:production, {:unix, platform})
       when platform in [:linux, :darwin],
       do: Path.join(@production_runtime_root, "handoff")

  defp default_runtime_handoff_directory(:development, {:unix, :linux}),
    do: Path.join([System.fetch_env!("XDG_RUNTIME_DIR"), "phx-port", "handoff"])

  defp default_runtime_handoff_directory(:development, {:unix, :darwin}),
    do: Path.join(["/tmp", "phx-port-#{Native.effective_uid()}", "handoff"])

  defp default_runtime_handoff_directory(_profile, platform) do
    raise "socket handoff is unavailable on #{inspect(platform)}"
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

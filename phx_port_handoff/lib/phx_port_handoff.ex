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
  @doc """
  Returns a child specification for a handoff listener backed by an endpoint's
  configured HTTPS options.

  The child is ignored when the endpoint has no HTTPS configuration, allowing
  the same supervision tree to run in environments where HTTPS is disabled.

  Set `:handshake_timeout` on this child, not in the endpoint's HTTPS options,
  to override the handoff-only TLS handshake deadline. It defaults to 5,000
  milliseconds and must be a positive integer; invalid values fail startup.
  """
  @spec child_spec(keyword()) :: Supervisor.child_spec()
  def child_spec(options) do
    endpoint = Keyword.fetch!(options, :endpoint)
    role = Keyword.get(options, :role, "https")

    %{
      id: {__MODULE__, endpoint, role},
      start: {__MODULE__, :start_link, [options]},
      type: :supervisor
    }
  end

  @doc false
  @spec start_link(keyword()) :: Supervisor.on_start()
  def start_link(options) do
    otp_app = Keyword.fetch!(options, :otp_app)
    endpoint = Keyword.fetch!(options, :endpoint)
    role = Keyword.get(options, :role, "https")

    case Application.fetch_env!(otp_app, endpoint)[:https] do
      disabled when disabled in [nil, false] ->
        :ignore

      https ->
        identity = Keyword.get_lazy(options, :identity, &handoff_identity/0)

        %{start: {module, function, arguments}} =
          bandit_child_spec(
            endpoint,
            identity,
            role,
            Keyword.put_new(https, :otp_app, otp_app),
            options
          )

        apply(module, function, arguments)
    end
  end

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

  @doc """
  Returns a handoff-only Bandit child using the endpoint's HTTPS options.

  The optional fifth argument accepts `:handshake_timeout` with the same
  finite, positive millisecond bound as `child_spec/1`. This handoff-only
  option is kept separate from the shared endpoint TLS configuration.
  """
  @spec bandit_child_spec(module(), endpoint_identity(), String.t(), keyword()) ::
          Supervisor.child_spec()
  @spec bandit_child_spec(module(), endpoint_identity(), String.t(), keyword(), keyword()) ::
          Supervisor.child_spec()
  def bandit_child_spec(plug, identity, role, tls_options, handoff_options \\ []) do
    {handoff_path, validate_runtime_root?} = derived_endpoint(identity, role)
    thousand_island_options = Keyword.get(tls_options, :thousand_island_options, [])

    transport_options =
      Keyword.take(handoff_options, [:handshake_timeout]) ++
        Keyword.get(thousand_island_options, :transport_options, [])

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
           :global.trans(lock, fn -> Native.accept(broker) end, [node()]),
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

  defp handoff_identity do
    case System.get_env("PHX_PORT_WORKLOAD_ID") do
      id when is_binary(id) and id != "" -> {:workload, id}
      _other -> File.cwd!()
    end
  end

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

  # `{:inet_backend, :inet}` is deliberate; see docs/socket-forwarding-design.md.
  #
  # Do not add an O_NONBLOCK normalization here. It looks necessary, because a
  # descriptor arrives however the sender left it, but `inet_drv` already issues
  # `fcntl(fd, F_SETFL, O_RDWR|O_NONBLOCK)` on adoption. A previous fix added a
  # NIF to re-apply it and was reverted as redundant.
  #
  # The related gotcha, if you are chasing a frozen node: SCM_RIGHTS *shares* the
  # open file description rather than copying it, and O_NONBLOCK lives on that
  # description. A PHXP sender running in the *same* BEAM can therefore clear the
  # flag behind `inet_drv`'s back, after which the driver blocks in `recv(2)` on a
  # normal scheduler and, with an in-VM peer, wedges the whole VM. That is a
  # test-harness topology only — the real ingress is a separate OS process — so
  # write handoff tests with an out-of-process sender. Full analysis and the
  # reproductions are in docs/adversarial-audit.md.
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

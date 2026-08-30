defmodule PhxPortHandoff do
  @moduledoc """
  Linux connected-socket handoff support for phx-port.
  """

  alias PhxPortHandoff.Native

  @type broker :: reference()
  @type receipt :: reference()

  @spec endpoint_path(Path.t(), String.t()) :: Path.t()
  def endpoint_path(project, role) do
    runtime = System.fetch_env!("XDG_RUNTIME_DIR")

    hash =
      :crypto.hash(:sha256, [Path.expand(project), <<0>>, role]) |> Base.encode16(case: :lower)

    Path.join([runtime, "phx-port", "handoff", hash <> ".sock"])
  end

  @spec listen(Path.t(), String.t()) :: {:ok, broker()} | {:error, term()}
  def listen(project, role) do
    Native.listen(endpoint_path(project, role))
  end

  @spec bandit_child_spec(module(), Path.t(), String.t(), keyword()) :: Supervisor.child_spec()
  def bandit_child_spec(plug, project, role, tls_options) do
    handoff_path = endpoint_path(project, role)
    thousand_island_options = Keyword.get(tls_options, :thousand_island_options, [])
    transport_options = Keyword.get(thousand_island_options, :transport_options, [])

    thousand_island_options =
      thousand_island_options
      |> Keyword.put(:transport_module, PhxPortHandoff.Transport)
      |> Keyword.put(:transport_options, [handoff_path: handoff_path] ++ transport_options)
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

    with {:ok, receipt, fd, sni, peeked_length} <-
           :global.trans(lock, fn -> Native.accept(broker) end),
         {:ok, socket} <- fdopen(receipt, fd) do
      {:ok, socket, receipt, %{sni: sni, peeked_length: peeked_length}}
    end
  end

  defp fdopen(receipt, fd) do
    case :gen_tcp.fdopen(fd, [:binary, active: false, packet: :raw, nodelay: true]) do
      {:ok, socket} ->
        {:ok, socket}

      {:error, reason} ->
        _ = Native.close_fd(fd)
        _ = Native.rejected(receipt, 1)
        {:error, {:fdopen, reason}}
    end
  end
end

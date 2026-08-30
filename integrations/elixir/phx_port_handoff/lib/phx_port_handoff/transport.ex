defmodule PhxPortHandoff.Transport do
  @moduledoc """
  Handoff-only TLS transport for Thousand Island.

  `:handoff_path` identifies the `SOCK_SEQPACKET` endpoint. All remaining
  transport options are passed to the server-side TLS handshake.
  """

  @behaviour ThousandIsland.Transport

  alias PhxPortHandoff.Native

  defstruct [:socket, :receipt, :tls_options]

  @impl true
  def listen(port, options) do
    {path, tls_options} = Keyword.pop!(options, :handoff_path)

    case Native.listen(path) do
      {:ok, broker} -> {:ok, {broker, tls_options, {{0, 0, 0, 0}, port}}}
      other -> other
    end
  end

  @impl true
  def accept({broker, tls_options, _public_address}) do
    case PhxPortHandoff.accept(broker) do
      {:ok, socket, receipt, metadata} ->
        {:ok,
         %__MODULE__{
           socket: socket,
           receipt: receipt,
           tls_options: seed_sni_options(tls_options, metadata.sni)
         }}

      other ->
        other
    end
  end

  @impl true
  def controlling_process(%__MODULE__{socket: socket, receipt: receipt}, pid) do
    with :ok <- :gen_tcp.controlling_process(socket, pid),
         :ok <- Native.adopted(receipt) do
      :ok
    end
  end

  @impl true
  def handshake(%__MODULE__{socket: socket, tls_options: options}) do
    peername = :inet.peername(socket)
    sockname = :inet.sockname(socket)

    case :ssl.handshake(socket, options) do
      {:ok, tls_socket, _extensions} ->
        remember_addresses(tls_socket, peername, sockname)
        {:ok, tls_socket}

      {:ok, tls_socket} ->
        remember_addresses(tls_socket, peername, sockname)
        {:ok, tls_socket}

      other ->
        other
    end
  end

  @impl true
  def upgrade(%__MODULE__{} = socket, options), do: handshake(%{socket | tls_options: options})

  @impl true
  def recv(socket, length, timeout), do: :ssl.recv(socket, length, timeout)

  @impl true
  def send(socket, data), do: :ssl.send(socket, data)

  @impl true
  def sendfile(socket, filename, offset, length),
    do: ThousandIsland.Transports.SSL.sendfile(socket, filename, offset, length)

  @impl true
  def getopts(%__MODULE__{socket: socket}, options), do: :inet.getopts(socket, options)
  def getopts(socket, options), do: :ssl.getopts(socket, options)

  @impl true
  def setopts(%__MODULE__{socket: socket}, options), do: :inet.setopts(socket, options)
  def setopts(socket, options), do: :ssl.setopts(socket, options)

  @impl true
  def shutdown(%__MODULE__{socket: socket}, way), do: :gen_tcp.shutdown(socket, way)
  def shutdown(socket, way), do: :ssl.shutdown(socket, way)

  @impl true
  def close(%__MODULE__{socket: socket, receipt: receipt}) do
    if receipt, do: Native.rejected(receipt, 2)
    :gen_tcp.close(socket)
  end

  def close({broker, _tls_options, _public_address}), do: Native.close_listener(broker)
  def close(socket), do: :ssl.close(socket)

  @impl true
  def sockname(%__MODULE__{socket: socket}), do: :inet.sockname(socket)
  def sockname({_broker, _tls_options, public_address}), do: {:ok, public_address}

  def sockname(socket) do
    case :ssl.sockname(socket) do
      {:error, :ebadf} -> Process.get({__MODULE__, :sockname, socket}, {:error, :ebadf})
      result -> result
    end
  end

  @impl true
  def peername(%__MODULE__{socket: socket}), do: :inet.peername(socket)

  def peername(socket) do
    case :ssl.peername(socket) do
      {:error, :ebadf} -> Process.get({__MODULE__, :peername, socket}, {:error, :ebadf})
      result -> result
    end
  end

  @impl true
  def peercert(socket), do: :ssl.peercert(socket)

  @impl true
  def secure?, do: true

  @impl true
  def getstat(%__MODULE__{socket: socket}), do: :inet.getstat(socket)
  def getstat(socket), do: :ssl.getstat(socket)

  @impl true
  def negotiated_protocol(socket), do: :ssl.negotiated_protocol(socket)

  @impl true
  def connection_information(socket), do: :ssl.connection_information(socket)

  defp seed_sni_options(options, requested_sni) do
    case Keyword.fetch(options, :sni_fun) do
      {:ok, sni_fun} -> sni_fun.(String.to_charlist(requested_sni)) ++ options
      :error -> options
    end
  end

  defp remember_addresses(socket, peername, sockname) do
    Process.put({__MODULE__, :peername, socket}, peername)
    Process.put({__MODULE__, :sockname, socket}, sockname)
  end
end

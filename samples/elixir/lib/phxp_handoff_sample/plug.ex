defmodule PhxpHandoffSample.Plug do
  @behaviour Plug

  import Plug.Conn

  @impl true
  def init(options), do: options

  @impl true
  def call(conn, options) do
    peer = conn |> get_peer_data() |> format_endpoint()
    local = conn |> get_sock_data() |> format_endpoint()
    target = conn.request_path <> query_suffix(conn.query_string)
    protocol = conn |> get_http_protocol() |> Atom.to_string()

    body = """
    phxp Elixir handoff example
    listener=#{Keyword.fetch!(options, :listener)}
    peer=#{peer}
    local=#{local}
    public_port=#{conn.port}
    request=#{conn.method} #{target} #{protocol}
    """

    conn
    |> put_resp_content_type("text/plain")
    |> send_resp(200, body)
  end

  defp format_endpoint(%{address: address, port: port}) do
    ipv6? = tuple_size(address) == 8
    address = address |> :inet.ntoa() |> List.to_string()

    if ipv6?, do: "[#{address}]:#{port}", else: "#{address}:#{port}"
  end

  defp query_suffix(""), do: ""
  defp query_suffix(query), do: "?" <> query
end

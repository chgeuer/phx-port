defmodule PhxpHandoffSample.PlugTest do
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  alias PhxpHandoffSample.Plug, as: SamplePlug

  test "reports the listener, socket endpoints, public port, and request line" do
    conn =
      :get
      |> conn("https://alias-alpha.phx-port.pollmann.rocks/demo?q=socket")
      |> SamplePlug.call(listener: "phxp-handoff-https")

    assert conn.status == 200
    assert get_resp_header(conn, "content-type") == ["text/plain; charset=utf-8"]
    assert conn.resp_body =~ "phxp Elixir handoff example"
    assert conn.resp_body =~ "listener=phxp-handoff-https"
    assert conn.resp_body =~ "peer=127.0.0.1:111317"
    assert conn.resp_body =~ "local=127.0.0.1:111318"
    assert conn.resp_body =~ "public_port=443"
    assert conn.resp_body =~ "request=GET /demo?q=socket HTTP/1.1"
  end
end

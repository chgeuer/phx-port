defmodule PhxPortHandoffTest do
  use ExUnit.Case

  alias PhxPortHandoff.Native

  test "endpoint path matches the PHXP project and role convention" do
    runtime = System.fetch_env!("XDG_RUNTIME_DIR")
    project = Path.expand("/srv/contoso")

    expected_hash =
      :crypto.hash(:sha256, [project, <<0>>, "https"]) |> Base.encode16(case: :lower)

    assert PhxPortHandoff.endpoint_path(project, "https") ==
             Path.join([runtime, "phx-port", "handoff", expected_hash <> ".sock"])
  end

  test "native broker creates a private seqpacket endpoint" do
    path =
      Path.join([
        System.tmp_dir!(),
        "phxp-#{System.unique_integer([:positive])}",
        "handoff.sock"
      ])

    assert {:ok, broker} = Native.listen(path)
    assert is_reference(broker)
    assert File.stat!(path).mode |> Bitwise.band(0o777) == 0o600
  end

  test "native broker refuses to replace a live endpoint" do
    path =
      Path.join([
        System.tmp_dir!(),
        "phxp-#{System.unique_integer([:positive])}",
        "handoff.sock"
      ])

    assert {:ok, broker} = Native.listen(path)
    accept = Task.async(fn -> Native.accept(broker) end)
    assert is_reference(broker)
    assert {:error, message} = Native.listen(path)
    assert message =~ "already listening"
    assert {:error, :econnaborted} = Task.await(accept)
  end

  test "native broker replaces a stale endpoint" do
    path =
      Path.join([
        System.tmp_dir!(),
        "phxp-#{System.unique_integer([:positive])}",
        "handoff.sock"
      ])

    File.mkdir_p!(Path.dirname(path))
    File.write!(path, "stale")

    assert {:ok, broker} = Native.listen(path)
    assert is_reference(broker)
    assert File.stat!(path).type == :other
  end

  test "closing a broker unblocks its pending accept and removes the endpoint" do
    path =
      Path.join([
        System.tmp_dir!(),
        "phxp-#{System.unique_integer([:positive])}",
        "handoff.sock"
      ])

    assert {:ok, broker} = Native.listen(path)
    accept = Task.async(fn -> Native.accept(broker) end)
    assert :ok = Native.close_listener(broker)
    assert {:error, :closed} = Task.await(accept)
    refute File.exists?(path)
  end

  test "listener owner exit closes the broker even while another process is accepting" do
    path =
      Path.join([
        System.tmp_dir!(),
        "phxp-#{System.unique_integer([:positive])}",
        "handoff.sock"
      ])

    parent = self()

    owner =
      spawn(fn ->
        {:ok, broker} = Native.listen(path)
        send(parent, {:broker, broker})
        Process.sleep(:infinity)
      end)

    assert_receive {:broker, broker}
    accept = Task.async(fn -> Native.accept(broker) end)
    Process.exit(owner, :kill)
    assert {:error, :closed} = Task.await(accept)
    refute File.exists?(path)
  end
end

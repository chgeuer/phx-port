defmodule PhxPortHandoffTest do
  use ExUnit.Case

  alias PhxPortHandoff.Native

  test "endpoint path matches the PHXP project and role convention" do
    runtime = Path.join(System.tmp_dir!(), "phxp-runtime")
    previous = System.get_env("PHX_PORT_RUNTIME_DIR")
    System.put_env("PHX_PORT_RUNTIME_DIR", runtime)

    on_exit(fn ->
      if previous,
        do: System.put_env("PHX_PORT_RUNTIME_DIR", previous),
        else: System.delete_env("PHX_PORT_RUNTIME_DIR")
    end)

    project = Path.expand("/srv/contoso")

    expected_hash =
      :crypto.hash(:sha256, [project, <<0>>, "https"]) |> Base.encode16(case: :lower)

    assert PhxPortHandoff.endpoint_path(project, "https") ==
             Path.join([runtime, "handoff", expected_hash <> ".sock"])
  end

  test "macOS default endpoint uses the effective UID" do
    if :os.type() == {:unix, :darwin} do
      previous = System.get_env("PHX_PORT_RUNTIME_DIR")
      System.delete_env("PHX_PORT_RUNTIME_DIR")

      on_exit(fn ->
        if previous, do: System.put_env("PHX_PORT_RUNTIME_DIR", previous)
      end)

      path = PhxPortHandoff.endpoint_path("/srv/contoso", "https")
      assert String.starts_with?(path, "/tmp/phx-port-#{Native.effective_uid()}/handoff/")
    end
  end

  test "native broker creates a private endpoint" do
    path = endpoint_path()

    assert {:ok, broker} = Native.listen(path)
    assert is_reference(broker)
    assert File.stat!(path).mode |> Bitwise.band(0o777) == 0o600
    assert :ok = Native.close_listener(broker)
  end

  test "native broker refuses to replace a live endpoint" do
    path = endpoint_path()

    assert {:ok, broker} = Native.listen(path)
    accept = Task.async(fn -> Native.accept(broker) end)
    assert is_reference(broker)
    assert {:error, message} = Native.listen(path)
    assert message =~ "already listening"
    assert {:error, :econnaborted} = Task.await(accept)
  end

  test "native broker refuses to replace a regular file" do
    path = endpoint_path()

    File.mkdir_p!(Path.dirname(path))
    File.chmod!(Path.dirname(path), 0o700)
    File.write!(path, "stale")

    assert {:error, message} = Native.listen(path)
    assert message =~ "refusing to replace non-socket"
  end

  test "closing a broker unblocks its pending accept and removes the endpoint" do
    path = endpoint_path()

    assert {:ok, broker} = Native.listen(path)
    accept = Task.async(fn -> Native.accept(broker) end)
    assert :ok = Native.close_listener(broker)
    assert {:error, :closed} = Task.await(accept)
    refute File.exists?(path)
  end

  test "listener owner exit closes the broker even while another process is accepting" do
    path = endpoint_path()

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

  defp endpoint_path do
    directory = Path.join("/tmp", "phxp-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm_rf!(directory) end)
    Path.join(directory, "handoff.sock")
  end
end

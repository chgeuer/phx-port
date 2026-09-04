defmodule PhxPortHandoffTest do
  use ExUnit.Case, async: false

  alias PhxPortHandoff.Native

  setup do
    previous =
      Map.new(["PHX_PORT_RUNTIME_DIR", "PHX_PORT_WORKLOAD_ID"], fn name ->
        {name, System.get_env(name)}
      end)

    on_exit(fn ->
      Enum.each(previous, fn
        {name, nil} -> System.delete_env(name)
        {name, value} -> System.put_env(name, value)
      end)
    end)

    :ok
  end

  test "endpoint path matches the PHXP project and role convention" do
    runtime = Path.join(System.tmp_dir!(), "phxp-runtime")
    System.put_env("PHX_PORT_RUNTIME_DIR", runtime)
    System.delete_env("PHX_PORT_WORKLOAD_ID")

    project = Path.expand("/srv/contoso")

    expected_hash =
      :crypto.hash(:sha256, [project, <<0>>, "https"]) |> Base.encode16(case: :lower)

    assert PhxPortHandoff.endpoint_path(project, "https") ==
             Path.join([runtime, "handoff", expected_hash <> ".sock"])
  end

  test "macOS default endpoint uses the effective UID" do
    if :os.type() == {:unix, :darwin} do
      System.delete_env("PHX_PORT_RUNTIME_DIR")
      System.delete_env("PHX_PORT_WORKLOAD_ID")

      path = PhxPortHandoff.endpoint_path("/srv/contoso", "https")
      assert String.starts_with?(path, "/tmp/phx-port-#{Native.effective_uid()}/handoff/")
    end
  end

  test "logical Workload endpoint defaults to the production runtime root" do
    System.delete_env("PHX_PORT_RUNTIME_DIR")

    expected_hash =
      :crypto.hash(:sha256, ["contoso-web", <<0>>, "https"]) |> Base.encode16(case: :lower)

    assert PhxPortHandoff.endpoint_path({:workload, "contoso-web"}, "https") ==
             Path.join(["/run/phx-port", "handoff", expected_hash <> ".sock"])
  end

  test "logical Workload listener accepts a group-traversable production runtime root" do
    root = Path.join("/tmp", "pp-#{:os.getpid()}-#{System.unique_integer([:positive])}")
    File.mkdir_p!(root)
    File.chmod!(root, 0o750)
    on_exit(fn -> File.rm_rf!(root) end)
    System.put_env("PHX_PORT_RUNTIME_DIR", root)

    identity = {:workload, "contoso-web"}
    path = PhxPortHandoff.endpoint_path(identity, "https")
    assert {:ok, broker} = PhxPortHandoff.listen(identity, "https")
    assert File.stat!(Path.dirname(path)).mode |> Bitwise.band(0o777) == 0o700
    assert File.stat!(path).mode |> Bitwise.band(0o777) == 0o600
    assert :ok = Native.close_listener(broker)
  end

  test "invalid logical Workload identity fails closed" do
    assert_raise ArgumentError, ~r/logical Workload ID must contain/, fn ->
      PhxPortHandoff.endpoint_path({:workload, "../contoso"}, "https")
    end
  end

  test "allocator Workload identity alone does not change development handoff" do
    runtime = Path.join(System.tmp_dir!(), "phxp-runtime")
    System.put_env("PHX_PORT_RUNTIME_DIR", runtime)
    System.put_env("PHX_PORT_WORKLOAD_ID", "contoso-web")
    project = Path.expand("/srv/contoso")

    expected_hash =
      :crypto.hash(:sha256, [project, <<0>>, "https"]) |> Base.encode16(case: :lower)

    assert PhxPortHandoff.endpoint_path(project, "https") ==
             Path.join([runtime, "handoff", expected_hash <> ".sock"])
  end

  test "native broker creates a private endpoint" do
    path = endpoint_path()

    assert {:ok, broker} = Native.listen(path)
    assert is_reference(broker)
    assert File.stat!(path).mode |> Bitwise.band(0o777) == 0o600
    assert :ok = Native.close_listener(broker)
  end

  test "explicit endpoint validates only its private parent directory" do
    root = Path.join("/tmp", "phxp-explicit-#{:os.getpid()}-#{System.unique_integer()}")
    path = Path.join([root, "handoff", "receiver.sock"])
    File.mkdir_p!(Path.dirname(path))
    File.chmod!(root, 0o755)
    File.chmod!(Path.dirname(path), 0o700)
    on_exit(fn -> File.rm_rf!(root) end)

    assert {:ok, broker} = Native.listen(path)
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

    assert_receive {:broker, broker}, 1_000
    accept = Task.async(fn -> Native.accept(broker) end)
    Process.exit(owner, :kill)
    assert {:error, :closed} = Task.await(accept)
    assert wait_until_removed(path)
  end

  defp endpoint_path do
    directory =
      Path.join(
        "/tmp",
        "phxp-#{:os.getpid()}-#{System.unique_integer([:positive, :monotonic])}"
      )

    on_exit(fn -> File.rm_rf!(directory) end)
    Path.join(directory, "handoff.sock")
  end

  defp wait_until_removed(path, attempts \\ 100)

  defp wait_until_removed(_path, 0), do: false

  defp wait_until_removed(path, attempts) do
    if File.exists?(path) do
      Process.sleep(10)
      wait_until_removed(path, attempts - 1)
    else
      true
    end
  end
end

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

  test "configured child has a stable identity and ignores disabled HTTPS" do
    endpoint = __MODULE__.Endpoint
    Application.put_env(:phx_port_handoff, endpoint, [])
    on_exit(fn -> Application.delete_env(:phx_port_handoff, endpoint) end)

    assert %{
             id: {PhxPortHandoff, ^endpoint, "https"},
             start:
               {PhxPortHandoff, :start_link, [[otp_app: :phx_port_handoff, endpoint: ^endpoint]]},
             type: :supervisor
           } =
             PhxPortHandoff.child_spec(
               otp_app: :phx_port_handoff,
               endpoint: endpoint
             )

    assert :ignore =
             PhxPortHandoff.start_link(
               otp_app: :phx_port_handoff,
               endpoint: endpoint
             )
  end

  test "Bandit helper keeps handoff deadlines separate from the shared TLS options" do
    System.put_env("PHX_PORT_RUNTIME_DIR", Path.join(System.tmp_dir!(), "phxp-runtime"))
    identity = {:workload, "child-options-test"}
    path = PhxPortHandoff.endpoint_path(identity, "https")
    transport_options = [:inet, alpn_preferred_protocols: ["h2"]]

    https = [
      port: 4043,
      ip: {127, 0, 0, 1},
      thousand_island_options: [read_timeout: 1_234, transport_options: transport_options]
    ]

    default = PhxPortHandoff.bandit_child_spec(__MODULE__.Endpoint, identity, "https", https)

    configured =
      PhxPortHandoff.bandit_child_spec(__MODULE__.Endpoint, identity, "https", https,
        handshake_timeout: 250
      )

    for {spec, timeout_options} <- [{default, []}, {configured, [handshake_timeout: 250]}] do
      assert %{start: {Bandit, :start_link, [options]}} = spec
      refute Keyword.has_key?(options, :handshake_timeout)
      assert options[:thousand_island_options][:transport_module] == PhxPortHandoff.Transport
      assert options[:thousand_island_options][:read_timeout] == 1_234

      assert options[:thousand_island_options][:transport_options] ==
               [handoff_path: path, derived_handoff_path: false] ++
                 timeout_options ++ transport_options
    end
  end

  test "native broker creates a private endpoint" do
    path = endpoint_path()

    assert {:ok, broker} = Native.listen(path)
    assert is_reference(broker)
    assert File.stat!(path).mode |> Bitwise.band(0o777) == 0o600
    assert :ok = Native.close_listener(broker)
  end

  test "explicitly disabled HTTPS ignores the configured child" do
    endpoint = __MODULE__.DisabledEndpoint
    Application.put_env(:phx_port_handoff, endpoint, https: false)
    on_exit(fn -> Application.delete_env(:phx_port_handoff, endpoint) end)

    assert :ignore =
             PhxPortHandoff.start_link(
               otp_app: :phx_port_handoff,
               endpoint: endpoint
             )
  end

  test "idle accepts leave dirty I/O schedulers available for unrelated work" do
    brokers =
      for _ <- 1..(:erlang.system_info(:dirty_io_schedulers) + 1) do
        {:ok, broker} = Native.listen(endpoint_path())
        broker
      end

    accepts = Enum.map(brokers, fn broker -> Task.async(fn -> Native.accept(broker) end) end)
    Process.sleep(100)
    file_operation = Task.async(fn -> File.stat!(__ENV__.file).type end)

    result =
      try do
        Task.yield(file_operation, 1_000)
      after
        Enum.each(brokers, &Native.close_listener/1)
        Enum.each(accepts, fn accept -> assert {:error, :closed} = Task.await(accept) end)
        Task.shutdown(file_operation)
      end

    assert {:ok, :regular} = result
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

  @tag :endpoint_liveness
  @tag skip: :os.type() != {:unix, :linux}
  test "native startup preserves a full endpoint within its probe deadline" do
    path = endpoint_path()
    listener = bound_socket(path, :seqpacket)
    :ok = :socket.listen(listener, 1)
    original = File.lstat!(path)

    queued =
      for _ <- 1..2 do
        {:ok, client} = :socket.open(:local, :seqpacket, :default)
        on_exit(fn -> :socket.close(client) end)
        :ok = :socket.connect(client, %{family: :local, path: path}, 1_000)
        client
      end

    probe =
      Task.async(fn ->
        started = System.monotonic_time(:millisecond)
        result = Native.listen(path)
        {result, System.monotonic_time(:millisecond) - started}
      end)

    {outcome, preserved} =
      try do
        outcome = Task.yield(probe, 2_500)
        {outcome, File.lstat!(path)}
      after
        :socket.close(listener)
        Enum.each(queued, &:socket.close/1)
        Task.shutdown(probe, 5_000)
      end

    assert {:ok, {{:error, _message}, elapsed}} = outcome
    assert elapsed < 2_500
    assert preserved.inode == original.inode
    assert preserved.major_device == original.major_device
  end

  @tag :endpoint_liveness
  test "native startup preserves an endpoint when its probe has a protocol error" do
    path = endpoint_path()
    _datagram = bound_socket(path, :dgram)
    original = File.lstat!(path)

    assert {:error, message} = Native.listen(path)
    assert message =~ "cannot probe handoff endpoint"
    preserved = File.lstat!(path)
    assert preserved.inode == original.inode
    assert preserved.major_device == original.major_device
  end

  @tag :endpoint_liveness
  @tag skip: :os.type() != {:unix, :linux}
  test "native startup preserves an endpoint when its probe is denied permission" do
    refute Native.effective_uid() == 0, "run this fixture unprivileged"
    path = endpoint_path()
    assert {:ok, broker} = Native.listen(path)

    try do
      File.chmod!(path, 0o000)
      original = File.lstat!(path)
      assert {:error, message} = Native.listen(path)
      assert message =~ "cannot probe handoff endpoint"
      preserved = File.lstat!(path)
      assert preserved.inode == original.inode
      assert preserved.major_device == original.major_device
      assert Bitwise.band(preserved.mode, 0o777) == 0o000
    after
      Native.close_listener(broker)
    end
  end

  @tag :endpoint_liveness
  test "native startup replaces a confirmed stale endpoint" do
    type = if :os.type() == {:unix, :linux}, do: :seqpacket, else: :stream
    path = endpoint_path()
    stale = bound_socket(path, type)
    :ok = :socket.close(stale)

    assert {:ok, broker} = Native.listen(path)
    assert {:error, :eagain} = Native.try_accept(broker)
    assert :ok = Native.close_listener(broker)
    refute File.exists?(path)
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

  @tag :endpoint_cleanup
  test "resource collection cleans up the endpoint while its owner remains alive" do
    path = endpoint_path()
    parent = self()

    owner =
      spawn(fn ->
        listen_and_forget(path)
        true = :erlang.garbage_collect()
        send(parent, :collected)

        receive do
          :stop -> :ok
        end
      end)

    monitor = Process.monitor(owner)
    on_exit(fn -> Process.exit(owner, :kill) end)
    assert_receive :collected, 1_000
    assert wait_until_removed(path)
    assert Process.alive?(owner)
    send(owner, :stop)
    assert_receive {:DOWN, ^monitor, :process, ^owner, :normal}, 1_000
  end

  @tag :endpoint_cleanup
  test "cleanup worker restart retains pending endpoint cleanup" do
    path = endpoint_path()
    parent = self()

    owner =
      spawn(fn ->
        {:ok, broker} = Native.listen(path)
        send(parent, {:broker, broker})
        Process.sleep(:infinity)
      end)

    on_exit(fn -> Process.exit(owner, :kill) end)
    assert_receive {:broker, broker}, 1_000
    cleanup = Process.whereis(PhxPortHandoff.Cleanup)
    assert :ok = :sys.suspend(cleanup, 1_000)

    try do
      accept = Task.async(fn -> Native.accept(broker) end)
      Process.exit(owner, :kill)
      assert {:error, :closed} = Task.await(accept, 1_000)
      assert File.exists?(path)
      monitor = Process.monitor(cleanup)
      Process.exit(cleanup, :kill)
      assert_receive {:DOWN, ^monitor, :process, ^cleanup, :killed}, 1_000
      assert wait_until_removed(path)
      assert is_pid(Process.whereis(PhxPortHandoff.Cleanup))
      refute Process.whereis(PhxPortHandoff.Cleanup) == cleanup

      assert {:ok, replacement} = Native.listen(path)
      assert :ok = Native.close_listener(broker)
      assert File.exists?(path)
      assert :ok = Native.close_listener(replacement)
    after
      if Process.alive?(cleanup), do: :sys.resume(cleanup, 1_000)
      Native.close_listener(broker)
    end
  end

  @tag :endpoint_cleanup
  test "same-path restart drains owner-down cleanup even while the worker is suspended" do
    path = endpoint_path()
    parent = self()

    owner =
      spawn(fn ->
        {:ok, broker} = Native.listen(path)
        send(parent, {:broker, broker})
        Process.sleep(:infinity)
      end)

    on_exit(fn -> Process.exit(owner, :kill) end)
    assert_receive {:broker, broker}, 1_000
    cleanup = Process.whereis(PhxPortHandoff.Cleanup)
    assert :ok = :sys.suspend(cleanup, 1_000)

    try do
      accept = Task.async(fn -> Native.accept(broker) end)
      Process.exit(owner, :kill)
      assert {:error, :closed} = Task.await(accept, 1_000)
      assert File.exists?(path)

      assert {:ok, replacement} = Native.listen(Path.join(Path.dirname(path), "./handoff.sock"))
      assert :ok = Native.close_listener(broker)
      assert File.exists?(path)
      assert :ok = Native.close_listener(replacement)
    after
      :sys.resume(cleanup, 1_000)
      Native.close_listener(broker)
    end
  end

  defp listen_and_forget(path) do
    assert {:ok, _broker} = Native.listen(path)
    :ok
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

  defp bound_socket(path, type) do
    File.mkdir_p!(Path.dirname(path))
    File.chmod!(Path.dirname(path), 0o700)
    {:ok, socket} = :socket.open(:local, type, :default)
    on_exit(fn -> :socket.close(socket) end)
    :ok = :socket.bind(socket, %{family: :local, path: path})
    socket
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

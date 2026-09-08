defmodule PhxPortHandoff.SchedulerProbeTest do
  use ExUnit.Case, async: false

  @evidence Path.expand("../../docs/evidence", __DIR__)
  @scripts [
    "out_of_vm_starvation.exs",
    "invm_peer_starvation.exs",
    "invm_tls_starvation.exs"
  ]
  @files @scripts ++
           ["scheduler_probe.exs", "stalled_handoff_sender.py", "invm_peer_sender.py"]

  test "none of the scheduler probes runs a PHXP sender inside the receiving VM" do
    for file <- @scripts ++ ["scheduler_probe.exs"] do
      {_source, in_vm_sends} =
        @evidence
        |> Path.join(file)
        |> File.read!()
        |> Code.string_to_quoted!()
        |> Macro.prewalk([], fn
          {{:., _, [:socket, :sendmsg]}, metadata, _} = node, calls ->
            {node, [Keyword.fetch!(metadata, :line) | calls]}

          node, calls ->
            {node, calls}
        end)

      assert in_vm_sends == [], "in-VM descriptor sends in #{file}"
    end
  end

  for script <- @scripts do
    @tag timeout: 30_000
    test "#{script}: a missing external sender cannot produce a healthy scheduler verdict" do
      result = run_probe(unquote(script), :missing_sender)
      assert_inconclusive(result)
    end

    for blocking <- ["0", "1"] do
      @tag timeout: 30_000
      test "#{script}: real adopted peers stay live through the window (blocking=#{blocking})" do
        result = run_probe(unquote(script), :none, ["2", unquote(blocking)])
        assert result.status == 0, result.output
        assert result.verdict =~ "VERDICT schedulers_healthy"
        assert result.verdict =~ "adopted: 2"
        assert result.verdict =~ "receiver_started: 2"
        assert result.verdict =~ "sender_exit: 0"
        assert result.verdict =~ "normal_schedulers: 2"
        assert result.verdict =~ "sender_blocking: #{unquote(blocking) == "1"}"
        assert [_, ticks] = Regex.run(~r/ticks: (\d+)/, result.verdict)
        assert String.to_integer(ticks) >= 10
        assert [_, window] = Regex.run(~r/window_ms: (\d+)/, result.verdict)
        assert String.to_integer(window) >= 3_000
        assert [_, samples] = Regex.run(~r/live_samples: (\d+)/, result.verdict)
        assert String.to_integer(samples) >= 2
        assert result.log =~ "ADOPTED 1\nADOPTED 2\nHOLDING 2\nCHECKED 0\n"
        assert result.log =~ "STOPPED\n"
        assert {:ok, stat} = File.stat(result.directory)
        assert Bitwise.band(stat.mode, 0o777) == 0o700
        assert Enum.sort(File.ls!(result.directory)) == ["sender.log", "verdict"]
        assert_sender_reaped(result.output)
      end
    end
  end

  for {fault, reason} <- [
        {:failed_sender, "{:sender_exit, 7, :startup}"},
        {:stalled_sender, "{:sender_timeout, :startup}"},
        {:wrong_pid, ":invalid_sender_identity_or_readiness"},
        {:no_receiver_adoptions, "{:receiver_population, 0, :expected, 2}"},
        {:insufficient_receiver_adoptions, "{:receiver_population, 1, :expected, 2}"},
        {:insufficient_adoptions, "{:adoptions, 1, :expected, 2}"},
        {:premature_close, [":live_population", ":premature_socket_close"]},
        {:early_exit,
         [":sender_closed", "{:sender_exit, 0, :live_population}", ":premature_socket_close"]},
        {:nonzero_exit, "{:sender_exit, 7, :completion}"}
      ] do
    @tag timeout: 30_000
    test "#{fault} is inconclusive, never healthy" do
      result = run_probe("out_of_vm_starvation.exs", unquote(fault))
      assert_inconclusive(result)
      assert Enum.any?(List.wrap(unquote(reason)), &(result.verdict =~ &1)), result.output
      assert_sender_reaped(result.output)

      if unquote(fault) in [:premature_close, :nonzero_exit] do
        assert result.log =~ "ADOPTED 1\nADOPTED 2\nHOLDING 2\nCHECKED 0\n"
      end
    end
  end

  @tag timeout: 30_000
  test "zero requested peers cannot produce an unloaded healthy verdict" do
    result = run_probe("out_of_vm_starvation.exs", :none, ["0", "1"])
    assert_inconclusive(result)
    assert result.verdict =~ ":invalid_count"
    refute result.output =~ "SENDER_PID"
  end

  @tag timeout: 30_000
  test "an existing artifact directory is preserved rather than reused as evidence" do
    fixture = temporary_directory()
    directory = Path.join(fixture, "run")
    File.mkdir!(directory)
    verdict = Path.join(directory, "verdict")
    File.write!(verdict, "previous run")

    {output, status} = execute_probe(Path.join(@evidence, hd(@scripts)), directory, ["2", "1"])
    refute status in [0, 124, 137], output
    refute output =~ "schedulers_healthy"
    assert output =~ "file already exists"
    assert File.read!(verdict) == "previous run"
    assert File.ls!(directory) == ["verdict"]
  end

  defp assert_inconclusive(result) do
    refute result.output =~ "schedulers_healthy",
           "the evidence reported healthy without its required load:\n#{result.output}"

    assert result.status == 2, result.output
    assert result.verdict =~ "VERDICT inconclusive", result.output
  end

  defp run_probe(script, fault, arguments \\ ["2", "1"]) do
    fixture = temporary_directory()

    for filename <- @files do
      File.cp!(Path.join(@evidence, filename), Path.join(fixture, filename))
    end

    prepare_fault(fixture, fault)
    directory = Path.join(fixture, "run")

    {output, status} = execute_probe(Path.join(fixture, script), directory, arguments)

    assert status not in [124, 137], "the external probe watchdog fired:\n#{output}"
    assert File.exists?(Path.join(directory, "verdict")), output

    log =
      case File.read(Path.join(directory, "sender.log")) do
        {:ok, log} -> log
        {:error, :enoent} when arguments == ["0", "1"] -> ""
      end

    %{
      output: output,
      status: status,
      directory: directory,
      verdict: File.read!(Path.join(directory, "verdict")),
      log: log
    }
  end

  defp execute_probe(script, directory, arguments) do
    System.cmd(
      "timeout",
      ["--kill-after=2s", "20s", "mix", "run", script | arguments],
      env: [
        {"ELIXIR_ERL_OPTIONS", "+S 2:2"},
        {"MIX_ENV", "test"},
        {"PHXP_PROBE_DIRECTORY", directory}
      ],
      stderr_to_stdout: true
    )
  end

  defp prepare_fault(_directory, :none), do: :ok

  defp prepare_fault(directory, :missing_sender) do
    File.rm!(Path.join(directory, "stalled_handoff_sender.py"))
    File.rm!(Path.join(directory, "invm_peer_sender.py"))
  end

  defp prepare_fault(directory, fault) do
    sender = Path.join(directory, "stalled_handoff_sender.py")
    File.cp!(sender, Path.join(directory, "real_sender.py"))

    source =
      case fault do
        :failed_sender ->
          "raise SystemExit(7)"

        :stalled_sender ->
          "signal.alarm(20)\ntime.sleep(30)"

        :wrong_pid ->
          ~s|print("READY 0 12345", flush=True)\nsignal.alarm(20)\ntime.sleep(30)|

        fault when fault in [:no_receiver_adoptions, :insufficient_receiver_adoptions] ->
          actual_adoptions = if fault == :no_receiver_adoptions, do: 0, else: 1

          """
          original_handoff = sender.hand_off
          handoffs = 0
          with sender.ExitStack() as undelivered:
              def hand_off_subset(accepted, path):
                  global handoffs
                  if handoffs < #{actual_adoptions}:
                      original_handoff(accepted, path)
                  else:
                      undelivered.enter_context(accepted.dup())
                  handoffs += 1
              sender.hand_off = hand_off_subset
              sender.main()
          """

        :insufficient_adoptions ->
          ~s|sys.argv[2] = "1"\nsender.main()|

        :premature_close ->
          """
          original_check = sender.check_peers
          checks = 0
          def close_during_measurement(peers):
              global checks
              checks += 1
              if checks == 4:
                  peers[0].shutdown(socket.SHUT_RDWR)
              original_check(peers)
          sender.check_peers = close_during_measurement
          sender.main()
          """

        :nonzero_exit ->
          "sender.main()\nraise SystemExit(7)"

        :early_exit ->
          "sender.serve_commands = lambda peers: None\nsender.main()"
      end

    File.write!(
      sender,
      """
      import signal
      import socket
      import sys
      import time
      import real_sender as sender
      #{source}
      """
    )
  end

  defp assert_sender_reaped(output) do
    assert [_, pid] = Regex.run(~r/^SENDER_PID (\d+)$/m, output)
    {message, status} = System.cmd("kill", ["-0", pid], stderr_to_stdout: true)
    assert status != 0, "sender #{pid} survived cleanup: #{message}"
  end

  defp temporary_directory do
    path = Path.join("/tmp", "e6-" <> Base.encode16(:crypto.strong_rand_bytes(4)))
    File.mkdir!(path)
    File.chmod!(path, 0o700)
    on_exit(fn -> File.rm_rf!(path) end)
    path
  end
end

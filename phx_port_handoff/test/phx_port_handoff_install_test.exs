defmodule PhxPortHandoffInstallTest do
  use ExUnit.Case

  import Igniter.Test

  @application """
  defmodule Test.Application do
    use Application

    @impl true
    def start(_type, _args) do
      children = [
        Test.Telemetry,
        {Phoenix.PubSub, name: Test.PubSub},
        TestWeb.Endpoint
      ]

      Supervisor.start_link(children, strategy: :one_for_one, name: Test.Supervisor)
    end
  end
  """

  @endpoint """
  defmodule TestWeb.Endpoint do
    use Phoenix.Endpoint, otp_app: :test
  end
  """

  @mix_exs """
  defmodule Test.MixProject do
    use Mix.Project

    def project do
      [app: :test, version: "0.1.0", deps: []]
    end

    def application do
      [mod: {Test.Application, []}]
    end
  end
  """

  test "inserts the handoff child immediately before the endpoint and is idempotent" do
    igniter =
      test_project(
        files: %{
          "mix.exs" => @mix_exs,
          "lib/test/application.ex" => @application,
          "lib/test_web/endpoint.ex" => @endpoint
        }
      )
      |> Igniter.compose_task("phx_port_handoff.install")
      |> assert_has_patch("lib/test/application.ex", """
      + |    {PhxPortHandoff, [otp_app: :test, endpoint: TestWeb.Endpoint, role: "https"]},
        |    TestWeb.Endpoint
      """)
      |> apply_igniter!()

    igniter
    |> Igniter.compose_task("phx_port_handoff.install")
    |> assert_unchanged("lib/test/application.ex")
  end

  @tag :tmp_dir
  test "the default formatter checks and formats the installer", %{tmp_dir: tmp_dir} do
    File.chmod!(tmp_dir, 0o700)
    on_exit(fn -> File.rm_rf!(tmp_dir) end)

    File.cp!(Path.expand("../.formatter.exs", __DIR__), Path.join(tmp_dir, ".formatter.exs"))
    installer = Path.join(tmp_dir, "priv/installer/igniter.exs")
    File.mkdir_p!(Path.dirname(installer))

    File.write!(installer, """
    defmodule InstallerFixture do
      def install( igniter ),do: igniter
    end
    """)

    options = [cd: tmp_dir, stderr_to_stdout: true, env: [{"ERL_FLAGS", "+S 2:2"}]]
    {output, status} = System.cmd("mix", ["format", "--check-formatted"], options)

    assert status == 1,
           "formatter must reject the unformatted installer (exit #{status}):\n#{output}"

    assert output =~ "priv/installer/igniter.exs"
    assert {"", 0} = System.cmd("mix", ["format"], options)
    assert {"", 0} = System.cmd("mix", ["format", "--check-formatted"], options)

    assert File.read!(installer) == """
           defmodule InstallerFixture do
             def install(igniter), do: igniter
           end
           """
  end
end

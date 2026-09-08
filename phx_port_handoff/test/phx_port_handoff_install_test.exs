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
      installer_project()
      |> Igniter.compose_task("phx_port_handoff.install")
      |> assert_has_patch("lib/test/application.ex", """
      + |    {PhxPortHandoff, [otp_app: :test, endpoint: TestWeb.Endpoint, role: "https"]},
        |    TestWeb.Endpoint
      """)
      |> assert_has_notice(&String.starts_with?(&1, "PhxPortHandoff is configured"))
      |> apply_igniter!()

    igniter =
      igniter
      |> Igniter.compose_task("phx_port_handoff.install")
      |> assert_unchanged("lib/test/application.ex")

    assert igniter.notices == []
  end

  test "adds the selected endpoint without changing another endpoint's handoff child" do
    for role <- [~s("https"), "configured_role()"] do
      other_children = [
        "{PhxPortHandoff, [otp_app: :test, endpoint: OtherWeb.Endpoint, role: #{role}, handshake_timeout: 250]}",
        "OtherWeb.Endpoint"
      ]

      igniter =
        installer_project(application_with_children(other_children), %{
          "lib/other_web/endpoint.ex" => String.replace(@endpoint, "TestWeb", "OtherWeb")
        })
        |> install_for_endpoint(TestWeb.Endpoint)
        |> assert_application(
          application_with_children(
            other_children ++
              [
                ~s({PhxPortHandoff, [otp_app: :test, endpoint: TestWeb.Endpoint, role: "https"]})
              ]
          )
        )
        |> assert_has_notice(&String.starts_with?(&1, "PhxPortHandoff is configured"))
        |> apply_igniter!()

      igniter =
        igniter
        |> install_for_endpoint(TestWeb.Endpoint)
        |> assert_unchanged()

      assert igniter.notices == []
    end
  end

  test "adds the https role without changing another role for the same endpoint" do
    other_children = [
      ~s({PhxPortHandoff, [otp_app: :test, endpoint: TestWeb.Endpoint, role: "admin", handshake_timeout: 250]})
    ]

    igniter =
      installer_project(application_with_children(other_children))
      |> Igniter.compose_task("phx_port_handoff.install")
      |> assert_application(
        application_with_children(
          other_children ++
            [
              ~s({PhxPortHandoff, [otp_app: :test, endpoint: TestWeb.Endpoint, role: "https"]})
            ]
        )
      )
      |> apply_igniter!()

    igniter =
      igniter
      |> Igniter.compose_task("phx_port_handoff.install")
      |> assert_unchanged()

    assert igniter.notices == []
  end

  test "recognizes aliased existing children with explicit or default https roles" do
    for role <- ["", ~s(, role: "https")] do
      application =
        application_with_children([
          "{Handoff, [endpoint: Endpoint, otp_app: :test, handshake_timeout: 250#{role}]}"
        ])
        |> String.replace(
          "use Application",
          "use Application\nalias PhxPortHandoff, as: Handoff\nalias TestWeb.Endpoint"
        )
        |> format_source()

      igniter =
        installer_project(application)
        |> Igniter.compose_task("phx_port_handoff.install")
        |> assert_unchanged()

      assert igniter.notices == []
    end
  end

  test "requires a manual check when an existing handoff child's target cannot be determined" do
    for child <- [
          "{PhxPortHandoff, handoff_options()}",
          "{PhxPortHandoff, [otp_app: :test, endpoint: configured_endpoint()]}",
          "{PhxPortHandoff, [otp_app: :test, endpoint: TestWeb.Endpoint, role: configured_role()]}"
        ] do
      igniter =
        installer_project(application_with_children([child]))
        |> Igniter.compose_task("phx_port_handoff.install")
        |> assert_has_warning(
          &String.contains?(
            &1,
            "Could not determine the endpoint/role of an existing PhxPortHandoff child."
          )
        )
        |> assert_unchanged()

      assert igniter.notices == []
    end
  end

  test "requires a manual edit without a configured notice for a nonliteral children list" do
    application = String.replace(@application, "children = [", "children = extra_children() ++ [")

    igniter =
      installer_project(application)
      |> Igniter.compose_task("phx_port_handoff.install")
      |> assert_has_warning(&String.contains?(&1, "Could not find a literal `children = [...]`"))
      |> assert_unchanged()

    assert igniter.notices == []
  end

  test "warns without a configured notice when the endpoint is absent from the children list" do
    application = String.replace(@application, "TestWeb.Endpoint", "Test.Worker")

    igniter =
      installer_project(application)
      |> Igniter.compose_task("phx_port_handoff.install")
      |> assert_has_warning("Could not find TestWeb.Endpoint in the application children.")
      |> assert_unchanged()

    assert igniter.notices == []
  end

  test "reports a missing Phoenix endpoint without a configured notice" do
    igniter =
      installer_project(@application, %{
        "lib/test_web/endpoint.ex" => "defmodule TestWeb.Endpoint do\nend\n"
      })
      |> Igniter.compose_task("phx_port_handoff.install")
      |> assert_has_issue(
        "Could not find a Phoenix endpoint. PhxPortHandoff requires a Phoenix/Bandit endpoint."
      )
      |> assert_unchanged()

    assert igniter.notices == []
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

  defp installer_project(application \\ @application, extra_files \\ %{}) do
    test_project(
      files:
        Map.merge(
          %{
            "mix.exs" => @mix_exs,
            "lib/test/application.ex" => application,
            "lib/test_web/endpoint.ex" => @endpoint
          },
          extra_files
        )
    )
  end

  defp application_with_children(children) do
    @application
    |> String.replace("TestWeb.Endpoint", Enum.join(children ++ ["TestWeb.Endpoint"], ",\n"))
    |> format_source()
  end

  defp assert_application(igniter, application) do
    assert_content_equals(igniter, "lib/test/application.ex", format_source(application))
  end

  defp format_source(source) do
    source
    |> Code.format_string!()
    |> IO.iodata_to_binary()
    |> Kernel.<>("\n")
  end

  defp install_for_endpoint(igniter, endpoint) do
    {igniter, endpoints} =
      Igniter.Project.Module.find_all_matching_modules(igniter, fn _module, zipper ->
        Igniter.Code.Module.move_to_use(zipper, Phoenix.Endpoint) != :error
      end)

    assert length(endpoints) == 2
    index = Enum.find_index(endpoints, &(&1 == endpoint))
    assert is_integer(index)

    shell = Mix.shell()
    Mix.shell(Mix.Shell.Process)

    try do
      send(self(), {:mix_shell_input, :prompt, Integer.to_string(index)})
      igniter = Igniter.compose_task(igniter, "phx_port_handoff.install")
      assert_receive {:mix_shell, :prompt, [prompt]}
      assert prompt =~ "#{index}. #{inspect(endpoint)}"
      igniter
    after
      Mix.shell(shell)
    end
  end
end

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
end

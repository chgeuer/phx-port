defmodule PhxpHandoffSample.MixProject do
  use Mix.Project

  def project do
    [
      app: :phxp_handoff_sample,
      version: "0.1.0",
      elixir: "~> 1.20",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :ssl],
      mod: {PhxpHandoffSample.Application, []}
    ]
  end

  defp deps do
    [
      {:bandit, "~> 1.12"},
      {:plug, "~> 1.20"},
      {:phx_port_handoff, path: "../../integrations/elixir/phx_port_handoff"}
    ]
  end
end

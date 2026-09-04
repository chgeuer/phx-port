defmodule PhxPortHandoff.MixProject do
  use Mix.Project

  def project do
    [
      app: :phx_port_handoff,
      version: "0.1.0",
      elixir: "~> 1.20",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:crypto, :logger, :ssl],
      mod: {PhxPortHandoff.Application, []}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:rustler, "~> 0.36.1"},
      {:thousand_island, "~> 1.4"}
    ]
  end
end

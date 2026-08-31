defmodule PhxpHandoffSample.Application do
  use Application

  alias PhxpHandoffSample.Config
  alias PhxpHandoffSample.Plug, as: SamplePlug

  @impl true
  def start(_type, _args) do
    children =
      if Application.fetch_env!(:phxp_handoff_sample, :start_servers) do
        Config.load() |> children()
      else
        []
      end

    Supervisor.start_link(children,
      strategy: :one_for_one,
      name: PhxpHandoffSample.Supervisor
    )
  end

  def children(config) do
    http_options = [
      plug: {SamplePlug, listener: "http"},
      scheme: :http,
      ip: :loopback,
      port: config.port
    ]

    https_options = [
      plug: {SamplePlug, listener: "https"},
      scheme: :https,
      ip: :loopback,
      port: config.https_port,
      certfile: config.tls_cert,
      keyfile: config.tls_key
    ]

    [
      Supervisor.child_spec({Bandit, http_options}, id: :http),
      Supervisor.child_spec({Bandit, https_options}, id: :https),
      PhxPortHandoff.bandit_child_spec(
        {SamplePlug, listener: "phxp-handoff-https"},
        config.project,
        config.role,
        https_options
      )
    ]
  end
end

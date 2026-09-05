defmodule Mix.Tasks.PhxPortHandoff.Install do
  @shortdoc "Installs PhxPortHandoff into a Phoenix application"
  @example "mix igniter.install phx_port_handoff"

  @moduledoc """
  Adds a conditional PhxPortHandoff listener immediately before the Phoenix
  endpoint in the application's supervision tree.

  Run through Igniter:

      #{@example}
  """

  use Mix.Task

  alias PhxPortHandoff.Installer.Loader

  @igniter_args Module.concat(["Igniter", "Mix", "Task", "Args"])
  @igniter_info Module.concat(["Igniter", "Mix", "Task", "Info"])
  @igniter_task Module.concat(["Igniter", "Mix", "Task"])

  @impl Mix.Task
  def run(_argv) do
    Mix.raise("Install PhxPortHandoff with `mix igniter.install phx_port_handoff`.")
  end

  @doc false
  def installer?, do: true

  @doc false
  def supports_umbrella?, do: false

  @doc false
  def info(_argv, _composing_task) do
    struct!(@igniter_info,
      group: :phx_port_handoff,
      example: @example
    )
  end

  @doc false
  def parse_argv(argv) do
    positional_parser = Function.capture(@igniter_task, :__positional_args__!, 2)
    options_parser = Function.capture(@igniter_task, :__options__!, 2)
    {positional, argv_flags} = positional_parser.(__MODULE__, argv)
    options = options_parser.(__MODULE__, argv_flags)

    struct!(@igniter_args,
      positional: positional,
      options: options,
      argv: argv,
      argv_flags: argv_flags
    )
  end

  @doc false
  def igniter(igniter) do
    installer_module = Loader.load!()
    installer = Function.capture(installer_module, :install, 1)
    installer.(igniter)
  end
end

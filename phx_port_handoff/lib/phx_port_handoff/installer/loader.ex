defmodule PhxPortHandoff.Installer.Loader do
  @moduledoc false

  @required_modules [
    "Igniter.Code.Common",
    "Igniter.Code.Function",
    "Igniter.Code.List",
    "Igniter.Code.Tuple",
    "Igniter.Libs.Phoenix",
    "Igniter.Project.Application",
    "Igniter.Project.Module",
    "Sourceror.Zipper"
  ]

  @spec load!() :: :ok
  def load! do
    case unavailable_modules() do
      [] ->
        :phx_port_handoff
        |> Application.app_dir(["priv", "installer", "igniter.exs"])
        |> Code.require_file()

        :ok

      modules ->
        Mix.raise("Igniter installer modules are unavailable: #{Enum.join(modules, ", ")}")
    end
  end

  defp unavailable_modules do
    Enum.reject(@required_modules, fn name ->
      name
      |> module_from_name()
      |> Code.ensure_loaded?()
    end)
  end

  defp module_from_name(name), do: name |> String.split(".") |> Module.concat()
end

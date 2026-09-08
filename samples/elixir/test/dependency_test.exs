defmodule PhxpHandoffSample.DependencyTest do
  use ExUnit.Case, async: false

  test "resolves and compiles the adjacent handoff package" do
    package_path = Path.expand("../../../phx_port_handoff", __DIR__)

    assert %Mix.Dep{scm: Mix.SCM.Path, opts: opts} =
             Enum.find(Mix.Dep.cached(), &(&1.app == :phx_port_handoff))

    assert Keyword.fetch!(opts, :dest) == package_path

    source =
      PhxPortHandoff.module_info(:compile)
      |> Keyword.fetch!(:source)
      |> to_string()

    assert source == Path.join(package_path, "lib/phx_port_handoff.ex")
  end
end

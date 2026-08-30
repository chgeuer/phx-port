defmodule PhxPortHandoffTest do
  use ExUnit.Case

  alias PhxPortHandoff.Native

  test "endpoint path matches the PHXP project and role convention" do
    runtime = System.fetch_env!("XDG_RUNTIME_DIR")
    project = Path.expand("/srv/contoso")

    expected_hash =
      :crypto.hash(:sha256, [project, <<0>>, "https"]) |> Base.encode16(case: :lower)

    assert PhxPortHandoff.endpoint_path(project, "https") ==
             Path.join([runtime, "phx-port", "handoff", expected_hash <> ".sock"])
  end

  test "native broker creates a private seqpacket endpoint" do
    path =
      Path.join([
        System.tmp_dir!(),
        "phxp-#{System.unique_integer([:positive])}",
        "handoff.sock"
      ])

    assert {:ok, broker} = Native.listen(path)
    assert is_reference(broker)
    assert File.stat!(path).mode |> Bitwise.band(0o777) == 0o600
  end

  test "native broker refuses to replace a live endpoint" do
    path =
      Path.join([
        System.tmp_dir!(),
        "phxp-#{System.unique_integer([:positive])}",
        "handoff.sock"
      ])

    assert {:ok, broker} = Native.listen(path)
    assert is_reference(broker)
    assert {:error, message} = Native.listen(path)
    assert message =~ "already listening"
    assert File.exists?(path)
  end

  test "native broker replaces a stale endpoint" do
    path =
      Path.join([
        System.tmp_dir!(),
        "phxp-#{System.unique_integer([:positive])}",
        "handoff.sock"
      ])

    File.mkdir_p!(Path.dirname(path))
    File.write!(path, "stale")

    assert {:ok, broker} = Native.listen(path)
    assert is_reference(broker)
    assert File.stat!(path).type == :other
  end
end

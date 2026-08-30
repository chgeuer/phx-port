defmodule PhxPortHandoff.Native do
  @moduledoc false

  use Rustler,
    otp_app: :phx_port_handoff,
    crate: "phx_port_handoff_native",
    path: "native/phx_port_handoff_native"

  def listen(_path), do: :erlang.nif_error(:nif_not_loaded)
  def close_listener(_broker), do: :erlang.nif_error(:nif_not_loaded)
  def accept(_broker), do: :erlang.nif_error(:nif_not_loaded)
  def take_fd(_receipt), do: :erlang.nif_error(:nif_not_loaded)
  def adopted(_receipt), do: :erlang.nif_error(:nif_not_loaded)
  def rejected(_receipt, _reason_code), do: :erlang.nif_error(:nif_not_loaded)
  def close_fd(_fd), do: :erlang.nif_error(:nif_not_loaded)
end

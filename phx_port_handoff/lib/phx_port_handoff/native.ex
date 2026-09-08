defmodule PhxPortHandoff.Native do
  @moduledoc false

  use Rustler,
    otp_app: :phx_port_handoff,
    crate: "phx_port_handoff_native",
    path: "native/phx_port_handoff_native"

  @accept_retry_delay 10

  def listen(_path), do: :erlang.nif_error(:nif_not_loaded)
  def listen_derived(_path), do: :erlang.nif_error(:nif_not_loaded)
  def close_listener(_broker), do: :erlang.nif_error(:nif_not_loaded)
  def cleanup_pending(), do: :erlang.nif_error(:nif_not_loaded)
  def effective_uid(), do: :erlang.nif_error(:nif_not_loaded)

  def accept(broker) do
    case try_accept(broker) do
      {:error, :eagain} ->
        Process.sleep(@accept_retry_delay)
        accept(broker)

      result ->
        result
    end
  end

  def try_accept(_broker), do: :erlang.nif_error(:nif_not_loaded)
  def take_fd(_receipt), do: :erlang.nif_error(:nif_not_loaded)
  def close_client(_receipt), do: :erlang.nif_error(:nif_not_loaded)
  def adopted(_receipt), do: :erlang.nif_error(:nif_not_loaded)
  def rejected(_receipt, _reason_code), do: :erlang.nif_error(:nif_not_loaded)
  def close_fd(_fd), do: :erlang.nif_error(:nif_not_loaded)
end

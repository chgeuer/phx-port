defmodule PhxPortHandoff.Cleanup do
  @moduledoc false
  use GenServer

  require Logger

  @interval 10

  def start_link(_options), do: GenServer.start_link(__MODULE__, nil, name: __MODULE__)

  @impl true
  def init(nil) do
    {:ok, nil, {:continue, :cleanup}}
  end

  @impl true
  def handle_continue(:cleanup, _state), do: cleanup()

  @impl true
  def handle_info({:timeout, timer, :cleanup}, timer), do: cleanup()

  defp cleanup do
    case PhxPortHandoff.Native.cleanup_pending() do
      {:ok, failures} ->
        if failures > 0 do
          Logger.warning("PHXP endpoint cleanup failed", endpoint_count: failures)
        end

        {:noreply, :erlang.start_timer(@interval, self(), :cleanup)}

      {:error, reason} ->
        {:stop, {:endpoint_cleanup_failed, reason}, nil}
    end
  end
end

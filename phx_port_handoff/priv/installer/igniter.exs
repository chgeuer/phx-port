defmodule PhxPortHandoff.Installer do
  @moduledoc false

  require Igniter.Code.Function

  @spec install(Igniter.t()) :: Igniter.t()
  def install(igniter) do
    otp_app = Igniter.Project.Application.app_name(igniter)
    {igniter, endpoint} = Igniter.Libs.Phoenix.select_endpoint(igniter)

    if endpoint do
      igniter
      |> add_handoff_child(otp_app, endpoint)
      |> Igniter.add_notice("""
      PhxPortHandoff is configured immediately before #{inspect(endpoint)}.

      Export HTTPS_PORT from `phx-port https` before starting Phoenix, then
      verify that `successful_handoffs` increases in `phx-port proxy status --json`.
      """)
    else
      Igniter.add_issue(
        igniter,
        "Could not find a Phoenix endpoint. PhxPortHandoff requires a Phoenix/Bandit endpoint."
      )
    end
  end

  @spec supports_umbrella?() :: false
  def supports_umbrella?, do: false

  defp add_handoff_child(igniter, otp_app, endpoint) do
    application = Igniter.Project.Application.app_module(igniter)

    child =
      quote do
        {PhxPortHandoff,
         [
           otp_app: unquote(otp_app),
           endpoint: unquote(endpoint),
           role: "https"
         ]}
      end

    Igniter.Project.Module.find_and_update_module!(igniter, application, fn zipper ->
      with {:ok, zipper} <- Igniter.Code.Function.move_to_def(zipper, :start, 2),
           {:ok, zipper} <- move_to_children_list(zipper) do
        insert_before_endpoint(zipper, child, endpoint)
      else
        _ ->
          {:warning,
           """
           Could not find a literal `children = [...]` assignment in
           `#{inspect(application)}`. Add the following child immediately before
           `#{inspect(endpoint)}`:

               #{Sourceror.to_string(child)}
           """}
      end
    end)
  end

  defp move_to_children_list(zipper) do
    with {:ok, zipper} <-
           Igniter.Code.Function.move_to_function_call_in_current_scope(
             zipper,
             :=,
             [2],
             fn call ->
               Igniter.Code.Function.argument_matches_pattern?(
                 call,
                 0,
                 {:children, _, context} when is_atom(context)
               ) &&
                 Igniter.Code.Function.argument_matches_pattern?(
                   call,
                   1,
                   value when is_list(value)
                 )
             end
           ) do
      Igniter.Code.Function.move_to_nth_argument(zipper, 1)
    end
  end

  defp insert_before_endpoint(children, child, endpoint) do
    case Igniter.Code.List.move_to_list_item(
           children,
           &child_module_matches?(&1, PhxPortHandoff)
         ) do
      {:ok, _zipper} ->
        {:ok, children}

      :error ->
        case Igniter.Code.List.move_to_list_item(
               children,
               &child_module_matches?(&1, endpoint)
             ) do
          {:ok, zipper} -> {:ok, Sourceror.Zipper.insert_left(zipper, child)}
          :error -> {:warning, "Could not find #{inspect(endpoint)} in the application children."}
        end
    end
  end

  defp child_module_matches?(zipper, expected) do
    module =
      if Igniter.Code.Tuple.tuple?(zipper) do
        Igniter.Code.Tuple.tuple_elem(zipper, 0)
      else
        {:ok, zipper}
      end

    case module do
      {:ok, module} ->
        module
        |> Igniter.Code.Common.expand_alias()
        |> Igniter.Code.Common.nodes_equal?(expected)

      :error ->
        false
    end
  end
end

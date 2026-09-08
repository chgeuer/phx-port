defmodule PhxPortHandoff.Installer do
  @moduledoc false

  require Igniter.Code.Function

  @spec install(Igniter.t()) :: Igniter.t()
  def install(igniter) do
    otp_app = Igniter.Project.Application.app_name(igniter)
    {igniter, endpoint} = Igniter.Libs.Phoenix.select_endpoint(igniter)

    if endpoint do
      add_handoff_child(igniter, otp_app, endpoint)
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

    update_children = fn zipper ->
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
    end

    {igniter, _source, zipper} = Igniter.Project.Module.find_module!(igniter, application)
    {:ok, zipper} = Igniter.Code.Common.move_to_do_block(zipper)

    case update_children.(zipper) do
      :already_present ->
        igniter

      {:warning, warning} ->
        Igniter.add_warning(igniter, warning)

      {:ok, _zipper} ->
        igniter
        |> Igniter.Project.Module.find_and_update_module!(application, update_children)
        |> Igniter.add_notice("""
        PhxPortHandoff is configured immediately before #{inspect(endpoint)}.

        Export HTTPS_PORT from `phx-port https` before starting Phoenix, then
        verify that `successful_handoffs` increases in `phx-port proxy status --json`.
        """)
    end
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
    with :error <-
           Igniter.Code.List.move_to_list_item(
             children,
             &(handoff_child_match(&1, endpoint) == :match)
           ),
         :error <-
           Igniter.Code.List.move_to_list_item(
             children,
             &(handoff_child_match(&1, endpoint) == :unknown)
           ),
         {:ok, zipper} <-
           Igniter.Code.List.move_to_list_item(
             children,
             &child_module_matches?(&1, endpoint)
           ) do
      {:ok, Sourceror.Zipper.insert_left(zipper, child)}
    else
      {:ok, zipper} ->
        case handoff_child_match(zipper, endpoint) do
          :match ->
            :already_present

          :unknown ->
            {:warning,
             """
             Could not determine the endpoint/role of an existing PhxPortHandoff child.
             Check it manually before adding handoff for #{inspect(endpoint)} (role "https").
             """}
        end

      :error ->
        {:warning, "Could not find #{inspect(endpoint)} in the application children."}
    end
  end

  defp handoff_child_match(zipper, endpoint) do
    with true <- child_module_matches?(zipper, PhxPortHandoff),
         {:ok, options} <- Igniter.Code.Tuple.tuple_elem(zipper, 1),
         {:ok, child_endpoint} <- Igniter.Code.Keyword.get_key(options, :endpoint),
         {:ok, child_endpoint} <-
           child_endpoint
           |> Igniter.Code.Common.expand_alias()
           |> Igniter.Code.Common.expand_literal() do
      if child_endpoint == endpoint do
        handoff_role_match(options)
      else
        :different
      end
    else
      false -> :different
      :error -> :unknown
    end
  end

  defp handoff_role_match(options) do
    case Igniter.Code.Keyword.get_key(options, :role) do
      :error ->
        :match

      {:ok, role} ->
        case Igniter.Code.Common.expand_literal(role) do
          {:ok, "https"} -> :match
          {:ok, _role} -> :different
          :error -> :unknown
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

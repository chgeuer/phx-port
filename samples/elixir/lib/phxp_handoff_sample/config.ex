defmodule PhxpHandoffSample.Config do
  @enforce_keys [:port, :https_port, :tls_cert, :tls_key, :project, :role]
  defstruct @enforce_keys

  def load(options \\ []) do
    argv = Keyword.get(options, :argv, System.argv())
    env = Keyword.get(options, :env, &System.get_env/1)
    app_config = Keyword.get(options, :app_config, Application.get_all_env(:phxp_handoff_sample))
    cwd = Keyword.get(options, :cwd, File.cwd!())

    %__MODULE__{
      port: port!(env.("PORT") || app_config[:port], "PORT"),
      https_port: port!(env.("HTTPS_PORT") || app_config[:https_port], "HTTPS_PORT"),
      tls_cert:
        cli_value(argv, "--cert") || env.("PHXP_TLS_CERT") || app_config[:tls_cert] ||
          raise("TLS certificate must be set with --cert, PHXP_TLS_CERT, or application config"),
      tls_key:
        cli_value(argv, "--key") || env.("PHXP_TLS_KEY") || app_config[:tls_key] ||
          raise("TLS private key must be set with --key, PHXP_TLS_KEY, or application config"),
      project:
        Path.expand(
          cli_value(argv, "--project") || env.("PHXP_PROJECT") || app_config[:project] || cwd
        ),
      role: cli_value(argv, "--role") || env.("PHXP_ROLE") || app_config[:role] || "https"
    }
  end

  defp port!(nil, name), do: raise("#{name} must be set")

  defp port!(value, name) do
    case Integer.parse(to_string(value)) do
      {port, ""} when port in 1..65_535 -> port
      _ -> raise "#{name} must be an integer from 1 through 65535"
    end
  end

  defp cli_value(argv, flag) do
    Enum.reduce_while(argv, nil, fn
      ^flag, _ ->
        {:halt, :next}

      argument, _ ->
        case String.split(argument, "=", parts: 2) do
          [^flag, value] -> {:halt, value}
          _ -> {:cont, nil}
        end
    end)
    |> case do
      :next ->
        argv
        |> Enum.drop_while(&(&1 != flag))
        |> Enum.at(1)

      value ->
        value
    end
  end
end

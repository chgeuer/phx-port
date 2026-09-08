defmodule PhxpHandoffSample.Config do
  @enforce_keys [:port, :https_port, :tls_cert, :tls_key, :project, :role]
  defstruct @enforce_keys

  def load(options \\ []) do
    argv = Keyword.get(options, :argv, System.argv())
    env = Keyword.get(options, :env, &System.get_env/1)
    app_config = Keyword.get(options, :app_config, Application.get_all_env(:phxp_handoff_sample))
    cwd = Keyword.get(options, :cwd, File.cwd!())
    cli = parse_argv!(argv)

    %__MODULE__{
      port: port!(env.("PORT") || app_config[:port], "PORT"),
      https_port: port!(env.("HTTPS_PORT") || app_config[:https_port], "HTTPS_PORT"),
      tls_cert:
        string!(
          cli[:cert] || env.("PHXP_TLS_CERT") || app_config[:tls_cert] ||
            raise("TLS certificate must be set with --cert, PHXP_TLS_CERT, or application config"),
          "TLS certificate (--cert, PHXP_TLS_CERT, :tls_cert)"
        ),
      tls_key:
        string!(
          cli[:key] || env.("PHXP_TLS_KEY") || app_config[:tls_key] ||
            raise("TLS private key must be set with --key, PHXP_TLS_KEY, or application config"),
          "TLS private key (--key, PHXP_TLS_KEY, :tls_key)"
        ),
      project:
        (cli[:project] || env.("PHXP_PROJECT") || app_config[:project] || cwd)
        |> string!("project (--project, PHXP_PROJECT, :project)")
        |> Path.expand(),
      role:
        string!(
          cli[:role] || env.("PHXP_ROLE") || app_config[:role] || "https",
          "role (--role, PHXP_ROLE, :role)"
        )
    }
  end

  defp port!(nil, name), do: raise("#{name} must be set")

  defp port!(value, name) do
    case Integer.parse(to_string(value)) do
      {port, ""} when port in 1..65_535 -> port
      _ -> raise "#{name} must be an integer from 1 through 65535"
    end
  end

  defp parse_argv!(argv) do
    {options, positional} =
      OptionParser.parse!(argv, strict: [cert: :keep, key: :keep, project: :keep, role: :keep])

    if positional != [] do
      raise ArgumentError, "unexpected positional arguments: #{inspect(positional)}"
    end

    Enum.each(options, fn {name, value} -> string!(value, "--#{name}") end)
    options
  end

  defp string!(value, _name) when is_binary(value) and byte_size(value) > 0, do: value
  defp string!(_value, name), do: raise(ArgumentError, "#{name} must be a non-empty string")
end

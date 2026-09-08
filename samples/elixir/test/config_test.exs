defmodule PhxpHandoffSample.ConfigTest do
  use ExUnit.Case, async: true

  alias PhxpHandoffSample.Config

  test "uses stable listener ports and explicit TLS configuration" do
    env = %{
      "PORT" => "4101",
      "HTTPS_PORT" => "4102",
      "PHXP_TLS_CERT" => "/certs/server.crt",
      "PHXP_TLS_KEY" => "/certs/server.key"
    }

    config =
      Config.load(
        argv: [],
        env: &env[&1],
        app_config: [],
        cwd: "/work/phx-port/samples/elixir"
      )

    assert config.port == 4101
    assert config.https_port == 4102

    assert config.tls_cert == "/certs/server.crt"
    assert config.tls_key == "/certs/server.key"

    assert config.project == "/work/phx-port/samples/elixir"
    assert config.role == "https"
  end

  test "requires a certificate and private key" do
    env = %{"PORT" => "4101", "HTTPS_PORT" => "4102"}

    assert_raise RuntimeError, ~r/TLS certificate must be set/, fn ->
      Config.load(argv: [], env: &env[&1], app_config: [], cwd: ".")
    end
  end

  test "CLI certificate options override environment and application config" do
    env = %{
      "PORT" => "4201",
      "HTTPS_PORT" => "4202",
      "PHXP_TLS_CERT" => "/env/cert.pem",
      "PHXP_TLS_KEY" => "/env/key.pem"
    }

    config =
      Config.load(
        argv: ["--cert=/cli/cert.pem", "--key", "/cli/key.pem"],
        env: &env[&1],
        app_config: [tls_cert: "/config/cert.pem", tls_key: "/config/key.pem"],
        home: "/unused",
        cwd: "."
      )

    assert config.tls_cert == "/cli/cert.pem"
    assert config.tls_key == "/cli/key.pem"
  end

  test "accepts all documented options in separated and equals forms" do
    values = [
      cert: "/cli/cert.pem",
      key: "/cli/key.pem",
      project: "/cli/project",
      role: "custom-https"
    ]

    for form <- [:separated, :equals] do
      argv =
        Enum.flat_map(values, fn {name, value} ->
          case form do
            :separated -> ["--#{name}", value]
            :equals -> ["--#{name}=#{value}"]
          end
        end)

      config = load_config(argv: argv)

      assert config.tls_cert == values[:cert]
      assert config.tls_key == values[:key]
      assert config.project == values[:project]
      assert config.role == values[:role]
      assert config.port == 4101
      assert config.https_port == 4102
    end
  end

  test "preserves CLI then environment then application config precedence" do
    env = %{
      "PORT" => "4201",
      "HTTPS_PORT" => "4202",
      "PHXP_TLS_CERT" => "/env/cert.pem",
      "PHXP_TLS_KEY" => "/env/key.pem",
      "PHXP_PROJECT" => "/env/project",
      "PHXP_ROLE" => "env-https"
    }

    app_config = [
      port: 4301,
      https_port: 4302,
      tls_cert: "/config/cert.pem",
      tls_key: "/config/key.pem",
      project: "/config/project",
      role: "config-https"
    ]

    config =
      load_config(
        argv: ["--cert", "/cli/cert.pem", "--role=cli-https"],
        env: &env[&1],
        app_config: app_config
      )

    assert config == %Config{
             port: 4201,
             https_port: 4202,
             tls_cert: "/cli/cert.pem",
             tls_key: "/env/key.pem",
             project: "/env/project",
             role: "cli-https"
           }

    assert load_config(env: fn _ -> nil end, app_config: app_config) ==
             struct!(Config, app_config)
  end

  test "preserves the first value of repeated options" do
    config =
      load_config(
        argv: [
          "--cert=/first/cert.pem",
          "--cert",
          "/second/cert.pem",
          "--key",
          "/first/key.pem",
          "--key=/second/key.pem",
          "--project=/first/project",
          "--project=/second/project",
          "--role=first",
          "--role=second"
        ]
      )

    assert config.tls_cert == "/first/cert.pem"
    assert config.tls_key == "/first/key.pem"
    assert config.project == "/first/project"
    assert config.role == "first"
  end

  test "expands relative project paths without changing other option values" do
    config = load_config(argv: ["--project=relative/project", "--cert=relative/cert.pem"])

    assert config.project == Path.expand("relative/project")
    assert config.tls_cert == "relative/cert.pem"
  end

  test "rejects missing option values instead of falling back to valid environment values" do
    for flag <- ["--cert", "--key", "--project", "--role"] do
      assert_raise OptionParser.ParseError, ~r/#{flag}.*Missing argument/, fn ->
        load_config(argv: [flag])
      end
    end
  end

  test "does not consume another option as a missing value" do
    for flag <- ["--cert", "--key", "--project", "--role"] do
      assert_raise OptionParser.ParseError, ~r/#{flag}.*Missing argument/, fn ->
        load_config(argv: [flag, "--role=https"])
      end
    end
  end

  test "rejects unknown options even after valid options" do
    for unknown <- ["--unknown", "--port=4103", "--https-port=4104", "-x"] do
      assert_raise OptionParser.ParseError, ~r/Unknown option/, fn ->
        load_config(argv: ["--role=https", unknown])
      end
    end
  end

  test "rejects positional arguments including those after the option terminator" do
    for argv <- [
          ["unexpected"],
          ["--role=https", "unexpected"],
          ["unexpected", "--role=https"],
          ["--", "unexpected"],
          ["--", "--role=https"]
        ] do
      assert_raise ArgumentError, ~r/unexpected positional argument/, fn ->
        load_config(argv: argv)
      end
    end
  end

  test "accepts an option terminator without positional arguments" do
    assert load_config(argv: ["--"]).role == "https"
  end

  test "rejects empty CLI values in both supported forms" do
    for flag <- ["--cert", "--key", "--project", "--role"],
        argv <- [[flag, ""], ["#{flag}="]] do
      assert_raise ArgumentError, ~r/#{flag}.*non-empty string/, fn ->
        load_config(argv: argv)
      end
    end
  end

  test "validates every repeated value rather than hiding malformed explicit input" do
    for argv <- [
          ["--role=https", "--role"],
          ["--role", "--role=https"]
        ] do
      assert_raise OptionParser.ParseError, ~r/--role.*Missing argument/, fn ->
        load_config(argv: argv)
      end
    end

    for argv <- [
          ["--role=https", "--role="],
          ["--role=", "--role=https"]
        ] do
      assert_raise ArgumentError, ~r/--role.*non-empty string/, fn ->
        load_config(argv: argv)
      end
    end
  end

  test "rejects empty environment and application values rather than using defaults" do
    for {name, key} <- [
          {"PHXP_TLS_CERT", :tls_cert},
          {"PHXP_TLS_KEY", :tls_key},
          {"PHXP_PROJECT", :project},
          {"PHXP_ROLE", :role}
        ] do
      env = Map.put(valid_env(), name, "")

      assert_raise ArgumentError, ~r/#{name}.*non-empty string/, fn ->
        load_config(env: &env[&1])
      end

      env = Map.delete(valid_env(), name)

      assert_raise ArgumentError, ~r/#{key}.*non-empty string/, fn ->
        load_config(env: &env[&1], app_config: [{key, ""}])
      end
    end
  end

  test "requires each listener port" do
    for name <- ["PORT", "HTTPS_PORT"] do
      env = Map.delete(valid_env(), name)

      assert_raise RuntimeError, "#{name} must be set", fn ->
        load_config(env: &env[&1])
      end
    end
  end

  test "rejects invalid listener ports instead of falling back to application config" do
    for name <- ["PORT", "HTTPS_PORT"],
        value <- ["", "0", "-1", "65536", "4101x", "4101.5", " 4101", "4101 "] do
      env = Map.put(valid_env(), name, value)

      assert_raise RuntimeError, "#{name} must be an integer from 1 through 65535", fn ->
        load_config(env: &env[&1], app_config: [port: 4301, https_port: 4302])
      end
    end
  end

  test "accepts boundary ports from environment and application config" do
    env = Map.merge(valid_env(), %{"PORT" => "1", "HTTPS_PORT" => "65535"})
    config = load_config(env: &env[&1])
    assert config.port == 1
    assert config.https_port == 65_535

    env = Map.drop(env, ["PORT", "HTTPS_PORT"])
    config = load_config(env: &env[&1], app_config: [port: 65_535, https_port: 1])
    assert config.port == 65_535
    assert config.https_port == 1
  end

  defp load_config(options) do
    env = valid_env()

    [argv: [], env: &env[&1], app_config: [], cwd: "/work/phx-port/samples/elixir"]
    |> Keyword.merge(options)
    |> Config.load()
  end

  defp valid_env do
    %{
      "PORT" => "4101",
      "HTTPS_PORT" => "4102",
      "PHXP_TLS_CERT" => "/env/cert.pem",
      "PHXP_TLS_KEY" => "/env/key.pem",
      "PHXP_PROJECT" => "/env/project",
      "PHXP_ROLE" => "https"
    }
  end
end

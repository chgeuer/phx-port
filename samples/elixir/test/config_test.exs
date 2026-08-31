defmodule PhxpHandoffSample.ConfigTest do
  use ExUnit.Case, async: true

  alias PhxpHandoffSample.Config

  test "uses stable listener ports and portable TLS defaults" do
    env = %{"PORT" => "4101", "HTTPS_PORT" => "4102"}

    config =
      Config.load(
        argv: [],
        env: &env[&1],
        app_config: [],
        home: "/users/alice",
        cwd: "/work/phx-port/samples/elixir"
      )

    assert config.port == 4101
    assert config.https_port == 4102

    assert config.tls_cert ==
             "/users/alice/.dns/production/alias-alpha.phx-port.pollmann.rocks.crt"

    assert config.tls_key ==
             "/users/alice/.dns/production/alias-alpha.phx-port.pollmann.rocks.key"

    assert config.project == "/work/phx-port/samples/elixir"
    assert config.role == "https"
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
end

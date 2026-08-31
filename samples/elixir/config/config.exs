import Config

config :phxp_handoff_sample, start_servers: true

if config_env() == :test do
  config :phxp_handoff_sample, start_servers: false
end

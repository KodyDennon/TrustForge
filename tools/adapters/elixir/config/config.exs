import Config

config :trustforge,
  daemon_url: System.get_env("TRUSTFORGE_DAEMON_URL", "http://127.0.0.1:8787"),
  admin_token: System.get_env("TRUSTFORGE_ADMIN_TOKEN"),
  timeout_ms: 5_000,
  mode: :enforce

defmodule TrustForge.Umbrella.MixProject do
  use Mix.Project

  def project do
    [
      apps_path: "apps",
      version: "0.1.0",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases()
    ]
  end

  # Dependencies listed at the umbrella level are global to all apps.
  # Adapter-specific deps live in each app's own mix.exs.
  defp deps do
    []
  end

  defp aliases do
    [
      test: ["test --no-start"]
    ]
  end
end

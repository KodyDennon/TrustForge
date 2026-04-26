defmodule TrustForge.MixProject do
  use Mix.Project

  def project do
    [
      app: :trustforge,
      version: "0.1.0",
      build_path: "../../_build",
      config_path: "../../config/config.exs",
      deps_path: "../../deps",
      lockfile: "../../mix.lock",
      elixir: "~> 1.14",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger, :inets, :ssl, :crypto, :public_key]
    ]
  end

  defp deps do
    [
      {:jason, "~> 1.4"}
    ]
  end
end

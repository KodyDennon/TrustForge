defmodule TrustForge.Phoenix.MixProject do
  use Mix.Project

  def project do
    [
      app: :trustforge_phoenix,
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
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:trustforge, in_umbrella: true},
      {:trustforge_plug, in_umbrella: true},
      {:plug, "~> 1.15"},
      {:phoenix, "~> 1.7"},
      {:jason, "~> 1.4"}
    ]
  end
end

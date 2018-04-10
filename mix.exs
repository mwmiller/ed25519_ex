defmodule Ed25519.Mixfile do
  use Mix.Project

  def project do
    [
      app: :ed25519,
      version: "1.3.0",
      elixir: "~> 1.5",
      name: "Ed25519",
      source_url: "https://github.com/mwmiller/ed25519_ex",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      description: description(),
      package: package(),
      deps: deps()
    ]
  end

  def application do
    []
  end

  defp deps do
    [
      {:earmark, "~> 1.0", only: :dev},
      {:ex_doc, "~> 0.18", only: :dev},
      {:credo, "~> 0.8", only: [:dev, :test]}
    ]
  end

  defp description do
    """
    Ed25519 signature functions
    """
  end

  defp package do
    [
      files: ["lib", "mix.exs", "README*", "LICENSE*"],
      maintainers: ["Matt Miller"],
      licenses: ["MIT"],
      links: %{
        "GitHub" => "https://github.com/mwmiller/ed25519_ex",
        "Info" => "http://ed25519.cr.yp.to"
      }
    ]
  end
end

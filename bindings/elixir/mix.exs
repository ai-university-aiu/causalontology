defmodule Causalontology.MixProject do
  use Mix.Project

  @source_url "https://github.com/ai-university-aiu/causalontology"

  def project do
    [
      app: :causalontology,
      version: "2.0.0",
      elixir: "~> 1.16",
      start_permanent: Mix.env() == :prod,
      deps: [],
      description: description(),
      package: package(),
      name: "causalontology",
      source_url: @source_url
    ]
  end

  def application do
    # OTP :crypto carries SHA-256 and Ed25519 (RFC 8032); no Hex dependencies.
    [extra_applications: [:crypto]]
  end

  defp description do
    "The Elixir binding of the Causalontology standard - reified causation " <>
      "as a language-neutral standard and shared commons. OTP stdlib only: " <>
      "RFC 8785 canonicalization, SHA-256 identity, Ed25519 signing, and a " <>
      "conformant store. Passes all 38 frozen vectors."
  end

  defp package do
    [
      licenses: ["Apache-2.0"],
      maintainers: ["AI University (AIU)"],
      links: %{
        "GitHub" => @source_url,
        "Specification" => @source_url <> "/tree/main/spec"
      },
      files: ["lib", "mix.exs", "README.md", "LICENSE", "conformance.exs"]
    ]
  end
end

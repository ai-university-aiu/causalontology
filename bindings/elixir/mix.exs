defmodule Causalontology.MixProject do
  use Mix.Project

  @source_url "https://github.com/ai-university-aiu/causalontology"

  def project do
    [
      app: :causalontology,
      version: "1.0.0",
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
    "The Elixir binding of the Causalontology standard - a verb-first " <>
      "noun-hosting ontology; a language-neutral standard and shared commons " <>
      "for reified causation. OTP standard library only: RFC 8785 " <>
      "canonicalization, SHA-256 identity, Ed25519 (RFC 8032) via :crypto, " <>
      "schema and semantics validation, and an in-memory conformant store."
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

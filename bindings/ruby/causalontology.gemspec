# frozen_string_literal: false

# The gem manifest of causalontology-ruby, the Ruby binding of the
# Causalontology standard. Zero runtime dependencies beyond the Ruby
# standard library (json, digest).

Gem::Specification.new do |spec|
  spec.name = "causalontology"
  spec.version = "4.0.0"
  spec.authors = ["AI University (AIU)"]
  spec.email = ["ai.university.aiu@gmail.com"]

  spec.summary = "The Ruby binding of the Causalontology standard"
  spec.description =
    "The Ruby binding of the Causalontology standard - a verb-first " \
    "noun-hosting ontology; a programming-language-neutral standard and shared commons " \
    "for reified causation. Zero dependencies: RFC 8785 canonicalization, " \
    "SHA-256 identity, pure-Ruby Ed25519 (RFC 8032), schema and semantics " \
    "validation, and an in-memory conformant store."
  spec.homepage = "https://github.com/ai-university-aiu/causalontology"

  # RubyGems has no identifier for this license; the full name is recorded
  # in the metadata below and the text ships in LICENSE and NOTICE.
  spec.license = "Nonstandard"

  spec.metadata = {
    "homepage_uri"      => "https://github.com/ai-university-aiu/causalontology",
    "source_code_uri"   =>
      "https://github.com/ai-university-aiu/causalontology/tree/main/bindings/ruby",
    "documentation_uri" =>
      "https://github.com/ai-university-aiu/causalontology/tree/main/spec",
    "license_note"      =>
      "The attribution always; no profit, no problem license. " \
      "(Apache License 2.0 text) - see LICENSE and NOTICE in the repository root.",
  }

  spec.required_ruby_version = ">= 3.0"

  spec.files = [
    "lib/causalontology.rb",
    "lib/causalontology/jcs.rb",
    "lib/causalontology/canonical.rb",
    "lib/causalontology/ed25519.rb",
    "lib/causalontology/signing.rb",
    "lib/causalontology/schema.rb",
    "lib/causalontology/semantics.rb",
    "lib/causalontology/store.rb",
    "conformance.rb",
    "README.md",
    "LICENSE",
  ]
  spec.require_paths = ["lib"]
end

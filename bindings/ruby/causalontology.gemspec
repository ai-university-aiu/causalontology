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

  # The twenty-one JSON Schema files vendored under
  # lib/causalontology/spec/schema. Without them the installed gem cannot
  # validate anything: Schema.schema_dir falls through to a repository-relative
  # path that does not exist inside a gem, and every vector that validates
  # raises Errno::ENOENT.
  vendored_root = File.join(__dir__, "lib", "causalontology")
  vendored_dir  = File.join(vendored_root, "spec", "schema")
  vendored = Dir.glob("spec/schema/*.schema.json", base: vendored_root).sort

  # Pack-time guards. A silently empty or stale glob is exactly how a gem with
  # zero schemas reached a registry once; fail the build instead of shipping
  # an artifact that cannot validate.
  if vendored.empty?
    raise "causalontology.gemspec: no vendored schemas found under " \
          "#{vendored_dir} - copy spec/schema/*.schema.json there before packing"
  end

  # bindings/ruby -> bindings -> repository root. Absent when building from
  # somewhere other than a checkout, in which case only the guard above applies.
  repo_schema_dir = File.expand_path("../../spec/schema", __dir__)
  if File.directory?(repo_schema_dir)
    expected = Dir.glob("*.schema.json", base: repo_schema_dir).sort
    missing  = expected - vendored.map { |rel| File.basename(rel) }
    unless missing.empty?
      raise "causalontology.gemspec: vendored schemas incomplete, missing " \
            "#{missing.join(', ')} under #{vendored_dir} - re-copy from spec/schema"
    end
    drift = expected.reject do |name|
      File.binread(File.join(repo_schema_dir, name)) ==
        File.binread(File.join(vendored_dir, name))
    end
    unless drift.empty?
      raise "causalontology.gemspec: vendored schemas differ from spec/schema " \
            "(#{drift.join(', ')}) - re-copy before packing"
    end
  end

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
  ] + vendored.map { |rel| File.join("lib", "causalontology", rel) }

  spec.require_paths = ["lib"]
end

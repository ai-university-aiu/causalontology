# frozen_string_literal: false

# causalontology - the Ruby binding of the Causalontology standard.
#
# A faithful port of causalontology-py, proving language independence:
# standard library only (json, digest), conformant when it passes every
# vector in conformance/vectors/ (run bindings/ruby/conformance.rb).
#
# Causalontology is a verb-first noun-hosting ontology: reality is what
# happens, and things are its participants.

require "json"
require "digest"
require "set"

require_relative "causalontology/jcs"
require_relative "causalontology/canonical"
require_relative "causalontology/ed25519"
require_relative "causalontology/signing"
require_relative "causalontology/schema"
require_relative "causalontology/semantics"
require_relative "causalontology/store"

module Causalontology
  VERSION = "1.0.0" # specification 1.0.0 (vectors frozen 2026-07-13)

  # Rule 4's fixed unit-conversion constants, re-exported at the top level.
  UNIT_SECONDS = Semantics::UNIT_SECONDS

  module_function

  # -- canonicalization and identity (spec/identity.md) ---------------------

  def canonicalize(obj, kind = nil)
    Canonical.canonicalize(obj, kind)
  end

  def identify(obj, kind = nil)
    Canonical.identify(obj, kind)
  end

  def identity_bearing(obj, kind = nil)
    Canonical.identity_bearing(obj, kind)
  end

  def infer_kind(obj)
    Canonical.infer_kind(obj)
  end

  # -- validation (spec/schema/, spec/semantics.md) --------------------------

  def validate_schema(obj, kind = nil)
    Schema.validate_schema(obj, kind)
  end

  def validate_semantics(obj, kind = nil)
    Semantics.validate_semantics(obj, kind)
  end

  def is_partial(cro)
    Semantics.is_partial(cro)
  end

  def admissible(cro, elapsed_seconds)
    Semantics.admissible(cro, elapsed_seconds)
  end

  def conflicts(a, b)
    Semantics.conflicts(a, b)
  end

  def refinement_valid(child, parent)
    Semantics.refinement_valid(child, parent)
  end

  def hierarchy_consistent(parent, members)
    Semantics.hierarchy_consistent(parent, members)
  end

  # -- provenance (spec/provenance.md) ---------------------------------------

  def keypair_from_seed(seed32)
    Signing.keypair_from_seed(seed32)
  end

  def sign_record(record, secret, kind = nil)
    Signing.sign_record(record, secret, kind)
  end

  def verify_record(record, kind = nil)
    Signing.verify_record(record, kind)
  end
end

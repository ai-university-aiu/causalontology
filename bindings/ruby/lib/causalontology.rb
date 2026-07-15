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
  VERSION = "2.0.0" # specification 2.0.0 (whole-word re-mint; vectors re-frozen)

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

  def hierarchy_consistent(parent, members, bridges = [])
    Semantics.hierarchy_consistent(parent, members, bridges)
  end

  # -- 2.0.0 normative algorithms and rules (spec/semantics.md, Section 12) --

  def bridge_closure(occurrent_id, bridges)
    Semantics.bridge_closure(occurrent_id, bridges)
  end

  def classify_cro(cro, occ_map, stratum_map)
    Semantics.classify_cro(cro, occ_map, stratum_map)
  end

  def endpoints_mixed(cro, occ_map)
    Semantics.endpoints_mixed(cro, occ_map)
  end

  def skip_gaps(cro, classification)
    Semantics.skip_gaps(cro, classification)
  end

  def to_seconds(duration, unit)
    Semantics.to_seconds(duration, unit)
  end

  def delay_within_window(actual_delay, temporal)
    Semantics.delay_within_window(actual_delay, temporal)
  end

  def bridge_wellformed(bridge, occ_map, stratum_map)
    Semantics.bridge_wellformed(bridge, occ_map, stratum_map)
  end

  def conduit_wellformed(conduit, port_map, cro_map = nil)
    Semantics.conduit_wellformed(conduit, port_map, cro_map)
  end

  def state_gaps(state, quality)
    Semantics.state_gaps(state, quality)
  end

  def covering_law_mismatch(tcc, token_map, law)
    Semantics.covering_law_mismatch(tcc, token_map, law)
  end

  def retrocausal(tcc, token_map)
    Semantics.retrocausal(tcc, token_map)
  end

  def has_cycle(edges)
    Semantics.has_cycle(edges)
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

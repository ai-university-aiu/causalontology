# frozen_string_literal: false

# Canonicalization and content-addressed identity.
#
# Implements the identity procedure of spec/identity.md:
#   1. take the object as JSON,
#   2. keep only the identity-bearing fields for its kind (with "type" injected),
#   3. serialize with the JSON Canonicalization Scheme (RFC 8785),
#   4. hash with SHA-256,
#   5. identifier = scheme + ":" + lowercase hex digest.

require "digest"
require_relative "jcs"

module Causalontology
  module Canonical
    # The identity-bearing fields of each of the twenty-one kinds (3.0.0 adds the
    # cross_stratal_seam; the conduit gains realized_by; 4.0.0 adds the attitude,
    # the predicted_occurrence, and the prediction_error - all additive and
    # identity-preserving - a record that omits a new field keeps its earlier
    # identifier byte-for-byte, and the new kinds open new identity schemes that
    # disturb no existing record). "type" is always injected, so it is not listed
    # here. Order does not matter (JCS sorts keys).
    IDENTITY_FIELDS = {
      # ---- type tier ----
      "occurrent"  => ["label", "category", "stratum"],
      "causal_relation_object" => ["causes", "effects", "mechanism", "temporal",
                                   "modality", "context", "refines", "skips"],
      "continuant" => ["label", "category"],
      "realizable" => ["kind", "bearer", "label"],
      "stratum"    => ["label", "scheme", "ordinal", "unit", "governs"],
      "bridge"     => ["coarse", "fine", "relation"],
      "cross_stratal_seam" => ["source", "target", "mechanism_status", "chain"],
      "port"       => ["bearer", "label", "direction", "accepts", "realizable"],
      "conduit"    => ["label", "from", "to", "carries", "transform",
                       "realized_by"],
      "quality"    => ["label", "datatype", "unit", "stratum"],
      # ---- token tier ----
      "token_individual"   => ["instantiates", "designator", "part_of"],
      "token_occurrence"   => ["instantiates", "interval", "participants",
                               "locus", "observer"],
      "state_assertion"    => ["subject", "quality", "value", "interval"],
      "token_causal_claim" => ["causes", "effects", "covering_law",
                               "actual_delay", "counterfactual"],
      "attitude"             => ["holder", "attitude_type", "content"],
      "predicted_occurrence" => ["instantiates", "interval", "predictor",
                                 "strength"],
      "prediction_error"     => ["predicted", "observed", "discrepancy"],
      # ---- provenance tier ----
      "assertion"  => ["about", "source", "evidence_type", "evidence", "strength",
                       "confidence", "timestamp", "evidenced_by"],
      "enrichment" => ["about", "field", "entry", "source", "timestamp"],
      "retraction" => ["retracts", "source", "timestamp"],
      "succession" => ["predecessor", "successor", "timestamp"],
    }.freeze

    # Whole-word re-mint (P7): the scheme IS the type value for every kind.
    PREFIX = IDENTITY_FIELDS.keys.each_with_object({}) { |k, h| h[k] = k }.freeze
    KIND_OF_PREFIX = PREFIX.invert.freeze

    module_function

    # Infer an object's kind from its type field, id prefix, or shape.
    def infer_kind(obj)
      return obj["type"] if obj.key?("type")
      if obj.key?("id") && obj["id"].is_a?(String) && obj["id"].include?(":")
        pre = obj["id"].split(":", 2)[0]
        return KIND_OF_PREFIX[pre] if KIND_OF_PREFIX.key?(pre)
      end
      return "bridge" if obj.key?("coarse") && obj.key?("fine")
      return "causal_relation_object" if obj.key?("causes") && obj.key?("effects")
      return "retraction" if obj.key?("retracts")
      return "succession" if obj.key?("predecessor") && obj.key?("successor")
      return "enrichment" if obj.key?("field") && obj.key?("entry")
      return "assertion" if obj.key?("evidence_type") ||
                            (obj.key?("about") && obj.key?("confidence"))
      return "realizable" if obj.key?("kind") && obj.key?("bearer")
      raise ArgumentError,
            "cannot infer kind (occurrents and continuants share a shape); " \
            "pass kind explicitly"
    end

    # The identity-bearing subset of an object, with type always present.
    # Returns [kind, subset].
    def identity_bearing(obj, kind = nil)
      kind ||= infer_kind(obj)
      unless IDENTITY_FIELDS.key?(kind)
        raise ArgumentError, "unknown kind: #{kind.inspect}"
      end
      out = { "type" => kind }
      IDENTITY_FIELDS[kind].each do |field|
        out[field] = obj[field] if obj.key?(field)
      end
      [kind, out]
    end

    # The RFC 8785 identity-bearing bytes of an object (a UTF-8 string).
    def canonicalize(obj, kind = nil)
      _, ib = identity_bearing(obj, kind)
      Jcs.encode(ib).encode(Encoding::UTF_8)
    end

    # The content-addressed identifier: scheme + ":" + SHA-256 hex.
    def identify(obj, kind = nil)
      kind, ib = identity_bearing(obj, kind)
      digest = Digest::SHA256.hexdigest(Jcs.encode(ib).encode(Encoding::UTF_8))
      PREFIX[kind] + ":" + digest
    end
  end
end

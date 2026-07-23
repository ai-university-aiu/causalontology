# canonical.jl - canonicalization and content-addressed identity.
#
# Implements the identity procedure of spec/identity.md:
#   1. take the object as JSON,
#   2. keep only the identity-bearing fields for its kind (with type injected),
#   3. serialize with the JSON Canonicalization Scheme (RFC 8785),
#   4. hash with SHA-256,
#   5. identifier = scheme * ":" * lowercase hex digest.

# The identity-bearing fields of each of the twenty-one kinds (3.0.0 adds the
# cross_stratal_seam; the conduit gains realized_by; 4.0.0 adds the attitude,
# the predicted_occurrence, and the prediction_error - all additive and
# identity-preserving, so a record that omits a new field keeps its earlier
# identifier byte-for-byte, and the new kinds open new identity schemes that
# disturb no existing record).  "type" is always injected, so it is not listed
# here.  Order does not matter (JCS sorts keys).
const IDENTITY_FIELDS = Dict{String,Vector{String}}(
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
)

# Whole-word re-mint (P7): the scheme IS the type value for every kind.
const PREFIX = Dict{String,String}(k => k for k in keys(IDENTITY_FIELDS))
const KIND_OF_PREFIX = Dict{String,String}(v => k for (k, v) in PREFIX)

"Infer an object's kind from its type field, id prefix, or shape."
function infer_kind(obj::JObj)
    jhas(obj, "type") && return jget(obj, "type")
    if jhas(obj, "id")
        oid = jget(obj, "id")
        if oid isa AbstractString && occursin(':', oid)
            pre = String(split(oid, ':'; limit=2)[1])
            haskey(KIND_OF_PREFIX, pre) && return KIND_OF_PREFIX[pre]
        end
    end
    jhas(obj, "coarse") && jhas(obj, "fine") && return "bridge"
    jhas(obj, "causes") && jhas(obj, "effects") && return "causal_relation_object"
    jhas(obj, "retracts") && return "retraction"
    jhas(obj, "predecessor") && jhas(obj, "successor") && return "succession"
    jhas(obj, "field") && jhas(obj, "entry") && return "enrichment"
    (jhas(obj, "evidence_type") ||
     (jhas(obj, "about") && jhas(obj, "confidence"))) && return "assertion"
    jhas(obj, "kind") && jhas(obj, "bearer") && return "realizable"
    error("cannot infer kind (occurrents and continuants share a shape); " *
          "pass kind explicitly")
end

"The identity-bearing subset of an object, with type always present."
function identity_bearing(obj::JObj, kind=nothing)
    k = kind === nothing ? infer_kind(obj) : kind
    haskey(IDENTITY_FIELDS, k) || error("unknown kind: $(repr(k))")
    out = jobj("type" => k)
    for field in IDENTITY_FIELDS[k]
        jhas(obj, field) && jset!(out, field, jget(obj, field))
    end
    return k, out
end

"The RFC 8785 identity-bearing bytes of an object."
function canonicalize(obj::JObj, kind=nothing)
    _, ib = identity_bearing(obj, kind)
    return Vector{UInt8}(codeunits(_jcs(ib)))
end

"The content-addressed identifier: scheme * ':' * SHA-256 hex."
function identify(obj::JObj, kind=nothing)
    k, ib = identity_bearing(obj, kind)
    digest = sha256(Vector{UInt8}(codeunits(_jcs(ib))))
    return PREFIX[k] * ":" * bytes2hex(digest)
end

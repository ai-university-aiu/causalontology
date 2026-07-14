# Causalontology.jl - the Julia binding of the Causalontology standard.
#
# A faithful port of causalontology-py (bindings/python/causalontology/),
# standard library only: the SHA stdlib for hashing, native BigInt for the
# pure-Julia Ed25519, an own order-preserving JSON layer for everything else.
# Conformant when it passes every vector in conformance/vectors/
# (run bindings/julia/conformance.jl).
#
# Causalontology is a verb-first noun-hosting ontology: reality is what
# happens, and things are its participants.

module Causalontology

using SHA

# specification 1.0.0 (vectors frozen 2026-07-13)
const VERSION_STRING = "1.0.0"

include("json.jl")
include("jcs.jl")
include("canonical.jl")
include("ed25519.jl")
include("signing.jl")
include("schema.jl")
include("semantics.jl")
include("store.jl")

export JObj, jobj, jget, jset!, jsetdefault!, jdel!, jhas, jkeys, jcopy,
       json_parse,
       canonicalize, identify, identity_bearing, infer_kind,
       validate_schema, validate_semantics,
       is_partial, admissible, conflicts, refinement_valid,
       hierarchy_consistent, UNIT_SECONDS,
       keypair_from_seed, sign_record, verify_record, Ed25519,
       InMemoryStore, RejectedWrite, put, put_record, force_merge_record,
       assertions_about, enrichments_about, lineage, getobj, resolve, gaps

end # module Causalontology

# causalontology-r -- canonical.R
#
# Canonicalization and content-addressed identity, ported from the
# reference bindings/python/causalontology/canonical.py.
#
# The identity procedure of spec/identity.md:
#   1. take the object as JSON,
#   2. keep only the identity-bearing fields for its kind ("type" injected),
#   3. serialize with the JSON Canonicalization Scheme (RFC 8785),
#   4. hash with SHA-256,
#   5. identifier = scheme + ":" + lowercase hex digest.
#
# 2.0.0 (Principle P7): every identifier scheme is a whole English word;
# the scheme, the type value, and the id prefix are one and the same
# string. Kinds are keyed here by that whole word throughout.

# The identity-bearing fields of each of the twenty-one kinds (3.0.0 adds the
# cross_stratal_seam; the conduit gains realized_by; 4.0.0 adds the attitude,
# the predicted_occurrence, and the prediction_error - all additive and
# identity-preserving, so a record that omits a new field keeps its earlier
# identifier byte-for-byte, and the new kinds open new identity schemes that
# disturb no existing record). "type" is always injected, so it is not listed.
# Order is irrelevant (JCS sorts).
co_identity_fields <- list(
  # ---- type tier ----
  occurrent  = c("label", "category", "stratum"),
  causal_relation_object = c("causes", "effects", "mechanism", "temporal",
                             "modality", "context", "refines", "skips"),
  continuant = c("label", "category"),
  realizable = c("kind", "bearer", "label"),
  stratum    = c("label", "scheme", "ordinal", "unit", "governs"),
  bridge     = c("coarse", "fine", "relation"),
  cross_stratal_seam = c("source", "target", "mechanism_status", "chain"),
  port       = c("bearer", "label", "direction", "accepts", "realizable"),
  conduit    = c("label", "from", "to", "carries", "transform", "realized_by"),
  quality    = c("label", "datatype", "unit", "stratum"),
  # ---- token tier ----
  token_individual   = c("instantiates", "designator", "part_of"),
  token_occurrence   = c("instantiates", "interval", "participants",
                         "locus", "observer"),
  state_assertion    = c("subject", "quality", "value", "interval"),
  token_causal_claim = c("causes", "effects", "covering_law",
                         "actual_delay", "counterfactual"),
  attitude             = c("holder", "attitude_type", "content"),
  predicted_occurrence = c("instantiates", "interval", "predictor", "strength"),
  prediction_error     = c("predicted", "observed", "discrepancy"),
  # ---- provenance tier ----
  assertion  = c("about", "source", "evidence_type", "evidence", "strength",
                 "confidence", "timestamp", "evidenced_by"),
  enrichment = c("about", "field", "entry", "source", "timestamp"),
  retraction = c("retracts", "source", "timestamp"),
  succession = c("predecessor", "successor", "timestamp")
)

# Whole-word re-mint (P7): the scheme IS the type value for every kind.
co_prefix <- stats::setNames(names(co_identity_fields), names(co_identity_fields))
co_kind_of_prefix <- stats::setNames(names(co_prefix), unname(co_prefix))

# Infer an object's kind from its type field, id prefix, or shape.
co_infer_kind <- function(obj) {
  if (co_has(obj, "type")) return(as.character(obj[["type"]])[[1]])
  oid <- co_get(obj, "id")
  if (co_is_str(oid) && grepl(":", oid, fixed = TRUE)) {
    pre <- strsplit(oid, ":", fixed = TRUE)[[1]][[1]]
    if (pre %in% names(co_kind_of_prefix)) return(co_kind_of_prefix[[pre]])
  }
  if (co_has(obj, "coarse") && co_has(obj, "fine")) return("bridge")
  if (co_has(obj, "causes") && co_has(obj, "effects")) return("causal_relation_object")
  if (co_has(obj, "retracts")) return("retraction")
  if (co_has(obj, "predecessor") && co_has(obj, "successor")) return("succession")
  if (co_has(obj, "field") && co_has(obj, "entry")) return("enrichment")
  if (co_has(obj, "evidence_type") ||
      (co_has(obj, "about") && co_has(obj, "confidence"))) return("assertion")
  if (co_has(obj, "kind") && co_has(obj, "bearer")) return("realizable")
  stop("cannot infer kind (occurrents and continuants share a shape); ",
       "pass kind explicitly")
}

# The identity-bearing subset of an object, with type always present.
# Returns list(kind = <string>, ib = <co_obj>).
co_identity_bearing <- function(obj, kind = NULL) {
  if (is.null(kind)) kind <- co_infer_kind(obj)
  if (!(kind %in% names(co_identity_fields))) stop("unknown kind: ", kind)
  ib <- co_obj(type = kind)
  for (field in co_identity_fields[[kind]]) {
    if (co_has(obj, field)) ib[[field]] <- obj[[field]]
  }
  list(kind = kind, ib = ib)
}

# The RFC 8785 identity-bearing bytes of an object (a raw vector).
co_canonicalize <- function(obj, kind = NULL) {
  r <- co_identity_bearing(obj, kind)
  co_utf8(co_jcs(r$ib))
}

# The content-addressed identifier: scheme + ":" + SHA-256 hex.
co_identify <- function(obj, kind = NULL) {
  r <- co_identity_bearing(obj, kind)
  digest <- co_sha256_hex(co_utf8(co_jcs(r$ib)))
  paste0(co_prefix[[r$kind]], ":", digest)
}

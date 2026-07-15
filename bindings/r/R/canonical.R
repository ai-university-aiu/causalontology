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

# The identity-bearing fields per kind (order irrelevant: JCS sorts keys).
co_identity_fields <- list(
  occurrent  = c("label", "category"),
  cro        = c("causes", "effects", "mechanism", "temporal", "modality",
                 "context", "refines"),
  continuant = c("label", "category"),
  realizable = c("kind", "bearer"),
  assertion  = c("about", "source", "evidence_type", "evidence", "strength",
                 "confidence", "timestamp"),
  enrichment = c("about", "field", "entry", "source", "timestamp"),
  retraction = c("retracts", "source", "timestamp"),
  succession = c("predecessor", "successor", "timestamp")
)

# The identifier scheme prefix per kind, and its inverse.
co_prefix <- c(
  occurrent = "occurrent", cro = "causal_relation_object", continuant = "continuant", realizable = "realizable",
  assertion = "assertion", enrichment = "enrichment", retraction = "retraction",
  succession = "succession"
)
co_kind_of_prefix <- stats::setNames(names(co_prefix), unname(co_prefix))

# Infer an object's kind from its type field, id prefix, or shape.
co_infer_kind <- function(obj) {
  if (co_has(obj, "type")) return(as.character(obj[["type"]])[[1]])
  oid <- co_get(obj, "id")
  if (co_is_str(oid) && grepl(":", oid, fixed = TRUE)) {
    pre <- strsplit(oid, ":", fixed = TRUE)[[1]][[1]]
    if (pre %in% names(co_kind_of_prefix)) return(co_kind_of_prefix[[pre]])
  }
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

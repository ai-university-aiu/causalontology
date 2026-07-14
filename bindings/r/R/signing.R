# causalontology-r -- signing.R
#
# Record-level signing and verification (spec/provenance.md), ported from
# the reference bindings/python/causalontology/signing.py.
#
# Ed25519 comes from the 'sodium' package (libsodium). In sodium's R API
# the SIGNING KEY IS THE 32-BYTE SEED itself -- sodium derives the key
# pair internally (crypto_sign_seed_keypair). The argument orders, as
# documented by the sodium package, are:
#   sodium::sig_pubkey(key)             key = 32-byte seed -> 32-byte public
#   sodium::sig_sign(msg, key)          message FIRST, then the seed
#   sodium::sig_verify(msg, sig, pubkey)
# sig_verify THROWS an error on a bad signature instead of returning
# FALSE, so it is wrapped in tryCatch below. The RFC 8032 TEST 1
# known-answer check in conformance.R gates all of these assumptions.
#
# The signature is computed over the record's canonical identity-bearing
# bytes (the RFC 8785 form -- id and signature are never identity-bearing),
# so verification needs nothing but the record itself. Ed25519 signing is
# deterministic (RFC 8032): re-signing the same record with the same key
# yields the same signature, so re-submission is idempotent.

# Ed25519 verify as a plain TRUE/FALSE (sodium raises on failure).
co_ed25519_verify <- function(message, signature, public) {
  tryCatch(isTRUE(sodium::sig_verify(message, signature, public)),
           error = function(e) FALSE)
}

# list(secret = <32-byte raw seed>, public = "ed25519:<hex>") from a seed.
co_keypair_from_seed <- function(seed32) {
  stopifnot(is.raw(seed32), length(seed32) == 32L)
  public <- sodium::sig_pubkey(seed32)
  list(secret = seed32, public = paste0("ed25519:", co_bin2hex(public)))
}

# Return the record completed with its id and Ed25519 signature.
co_sign_record <- function(record, secret, kind = NULL) {
  if (is.null(kind)) kind <- co_infer_kind(record)
  body <- co_del(record, "signature")
  message <- co_canonicalize(body, kind)
  signature <- co_bin2hex(sodium::sig_sign(message, secret))
  out <- body
  out[["id"]] <- co_identify(body, kind)
  out[["signature"]] <- signature
  out
}

# The hex of the key a record must verify against, or NULL.
co_signer_key_hex <- function(record, kind) {
  # a succession is signed by the predecessor key
  field <- if (identical(kind, "succession")) "predecessor" else "source"
  value <- co_get(record, field, "")
  if (!co_is_str(value)) return(NULL)
  if (!startsWith(value, "ed25519:")) return(NULL)
  substring(value, nchar("ed25519:") + 1L)
}

# TRUE iff the record's signature verifies against its own key field.
co_verify_record <- function(record, kind = NULL) {
  if (is.null(kind)) kind <- co_infer_kind(record)
  sig_hex <- co_get(record, "signature")
  key_hex <- co_signer_key_hex(record, kind)
  if (!co_is_str(sig_hex) || !nzchar(sig_hex) || is.null(key_hex) ||
      !nzchar(key_hex)) {
    return(FALSE)
  }
  public <- co_hex2bin(key_hex)
  signature <- co_hex2bin(sig_hex)
  if (is.null(public) || is.null(signature)) return(FALSE)
  body <- co_del(record, "signature")
  message <- co_canonicalize(body, kind)
  co_ed25519_verify(message, signature, public)
}

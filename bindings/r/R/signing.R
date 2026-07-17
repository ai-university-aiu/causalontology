# causalontology-r -- signing.R
#
# Record-level signing and verification (spec/provenance.md), ported from
# the reference bindings/python/causalontology/signing.py.
#
# Ed25519 (RFC 8032) via the 'openssl' R package (Imports; openssl >= 1.4.1
# provides Ed25519). A 32-byte seed is wrapped in the fixed RFC 8410 PKCS#8
# DER envelope and read with openssl::read_key(); the public key is the DER
# SubjectPublicKeyInfo envelope, read with openssl::read_pubkey(). No system
# command-line tool is invoked. The RFC 8032 TEST 1 known-answer check in
# conformance.R gates these assumptions (the derived public key must equal
# the vector's).
#
# The signature is computed over the record's canonical identity-bearing
# bytes (the RFC 8785 form -- id and signature are never identity-bearing),
# so verification needs nothing but the record itself. Ed25519 signing is
# deterministic (RFC 8032): re-signing the same record with the same key
# yields the same signature, so re-submission is idempotent.

# The fixed DER prefixes (RFC 8410). A private key is
#   SEQUENCE{ INTEGER 0, SEQUENCE{ OID 1.3.101.112 }, OCTET STRING{ OCTET
#   STRING{ <32-byte seed> } } }
# and a public key is
#   SEQUENCE{ SEQUENCE{ OID 1.3.101.112 }, BIT STRING{ <32-byte key> } }.
.co_ed_priv_prefix <- function() co_hex2bin("302e020100300506032b657004220420")
.co_ed_pub_prefix  <- function() co_hex2bin("302a300506032b6570032100")

# Private-key DER (raw) from a 32-byte seed.
.co_ed_priv_der <- function(seed32) c(.co_ed_priv_prefix(), seed32)

# The openssl private-key object for a 32-byte seed (via the PKCS#8 envelope).
.co_ed_key <- function(seed32) openssl::read_key(.co_ed_priv_der(seed32), der = TRUE)

# 32-byte public key (raw) for a 32-byte seed.
.co_ed_public_raw <- function(seed32) {
  der <- openssl::write_der(.co_ed_key(seed32)$pubkey)
  utils::tail(der, 32L)   # the trailing 32 bytes are the raw public key
}

# Ed25519 signature (raw, 64 bytes) of a message under a 32-byte seed.
# hash = NULL: Ed25519 signs the raw message (it does its own hashing).
.co_ed_sign <- function(seed32, message_raw) {
  openssl::signature_create(message_raw, hash = NULL, key = .co_ed_key(seed32))
}

# TRUE iff a signature verifies for a message under a raw 32-byte public key.
# openssl::signature_verify signals an error on a bad signature, so the caller
# (co_ed25519_verify) wraps this in tryCatch.
.co_ed_verify <- function(public_raw, message_raw, signature_raw) {
  pubkey <- openssl::read_pubkey(c(.co_ed_pub_prefix(), public_raw), der = TRUE)
  isTRUE(openssl::signature_verify(message_raw, signature_raw,
                                   hash = NULL, pubkey = pubkey))
}

# Ed25519 verify as a plain TRUE/FALSE over raw byte vectors.
co_ed25519_verify <- function(message, signature, public) {
  if (!is.raw(message) || !is.raw(signature) || !is.raw(public)) return(FALSE)
  if (length(signature) != 64L || length(public) != 32L) return(FALSE)
  tryCatch(isTRUE(.co_ed_verify(public, message, signature)),
           error = function(e) FALSE)
}

# list(secret = <32-byte seed>, public = "ed25519:<hex>") from a 32-byte
# seed. The "secret" carried here is the raw seed; the openssl helpers
# rebuild the PKCS#8 envelope on demand.
co_keypair_from_seed <- function(seed32) {
  stopifnot(is.raw(seed32), length(seed32) == 32L)
  public <- .co_ed_public_raw(seed32)
  list(secret = seed32, public = paste0("ed25519:", co_bin2hex(public)))
}

# Return the record completed with its id and Ed25519 signature.
co_sign_record <- function(record, secret, kind = NULL) {
  if (is.null(kind)) kind <- co_infer_kind(record)
  body <- co_del(record, "signature")
  message <- co_canonicalize(body, kind)
  signature <- co_bin2hex(.co_ed_sign(secret, message))
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

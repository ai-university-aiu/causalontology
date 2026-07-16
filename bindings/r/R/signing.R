# causalontology-r -- signing.R
#
# Record-level signing and verification (spec/provenance.md), ported from
# the reference bindings/python/causalontology/signing.py.
#
# Ed25519 (RFC 8032). No CRAN crypto package is installed in this toolchain
# (neither the 'sodium' nor the 'openssl' R package is present), so the
# primitive is delegated to the system OpenSSL command-line tool, which
# ships a trusted Ed25519 implementation. A 32-byte seed is wrapped in the
# fixed RFC 8410 PKCS#8 DER envelope and handed to `openssl pkeyutl`; the
# public key is the DER SubjectPublicKeyInfo envelope. The RFC 8032 TEST 1
# known-answer check in conformance.R gates these assumptions (the derived
# public key must equal the vector's).
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

.co_openssl <- function() {
  bin <- Sys.getenv("OPENSSL", unset = "openssl")
  bin
}

.co_tmp <- function(ext) tempfile(fileext = ext)

# Private-key DER (raw) from a 32-byte seed.
.co_ed_priv_der <- function(seed32) c(.co_ed_priv_prefix(), seed32)

# 32-byte public key (raw) for a 32-byte seed, via `openssl pkey -pubout`.
.co_ed_public_raw <- function(seed32) {
  skder <- .co_tmp(".der")
  pkder <- .co_tmp(".der")
  on.exit(unlink(c(skder, pkder)), add = TRUE)
  writeBin(.co_ed_priv_der(seed32), skder)
  status <- suppressWarnings(system2(
    .co_openssl(),
    c("pkey", "-inform", "DER", "-in", shQuote(skder),
      "-pubout", "-outform", "DER", "-out", shQuote(pkder)),
    stdout = FALSE, stderr = FALSE))
  if (!identical(status, 0L) || !file.exists(pkder)) {
    stop("openssl: could not derive the Ed25519 public key")
  }
  der <- readBin(pkder, "raw", n = 128L)
  utils::tail(der, 32L)   # the trailing 32 bytes are the raw public key
}

# Ed25519 signature (raw, 64 bytes) of a message under a 32-byte seed.
.co_ed_sign <- function(seed32, message_raw) {
  skder <- .co_tmp(".der")
  mf <- .co_tmp(".bin")
  sf <- .co_tmp(".bin")
  on.exit(unlink(c(skder, mf, sf)), add = TRUE)
  writeBin(.co_ed_priv_der(seed32), skder)
  writeBin(message_raw, mf)
  status <- suppressWarnings(system2(
    .co_openssl(),
    c("pkeyutl", "-sign", "-inkey", shQuote(skder), "-keyform", "DER",
      "-rawin", "-in", shQuote(mf), "-out", shQuote(sf)),
    stdout = FALSE, stderr = FALSE))
  if (!identical(status, 0L) || !file.exists(sf)) {
    stop("openssl: Ed25519 signing failed")
  }
  readBin(sf, "raw", n = 64L)
}

# TRUE iff a signature verifies for a message under a raw 32-byte public key.
.co_ed_verify <- function(public_raw, message_raw, signature_raw) {
  pkder <- .co_tmp(".der")
  mf <- .co_tmp(".bin")
  sf <- .co_tmp(".bin")
  on.exit(unlink(c(pkder, mf, sf)), add = TRUE)
  writeBin(c(.co_ed_pub_prefix(), public_raw), pkder)
  writeBin(message_raw, mf)
  writeBin(signature_raw, sf)
  status <- suppressWarnings(system2(
    .co_openssl(),
    c("pkeyutl", "-verify", "-pubin", "-inkey", shQuote(pkder),
      "-keyform", "DER", "-rawin", "-in", shQuote(mf),
      "-sigfile", shQuote(sf)),
    stdout = FALSE, stderr = FALSE))
  identical(status, 0L)
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

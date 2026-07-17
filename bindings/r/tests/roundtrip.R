# Self-contained smoke test (no external vectors): the crypto rewritten to the
# 'openssl' package. RFC 8032 Test 1 known-answer plus a record sign/verify
# round-trip and a tamper-rejection. Exercised by R CMD check.
library(causalontology)

# RFC 8032 Test 1: a 32-byte seed derives a fixed Ed25519 public key.
seed <- co_hex2bin("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
kp <- co_keypair_from_seed(seed)
stopifnot(identical(
  kp$public,
  "ed25519:d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))

# Sign a record and verify it against its own source key.
rec <- list(type = "assertion", about = "occurrent:0", source = kp$public,
            evidence_type = "observation", confidence = 0.5,
            timestamp = "2026-01-01T00:00:00Z")
signed <- co_sign_record(rec, kp$secret)
stopifnot(isTRUE(co_verify_record(signed)))

# Tampering breaks verification.
tampered <- signed
tampered$timestamp <- "2026-01-02T00:00:00Z"
stopifnot(!isTRUE(co_verify_record(tampered)))

cat("causalontology R self-test: OK\n")

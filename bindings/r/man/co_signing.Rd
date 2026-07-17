\name{co_signing}
\alias{co_signing}
\alias{co_keypair_from_seed}
\alias{co_sign_record}
\alias{co_verify_record}
\alias{co_ed25519_verify}
\title{Ed25519 signing and verification}
\description{
Record-level Ed25519 (RFC 8032) signing and verification for Causalontology
records. Keys are derived deterministically from a 32-byte seed; signing is
computed over the record's RFC 8785 canonical identity-bearing bytes and is
itself deterministic (re-signing the same record yields the same signature).
Cryptography is provided by the \pkg{openssl} package; no external command-line
tool is used.
}
\usage{
co_keypair_from_seed(seed32)
co_sign_record(record, secret, kind = NULL)
co_verify_record(record, kind = NULL)
co_ed25519_verify(message, signature, public)
}
\arguments{
  \item{seed32}{A \code{raw} vector of exactly 32 bytes, the Ed25519 seed.}
  \item{record}{A record (a parsed Causalontology object, e.g. from
    \code{\link{co_parse_json}}).}
  \item{secret}{The 32-byte raw seed returned as \code{$secret} by
    \code{co_keypair_from_seed}.}
  \item{kind}{Optional object kind (character). If \code{NULL} it is inferred
    with \code{\link{co_infer_kind}}.}
  \item{message}{A \code{raw} vector: the message bytes.}
  \item{signature}{A \code{raw} vector of 64 bytes: the Ed25519 signature.}
  \item{public}{A \code{raw} vector of 32 bytes: the Ed25519 public key.}
}
\value{
\code{co_keypair_from_seed} returns a list with \code{secret} (the raw seed) and
\code{public} (a string \code{"ed25519:<hex>"}). \code{co_sign_record} returns
the record completed with its content-addressed \code{id} and hex
\code{signature}. \code{co_verify_record} and \code{co_ed25519_verify} return a
single logical.
}
\examples{
# Deterministic keypair from a 32-byte seed (RFC 8032 Test 1).
seed <- co_hex2bin(
  "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
kp <- co_keypair_from_seed(seed)
kp$public

# Sign a record and verify it against its own source key.
rec <- co_parse_json(sprintf(paste0(
  '{"type":"assertion","about":"occurrent:0","source":"\%s",',
  '"evidence_type":"observation","confidence":0.5,',
  '"timestamp":"2026-01-01T00:00:00Z"}'), kp$public))
signed <- co_sign_record(rec, kp$secret)
co_verify_record(signed)

# A non-matching signature does not verify (returns FALSE, never errors).
co_ed25519_verify(charToRaw("msg"), as.raw(rep(0, 64)), as.raw(rep(0, 32)))
}
\seealso{\code{\link{co_identify}}, \code{\link{co_parse_json}}}
\keyword{ signing }

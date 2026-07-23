\name{causalontology-package}
\alias{causalontology-package}
\alias{causalontology}
\docType{package}
\title{The R binding of the Causalontology standard}
\description{
Causalontology is a programming-language-neutral standard and shared commons for
reified causation. This package is its R binding: content-addressed identity over
RFC 8785 (JSON Canonicalization Scheme) bytes with SHA-256, record-level Ed25519
signing and verification (RFC 8032, via the \pkg{openssl} package), schema and
semantic validation, and an in-memory conformant store. Behavior is byte-identical
to the other bindings; an implementation is conformant if and only if it passes
the 137 frozen conformance vectors for the specification version it declares
(4.0.0).
}
\section{Main functions}{
\itemize{
  \item Cryptography: \code{\link{co_keypair_from_seed}}, \code{\link{co_sign_record}}, \code{\link{co_verify_record}}, \code{\link{co_ed25519_verify}}.
  \item Identity: \code{\link{co_identify}}, \code{\link{co_canonicalize}}, \code{\link{co_infer_kind}}.
  \item Validation: \code{\link{co_validate_schema}}, \code{\link{co_validate_semantics}}.
  \item JSON and configuration: \code{\link{co_parse_json}}, \code{\link{co_set_root}}.
  \item Store: \code{\link{co_store_new}} and the \code{co_store_*} operations.
}
}
\references{
Specification and conformance vectors:
\url{https://github.com/ai-university-aiu/causalontology}.
}
\keyword{ package }

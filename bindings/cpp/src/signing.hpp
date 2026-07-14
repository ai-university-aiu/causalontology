// signing.hpp - record-level signing and verification (spec/provenance.md).
//
// The signature is computed over the record's canonical identity-bearing
// bytes (the RFC 8785 form with id and signature removed - exactly the
// bytes hashed for the record's identifier), so verification needs nothing
// but the record itself. Ed25519 is deterministic (RFC 8032): re-signing
// the same record with the same key yields the same signature, so
// re-submission is idempotent.

#pragma once

#include <string>
#include <utility>

#include "json.hpp"

namespace co {

// (secret, "ed25519:<hex>") from a 32-byte seed.
std::pair<std::string, std::string> keypair_from_seed(const std::string& seed32);

// The record completed with its id and Ed25519 signature.
JValue sign_record(const JValue& record, const std::string& secret,
                   const std::string& kind = "");

// True iff the record's signature verifies against its own key field
// (source, or predecessor for a succession).
bool verify_record(const JValue& record, const std::string& kind = "");

}  // namespace co

// ed25519.hpp - Ed25519 digital signatures (RFC 8032), hand-built.
//
// A faithful port of bindings/python/causalontology/ed25519.py over the
// magnitude bignum layer: the twisted Edwards group in extended
// coordinates, Fermat inversion, deterministic signing and verification.
// Python's floored % is handled by keeping every field expression
// non-negative (a - b mod p is computed as a + p - b). Slow but correct -
// gated on the RFC 8032 TEST 1 known answer by the conformance runner.

#pragma once

#include <string>

namespace co {
namespace ed25519 {

// The 32-byte public key for a 32-byte secret key (seed).
std::string secret_to_public(const std::string& secret);

// The 64-byte deterministic Ed25519 signature of msg under secret.
std::string sign(const std::string& secret, const std::string& msg);

// True iff signature is a valid Ed25519 signature of msg under public.
bool verify(const std::string& public_key, const std::string& msg,
            const std::string& signature);

}  // namespace ed25519
}  // namespace co

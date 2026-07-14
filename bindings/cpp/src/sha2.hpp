// sha2.hpp - SHA-256 and SHA-512 (FIPS 180-4), hand-built, no libraries.
//
// SHA-256 runs over uint32_t words, SHA-512 over uint64_t words. Both are
// gated on the empty-string known answers by the conformance runner:
//   sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
//   sha512("") starts cf83e135...

#pragma once

#include <cstdint>
#include <string>

namespace co {

// The 32-byte SHA-256 digest of the message bytes.
std::string sha256(const std::string& msg);

// The 64-byte SHA-512 digest of the message bytes.
std::string sha512(const std::string& msg);

// Lowercase hex of arbitrary bytes.
std::string to_hex(const std::string& bytes);

// Hex decode; returns false on odd length or a non-hex character.
bool from_hex(const std::string& hex, std::string& out);

// Convenience: lowercase hex SHA-256 of the message bytes.
std::string sha256_hex(const std::string& msg);

}  // namespace co

// jcs.hpp - RFC 8785 (JSON Canonicalization Scheme) serialization.
//
// Sorted keys, minimal bytewise string escaping, and ECMAScript-style
// canonical numbers (1.0 -> "1", 0.7 stays "0.7", exponents as e-7 / e+21,
// never e-07), mirroring the Python binding's _jcs exactly.

#pragma once

#include <string>

#include "json.hpp"

namespace co {

// The canonical RFC 8785 serialization of a JValue (UTF-8 bytes).
std::string jcs(const JValue& value);

// The canonical string form (with surrounding quotes) - exposed for reuse.
std::string jcs_string(const std::string& s);

}  // namespace co

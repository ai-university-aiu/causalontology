// canonical.hpp - canonicalization and content-addressed identity.
//
// The identity procedure of spec/identity.md: keep only the identity-
// bearing fields for the kind (with "type" injected), serialize with
// RFC 8785, hash with SHA-256, identifier = scheme + ":" + lowercase hex.

#pragma once

#include <string>
#include <utility>

#include "json.hpp"

namespace co {

// Infer an object's kind from its type field, id prefix, or shape;
// throws std::runtime_error when the shape is ambiguous.
std::string infer_kind(const JValue& obj);

// The kind name for an id prefix ("occurrent" -> "occurrent"), or "" if unknown.
std::string kind_of_prefix(const std::string& prefix);

// The id prefix for a kind ("occurrent" -> "occurrent"); throws on unknown kind.
std::string prefix_of_kind(const std::string& kind);

// The identity-bearing subset of an object, with type always present.
// kind may be "" to infer. Returns (kind, subset).
std::pair<std::string, JValue> identity_bearing(const JValue& obj,
                                                const std::string& kind = "");

// The RFC 8785 identity-bearing bytes of an object.
std::string canonicalize(const JValue& obj, const std::string& kind = "");

// The content-addressed identifier: scheme + ":" + SHA-256 hex.
std::string identify(const JValue& obj, const std::string& kind = "");

}  // namespace co

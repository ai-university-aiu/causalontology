// semantics.hpp - the semantic rules beyond the schemas (spec/semantics.md).
//
// Local rules are checked here; store-context rules (materialized
// acyclicity, retraction lineage) live in store.cpp where the context is.

#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

#include "json.hpp"

namespace co {

// Rule 4: the fixed unit-conversion constants (average Gregorian values).
// months = 2629746 s, years = 31556952 s.
int64_t unit_seconds(const std::string& unit);

// The optional CRO fields, in spec order.
extern const std::vector<std::string> CRO_OPTIONAL_FIELDS;

// (ok, reasons) - the locally checkable semantic rules.
std::pair<bool, std::vector<std::string>> validate_semantics(
    const JValue& obj, const std::string& kind = "");

// (partial, missing) - which optional CRO fields are unspecified.
std::pair<bool, std::vector<std::string>> is_partial(const JValue& cro);

// Rule 4: temporal admissibility with the fixed constants.
bool admissible(const JValue& cro, double elapsed_seconds);

// Rule 6: the formal conflict test.
bool conflicts(const JValue& a, const JValue& b);

// Rule 3: (ok, reason) - is child a valid refinement of parent?
std::pair<bool, std::string> refinement_valid(const JValue& child,
                                              const JValue& parent);

// Rule 7: "consistent" | "inconsistent" | "indeterminate".
// members maps CRO identifier -> CRO object for the parent's mechanism.
std::string hierarchy_consistent(const JValue& parent,
                                 const std::map<std::string, JValue>& members);

}  // namespace co

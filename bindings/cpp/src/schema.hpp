// schema.hpp - validation against spec/schema/*.schema.json.
//
// A deliberately small interpreter for exactly the JSON Schema keywords
// the eight Causalontology schemas use: type, const, enum, pattern,
// required, properties, additionalProperties, items, minItems, minLength,
// minimum, maximum, oneOf, and local $ref (#/$defs/...). "format" is an
// annotation, as the 2020-12 draft treats it by default.

#pragma once

#include <string>
#include <utility>
#include <vector>

#include "json.hpp"

namespace co {

// Tell the schema loader where the spec/schema directory lives. When never
// called, the CAUSALONTOLOGY_SPEC environment variable (naming the spec/
// directory) is honored, mirroring the Python binding.
void schema_set_spec_dir(const std::string& schema_dir);

// (ok, reasons) - structural validity against the kind's JSON Schema.
// kind may be "" to infer from the object.
std::pair<bool, std::vector<std::string>> validate_schema(
    const JValue& obj, const std::string& kind = "");

}  // namespace co

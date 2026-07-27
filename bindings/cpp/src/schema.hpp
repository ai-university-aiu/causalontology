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

// Tell the schema loader where the directory holding the twenty-one
// *.schema.json files lives.
//
// The loader consults, in this order:
//
//   1. $CAUSALONTOLOGY_SPEC/schema, when that variable is set and non-empty.
//      It is the operator's override and it wins even over this call,
//      mirroring the Python and JavaScript bindings.
//   2. the directory passed to this function.
//   3. the copy `cmake --install` ships at
//      <prefix>/share/causalontology/spec/schema, whose absolute path
//      CMakeLists.txt compiles in as CAUSALONTOLOGY_SCHEMA_DIR.
//
// If no candidate is a directory, validation throws a std::runtime_error
// naming every place that was tried. Nothing is ever resolved relative to a
// repository checkout, so an installed copy never depends on the tree that
// built it.
void schema_set_spec_dir(const std::string& schema_dir);

// (ok, reasons) - structural validity against the kind's JSON Schema.
// kind may be "" to infer from the object.
std::pair<bool, std::vector<std::string>> validate_schema(
    const JValue& obj, const std::string& kind = "");

}  // namespace co

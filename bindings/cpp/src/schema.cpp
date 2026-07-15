// schema.cpp - the small JSON Schema interpreter.

#include "schema.hpp"

#include <cstdlib>
#include <fstream>
#include <map>
#include <regex>
#include <sstream>
#include <stdexcept>

#include "canonical.hpp"
#include "jcs.hpp"

namespace co {

namespace {

std::string g_schema_dir;

const std::map<std::string, std::string>& schemaFiles() {
    static const std::map<std::string, std::string> files = {
        {"causal_relation_object", "cro.schema.json"},
        {"occurrent", "occurrent.schema.json"},
        {"continuant", "continuant.schema.json"},
        {"realizable", "realizable.schema.json"},
        {"assertion", "assertion.schema.json"},
        {"enrichment", "enrichment.schema.json"},
        {"retraction", "retraction.schema.json"},
        {"succession", "succession.schema.json"},
    };
    return files;
}

std::string schemaDir() {
    if (!g_schema_dir.empty()) return g_schema_dir;
    const char* env = std::getenv("CAUSALONTOLOGY_SPEC");
    if (env && *env) return std::string(env) + "/schema";
    throw std::runtime_error(
        "schema directory unknown: call schema_set_spec_dir() or set "
        "CAUSALONTOLOGY_SPEC");
}

const JValue& loadSchema(const std::string& kind) {
    static std::map<std::string, JValue> cache;
    auto hit = cache.find(kind);
    if (hit != cache.end()) return hit->second;
    auto file = schemaFiles().find(kind);
    if (file == schemaFiles().end())
        throw std::runtime_error("unknown kind: '" + kind + "'");
    std::string path = schemaDir() + "/" + file->second;
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open schema " + path);
    std::ostringstream buf;
    buf << in.rdbuf();
    return cache.emplace(kind, json_parse(buf.str())).first->second;
}

// Follow local $ref chains (#/$defs/...) to the referenced subschema.
const JValue& resolveRef(const JValue& schema, const JValue& root) {
    const JValue* node = &schema;
    while (node->isObject() && node->has("$ref")) {
        const std::string& ref = node->at("$ref").str;
        if (ref.rfind("#/", 0) != 0)
            throw std::runtime_error("only local $ref supported: " + ref);
        const JValue* cursor = &root;
        std::string rest = ref.substr(2);
        size_t pos = 0;
        while (pos <= rest.size()) {
            size_t slash = rest.find('/', pos);
            std::string part = rest.substr(
                pos, slash == std::string::npos ? std::string::npos
                                                : slash - pos);
            cursor = &cursor->at(part);
            if (slash == std::string::npos) break;
            pos = slash + 1;
        }
        node = cursor;
    }
    return *node;
}

// A cached, compiled ECMAScript regex for a schema pattern.
const std::regex& compiledPattern(const std::string& pattern) {
    static std::map<std::string, std::regex> cache;
    auto hit = cache.find(pattern);
    if (hit != cache.end()) return hit->second;
    return cache.emplace(pattern, std::regex(pattern)).first->second;
}

// A short display form for error messages (mirrors Python's %r closely
// enough for the conformance substring checks).
std::string repr(const JValue& v) {
    if (v.isString()) return "'" + v.str + "'";
    return jcs(v);
}

bool typeMatches(const JValue& value, const std::string& t) {
    if (t == "object") return value.isObject();
    if (t == "array") return value.isArray();
    if (t == "string") return value.isString();
    if (t == "boolean") return value.isBool();
    if (t == "number") return value.isNumber();  // bools are a distinct tag
    return false;
}

void check(const JValue& value, const JValue& schemaIn, const JValue& root,
           const std::string& path, std::vector<std::string>& errors) {
    const JValue& schema = resolveRef(schemaIn, root);

    if (schema.has("oneOf")) {
        int passing = 0;
        for (const JValue& sub : schema.at("oneOf").array) {
            std::vector<std::string> subErrs;
            check(value, sub, root, path, subErrs);
            if (subErrs.empty()) ++passing;
        }
        if (passing != 1)
            errors.push_back(path + ": matches " + std::to_string(passing) +
                             " of the oneOf branches (need exactly 1)");
        return;
    }

    const JValue* t = schema.find("type");
    if (t) {
        if (!typeMatches(value, t->str)) {
            errors.push_back(path + ": expected " + t->str);
            return;
        }
    }

    if (schema.has("const") && value != schema.at("const"))
        errors.push_back(path + ": must equal " + repr(schema.at("const")));
    if (schema.has("enum")) {
        bool found = false;
        for (const JValue& option : schema.at("enum").array)
            if (value == option) { found = true; break; }
        if (!found)
            errors.push_back(path + ": " + repr(value) +
                             " not in enumeration");
    }
    if (schema.has("pattern") && value.isString()) {
        const std::string& pattern = schema.at("pattern").str;
        if (!std::regex_search(value.str, compiledPattern(pattern)))
            errors.push_back(path + ": " + repr(value) +
                             " does not match " + pattern);
    }
    if (schema.has("minLength") && value.isString()) {
        if (static_cast<int64_t>(value.str.size()) <
            schema.at("minLength").integer)
            errors.push_back(path + ": shorter than minLength");
    }
    if (schema.has("minimum") && value.isNumber()) {
        if (value.asDouble() < schema.at("minimum").asDouble())
            errors.push_back(path + ": below minimum " +
                             jcs(schema.at("minimum")));
    }
    if (schema.has("maximum") && value.isNumber()) {
        if (value.asDouble() > schema.at("maximum").asDouble())
            errors.push_back(path + ": above maximum " +
                             jcs(schema.at("maximum")));
    }

    if (value.isArray()) {
        if (schema.has("minItems") &&
            static_cast<int64_t>(value.array.size()) <
                schema.at("minItems").integer)
            errors.push_back(path + ": fewer than " +
                             jcs(schema.at("minItems")) + " items");
        if (schema.has("items")) {
            for (size_t i = 0; i < value.array.size(); ++i)
                check(value.array[i], schema.at("items"), root,
                      path + "[" + std::to_string(i) + "]", errors);
        }
    }

    if (value.isObject()) {
        static const JValue emptyObject = JValue::makeObject();
        const JValue* propsPtr = schema.find("properties");
        const JValue& props = propsPtr ? *propsPtr : emptyObject;
        if (schema.has("required")) {
            for (const JValue& req : schema.at("required").array)
                if (!value.has(req.str))
                    errors.push_back(path + ": required property '" +
                                     req.str + "' missing");
        }
        const JValue* addl = schema.find("additionalProperties");
        if (addl && addl->isBool() && !addl->boolean) {
            for (const auto& kv : value.object)
                if (!props.has(kv.first))
                    errors.push_back(path + ": additional property '" +
                                     kv.first + "'");
        }
        for (const auto& kv : props.object) {
            const JValue* present = value.find(kv.first);
            if (present)
                check(*present, kv.second, root, path + "." + kv.first,
                      errors);
        }
    }
}

}  // namespace

void schema_set_spec_dir(const std::string& schema_dir) {
    g_schema_dir = schema_dir;
}

std::pair<bool, std::vector<std::string>> validate_schema(
    const JValue& obj, const std::string& kind) {
    std::string k = kind.empty() ? infer_kind(obj) : kind;
    const JValue& root = loadSchema(k);
    std::vector<std::string> errors;
    check(obj, root, root, "$", errors);
    return {errors.empty(), errors};
}

}  // namespace co

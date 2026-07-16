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

const std::string kBaseUrl = "https://causalontology.org/schema/";

// kind -> schema file. Three token kinds keep their original 1.0.0-reserved
// file names (individual/token/state); the id scheme is the whole word.
const std::map<std::string, std::string>& schemaFiles() {
    static const std::map<std::string, std::string> files = {
        {"occurrent", "occurrent.schema.json"},
        {"causal_relation_object", "causal_relation_object.schema.json"},
        {"continuant", "continuant.schema.json"},
        {"realizable", "realizable.schema.json"},
        {"stratum", "stratum.schema.json"},
        {"bridge", "bridge.schema.json"},
        {"port", "port.schema.json"},
        {"conduit", "conduit.schema.json"},
        {"quality", "quality.schema.json"},
        {"token_individual", "individual.schema.json"},
        {"token_occurrence", "token.schema.json"},
        {"state_assertion", "state.schema.json"},
        {"token_causal_claim", "token_causal_claim.schema.json"},
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

// Load a schema document by filename, cached by filename so cross-file $refs
// share one parse.
const JValue& loadFile(const std::string& filename) {
    static std::map<std::string, JValue> cache;
    auto hit = cache.find(filename);
    if (hit != cache.end()) return hit->second;
    std::string path = schemaDir() + "/" + filename;
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open schema " + path);
    std::ostringstream buf;
    buf << in.rdbuf();
    return cache.emplace(filename, json_parse(buf.str())).first->second;
}

const JValue& loadSchema(const std::string& kind) {
    auto file = schemaFiles().find(kind);
    if (file == schemaFiles().end())
        throw std::runtime_error("unknown kind: '" + kind + "'");
    return loadFile(file->second);
}

// Navigate a JSON Pointer body ("$defs/interval") from a document root.
const JValue* navigate(const JValue* root, const std::string& pointer) {
    const JValue* cursor = root;
    size_t pos = 0;
    if (pointer.empty()) return cursor;
    while (pos <= pointer.size()) {
        size_t slash = pointer.find('/', pos);
        std::string part = pointer.substr(
            pos, slash == std::string::npos ? std::string::npos : slash - pos);
        if (!part.empty()) cursor = &cursor->at(part);
        if (slash == std::string::npos) break;
        pos = slash + 1;
    }
    return cursor;
}

// Follow local (#/$defs/...) and cross-file ($BASE<file>#/...) $ref chains to
// the concrete subschema; returns the node and the document root it lives in
// (the root changes across a cross-file hop, mirroring the Python binding).
std::pair<const JValue*, const JValue*> resolveRef(const JValue* schema,
                                                   const JValue* root) {
    while (schema->isObject() && schema->has("$ref")) {
        const std::string& ref = schema->at("$ref").str;
        if (ref.rfind("#/", 0) == 0) {
            schema = navigate(root, ref.substr(2));
        } else if (ref.rfind(kBaseUrl, 0) == 0) {
            std::string rest = ref.substr(kBaseUrl.size());
            size_t hash = rest.find("#/");
            std::string filename =
                hash == std::string::npos ? rest : rest.substr(0, hash);
            root = &loadFile(filename);
            schema = (hash == std::string::npos)
                         ? root
                         : navigate(root, rest.substr(hash + 2));
        } else {
            throw std::runtime_error("unsupported $ref: " + ref);
        }
    }
    return {schema, root};
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
    if (t == "integer") return value.isInt();
    return false;
}

void check(const JValue& value, const JValue& schemaIn, const JValue& rootIn,
           const std::string& path, std::vector<std::string>& errors) {
    auto [schemaP, rootP] = resolveRef(&schemaIn, &rootIn);
    const JValue& schema = *schemaP;
    const JValue& root = *rootP;

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

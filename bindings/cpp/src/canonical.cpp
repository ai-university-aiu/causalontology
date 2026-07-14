// canonical.cpp - identity-bearing field filtering and identify().

#include "canonical.hpp"

#include <stdexcept>
#include <vector>

#include "jcs.hpp"
#include "sha2.hpp"

namespace co {

namespace {

struct KindFields {
    const char* kind;
    const char* prefix;
    std::vector<const char*> fields;
};

// The identity-bearing fields per kind (spec/identity.md), in spec order.
const std::vector<KindFields>& table() {
    static const std::vector<KindFields> t = {
        {"occurrent", "occ", {"label", "category"}},
        {"cro", "cro",
         {"causes", "effects", "mechanism", "temporal", "modality", "context",
          "refines"}},
        {"continuant", "cnt", {"label", "category"}},
        {"realizable", "rlz", {"kind", "bearer"}},
        {"assertion", "ast",
         {"about", "source", "evidence_type", "evidence", "strength",
          "confidence", "timestamp"}},
        {"enrichment", "enr", {"about", "field", "entry", "source", "timestamp"}},
        {"retraction", "ret", {"retracts", "source", "timestamp"}},
        {"succession", "suc", {"predecessor", "successor", "timestamp"}},
    };
    return t;
}

const KindFields* lookup(const std::string& kind) {
    for (const auto& e : table())
        if (kind == e.kind) return &e;
    return nullptr;
}

}  // namespace

std::string kind_of_prefix(const std::string& prefix) {
    for (const auto& e : table())
        if (prefix == e.prefix) return e.kind;
    return "";
}

std::string prefix_of_kind(const std::string& kind) {
    const KindFields* e = lookup(kind);
    if (!e) throw std::runtime_error("unknown kind: '" + kind + "'");
    return e->prefix;
}

std::string infer_kind(const JValue& obj) {
    if (obj.has("type")) return obj.at("type").str;
    const JValue* id = obj.find("id");
    if (id && id->isString()) {
        size_t colon = id->str.find(':');
        if (colon != std::string::npos) {
            std::string kind = kind_of_prefix(id->str.substr(0, colon));
            if (!kind.empty()) return kind;
        }
    }
    if (obj.has("causes") && obj.has("effects")) return "cro";
    if (obj.has("retracts")) return "retraction";
    if (obj.has("predecessor") && obj.has("successor")) return "succession";
    if (obj.has("field") && obj.has("entry")) return "enrichment";
    if (obj.has("evidence_type") || (obj.has("about") && obj.has("confidence")))
        return "assertion";
    if (obj.has("kind") && obj.has("bearer")) return "realizable";
    throw std::runtime_error(
        "cannot infer kind (occurrents and continuants share a shape); "
        "pass kind explicitly");
}

std::pair<std::string, JValue> identity_bearing(const JValue& obj,
                                                const std::string& kind) {
    std::string k = kind.empty() ? infer_kind(obj) : kind;
    const KindFields* e = lookup(k);
    if (!e) throw std::runtime_error("unknown kind: '" + k + "'");
    JValue out = JValue::makeObject();
    out.set("type", JValue::of(k));
    for (const char* field : e->fields) {
        const JValue* v = obj.find(field);
        if (v) out.set(field, *v);
    }
    return {k, out};
}

std::string canonicalize(const JValue& obj, const std::string& kind) {
    auto [k, ib] = identity_bearing(obj, kind);
    (void)k;
    return jcs(ib);
}

std::string identify(const JValue& obj, const std::string& kind) {
    auto [k, ib] = identity_bearing(obj, kind);
    return prefix_of_kind(k) + ":" + sha256_hex(jcs(ib));
}

}  // namespace co

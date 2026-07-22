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
// 2.0.0 whole-word re-mint (Principle P7): the scheme IS the type value.
// 3.0.0 adds the cross_stratal_seam and the conduit's realized_by; 4.0.0 adds
// the attitude, the predicted_occurrence, and the prediction_error - all
// additive and identity-preserving: a record that omits a new field keeps its
// earlier identifier byte-for-byte, and the new kinds open new identity
// schemes that disturb no existing record.
const std::vector<KindFields>& table() {
    static const std::vector<KindFields> t = {
        // ---- type tier ----
        {"occurrent", "occurrent", {"label", "category", "stratum"}},
        {"causal_relation_object", "causal_relation_object",
         {"causes", "effects", "mechanism", "temporal", "modality", "context",
          "refines", "skips"}},
        {"continuant", "continuant", {"label", "category"}},
        {"realizable", "realizable", {"kind", "bearer", "label"}},
        {"stratum", "stratum", {"label", "scheme", "ordinal", "unit", "governs"}},
        {"bridge", "bridge", {"coarse", "fine", "relation"}},
        {"cross_stratal_seam", "cross_stratal_seam",
         {"source", "target", "mechanism_status", "chain"}},
        {"port", "port", {"bearer", "label", "direction", "accepts",
                          "realizable"}},
        {"conduit", "conduit", {"label", "from", "to", "carries", "transform",
                                "realized_by"}},
        {"quality", "quality", {"label", "datatype", "unit", "stratum"}},
        // ---- token tier ----
        {"token_individual", "token_individual",
         {"instantiates", "designator", "part_of"}},
        {"token_occurrence", "token_occurrence",
         {"instantiates", "interval", "participants", "locus", "observer"}},
        {"state_assertion", "state_assertion",
         {"subject", "quality", "value", "interval"}},
        {"token_causal_claim", "token_causal_claim",
         {"causes", "effects", "covering_law", "actual_delay",
          "counterfactual"}},
        {"attitude", "attitude", {"holder", "attitude_type", "content"}},
        {"predicted_occurrence", "predicted_occurrence",
         {"instantiates", "interval", "predictor", "strength"}},
        {"prediction_error", "prediction_error",
         {"predicted", "observed", "discrepancy"}},
        // ---- provenance tier ----
        {"assertion", "assertion",
         {"about", "source", "evidence_type", "evidence", "strength",
          "confidence", "timestamp", "evidenced_by"}},
        {"enrichment", "enrichment",
         {"about", "field", "entry", "source", "timestamp"}},
        {"retraction", "retraction", {"retracts", "source", "timestamp"}},
        {"succession", "succession", {"predecessor", "successor", "timestamp"}},
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
    if (obj.has("coarse") && obj.has("fine")) return "bridge";
    if (obj.has("causes") && obj.has("effects")) return "causal_relation_object";
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

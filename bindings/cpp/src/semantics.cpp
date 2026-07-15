// semantics.cpp - the 13 semantic rules' locally checkable subset.

#include "semantics.hpp"

#include <algorithm>
#include <set>
#include <stdexcept>

#include "canonical.hpp"

namespace co {

const std::vector<std::string> CRO_OPTIONAL_FIELDS = {
    "mechanism", "temporal", "modality", "context"};

int64_t unit_seconds(const std::string& unit) {
    if (unit == "instant") return 0;
    if (unit == "seconds") return 1;
    if (unit == "minutes") return 60;
    if (unit == "hours") return 3600;
    if (unit == "days") return 86400;
    if (unit == "weeks") return 604800;
    if (unit == "months") return 2629746;
    if (unit == "years") return 31556952;
    throw std::runtime_error("unknown temporal unit: " + unit);
}

namespace {

// Rule 12: enrichment field-to-kind validity and entry shapes.
struct FieldSpec {
    const char* field;
    std::vector<const char*> legalKinds;
    const char* shape;  // "alias" or an id prefix ("continuant", "occurrent")
};

const std::vector<FieldSpec>& enrichmentFields() {
    static const std::vector<FieldSpec> specs = {
        {"aliases", {"occurrent", "continuant"}, "alias"},
        {"participants", {"occurrent"}, "continuant"},
        {"subsumes", {"continuant"}, "continuant"},
        {"part_of", {"continuant"}, "continuant"},
        {"realized_in", {"realizable"}, "occurrent"},
    };
    return specs;
}

std::string kindOfId(const std::string& identifier) {
    size_t colon = identifier.find(':');
    if (colon == std::string::npos) return "";
    return kind_of_prefix(identifier.substr(0, colon));
}

std::set<std::string> stringSet(const JValue* arr) {
    std::set<std::string> out;
    if (arr && arr->isArray())
        for (const JValue& v : arr->array)
            if (v.isString()) out.insert(v.str);
    return out;
}

// True when either temporal window is absent, or the windows overlap.
bool windowOverlap(const JValue& a, const JValue& b) {
    const JValue* ta = a.find("temporal");
    const JValue* tb = b.find("temporal");
    if (!ta || ta->isNull() || !tb || tb->isNull()) return true;
    double ua = static_cast<double>(unit_seconds(ta->at("unit").str));
    double ub = static_cast<double>(unit_seconds(tb->at("unit").str));
    double loA = ta->at("minimum_delay").asDouble() * ua;
    double hiA = ta->at("maximum_delay").asDouble() * ua;
    double loB = tb->at("minimum_delay").asDouble() * ub;
    double hiB = tb->at("maximum_delay").asDouble() * ub;
    return loA <= hiB && loB <= hiA;
}

bool contextsCompatible(const JValue& a, const JValue& b) {
    const JValue* ca = a.find("context");
    const JValue* cb = b.find("context");
    // Either absent (or empty) counts as compatible.
    if (!ca || !ca->isArray() || ca->array.empty()) return true;
    if (!cb || !cb->isArray() || cb->array.empty()) return true;
    std::set<std::string> sa = stringSet(ca), sb = stringSet(cb);
    if (sa == sb) return true;
    bool aInB = std::includes(sb.begin(), sb.end(), sa.begin(), sa.end());
    bool bInA = std::includes(sa.begin(), sa.end(), sb.begin(), sb.end());
    return aInB || bInA;
}

bool isPositiveModality(const std::string& m) {
    return m == "necessary" || m == "sufficient" || m == "contributory";
}

}  // namespace

std::pair<bool, std::vector<std::string>> validate_semantics(
    const JValue& obj, const std::string& kind) {
    std::string k = kind.empty() ? infer_kind(obj) : kind;
    std::vector<std::string> errors;

    if (k == "causal_relation_object") {
        const JValue* t = obj.find("temporal");
        if (t && t->isObject()) {
            const JValue* minimum_delay = t->find("minimum_delay");
            const JValue* maximum_delay = t->find("maximum_delay");
            if (minimum_delay && !minimum_delay->isNull() && maximum_delay && !maximum_delay->isNull() &&
                minimum_delay->asDouble() > maximum_delay->asDouble())
                errors.push_back("minimum_delay must be <= maximum_delay");
        }
        std::string oid = obj.getString("id");
        if (!oid.empty()) {
            const JValue* mechanism = obj.find("mechanism");
            if (mechanism && mechanism->isArray()) {
                for (const JValue& m : mechanism->array)
                    if (m.isString() && m.str == oid) {
                        errors.push_back(
                            "mechanism must be acyclic (a Causal Relation "
                            "Object may not contain itself)");
                        break;
                    }
            }
            if (obj.getString("refines") == oid)
                errors.push_back("refines must be acyclic");
        }
    }

    if (k == "enrichment") {
        std::string field = obj.getString("field");
        std::string about = obj.getString("about");
        const JValue* entry = obj.find("entry");
        for (const auto& spec : enrichmentFields()) {
            if (field != spec.field) continue;
            std::string aboutKind = kindOfId(about);
            if (!aboutKind.empty()) {
                bool legal = false;
                for (const char* lk : spec.legalKinds)
                    if (aboutKind == lk) { legal = true; break; }
                if (!legal)
                    errors.push_back(field + " is not a legal field for a " +
                                     aboutKind + " (rule 12)");
            }
            if (std::string(spec.shape) == "alias") {
                if (!(entry && entry->isObject() && entry->has("lang") &&
                      entry->has("text")))
                    errors.push_back(
                        "an aliases entry must be a language-tagged text "
                        "object");
            } else {
                std::string prefix = std::string(spec.shape) + ":";
                if (!(entry && entry->isString() &&
                      entry->str.rfind(prefix, 0) == 0))
                    errors.push_back("a " + field + " entry must be a " +
                                     spec.shape + ": identifier");
            }
            break;
        }
    }

    return {errors.empty(), errors};
}

std::pair<bool, std::vector<std::string>> is_partial(const JValue& cro) {
    std::vector<std::string> missing;
    for (const std::string& field : CRO_OPTIONAL_FIELDS)
        if (!cro.has(field)) missing.push_back(field);
    return {!missing.empty(), missing};
}

bool admissible(const JValue& cro, double elapsed_seconds) {
    const JValue* t = cro.find("temporal");
    if (!t || t->isNull()) return true;  // no window imposes no constraint
    double unit = static_cast<double>(unit_seconds(t->at("unit").str));
    double lo = t->at("minimum_delay").asDouble() * unit;
    double hi = t->at("maximum_delay").asDouble() * unit;
    return lo <= elapsed_seconds && elapsed_seconds <= hi;
}

bool conflicts(const JValue& a, const JValue& b) {
    if (stringSet(a.find("causes")) != stringSet(b.find("causes")))
        return false;
    if (stringSet(a.find("effects")) != stringSet(b.find("effects")))
        return false;
    if (!contextsCompatible(a, b)) return false;
    if (!windowOverlap(a, b)) return false;
    std::string ma = a.getString("modality");
    std::string mb = b.getString("modality");
    return (ma == "preventive" && isPositiveModality(mb)) ||
           (mb == "preventive" && isPositiveModality(ma));
}

std::pair<bool, std::string> refinement_valid(const JValue& child,
                                              const JValue& parent) {
    if (child.getString("refines") != parent.getString("id"))
        return {false, "child does not name the parent in refines"};
    if (stringSet(child.find("causes")) != stringSet(parent.find("causes")) ||
        stringSet(child.find("effects")) != stringSet(parent.find("effects")))
        return {false,
                "a refinement must keep the parent's causes and effects"};
    int added = 0;
    for (const std::string& field : CRO_OPTIONAL_FIELDS) {
        const JValue* parentValue = parent.find(field);
        const JValue* childValue = child.find(field);
        if (parentValue) {
            if (!childValue || *childValue != *parentValue)
                return {false,
                        "a refinement may not change a field the parent "
                        "specified; this is a rival claim"};
        } else if (childValue) {
            ++added;
        }
    }
    if (added == 0)
        return {false, "a refinement must add at least one unspecified field"};
    return {true, "valid refinement"};
}

std::string hierarchy_consistent(
    const JValue& parent, const std::map<std::string, JValue>& members) {
    const JValue* mechanism = parent.find("mechanism");
    if (!mechanism || !mechanism->isArray() || mechanism->array.empty())
        return "consistent";  // nothing claimed, nothing to check
    std::map<std::string, std::set<std::string>> edges;
    for (const JValue& mid : mechanism->array) {
        auto hit = members.find(mid.str);
        if (hit == members.end())
            return "indeterminate";  // a dangling_reference gap, not a failure
        const JValue& m = hit->second;
        for (const JValue& c : m.at("causes").array)
            for (const JValue& e : m.at("effects").array)
                edges[c.str].insert(e.str);
    }
    auto reachable = [&edges](const std::string& src, const std::string& dst) {
        std::set<std::string> seen;
        std::vector<std::string> stack = {src};
        while (!stack.empty()) {
            std::string node = stack.back();
            stack.pop_back();
            if (node == dst) return true;
            if (!seen.insert(node).second) continue;
            auto hit = edges.find(node);
            if (hit != edges.end())
                for (const std::string& next : hit->second)
                    stack.push_back(next);
        }
        return false;
    };
    for (const JValue& c : parent.at("causes").array)
        for (const JValue& e : parent.at("effects").array)
            if (!reachable(c.str, e.str)) return "inconsistent";
    return "consistent";
}

}  // namespace co

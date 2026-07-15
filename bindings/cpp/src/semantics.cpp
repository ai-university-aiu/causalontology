// semantics.cpp - the 13 semantic rules' locally checkable subset.

#include "semantics.hpp"

#include <algorithm>
#include <cmath>
#include <functional>
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
        {"occurrent_subsumes", {"occurrent"}, "occurrent"},
        {"occurrent_part_of", {"occurrent"}, "occurrent"},
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
    return m == "necessary" || m == "sufficient" || m == "contributory" ||
           m == "enabling";
}

bool hasMechanism(const JValue& cro) {
    const JValue* m = cro.find("mechanism");
    return m && m->isArray() && !m->array.empty();
}

std::vector<std::string> stringVec(const JValue& obj, const std::string& key) {
    std::vector<std::string> out;
    const JValue* arr = obj.find(key);
    if (arr && arr->isArray())
        for (const JValue& v : arr->array)
            if (v.isString()) out.push_back(v.str);
    return out;
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
        // Rule 16, clause 1 (contradictory_skip): a HARD, locally-decidable
        // contradiction between skips:true and a non-empty mechanism.
        const JValue* skips = obj.find("skips");
        if (skips && skips->isBool() && skips->boolean && hasMechanism(obj))
            errors.push_back(
                "contradictory_skip: skips is true but a mechanism is present");
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

// ALGORITHM A: bridge closure (N12.1).
std::set<std::string> bridge_closure(const std::string& occurrent_id,
                                     const std::vector<JValue>& bridges) {
    std::set<std::string> result = {occurrent_id};
    std::vector<std::string> frontier = {occurrent_id};
    std::set<std::string> visited;
    std::map<std::string, std::vector<const JValue*>> coarseIndex;
    for (const JValue& b : bridges)
        coarseIndex[b.getString("coarse")].push_back(&b);
    while (!frontier.empty()) {
        std::string current = frontier.back();
        frontier.pop_back();
        if (!visited.insert(current).second) continue;
        auto hit = coarseIndex.find(current);
        if (hit == coarseIndex.end()) continue;
        for (const JValue* b : hit->second)
            for (const std::string& f : stringVec(*b, "fine")) {
                result.insert(f);
                frontier.push_back(f);
            }
    }
    return result;
}

std::string hierarchy_consistent(const JValue& parent,
                                 const std::map<std::string, JValue>& members,
                                 const std::vector<JValue>& bridges) {
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
    std::map<std::string, std::set<std::string>> bCause, bEffect;
    for (const JValue& c : parent.at("causes").array)
        bCause[c.str] = bridge_closure(c.str, bridges);
    for (const JValue& e : parent.at("effects").array)
        bEffect[e.str] = bridge_closure(e.str, bridges);
    for (const JValue& c : parent.at("causes").array) {
        for (const JValue& e : parent.at("effects").array) {
            bool connected = false;
            for (const std::string& cp : bCause[c.str]) {
                for (const std::string& ep : bEffect[e.str])
                    if (reachable(cp, ep)) { connected = true; break; }
                if (connected) break;
            }
            if (!connected) return "inconsistent";
        }
    }
    return "consistent";
}

// ALGORITHM C: stratal classification (Rule 15).
std::string classify_cro(const JValue& cro,
                         const std::map<std::string, JValue>& occ_map,
                         const std::map<std::string, JValue>& stratum_map) {
    auto stratumOf = [&occ_map](const std::string& occId) -> std::string {
        auto hit = occ_map.find(occId);
        if (hit == occ_map.end()) return "";
        return hit->second.getString("stratum");
    };
    std::vector<std::string> causeStrata, effectStrata;
    for (const std::string& c : stringVec(cro, "causes"))
        causeStrata.push_back(stratumOf(c));
    for (const std::string& e : stringVec(cro, "effects"))
        effectStrata.push_back(stratumOf(e));
    std::set<std::string> allStrata;
    for (const std::string& s : causeStrata) {
        if (s.empty()) return "unclassifiable";
        allStrata.insert(s);
    }
    for (const std::string& s : effectStrata) {
        if (s.empty()) return "unclassifiable";
        allStrata.insert(s);
    }
    std::set<std::string> schemes;
    for (const std::string& s : allStrata)
        schemes.insert(stratum_map.at(s).getString("scheme"));
    if (schemes.size() > 1) return "scheme_mismatch";
    auto ordOf = [&stratum_map](const std::string& s) -> int64_t {
        return stratum_map.at(s).at("ordinal").integer;
    };
    std::vector<int64_t> cOrd, eOrd;
    for (const std::string& s : causeStrata) cOrd.push_back(ordOf(s));
    for (const std::string& s : effectStrata) eOrd.push_back(ordOf(s));
    int64_t cMax = cOrd[0], cMin = cOrd[0], eMax = eOrd[0], eMin = eOrd[0];
    for (int64_t v : cOrd) { cMax = std::max(cMax, v); cMin = std::min(cMin, v); }
    for (int64_t v : eOrd) { eMax = std::max(eMax, v); eMin = std::min(eMin, v); }
    if (cMax == cMin && cMin == eMax && eMax == eMin) return "intra_stratal";
    int64_t gap = -1, span = -1;
    for (int64_t i : cOrd)
        for (int64_t j : eOrd) {
            int64_t d = std::abs(i - j);
            if (gap < 0 || d < gap) gap = d;
            if (span < 0 || d > span) span = d;
        }
    if (span == 1) return "adjacent_stratal";
    if (gap > 1) return "skipping";
    return "mixed";
}

bool endpoints_mixed(const JValue& cro,
                     const std::map<std::string, JValue>& occ_map) {
    auto stratumOf = [&occ_map](const std::string& occId) -> std::string {
        auto hit = occ_map.find(occId);
        if (hit == occ_map.end()) return "";
        return hit->second.getString("stratum");
    };
    std::set<std::string> cs, es;
    for (const std::string& c : stringVec(cro, "causes")) cs.insert(stratumOf(c));
    for (const std::string& e : stringVec(cro, "effects")) es.insert(stratumOf(e));
    if (cs.count("") || es.count("")) return false;
    return cs.size() > 1 || es.size() > 1;
}

// ALGORITHM D: the skip decision gaps (Rule 16), THE ASYMMETRY.
std::vector<std::string> skip_gaps(const JValue& cro,
                                   const std::string& classification) {
    std::vector<std::string> gaps;
    bool hasMech = hasMechanism(cro);
    const JValue* skips = cro.find("skips");
    bool skipsTrue = skips && skips->isBool() && skips->boolean;
    if (skipsTrue && hasMech) {
        gaps.push_back("contradictory_skip");  // HARD
        return gaps;
    }
    if (skipsTrue && classification != "skipping" &&
        classification != "unclassifiable")
        gaps.push_back("vacuous_skip");  // invitation
    if (classification == "skipping" && !hasMech) {
        if (skipsTrue) {
            // NOTHING: the absence of a mechanism is a positive finding.
        } else {
            gaps.push_back("incomplete_mechanism");  // invitation
        }
    }
    return gaps;
}

// ALGORITHM E helpers.
double to_seconds(double duration, const std::string& unit) {
    if (unit == "instant") return 0;
    return duration * static_cast<double>(unit_seconds(unit));
}

bool delay_within_window(const JValue& actual_delay, const JValue& temporal) {
    if (!actual_delay.isObject() || actual_delay.object.empty()) return true;
    if (!temporal.isObject() || temporal.object.empty()) return true;
    double observed = to_seconds(actual_delay.at("duration").asDouble(),
                                 actual_delay.at("unit").str);
    double lo = to_seconds(temporal.at("minimum_delay").asDouble(),
                           temporal.at("unit").str);
    double hi = to_seconds(temporal.at("maximum_delay").asDouble(),
                           temporal.at("unit").str);
    return lo <= observed && observed <= hi;
}

// Rule 14: bridge well-formedness (N3.2.1).
std::pair<bool, std::string> bridge_wellformed(
    const JValue& bridge, const std::map<std::string, JValue>& occ_map,
    const std::map<std::string, JValue>& stratum_map) {
    auto stratumOf = [&occ_map](const std::string& occId) -> std::string {
        auto hit = occ_map.find(occId);
        if (hit == occ_map.end()) return "";
        return hit->second.getString("stratum");
    };
    std::string cs = stratumOf(bridge.getString("coarse"));
    if (cs.empty())
        return {false, "malformed_bridge: coarse has no stratum (a)"};
    std::vector<std::string> fineStrata;
    for (const std::string& f : stringVec(bridge, "fine"))
        fineStrata.push_back(stratumOf(f));
    for (const std::string& s : fineStrata)
        if (s.empty())
            return {false, "malformed_bridge: a fine member has no stratum (b)"};
    std::set<std::string> distinct(fineStrata.begin(), fineStrata.end());
    if (distinct.size() != 1)
        return {false, "malformed_bridge: fine members span >1 stratum (c)"};
    std::string fs = fineStrata[0];
    if (stratum_map.at(cs).getString("scheme") !=
        stratum_map.at(fs).getString("scheme"))
        return {false, "malformed_bridge: coarse and fine differ in scheme (d)"};
    if (!(stratum_map.at(cs).at("ordinal").integer >
          stratum_map.at(fs).at("ordinal").integer))
        return {false, "malformed_bridge: coarse ordinal not > fine ordinal (e)"};
    return {true, "well-formed bridge"};
}

// Rule 17: conduit well-formedness (N4.2.1-2).
std::pair<bool, std::string> conduit_wellformed(
    const JValue& conduit, const std::map<std::string, JValue>& port_map,
    const std::map<std::string, JValue>* cro_map) {
    auto frmIt = port_map.find(conduit.getString("from"));
    auto toIt = port_map.find(conduit.getString("to"));
    if (frmIt == port_map.end() || toIt == port_map.end())
        return {false, "malformed_conduit: dangling port reference"};
    const JValue& frm = frmIt->second;
    const JValue& to = toIt->second;
    std::string fdir = frm.getString("direction");
    if (fdir != "out" && fdir != "bidirectional")
        return {false,
                "malformed_conduit: from port is not out/bidirectional (a)"};
    std::string tdir = to.getString("direction");
    if (tdir != "in" && tdir != "bidirectional")
        return {false, "malformed_conduit: to port is not in/bidirectional (b)"};
    std::vector<std::string> carries = stringVec(conduit, "carries");
    std::set<std::string> fromAccepts;
    for (const std::string& o : stringVec(frm, "accepts")) fromAccepts.insert(o);
    for (const std::string& o : carries)
        if (!fromAccepts.count(o))
            return {false,
                    "malformed_conduit: carries not accepted by from (c)"};
    const JValue* transform = conduit.find("transform");
    std::set<std::string> toAccepts;
    for (const std::string& o : stringVec(to, "accepts")) toAccepts.insert(o);
    if (!transform || transform->isNull()) {
        for (const std::string& o : carries)
            if (!toAccepts.count(o))
                return {false,
                        "malformed_conduit: carries not accepted by to (d)"};
    } else if (cro_map) {
        auto lawIt = cro_map->find(transform->str);
        if (lawIt != cro_map->end()) {
            for (const std::string& o : stringVec(lawIt->second, "effects"))
                if (!toAccepts.count(o))
                    return {false,
                            "malformed_conduit: transform effects not accepted "
                            "by to (d, relaxed per N4.2.2)"};
        }
    }
    return {true, "well-formed conduit"};
}

// Rule 19: state value-type and unit coherence (N5.3.1-2).
std::vector<std::string> state_gaps(const JValue& state,
                                    const JValue& quality) {
    std::vector<std::string> gaps;
    std::string dt = quality.getString("datatype");
    const JValue* v = state.find("value");
    std::string shape;
    if (v && v->isObject()) {
        if (v->has("quantity")) shape = "quantity";
        else if (v->has("categorical")) shape = "categorical";
        else if (v->has("boolean")) shape = "boolean";
    }
    if (shape != dt) {
        gaps.push_back("value_type_mismatch");
    } else if (dt == "quantity" &&
               v->getString("unit") != quality.getString("unit")) {
        gaps.push_back("unit_mismatch");
    }
    return gaps;
}

// Rule 20: covering-law coherence.
bool covering_law_mismatch(const JValue& tcc,
                           const std::map<std::string, JValue>& token_map,
                           const JValue& law) {
    if (!law.isObject() || law.object.empty()) return false;
    std::set<std::string> lawCauses, lawEffects;
    for (const std::string& c : stringVec(law, "causes")) lawCauses.insert(c);
    for (const std::string& e : stringVec(law, "effects")) lawEffects.insert(e);
    for (const std::string& c : stringVec(tcc, "causes"))
        if (!lawCauses.count(token_map.at(c).getString("instantiates")))
            return true;
    for (const std::string& e : stringVec(tcc, "effects"))
        if (!lawEffects.count(token_map.at(e).getString("instantiates")))
            return true;
    return false;
}

// Rule 21: temporal coherence of token causation.
bool retrocausal(const JValue& tcc,
                 const std::map<std::string, JValue>& token_map) {
    for (const std::string& c : stringVec(tcc, "causes")) {
        std::string cstart =
            token_map.at(c).at("interval").getString("start");
        for (const std::string& e : stringVec(tcc, "effects")) {
            std::string estart =
                token_map.at(e).at("interval").getString("start");
            if (cstart > estart) return true;
        }
    }
    return false;
}

// Rules 4 / 6.1: directed-graph cycle detection.
bool has_cycle(const std::map<std::string, std::vector<std::string>>& edges) {
    std::map<std::string, int> state;  // 0 white, 1 grey, 2 black
    std::function<bool(const std::string&)> visit =
        [&](const std::string& node) -> bool {
        state[node] = 1;
        auto hit = edges.find(node);
        if (hit != edges.end())
            for (const std::string& nxt : hit->second) {
                int s = state.count(nxt) ? state[nxt] : 0;
                if (s == 1) return true;
                if (s == 0 && visit(nxt)) return true;
            }
        state[node] = 2;
        return false;
    };
    for (const auto& kv : edges) {
        int s = state.count(kv.first) ? state[kv.first] : 0;
        if (s == 0 && visit(kv.first)) return true;
    }
    return false;
}

}  // namespace co

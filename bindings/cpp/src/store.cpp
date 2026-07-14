// store.cpp - the in-memory conformant store.

#include "store.hpp"

#include <functional>
#include <map>

#include "canonical.hpp"
#include "jcs.hpp"
#include "schema.hpp"
#include "semantics.hpp"
#include "signing.hpp"

namespace co {

namespace {

bool isContentKind(const std::string& kind) {
    return kind == "occurrent" || kind == "cro" || kind == "continuant" ||
           kind == "realizable";
}

bool isRecordKind(const std::string& kind) {
    return kind == "assertion" || kind == "enrichment" ||
           kind == "retraction" || kind == "succession";
}

std::string join(const std::vector<std::string>& parts,
                 const std::string& sep) {
    std::string out;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i) out += sep;
        out += parts[i];
    }
    return out;
}

// "_".join(text.strip().lower().split())
std::string canonLabel(const std::string& text) {
    std::vector<std::string> words;
    std::string word;
    for (char c : text) {
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' ||
            c == '\v') {
            if (!word.empty()) { words.push_back(word); word.clear(); }
        } else {
            word.push_back(
                (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c);
        }
    }
    if (!word.empty()) words.push_back(word);
    return join(words, "_");
}

// " ".join(text.split()).casefold() - ASCII casefold suffices here.
std::string normAlias(const std::string& text) {
    std::vector<std::string> words;
    std::string word;
    for (char c : text) {
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' ||
            c == '\v') {
            if (!word.empty()) { words.push_back(word); word.clear(); }
        } else {
            word.push_back(
                (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c);
        }
    }
    if (!word.empty()) words.push_back(word);
    return join(words, " ");
}

}  // namespace

const JValue* InMemoryStore::findObject(const std::string& id) const {
    for (const auto& kv : objects_)
        if (kv.first == id) return &kv.second;
    return nullptr;
}

const JValue* InMemoryStore::findRecord(const std::string& id) const {
    for (const auto& kv : records_)
        if (kv.first == id) return &kv.second;
    return nullptr;
}

// ------------------------------------------------------------------- put

std::string InMemoryStore::put(JValue obj, const std::string& kind) {
    std::string k = kind.empty() ? infer_kind(obj) : kind;
    if (!isContentKind(k))
        throw std::runtime_error("put() takes content objects; use put_record()");
    obj.setDefault("type", JValue::of(k));
    if (!obj.has("id")) obj.set("id", JValue::of(identify(obj, k)));
    std::string id = obj.at("id").str;
    if (findObject(id)) return id;  // immutable: identical identity is a no-op
    auto [schemaOk, schemaWhy] = validate_schema(obj, k);
    if (!schemaOk) throw RejectedWrite(join(schemaWhy, "; "));
    auto [semanticsOk, semanticsWhy] = validate_semantics(obj, k);
    if (!semanticsOk) throw RejectedWrite(join(semanticsWhy, "; "));
    objects_.emplace_back(id, std::move(obj));
    return id;
}

std::string InMemoryStore::putRecordImpl(JValue record,
                                         const std::string& kind, bool force) {
    std::string k = kind.empty() ? infer_kind(record) : kind;
    if (!isRecordKind(k))
        throw std::runtime_error("put_record() takes provenance records");
    record.setDefault("type", JValue::of(k));
    std::string rid = record.getString("id");
    if (rid.empty()) rid = identify(record, k);
    record.set("id", JValue::of(rid));
    if (findRecord(rid)) return rid;  // add-only and idempotent
    if (!verify_record(record, k)) {
        quarantine_.emplace_back(rid, record);
        throw RejectedWrite("unsigned or unverifiable record: quarantined");
    }
    auto [semanticsOk, semanticsWhy] = validate_semantics(record, k);
    if (!semanticsOk) throw RejectedWrite(join(semanticsWhy, "; "));
    if (k == "retraction" && !retractionSourceOk(record))
        throw RejectedWrite(
            "a retraction is valid only from the retracted record's source "
            "or its succession lineage");
    if (k == "enrichment" && enforcing_ && !force) {
        std::string field = record.getString("field");
        if ((field == "subsumes" || field == "part_of") && wouldCycle(record))
            throw RejectedWrite("would create a cycle in the materialized " +
                                field + " graph");
    }
    records_.emplace_back(rid, std::move(record));
    return rid;
}

std::string InMemoryStore::put_record(JValue record, const std::string& kind) {
    return putRecordImpl(std::move(record), kind, false);
}

std::string InMemoryStore::force_merge_record(JValue record,
                                              const std::string& kind) {
    return putRecordImpl(std::move(record), kind, true);
}

// -------------------------------------------------------- record queries

std::vector<const JValue*> InMemoryStore::recordsOf(
    const std::string& kind) const {
    std::vector<const JValue*> out;
    for (const auto& kv : records_)
        if (kv.second.getString("type") == kind) out.push_back(&kv.second);
    return out;
}

std::set<std::string> InMemoryStore::retractedIds() const {
    std::set<std::string> out;
    for (const JValue* r : recordsOf("retraction"))
        out.insert(r->getString("retracts"));
    return out;
}

bool InMemoryStore::retractionSourceOk(const JValue& retraction) const {
    const JValue* target = findRecord(retraction.getString("retracts"));
    if (!target) return true;  // open world: the target may arrive later
    std::set<std::string> chain = lineage(target->getString("source"));
    return chain.count(retraction.getString("source")) > 0;
}

std::set<std::string> InMemoryStore::lineage(const std::string& key) const {
    std::map<std::string, std::string> succ, pred;
    for (const JValue* s : recordsOf("succession")) {
        succ[s->getString("predecessor")] = s->getString("successor");
        pred[s->getString("successor")] = s->getString("predecessor");
    }
    std::set<std::string> chain = {key};
    std::string cursor = key;
    while (pred.count(cursor)) {
        cursor = pred[cursor];
        if (!chain.insert(cursor).second) break;  // guard a malformed loop
    }
    cursor = key;
    while (succ.count(cursor)) {
        cursor = succ[cursor];
        if (!chain.insert(cursor).second) break;
    }
    return chain;
}

std::vector<JValue> InMemoryStore::assertions_about(
    const std::string& identifier, bool include_retracted) const {
    std::set<std::string> retracted = retractedIds();
    std::vector<JValue> out;
    for (const JValue* r : recordsOf("assertion")) {
        if (r->getString("about") != identifier) continue;
        if (retracted.count(r->getString("id"))) {
            if (include_retracted) {
                JValue copy = *r;
                copy.set("retracted", JValue::of(true));
                out.push_back(std::move(copy));
            }
            continue;
        }
        out.push_back(*r);
    }
    return out;
}

std::vector<JValue> InMemoryStore::enrichments_about(
    const std::string& identifier, bool include_retracted) const {
    std::set<std::string> retracted = retractedIds();
    std::vector<JValue> out;
    for (const JValue* r : recordsOf("enrichment")) {
        if (r->getString("about") != identifier) continue;
        if (retracted.count(r->getString("id")) && !include_retracted)
            continue;
        out.push_back(*r);
    }
    return out;
}

// --------------------------------------------------- materialized views

std::vector<size_t> InMemoryStore::findCycleRecords(
    const std::vector<JValue>& recs) {
    // edges: about -> [(entry, record index)], in insertion order.
    std::vector<std::pair<std::string, std::vector<std::pair<std::string, size_t>>>>
        edges;
    auto edgesFor = [&edges](const std::string& node)
        -> std::vector<std::pair<std::string, size_t>>* {
        for (auto& kv : edges)
            if (kv.first == node) return &kv.second;
        return nullptr;
    };
    for (size_t i = 0; i < recs.size(); ++i) {
        std::string about = recs[i].getString("about");
        auto* list = edgesFor(about);
        if (!list) {
            edges.emplace_back(
                about, std::vector<std::pair<std::string, size_t>>());
            list = &edges.back().second;
        }
        list->emplace_back(recs[i].getString("entry"), i);
    }
    std::map<std::string, int> state;  // 0 unseen, 1 on stack, 2 done
    std::vector<size_t> cycle;
    std::vector<size_t> path;
    std::function<bool(const std::string&)> dfs =
        [&](const std::string& node) -> bool {
        state[node] = 1;
        auto* list = edgesFor(node);
        if (list) {
            for (const auto& [next, recIdx] : *list) {
                int nextState = state.count(next) ? state[next] : 0;
                if (nextState == 1) {
                    // The path so far plus the closing record is the cycle
                    // chain the deterministic exclusion chooses from.
                    cycle = path;
                    cycle.push_back(recIdx);
                    return true;
                }
                if (nextState == 0) {
                    path.push_back(recIdx);
                    if (dfs(next)) return true;
                    path.pop_back();
                }
            }
        }
        state[node] = 2;
        return false;
    };
    for (size_t e = 0; e < edges.size(); ++e) {
        const std::string start = edges[e].first;
        int startState = state.count(start) ? state[start] : 0;
        if (startState == 0) {
            path.clear();
            if (dfs(start)) return cycle;
        }
    }
    return {};
}

std::pair<std::vector<JValue>, std::vector<JValue>>
InMemoryStore::active_taxonomy_edges(const std::string& field) const {
    std::set<std::string> retracted = retractedIds();
    std::vector<JValue> active;
    for (const JValue* r : recordsOf("enrichment"))
        if (r->getString("field") == field &&
            !retracted.count(r->getString("id")))
            active.push_back(*r);
    std::vector<JValue> excluded;
    while (true) {
        std::vector<size_t> cyc = findCycleRecords(active);
        if (cyc.empty()) break;
        // Exclude the cycle-completing record with the LATEST timestamp,
        // ties broken by lexicographic record identifier (deterministic).
        size_t loser = cyc[0];
        for (size_t idx : cyc) {
            std::pair<std::string, std::string> a = {
                active[idx].getString("timestamp"),
                active[idx].getString("id")};
            std::pair<std::string, std::string> b = {
                active[loser].getString("timestamp"),
                active[loser].getString("id")};
            if (a > b) loser = idx;
        }
        excluded.push_back(active[loser]);
        active.erase(active.begin() + static_cast<long>(loser));
    }
    return {active, excluded};
}

bool InMemoryStore::wouldCycle(const JValue& record) const {
    std::set<std::string> retracted = retractedIds();
    std::vector<JValue> recs;
    for (const JValue* r : recordsOf("enrichment"))
        if (r->getString("field") == record.getString("field") &&
            !retracted.count(r->getString("id")))
            recs.push_back(*r);
    recs.push_back(record);
    return !findCycleRecords(recs).empty();
}

std::optional<JValue> InMemoryStore::get(const std::string& identifier,
                                         const std::string& view) const {
    const JValue* obj = findObject(identifier);
    if (!obj) return std::nullopt;
    bool includeRetracted = (view == "history");
    std::set<std::string> excludedIds;
    for (const std::string& field : {std::string("subsumes"),
                                     std::string("part_of")}) {
        auto [active, excluded] = active_taxonomy_edges(field);
        (void)active;
        for (const JValue& r : excluded) excludedIds.insert(r.getString("id"));
    }
    // field -> ordered buckets keyed by the canonical entry bytes.
    struct Bucket {
        std::string key;
        JValue entry;
        JValue contributors = JValue::makeArray();
    };
    std::vector<std::pair<std::string, std::vector<Bucket>>> fields;
    for (const JValue& rec : enrichments_about(identifier, includeRetracted)) {
        if (excludedIds.count(rec.getString("id")) && view != "history")
            continue;
        std::string field = rec.getString("field");
        std::string entryKey = jcs(rec.at("entry"));
        std::vector<Bucket>* slot = nullptr;
        for (auto& kv : fields)
            if (kv.first == field) { slot = &kv.second; break; }
        if (!slot) {
            fields.emplace_back(field, std::vector<Bucket>());
            slot = &fields.back().second;
        }
        Bucket* bucket = nullptr;
        for (Bucket& b : *slot)
            if (b.key == entryKey) { bucket = &b; break; }
        if (!bucket) {
            slot->push_back(Bucket{entryKey, rec.at("entry"), JValue::makeArray()});
            bucket = &slot->back();
        }
        JValue contributor = JValue::makeObject();
        contributor.set("source", JValue::of(rec.getString("source")));
        contributor.set("timestamp", JValue::of(rec.getString("timestamp")));
        bucket->contributors.array.push_back(std::move(contributor));
    }
    JValue result = JValue::makeObject();
    result.set("object", *obj);
    if (view == "raw") return result;
    JValue enrichments = JValue::makeObject();
    for (auto& kv : fields) {
        JValue list = JValue::makeArray();
        for (Bucket& b : kv.second) {
            JValue item = JValue::makeObject();
            item.set("entry", b.entry);
            item.set("contributors", b.contributors);
            list.array.push_back(std::move(item));
        }
        enrichments.set(kv.first, std::move(list));
    }
    result.set("enrichments", std::move(enrichments));
    return result;
}

// -------------------------------------------------------------- resolve

std::vector<std::string> InMemoryStore::resolve(const std::string& text,
                                                const char* lang) const {
    std::vector<std::string> labelHits, aliasHits;
    std::string wantedLabel = canonLabel(text);
    std::string wantedAlias = normAlias(text);
    std::set<std::string> retracted = retractedIds();
    for (const auto& [oid, obj] : objects_) {
        std::string type = obj.getString("type");
        if (type != "occurrent" && type != "continuant") continue;
        if (obj.getString("label") == wantedLabel) {
            labelHits.push_back(oid);
            continue;
        }
        for (const JValue* rec : recordsOf("enrichment")) {
            if (rec->getString("about") != oid ||
                rec->getString("field") != "aliases")
                continue;
            if (retracted.count(rec->getString("id"))) continue;
            const JValue* entry = rec->find("entry");
            if (!entry || !entry->isObject()) continue;
            if (lang != nullptr && entry->getString("lang") != lang) continue;
            if (normAlias(entry->getString("text")) == wantedAlias) {
                aliasHits.push_back(oid);
                break;
            }
        }
    }
    labelHits.insert(labelHits.end(), aliasHits.begin(), aliasHits.end());
    return labelHits;
}

// ---------------------------------------------------------------- gaps

std::vector<JValue> InMemoryStore::gaps(const std::string& kind) const {
    std::vector<JValue> out;
    std::set<std::string> refined;
    for (const auto& [oid, obj] : objects_) {
        (void)oid;
        if (obj.getString("type") != "cro") continue;
        std::string refines = obj.getString("refines");
        if (refines.empty()) continue;
        const JValue* parent = findObject(refines);
        if (parent) {
            auto [ok, reason] = refinement_valid(obj, *parent);
            (void)reason;
            if (ok) refined.insert(parent->getString("id"));
        }
    }
    for (const auto& [oid, obj] : objects_) {
        if (obj.getString("type") != "cro") continue;
        // missing_field: lacking the temporal window or the modality -
        // mechanism and context may legitimately stay unspecified forever
        // (empty_mechanism is its own kind; absent context = context-free).
        if ((!obj.has("temporal") || !obj.has("modality")) &&
            !refined.count(oid)) {
            JValue gap = JValue::makeObject();
            gap.set("id", JValue::of(oid));
            gap.set("kind", JValue::of("missing_field"));
            JValue missing = JValue::makeArray();
            for (const std::string& f : is_partial(obj).second)
                missing.array.push_back(JValue::of(f));
            gap.set("missing", std::move(missing));
            out.push_back(std::move(gap));
        }
        const JValue* mechanism = obj.find("mechanism");
        if (!mechanism || (mechanism->isArray() && mechanism->array.empty())) {
            if (!refined.count(oid)) {
                JValue gap = JValue::makeObject();
                gap.set("id", JValue::of(oid));
                gap.set("kind", JValue::of("empty_mechanism"));
                out.push_back(std::move(gap));
            }
        }
    }
    for (const std::string& field : {std::string("subsumes"),
                                     std::string("part_of")}) {
        auto [active, excluded] = active_taxonomy_edges(field);
        (void)active;
        for (const JValue& rec : excluded) {
            JValue gap = JValue::makeObject();
            gap.set("id", JValue::of(rec.getString("id")));
            gap.set("kind", JValue::of("inconsistent_hierarchy"));
            gap.set("note",
                    JValue::of("excluded by the deterministic "
                               "cycle-breaking view rule"));
            out.push_back(std::move(gap));
        }
    }
    // dangling_reference: a reference to an object absent from the store -
    // the red link that says "this page is wanted".
    for (const auto& [oid, obj] : objects_) {
        std::vector<std::string> refs;
        std::string type = obj.getString("type");
        if (type == "cro") {
            for (const char* field : {"causes", "effects", "context",
                                      "mechanism"}) {
                const JValue* list = obj.find(field);
                if (list && list->isArray())
                    for (const JValue& ref : list->array)
                        if (ref.isString()) refs.push_back(ref.str);
            }
            std::string refines = obj.getString("refines");
            if (!refines.empty()) refs.push_back(refines);
        } else if (type == "realizable") {
            refs.push_back(obj.getString("bearer"));
        }
        for (const std::string& ref : refs) {
            if (!ref.empty() && !findObject(ref)) {
                JValue gap = JValue::makeObject();
                gap.set("id", JValue::of(oid));
                gap.set("kind", JValue::of("dangling_reference"));
                gap.set("ref", JValue::of(ref));
                out.push_back(std::move(gap));
            }
        }
    }
    // conflict: pairs of claims satisfying the formal test (rule 6).
    std::vector<const JValue*> cros;
    for (const auto& kv : objects_)
        if (kv.second.getString("type") == "cro") cros.push_back(&kv.second);
    for (size_t i = 0; i < cros.size(); ++i) {
        for (size_t j = i + 1; j < cros.size(); ++j) {
            if (conflicts(*cros[i], *cros[j])) {
                JValue gap = JValue::makeObject();
                gap.set("kind", JValue::of("conflict"));
                gap.set("a", JValue::of(cros[i]->getString("id")));
                gap.set("b", JValue::of(cros[j]->getString("id")));
                out.push_back(std::move(gap));
            }
        }
    }
    if (!kind.empty()) {
        std::vector<JValue> filtered;
        for (JValue& g : out)
            if (g.getString("kind") == kind) filtered.push_back(std::move(g));
        return filtered;
    }
    return out;
}

}  // namespace co

// store.hpp - an in-memory conformant store.
//
// Implements the store side of the abstract operation set (spec/store.md):
// immutable content objects with idempotent put; signed, add-only
// provenance records; materialized enrichment views with contributors;
// retraction handling in default views; succession lineage; the resolve
// minimum; the deterministic cycle-breaking view rule; and the stigmergy
// gap read. Insertion order is explicit everywhere the Python binding
// leans on dict ordering.

#pragma once

#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "json.hpp"

namespace co {

// An enforcing store refused a write; the reason is what().
class RejectedWrite : public std::runtime_error {
public:
    explicit RejectedWrite(const std::string& why)
        : std::runtime_error(why) {}
};

class InMemoryStore {
public:
    explicit InMemoryStore(bool enforcing = true) : enforcing_(enforcing) {}

    // Write a content object; idempotent; returns the identifier.
    std::string put(JValue obj, const std::string& kind = "");

    // Write a signed provenance record; returns the identifier.
    std::string put_record(JValue record, const std::string& kind = "");

    // Simulate a decentralized replica merge (no enforcement gate).
    std::string force_merge_record(JValue record, const std::string& kind = "");

    // The succession chain closure containing key (includes key).
    std::set<std::string> lineage(const std::string& key) const;

    // Assertions about an identifier; retracted ones excluded by default,
    // or included with a "retracted": true flag.
    std::vector<JValue> assertions_about(const std::string& identifier,
                                         bool include_retracted = false) const;

    // Enrichment records about an identifier.
    std::vector<JValue> enrichments_about(const std::string& identifier,
                                          bool include_retracted = false) const;

    // (active, excluded) for subsumes/part_of after rule 13 cycle-breaking.
    std::pair<std::vector<JValue>, std::vector<JValue>> active_taxonomy_edges(
        const std::string& field) const;

    // The object with its materialized enrichment sets and contributors.
    // view: "default" | "history" | "raw". Nullopt when the id is unknown.
    std::optional<JValue> get(const std::string& identifier,
                              const std::string& view = "default") const;

    // The conformance minimum: exact label, then alias, then nothing.
    // lang: pass nullptr for no language filter.
    std::vector<std::string> resolve(const std::string& text,
                                     const char* lang = nullptr) const;

    // The stigmergy read; kind "" means every gap kind.
    std::vector<JValue> gaps(const std::string& kind = "") const;

    // The number of stored content objects (conformance visibility).
    size_t object_count() const { return objects_.size(); }
    // The number of quarantined records (unsigned / unverifiable).
    size_t quarantine_count() const { return quarantine_.size(); }

private:
    bool enforcing_;
    // Insertion-ordered id -> object / record association vectors.
    std::vector<std::pair<std::string, JValue>> objects_;
    std::vector<std::pair<std::string, JValue>> records_;
    std::vector<std::pair<std::string, JValue>> quarantine_;

    std::string putRecordImpl(JValue record, const std::string& kind,
                              bool force);
    const JValue* findObject(const std::string& id) const;
    const JValue* findRecord(const std::string& id) const;
    std::vector<const JValue*> recordsOf(const std::string& kind) const;
    std::set<std::string> retractedIds() const;
    bool retractionSourceOk(const JValue& retraction) const;
    bool wouldCycle(const JValue& record) const;

    // The record indices (into recs) of a cycle-completing chain, or empty.
    static std::vector<size_t> findCycleRecords(
        const std::vector<JValue>& recs);
};

}  // namespace co

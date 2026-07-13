// Store.swift
//
// An in-memory conformant store.
//
// Implements the store side of the abstract operation set (spec/store.md):
// immutable content objects with idempotent put; signed, add-only provenance
// records; materialized enrichment views with contributors; retraction
// handling in default views; succession lineage; the resolve minimum; the
// deterministic cycle-breaking view rule; and the stigmergy gap read.
// A faithful port of the Python binding's store.py, with insertion order
// kept explicitly (Swift dictionaries are unordered; Python dicts are not).

import Foundation

/// An enforcing store refused a write; the reason is the message.
public struct RejectedWrite: Error, CustomStringConvertible {
    public let message: String

    public init(_ message: String) {
        self.message = message
    }

    public var description: String {
        return message
    }
}

/// The four immutable content object kinds.
public let contentKinds: Set<String> = ["occurrent", "cro", "continuant", "realizable"]

/// The four signed provenance record kinds.
public let recordKinds: Set<String> = ["assertion", "enrichment", "retraction", "succession"]

public final class InMemoryStore {
    /// Enforcing stores reject cycle-completing taxonomy writes up front.
    public let enforcing: Bool

    /// The schema validator used by put().
    private let validator: SchemaValidator

    /// id -> content object.
    public private(set) var objects: [String: [String: JsonValue]] = [:]

    /// Content object ids in insertion order.
    public private(set) var objectOrder: [String] = []

    /// id -> provenance record.
    public private(set) var records: [String: [String: JsonValue]] = [:]

    /// Provenance record ids in insertion order.
    public private(set) var recordOrder: [String] = []

    /// id -> record (unsigned / unverifiable).
    public private(set) var quarantine: [String: [String: JsonValue]] = [:]

    public init(enforcing: Bool = true, validator: SchemaValidator = SchemaValidator.standard) {
        self.enforcing = enforcing
        self.validator = validator
    }

    // MARK: - put

    /// Write a content object; idempotent; returns the identifier.
    @discardableResult
    public func put(_ object: [String: JsonValue], kind: String? = nil) throws -> String {
        let resolvedKind: String
        if let kind = kind {
            resolvedKind = kind
        } else {
            resolvedKind = try inferKind(object)
        }
        guard contentKinds.contains(resolvedKind) else {
            throw CausalontologyError("put() takes content objects; use putRecord()")
        }
        var obj = object
        if obj["type"] == nil {
            obj["type"] = .string(resolvedKind)
        }
        if obj["id"] == nil {
            obj["id"] = .string(try identify(obj, kind: resolvedKind))
        }
        guard let objectId = obj["id"]?.stringValue else {
            throw CausalontologyError("object id must be a string")
        }
        if objects[objectId] != nil {
            // Immutable: identical identity is a no-op.
            return objectId
        }
        let schemaResult = try validator.validate(obj, kind: resolvedKind)
        if !schemaResult.ok {
            throw RejectedWrite(schemaResult.reasons.joined(separator: "; "))
        }
        let semanticsResult = try validateSemantics(obj, kind: resolvedKind)
        if !semanticsResult.ok {
            throw RejectedWrite(semanticsResult.reasons.joined(separator: "; "))
        }
        objects[objectId] = obj
        objectOrder.append(objectId)
        return objectId
    }

    /// Write a signed provenance record; returns the identifier.
    @discardableResult
    public func putRecord(_ record: [String: JsonValue], kind: String? = nil) throws -> String {
        return try writeRecord(record, kind: kind, force: false)
    }

    /// Simulate a decentralized replica merge (no enforcement gate).
    @discardableResult
    public func forceMergeRecord(_ record: [String: JsonValue], kind: String? = nil) throws -> String {
        return try writeRecord(record, kind: kind, force: true)
    }

    private func writeRecord(
        _ record: [String: JsonValue],
        kind: String?,
        force: Bool
    ) throws -> String {
        let resolvedKind: String
        if let kind = kind {
            resolvedKind = kind
        } else {
            resolvedKind = try inferKind(record)
        }
        guard recordKinds.contains(resolvedKind) else {
            throw CausalontologyError("putRecord() takes provenance records")
        }
        var rec = record
        if rec["type"] == nil {
            rec["type"] = .string(resolvedKind)
        }
        let recordId: String
        if let existing = rec["id"]?.stringValue, !existing.isEmpty {
            recordId = existing
        } else {
            recordId = try identify(rec, kind: resolvedKind)
        }
        rec["id"] = .string(recordId)
        if records[recordId] != nil {
            // Add-only and idempotent.
            return recordId
        }
        if !verifyRecord(rec, kind: resolvedKind) {
            quarantine[recordId] = rec
            throw RejectedWrite("unsigned or unverifiable record: quarantined")
        }
        let semanticsResult = try validateSemantics(rec, kind: resolvedKind)
        if !semanticsResult.ok {
            throw RejectedWrite(semanticsResult.reasons.joined(separator: "; "))
        }
        if resolvedKind == "retraction" && !retractionSourceOk(rec) {
            throw RejectedWrite("a retraction is valid only from the retracted record's "
                                + "source or its succession lineage")
        }
        if resolvedKind == "enrichment" && enforcing && !force {
            let field = rec["field"]?.stringValue ?? ""
            if (field == "subsumes" || field == "part_of") && wouldCycle(rec) {
                throw RejectedWrite("would create a cycle in the materialized \(field) graph")
            }
        }
        records[recordId] = rec
        recordOrder.append(recordId)
        return recordId
    }

    // MARK: - record queries

    /// All stored records of one kind, in insertion order.
    public func recordsOf(_ kind: String) -> [[String: JsonValue]] {
        var out: [[String: JsonValue]] = []
        for recordId in recordOrder {
            if let rec = records[recordId], rec["type"]?.stringValue == kind {
                out.append(rec)
            }
        }
        return out
    }

    /// The ids named by every stored retraction.
    public func retractedIds() -> Set<String> {
        var out: Set<String> = []
        for rec in recordsOf("retraction") {
            if let target = rec["retracts"]?.stringValue {
                out.insert(target)
            }
        }
        return out
    }

    /// True when the retraction's source lies in the lineage of the
    /// retracted record's source; open world: the target may arrive later.
    private func retractionSourceOk(_ retraction: [String: JsonValue]) -> Bool {
        guard let targetId = retraction["retracts"]?.stringValue,
              let target = records[targetId] else {
            return true
        }
        guard let retractionSource = retraction["source"]?.stringValue,
              let targetSource = target["source"]?.stringValue else {
            return false
        }
        return lineage(targetSource).contains(retractionSource)
    }

    /// The succession chain closure containing key (includes key).
    public func lineage(_ key: String) -> Set<String> {
        var successorOf: [String: String] = [:]
        var predecessorOf: [String: String] = [:]
        for rec in recordsOf("succession") {
            if let predecessor = rec["predecessor"]?.stringValue,
               let successor = rec["successor"]?.stringValue {
                successorOf[predecessor] = successor
                predecessorOf[successor] = predecessor
            }
        }
        var chain: Set<String> = [key]
        var cursor = key
        while let previous = predecessorOf[cursor], !chain.contains(previous) {
            chain.insert(previous)
            cursor = previous
        }
        cursor = key
        while let next = successorOf[cursor], !chain.contains(next) {
            chain.insert(next)
            cursor = next
        }
        return chain
    }

    /// The assertions about an identifier; retracted ones are excluded by
    /// default, or included with a retracted flag under the history view.
    public func assertionsAbout(
        _ identifier: String,
        includeRetracted: Bool = false
    ) -> [[String: JsonValue]] {
        let retracted = retractedIds()
        var out: [[String: JsonValue]] = []
        for rec in recordsOf("assertion") {
            guard rec["about"]?.stringValue == identifier else { continue }
            guard let recordId = rec["id"]?.stringValue else { continue }
            if retracted.contains(recordId) {
                if includeRetracted {
                    var marked = rec
                    marked["retracted"] = .bool(true)
                    out.append(marked)
                }
                continue
            }
            out.append(rec)
        }
        return out
    }

    /// The enrichments about an identifier; retracted ones are excluded
    /// unless includeRetracted is set.
    public func enrichmentsAbout(
        _ identifier: String,
        includeRetracted: Bool = false
    ) -> [[String: JsonValue]] {
        let retracted = retractedIds()
        var out: [[String: JsonValue]] = []
        for rec in recordsOf("enrichment") {
            guard rec["about"]?.stringValue == identifier else { continue }
            if let recordId = rec["id"]?.stringValue,
               retracted.contains(recordId), !includeRetracted {
                continue
            }
            out.append(rec)
        }
        return out
    }

    // MARK: - materialized views

    /// (active, excluded) for subsumes/part_of after the rule 13
    /// deterministic cycle-breaking: while a cycle exists, exclude the
    /// record with the latest timestamp (ties by lexicographically greatest
    /// record identifier).
    public func activeTaxonomyEdges(
        _ field: String
    ) -> (active: [[String: JsonValue]], excluded: [[String: JsonValue]]) {
        let retracted = retractedIds()
        var active: [[String: JsonValue]] = []
        for rec in recordsOf("enrichment") {
            guard rec["field"]?.stringValue == field else { continue }
            if let recordId = rec["id"]?.stringValue, retracted.contains(recordId) {
                continue
            }
            active.append(rec)
        }
        var excluded: [[String: JsonValue]] = []
        while true {
            let cycle = InMemoryStore.findCycleRecords(active)
            if cycle.isEmpty {
                break
            }
            var loser = cycle[0]
            for candidate in cycle.dropFirst() {
                let candidateKey = (candidate["timestamp"]?.stringValue ?? "",
                                    candidate["id"]?.stringValue ?? "")
                let loserKey = (loser["timestamp"]?.stringValue ?? "",
                                loser["id"]?.stringValue ?? "")
                if candidateKey > loserKey {
                    loser = candidate
                }
            }
            guard let index = active.firstIndex(where: { $0["id"] == loser["id"] }) else {
                // Defensive: the loser always comes from the active list.
                break
            }
            active.remove(at: index)
            excluded.append(loser)
        }
        return (active, excluded)
    }

    /// The records forming a cycle in the about -> entry graph, or an empty
    /// array when the graph is acyclic. (As in the Python binding, the
    /// returned list is the DFS path up to and including the closing edge.)
    static func findCycleRecords(_ recs: [[String: JsonValue]]) -> [[String: JsonValue]] {
        var edges: [String: [(target: String, record: [String: JsonValue])]] = [:]
        var nodeOrder: [String] = []
        for rec in recs {
            guard let about = rec["about"]?.stringValue,
                  let entry = rec["entry"]?.stringValue else {
                continue
            }
            if edges[about] == nil {
                edges[about] = []
                nodeOrder.append(about)
            }
            edges[about]!.append((entry, rec))
        }

        // 0 (absent) = unvisited, 1 = on the current path, 2 = finished.
        var state: [String: Int] = [:]
        var cycle: [[String: JsonValue]] = []

        func dfs(_ node: String, _ pathRecords: [[String: JsonValue]]) -> Bool {
            state[node] = 1
            for (next, rec) in edges[node] ?? [] {
                if state[next] == 1 {
                    cycle = pathRecords + [rec]
                    return true
                }
                if (state[next] ?? 0) == 0 {
                    if dfs(next, pathRecords + [rec]) {
                        return true
                    }
                }
            }
            state[node] = 2
            return false
        }

        for start in nodeOrder {
            if (state[start] ?? 0) == 0 {
                if dfs(start, []) {
                    return cycle
                }
            }
        }
        return []
    }

    /// True when adding the record would close a cycle among the active
    /// (unretracted) records of the same field.
    private func wouldCycle(_ record: [String: JsonValue]) -> Bool {
        let retracted = retractedIds()
        var recs: [[String: JsonValue]] = []
        for rec in recordsOf("enrichment") {
            guard rec["field"] == record["field"] else { continue }
            if let recordId = rec["id"]?.stringValue, retracted.contains(recordId) {
                continue
            }
            recs.append(rec)
        }
        recs.append(record)
        return !InMemoryStore.findCycleRecords(recs).isEmpty
    }

    /// The object with its materialized enrichment sets and contributors.
    /// Views: "default" (retractions and cycle-broken edges excluded),
    /// "history" (everything included), "raw" (the bare object).
    public func get(_ identifier: String, view: String = "default") -> [String: JsonValue]? {
        guard let obj = objects[identifier] else {
            return nil
        }
        if view == "raw" {
            return ["object": .object(obj)]
        }
        let includeRetracted = (view == "history")
        var excludedIds: Set<String> = []
        for field in ["subsumes", "part_of"] {
            let result = activeTaxonomyEdges(field)
            for rec in result.excluded {
                if let recordId = rec["id"]?.stringValue {
                    excludedIds.insert(recordId)
                }
            }
        }

        struct Bucket {
            var entry: JsonValue
            var contributors: [JsonValue]
        }

        var fieldOrder: [String] = []
        var bucketOrder: [String: [String]] = [:]
        var buckets: [String: [String: Bucket]] = [:]

        for rec in enrichmentsAbout(identifier, includeRetracted: includeRetracted) {
            guard let recordId = rec["id"]?.stringValue else { continue }
            if excludedIds.contains(recordId) && view != "history" {
                continue
            }
            guard let field = rec["field"]?.stringValue, let entry = rec["entry"] else {
                continue
            }
            // The (field, entry) dedup key: the canonical bytes of the entry.
            let entryKey = (try? jcsString(entry)) ?? "<uncanonical>"
            if buckets[field] == nil {
                buckets[field] = [:]
                bucketOrder[field] = []
                fieldOrder.append(field)
            }
            if buckets[field]![entryKey] == nil {
                buckets[field]![entryKey] = Bucket(entry: entry, contributors: [])
                bucketOrder[field]!.append(entryKey)
            }
            let contributor: JsonValue = .object([
                "source": rec["source"] ?? .null,
                "timestamp": rec["timestamp"] ?? .null,
            ])
            buckets[field]![entryKey]!.contributors.append(contributor)
        }

        var enrichments: [String: JsonValue] = [:]
        for field in fieldOrder {
            var entries: [JsonValue] = []
            for entryKey in bucketOrder[field]! {
                let bucket = buckets[field]![entryKey]!
                entries.append(.object([
                    "entry": bucket.entry,
                    "contributors": .array(bucket.contributors),
                ]))
            }
            enrichments[field] = .array(entries)
        }
        return ["object": .object(obj), "enrichments": .object(enrichments)]
    }

    // MARK: - resolve

    /// The canonical-label form of free text: lowercase, whitespace runs
    /// collapsed to single underscores.
    public static func canonLabel(_ text: String) -> String {
        let pieces = text.lowercased().split(whereSeparator: { $0.isWhitespace })
        return pieces.joined(separator: "_")
    }

    /// The alias-normal form of free text: whitespace runs collapsed to
    /// single spaces, case-insensitive.
    public static func normAlias(_ text: String) -> String {
        let pieces = text.split(whereSeparator: { $0.isWhitespace })
        return pieces.joined(separator: " ").lowercased()
    }

    /// The conformance minimum: exact label, then alias, then nothing.
    public func resolve(_ text: String, lang: String? = nil) -> [String] {
        var labelHits: [String] = []
        var aliasHits: [String] = []
        let wantedLabel = InMemoryStore.canonLabel(text)
        let wantedAlias = InMemoryStore.normAlias(text)
        let retracted = retractedIds()
        for objectId in objectOrder {
            guard let obj = objects[objectId] else { continue }
            let typeName = obj["type"]?.stringValue ?? ""
            guard typeName == "occurrent" || typeName == "continuant" else { continue }
            if obj["label"]?.stringValue == wantedLabel {
                labelHits.append(objectId)
                continue
            }
            for rec in recordsOf("enrichment") {
                guard rec["about"]?.stringValue == objectId,
                      rec["field"]?.stringValue == "aliases" else {
                    continue
                }
                if let recordId = rec["id"]?.stringValue, retracted.contains(recordId) {
                    continue
                }
                guard let entry = rec["entry"]?.objectValue else { continue }
                if let lang = lang, entry["lang"]?.stringValue != lang {
                    continue
                }
                let aliasText = entry["text"]?.stringValue ?? ""
                if InMemoryStore.normAlias(aliasText) == wantedAlias {
                    aliasHits.append(objectId)
                    break
                }
            }
        }
        return labelHits + aliasHits
    }

    // MARK: - gaps

    /// The stigmergy read. Gap kinds per spec/store.md; pass a kind to
    /// filter the list.
    public func gaps(_ kind: String? = nil) -> [[String: JsonValue]] {
        var out: [[String: JsonValue]] = []

        // The parents closed by a valid refinement in the store.
        var refined: Set<String> = []
        for objectId in objectOrder {
            guard let obj = objects[objectId], obj["type"]?.stringValue == "cro" else { continue }
            guard let refines = obj["refines"]?.stringValue,
                  let parent = objects[refines] else {
                continue
            }
            let result = refinementValid(obj, parent)
            if result.ok, let parentId = parent["id"]?.stringValue {
                refined.insert(parentId)
            }
        }

        for objectId in objectOrder {
            guard let obj = objects[objectId], obj["type"]?.stringValue == "cro" else { continue }
            // missing_field: lacking the temporal window or the modality -
            // mechanism and context may legitimately stay unspecified forever
            // (empty_mechanism is its own kind; absent context = context-free).
            if (obj["temporal"] == nil || obj["modality"] == nil) && !refined.contains(objectId) {
                var missing: [JsonValue] = []
                for field in isPartial(obj).missing {
                    missing.append(.string(field))
                }
                out.append([
                    "id": .string(objectId),
                    "kind": .string("missing_field"),
                    "missing": .array(missing),
                ])
            }
            let mechanismEmpty = (obj["mechanism"] == nil)
                || (obj["mechanism"]?.arrayValue?.isEmpty == true)
            if mechanismEmpty && !refined.contains(objectId) {
                out.append([
                    "id": .string(objectId),
                    "kind": .string("empty_mechanism"),
                ])
            }
        }

        for field in ["subsumes", "part_of"] {
            let result = activeTaxonomyEdges(field)
            for rec in result.excluded {
                out.append([
                    "id": rec["id"] ?? .null,
                    "kind": .string("inconsistent_hierarchy"),
                    "note": .string("excluded by the deterministic cycle-breaking view rule"),
                ])
            }
        }

        // dangling_reference: a reference to an object absent from the
        // store - the red link that says "this page is wanted".
        for objectId in objectOrder {
            guard let obj = objects[objectId] else { continue }
            var refs: [String] = []
            let typeName = obj["type"]?.stringValue ?? ""
            if typeName == "cro" {
                for fieldName in ["causes", "effects", "context", "mechanism"] {
                    for item in obj[fieldName]?.arrayValue ?? [] {
                        if let text = item.stringValue {
                            refs.append(text)
                        }
                    }
                }
                if let refines = obj["refines"]?.stringValue {
                    refs.append(refines)
                }
            } else if typeName == "realizable" {
                if let bearer = obj["bearer"]?.stringValue {
                    refs.append(bearer)
                }
            }
            for ref in refs where !ref.isEmpty && objects[ref] == nil {
                out.append([
                    "id": .string(objectId),
                    "kind": .string("dangling_reference"),
                    "ref": .string(ref),
                ])
            }
        }

        // conflict: pairs of claims satisfying the formal test (rule 6).
        var cros: [[String: JsonValue]] = []
        for objectId in objectOrder {
            if let obj = objects[objectId], obj["type"]?.stringValue == "cro" {
                cros.append(obj)
            }
        }
        if cros.count >= 2 {
            for i in 0..<(cros.count - 1) {
                for j in (i + 1)..<cros.count {
                    if conflicts(cros[i], cros[j]) {
                        out.append([
                            "kind": .string("conflict"),
                            "a": cros[i]["id"] ?? .null,
                            "b": cros[j]["id"] ?? .null,
                        ])
                    }
                }
            }
        }

        if let kind = kind {
            var filtered: [[String: JsonValue]] = []
            for gap in out where gap["kind"]?.stringValue == kind {
                filtered.append(gap)
            }
            out = filtered
        }
        return out
    }
}

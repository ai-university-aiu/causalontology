// main.swift
//
// The Causalontology conformance runner for causalontology-swift.
//
// Runs every vector in conformance/vectors/ against the Swift binding. An
// implementation is conformant if and only if it passes every vector; this
// runner exits nonzero on any failure.
//
// Pre-freeze note (see conformance/README.md): the vectors carry symbolic
// identifiers ("occurrent:press_button", "ed25519:alice"). This harness normalizes
// them deterministically - symbolic object ids become scheme:sha256(name),
// and symbolic key names become real Ed25519 keypairs seeded from
// sha256("key:" + name) - so the normative behaviors are tested with
// well-formed data. The 1.0.0 freeze pins concrete bytes into the vectors.

import Foundation
import Crypto
import Causalontology

// MARK: - failure type and assertion helper

struct ConformanceFailure: Error, CustomStringConvertible {
    let message: String

    init(_ message: String) {
        self.message = message
    }

    var description: String {
        return message
    }
}

func check(_ condition: Bool, _ message: @autoclosure () -> String) throws {
    if !condition {
        throw ConformanceFailure(message())
    }
}

// MARK: - repository layout

/// Find the repository root: CAUSALONTOLOGY_ROOT if set; else derived from
/// this source file's compile-time path (bindings/swift/Sources/conformance/
/// main.swift -> five parents up); else walk up from the working directory.
func findRepositoryRoot() -> URL {
    let fileManager = FileManager.default
    func hasVectors(_ url: URL) -> Bool {
        let vectors = url.appendingPathComponent("conformance").appendingPathComponent("vectors")
        return fileManager.fileExists(atPath: vectors.path)
    }
    if let env = ProcessInfo.processInfo.environment["CAUSALONTOLOGY_ROOT"] {
        return URL(fileURLWithPath: env)
    }
    var candidate = URL(fileURLWithPath: #filePath)
    for _ in 0..<5 {
        candidate.deleteLastPathComponent()
    }
    if hasVectors(candidate) {
        return candidate
    }
    var cwd = URL(fileURLWithPath: fileManager.currentDirectoryPath)
    for _ in 0..<8 {
        if hasVectors(cwd) {
            return cwd
        }
        cwd.deleteLastPathComponent()
    }
    return candidate
}

let repoRoot = findRepositoryRoot()
let vectorsDir = repoRoot.appendingPathComponent("conformance").appendingPathComponent("vectors")
let schemaDir = repoRoot.appendingPathComponent("spec").appendingPathComponent("schema")
let validator = SchemaValidator(schemaDirectory: schemaDir)

// MARK: - symbolic-identifier normalization

let symbolicSchemes = ["occurrent", "causal_relation_object", "continuant", "realizable",
                       "assertion", "enrichment", "retraction", "succession",
                       "stratum", "bridge", "cross_stratal_seam", "port", "conduit", "quality",
                       "token_individual", "token_occurrence", "state_assertion",
                       "token_causal_claim",
                       "attitude", "predicted_occurrence", "prediction_error", "ed25519"]

/// The whole-word schemes (Principle P7) plus the external ed25519 scheme.
let wholeWordSchemes: Set<String> = Set([
    "occurrent", "causal_relation_object", "continuant", "realizable",
    "assertion", "enrichment", "retraction", "succession",
    "stratum", "bridge", "cross_stratal_seam", "port", "conduit", "quality",
    "token_individual", "token_occurrence", "state_assertion",
    "token_causal_claim",
    "attitude", "predicted_occurrence", "prediction_error", "ed25519",
])

var keyCache: [String: (secret: Curve25519.Signing.PrivateKey, publicId: String)] = [:]

/// A real, deterministic Ed25519 keypair for a symbolic key name.
func key(_ name: String) throws -> (secret: Curve25519.Signing.PrivateKey, publicId: String) {
    if let cached = keyCache[name] {
        return cached
    }
    let seed = Data(SHA256.hash(data: Data(("key:" + name).utf8)))
    let pair = try keypairFromSeed(seed)
    keyCache[name] = pair
    return pair
}

/// True for a 64-character lowercase hex string.
func isHex64(_ text: String) -> Bool {
    guard text.count == 64 else { return false }
    for c in text {
        let isDigit = (c >= "0" && c <= "9")
        let isLowerHex = (c >= "a" && c <= "f")
        if !isDigit && !isLowerHex {
            return false
        }
    }
    return true
}

/// Normalize one symbolic identifier to a well-formed one.
func sym(_ text: String) throws -> String {
    guard let colon = text.firstIndex(of: ":") else {
        return text
    }
    let scheme = String(text[text.startIndex..<colon])
    let name = String(text[text.index(after: colon)...])
    if scheme == "ed25519" {
        if isHex64(name) {
            return text
        }
        return try key(name).publicId
    }
    if isHex64(name) {
        return text
    }
    return scheme + ":" + sha256Hex(Data(name.utf8))
}

/// Recursively normalize symbolic identifiers and placeholders.
func normalize(_ value: JsonValue) throws -> JsonValue {
    switch value {
    case let .string(text):
        if text == "<128 hex>" {
            return .string(String(repeating: "ab", count: 64))
        }
        for scheme in symbolicSchemes where text.hasPrefix(scheme + ":") {
            return .string(try sym(text))
        }
        return value
    case let .array(items):
        var out: [JsonValue] = []
        for item in items {
            out.append(try normalize(item))
        }
        return .array(out)
    case let .object(members):
        var out: [String: JsonValue] = [:]
        for (memberKey, memberValue) in members {
            out[memberKey] = try normalize(memberValue)
        }
        return .object(out)
    default:
        return value
    }
}

// MARK: - vector loading

func vectorFileName(_ n: Int) throws -> String {
    let prefix = String(format: "v%02d_", n)
    let names = try FileManager.default.contentsOfDirectory(atPath: vectorsDir.path)
        .filter { $0.hasPrefix(prefix) && $0.hasSuffix(".json") }
    try check(names.count == 1, "vector \(n) not found in \(vectorsDir.path)")
    return names[0]
}

/// Load vector n's JSON file (for its structured inputs).
func vec(_ n: Int) throws -> [String: JsonValue] {
    let name = try vectorFileName(n)
    let data = try Data(contentsOf: vectorsDir.appendingPathComponent(name))
    guard let obj = try JsonValue.parse(data).objectValue else {
        throw ConformanceFailure("vector \(n) is not a JSON object")
    }
    return obj
}

/// Unwrap an optional JsonValue as a JSON object or fail loudly.
func asObject(_ value: JsonValue?, _ what: String) throws -> [String: JsonValue] {
    guard let obj = value?.objectValue else {
        throw ConformanceFailure("\(what) is not a JSON object")
    }
    return obj
}

/// The normalized "input" object of vector n.
func normalizedInput(_ n: Int) throws -> [String: JsonValue] {
    let v = try vec(n)
    return try asObject(try normalize(v["input"] ?? .null), "vector \(n) input")
}

// MARK: - record building

/// Build, timestamp, and sign a provenance record.
func signed(
    _ kind: String,
    _ body: [String: JsonValue],
    _ who: String,
    _ tsIndex: Int = 0
) throws -> [String: JsonValue] {
    let pair = try key(who)
    var rec = body
    rec["type"] = .string(kind)
    if rec["timestamp"] == nil {
        rec["timestamp"] = .string("2026-07-13T0\(tsIndex):00:00Z")
    }
    if kind == "succession" {
        if rec["predecessor"] == nil {
            rec["predecessor"] = .string(pair.publicId)
        }
    } else {
        rec["source"] = .string(pair.publicId)
    }
    return try signRecord(rec, secret: pair.secret, kind: kind)
}

// MARK: - content-object builders (mirror the Python harness)

/// A content object completed with its real content-addressed id.
func mk(_ obj: [String: JsonValue]) throws -> [String: JsonValue] {
    var out = obj
    out["id"] = .string(try identify(out))
    return out
}

/// The id of a built object.
func oid(_ obj: [String: JsonValue]) -> String {
    return obj["id"]?.stringValue ?? ""
}

/// Convenience: a JSON array of string values.
func strings(_ values: [String]) -> JsonValue {
    return .array(values.map { .string($0) })
}

func stratumObj(_ label: String, _ scheme: String, _ ordinal: Int,
                unit: String? = nil, governs: [String]? = nil) throws -> [String: JsonValue] {
    var o: [String: JsonValue] = [
        "type": .string("stratum"), "label": .string(label),
        "scheme": .string(scheme), "ordinal": .int(Int64(ordinal)),
    ]
    if let unit = unit { o["unit"] = .string(unit) }
    if let governs = governs { o["governs"] = strings(governs) }
    return try mk(o)
}

func occObj(_ label: String, _ stratumId: String? = nil,
            category: String = "event") throws -> [String: JsonValue] {
    var o: [String: JsonValue] = [
        "type": .string("occurrent"), "label": .string(label),
        "category": .string(category),
    ]
    if let stratumId = stratumId { o["stratum"] = .string(stratumId) }
    return try mk(o)
}

func cntObj(_ label: String, category: String = "object") throws -> [String: JsonValue] {
    return try mk([
        "type": .string("continuant"), "label": .string(label),
        "category": .string(category),
    ])
}

func croObj(_ causes: [String], _ effects: [String],
            _ extra: [String: JsonValue] = [:]) throws -> [String: JsonValue] {
    var o: [String: JsonValue] = [
        "type": .string("causal_relation_object"),
        "causes": strings(causes), "effects": strings(effects),
    ]
    for (k, v) in extra { o[k] = v }
    return try mk(o)
}

func bridgeObj(_ coarse: String, _ fine: [String], _ relation: String) throws -> [String: JsonValue] {
    return try mk([
        "type": .string("bridge"), "coarse": .string(coarse),
        "fine": strings(fine), "relation": .string(relation),
    ])
}

func portObj(_ bearer: String, _ label: String, _ direction: String,
             _ accepts: [String], realizable: String? = nil) throws -> [String: JsonValue] {
    var o: [String: JsonValue] = [
        "type": .string("port"), "bearer": .string(bearer),
        "label": .string(label), "direction": .string(direction),
        "accepts": strings(accepts),
    ]
    if let realizable = realizable { o["realizable"] = .string(realizable) }
    return try mk(o)
}

func conduitObj(_ frm: String, _ to: String, _ carries: [String],
                label: String = "conn", transform: String? = nil) throws -> [String: JsonValue] {
    var o: [String: JsonValue] = [
        "type": .string("conduit"), "label": .string(label),
        "from": .string(frm), "to": .string(to), "carries": strings(carries),
    ]
    if let transform = transform { o["transform"] = .string(transform) }
    return try mk(o)
}

func qualityObj(_ label: String, _ datatype: String,
                unit: String? = nil, stratumId: String? = nil) throws -> [String: JsonValue] {
    var o: [String: JsonValue] = [
        "type": .string("quality"), "label": .string(label),
        "datatype": .string(datatype),
    ]
    if let unit = unit { o["unit"] = .string(unit) }
    if let stratumId = stratumId { o["stratum"] = .string(stratumId) }
    return try mk(o)
}

func individualObj(_ instantiates: String, designator: String? = nil,
                   partOf: String? = nil) throws -> [String: JsonValue] {
    var o: [String: JsonValue] = [
        "type": .string("token_individual"), "instantiates": .string(instantiates),
    ]
    if let designator = designator { o["designator"] = .string(designator) }
    if let partOf = partOf { o["part_of"] = .string(partOf) }
    return try mk(o)
}

func tokenObj(_ instantiates: String, _ interval: JsonValue,
              participants: JsonValue? = nil, locus: String? = nil) throws -> [String: JsonValue] {
    var o: [String: JsonValue] = [
        "type": .string("token_occurrence"), "instantiates": .string(instantiates),
        "interval": interval,
    ]
    if let participants = participants { o["participants"] = participants }
    if let locus = locus { o["locus"] = .string(locus) }
    return try mk(o)
}

func stateObj(_ subject: String, _ qual: String,
              _ value: JsonValue, _ interval: JsonValue) throws -> [String: JsonValue] {
    return try mk([
        "type": .string("state_assertion"), "subject": .string(subject),
        "quality": .string(qual), "value": value, "interval": interval,
    ])
}

func tccObj(_ causes: [String], _ effects: [String], coveringLaw: String? = nil,
            actualDelay: JsonValue? = nil, counterfactual: Bool? = nil) throws -> [String: JsonValue] {
    var o: [String: JsonValue] = [
        "type": .string("token_causal_claim"),
        "causes": strings(causes), "effects": strings(effects),
    ]
    if let coveringLaw = coveringLaw { o["covering_law"] = .string(coveringLaw) }
    if let actualDelay = actualDelay { o["actual_delay"] = actualDelay }
    if let counterfactual = counterfactual { o["counterfactual"] = .bool(counterfactual) }
    return try mk(o)
}

func rlzObj(_ bearer: String, _ kind: String, _ label: String? = nil) throws -> [String: JsonValue] {
    var o: [String: JsonValue] = [
        "type": .string("realizable"), "kind": .string(kind), "bearer": .string(bearer),
    ]
    if let label = label { o["label"] = .string(label) }
    return try mk(o)
}

/// The neuroendocrine stratum fixture keyed by ordinal.
func neuro() throws -> [Int: [String: JsonValue]] {
    let labels: [Int: String] = [
        4: "macromolecular", 5: "subcellular", 6: "cellular",
        7: "synaptic", 9: "region", 14: "community_and_society",
    ]
    var out: [Int: [String: JsonValue]] = [:]
    for (ordinal, label) in labels {
        out[ordinal] = try stratumObj(label, "neuroendocrine", ordinal)
    }
    return out
}

/// The ordered string members of a JSON array field (local mirror).
func stringList(_ value: JsonValue?) -> [String] {
    var out: [String] = []
    for item in value?.arrayValue ?? [] {
        if let text = item.stringValue { out.append(text) }
    }
    return out
}

// MARK: - internal sanity checks (not conformance vectors)

func internalChecks() throws {
    // RFC 8032, TEST 1 known-answer: the public key for the test seed.
    guard let seed = hexDecode(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60") else {
        throw ConformanceFailure("internal: bad seed hex")
    }
    let pair = try keypairFromSeed(seed)
    let expectedPublic = "ed25519:"
        + "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    try check(pair.publicId == expectedPublic,
              "RFC 8032 TEST 1 public key mismatch: \(pair.publicId)")
    // Signature round-trip on the empty message; wrong message must fail.
    let signature = try pair.secret.signature(for: Data())
    let publicKey = pair.secret.publicKey
    try check(publicKey.isValidSignature(signature, for: Data()),
              "internal: signature round-trip failed")
    try check(!publicKey.isValidSignature(signature, for: Data("x".utf8)),
              "internal: signature verified a different message")
    // JCS basics.
    try check(try jcsString(.object(["b": .int(2), "a": .int(1)])) == "{\"a\":1,\"b\":2}",
              "internal: JCS key order")
    try check(try jcsString(.double(1.0)) == "1", "internal: JCS 1.0")
    try check(try jcsString(.double(6.0)) == "6", "internal: JCS 6.0")
    try check(try jcsString(.double(0.7)) == "0.7", "internal: JCS 0.7")
    // Algorithm E fixed constants.
    try check(try toSeconds(1, "months") == 2629746, "internal: months constant")
    try check(try toSeconds(1, "years") == 31556952, "internal: years constant")
    // Ground-truth content-addressed ids (spec 2.0.0 freeze).
    let zeros = String(repeating: "0", count: 64)
    let gtStratum = try identify([
        "type": .string("stratum"), "label": .string("cellular"),
        "scheme": .string("neuroendocrine"), "ordinal": .int(6),
    ])
    try check(gtStratum == "stratum:99162f6202087b209696f9a2a21fe57ada3a349840ce5f8af25e034c8bde5b81",
              "internal: stratum ground-truth id mismatch: \(gtStratum)")
    let gtRealizable = try identify([
        "type": .string("realizable"), "kind": .string("disposition"),
        "bearer": .string("continuant:" + zeros), "label": .string("ltp"),
    ])
    try check(gtRealizable == "realizable:486be612e50996f60632764a36d009e151a3967d4bedac3f61c88844577243c1",
              "internal: realizable ground-truth id mismatch: \(gtRealizable)")
    let gtToken = try identify([
        "type": .string("token_occurrence"), "instantiates": .string("occurrent:" + zeros),
        "interval": .object(["start": .string("1953-08-25T00:00:00Z"), "open": .bool(true)]),
    ])
    try check(gtToken == "token_occurrence:85987b294d9902330b25a9d692cdce27bce090bca30e7c09e8b943059e23351d",
              "internal: token_occurrence ground-truth id mismatch: \(gtToken)")
}

// MARK: - shared vector helpers

func schemaFails(_ n: Int, mustMention: String) throws {
    let input = try normalizedInput(n)
    let result = try validator.validate(input)
    try check(!result.ok, "vector \(n): expected schema-invalid")
    try check(result.reasons.contains { $0.contains(mustMention) },
              "vector \(n): reasons \(result.reasons) do not mention '\(mustMention)'")
}

func semanticsFails(_ n: Int, mustMention: String) throws {
    let input = try normalizedInput(n)
    let result = try validateSemantics(input)
    try check(!result.ok, "vector \(n): expected semantically-invalid")
    try check(result.reasons.contains { $0.contains(mustMention) },
              "vector \(n): reasons \(result.reasons) do not mention '\(mustMention)'")
}

// MARK: - the 38 vectors

func v01() throws {
    let input = try normalizedInput(1)
    let schemaResult = try validator.validate(input)
    try check(schemaResult.ok, "schema: \(schemaResult.reasons)")
    let semanticsResult = try validateSemantics(input)
    try check(semanticsResult.ok, "semantics: \(semanticsResult.reasons)")
}

func v02() throws {
    let v = try vec(2)
    let input = try asObject(try normalize(v["input"] ?? .null), "input")
    let schemaResult = try validator.validate(input)
    try check(schemaResult.ok, "schema: \(schemaResult.reasons)")
    let semanticsResult = try validateSemantics(input)
    try check(semanticsResult.ok, "semantics: \(semanticsResult.reasons)")
    let partialResult = isPartial(input)
    try check(partialResult.partial, "expected a partial object")
    var expectedMissing: [String] = []
    for item in v["expect"]?["missing"]?.arrayValue ?? [] {
        if let text = item.stringValue {
            expectedMissing.append(text)
        }
    }
    try check(partialResult.missing == expectedMissing,
              "missing fields \(partialResult.missing) != \(expectedMissing)")
}

func v03() throws { try schemaFails(3, mustMention: "effects") }
func v04() throws { try schemaFails(4, mustMention: "causes") }
func v05() throws { try schemaFails(5, mustMention: "modality") }
func v06() throws { try schemaFails(6, mustMention: "colour") }
func v07() throws { try schemaFails(7, mustMention: "causes") }

func v08() throws {
    let result = try validator.validate(try normalizedInput(8))
    try check(result.ok, "schema: \(result.reasons)")
}

func v09() throws { try schemaFails(9, mustMention: "label") }
func v10() throws { try schemaFails(10, mustMention: "category") }

func v11() throws {
    let result = try validator.validate(try normalizedInput(11))
    try check(result.ok, "schema: \(result.reasons)")
}

func v12() throws { try schemaFails(12, mustMention: "confidence") }

func v13() throws {
    let input = try normalizedInput(13)
    let schemaResult = try validator.validate(input)
    try check(schemaResult.ok, "schema: \(schemaResult.reasons)")
    let semanticsResult = try validateSemantics(input)
    try check(semanticsResult.ok, "semantics: \(semanticsResult.reasons)")
}

func v14() throws {
    let input = try normalizedInput(14)
    let schemaResult = try validator.validate(input)
    try check(schemaResult.ok, "schema: \(schemaResult.reasons)")
    try semanticsFails(14, mustMention: "minimum_delay")
}

func v15() throws { try semanticsFails(15, mustMention: "acyclic") }
func v16() throws { try semanticsFails(16, mustMention: "acyclic") }

func v17() throws {
    let v = try vec(17)
    let given = try asObject(v["given"], "given")
    let parent = try asObject(try normalize(given["parent"] ?? .null), "parent")
    let child = try asObject(try normalize(v["input"] ?? .null), "input")
    let result = refinementValid(child, parent)
    try check(!result.ok, "expected an invalid refinement")
    try check(result.reason.contains("rival"), "reason: \(result.reason)")
}

func v18() throws { try semanticsFails(18, mustMention: "not a legal field") }
func v19() throws { try semanticsFails(19, mustMention: "language-tagged") }

func v20() throws {
    let dog = try sym("continuant:dog")
    let mammal = try sym("continuant:mammal")
    let animal = try sym("continuant:animal")
    func enrich(_ about: String, _ entry: String, _ i: Int) throws -> [String: JsonValue] {
        return try signed("enrichment", [
            "about": .string(about),
            "field": .string("subsumes"),
            "entry": .string(entry),
        ], "taxo", i)
    }
    // Enforcing tier rejects the cycle-completing write.
    let s = InMemoryStore(enforcing: true, validator: validator)
    try s.putRecord(try enrich(dog, mammal, 1))
    try s.putRecord(try enrich(mammal, animal, 2))
    var rejected = false
    do {
        try s.putRecord(try enrich(animal, dog, 3))
    } catch let e as RejectedWrite {
        rejected = true
        try check(e.message.contains("cycle"), "wrong rejection reason: \(e.message)")
    }
    try check(rejected, "enforcing store accepted a cycle")
    // Decentralized merge: the view breaks the cycle deterministically.
    let s2 = InMemoryStore(enforcing: true, validator: validator)
    try s2.putRecord(try enrich(dog, mammal, 1))
    try s2.putRecord(try enrich(mammal, animal, 2))
    let bad = try enrich(animal, dog, 3)
    try s2.forceMergeRecord(bad)
    let result = s2.activeTaxonomyEdges("subsumes")
    try check(result.excluded.count == 1, "excluded \(result.excluded.count) records")
    try check(result.excluded[0]["id"] == bad["id"], "excluded the wrong record")
    let repair = s2.gaps("inconsistent_hierarchy")
    try check(repair.contains { $0["id"] == bad["id"] }, "no repair gap surfaced")
}

func admissibleForVector(_ n: Int) throws -> Bool {
    let v = try vec(n)
    let given = try asObject(v["given"], "given")
    let cro: [String: JsonValue] = [
        "causes": .array([.string(try sym("occurrent:c"))]),
        "effects": .array([.string(try sym("occurrent:e"))]),
        "temporal": given["temporal"] ?? .null,
    ]
    guard let elapsed = given["elapsed_seconds"]?.numberValue else {
        throw ConformanceFailure("vector \(n): elapsed_seconds missing")
    }
    return admissible(cro, elapsedSeconds: elapsed)
}

func v21() throws { try check(try admissibleForVector(21) == true, "expected admissible") }
func v22() throws { try check(try admissibleForVector(22) == false, "expected not admissible") }
func v23() throws { try check(try admissibleForVector(23) == true, "expected admissible") }

func v24() throws {
    let v = try vec(24)
    let a = try asObject(try normalize(v["inputA"] ?? .null), "inputA")
    let b = try asObject(try normalize(v["inputB"] ?? .null), "inputB")
    try check(try identify(a) == (try identify(b)), "identifiers differ across key order")
}

func v25() throws {
    let v = try vec(25)
    let a = try asObject(try normalize(v["inputA"] ?? .null), "inputA")
    let b = try asObject(try normalize(v["inputB"] ?? .null), "inputB")
    try check(try identify(a) == (try identify(b)), "identifiers differ across number form")
}

func v26() throws {
    let s = InMemoryStore(validator: validator)
    let obj: [String: JsonValue] = [
        "type": .string("occurrent"),
        "label": .string("press_button"),
        "category": .string("action"),
    ]
    let first = try s.put(obj)
    let second = try s.put(obj)
    try check(first == second, "second put returned a different identifier")
    try check(s.objects.count == 1, "store holds \(s.objects.count) objects")
}

func v27() throws {
    let s = InMemoryStore(validator: validator)
    let occ = try s.put([
        "type": .string("occurrent"),
        "label": .string("press_button"),
        "category": .string("action"),
    ])
    let entry: JsonValue = .object(["lang": .string("en"), "text": .string("press the button")])
    let r1 = try signed("enrichment", [
        "about": .string(occ), "field": .string("aliases"), "entry": entry,
    ], "alice", 1)
    let r2 = try signed("enrichment", [
        "about": .string(occ), "field": .string("aliases"), "entry": entry,
    ], "bob", 2)
    let id1 = try s.putRecord(r1)
    let id2 = try s.putRecord(r2)
    try check(id1 != id2, "expected two distinct records")
    let aliases = s.get(occ)?["enrichments"]?["aliases"]?.arrayValue ?? []
    try check(aliases.count == 1, "materialized \(aliases.count) alias entries")
    let contributors = aliases[0]["contributors"]?.arrayValue ?? []
    try check(contributors.count == 2, "entry has \(contributors.count) contributors")
}

func v28() throws {
    let s = InMemoryStore(validator: validator)
    let claim: [String: JsonValue] = [
        "type": .string("causal_relation_object"),
        "causes": .array([.string(try sym("occurrent:A"))]),
        "effects": .array([.string(try sym("occurrent:B"))]),
        "modality": .string("sufficient"),
    ]
    let i1 = try s.put(claim)
    let i2 = try s.put(claim)
    try check(i1 == i2, "the same claim produced two identifiers")
    try check(s.objects.count == 1, "store holds \(s.objects.count) objects")
    for (who, ts) in [("lab1", 1), ("lab2", 2)] {
        try s.putRecord(try signed("assertion", [
            "about": .string(i1),
            "evidence_type": .string("observation"),
            "strength": .double(0.8),
            "confidence": .double(0.8),
        ], who, ts))
    }
    try check(s.assertionsAbout(i1).count == 2, "expected two assertions")
}

func demoAssertion() throws -> [String: JsonValue] {
    return try signed("assertion", [
        "about": .string(try sym("causal_relation_object:demo")),
        "evidence_type": .string("intervention"),
        "strength": .double(0.7),
        "confidence": .double(0.9),
    ], "signer")
}

func v29() throws {
    try check(verifyRecord(try demoAssertion()) == true, "valid signature did not verify")
}

func v30() throws {
    var tampered = try demoAssertion()
    tampered["confidence"] = .double(0.1)
    try check(verifyRecord(tampered) == false, "tampered record verified")
}

func v31() throws {
    let s = InMemoryStore(validator: validator)
    let x = try s.put([
        "type": .string("causal_relation_object"),
        "causes": .array([.string(try sym("occurrent:A"))]),
        "effects": .array([.string(try sym("occurrent:B"))]),
    ])
    let a = try signed("assertion", [
        "about": .string(x),
        "evidence_type": .string("observation"),
        "confidence": .double(0.8),
    ], "lab1", 1)
    try s.putRecord(a)
    try s.putRecord(try signed("retraction", ["retracts": a["id"] ?? .null], "lab1", 2))
    try check(s.assertionsAbout(x).isEmpty, "default view still shows the assertion")
    let history = s.assertionsAbout(x, includeRetracted: true)
    try check(history.count == 1, "history view has \(history.count) assertions")
    try check(history[0]["retracted"] == JsonValue.bool(true), "history entry lacks the retracted mark")
    let foreign = try signed("retraction", ["retracts": a["id"] ?? .null], "mallory", 3)
    var rejected = false
    do {
        try s.putRecord(foreign)
    } catch is RejectedWrite {
        rejected = true
    }
    try check(rejected, "foreign retraction accepted")
    try check(s.assertionsAbout(x).isEmpty, "still excluded by lab1's own retraction")
    try check(s.assertionsAbout(x, includeRetracted: true).count == 1, "history count changed")
}

func v32() throws {
    let s = InMemoryStore(validator: validator)
    let occ = try s.put([
        "type": .string("occurrent"),
        "label": .string("press_button"),
        "category": .string("action"),
    ])
    let e = try signed("enrichment", [
        "about": .string(occ),
        "field": .string("aliases"),
        "entry": .object(["lang": .string("ja"), "text": .string("botan")]),
    ], "bob", 1)
    try s.putRecord(e)
    let before = s.get(occ)?["enrichments"]?["aliases"]?.arrayValue ?? []
    try check(before.count == 1, "before retraction: \(before.count) entries")
    try s.putRecord(try signed("retraction", ["retracts": e["id"] ?? .null], "bob", 2))
    let after = s.get(occ)?["enrichments"]?["aliases"]?.arrayValue ?? []
    try check(after.isEmpty, "after retraction: \(after.count) entries")
    let history = s.get(occ, view: "history")?["enrichments"]?["aliases"]?.arrayValue ?? []
    try check(history.count == 1, "history view has \(history.count) entries")
}

func v33() throws {
    let s = InMemoryStore(validator: validator)
    let k1 = try key("K1").publicId
    let k2 = try key("K2").publicId
    let claim = try sym("causal_relation_object:claim")
    let a = try signed("assertion", [
        "about": .string(claim),
        "evidence_type": .string("observation"),
        "confidence": .double(0.9),
    ], "K1", 1)
    try s.putRecord(a)
    let succession = try signed("succession", ["successor": .string(k2)], "K1", 2)
    try s.putRecord(succession)
    try check(s.lineage(k2).contains(k1), "K1 not in lineage of K2")
    try check(s.lineage(k1).contains(k2), "K2 not in lineage of K1")
    // The successor may retract the predecessor's record.
    let r = try signed("retraction", ["retracts": a["id"] ?? .null], "K2", 3)
    try s.putRecord(r)
    try check(s.assertionsAbout(claim).isEmpty, "successor retraction did not apply")
}

func v34() throws {
    let v = try vec(34)
    let given = try asObject(try normalize(v["given"] ?? .null), "given")
    let a = try asObject(given["A"], "A")
    let b = try asObject(given["B"], "B")
    try check(conflicts(a, b) == true, "expected a conflict")
}

func v35() throws {
    let v = try vec(35)
    let given = try asObject(try normalize(v["given"] ?? .null), "given")
    let a = try asObject(given["A"], "A")
    let b = try asObject(given["B"], "B")
    try check(conflicts(a, b) == false, "expected no conflict")
}

func v36() throws {
    let occA = try sym("occurrent:A")
    let occB = try sym("occurrent:B")
    let occC = try sym("occurrent:C")
    let occD = try sym("occurrent:D")
    let m1Id = try sym("causal_relation_object:m1")
    let m2Id = try sym("causal_relation_object:m2")
    let m3Id = try sym("causal_relation_object:m3")
    let m1: [String: JsonValue] = [
        "id": .string(m1Id),
        "causes": .array([.string(occA)]),
        "effects": .array([.string(occB)]),
    ]
    let m2: [String: JsonValue] = [
        "id": .string(m2Id),
        "causes": .array([.string(occB)]),
        "effects": .array([.string(occC)]),
    ]
    let m3: [String: JsonValue] = [
        "id": .string(m3Id),
        "causes": .array([.string(occD)]),
        "effects": .array([.string(occC)]),
    ]
    let parent: [String: JsonValue] = [
        "causes": .array([.string(occA)]),
        "effects": .array([.string(occC)]),
        "mechanism": .array([.string(m1Id), .string(m2Id)]),
    ]
    try check(hierarchyConsistent(parent, [m1Id: m1, m2Id: m2]) == "consistent",
              "path A -> B -> C should be consistent")
    var parent2 = parent
    parent2["mechanism"] = .array([.string(m1Id), .string(m3Id)])
    try check(hierarchyConsistent(parent2, [m1Id: m1, m3Id: m3]) == "inconsistent",
              "D -> C replacement should be inconsistent")
    try check(hierarchyConsistent(parent, [m1Id: m1]) == "indeterminate",
              "absent member should be indeterminate")
}

func v37() throws {
    let s = InMemoryStore(validator: validator)
    let occ = try s.put([
        "type": .string("occurrent"),
        "label": .string("press_button"),
        "category": .string("action"),
    ])
    try s.putRecord(try signed("enrichment", [
        "about": .string(occ),
        "field": .string("aliases"),
        "entry": .object(["lang": .string("en"), "text": .string("Press the Button")]),
    ], "alice", 1))
    try check(s.resolve("Press  The   Button", lang: "en") == [occ], "alias match failed")
    let byLabel = s.resolve("press_button", lang: "en")
    try check(byLabel.first == occ, "canonical-label match not ranked first")
}

func v38() throws {
    let s = InMemoryStore(validator: validator)
    let occA = try sym("occurrent:A")
    let occB = try sym("occurrent:B")
    let parent = try s.put([
        "type": .string("causal_relation_object"),
        "causes": .array([.string(occA)]),
        "effects": .array([.string(occB)]),
    ])
    var gapIds: [String] = []
    for gap in s.gaps("missing_field") {
        if let gapId = gap["id"]?.stringValue {
            gapIds.append(gapId)
        }
    }
    try check(gapIds.contains(parent), "P is not in the missing_field gaps")
    let refinement = try s.put([
        "type": .string("causal_relation_object"),
        "causes": .array([.string(occA)]),
        "effects": .array([.string(occB)]),
        "temporal": .object([
            "minimum_delay": .int(0), "maximum_delay": .int(1), "unit": .string("seconds"),
        ]),
        "modality": .string("sufficient"),
        "refines": .string(parent),
    ])
    gapIds = []
    for gap in s.gaps("missing_field") {
        if let gapId = gap["id"]?.stringValue {
            gapIds.append(gapId)
        }
    }
    try check(!gapIds.contains(parent), "the gap did not close")
    try check(!gapIds.contains(refinement), "the refinement itself must be complete")
}

// MARK: - V39 - V107: the 2.0.0 additions

func v39() throws {
    let st = try stratumObj("cellular", "neuroendocrine", 6, unit: "cell", governs: ["cell_biology"])
    let r = try validator.validate(st)
    try check(r.ok, "schema: \(r.reasons)")
}

func v40() throws {
    let bad = try mk(["type": .string("stratum"), "label": .string("cellular"), "ordinal": .int(6)])
    let r = try validator.validate(bad, kind: "stratum")
    try check(!r.ok && r.reasons.contains { $0.contains("scheme") }, "reasons: \(r.reasons)")
}

func v41() throws {
    let a = try stratumObj("cellular", "neuroendocrine", 6)
    let b = try stratumObj("neuronal", "neuroendocrine", 6)
    for x in [a, b] {
        let r = try validator.validate(x)
        try check(r.ok, "schema: \(r.reasons)")
    }
    try check(oid(a) != oid(b), "distinct strata share an id")
}

func v42() throws {
    let s = try neuro()
    let s4p = try stratumObj("molecular", "physics", 4)
    let c = try occObj("chronic_social_subordination", oid(s[14]!))
    let e = try occObj("gene_expression", oid(s4p))
    let smap = [oid(s[14]!): s[14]!, oid(s4p): s4p]
    let omap = [oid(c): c, oid(e): e]
    let p = try croObj([oid(c)], [oid(e)])
    try check(classifyCro(p, omap, smap) == "scheme_mismatch", "expected scheme_mismatch")
}

func v43() throws {
    for x in [try stratumObj("macromolecular", "neuroendocrine", 4),
              try stratumObj("region", "neuroendocrine", 9)] {
        let r = try validator.validate(x)
        try check(r.ok, "schema: \(r.reasons)")
    }
}

func v44() throws {
    let st = try stratumObj("cellular", "neuroendocrine", 6)
    let o = try occObj("neuron_fires", oid(st))
    let r = try validator.validate(o)
    try check(r.ok, "schema: \(r.reasons)")
    let sem = try validateSemantics(o)
    try check(sem.ok, "semantics: \(sem.reasons)")
}

func v45() throws {
    let o = try occObj("press_button")
    let r = try validator.validate(o)
    try check(r.ok, "schema: \(r.reasons)")
    let e = try occObj("light_on")
    let p = try croObj([oid(o)], [oid(e)])
    try check(classifyCro(p, [oid(o): o, oid(e): e], [:]) == "unclassifiable", "expected unclassifiable")
}

func v46() throws {
    let s = try neuro()
    let a = try occObj("depolarization", oid(s[5]!))
    let b = try occObj("depolarization", oid(s[6]!))
    try check(oid(a) != oid(b), "same-label occurrents at different strata share an id")
}

func bridgeFixture(_ relation: String) throws
    -> (bridge: [String: JsonValue], omap: [String: [String: JsonValue]], smap: [String: [String: JsonValue]]) {
    let s = try neuro()
    let coarse = try occObj("action_potential_fires", oid(s[6]!))
    let fine = [try occObj("sodium_channels_open", oid(s[4]!)),
                try occObj("sodium_influx", oid(s[4]!))]
    let b = try bridgeObj(oid(coarse), fine.map { oid($0) }, relation)
    var omap = [oid(coarse): coarse]
    for f in fine { omap[oid(f)] = f }
    let smap = [oid(s[4]!): s[4]!, oid(s[6]!): s[6]!]
    return (b, omap, smap)
}

func validBridge(_ relation: String) throws {
    let (b, omap, smap) = try bridgeFixture(relation)
    let r = try validator.validate(b)
    try check(r.ok, "schema: \(r.reasons)")
    let wf = bridgeWellformed(b, omap, smap)
    try check(wf.ok, "well-formedness: \(wf.reason)")
}

func v47() throws { try validBridge("constitutes") }
func v48() throws { try validBridge("aggregates") }
func v49() throws { try validBridge("realizes") }
func v50() throws { try validBridge("supervenes_on") }

func v51() throws {
    let s = try neuro()
    let coarse = try occObj("x_coarse", oid(s[4]!))
    let fine = try occObj("x_fine", oid(s[6]!))
    let b = try bridgeObj(oid(coarse), [oid(fine)], "constitutes")
    let omap = [oid(coarse): coarse, oid(fine): fine]
    let smap = [oid(s[4]!): s[4]!, oid(s[6]!): s[6]!]
    try check(!bridgeWellformed(b, omap, smap).ok, "expected malformed bridge")
}

func v52() throws {
    let s = try neuro()
    let coarse = try occObj("c", oid(s[6]!))
    let f1 = try occObj("f1", oid(s[4]!))
    let f2 = try occObj("f2", oid(s[5]!))
    let b = try bridgeObj(oid(coarse), [oid(f1), oid(f2)], "constitutes")
    let omap = [oid(coarse): coarse, oid(f1): f1, oid(f2): f2]
    let smap = [oid(s[4]!): s[4]!, oid(s[5]!): s[5]!, oid(s[6]!): s[6]!]
    try check(!bridgeWellformed(b, omap, smap).ok, "expected malformed bridge (fine span)")
}

func v53() throws {
    let x = try sym("occurrent:x")
    let y = try sym("occurrent:y")
    let b1 = try bridgeObj(x, [y], "constitutes")
    let b2 = try bridgeObj(y, [x], "constitutes")
    var edges: [String: [String]] = [:]
    for b in [b1, b2] {
        for f in stringList(b["fine"]) {
            edges[f, default: []].append(b["coarse"]!.stringValue!)
        }
    }
    try check(hasCycle(edges) == true, "expected a cycle in the bridge graph")
}

func v54() throws {
    let a = try stratumObj("cellular", "neuroendocrine", 6)
    let b = try stratumObj("molecular", "physics", 4)
    let coarse = try occObj("c", oid(a))
    let fine = try occObj("f", oid(b))
    let br = try bridgeObj(oid(coarse), [oid(fine)], "constitutes")
    let omap = [oid(coarse): coarse, oid(fine): fine]
    let smap = [oid(a): a, oid(b): b]
    try check(!bridgeWellformed(br, omap, smap).ok, "expected malformed bridge (scheme)")
}

func v55() throws {
    let s = try neuro()
    let coarse = try occObj("decision_made", oid(s[6]!))
    let f1 = try occObj("cascade_a", oid(s[4]!))
    let f2 = try occObj("cascade_b", oid(s[4]!))
    let b1 = try bridgeObj(oid(coarse), [oid(f1)], "realizes")
    let b2 = try bridgeObj(oid(coarse), [oid(f2)], "realizes")
    try check(oid(b1) != oid(b2), "distinct bridges share an id")
    for b in [b1, b2] {
        let r = try validator.validate(b)
        try check(r.ok, "schema: \(r.reasons)")
    }
}

func reachFixture() throws
    -> (parent: [String: JsonValue], members: [String: [String: JsonValue]], bridges: [[String: JsonValue]]) {
    let s = try neuro()
    let ap = try occObj("action_potential_fires", oid(s[6]!))
    let nt = try occObj("neurotransmitter_released", oid(s[6]!))
    let fa = try occObj("calcium_enters", oid(s[4]!))
    let fb = try occObj("vesicle_fuses", oid(s[4]!))
    let m1 = try croObj([oid(fa)], [oid(fb)])
    let p = try croObj([oid(ap)], [oid(nt)], ["mechanism": strings([oid(m1)])])
    let bridges = [try bridgeObj(oid(ap), [oid(fa)], "constitutes"),
                   try bridgeObj(oid(nt), [oid(fb)], "constitutes")]
    return (p, [oid(m1): m1], bridges)
}

func v56() throws {
    let (p, members, bridges) = try reachFixture()
    try check(hierarchyConsistent(p, members, bridges) == "consistent", "expected consistent")
}

func v57() throws {
    let (p, members, _) = try reachFixture()
    try check(hierarchyConsistent(p, members, []) == "inconsistent", "expected inconsistent")
}

func v58() throws {
    let (p, members, bridges) = try reachFixture()
    let literal = hierarchyConsistent(p, members, [])
    let bridged = hierarchyConsistent(p, members, bridges)
    try check(literal != "consistent" && bridged == "consistent",
              "literal=\(literal) bridged=\(bridged)")
}

func classifyOrds(_ causeOrd: Int, _ effectOrd: Int) throws -> String {
    let s = try neuro()
    let c = try occObj("c", oid(s[causeOrd]!))
    let e = try occObj("e", oid(s[effectOrd]!))
    var smap: [String: [String: JsonValue]] = [:]
    smap[oid(s[causeOrd]!)] = s[causeOrd]!
    smap[oid(s[effectOrd]!)] = s[effectOrd]!
    let omap = [oid(c): c, oid(e): e]
    return classifyCro(try croObj([oid(c)], [oid(e)]), omap, smap)
}

func v59() throws { try check(try classifyOrds(6, 6) == "intra_stratal", "expected intra_stratal") }
func v60() throws { try check(try classifyOrds(6, 5) == "adjacent_stratal", "expected adjacent_stratal") }
func v61() throws { try check(try classifyOrds(14, 4) == "skipping", "expected skipping") }

func skipFixture(_ causeOrd: Int, _ effectOrd: Int, _ extra: [String: JsonValue] = [:]) throws
    -> (parent: [String: JsonValue], classification: String) {
    let s = try neuro()
    let c = try occObj("c", oid(s[causeOrd]!))
    let e = try occObj("e", oid(s[effectOrd]!))
    var smap: [String: [String: JsonValue]] = [:]
    smap[oid(s[causeOrd]!)] = s[causeOrd]!
    smap[oid(s[effectOrd]!)] = s[effectOrd]!
    let omap = [oid(c): c, oid(e): e]
    let p = try croObj([oid(c)], [oid(e)], extra)
    return (p, classifyCro(p, omap, smap))
}

func v62() throws {
    let (p, cls) = try skipFixture(14, 4)
    try check(skipGaps(p, cls) == ["incomplete_mechanism"], "gaps: \(skipGaps(p, cls))")
}

func v63() throws {
    let (p, cls) = try skipFixture(14, 4, ["skips": .bool(true)])
    try check(skipGaps(p, cls) == [], "gaps: \(skipGaps(p, cls))")
}

func v64() throws {
    let (p, cls) = try skipFixture(14, 4,
        ["skips": .bool(true), "mechanism": strings([try sym("causal_relation_object:m")])])
    try check(skipGaps(p, cls) == ["contradictory_skip"], "gaps: \(skipGaps(p, cls))")
    let sem = try validateSemantics(p)
    try check(!sem.ok && sem.reasons.contains { $0.contains("contradictory_skip") },
              "semantics: \(sem.reasons)")
}

func v65() throws {
    let (p, cls) = try skipFixture(6, 6, ["skips": .bool(true)])
    try check(skipGaps(p, cls) == ["vacuous_skip"], "gaps: \(skipGaps(p, cls))")
}

func v66() throws {
    let s = try neuro()
    let c = try occObj("c", oid(s[14]!))
    let e = try occObj("e", oid(s[4]!))
    let absent = try croObj([oid(c)], [oid(e)])
    let falseSkip = try croObj([oid(c)], [oid(e)], ["skips": .bool(false)])
    try check(oid(absent) != oid(falseSkip), "absent and false skips share an id")
}

func v67() throws {
    let s = try neuro()
    let c1 = try occObj("c1", oid(s[4]!))
    let c2 = try occObj("c2", oid(s[6]!))
    let e = try occObj("e", oid(s[6]!))
    let p = try croObj([oid(c1), oid(c2)], [oid(e)])
    try check(endpointsMixed(p, [oid(c1): c1, oid(c2): c2, oid(e): e]) == true, "expected mixed endpoints")
}

func v68() throws {
    let p = try croObj([try sym("occurrent:a")], [try sym("occurrent:b")], ["modality": .string("enabling")])
    let r = try validator.validate(p)
    try check(r.ok, "schema: \(r.reasons)")
}

func v69() throws {
    let a: [String: JsonValue] = ["causes": strings([try sym("occurrent:a")]),
        "effects": strings([try sym("occurrent:b")]), "modality": .string("enabling")]
    let b: [String: JsonValue] = ["causes": strings([try sym("occurrent:a")]),
        "effects": strings([try sym("occurrent:b")]), "modality": .string("sufficient")]
    try check(conflicts(a, b) == false, "enabling and sufficient must not conflict")
}

func v70() throws {
    let a: [String: JsonValue] = ["causes": strings([try sym("occurrent:a")]),
        "effects": strings([try sym("occurrent:b")]), "modality": .string("enabling")]
    let b: [String: JsonValue] = ["causes": strings([try sym("occurrent:a")]),
        "effects": strings([try sym("occurrent:b")]), "modality": .string("preventive")]
    try check(conflicts(a, b) == true, "enabling and preventive must conflict")
}

func v71() throws {
    let b = try cntObj("hippocampus")
    let p = try portObj(oid(b), "perforant_path", "in", [try sym("occurrent:signal")])
    let r = try validator.validate(p)
    try check(r.ok, "schema: \(r.reasons)")
}

func v72() throws {
    let b = oid(try cntObj("hippocampus"))
    let x = try sym("occurrent:signal")
    try check(oid(try portObj(b, "perforant_path", "in", [x])) != oid(try portObj(b, "fornix", "in", [x])),
              "distinct ports share an id")
}

func conduitFixture(transform: Bool = false, badCarry: Bool = false, inFrom: Bool = false) throws
    -> (conduit: [String: JsonValue], pmap: [String: [String: JsonValue]], cmap: [String: [String: JsonValue]]) {
    let x = try sym("occurrent:motor_command")
    let y = try sym("occurrent:error_signal")
    let z = try sym("occurrent:unrelated")
    let m1 = oid(try cntObj("motor_cortex"))
    let m2 = oid(try cntObj("spinal_neuron"))
    let frm = try portObj(m1, "out_port", inFrom ? "in" : "out", [x])
    let to = try portObj(m2, "in_port", "in", transform ? [y] : [x])
    let carries = badCarry ? [z] : [x]
    var xform: String? = nil
    var cmap: [String: [String: JsonValue]] = [:]
    if transform {
        let law = try croObj([x], [y])
        cmap[oid(law)] = law
        xform = oid(law)
    }
    let c = try conduitObj(oid(frm), oid(to), carries, transform: xform)
    return (c, [oid(frm): frm, oid(to): to], cmap)
}

func v73() throws {
    let (c, pmap, _) = try conduitFixture()
    let r = try validator.validate(c)
    try check(r.ok, "schema: \(r.reasons)")
    let wf = conduitWellformed(c, pmap)
    try check(wf.ok, "well-formedness: \(wf.reason)")
}

func v74() throws {
    let (c, pmap, cmap) = try conduitFixture(transform: true)
    let r = try validator.validate(c)
    try check(r.ok, "schema: \(r.reasons)")
    let wf = conduitWellformed(c, pmap, cmap)
    try check(wf.ok, "well-formedness: \(wf.reason)")
}

func v75() throws {
    let (c, pmap, _) = try conduitFixture(badCarry: true)
    try check(!conduitWellformed(c, pmap).ok, "expected malformed conduit (carry)")
}

func v76() throws {
    let (c, pmap, _) = try conduitFixture(inFrom: true)
    try check(!conduitWellformed(c, pmap).ok, "expected malformed conduit (direction)")
}

func v77() throws {
    let (c, pmap, cmap) = try conduitFixture(transform: true)
    let wf = conduitWellformed(c, pmap, cmap)
    try check(wf.ok, "well-formedness: \(wf.reason)")
    let law = cmap.values.first!
    try check(!stringList(c["carries"]).contains(stringList(law["effects"])[0]),
              "the transform's effect should not be directly carried")
}

func v78() throws {
    let b = oid(try cntObj("hippocampus"))
    try check(oid(try rlzObj(b, "disposition", "long_term_potentiation"))
              != oid(try rlzObj(b, "disposition", "pattern_separation")),
              "distinct realizables share an id")
}

func v79() throws {
    let b = oid(try cntObj("hippocampus"))
    let u1 = try rlzObj(b, "disposition")
    let u2 = try rlzObj(b, "disposition")
    let r = try validator.validate(u1)
    try check(r.ok, "schema: \(r.reasons)")
    try check(oid(u1) == oid(u2), "identical realizables differ")
    try check(oid(try rlzObj(b, "disposition", "some_function")) != oid(u1),
              "labelled realizable collides with unlabelled")
}

func v80() throws {
    let parent = try occObj("fires")
    let child = try occObj("fires_action_potential")
    let e: [String: JsonValue] = ["type": .string("enrichment"), "about": .string(oid(child)),
        "field": .string("occurrent_subsumes"), "entry": .string(oid(parent))]
    let sem = try validateSemantics(e)
    try check(sem.ok, "semantics: \(sem.reasons)")
}

func v81() throws {
    let a = try sym("occurrent:a")
    let b = try sym("occurrent:b")
    try check(hasCycle([a: [b], b: [a]]) == true, "expected a cycle")
}

func v82() throws {
    let whole = try occObj("eat")
    let part = try occObj("chew")
    let e: [String: JsonValue] = ["type": .string("enrichment"), "about": .string(oid(part)),
        "field": .string("occurrent_part_of"), "entry": .string(oid(whole))]
    let sem = try validateSemantics(e)
    try check(sem.ok, "semantics: \(sem.reasons)")
}

func v83() throws {
    guard let spec = enrichmentFields["occurrent_part_of"] else {
        throw ConformanceFailure("occurrent_part_of not registered")
    }
    try check(spec.entryShape == "occurrent" && spec.legalKinds == ["occurrent"], "wrong enrichment spec")
    let s = InMemoryStore(validator: validator)
    try s.put(try occObj("eat"))
    try s.put(try occObj("chew"))
    for obj in s.objects.values {
        try check(obj["type"]?.stringValue != "causal_relation_object", "unexpected CRO in store")
    }
}

func v84() throws {
    let s = try neuro()
    let a = try occObj("run", oid(s[9]!))
    let b = try occObj("sprint", oid(s[6]!))
    try check(a["stratum"] != b["stratum"], "occurrents at different strata share a stratum ref")
}

func v85() throws {
    let c = try cntObj("human_patient")
    let ti = try individualObj(oid(c), designator: "salted_hash_abc123")
    let r = try validator.validate(ti)
    try check(r.ok, "schema: \(r.reasons)")
}

func v86() throws {
    let bad = try mk(["type": .string("token_individual"), "designator": .string("x")])
    let r = try validator.validate(bad, kind: "token_individual")
    try check(!r.ok && r.reasons.contains { $0.contains("instantiates") }, "reasons: \(r.reasons)")
}

func v87() throws {
    let c = oid(try cntObj("human_patient"))
    try check(oid(try individualObj(c, designator: "hash_a")) != oid(try individualObj(c, designator: "hash_b")),
              "distinct individuals share an id")
}

func v88() throws {
    let o = try occObj("bilateral_hippocampal_resection")
    let t = try tokenObj(oid(o), .object([
        "start": .string("1953-08-25T00:00:00Z"), "end": .string("1953-08-25T00:00:00Z"),
    ]))
    let r = try validator.validate(t)
    try check(r.ok, "schema: \(r.reasons)")
}

func v89() throws {
    let o = oid(try occObj("amnesia_onset"))
    let bounded = try tokenObj(o, .object([
        "start": .string("1953-08-25T00:00:00Z"), "end": .string("1953-08-26T00:00:00Z")]))
    let instantaneous = try tokenObj(o, .object(["start": .string("1953-08-25T00:00:00Z")]))
    let ongoing = try tokenObj(o, .object([
        "start": .string("1953-08-25T00:00:00Z"), "open": .bool(true)]))
    try check(Set([oid(bounded), oid(instantaneous), oid(ongoing)]).count == 3,
              "the three interval forms are not all distinct")
}

func v90() throws {
    let o = oid(try occObj("resection"))
    let c = oid(try cntObj("human_patient"))
    let patient = oid(try individualObj(c, designator: "p"))
    let surgeon = oid(try individualObj(c, designator: "s"))
    let t = try tokenObj(o, .object(["start": .string("1953-08-25T00:00:00Z")]),
        participants: .array([
            .object(["role": .string("patient"), "filler": .string(patient)]),
            .object(["role": .string("agent"), "filler": .string(surgeon)]),
        ]))
    let r = try validator.validate(t)
    try check(r.ok, "schema: \(r.reasons)")
}

func v91() throws {
    let q = try qualityObj("cortisol_concentration", "quantity", unit: "ug/dL")
    let r = try validator.validate(q)
    try check(r.ok, "schema: \(r.reasons)")
}

func stateFixture(_ datatype: String, _ value: JsonValue, unit: String? = nil) throws
    -> (state: [String: JsonValue], quality: [String: JsonValue]) {
    let q = try qualityObj("cortisol_concentration", datatype, unit: unit)
    let c = oid(try cntObj("human_patient"))
    let subj = oid(try individualObj(c, designator: "p"))
    let st = try stateObj(subj, oid(q), value, .object([
        "start": .string("2026-01-01T00:00:00Z"), "end": .string("2026-01-01T01:00:00Z")]))
    return (st, q)
}

func v92() throws {
    let (st, q) = try stateFixture("quantity", .object([
        "quantity": .double(15.0), "unit": .string("ug/dL")]), unit: "ug/dL")
    let r = try validator.validate(st)
    try check(r.ok, "schema: \(r.reasons)")
    try check(stateGaps(st, q) == [], "gaps: \(stateGaps(st, q))")
}

func v93() throws {
    let (st, q) = try stateFixture("categorical", .object(["categorical": .string("elevated")]))
    let r = try validator.validate(st)
    try check(r.ok, "schema: \(r.reasons)")
    try check(stateGaps(st, q) == [], "gaps: \(stateGaps(st, q))")
}

func v94() throws {
    let (st, q) = try stateFixture("boolean", .object(["boolean": .bool(true)]))
    let r = try validator.validate(st)
    try check(r.ok, "schema: \(r.reasons)")
    try check(stateGaps(st, q) == [], "gaps: \(stateGaps(st, q))")
}

func v95() throws {
    let (st, q) = try stateFixture("quantity", .object(["categorical": .string("elevated")]), unit: "ug/dL")
    try check(stateGaps(st, q) == ["value_type_mismatch"], "gaps: \(stateGaps(st, q))")
}

func v96() throws {
    let (st, q) = try stateFixture("quantity", .object([
        "quantity": .double(15.0), "unit": .string("mg/dL")]), unit: "ug/dL")
    try check(stateGaps(st, q) == ["unit_mismatch"], "gaps: \(stateGaps(st, q))")
}

func lawAndTokens() throws
    -> (law: [String: JsonValue], oCause: [String: JsonValue], oEffect: [String: JsonValue],
        tCause: [String: JsonValue], tEffect: [String: JsonValue]) {
    let oCause = try occObj("resection")
    let oEffect = try occObj("amnesia_onset")
    let law = try croObj([oid(oCause)], [oid(oEffect)], [
        "temporal": .object(["minimum_delay": .int(0), "maximum_delay": .int(1), "unit": .string("days")]),
        "modality": .string("sufficient"),
    ])
    let tCause = try tokenObj(oid(oCause), .object(["start": .string("1953-08-25T00:00:00Z")]))
    let tEffect = try tokenObj(oid(oEffect), .object([
        "start": .string("1953-08-25T00:00:00Z"), "open": .bool(true)]))
    return (law, oCause, oEffect, tCause, tEffect)
}

func v97() throws {
    let f = try lawAndTokens()
    let claim = try tccObj([oid(f.tCause)], [oid(f.tEffect)], coveringLaw: oid(f.law),
        actualDelay: .object(["duration": .int(0), "unit": .string("instant")]), counterfactual: true)
    let r = try validator.validate(claim)
    try check(r.ok, "schema: \(r.reasons)")
}

func v98() throws {
    let f = try lawAndTokens()
    let claim = try tccObj([oid(f.tCause)], [oid(f.tEffect)])
    let r = try validator.validate(claim)
    try check(r.ok, "schema: \(r.reasons)")
    try check(claim["covering_law"] == nil, "covering_law should be absent")
}

func v99() throws {
    let f = try lawAndTokens()
    try check(delayWithinWindow(["duration": .int(0), "unit": .string("instant")],
                                f.law["temporal"]?.objectValue) == true, "expected within window")
}

func v100() throws {
    let temporal: [String: JsonValue] = ["minimum_delay": .int(0), "maximum_delay": .int(1), "unit": .string("hours")]
    try check(delayWithinWindow(["duration": .int(5), "unit": .string("days")], temporal) == false,
              "expected outside window")
}

func v101() throws {
    let o = oid(try occObj("x"))
    let cause = try tokenObj(o, .object(["start": .string("2026-01-02T00:00:00Z")]))
    let effect = try tokenObj(o, .object(["start": .string("2026-01-01T00:00:00Z")]))
    let claim = try tccObj([oid(cause)], [oid(effect)])
    try check(retrocausal(claim, [oid(cause): cause, oid(effect): effect]) == true, "expected retrocausal")
}

func v102() throws {
    let other = try croObj([try sym("occurrent:foo")], [try sym("occurrent:bar")])
    let f = try lawAndTokens()
    let claim = try tccObj([oid(f.tCause)], [oid(f.tEffect)], coveringLaw: oid(other))
    try check(coveringLawMismatch(claim, [oid(f.tCause): f.tCause, oid(f.tEffect): f.tEffect], other) == true,
              "expected covering-law mismatch")
}

func v103() throws {
    let a = try signed("assertion", ["about": .string(try sym("token_occurrence:t")),
        "evidence_type": .string("observation"), "confidence": .double(0.9)], "signer")
    let r = try validator.validate(a)
    try check(r.ok, "schema: \(r.reasons)")
}

func v104() throws {
    let ev = [try sym("token_occurrence:t1"), try sym("token_causal_claim:c1")]
    let base: [String: JsonValue] = ["type": .string("assertion"),
        "about": .string(try sym("causal_relation_object:law")),
        "source": .string(try key("signer").publicId),
        "evidence_type": .string("intervention"),
        "strength": .double(0.95), "confidence": .double(0.99),
        "timestamp": .string("2026-07-14T00:00:00Z")]
    var a = base
    a["evidenced_by"] = strings(ev)
    var withId = a
    withId["id"] = .string(try identify(a))
    let r = try validator.validate(withId)
    try check(r.ok, "schema: \(r.reasons)")
    try check(try identify(a) != (try identify(base)), "evidenced_by must be identity-bearing")
}

func v105() throws {
    let a = try signed("assertion", ["about": .string(try sym("causal_relation_object:law")),
        "evidence_type": .string("simulation"), "confidence": .double(0.5)], "signer")
    let r = try validator.validate(a)
    try check(r.ok, "schema: \(r.reasons)")
}

func v106() throws {
    func scan(_ node: JsonValue, _ ids: inout [String]) {
        switch node {
        case let .string(text):
            if let colon = text.firstIndex(of: ":") {
                let scheme = String(text[text.startIndex..<colon])
                let name = String(text[text.index(after: colon)...])
                let schemeOk = !scheme.isEmpty && scheme.allSatisfy {
                    ($0 >= "a" && $0 <= "z") || ($0 >= "0" && $0 <= "9") || $0 == "_"
                }
                if schemeOk && isHex64(name) {
                    ids.append(scheme)
                }
            }
        case let .array(items):
            for x in items { scan(x, &ids) }
        case let .object(members):
            for x in members.values { scan(x, &ids) }
        default:
            break
        }
    }
    for n in 1...38 {
        var ids: [String] = []
        scan(.object(try vec(n)), &ids)
        for scheme in ids {
            try check(wholeWordSchemes.contains(scheme),
                      "V106: abbreviated scheme '\(scheme)' in vector \(n)")
        }
    }
    let rec: [String: JsonValue] = ["type": .string("occurrent"),
        "label": .string("press_button"), "category": .string("action")]
    try check(try identify(rec) == (try identify(rec)), "identity not deterministic")
    let prefix = try identify(rec).split(separator: ":", maxSplits: 1)[0]
    try check(String(prefix) == "occurrent", "wrong scheme prefix: \(prefix)")
}

func v107() throws {
    let hexid = String(repeating: "0", count: 64)
    // The abbreviated prefix below is intentional (the negative test); it must
    // NOT be re-minted. "c" "r" "o" is assembled to survive re-mint tools.
    let croAbbr = "c" + "r" + "o"
    let abbreviated: [String: JsonValue] = ["type": .string("causal_relation_object"),
        "id": .string(croAbbr + ":" + hexid),
        "causes": strings(["occurrent:" + hexid]), "effects": strings(["occurrent:" + hexid])]
    try check(!(try validator.validate(abbreviated, kind: "causal_relation_object")).ok,
              "abbreviated scheme must be rejected")
    let abbrStr: [String: JsonValue] = ["type": .string("stratum"),
        "id": .string("str:" + hexid), "label": .string("cellular"),
        "scheme": .string("neuroendocrine"), "ordinal": .int(6)]
    try check(!(try validator.validate(abbrStr, kind: "stratum")).ok,
              "abbreviated stratum scheme must be rejected")
    let whole: [String: JsonValue] = ["type": .string("causal_relation_object"),
        "id": .string("causal_relation_object:" + hexid),
        "causes": strings(["occurrent:" + hexid]), "effects": strings(["occurrent:" + hexid])]
    let r = try validator.validate(whole, kind: "causal_relation_object")
    try check(r.ok, "whole-word scheme must validate: \(r.reasons)")
}

// MARK: - V108 - V137: the 3.0.0 and 4.0.0 additions

/// A cross_stratal_seam content object.
func seamObj(_ source: String, _ target: String, _ mechanismStatus: String,
             chain: [String]? = nil) throws -> [String: JsonValue] {
    var o: [String: JsonValue] = [
        "type": .string("cross_stratal_seam"),
        "source": .string(source), "target": .string(target),
        "mechanism_status": .string(mechanismStatus),
    ]
    if let chain = chain { o["chain"] = strings(chain) }
    return try mk(o)
}

/// A seam plus its endpoint/chain occurrent map and stratum map.
func seamFixture(_ srcOrd: Int, _ tgtOrd: Int, _ mechanismStatus: String,
                 chainOrds: [Int]? = nil) throws
    -> (seam: [String: JsonValue], omap: [String: [String: JsonValue]], smap: [String: [String: JsonValue]]) {
    let s = try neuro()
    let src = try occObj("source_event", oid(s[srcOrd]!))
    let tgt = try occObj("target_event", oid(s[tgtOrd]!))
    var omap: [String: [String: JsonValue]] = [oid(src): src, oid(tgt): tgt]
    // Subscript assignment, not a dictionary literal: srcOrd and tgtOrd may
    // coincide (the co-stratal fixture), and a duplicate key traps a literal.
    var smap: [String: [String: JsonValue]] = [:]
    smap[oid(s[srcOrd]!)] = s[srcOrd]!
    smap[oid(s[tgtOrd]!)] = s[tgtOrd]!
    var chain: [String]? = nil
    if let chainOrds = chainOrds {
        var members: [String] = []
        for (i, ord) in chainOrds.enumerated() {
            let c = try occObj("chain_\(i)", oid(s[ord]!))
            omap[oid(c)] = c
            smap[oid(s[ord]!)] = s[ord]!
            members.append(oid(c))
        }
        chain = members
    }
    let seam = try seamObj(oid(src), oid(tgt), mechanismStatus, chain: chain)
    return (seam, omap, smap)
}

/// A conduit with an optional realized_by reference (mirrors _conduit_realized).
func conduitRealized(_ realizedBy: String? = nil) throws -> [String: JsonValue] {
    let frm = "port:" + String(repeating: "1", count: 64)
    let to = "port:" + String(repeating: "2", count: 64)
    let x = "occurrent:" + String(repeating: "3", count: 64)
    var o: [String: JsonValue] = [
        "type": .string("conduit"), "label": .string("conn"),
        "from": .string(frm), "to": .string(to), "carries": strings([x]),
    ]
    if let realizedBy = realizedBy { o["realized_by"] = .string(realizedBy) }
    return try mk(o)
}

/// An attitude content object.
func attitudeObj(_ holder: String, _ attitudeType: String, _ content: String) throws -> [String: JsonValue] {
    return try mk([
        "type": .string("attitude"), "holder": .string(holder),
        "attitude_type": .string(attitudeType), "content": .string(content),
    ])
}

/// A predicted_occurrence content object.
func predictedObj(_ instantiates: String, _ interval: JsonValue, _ predictor: String,
                  strength: Double? = nil) throws -> [String: JsonValue] {
    var o: [String: JsonValue] = [
        "type": .string("predicted_occurrence"),
        "instantiates": .string(instantiates), "interval": interval,
        "predictor": .string(predictor),
    ]
    if let strength = strength { o["strength"] = .double(strength) }
    return try mk(o)
}

/// A prediction_error content object.
func predictionErrorObj(_ predictedId: String, _ discrepancy: Double,
                        observed: String? = nil) throws -> [String: JsonValue] {
    var o: [String: JsonValue] = [
        "type": .string("prediction_error"),
        "predicted": .string(predictedId), "discrepancy": .double(discrepancy),
    ]
    if let observed = observed { o["observed"] = .string(observed) }
    return try mk(o)
}

/// A modeled predicting agent (a token individual); mirrors _predictor.
func predictorId() throws -> String {
    let c = try cntObj("forecasting_mind")
    return oid(try individualObj(oid(c), designator: "predictor_p"))
}

/// A modeled believing agent (a token individual); mirrors _believer.
func believerId(_ designator: String = "holder_h") throws -> String {
    let c = try cntObj("believing_mind")
    return oid(try individualObj(oid(c), designator: designator))
}

/// An ordinal (tick) interval for a predicted_occurrence.
func tickInterval(_ startTick: Int, _ endTick: Int? = nil) -> JsonValue {
    var o: [String: JsonValue] = ["start_tick": .int(Int64(startTick))]
    if let endTick = endTick { o["end_tick"] = .int(Int64(endTick)) }
    return .object(o)
}

/// A wall-clock interval for a predicted_occurrence.
func wallInterval(_ start: String, _ end: String? = nil) -> JsonValue {
    var o: [String: JsonValue] = ["start": .string(start)]
    if let end = end { o["end"] = .string(end) }
    return .object(o)
}

// -- Change One: the ordinal (tick) temporal unit --

func v108() throws {
    let p = try croObj([try sym("occurrent:a")], [try sym("occurrent:b")], [
        "temporal": .object(["minimum_delay": .int(0), "maximum_delay": .int(5), "unit": .string("ticks")]),
        "modality": .string("sufficient"),
    ])
    let r = try validator.validate(p)
    try check(r.ok, "schema: \(r.reasons)")
    let sem = try validateSemantics(p)
    try check(sem.ok, "semantics: \(sem.reasons)")
}

func v109() throws {
    let p = try croObj([try sym("occurrent:a")], [try sym("occurrent:b")], [
        "temporal": .object(["minimum_delay": .int(2), "maximum_delay": .int(5), "unit": .string("ticks")]),
    ])
    try check(admissible(p, elapsedSeconds: 3) == true, "3 ticks must be inside [2, 5]")
    try check(admissible(p, elapsedSeconds: 2) == true && admissible(p, elapsedSeconds: 5) == true,
              "the tick window is inclusive at both ends")
    try check(admissible(p, elapsedSeconds: 6) == false && admissible(p, elapsedSeconds: 1) == false,
              "ticks outside [2, 5] must not be admissible")
}

func v110() throws {
    let tickWindow: [String: JsonValue] = ["minimum_delay": .int(0), "maximum_delay": .int(5), "unit": .string("ticks")]
    let wallWindow: [String: JsonValue] = ["minimum_delay": .int(0), "maximum_delay": .int(5), "unit": .string("seconds")]
    try check(delayWithinWindow(["duration": .int(3), "unit": .string("ticks")], tickWindow) == true,
              "a tick delay must fall within a tick window")
    try check(delayWithinWindow(["duration": .int(1), "unit": .string("ticks")], wallWindow) == false,
              "a tick delay is never within a wall-clock window")
    try check(delayWithinWindow(["duration": .int(1), "unit": .string("seconds")], tickWindow) == false,
              "a wall-clock delay is never within a tick window")
    let a: [String: JsonValue] = ["causes": strings([try sym("occurrent:a")]),
        "effects": strings([try sym("occurrent:b")]),
        "temporal": .object(tickWindow), "modality": .string("sufficient")]
    let b: [String: JsonValue] = ["causes": strings([try sym("occurrent:a")]),
        "effects": strings([try sym("occurrent:b")]),
        "temporal": .object(wallWindow), "modality": .string("preventive")]
    try check(conflicts(a, b) == false, "disjoint dimensions -> no overlap")
    var refused = false
    do {
        _ = try toSeconds(1, "ticks")
    } catch {
        refused = true
    }
    try check(refused, "to_seconds accepted ticks")
}

func v111() throws {
    let base: [String: JsonValue] = ["type": .string("causal_relation_object"),
        "causes": strings([try sym("occurrent:a")]),
        "effects": strings([try sym("occurrent:b")]),
        "modality": .string("sufficient")]
    var tick = base
    tick["temporal"] = .object(["minimum_delay": .int(0), "maximum_delay": .int(1), "unit": .string("ticks")])
    var secs = base
    secs["temporal"] = .object(["minimum_delay": .int(0), "maximum_delay": .int(1), "unit": .string("seconds")])
    let secsId = try identify(secs)
    try check(try identify(tick) != secsId, "the unit is identity-bearing")
    try check(secsId == "causal_relation_object:d8daf899daa3ee03caa6b1425cc6d4d33cef20d951e1203ffd35df29857aa43c",
              "the pinned 2.0.0 identifier must hold: \(secsId)")
}

// -- Change Two: the managed cross-stratal seam (eighteenth kind) --

func v112() throws {
    let (seam, omap, smap) = try seamFixture(14, 4, "unmodeled")
    let r = try validator.validate(seam)
    try check(r.ok, "schema: \(r.reasons)")
    let sem = try validateSemantics(seam)
    try check(sem.ok, "semantics: \(sem.reasons)")
    let wf = seamWellformed(seam, omap, smap)
    try check(wf.ok, wf.reason)
}

func v113() throws {
    let (a, _, _) = try seamFixture(14, 4, "unmodeled")
    let (b, omap, smap) = try seamFixture(14, 4, "absent")
    let r = try validator.validate(b)
    try check(r.ok, "schema: \(r.reasons)")
    let wf = seamWellformed(b, omap, smap)
    try check(wf.ok, wf.reason)
    try check(oid(a) != oid(b), "mechanism_status must be identity-bearing")
}

func v114() throws {
    let (drawn, omap, smap) = try seamFixture(14, 4, "unmodeled", chainOrds: [9, 7, 6, 5])
    let r = try validator.validate(drawn)
    try check(r.ok, "schema: \(r.reasons)")
    let wf = seamWellformed(drawn, omap, smap)
    try check(wf.ok, wf.reason)
    let (bad, omap2, smap2) = try seamFixture(14, 4, "absent", chainOrds: [9, 7, 6, 5])
    let sem = try validateSemantics(bad)
    try check(!sem.ok && sem.reasons.contains { $0.contains("contradictory_seam") },
              "semantics must reject the drawn 'absent' seam: \(sem.reasons)")
    try check(!seamWellformed(bad, omap2, smap2).ok, "the drawn 'absent' seam must be malformed")
}

func v115() throws {
    let (seam, omap, smap) = try seamFixture(14, 4, "unmodeled")
    let s = try neuro()
    try check(seamHome(seam, omap, smap) == oid(s[14]!),
              "home must be the coarsest (max ordinal) stratum")
}

func v116() throws {
    let (adj, o1, s1) = try seamFixture(6, 5, "unmodeled")  // adjacent (gap 1)
    try check(!seamWellformed(adj, o1, s1).ok, "adjacent endpoints must be malformed")
    let (co, o2, s2) = try seamFixture(6, 6, "unmodeled")   // co-stratal (gap 0)
    try check(!seamWellformed(co, o2, s2).ok, "co-stratal endpoints must be malformed")
    let (seam, _, _) = try seamFixture(14, 4, "unmodeled")
    try check(oid(seam).hasPrefix("cross_stratal_seam:"),
              "a seam must mint in the new identity scheme")
}

// -- Change Three: the realized_by reference --

func v117() throws {
    let c = try conduitRealized("causal_relation_object:" + String(repeating: "a", count: 64))
    let r = try validator.validate(c)
    try check(r.ok, "schema: \(r.reasons)")
    let c2 = try conduitRealized("native:region_stratum_predict")
    let r2 = try validator.validate(c2)
    try check(r2.ok, "a native scheme reference is legal: \(r2.reasons)")
}

func v118() throws {
    let bound = try conduitRealized("native:region_stratum_predict")
    let unbound = try conduitRealized()
    try check(oid(bound) != oid(unbound), "realized_by must be identity-bearing")
    try check(oid(unbound) == "conduit:dc4af3b1a24f0560d5ebcee488779f06ab3c78301cfb9d0c7edff80bc62e27a6",
              "the pinned 2.0.0 identifier must hold: \(oid(unbound))")
}

func v119() throws {
    let unbound = try conduitRealized()
    let r = try validator.validate(unbound)
    try check(r.ok, "unbound is legal: \(r.reasons)")
    var bad = unbound
    bad["realized_by"] = .string("not-a-scheme-qualified-reference")
    try check(!(try validator.validate(bad, kind: "conduit")).ok,
              "a malformed realized_by reference must be rejected")
}

// -- Group X: prediction and prediction error (Section A) --

func v120() throws {
    let o = try occObj("rainfall_begins")
    let p = try predictedObj(oid(o), tickInterval(3, 8), try predictorId())
    let r = try validator.validate(p)
    try check(r.ok, "schema: \(r.reasons)")
    let sem = try validateSemantics(p)
    try check(sem.ok, "semantics: \(sem.reasons)")
    try check(oid(p).hasPrefix("predicted_occurrence:"),
              "a forecast must mint in the new identity scheme")
    let report = try identify([
        "type": .string("token_occurrence"), "instantiates": .string(oid(o)),
        "interval": tickInterval(3, 8),
    ], kind: "token_occurrence")
    try check(oid(p) != report, "a forecast is not a report")
    try check(report.hasPrefix("token_occurrence:"), "the report keeps its own scheme")
}

func v121() throws {
    let o = try occObj("rainfall_begins")
    let wall = wallInterval("2026-07-23T00:00:00Z", "2026-07-24T00:00:00Z")
    let who = try predictorId()
    let withStrength = try predictedObj(oid(o), wall, who, strength: 0.8)
    let without = try predictedObj(oid(o), wall, who)
    for p in [withStrength, without] {
        let r = try validator.validate(p)
        try check(r.ok, "schema: \(r.reasons)")
        let sem = try validateSemantics(p)
        try check(sem.ok, "semantics: \(sem.reasons)")
    }
    try check(oid(withStrength) != oid(without), "strength must be identity-bearing")
}

func v122() throws {
    let o = try occObj("rainfall_begins")
    let bad = try mk([
        "type": .string("predicted_occurrence"),
        "instantiates": .string(oid(o)),
        "interval": tickInterval(3),
    ])
    let r = try validator.validate(bad, kind: "predicted_occurrence")
    try check(!r.ok && r.reasons.contains { $0.contains("predictor") },
              "expected predictor error: \(r.reasons)")
}

func v123() throws {
    let o = try occObj("rainfall_begins")
    let both = try predictedObj(oid(o),
        .object(["start": .string("2026-07-23T00:00:00Z"), "start_tick": .int(3)]),
        try predictorId())
    let r = try validator.validate(both)
    try check(r.ok, "schema: \(r.reasons)")
    let sem = try validateSemantics(both)
    try check(!sem.ok && sem.reasons.contains { $0.contains("dimension_conflict") },
              "semantics must reject both dimensions: \(sem.reasons)")
}

func v124() throws {
    let o = try occObj("rainfall_begins")
    let p = try predictedObj(oid(o), wallInterval("2026-07-23T00:00:00Z"), try predictorId())
    let t = try tokenObj(oid(o), wallInterval("2026-07-23T06:00:00Z"))
    let err = try predictionErrorObj(oid(p), 0.0, observed: oid(t))
    let r = try validator.validate(err)
    try check(r.ok, "schema: \(r.reasons)")
    let sem = try validateSemantics(err)
    try check(sem.ok, "semantics: \(sem.reasons)")
    try check(predictionPairingMismatch(err, p, t) == false,
              "a matching observation is not a mismatch")
}

func v125() throws {
    let o = try occObj("rainfall_begins")
    let p = try predictedObj(oid(o), wallInterval("2026-07-23T00:00:00Z"), try predictorId())
    let err = try predictionErrorObj(oid(p), -1.0)
    let r = try validator.validate(err)
    try check(r.ok, "schema: \(r.reasons)")
    let sem = try validateSemantics(err)
    try check(sem.ok, "semantics: \(sem.reasons)")
    try check(err["observed"] == nil, "observed must be absent")
    try check(predictionPairingMismatch(err, p, nil) == false,
              "an unfulfilled prediction is not a mismatch")
}

func v126() throws {
    let o = try occObj("rainfall_begins")
    let p = try predictedObj(oid(o), tickInterval(0), try predictorId())
    let bad = try mk([
        "type": .string("prediction_error"),
        "predicted": .string(oid(p)),
    ])
    let r = try validator.validate(bad, kind: "prediction_error")
    try check(!r.ok && r.reasons.contains { $0.contains("discrepancy") },
              "expected discrepancy error: \(r.reasons)")
}

func v127() throws {
    let o = try occObj("rainfall_begins")
    let other = try occObj("snowfall_begins")
    let p = try predictedObj(oid(o), wallInterval("2026-07-23T00:00:00Z"), try predictorId())
    let t = try tokenObj(oid(other), wallInterval("2026-07-23T06:00:00Z"))
    let err = try predictionErrorObj(oid(p), 1.0, observed: oid(t))
    let r = try validator.validate(err)
    try check(r.ok, "schema: \(r.reasons)")
    try check(predictionPairingMismatch(err, p, t) == true, "must surface a pairing mismatch")
}

// -- Group Y: attitude and theory of mind (Section B) --

func v128() throws {
    let (st, _) = try stateFixture("quantity",
        .object(["quantity": .double(15.0), "unit": .string("ug/dL")]), unit: "ug/dL")
    let att = try attitudeObj(try believerId(), "believes", oid(st))
    let r = try validator.validate(att)
    try check(r.ok, "schema: \(r.reasons)")
    let sem = try validateSemantics(att)
    try check(sem.ok, "semantics: \(sem.reasons)")
}

func v129() throws {
    let a = try occObj("switch_pressed")
    let b = try occObj("light_on")
    let actual = try croObj([oid(a)], [oid(b)], ["modality": .string("sufficient")])
    let believed = try croObj([oid(a)], [oid(b)], ["modality": .string("preventive")])
    try check(conflicts(believed, actual) == true, "the CLAIMS contradict")
    let att = try attitudeObj(try believerId(), "believes", oid(believed))
    let r = try validator.validate(att)
    try check(r.ok, "schema: \(r.reasons)")
    let sem = try validateSemantics(att)
    try check(sem.ok, "semantics: \(sem.reasons)")  // validity unaffected
    let s = InMemoryStore(validator: validator)
    try s.put(a)
    try s.put(b)
    try s.put(actual)
    try s.put(att)
    try check(s.gaps("conflict").isEmpty, "Rule 25: NO conflict raised")
}

func v130() throws {
    let o = try occObj("rainfall_begins")
    let att = try attitudeObj(try believerId(), "desires", oid(o))
    let r = try validator.validate(att)
    try check(r.ok, "schema: \(r.reasons)")
    let sem = try validateSemantics(att)
    try check(sem.ok, "semantics: \(sem.reasons)")
}

func v131() throws {
    let o = try occObj("press_button")
    let att = try attitudeObj(try believerId(), "intends", oid(o))
    let r = try validator.validate(att)
    try check(r.ok, "schema: \(r.reasons)")
    let sem = try validateSemantics(att)
    try check(sem.ok, "semantics: \(sem.reasons)")
}

func v132() throws {
    let (st, _) = try stateFixture("boolean", .object(["boolean": .bool(true)]))
    let inner = try attitudeObj(try believerId("holder_b"), "believes", oid(st))
    let outer = try attitudeObj(try believerId("holder_a"), "believes", oid(inner))
    for att in [inner, outer] {
        let r = try validator.validate(att)
        try check(r.ok, "schema: \(r.reasons)")
        let sem = try validateSemantics(att)
        try check(sem.ok, "semantics: \(sem.reasons)")
    }
    try check(oid(outer) != oid(inner), "ids must differ")
    try check(outer["content"]?.stringValue == oid(inner),
              "the outer content must be the inner attitude")
}

func v133() throws {
    let o = try occObj("rainfall_begins")
    let bad = try mk([
        "type": .string("attitude"),
        "holder": .string(try believerId()),
        "attitude_type": .string("suspects"),
        "content": .string(oid(o)),
    ])
    let r = try validator.validate(bad, kind: "attitude")
    try check(!r.ok && r.reasons.contains { $0.contains("attitude_type") },
              "expected attitude_type error: \(r.reasons)")
}

func v134() throws {
    let o = try occObj("rainfall_begins")
    let bad = try mk([
        "type": .string("attitude"),
        "holder": .string(try believerId()),
        "attitude_type": .string("believes"),
        "content": .string(oid(o)),
        "strength": .double(0.9),
    ])
    let r = try validator.validate(bad, kind: "attitude")
    try check(!r.ok && r.reasons.contains { $0.contains("strength") },
              "expected strength error: \(r.reasons)")
}

func v135() throws {
    let o = try occObj("rainfall_begins")
    let att = try attitudeObj(try believerId(), "expects", oid(o))
    let a = try signed("assertion", [
        "about": .string(oid(att)),
        "evidence_type": .string("observation"),
        "confidence": .double(0.9),
    ], "signer")
    let r = try validator.validate(a)
    try check(r.ok, "schema: \(r.reasons)")
    try check(verifyRecord(a) == true, "the assertion must verify")
    // the HOLDER (a modeled agent) and the SOURCE (a signing key) differ.
    let holder = att["holder"]?.stringValue ?? ""
    try check(holder.split(separator: ":", maxSplits: 1).first.map(String.init) == "token_individual",
              "the holder must be a modeled agent")
    let source = a["source"]?.stringValue ?? ""
    try check(source.split(separator: ":", maxSplits: 1).first.map(String.init) == "ed25519",
              "the source must be a signing key")
    try check(holder != source, "holder and source are different things")
}

// -- Group Z: the 4.0.0 identity witnesses --

func v136() throws {
    // the V111 wall-clock Causal Relation Object, re-pinned under 4.0.0.
    let secs: [String: JsonValue] = ["type": .string("causal_relation_object"),
        "causes": strings([try sym("occurrent:a")]),
        "effects": strings([try sym("occurrent:b")]),
        "modality": .string("sufficient"),
        "temporal": .object(["minimum_delay": .int(0), "maximum_delay": .int(1), "unit": .string("seconds")])]
    try check(try identify(secs) == "causal_relation_object:d8daf899daa3ee03caa6b1425cc6d4d33cef20d951e1203ffd35df29857aa43c",
              "the 3.0.0 wall-clock identifier must hold under 4.0.0")
    // the V118 unbound conduit, re-pinned under 4.0.0.
    let unbound = try conduitRealized()
    try check(oid(unbound) == "conduit:dc4af3b1a24f0560d5ebcee488779f06ab3c78301cfb9d0c7edff80bc62e27a6",
              "the 3.0.0 unbound-conduit identifier must hold under 4.0.0")
}

func v137() throws {
    let hexid = String(repeating: "0", count: 64)
    // The abbreviated prefixes below are intentional (the negative tests); each
    // is assembled so it survives any whole-word re-mint pass.
    let attAbbr = "a" + "t" + "t"
    let prdAbbr = "p" + "r" + "d"
    let errAbbr = "e" + "r" + "r"
    let badAtt: [String: JsonValue] = ["type": .string("attitude"),
        "id": .string(attAbbr + ":" + hexid),
        "holder": .string("token_individual:" + hexid),
        "attitude_type": .string("believes"),
        "content": .string("state_assertion:" + hexid)]
    try check(!(try validator.validate(badAtt, kind: "attitude")).ok,
              "abbreviated attitude scheme must be rejected")
    let badPrd: [String: JsonValue] = ["type": .string("predicted_occurrence"),
        "id": .string(prdAbbr + ":" + hexid),
        "instantiates": .string("occurrent:" + hexid),
        "interval": tickInterval(0),
        "predictor": .string("token_individual:" + hexid)]
    try check(!(try validator.validate(badPrd, kind: "predicted_occurrence")).ok,
              "abbreviated predicted_occurrence scheme must be rejected")
    let badErr: [String: JsonValue] = ["type": .string("prediction_error"),
        "id": .string(errAbbr + ":" + hexid),
        "predicted": .string("predicted_occurrence:" + hexid),
        "discrepancy": .double(0.0)]
    try check(!(try validator.validate(badErr, kind: "prediction_error")).ok,
              "abbreviated prediction_error scheme must be rejected")
    var wholeAtt = badAtt
    wholeAtt["id"] = .string("attitude:" + hexid)
    let attR = try validator.validate(wholeAtt, kind: "attitude")
    try check(attR.ok, "whole-word attitude must validate: \(attR.reasons)")
    var wholePrd = badPrd
    wholePrd["id"] = .string("predicted_occurrence:" + hexid)
    let prdR = try validator.validate(wholePrd, kind: "predicted_occurrence")
    try check(prdR.ok, "whole-word predicted_occurrence must validate: \(prdR.reasons)")
    var wholeErr = badErr
    wholeErr["id"] = .string("prediction_error:" + hexid)
    let errR = try validator.validate(wholeErr, kind: "prediction_error")
    try check(errR.ok, "whole-word prediction_error must validate: \(errR.reasons)")
}

// MARK: - runner

let vectorFunctions: [(Int, () throws -> Void)] = [
    (1, v01), (2, v02), (3, v03), (4, v04), (5, v05), (6, v06), (7, v07),
    (8, v08), (9, v09), (10, v10), (11, v11), (12, v12), (13, v13), (14, v14),
    (15, v15), (16, v16), (17, v17), (18, v18), (19, v19), (20, v20),
    (21, v21), (22, v22), (23, v23), (24, v24), (25, v25), (26, v26),
    (27, v27), (28, v28), (29, v29), (30, v30), (31, v31), (32, v32),
    (33, v33), (34, v34), (35, v35), (36, v36), (37, v37), (38, v38),
    (39, v39), (40, v40), (41, v41), (42, v42), (43, v43), (44, v44),
    (45, v45), (46, v46), (47, v47), (48, v48), (49, v49), (50, v50),
    (51, v51), (52, v52), (53, v53), (54, v54), (55, v55), (56, v56),
    (57, v57), (58, v58), (59, v59), (60, v60), (61, v61), (62, v62),
    (63, v63), (64, v64), (65, v65), (66, v66), (67, v67), (68, v68),
    (69, v69), (70, v70), (71, v71), (72, v72), (73, v73), (74, v74),
    (75, v75), (76, v76), (77, v77), (78, v78), (79, v79), (80, v80),
    (81, v81), (82, v82), (83, v83), (84, v84), (85, v85), (86, v86),
    (87, v87), (88, v88), (89, v89), (90, v90), (91, v91), (92, v92),
    (93, v93), (94, v94), (95, v95), (96, v96), (97, v97), (98, v98),
    (99, v99), (100, v100), (101, v101), (102, v102), (103, v103),
    (104, v104), (105, v105), (106, v106), (107, v107),
    (108, v108), (109, v109), (110, v110), (111, v111), (112, v112),
    (113, v113), (114, v114), (115, v115), (116, v116), (117, v117),
    (118, v118), (119, v119), (120, v120), (121, v121), (122, v122),
    (123, v123), (124, v124), (125, v125), (126, v126), (127, v127),
    (128, v128), (129, v129), (130, v130), (131, v131), (132, v132),
    (133, v133), (134, v134), (135, v135), (136, v136), (137, v137),
]

print("causalontology-swift conformance run")
print("internal checks (RFC 8032 known-answer, RFC 8785 basics) ... ", terminator: "")
do {
    try internalChecks()
    print("ok")
} catch {
    print("FAILED :: \(error)")
    exit(1)
}

var failures = 0
for (n, run) in vectorFunctions {
    var displayName = String(format: "v%02d", n)
    if let fileName = try? vectorFileName(n) {
        // Strip the ".json" suffix for display, as the Python harness does.
        displayName = String(fileName.dropLast(".json".count))
    }
    do {
        try run()
        print("PASS  \(displayName)")
    } catch {
        failures += 1
        print("FAIL  \(displayName) :: \(error)")
    }
}

let total = vectorFunctions.count
print(String(repeating: "-", count: 60))
print("\(total - failures)/\(total) vectors passed")
if failures > 0 {
    exit(1)
}
print("causalontology-swift is CONFORMANT to the suite "
      + "(vectors frozen at specification 4.0.0).")

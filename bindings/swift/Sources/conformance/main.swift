// main.swift
//
// The Causalontology conformance runner for causalontology-swift.
//
// Runs every vector in conformance/vectors/ against the Swift binding. An
// implementation is conformant if and only if it passes every vector; this
// runner exits nonzero on any failure.
//
// Pre-freeze note (see conformance/README.md): the vectors carry symbolic
// identifiers ("occ:press_button", "ed25519:alice"). This harness normalizes
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

let symbolicSchemes = ["occ", "cro", "cnt", "rlz", "ast", "enr", "ret", "suc", "ed25519"]

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
    try semanticsFails(14, mustMention: "dmin")
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
    let dog = try sym("cnt:dog")
    let mammal = try sym("cnt:mammal")
    let animal = try sym("cnt:animal")
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
        "causes": .array([.string(try sym("occ:c"))]),
        "effects": .array([.string(try sym("occ:e"))]),
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
        "type": .string("cro"),
        "causes": .array([.string(try sym("occ:A"))]),
        "effects": .array([.string(try sym("occ:B"))]),
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
        "about": .string(try sym("cro:demo")),
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
        "type": .string("cro"),
        "causes": .array([.string(try sym("occ:A"))]),
        "effects": .array([.string(try sym("occ:B"))]),
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
    let claim = try sym("cro:claim")
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
    let occA = try sym("occ:A")
    let occB = try sym("occ:B")
    let occC = try sym("occ:C")
    let occD = try sym("occ:D")
    let m1Id = try sym("cro:m1")
    let m2Id = try sym("cro:m2")
    let m3Id = try sym("cro:m3")
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
    let occA = try sym("occ:A")
    let occB = try sym("occ:B")
    let parent = try s.put([
        "type": .string("cro"),
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
        "type": .string("cro"),
        "causes": .array([.string(occA)]),
        "effects": .array([.string(occB)]),
        "temporal": .object([
            "dmin": .int(0), "dmax": .int(1), "unit": .string("seconds"),
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

// MARK: - runner

let vectorFunctions: [(Int, () throws -> Void)] = [
    (1, v01), (2, v02), (3, v03), (4, v04), (5, v05), (6, v06), (7, v07),
    (8, v08), (9, v09), (10, v10), (11, v11), (12, v12), (13, v13), (14, v14),
    (15, v15), (16, v16), (17, v17), (18, v18), (19, v19), (20, v20),
    (21, v21), (22, v22), (23, v23), (24, v24), (25, v25), (26, v26),
    (27, v27), (28, v28), (29, v29), (30, v30), (31, v31), (32, v32),
    (33, v33), (34, v34), (35, v35), (36, v36), (37, v37), (38, v38),
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
      + "(vectors frozen at specification 1.0.0).")

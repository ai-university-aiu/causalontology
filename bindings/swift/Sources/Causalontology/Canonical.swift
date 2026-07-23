// Canonical.swift
//
// Canonicalization and content-addressed identity.
//
// Implements the identity procedure of spec/identity.md:
//   1. take the object as JSON,
//   2. keep only the identity-bearing fields for its kind (with "type" injected),
//   3. serialize with the JSON Canonicalization Scheme (RFC 8785),
//   4. hash with SHA-256,
//   5. identifier = scheme + ":" + lowercase hex digest.

import Foundation
import Crypto

/// The identity-bearing fields of each of the twenty-one kinds, exactly as in
/// the Python binding. 3.0.0 adds the cross_stratal_seam and the conduit's
/// realized_by; 4.0.0 adds the attitude, the predicted_occurrence, and the
/// prediction_error - all additive and identity-preserving: a record that omits
/// a new field keeps its earlier identifier byte-for-byte, and the new kinds
/// open new identity schemes that disturb no existing record. "type" is always
/// injected, so it is not listed here.
public let identityFields: [String: [String]] = [
    // ---- type tier ----
    "occurrent": ["label", "category", "stratum"],
    "causal_relation_object": ["causes", "effects", "mechanism", "temporal",
            "modality", "context", "refines", "skips"],
    "continuant": ["label", "category"],
    "realizable": ["kind", "bearer", "label"],
    "stratum": ["label", "scheme", "ordinal", "unit", "governs"],
    "bridge": ["coarse", "fine", "relation"],
    "cross_stratal_seam": ["source", "target", "mechanism_status", "chain"],
    "port": ["bearer", "label", "direction", "accepts", "realizable"],
    "conduit": ["label", "from", "to", "carries", "transform", "realized_by"],
    "quality": ["label", "datatype", "unit", "stratum"],
    // ---- token tier ----
    "token_individual": ["instantiates", "designator", "part_of"],
    "token_occurrence": ["instantiates", "interval", "participants",
            "locus", "observer"],
    "state_assertion": ["subject", "quality", "value", "interval"],
    "token_causal_claim": ["causes", "effects", "covering_law",
            "actual_delay", "counterfactual"],
    "attitude": ["holder", "attitude_type", "content"],
    "predicted_occurrence": ["instantiates", "interval", "predictor",
            "strength"],
    "prediction_error": ["predicted", "observed", "discrepancy"],
    // ---- provenance tier ----
    "assertion": ["about", "source", "evidence_type", "evidence", "strength",
                  "confidence", "timestamp", "evidenced_by"],
    "enrichment": ["about", "field", "entry", "source", "timestamp"],
    "retraction": ["retracts", "source", "timestamp"],
    "succession": ["predecessor", "successor", "timestamp"],
]

/// Whole-word re-mint (P7): the scheme IS the type value for every kind.
public let idPrefix: [String: String] = {
    var out: [String: String] = [:]
    for kind in identityFields.keys {
        out[kind] = kind
    }
    return out
}()

/// The kind per identifier scheme prefix (the inverse of idPrefix).
public let kindOfPrefix: [String: String] = {
    var out: [String: String] = [:]
    for kind in identityFields.keys {
        out[kind] = kind
    }
    return out
}()

/// Lowercase hex encoding of any bytes.
public func hexEncode<D: DataProtocol>(_ data: D) -> String {
    var out = ""
    for byte in data {
        out += String(format: "%02x", byte)
    }
    return out
}

/// Decode a hex string to bytes; nil when the string is not valid hex.
public func hexDecode(_ hex: String) -> Data? {
    let characters = Array(hex)
    guard characters.count % 2 == 0 else { return nil }
    var out = Data(capacity: characters.count / 2)
    var i = 0
    while i < characters.count {
        guard let high = characters[i].hexDigitValue,
              let low = characters[i + 1].hexDigitValue else {
            return nil
        }
        out.append(UInt8(high * 16 + low))
        i += 2
    }
    return out
}

/// The lowercase SHA-256 hex digest of any bytes.
public func sha256Hex<D: DataProtocol>(_ data: D) -> String {
    let digest = SHA256.hash(data: data)
    var out = ""
    for byte in digest {
        out += String(format: "%02x", byte)
    }
    return out
}

/// Infer an object's kind from its type field, id prefix, or shape.
public func inferKind(_ obj: [String: JsonValue]) throws -> String {
    if let typeName = obj["type"]?.stringValue {
        return typeName
    }
    if let identifier = obj["id"]?.stringValue, identifier.contains(":") {
        let prefix = String(identifier.split(separator: ":", maxSplits: 1)[0])
        if let kind = kindOfPrefix[prefix] {
            return kind
        }
    }
    if obj["coarse"] != nil && obj["fine"] != nil {
        return "bridge"
    }
    if obj["causes"] != nil && obj["effects"] != nil {
        return "causal_relation_object"
    }
    if obj["retracts"] != nil {
        return "retraction"
    }
    if obj["predecessor"] != nil && obj["successor"] != nil {
        return "succession"
    }
    if obj["field"] != nil && obj["entry"] != nil {
        return "enrichment"
    }
    if obj["evidence_type"] != nil || (obj["about"] != nil && obj["confidence"] != nil) {
        return "assertion"
    }
    if obj["kind"] != nil && obj["bearer"] != nil {
        return "realizable"
    }
    throw CausalontologyError(
        "cannot infer kind (occurrents and continuants share a shape); "
        + "pass kind explicitly")
}

/// The identity-bearing subset of an object, with type always present.
public func identityBearing(
    _ obj: [String: JsonValue],
    kind: String? = nil
) throws -> (kind: String, subset: [String: JsonValue]) {
    let resolvedKind: String
    if let kind = kind {
        resolvedKind = kind
    } else {
        resolvedKind = try inferKind(obj)
    }
    guard let fields = identityFields[resolvedKind] else {
        throw CausalontologyError("unknown kind: \(resolvedKind)")
    }
    var out: [String: JsonValue] = ["type": .string(resolvedKind)]
    for field in fields {
        if let value = obj[field] {
            out[field] = value
        }
    }
    return (resolvedKind, out)
}

/// The RFC 8785 identity-bearing bytes of an object.
public func canonicalize(_ obj: [String: JsonValue], kind: String? = nil) throws -> Data {
    let (_, subset) = try identityBearing(obj, kind: kind)
    return try jcsData(.object(subset))
}

/// The content-addressed identifier: scheme + ":" + SHA-256 hex.
public func identify(_ obj: [String: JsonValue], kind: String? = nil) throws -> String {
    let (resolvedKind, subset) = try identityBearing(obj, kind: kind)
    let digest = sha256Hex(try jcsData(.object(subset)))
    // Every kind in identityFields has a prefix, so the force-unwrap is safe;
    // spelled as a guard anyway for obviousness.
    guard let prefix = idPrefix[resolvedKind] else {
        throw CausalontologyError("unknown kind: \(resolvedKind)")
    }
    return prefix + ":" + digest
}

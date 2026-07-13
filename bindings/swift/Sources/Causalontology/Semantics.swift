// Semantics.swift
//
// The semantic rules beyond the schemas (spec/semantics.md).
//
// Local rules are checked here; store-context rules (materialized
// acyclicity, retraction lineage) live in Store.swift where the context
// exists. A faithful port of the Python binding's semantics.py.

import Foundation

/// Rule 4: the fixed unit-conversion constants (average Gregorian values).
public let unitSeconds: [String: Double] = [
    "instant": 0,
    "seconds": 1,
    "minutes": 60,
    "hours": 3600,
    "days": 86400,
    "weeks": 604800,
    "months": 2629746,
    "years": 31556952,
]

/// Rule 12: enrichment field-to-kind validity and entry shapes. The entry
/// shape is either the literal "alias" (a language-tagged text object) or
/// the scheme prefix a string entry must carry.
public let enrichmentFields: [String: (legalKinds: [String], entryShape: String)] = [
    "aliases": (["occurrent", "continuant"], "alias"),
    "participants": (["occurrent"], "cnt"),
    "subsumes": (["continuant"], "cnt"),
    "part_of": (["continuant"], "cnt"),
    "realized_in": (["realizable"], "occ"),
]

/// The optional Causal Relation Object fields, in canonical order.
public let croOptionalFields: [String] = ["mechanism", "temporal", "modality", "context"]

/// The kind named by an identifier's scheme prefix, or nil.
func kindOfIdentifier(_ identifier: String) -> String? {
    guard let colon = identifier.firstIndex(of: ":") else { return nil }
    let prefix = String(identifier[identifier.startIndex..<colon])
    return kindOfPrefix[prefix]
}

/// The set of strings inside a JSON array value (non-strings are ignored).
func stringSet(_ value: JsonValue?) -> Set<String> {
    var out: Set<String> = []
    for item in value?.arrayValue ?? [] {
        if let text = item.stringValue {
            out.insert(text)
        }
    }
    return out
}

/// (ok, reasons) - the locally checkable semantic rules.
public func validateSemantics(
    _ obj: [String: JsonValue],
    kind: String? = nil
) throws -> (ok: Bool, reasons: [String]) {
    let resolvedKind: String
    if let kind = kind {
        resolvedKind = kind
    } else {
        resolvedKind = try inferKind(obj)
    }
    var errors: [String] = []

    if resolvedKind == "cro" {
        if let temporal = obj["temporal"]?.objectValue,
           let dmin = temporal["dmin"]?.numberValue,
           let dmax = temporal["dmax"]?.numberValue,
           dmin > dmax {
            errors.append("dmin must be <= dmax")
        }
        if let identifier = obj["id"]?.stringValue {
            let mechanism = obj["mechanism"]?.arrayValue ?? []
            if mechanism.contains(.string(identifier)) {
                errors.append("mechanism must be acyclic "
                              + "(a Causal Relation Object may not contain itself)")
            }
            if obj["refines"]?.stringValue == identifier {
                errors.append("refines must be acyclic")
            }
        }
    }

    if resolvedKind == "enrichment" {
        let field = obj["field"]?.stringValue ?? ""
        let about = obj["about"]?.stringValue ?? ""
        if let spec = enrichmentFields[field] {
            if let aboutKind = kindOfIdentifier(about), !spec.legalKinds.contains(aboutKind) {
                errors.append("\(field) is not a legal field for a \(aboutKind) (rule 12)")
            }
            if spec.entryShape == "alias" {
                var isAliasObject = false
                if let entryObject = obj["entry"]?.objectValue {
                    isAliasObject = entryObject["lang"] != nil && entryObject["text"] != nil
                }
                if !isAliasObject {
                    errors.append("an aliases entry must be a language-tagged text object")
                }
            } else {
                var isReference = false
                if let entryText = obj["entry"]?.stringValue {
                    isReference = entryText.hasPrefix(spec.entryShape + ":")
                }
                if !isReference {
                    errors.append("a \(field) entry must be a \(spec.entryShape): identifier")
                }
            }
        }
    }

    return (errors.isEmpty, errors)
}

/// (partial, missing) - which optional CRO fields are unspecified, in the
/// canonical order [mechanism, temporal, modality, context].
public func isPartial(_ cro: [String: JsonValue]) -> (partial: Bool, missing: [String]) {
    var missing: [String] = []
    for field in croOptionalFields where cro[field] == nil {
        missing.append(field)
    }
    return (!missing.isEmpty, missing)
}

/// Rule 4: temporal admissibility with the fixed constants. A missing
/// window imposes no constraint.
public func admissible(_ cro: [String: JsonValue], elapsedSeconds: Double) -> Bool {
    guard let temporal = cro["temporal"]?.objectValue else {
        return true
    }
    guard let unitName = temporal["unit"]?.stringValue,
          let unit = unitSeconds[unitName],
          let dmin = temporal["dmin"]?.numberValue,
          let dmax = temporal["dmax"]?.numberValue else {
        return false
    }
    let lo = dmin * unit
    let hi = dmax * unit
    return lo <= elapsedSeconds && elapsedSeconds <= hi
}

/// True when the two temporal windows overlap; either window absent (or
/// malformed) counts as overlapping.
func windowOverlap(_ a: [String: JsonValue], _ b: [String: JsonValue]) -> Bool {
    guard let ta = a["temporal"]?.objectValue, let tb = b["temporal"]?.objectValue else {
        return true
    }
    guard let ua = unitSeconds[ta["unit"]?.stringValue ?? ""],
          let ub = unitSeconds[tb["unit"]?.stringValue ?? ""],
          let dminA = ta["dmin"]?.numberValue, let dmaxA = ta["dmax"]?.numberValue,
          let dminB = tb["dmin"]?.numberValue, let dmaxB = tb["dmax"]?.numberValue else {
        return true
    }
    let loA = dminA * ua
    let hiA = dmaxA * ua
    let loB = dminB * ub
    let hiB = dmaxB * ub
    return loA <= hiB && loB <= hiA
}

/// True when the two context sets are compatible: either absent or empty,
/// or one contains the other.
func contextsCompatible(_ a: [String: JsonValue], _ b: [String: JsonValue]) -> Bool {
    let ca = stringSet(a["context"])
    let cb = stringSet(b["context"])
    if ca.isEmpty || cb.isEmpty {
        return true
    }
    return ca == cb || ca.isSubset(of: cb) || cb.isSubset(of: ca)
}

/// The positive modalities, against which "preventive" conflicts.
let positiveModalities: Set<String> = ["necessary", "sufficient", "contributory"]

/// Rule 6: the formal conflict test.
public func conflicts(_ a: [String: JsonValue], _ b: [String: JsonValue]) -> Bool {
    if stringSet(a["causes"]) != stringSet(b["causes"]) {
        return false
    }
    if stringSet(a["effects"]) != stringSet(b["effects"]) {
        return false
    }
    if !contextsCompatible(a, b) {
        return false
    }
    if !windowOverlap(a, b) {
        return false
    }
    let modalityA = a["modality"]?.stringValue
    let modalityB = b["modality"]?.stringValue
    if modalityA == "preventive", let mb = modalityB, positiveModalities.contains(mb) {
        return true
    }
    if modalityB == "preventive", let ma = modalityA, positiveModalities.contains(ma) {
        return true
    }
    return false
}

/// Rule 3: (ok, reason) - is child a valid refinement of parent?
public func refinementValid(
    _ child: [String: JsonValue],
    _ parent: [String: JsonValue]
) -> (ok: Bool, reason: String) {
    if child["refines"] != parent["id"] {
        return (false, "child does not name the parent in refines")
    }
    if stringSet(child["causes"]) != stringSet(parent["causes"])
        || stringSet(child["effects"]) != stringSet(parent["effects"]) {
        return (false, "a refinement must keep the parent's causes and effects")
    }
    var added = 0
    for field in croOptionalFields {
        if let parentValue = parent[field] {
            if child[field] != parentValue {
                return (false, "a refinement may not change a field the "
                        + "parent specified; this is a rival claim")
            }
        } else if child[field] != nil {
            added += 1
        }
    }
    if added == 0 {
        return (false, "a refinement must add at least one unspecified field")
    }
    return (true, "valid refinement")
}

/// Rule 7: "consistent" | "inconsistent" | "indeterminate".
///
/// members: a mapping from CRO identifier to CRO object for the parent's
/// mechanism entries (the store's view of them).
public func hierarchyConsistent(
    _ parent: [String: JsonValue],
    _ members: [String: [String: JsonValue]]
) -> String {
    let mechanism = parent["mechanism"]?.arrayValue ?? []
    if mechanism.isEmpty {
        // Nothing claimed, nothing to check.
        return "consistent"
    }
    var edges: [String: Set<String>] = [:]
    for entry in mechanism {
        guard let memberId = entry.stringValue, let member = members[memberId] else {
            // A dangling_reference gap, not a failure.
            return "indeterminate"
        }
        let effects = stringSet(member["effects"])
        for cause in stringSet(member["causes"]) {
            edges[cause, default: []].formUnion(effects)
        }
    }

    func reachable(_ src: String, _ dst: String) -> Bool {
        var seen: Set<String> = []
        var stack: [String] = [src]
        while let node = stack.popLast() {
            if node == dst {
                return true
            }
            if seen.contains(node) {
                continue
            }
            seen.insert(node)
            for next in edges[node] ?? [] {
                stack.append(next)
            }
        }
        return false
    }

    for cause in stringSet(parent["causes"]) {
        for effect in stringSet(parent["effects"]) {
            if !reachable(cause, effect) {
                return "inconsistent"
            }
        }
    }
    return "consistent"
}

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

/// 3.0.0: the ordinal (dimensionless) temporal units. A tick is a discrete step
/// with NO wall-clock mapping; a tick window is ordered by integer comparison,
/// and an ordinal window and a wall-clock window are DIFFERENT DIMENSIONS that
/// do not compare (mixing them is never within-window and never overlapping).
public let ordinalUnits: Set<String> = ["ticks"]

/// "ordinal" for a tick-like unit, else "wallclock".
func dimensionOf(_ unit: String) -> String {
    return ordinalUnits.contains(unit) ? "ordinal" : "wallclock"
}

/// A comparable magnitude within ONE dimension: raw tick count for an ordinal
/// unit, seconds for a wall-clock unit. Never mix dimensions.
func magnitudeOf(_ value: Double, _ unit: String) -> Double {
    if ordinalUnits.contains(unit) {
        return value  // a dimensionless tick count
    }
    if unit == "instant" {
        return 0
    }
    return value * (unitSeconds[unit] ?? 0)
}

/// Rule 12: enrichment field-to-kind validity and entry shapes. The entry
/// shape is either the literal "alias" (a language-tagged text object) or
/// the scheme prefix a string entry must carry.
public let enrichmentFields: [String: (legalKinds: [String], entryShape: String)] = [
    "aliases": (["occurrent", "continuant"], "alias"),
    "participants": (["occurrent"], "continuant"),
    "subsumes": (["continuant"], "continuant"),
    "part_of": (["continuant"], "continuant"),
    "realized_in": (["realizable"], "occurrent"),
    "occurrent_subsumes": (["occurrent"], "occurrent"),
    "occurrent_part_of": (["occurrent"], "occurrent"),
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

    if resolvedKind == "causal_relation_object" {
        if let temporal = obj["temporal"]?.objectValue,
           let minimum_delay = temporal["minimum_delay"]?.numberValue,
           let maximum_delay = temporal["maximum_delay"]?.numberValue,
           minimum_delay > maximum_delay {
            errors.append("minimum_delay must be <= maximum_delay")
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
        // Rule 16, clause 1 (contradictory_skip): a HARD, locally-decidable
        // contradiction between skips:true and a non-empty mechanism.
        let mechanismPresent = !(obj["mechanism"]?.arrayValue?.isEmpty ?? true)
        if obj["skips"]?.boolValue == true && mechanismPresent {
            errors.append("contradictory_skip: skips is true but a mechanism "
                          + "is present")
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

    // 3.0.0 Rule 22, local clause: a Cross Stratal Seam that DRAWS a chain has,
    // by drawing it, a modelled intervening mechanism - so mechanism_status
    // 'absent' contradicts a present chain (the honest-ignorance distinction
    // must stay honest). The stratal well-formedness (non-adjacency, adjacency
    // of chain steps, scheme, the home rule) needs the strata map and lives in
    // seamWellformed, exactly as bridge well-formedness does.
    if resolvedKind == "cross_stratal_seam" {
        if let chain = obj["chain"], !chain.isNull,
           obj["mechanism_status"]?.stringValue == "absent" {
            errors.append("contradictory_seam: a drawn chain cannot carry "
                          + "mechanism_status 'absent' (a drawn mechanism is not absent)")
        }
    }

    // 4.0.0 Rule 24, local clause: a predicted_occurrence's interval carries
    // exactly ONE temporal dimension - a wall-clock start (optional end) or an
    // ordinal start_tick (optional end_tick), never both and never neither.
    // Per Rule 23 the two dimensions never compare. The pairing check of a
    // prediction_error against its predicted_occurrence and its observed
    // token_occurrence needs those objects and lives in
    // predictionPairingMismatch, exactly as coveringLawMismatch does.
    if resolvedKind == "predicted_occurrence" {
        let interval = obj["interval"]?.objectValue ?? [:]
        let wall = interval["start"] != nil
        let tick = interval["start_tick"] != nil
        if wall && tick {
            errors.append("dimension_conflict: a predicted interval must "
                          + "carry exactly one temporal dimension, not a "
                          + "wall-clock start AND an ordinal start_tick")
        }
        if !wall && !tick {
            errors.append("missing_dimension: a predicted interval must "
                          + "carry a wall-clock start or an ordinal start_tick")
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

/// Rule 4: temporal admissibility. For a wall-clock window `elapsedSeconds` is
/// in seconds; for an ordinal ('ticks') window it is a tick count. Ordering is
/// by magnitude WITHIN the window's own dimension (3.0.0). A missing window
/// imposes no constraint.
public func admissible(_ cro: [String: JsonValue], elapsedSeconds: Double) -> Bool {
    guard let temporal = cro["temporal"]?.objectValue else {
        return true
    }
    guard let unitName = temporal["unit"]?.stringValue,
          let minimum_delay = temporal["minimum_delay"]?.numberValue,
          let maximum_delay = temporal["maximum_delay"]?.numberValue else {
        return false
    }
    let lo = magnitudeOf(minimum_delay, unitName)
    let hi = magnitudeOf(maximum_delay, unitName)
    return lo <= elapsedSeconds && elapsedSeconds <= hi
}

/// True when the two temporal windows overlap; either window absent (or
/// malformed) counts as overlapping. 3.0.0: an ordinal window and a wall-clock
/// window are different dimensions and never overlap.
func windowOverlap(_ a: [String: JsonValue], _ b: [String: JsonValue]) -> Bool {
    guard let ta = a["temporal"]?.objectValue, let tb = b["temporal"]?.objectValue else {
        return true
    }
    guard let unitA = ta["unit"]?.stringValue, let unitB = tb["unit"]?.stringValue,
          let dminA = ta["minimum_delay"]?.numberValue, let dmaxA = ta["maximum_delay"]?.numberValue,
          let dminB = tb["minimum_delay"]?.numberValue, let dmaxB = tb["maximum_delay"]?.numberValue else {
        return true
    }
    if dimensionOf(unitA) != dimensionOf(unitB) {
        return false  // an ordinal window and a wall-clock window never overlap
    }
    let loA = magnitudeOf(dminA, unitA)
    let hiA = magnitudeOf(dmaxA, unitA)
    let loB = magnitudeOf(dminB, unitB)
    let hiB = magnitudeOf(dmaxB, unitB)
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

/// The positive modalities, against which "preventive" conflicts. Rule 6
/// (amended): necessary, sufficient, contributory, enabling are mutually
/// compatible; preventive opposes all four.
let positiveModalities: Set<String> = ["necessary", "sufficient", "contributory", "enabling"]

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

/// The ordered list of string members of a JSON array field.
func stringArray(_ value: JsonValue?) -> [String] {
    var out: [String] = []
    for item in value?.arrayValue ?? [] {
        if let text = item.stringValue {
            out.append(text)
        }
    }
    return out
}

// ===========================================================================
// 2.0.0 NORMATIVE ALGORITHMS (Section 12)
// ===========================================================================

/// ALGORITHM A (N12.1): every finer occurrent an occurrent resolves to,
/// following Bridges downward, transitively. Includes the starting
/// occurrent; the visited guard prevents an infinite loop on cyclic data.
public func bridgeClosure(_ occurrentId: String, _ bridges: [[String: JsonValue]]) -> Set<String> {
    var result: Set<String> = [occurrentId]
    var frontier: [String] = [occurrentId]
    var visited: Set<String> = []
    var coarseIndex: [String: [[String: JsonValue]]] = [:]
    for bridge in bridges {
        if let coarse = bridge["coarse"]?.stringValue {
            coarseIndex[coarse, default: []].append(bridge)
        }
    }
    while let current = frontier.popLast() {
        if visited.contains(current) {
            continue
        }
        visited.insert(current)
        for bridge in coarseIndex[current] ?? [] {
            for fine in stringArray(bridge["fine"]) {
                result.insert(fine)
                frontier.append(fine)
            }
        }
    }
    return result
}

/// Depth-first reachability over an adjacency map.
func pathExists(_ edges: [String: Set<String>], _ src: String, _ dst: String) -> Bool {
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

/// ALGORITHM B (amended Rule 7): "consistent" | "inconsistent" |
/// "indeterminate", ACROSS STRATA via bridged reachability.
///
/// members: a mapping from CRO identifier to CRO object for the parent's
/// mechanism entries. bridges: the store's bridges (empty -> 1.0.0 literal
/// reachability, the degenerate case).
public func hierarchyConsistent(
    _ parent: [String: JsonValue],
    _ members: [String: [String: JsonValue]],
    _ bridges: [[String: JsonValue]] = []
) -> String {
    let mechanism = parent["mechanism"]?.arrayValue ?? []
    if mechanism.isEmpty {
        return "consistent"  // nothing claimed, nothing to check
    }
    var edges: [String: Set<String>] = [:]
    for entry in mechanism {
        guard let memberId = entry.stringValue, let member = members[memberId] else {
            return "indeterminate"  // dangling; ignorance, not refutation
        }
        let effects = Set(stringArray(member["effects"]))
        for cause in stringArray(member["causes"]) {
            edges[cause, default: []].formUnion(effects)
        }
    }
    var bCause: [String: Set<String>] = [:]
    for cause in stringArray(parent["causes"]) {
        bCause[cause] = bridgeClosure(cause, bridges)
    }
    var bEffect: [String: Set<String>] = [:]
    for effect in stringArray(parent["effects"]) {
        bEffect[effect] = bridgeClosure(effect, bridges)
    }
    for cause in stringArray(parent["causes"]) {
        for effect in stringArray(parent["effects"]) {
            var connected = false
            outer: for cp in bCause[cause] ?? [] {
                for ep in bEffect[effect] ?? [] {
                    if pathExists(edges, cp, ep) {
                        connected = true
                        break outer
                    }
                }
            }
            if !connected {
                return "inconsistent"
            }
        }
    }
    return "consistent"
}

/// The stratum id of an occurrent by id, or nil.
private func stratumOf(_ occId: String, _ occMap: [String: [String: JsonValue]]) -> String? {
    return occMap[occId]?["stratum"]?.stringValue
}

/// ALGORITHM C (Rule 15): "intra_stratal" | "adjacent_stratal" | "skipping"
/// | "mixed" | "unclassifiable" | "scheme_mismatch". Derived, never asserted.
public func classifyCro(
    _ cro: [String: JsonValue],
    _ occMap: [String: [String: JsonValue]],
    _ stratumMap: [String: [String: JsonValue]]
) -> String {
    let causeStrata = stringArray(cro["causes"]).map { stratumOf($0, occMap) }
    let effectStrata = stringArray(cro["effects"]).map { stratumOf($0, occMap) }
    if (causeStrata + effectStrata).contains(where: { $0 == nil }) {
        return "unclassifiable"
    }
    let cStrata = causeStrata.compactMap { $0 }
    let eStrata = effectStrata.compactMap { $0 }
    let allStrata = Set(cStrata).union(eStrata)
    var schemes: Set<String> = []
    for s in allStrata {
        if let scheme = stratumMap[s]?["scheme"]?.stringValue {
            schemes.insert(scheme)
        }
    }
    if schemes.count > 1 {
        return "scheme_mismatch"  // HARD
    }
    let cOrd = cStrata.compactMap { stratumMap[$0]?["ordinal"]?.numberValue }
    let eOrd = eStrata.compactMap { stratumMap[$0]?["ordinal"]?.numberValue }
    if let cMax = cOrd.max(), let cMin = cOrd.min(),
       let eMax = eOrd.max(), let eMin = eOrd.min(),
       cMax == cMin && cMin == eMax && eMax == eMin {
        return "intra_stratal"
    }
    var gap = Double.infinity
    var span = -Double.infinity
    for i in cOrd {
        for j in eOrd {
            let d = abs(i - j)
            gap = Swift.min(gap, d)
            span = Swift.max(span, d)
        }
    }
    if span == 1 {
        return "adjacent_stratal"
    }
    if gap > 1 {
        return "skipping"
    }
    return "mixed"  // some pairs adjacent, some skipping
}

/// True iff causes or effects span more than one distinct stratum
/// (surfaces mixed_stratal_endpoints, an invitation).
public func endpointsMixed(
    _ cro: [String: JsonValue],
    _ occMap: [String: [String: JsonValue]]
) -> Bool {
    let cs = stringArray(cro["causes"]).map { stratumOf($0, occMap) }
    let es = stringArray(cro["effects"]).map { stratumOf($0, occMap) }
    if cs.contains(where: { $0 == nil }) || es.contains(where: { $0 == nil }) {
        return false
    }
    return Set(cs.compactMap { $0 }).count > 1 || Set(es.compactMap { $0 }).count > 1
}

/// ALGORITHM D (Rule 16): the gaps a Causal Relation Object surfaces for the
/// skip decision. The asymmetry (clause 3) is implemented exactly.
public func skipGaps(_ cro: [String: JsonValue], _ classification: String) -> [String] {
    var gaps: [String] = []
    let hasMech = !(cro["mechanism"]?.arrayValue?.isEmpty ?? true)
    let skipsTrue = (cro["skips"]?.boolValue == true)
    if skipsTrue && hasMech {
        gaps.append("contradictory_skip")  // HARD
        return gaps
    }
    if skipsTrue && classification != "skipping" && classification != "unclassifiable" {
        gaps.append("vacuous_skip")  // invitation
    }
    if classification == "skipping" && !hasMech {
        if skipsTrue {
            // NOTHING: absence is a finding.
        } else {
            gaps.append("incomplete_mechanism")  // invitation
        }
    }
    return gaps
}

/// ALGORITHM E helper: normalize a delay to seconds by the fixed table.
/// 3.0.0: an ordinal ('ticks') unit is dimensionless and has NO wall-clock
/// mapping - converting one to seconds is a category error and is refused.
public func toSeconds(_ duration: Double, _ unit: String) throws -> Double {
    if ordinalUnits.contains(unit) {
        throw CausalontologyError("'\(unit)' is an ordinal (dimensionless) unit "
                                  + "and has no wall-clock seconds mapping")
    }
    if unit == "instant" {
        return 0
    }
    return duration * (unitSeconds[unit] ?? 0)
}

/// ALGORITHM E (Rule 20): does an observed delay fall within a covering
/// law's temporal window? Inclusive at both ends. 3.0.0: an ordinal delay
/// compares to an ordinal window by integer tick count; an ordinal delay and a
/// wall-clock window (or vice versa) are different dimensions and never fall
/// within one another.
public func delayWithinWindow(
    _ actualDelay: [String: JsonValue]?,
    _ temporal: [String: JsonValue]?
) -> Bool {
    guard let actualDelay = actualDelay, !actualDelay.isEmpty,
          let temporal = temporal, !temporal.isEmpty else {
        return true  // nothing to check
    }
    let delayUnit = actualDelay["unit"]?.stringValue ?? ""
    let windowUnit = temporal["unit"]?.stringValue ?? ""
    if dimensionOf(delayUnit) != dimensionOf(windowUnit) {
        return false  // a tick delay is never within a wall-clock window
    }
    let observed = magnitudeOf(actualDelay["duration"]?.numberValue ?? 0, delayUnit)
    let lo = magnitudeOf(temporal["minimum_delay"]?.numberValue ?? 0, windowUnit)
    let hi = magnitudeOf(temporal["maximum_delay"]?.numberValue ?? 0, windowUnit)
    return lo <= observed && observed <= hi
}

/// Rule 14 / N3.2.1: Bridge well-formedness. All of (a)-(e) must hold, else
/// malformed_bridge.
public func bridgeWellformed(
    _ bridge: [String: JsonValue],
    _ occMap: [String: [String: JsonValue]],
    _ stratumMap: [String: [String: JsonValue]]
) -> (ok: Bool, reason: String) {
    guard let coarseId = bridge["coarse"]?.stringValue,
          let cs = occMap[coarseId]?["stratum"]?.stringValue else {
        return (false, "malformed_bridge: coarse has no stratum (a)")
    }
    let fineStrata = stringArray(bridge["fine"]).map { occMap[$0]?["stratum"]?.stringValue }
    if fineStrata.contains(where: { $0 == nil }) {
        return (false, "malformed_bridge: a fine member has no stratum (b)")
    }
    let concreteFine = fineStrata.compactMap { $0 }
    if Set(concreteFine).count != 1 {
        return (false, "malformed_bridge: fine members span >1 stratum (c)")
    }
    let fs = concreteFine[0]
    if stratumMap[cs]?["scheme"]?.stringValue != stratumMap[fs]?["scheme"]?.stringValue {
        return (false, "malformed_bridge: coarse and fine differ in scheme (d)")
    }
    let coarseOrd = stratumMap[cs]?["ordinal"]?.numberValue ?? 0
    let fineOrd = stratumMap[fs]?["ordinal"]?.numberValue ?? 0
    if !(coarseOrd > fineOrd) {
        return (false, "malformed_bridge: coarse ordinal not > fine ordinal (e)")
    }
    return (true, "well-formed bridge")
}

/// 3.0.0 Rule 22 / Algorithm F: Cross Stratal Seam well-formedness. All of
/// (a)-(g) must hold, else malformed_seam. A seam is a MANAGED jump across
/// NON-ADJACENT strata; when it DRAWS a chain, the chain must be an
/// adjacent-stratum path spanning the two endpoints' strata.
public func seamWellformed(
    _ seam: [String: JsonValue],
    _ occMap: [String: [String: JsonValue]],
    _ stratumMap: [String: [String: JsonValue]]
) -> (ok: Bool, reason: String) {
    guard let sourceId = seam["source"]?.stringValue,
          let srcS = occMap[sourceId]?["stratum"]?.stringValue,
          let targetId = seam["target"]?.stringValue,
          let tgtS = occMap[targetId]?["stratum"]?.stringValue,
          let srcStratum = stratumMap[srcS], let tgtStratum = stratumMap[tgtS] else {
        return (false, "malformed_seam: an endpoint has no stratum (a)")
    }
    if srcStratum["scheme"]?.stringValue != tgtStratum["scheme"]?.stringValue {
        return (false, "malformed_seam: endpoints differ in scheme (b)")
    }
    let so = srcStratum["ordinal"]?.numberValue ?? 0
    let to = tgtStratum["ordinal"]?.numberValue ?? 0
    if abs(so - to) <= 1 {
        return (false, "malformed_seam: endpoints are adjacent or co-stratal; "
                + "a seam is for NON-adjacent strata (c)")
    }
    if let chain = seam["chain"], !chain.isNull {
        if seam["mechanism_status"]?.stringValue == "absent" {
            return (false, "malformed_seam: a drawn chain contradicts "
                    + "mechanism_status 'absent' (d)")
        }
        let lo = Swift.min(so, to)
        let hi = Swift.max(so, to)
        var ords: [Double] = []
        for oid in stringArray(seam["chain"]) {
            guard let st = occMap[oid]?["stratum"]?.stringValue,
                  let stStratum = stratumMap[st] else {
                return (false, "malformed_seam: a chain member has no stratum (e)")
            }
            if stStratum["scheme"]?.stringValue != srcStratum["scheme"]?.stringValue {
                return (false, "malformed_seam: a chain member differs in scheme (e)")
            }
            ords.append(stStratum["ordinal"]?.numberValue ?? 0)
        }
        if !ords.allSatisfy({ lo < $0 && $0 < hi }) {
            return (false, "malformed_seam: a chain member is not at an "
                    + "INTERVENING stratum, strictly between the endpoints (f)")
        }
        if ords.count > 1 {
            var diffs: [Double] = []
            for i in 0..<(ords.count - 1) {
                diffs.append(ords[i + 1] - ords[i])
            }
            let allRising = diffs.allSatisfy { $0 > 0 }
            let allFalling = diffs.allSatisfy { $0 < 0 }
            if !(allRising || allFalling) {
                return (false, "malformed_seam: chain is not strictly monotone from "
                        + "one endpoint toward the other (g)")
            }
        }
    }
    return (true, "well-formed cross_stratal_seam")
}

/// THE HOME RULE (3.0.0): a Cross Stratal Seam belongs to the COARSEST stratum
/// it touches - the endpoint of the greater ordinal. Returns that stratum's
/// identifier (nil if an endpoint is unstratified). A layer-to-stratum binding
/// places and checks the seam by this rule.
public func seamHome(
    _ seam: [String: JsonValue],
    _ occMap: [String: [String: JsonValue]],
    _ stratumMap: [String: [String: JsonValue]]
) -> String? {
    guard let sourceId = seam["source"]?.stringValue,
          let srcS = occMap[sourceId]?["stratum"]?.stringValue,
          let targetId = seam["target"]?.stringValue,
          let tgtS = occMap[targetId]?["stratum"]?.stringValue else {
        return nil
    }
    let srcOrd = stratumMap[srcS]?["ordinal"]?.numberValue ?? 0
    let tgtOrd = stratumMap[tgtS]?["ordinal"]?.numberValue ?? 0
    return srcOrd >= tgtOrd ? srcS : tgtS
}

/// Rule 17 / N4.2.1-2: Conduit well-formedness, with the transform exception.
public func conduitWellformed(
    _ conduit: [String: JsonValue],
    _ portMap: [String: [String: JsonValue]],
    _ croMap: [String: [String: JsonValue]] = [:]
) -> (ok: Bool, reason: String) {
    guard let fromId = conduit["from"]?.stringValue, let frm = portMap[fromId],
          let toId = conduit["to"]?.stringValue, let to = portMap[toId] else {
        return (false, "malformed_conduit: dangling port reference")
    }
    let fromDir = frm["direction"]?.stringValue ?? ""
    if fromDir != "out" && fromDir != "bidirectional" {
        return (false, "malformed_conduit: from port is not out/bidirectional (a)")
    }
    let toDir = to["direction"]?.stringValue ?? ""
    if toDir != "in" && toDir != "bidirectional" {
        return (false, "malformed_conduit: to port is not in/bidirectional (b)")
    }
    let carries = stringArray(conduit["carries"])
    let fromAccepts = Set(stringArray(frm["accepts"]))
    if !carries.allSatisfy({ fromAccepts.contains($0) }) {
        return (false, "malformed_conduit: carries not accepted by from (c)")
    }
    let toAccepts = Set(stringArray(to["accepts"]))
    if let transform = conduit["transform"]?.stringValue {
        if let law = croMap[transform] {
            let lawEffects = stringArray(law["effects"])
            if !lawEffects.allSatisfy({ toAccepts.contains($0) }) {
                return (false, "malformed_conduit: transform effects not "
                        + "accepted by to (d, relaxed per N4.2.2)")
            }
        }
    } else {
        if !carries.allSatisfy({ toAccepts.contains($0) }) {
            return (false, "malformed_conduit: carries not accepted by to (d)")
        }
    }
    return (true, "well-formed conduit")
}

/// Rule 19 / N5.3.1-2: the HARD gaps a state assertion surfaces against its
/// quality: value_type_mismatch and/or unit_mismatch.
public func stateGaps(_ state: [String: JsonValue], _ quality: [String: JsonValue]) -> [String] {
    var gaps: [String] = []
    let dt = quality["datatype"]?.stringValue
    let v = state["value"]?.objectValue ?? [:]
    let shape: String?
    if v["quantity"] != nil {
        shape = "quantity"
    } else if v["categorical"] != nil {
        shape = "categorical"
    } else if v["boolean"] != nil {
        shape = "boolean"
    } else {
        shape = nil
    }
    if shape != dt {
        gaps.append("value_type_mismatch")
    } else if dt == "quantity" && v["unit"]?.stringValue != quality["unit"]?.stringValue {
        gaps.append("unit_mismatch")
    }
    return gaps
}

/// Rule 20: true iff the token claim's cause/effect tokens do not instantiate
/// the covering law's causes/effects (surfaces covering_law_mismatch).
public func coveringLawMismatch(
    _ tcc: [String: JsonValue],
    _ tokenMap: [String: [String: JsonValue]],
    _ law: [String: JsonValue]?
) -> Bool {
    guard let law = law, !law.isEmpty else {
        return false
    }
    let lawCauses = Set(stringArray(law["causes"]))
    let lawEffects = Set(stringArray(law["effects"]))
    for c in stringArray(tcc["causes"]) {
        if let inst = tokenMap[c]?["instantiates"]?.stringValue, !lawCauses.contains(inst) {
            return true
        }
    }
    for e in stringArray(tcc["effects"]) {
        if let inst = tokenMap[e]?["instantiates"]?.stringValue, !lawEffects.contains(inst) {
            return true
        }
    }
    return false
}

/// 4.0.0 Rule 24: prediction-to-observation pairing. True iff the prediction
/// error's observed token does not instantiate the occurrent its
/// predicted_occurrence instantiates (surfaces pairing_mismatch). An ABSENT
/// observed is never a mismatch - it means the predicted occurrence was not
/// fulfilled by any recorded occurrence.
public func predictionPairingMismatch(
    _ error: [String: JsonValue],
    _ predicted: [String: JsonValue],
    _ observed: [String: JsonValue]?
) -> Bool {
    guard let observedRef = error["observed"], !observedRef.isNull else {
        return false
    }
    guard let observed = observed else {
        return false
    }
    return observed["instantiates"]?.stringValue != predicted["instantiates"]?.stringValue
}

/// Rule 21: true iff any cause token starts after any effect token (HARD;
/// retrocausal_claim). RFC 3339 UTC 'Z' strings compare lexicographically.
public func retrocausal(
    _ tcc: [String: JsonValue],
    _ tokenMap: [String: [String: JsonValue]]
) -> Bool {
    for c in stringArray(tcc["causes"]) {
        guard let cstart = tokenMap[c]?["interval"]?["start"]?.stringValue else { continue }
        for e in stringArray(tcc["effects"]) {
            guard let estart = tokenMap[e]?["interval"]?["start"]?.stringValue else { continue }
            if cstart > estart {
                return true
            }
        }
    }
    return false
}

/// Rules 4 / 6.1: true iff a directed graph (node -> successors) has a cycle.
/// Used for the bridge graph, occurrent_subsumes, occurrent_part_of, and
/// token mereology.
public func hasCycle(_ edges: [String: [String]]) -> Bool {
    // 0 = white (unvisited), 1 = grey (on path), 2 = black (finished).
    var state: [String: Int] = [:]

    func visit(_ node: String) -> Bool {
        state[node] = 1
        for next in edges[node] ?? [] {
            let s = state[next] ?? 0
            if s == 1 {
                return true
            }
            if s == 0 && visit(next) {
                return true
            }
        }
        state[node] = 2
        return false
    }

    for node in edges.keys {
        if (state[node] ?? 0) == 0 && visit(node) {
            return true
        }
    }
    return false
}

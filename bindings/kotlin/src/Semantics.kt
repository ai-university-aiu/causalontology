// The semantic rules beyond the schemas (spec/semantics.md).
//
// Local rules are checked here; store-context rules (materialized acyclicity,
// retraction lineage) live in Store.kt where the context exists. A faithful
// port of the Python binding's semantics.py.
package org.causalontology

object Semantics {

    // Rule 4: the fixed unit-conversion constants (average Gregorian values).
    val UNIT_SECONDS: Map<String, Long> = mapOf(
        "instant" to 0L,
        "seconds" to 1L,
        "minutes" to 60L,
        "hours" to 3600L,
        "days" to 86400L,
        "weeks" to 604800L,
        "months" to 2629746L,
        "years" to 31556952L
    )

    // Rule 12: enrichment field-to-kind validity and entry shapes. Two
    // occurrent forms added in 2.0.0.
    val ENRICHMENT_FIELDS: Map<String, Pair<List<String>, String>> = mapOf(
        "aliases" to Pair(listOf("occurrent", "continuant"), "alias"),
        "participants" to Pair(listOf("occurrent"), "continuant"),
        "subsumes" to Pair(listOf("continuant"), "continuant"),
        "part_of" to Pair(listOf("continuant"), "continuant"),
        "realized_in" to Pair(listOf("realizable"), "occurrent"),
        "occurrent_subsumes" to Pair(listOf("occurrent"), "occurrent"),
        "occurrent_part_of" to Pair(listOf("occurrent"), "occurrent")
    )

    val CRO_OPTIONAL_FIELDS = listOf("mechanism", "temporal", "modality", "context")

    private fun kindOfId(identifier: String): String? =
        Canonical.KIND_OF_PREFIX[identifier.substringBefore(":")]

    // (ok, reasons) - the locally checkable semantic rules.
    fun validateSemantics(obj: JObj, kind: String? = null): Pair<Boolean, List<String>> {
        val k = kind ?: Canonical.inferKind(obj)
        val errors = mutableListOf<String>()

        if (k == "causal_relation_object") {
            val t = obj["temporal"]
            if (t is Map<*, *> && t["minimum_delay"] != null && t["maximum_delay"] != null &&
                asDoubleNum(t["minimum_delay"]) > asDoubleNum(t["maximum_delay"])) {
                errors.add("minimum_delay must be <= maximum_delay")
            }
            val oid = obj["id"] as? String
            val mechanism = obj["mechanism"] as? List<*> ?: emptyList<Any?>()
            if (oid != null && oid != "" && mechanism.contains(oid)) {
                errors.add("mechanism must be acyclic " +
                           "(a Causal Relation Object may not contain itself)")
            }
            if (oid != null && oid != "" && obj["refines"] == oid) {
                errors.add("refines must be acyclic")
            }
            // Rule 16, clause 1 (contradictory_skip): a HARD, locally-decidable
            // contradiction between skips:true and a non-empty mechanism.
            if (obj["skips"] == true && mechanism.isNotEmpty()) {
                errors.add("contradictory_skip: skips is true but a mechanism " +
                           "is present")
            }
        }

        if (k == "enrichment") {
            val field = obj["field"] as? String
            val about = obj["about"] as? String ?: ""
            val entry = obj["entry"]
            val spec = ENRICHMENT_FIELDS[field]
            if (spec != null) {
                val (legalKinds, shape) = spec
                val aboutKind = kindOfId(about)
                if (aboutKind != null && aboutKind !in legalKinds) {
                    errors.add("$field is not a legal field for a $aboutKind (rule 12)")
                }
                if (shape == "alias") {
                    if (!(entry is Map<*, *> && entry.containsKey("lang") && entry.containsKey("text"))) {
                        errors.add("an aliases entry must be a language-tagged text object")
                    }
                } else {
                    if (!(entry is String && entry.startsWith("$shape:"))) {
                        errors.add("a $field entry must be a $shape: identifier")
                    }
                }
            }
        }

        return Pair(errors.isEmpty(), errors)
    }

    // (partial, missing) - which optional CRO fields are unspecified.
    fun isPartial(cro: JObj): Pair<Boolean, List<String>> {
        val missing = CRO_OPTIONAL_FIELDS.filter { !cro.containsKey(it) }
        return Pair(missing.isNotEmpty(), missing)
    }

    // Rule 4: temporal admissibility with the fixed constants.
    fun admissible(cro: JObj, elapsedSeconds: Double): Boolean {
        val t = cro["temporal"] ?: return true  // no window imposes no constraint
        val tm = asObj(t)
        val unit = UNIT_SECONDS[tm["unit"] as String]!!.toDouble()
        val lo = asDoubleNum(tm["minimum_delay"]) * unit
        val hi = asDoubleNum(tm["maximum_delay"]) * unit
        return lo <= elapsedSeconds && elapsedSeconds <= hi
    }

    private fun windowOverlap(a: JObj, b: JObj): Boolean {
        val ta = a["temporal"] ?: return true
        val tb = b["temporal"] ?: return true  // either absent counts as overlapping
        val ma = asObj(ta); val mb = asObj(tb)
        val ua = UNIT_SECONDS[ma["unit"] as String]!!.toDouble()
        val ub = UNIT_SECONDS[mb["unit"] as String]!!.toDouble()
        val loA = asDoubleNum(ma["minimum_delay"]) * ua; val hiA = asDoubleNum(ma["maximum_delay"]) * ua
        val loB = asDoubleNum(mb["minimum_delay"]) * ub; val hiB = asDoubleNum(mb["maximum_delay"]) * ub
        return loA <= hiB && loB <= hiA
    }

    private fun contextsCompatible(a: JObj, b: JObj): Boolean {
        val ca = a["context"] as? List<*>
        val cb = b["context"] as? List<*>
        if (ca == null || ca.isEmpty() || cb == null || cb.isEmpty()) return true
        val sa = ca.toSet(); val sb = cb.toSet()
        return sa == sb || sb.containsAll(sa) || sa.containsAll(sb)
    }

    // Rule 6 (amended): necessary, sufficient, contributory, enabling are
    // mutually compatible; preventive opposes all four.
    private val POSITIVE = setOf("necessary", "sufficient", "contributory", "enabling")

    // Rule 6: the formal conflict test.
    fun conflicts(a: JObj, b: JObj): Boolean {
        if (asList(a["causes"]).toSet() != asList(b["causes"]).toSet()) return false
        if (asList(a["effects"]).toSet() != asList(b["effects"]).toSet()) return false
        if (!contextsCompatible(a, b)) return false
        if (!windowOverlap(a, b)) return false
        val ma = a["modality"]; val mb = b["modality"]
        return (ma == "preventive" && mb in POSITIVE) ||
               (mb == "preventive" && ma in POSITIVE)
    }

    // Rule 3: (ok, reason) - is child a valid refinement of parent?
    fun refinementValid(child: JObj, parent: JObj): Pair<Boolean, String> {
        if (child["refines"] != parent["id"]) {
            return Pair(false, "child does not name the parent in refines")
        }
        if (asList(child["causes"]).toSet() != asList(parent["causes"]).toSet() ||
            asList(child["effects"]).toSet() != asList(parent["effects"]).toSet()) {
            return Pair(false, "a refinement must keep the parent's causes and effects")
        }
        var added = 0
        for (field in CRO_OPTIONAL_FIELDS) {
            if (parent.containsKey(field)) {
                if (!deepEq(child[field], parent[field])) {
                    return Pair(false, "a refinement may not change a field the " +
                                       "parent specified; this is a rival claim")
                }
            } else if (child.containsKey(field)) {
                added++
            }
        }
        if (added == 0) {
            return Pair(false, "a refinement must add at least one unspecified field")
        }
        return Pair(true, "valid refinement")
    }

    // =======================================================================
    // 2.0.0 NORMATIVE ALGORITHMS (Section 12)
    // =======================================================================

    // ALGORITHM A. Every finer occurrent an occurrent resolves to, following
    // Bridges downward, transitively. Includes the starting occurrent
    // (N12.1.1). The visited guard (N12.1.2) prevents an infinite loop on
    // malformed cyclic data.
    fun bridgeClosure(occurrentId: String, bridges: List<JObj>): Set<String> {
        val result = mutableSetOf(occurrentId)
        val frontier = ArrayDeque<String>()
        frontier.addLast(occurrentId)
        val visited = mutableSetOf<String>()
        val coarseIndex = LinkedHashMap<String, MutableList<JObj>>()
        for (b in bridges) {
            coarseIndex.getOrPut(b["coarse"] as String) { mutableListOf() }.add(b)
        }
        while (frontier.isNotEmpty()) {
            val current = frontier.removeLast()
            if (current in visited) continue
            visited.add(current)
            for (b in coarseIndex[current] ?: emptyList()) {
                for (f in asList(b["fine"])) {
                    result.add(f as String)
                    frontier.addLast(f)
                }
            }
        }
        return result
    }

    private fun pathExists(edges: Map<String, Set<String>>, src: String, dst: String): Boolean {
        val seen = mutableSetOf<String>()
        val stack = ArrayDeque<String>()
        stack.addLast(src)
        while (stack.isNotEmpty()) {
            val node = stack.removeLast()
            if (node == dst) return true
            if (node in seen) continue
            seen.add(node)
            edges[node]?.let { stack.addAll(it) }
        }
        return false
    }

    // ALGORITHM B (amended Rule 7): "consistent" | "inconsistent" |
    // "indeterminate", ACROSS STRATA via bridged reachability. members maps
    // each mechanism CRO identifier to its object; bridges empty -> 1.0.0
    // literal reachability (the degenerate case, N12.2.3).
    fun hierarchyConsistent(parent: JObj, members: Map<String, JObj>,
                            bridges: List<JObj> = emptyList()): String {
        val mechanism = parent["mechanism"] as? List<*> ?: emptyList<Any?>()
        if (mechanism.isEmpty()) return "consistent"  // nothing claimed (N12.2.1)
        val edges = LinkedHashMap<String, MutableSet<String>>()
        for (mid in mechanism) {
            val m = members[mid] ?: return "indeterminate"  // dangling; ignorance
            for (c in asList(m["causes"])) {
                val bucket = edges.getOrPut(c as String) { mutableSetOf() }
                for (e in asList(m["effects"])) bucket.add(e as String)
            }
        }
        val bCause = asList(parent["causes"]).associate {
            (it as String) to bridgeClosure(it, bridges) }
        val bEffect = asList(parent["effects"]).associate {
            (it as String) to bridgeClosure(it, bridges) }
        for (c in asList(parent["causes"])) {
            for (e in asList(parent["effects"])) {
                val connected = bCause[c]!!.any { cp ->
                    bEffect[e]!!.any { ep -> pathExists(edges, cp, ep) } }
                if (!connected) return "inconsistent"
            }
        }
        return "consistent"
    }

    private fun stratumOf(occId: String, occMap: Map<String, JObj>): String? =
        (occMap[occId]?.get("stratum")) as? String

    private fun ordOf(sid: String, stratumMap: Map<String, JObj>): Long =
        (stratumMap[sid]!!["ordinal"] as Number).toLong()

    // ALGORITHM C (Rule 15): "intra_stratal" | "adjacent_stratal" | "skipping"
    // | "mixed" | "unclassifiable" | "scheme_mismatch". Derived, never asserted.
    fun classifyCro(cro: JObj, occMap: Map<String, JObj>,
                    stratumMap: Map<String, JObj>): String {
        val causeStrata = asList(cro["causes"]).map { stratumOf(it as String, occMap) }
        val effectStrata = asList(cro["effects"]).map { stratumOf(it as String, occMap) }
        if ((causeStrata + effectStrata).any { it == null }) return "unclassifiable"
        val allStrata = (causeStrata + effectStrata).filterNotNull().toSet()
        val schemes = allStrata.map { stratumMap[it]!!["scheme"] as String }.toSet()
        if (schemes.size > 1) return "scheme_mismatch"  // HARD
        val cOrd = causeStrata.map { ordOf(it!!, stratumMap) }
        val eOrd = effectStrata.map { ordOf(it!!, stratumMap) }
        if (cOrd.max() == cOrd.min() && cOrd.min() == eOrd.max() && eOrd.max() == eOrd.min()) {
            return "intra_stratal"
        }
        var gap = Long.MAX_VALUE
        var span = Long.MIN_VALUE
        for (i in cOrd) for (j in eOrd) {
            val d = kotlin.math.abs(i - j)
            if (d < gap) gap = d
            if (d > span) span = d
        }
        if (span == 1L) return "adjacent_stratal"
        if (gap > 1L) return "skipping"
        return "mixed"  // some pairs adjacent, some skipping
    }

    // True iff causes or effects span more than one distinct stratum
    // (surfaces mixed_stratal_endpoints, an invitation; N12.3.2).
    fun endpointsMixed(cro: JObj, occMap: Map<String, JObj>): Boolean {
        val cs = asList(cro["causes"]).map { stratumOf(it as String, occMap) }.toSet()
        val es = asList(cro["effects"]).map { stratumOf(it as String, occMap) }.toSet()
        if (null in cs || null in es) return false
        return cs.size > 1 || es.size > 1
    }

    // ALGORITHM D (Rule 16): the gaps a CRO surfaces for the skip decision.
    // THE ASYMMETRY (clause 3) is the whole point of the field.
    fun skipGaps(cro: JObj, classification: String): List<String> {
        val gaps = mutableListOf<String>()
        val hasMech = (cro["mechanism"] as? List<*>)?.isNotEmpty() == true
        if (cro["skips"] == true && hasMech) {
            gaps.add("contradictory_skip")        // HARD
            return gaps
        }
        if (cro["skips"] == true &&
            classification != "skipping" && classification != "unclassifiable") {
            gaps.add("vacuous_skip")              // invitation
        }
        if (classification == "skipping" && !hasMech) {
            if (cro["skips"] == true) {
                // NOTHING: absence is a finding
            } else {
                gaps.add("incomplete_mechanism")  // invitation
            }
        }
        return gaps
    }

    // ALGORITHM E helper: normalize a delay to seconds by the fixed table.
    fun toSeconds(duration: Number, unit: String): Long {
        if (unit == "instant") return 0
        return duration.toLong() * UNIT_SECONDS[unit]!!
    }

    // ALGORITHM E (Rule 20): does an observed delay fall within a covering
    // law's temporal window? Inclusive at both ends (N12.5.2).
    fun delayWithinWindow(actualDelay: JObj?, temporal: JObj?): Boolean {
        if (actualDelay == null || actualDelay.isEmpty() ||
            temporal == null || temporal.isEmpty()) return true
        val observed = toSeconds(actualDelay["duration"] as Number, actualDelay["unit"] as String)
        val lo = toSeconds(temporal["minimum_delay"] as Number, temporal["unit"] as String)
        val hi = toSeconds(temporal["maximum_delay"] as Number, temporal["unit"] as String)
        return lo <= observed && observed <= hi
    }

    // Rule 14 / N3.2.1: Bridge well-formedness. All of (a)-(e) must hold.
    fun bridgeWellformed(bridge: JObj, occMap: Map<String, JObj>,
                         stratumMap: Map<String, JObj>): Pair<Boolean, String> {
        val cs = stratumOf(bridge["coarse"] as String, occMap)
            ?: return Pair(false, "malformed_bridge: coarse has no stratum (a)")
        val fineStrata = asList(bridge["fine"]).map { stratumOf(it as String, occMap) }
        if (fineStrata.any { it == null }) {
            return Pair(false, "malformed_bridge: a fine member has no stratum (b)")
        }
        if (fineStrata.toSet().size != 1) {
            return Pair(false, "malformed_bridge: fine members span >1 stratum (c)")
        }
        val fs = fineStrata[0]!!
        if (stratumMap[cs]!!["scheme"] != stratumMap[fs]!!["scheme"]) {
            return Pair(false, "malformed_bridge: coarse and fine differ in scheme (d)")
        }
        if (!(ordOf(cs, stratumMap) > ordOf(fs, stratumMap))) {
            return Pair(false, "malformed_bridge: coarse ordinal not > fine ordinal (e)")
        }
        return Pair(true, "well-formed bridge")
    }

    // Rule 17 / N4.2.1-2: Conduit well-formedness with the transform exception.
    fun conduitWellformed(conduit: JObj, portMap: Map<String, JObj>,
                          croMap: Map<String, JObj>? = null): Pair<Boolean, String> {
        val frm = portMap[conduit["from"]]
        val to = portMap[conduit["to"]]
        if (frm == null || to == null) {
            return Pair(false, "malformed_conduit: dangling port reference")
        }
        if ((frm["direction"] as String) !in setOf("out", "bidirectional")) {
            return Pair(false, "malformed_conduit: from port is not out/bidirectional (a)")
        }
        if ((to["direction"] as String) !in setOf("in", "bidirectional")) {
            return Pair(false, "malformed_conduit: to port is not in/bidirectional (b)")
        }
        val carries = asList(conduit["carries"])
        val fromAccepts = asList(frm["accepts"]).toSet()
        if (!carries.all { it in fromAccepts }) {
            return Pair(false, "malformed_conduit: carries not accepted by from (c)")
        }
        val transform = conduit["transform"] as? String
        val toAccepts = asList(to["accepts"]).toSet()
        if (transform == null) {
            if (!carries.all { it in toAccepts }) {
                return Pair(false, "malformed_conduit: carries not accepted by to (d)")
            }
        } else {
            val law = croMap?.get(transform)
            if (law != null) {
                if (!asList(law["effects"]).all { it in toAccepts }) {
                    return Pair(false, "malformed_conduit: transform effects not " +
                        "accepted by to (d, relaxed per N4.2.2)")
                }
            }
        }
        return Pair(true, "well-formed conduit")
    }

    // Rule 19 / N5.3.1-2: state value type and unit coherence. The HARD gaps:
    // value_type_mismatch and/or unit_mismatch.
    fun stateGaps(state: JObj, quality: JObj): List<String> {
        val gaps = mutableListOf<String>()
        val dt = quality["datatype"] as? String
        val v = (state["value"] as? Map<*, *>) ?: emptyMap<String, Any?>()
        val shape = when {
            v.containsKey("quantity") -> "quantity"
            v.containsKey("categorical") -> "categorical"
            v.containsKey("boolean") -> "boolean"
            else -> null
        }
        if (shape != dt) {
            gaps.add("value_type_mismatch")
        } else if (dt == "quantity" && v["unit"] != quality["unit"]) {
            gaps.add("unit_mismatch")
        }
        return gaps
    }

    // Rule 20: covering-law coherence.
    fun coveringLawMismatch(tcc: JObj, tokenMap: Map<String, JObj>, law: JObj?): Boolean {
        if (law == null) return false
        val lawCauses = asList(law["causes"]).toSet()
        val lawEffects = asList(law["effects"]).toSet()
        for (c in asList(tcc["causes"])) {
            if (tokenMap[c]!!["instantiates"] !in lawCauses) return true
        }
        for (e in asList(tcc["effects"])) {
            if (tokenMap[e]!!["instantiates"] !in lawEffects) return true
        }
        return false
    }

    // Rule 21: temporal coherence of token causation. True iff any cause token
    // starts after any effect token (HARD; retrocausal_claim). RFC 3339 UTC 'Z'
    // strings compare lexicographically.
    fun retrocausal(tcc: JObj, tokenMap: Map<String, JObj>): Boolean {
        for (c in asList(tcc["causes"])) {
            val cstart = asObj(tokenMap[c]!!["interval"])["start"] as String
            for (e in asList(tcc["effects"])) {
                val estart = asObj(tokenMap[e]!!["interval"])["start"] as String
                if (cstart > estart) return true
            }
        }
        return false
    }

    // Rules 4 / 6.1: generic acyclicity for the new graph relations.
    fun hasCycle(edges: Map<String, List<String>>): Boolean {
        val WHITE = 0; val GREY = 1; val BLACK = 2
        val state = HashMap<String, Int>()

        fun visit(node: String): Boolean {
            state[node] = GREY
            for (nxt in edges[node] ?: emptyList()) {
                val s = state.getOrElse(nxt) { WHITE }
                if (s == GREY) return true
                if (s == WHITE && visit(nxt)) return true
            }
            state[node] = BLACK
            return false
        }

        return edges.keys.toList().any { state.getOrElse(it) { WHITE } == WHITE && visit(it) }
    }
}

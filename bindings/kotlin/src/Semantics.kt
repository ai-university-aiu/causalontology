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

    // Rule 12: enrichment field-to-kind validity and entry shapes.
    val ENRICHMENT_FIELDS: Map<String, Pair<List<String>, String>> = mapOf(
        "aliases" to Pair(listOf("occurrent", "continuant"), "alias"),
        "participants" to Pair(listOf("occurrent"), "continuant"),
        "subsumes" to Pair(listOf("continuant"), "continuant"),
        "part_of" to Pair(listOf("continuant"), "continuant"),
        "realized_in" to Pair(listOf("realizable"), "occurrent")
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

    private val POSITIVE = setOf("necessary", "sufficient", "contributory")

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

    // Rule 7: "consistent" | "inconsistent" | "indeterminate".
    // members maps each mechanism CRO identifier to the store's view of it.
    fun hierarchyConsistent(parent: JObj, members: Map<String, JObj>): String {
        val mechanism = parent["mechanism"] as? List<*> ?: emptyList<Any?>()
        if (mechanism.isEmpty()) return "consistent"  // nothing claimed, nothing to check
        val edges = LinkedHashMap<String, MutableSet<String>>()
        for (mid in mechanism) {
            val m = members[mid] ?: return "indeterminate"  // a dangling_reference gap
            for (c in asList(m["causes"])) {
                val bucket = edges.getOrPut(c as String) { mutableSetOf() }
                for (e in asList(m["effects"])) bucket.add(e as String)
            }
        }

        fun reachable(src: String, dst: String): Boolean {
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

        for (c in asList(parent["causes"])) {
            for (e in asList(parent["effects"])) {
                if (!reachable(c as String, e as String)) return "inconsistent"
            }
        }
        return "consistent"
    }
}

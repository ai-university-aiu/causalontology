// Canonicalization and content-addressed identity (spec/identity.md):
//   1. take the object as parsed JSON,
//   2. keep only the identity-bearing fields for its kind (with "type" injected),
//   3. serialize with the JSON Canonicalization Scheme (RFC 8785),
//   4. hash with SHA-256,
//   5. identifier = scheme + ":" + lowercase hex digest.
package org.causalontology

// The JSON object shape used throughout the binding.
typealias JObj = Map<String, Any?>

@Suppress("UNCHECKED_CAST")
fun asObj(v: Any?): JObj = v as JObj

@Suppress("UNCHECKED_CAST")
fun asList(v: Any?): List<Any?> = v as List<Any?>

fun asDoubleNum(v: Any?): Double = when (v) {
    is Long -> v.toDouble()
    is Int -> v.toDouble()
    is Double -> v
    else -> throw IllegalArgumentException("expected a number, got $v")
}

// Deep equality over the JSON value model, numerically tolerant the way
// Python is (1 == 1.0).
fun deepEq(a: Any?, b: Any?): Boolean = when {
    a is Long && b is Long -> a == b
    (a is Long || a is Double) && (b is Long || b is Double) ->
        asDoubleNum(a) == asDoubleNum(b)
    a is List<*> && b is List<*> ->
        a.size == b.size && a.indices.all { deepEq(a[it], b[it]) }
    a is Map<*, *> && b is Map<*, *> ->
        a.keys == b.keys && a.keys.all { deepEq(a[it], b[it]) }
    else -> a == b
}

object Canonical {

    // The identity-bearing fields of each of the seventeen kinds. "type" is
    // always injected, so it is not listed here. Order does not matter
    // (JCS sorts keys). Mirrors canonical.py's IDENTITY_FIELDS exactly.
    val IDENTITY_FIELDS: Map<String, List<String>> = mapOf(
        // ---- type tier ----
        "occurrent" to listOf("label", "category", "stratum"),
        "causal_relation_object" to listOf("causes", "effects", "mechanism", "temporal",
                        "modality", "context", "refines", "skips"),
        "continuant" to listOf("label", "category"),
        "realizable" to listOf("kind", "bearer", "label"),
        "stratum" to listOf("label", "scheme", "ordinal", "unit", "governs"),
        "bridge" to listOf("coarse", "fine", "relation"),
        "port" to listOf("bearer", "label", "direction", "accepts", "realizable"),
        "conduit" to listOf("label", "from", "to", "carries", "transform"),
        "quality" to listOf("label", "datatype", "unit", "stratum"),
        // ---- token tier ----
        "token_individual" to listOf("instantiates", "designator", "part_of"),
        "token_occurrence" to listOf("instantiates", "interval", "participants",
                        "locus", "observer"),
        "state_assertion" to listOf("subject", "quality", "value", "interval"),
        "token_causal_claim" to listOf("causes", "effects", "covering_law",
                        "actual_delay", "counterfactual"),
        // ---- provenance tier ----
        "assertion" to listOf("about", "source", "evidence_type", "evidence", "strength",
                              "confidence", "timestamp", "evidenced_by"),
        "enrichment" to listOf("about", "field", "entry", "source", "timestamp"),
        "retraction" to listOf("retracts", "source", "timestamp"),
        "succession" to listOf("predecessor", "successor", "timestamp")
    )

    // Whole-word re-mint (P7): the scheme IS the type value for every kind.
    val PREFIX: Map<String, String> = IDENTITY_FIELDS.keys.associateWith { it }

    val KIND_OF_PREFIX: Map<String, String> = PREFIX.entries.associate { it.value to it.key }

    // Infer an object's kind from its type field, id prefix, or shape
    // (the exact decision order of canonical.py's infer_kind).
    fun inferKind(obj: JObj): String {
        val t = obj["type"]
        if (obj.containsKey("type")) return t as String
        val id = obj["id"]
        if (id is String && id.contains(":")) {
            val pre = id.substringBefore(":")
            KIND_OF_PREFIX[pre]?.let { return it }
        }
        if (obj.containsKey("coarse") && obj.containsKey("fine")) return "bridge"
        if (obj.containsKey("causes") && obj.containsKey("effects")) return "causal_relation_object"
        if (obj.containsKey("retracts")) return "retraction"
        if (obj.containsKey("predecessor") && obj.containsKey("successor")) return "succession"
        if (obj.containsKey("field") && obj.containsKey("entry")) return "enrichment"
        if (obj.containsKey("evidence_type") ||
            (obj.containsKey("about") && obj.containsKey("confidence"))) return "assertion"
        if (obj.containsKey("kind") && obj.containsKey("bearer")) return "realizable"
        throw IllegalArgumentException(
            "cannot infer kind (occurrents and continuants share a shape); pass kind explicitly")
    }

    // The identity-bearing subset of an object, with type always present.
    fun identityBearing(obj: JObj, kind: String? = null): Pair<String, JObj> {
        val k = kind ?: inferKind(obj)
        val fields = IDENTITY_FIELDS[k]
            ?: throw IllegalArgumentException("unknown kind: $k")
        val out = LinkedHashMap<String, Any?>()
        out["type"] = k
        for (field in fields) {
            if (obj.containsKey(field)) out[field] = obj[field]
        }
        return Pair(k, out)
    }

    // The RFC 8785 identity-bearing bytes of an object.
    fun canonicalize(obj: JObj, kind: String? = null): ByteArray {
        val (_, ib) = identityBearing(obj, kind)
        return Jcs.serialize(ib).encodeToByteArray()
    }

    // The content-addressed identifier: scheme + ":" + SHA-256 hex.
    fun identify(obj: JObj, kind: String? = null): String {
        val (k, ib) = identityBearing(obj, kind)
        val digest = Sha2.sha256Hex(Jcs.serialize(ib).encodeToByteArray())
        return PREFIX[k]!! + ":" + digest
    }
}

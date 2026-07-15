// The Causalontology conformance runner for causalontology-kotlin.
//
// Runs every vector in conformance/vectors/ against this binding, mirroring
// bindings/python/tests/run_conformance.py exactly. An implementation is
// conformant if and only if it passes every vector; this runner exits nonzero
// on any failure.
//
// The vectors are frozen at specification 1.0.0: they carry concrete 64-hex
// identifiers, real keys, and a real verifying signature, which the
// normalization below passes through unchanged. (The pre-freeze symbolic
// forms - "occurrent:press_button", "ed25519:alice" - still normalize
// deterministically: symbolic object ids become scheme:sha256(name), and
// symbolic key names become real Ed25519 keypairs seeded from
// sha256("key:" + name), exactly as the Python harness does.)
//
// Run from the repository root (or set CAUSALONTOLOGY_ROOT).
package org.causalontology

import kotlin.system.exitProcess

// ---------------------------------------------------------------------------
// symbolic-identifier normalization
// ---------------------------------------------------------------------------
private val SCHEMES = setOf("occurrent", "causal_relation_object", "continuant", "realizable", "assertion", "enrichment", "retraction", "succession")
private val KEYS = HashMap<String, Pair<ByteArray, String>>()

// A real, deterministic Ed25519 keypair for a symbolic key name.
private fun key(name: String): Pair<ByteArray, String> = KEYS.getOrPut(name) {
    val seed = Sha2.sha256(("key:" + name).encodeToByteArray())
    Signing.keypairFromSeed(seed)
}

private fun isHex64(s: String): Boolean =
    s.length == 64 && s.all { it in '0'..'9' || it in 'a'..'f' }

// Normalize one symbolic identifier to a well-formed one.
private fun sym(s: String): String {
    val i = s.indexOf(':')
    val scheme = s.substring(0, i)
    val name = s.substring(i + 1)
    if (scheme == "ed25519") {
        return if (isHex64(name)) s else key(name).second  // frozen keys pass through
    }
    return if (isHex64(name)) s
    else scheme + ":" + Sha2.sha256Hex(name.encodeToByteArray())
}

// Recursively normalize symbolic identifiers and placeholders.
private fun normalize(x: Any?): Any? = when (x) {
    is String -> {
        if (x == "<128 hex>") "ab".repeat(64)
        else {
            val i = x.indexOf(':')
            if (i > 0 && (x.substring(0, i) in SCHEMES || x.substring(0, i) == "ed25519"))
                sym(x)
            else x
        }
    }
    is List<*> -> x.map { normalize(it) }
    is Map<*, *> -> {
        val out = LinkedHashMap<String, Any?>()
        for ((k, v) in x) out[k as String] = normalize(v)
        out
    }
    else -> x
}

// ---------------------------------------------------------------------------
// vector loading
// ---------------------------------------------------------------------------
private val ROOT: String by lazy { Schema.repoRoot() }
private val VECDIR: String by lazy { "$ROOT/conformance/vectors" }
private val VECTOR_FILES: List<String> by lazy {
    listDir(VECDIR).filter { it.endsWith(".json") }
}

private fun vecFileName(n: Int): String {
    val nn = n.toString().padStart(2, '0')
    val hits = VECTOR_FILES.filter { it.startsWith("v${nn}_") }
    check(hits.size == 1) { "vector $n not found" }
    return hits[0]
}

// Load vector n's JSON file (for its structured inputs).
private fun vec(n: Int): JObj = asObj(Json.parse(readFile("$VECDIR/" + vecFileName(n))))

// Build, timestamp, and sign a provenance record.
private fun signed(kind: String, body: JObj, who: String, tsI: Int = 0): JObj {
    val (secret, pub) = key(who)
    val rec = LinkedHashMap(body)
    rec["type"] = kind
    if (!rec.containsKey("timestamp")) rec["timestamp"] = "2026-07-13T0$tsI:00:00Z"
    if (kind == "succession") {
        if (!rec.containsKey("predecessor")) rec["predecessor"] = pub
    } else {
        rec["source"] = pub
    }
    return Signing.signRecord(rec, secret, kind)
}

// ---------------------------------------------------------------------------
// assertion helpers
// ---------------------------------------------------------------------------
private fun assertTrue(cond: Boolean, msg: String) {
    if (!cond) throw AssertionError(msg)
}

// ---------------------------------------------------------------------------
// internal sanity checks (not conformance vectors)
// ---------------------------------------------------------------------------
private fun internalChecks() {
    // FIPS 180-4 empty-string known answers gate both hash functions.
    Sha2.checkKnownAnswers()
    // RFC 8032 TEST 1 known answer (public key, exact signature, verify, reject).
    Ed25519.checkKnownAnswer()
    // JCS basics.
    assertTrue(Jcs.serialize(linkedMapOf("b" to 2L, "a" to 1L)) == "{\"a\":1,\"b\":2}",
               "JCS key sorting failed")
    assertTrue(Jcs.serialize(1.0) == "1" && Jcs.serialize(6.000) == "6" &&
               Jcs.serialize(0.7) == "0.7", "JCS number formatting failed")
}

// ---------------------------------------------------------------------------
// the 38 vectors
// ---------------------------------------------------------------------------
private fun v01() {
    val inp = asObj(normalize(vec(1)["input"]))
    val (okS, whyS) = Schema.validateSchema(inp)
    assertTrue(okS, whyS.toString())
    val (okM, whyM) = Semantics.validateSemantics(inp)
    assertTrue(okM, whyM.toString())
}

private fun v02() {
    val v = vec(2)
    val inp = asObj(normalize(v["input"]))
    assertTrue(Schema.validateSchema(inp).first, "schema")
    assertTrue(Semantics.validateSemantics(inp).first, "semantics")
    val (partial, missing) = Semantics.isPartial(inp)
    val expect = asList(asObj(v["expect"])["missing"]).map { it as String }
    assertTrue(partial && missing == expect, missing.toString())
}

private fun schemaFails(n: Int, mustMention: String) {
    val inp = asObj(normalize(vec(n)["input"]))
    val (ok, why) = Schema.validateSchema(inp)
    assertTrue(!ok, "expected schema-invalid")
    assertTrue(why.any { it.contains(mustMention) }, why.toString())
}

private fun v03() = schemaFails(3, "effects")
private fun v04() = schemaFails(4, "causes")
private fun v05() = schemaFails(5, "modality")
private fun v06() = schemaFails(6, "colour")
private fun v07() = schemaFails(7, "causes")

private fun v08() {
    val (ok, why) = Schema.validateSchema(asObj(normalize(vec(8)["input"])))
    assertTrue(ok, why.toString())
}

private fun v09() = schemaFails(9, "label")
private fun v10() = schemaFails(10, "category")

private fun v11() {
    val (ok, why) = Schema.validateSchema(asObj(normalize(vec(11)["input"])))
    assertTrue(ok, why.toString())
}

private fun v12() = schemaFails(12, "confidence")

private fun v13() {
    val inp = asObj(normalize(vec(13)["input"]))
    val (okS, whyS) = Schema.validateSchema(inp)
    assertTrue(okS, whyS.toString())
    val (okM, whyM) = Semantics.validateSemantics(inp)
    assertTrue(okM, whyM.toString())
}

private fun semanticsFails(n: Int, mustMention: String) {
    val inp = asObj(normalize(vec(n)["input"]))
    val (ok, why) = Semantics.validateSemantics(inp)
    assertTrue(!ok, "expected semantically-invalid")
    assertTrue(why.any { it.contains(mustMention) }, why.toString())
}

private fun v14() {
    val inp = asObj(normalize(vec(14)["input"]))
    assertTrue(Schema.validateSchema(inp).first, "schema")
    semanticsFails(14, "minimum_delay")
}

private fun v15() = semanticsFails(15, "acyclic")
private fun v16() = semanticsFails(16, "acyclic")

private fun v17() {
    val v = vec(17)
    val parent = asObj(normalize(asObj(v["given"])["parent"]))
    val child = asObj(normalize(v["input"]))
    val (ok, reason) = Semantics.refinementValid(child, parent)
    assertTrue(!ok && reason.contains("rival"), reason)
}

private fun v18() = semanticsFails(18, "not a legal field")
private fun v19() = semanticsFails(19, "language-tagged")

private fun v20() {
    val dog = sym("continuant:dog"); val mam = sym("continuant:mammal"); val ani = sym("continuant:animal")
    fun enrich(about: String, entry: String, i: Int): JObj = signed(
        "enrichment",
        linkedMapOf("about" to about, "field" to "subsumes", "entry" to entry),
        "taxo", i)
    // enforcing tier rejects the cycle-completing write
    val s = InMemoryStore(enforcing = true)
    s.putRecord(enrich(dog, mam, 1))
    s.putRecord(enrich(mam, ani, 2))
    var rejected = false
    try {
        s.putRecord(enrich(ani, dog, 3))
    } catch (e: RejectedWrite) {
        rejected = true
        assertTrue((e.message ?: "").contains("cycle"), e.message ?: "")
    }
    assertTrue(rejected, "enforcing store accepted a cycle")
    // decentralized merge: the view breaks the cycle deterministically
    val s2 = InMemoryStore(enforcing = true)
    s2.putRecord(enrich(dog, mam, 1))
    s2.putRecord(enrich(mam, ani, 2))
    val bad = enrich(ani, dog, 3)
    s2.forceMergeRecord(bad)
    val (_, excluded) = s2.activeTaxonomyEdges("subsumes")
    assertTrue(excluded.size == 1 && excluded[0]["id"] == bad["id"],
               "wrong excluded record")
    val repair = s2.gaps("inconsistent_hierarchy")
    assertTrue(repair.any { it["id"] == bad["id"] }, "gap read missed the exclusion")
}

private fun adm(n: Int): Boolean {
    val g = asObj(vec(n)["given"])
    val cro = linkedMapOf<String, Any?>(
        "causes" to listOf(sym("occurrent:c")), "effects" to listOf(sym("occurrent:e")),
        "temporal" to g["temporal"])
    return Semantics.admissible(cro, asDoubleNum(g["elapsed_seconds"]))
}

private fun v21() = assertTrue(adm(21), "expected admissible")
private fun v22() = assertTrue(!adm(22), "expected not admissible")
private fun v23() = assertTrue(adm(23), "expected admissible")

private fun v24() {
    val v = vec(24)
    assertTrue(Canonical.identify(asObj(normalize(v["inputA"]))) ==
               Canonical.identify(asObj(normalize(v["inputB"]))),
               "identifiers differ under key reordering")
}

private fun v25() {
    val v = vec(25)
    assertTrue(Canonical.identify(asObj(normalize(v["inputA"]))) ==
               Canonical.identify(asObj(normalize(v["inputB"]))),
               "identifiers differ under number reformatting")
}

private fun v26() {
    val s = InMemoryStore()
    val obj = linkedMapOf<String, Any?>(
        "type" to "occurrent", "label" to "press_button", "category" to "action")
    val a = s.put(LinkedHashMap(obj))
    val b = s.put(LinkedHashMap(obj))
    assertTrue(a == b && s.objects.size == 1, "put is not idempotent")
}

private fun v27() {
    val s = InMemoryStore()
    val occ = s.put(linkedMapOf(
        "type" to "occurrent", "label" to "press_button", "category" to "action"))
    val entry = linkedMapOf<String, Any?>("lang" to "en", "text" to "press the button")
    val r1 = signed("enrichment", linkedMapOf(
        "about" to occ, "field" to "aliases", "entry" to entry), "alice", 1)
    val r2 = signed("enrichment", linkedMapOf(
        "about" to occ, "field" to "aliases", "entry" to entry), "bob", 2)
    assertTrue(s.putRecord(r1) != s.putRecord(r2), "expected two records")
    val view = asList(asObj(asObj(s.get(occ))["enrichments"])["aliases"])
    assertTrue(view.size == 1, "expected one materialized entry")
    val contributors = asList(asObj(view[0])["contributors"])
    assertTrue(contributors.size == 2, "expected two contributors")
}

private fun v28() {
    val s = InMemoryStore()
    val claim = linkedMapOf<String, Any?>(
        "type" to "causal_relation_object", "causes" to listOf(sym("occurrent:A")),
        "effects" to listOf(sym("occurrent:B")), "modality" to "sufficient")
    val i1 = s.put(LinkedHashMap(claim))
    val i2 = s.put(LinkedHashMap(claim))
    assertTrue(i1 == i2 && s.objects.size == 1, "same claim must be one object")
    for ((who, ts) in listOf(Pair("lab1", 1), Pair("lab2", 2))) {
        s.putRecord(signed("assertion", linkedMapOf(
            "about" to i1, "evidence_type" to "observation",
            "strength" to 0.8, "confidence" to 0.8), who, ts))
    }
    assertTrue(s.assertionsAbout(i1).size == 2, "expected two assertions")
}

private fun v29() {
    val rec = signed("assertion", linkedMapOf(
        "about" to sym("causal_relation_object:demo"), "evidence_type" to "intervention",
        "strength" to 0.7, "confidence" to 0.9), "signer")
    assertTrue(Signing.verifyRecord(rec), "valid signature must verify")
}

private fun v30() {
    val rec = signed("assertion", linkedMapOf(
        "about" to sym("causal_relation_object:demo"), "evidence_type" to "intervention",
        "strength" to 0.7, "confidence" to 0.9), "signer")
    val tampered = LinkedHashMap(rec)
    tampered["confidence"] = 0.1
    assertTrue(!Signing.verifyRecord(tampered), "tampered record must not verify")
}

private fun v31() {
    val s = InMemoryStore()
    val x = s.put(linkedMapOf(
        "type" to "causal_relation_object", "causes" to listOf(sym("occurrent:A")),
        "effects" to listOf(sym("occurrent:B"))))
    val a = signed("assertion", linkedMapOf(
        "about" to x, "evidence_type" to "observation", "confidence" to 0.8),
        "lab1", 1)
    s.putRecord(a)
    s.putRecord(signed("retraction", linkedMapOf("retracts" to a["id"]), "lab1", 2))
    assertTrue(s.assertionsAbout(x).isEmpty(), "retracted assertion still visible")
    val hist = s.assertionsAbout(x, includeRetracted = true)
    assertTrue(hist.size == 1 && hist[0]["retracted"] == true, "history flag missing")
    val foreign = signed("retraction", linkedMapOf("retracts" to a["id"]), "mallory", 3)
    var rejected = false
    try {
        s.putRecord(foreign)
    } catch (e: RejectedWrite) {
        rejected = true
    }
    assertTrue(rejected, "foreign retraction accepted")
    assertTrue(s.assertionsAbout(x).isEmpty(), "still excluded by lab1's own")
    assertTrue(s.assertionsAbout(x, includeRetracted = true).size == 1, "history size")
}

private fun v32() {
    val s = InMemoryStore()
    val occ = s.put(linkedMapOf(
        "type" to "occurrent", "label" to "press_button", "category" to "action"))
    val e = signed("enrichment", linkedMapOf(
        "about" to occ, "field" to "aliases",
        "entry" to linkedMapOf<String, Any?>("lang" to "ja", "text" to "botan")), "bob", 1)
    s.putRecord(e)
    fun aliases(view: String): List<Any?> {
        val enr = asObj(asObj(s.get(occ, view))["enrichments"])
        return if (enr.containsKey("aliases")) asList(enr["aliases"]) else emptyList()
    }
    assertTrue(aliases("default").size == 1, "expected one alias")
    s.putRecord(signed("retraction", linkedMapOf("retracts" to e["id"]), "bob", 2))
    assertTrue(aliases("default").isEmpty(), "retracted alias still visible")
    assertTrue(aliases("history").size == 1, "history must keep the alias")
}

private fun v33() {
    val s = InMemoryStore()
    val k1 = key("K1").second
    val k2 = key("K2").second
    val a = signed("assertion", linkedMapOf(
        "about" to sym("causal_relation_object:claim"), "evidence_type" to "observation",
        "confidence" to 0.9), "K1", 1)
    s.putRecord(a)
    val succ = signed("succession", linkedMapOf<String, Any?>("successor" to k2), "K1", 2)
    s.putRecord(succ)
    assertTrue(k1 in s.lineage(k2) && k2 in s.lineage(k1), "lineage closure broken")
    val r = signed("retraction", linkedMapOf("retracts" to a["id"]), "K2", 3)
    s.putRecord(r)  // successor may retract the predecessor's record
    assertTrue(s.assertionsAbout(sym("causal_relation_object:claim")).isEmpty(),
               "successor's retraction must apply")
}

private fun v34() {
    val g = asObj(normalize(vec(34)["given"]))
    assertTrue(Semantics.conflicts(asObj(g["A"]), asObj(g["B"])), "expected a conflict")
}

private fun v35() {
    val g = asObj(normalize(vec(35)["given"]))
    assertTrue(!Semantics.conflicts(asObj(g["A"]), asObj(g["B"])), "expected no conflict")
}

private fun v36() {
    val a = sym("occurrent:A"); val b = sym("occurrent:B"); val c = sym("occurrent:C"); val d = sym("occurrent:D")
    val m1 = linkedMapOf<String, Any?>(
        "id" to sym("causal_relation_object:m1"), "causes" to listOf(a), "effects" to listOf(b))
    val m2 = linkedMapOf<String, Any?>(
        "id" to sym("causal_relation_object:m2"), "causes" to listOf(b), "effects" to listOf(c))
    val m3 = linkedMapOf<String, Any?>(
        "id" to sym("causal_relation_object:m3"), "causes" to listOf(d), "effects" to listOf(c))
    val p = linkedMapOf<String, Any?>(
        "causes" to listOf(a), "effects" to listOf(c),
        "mechanism" to listOf(m1["id"], m2["id"]))
    assertTrue(Semantics.hierarchyConsistent(p, mapOf(
        m1["id"] as String to m1, m2["id"] as String to m2)) == "consistent",
        "expected consistent")
    val p2 = LinkedHashMap(p)
    p2["mechanism"] = listOf(m1["id"], m3["id"])
    assertTrue(Semantics.hierarchyConsistent(p2, mapOf(
        m1["id"] as String to m1, m3["id"] as String to m3)) == "inconsistent",
        "expected inconsistent")
    assertTrue(Semantics.hierarchyConsistent(p, mapOf(
        m1["id"] as String to m1)) == "indeterminate", "expected indeterminate")
}

private fun v37() {
    val s = InMemoryStore()
    val occ = s.put(linkedMapOf(
        "type" to "occurrent", "label" to "press_button", "category" to "action"))
    s.putRecord(signed("enrichment", linkedMapOf(
        "about" to occ, "field" to "aliases",
        "entry" to linkedMapOf<String, Any?>(
            "lang" to "en", "text" to "Press the Button")), "alice", 1))
    assertTrue(s.resolve("Press  The   Button", "en") == listOf(occ), "alias match failed")
    assertTrue(s.resolve("press_button", "en").firstOrNull() == occ, "label match failed")
}

private fun v38() {
    val s = InMemoryStore()
    val p = s.put(linkedMapOf(
        "type" to "causal_relation_object", "causes" to listOf(sym("occurrent:A")),
        "effects" to listOf(sym("occurrent:B"))))
    var gapIds = s.gaps("missing_field").map { it["id"] }
    assertTrue(p in gapIds, "the degenerate claim must be a gap")
    val r = s.put(linkedMapOf(
        "type" to "causal_relation_object", "causes" to listOf(sym("occurrent:A")),
        "effects" to listOf(sym("occurrent:B")),
        "temporal" to linkedMapOf<String, Any?>(
            "minimum_delay" to 0L, "maximum_delay" to 1L, "unit" to "seconds"),
        "modality" to "sufficient", "refines" to p))
    gapIds = s.gaps("missing_field").map { it["id"] }
    assertTrue(p !in gapIds, "the gap did not close")
    assertTrue(r !in gapIds, "the refinement itself must be complete")
}

// ---------------------------------------------------------------------------
fun main() {
    println("causalontology-kotlin conformance run")
    print("internal checks (RFC 8032 known-answer, RFC 8785 basics) ... ")
    internalChecks()
    println("ok")
    val vectors: List<Pair<Int, () -> Unit>> = listOf(
        1 to ::v01, 2 to ::v02, 3 to ::v03, 4 to ::v04, 5 to ::v05, 6 to ::v06,
        7 to ::v07, 8 to ::v08, 9 to ::v09, 10 to ::v10, 11 to ::v11, 12 to ::v12,
        13 to ::v13, 14 to ::v14, 15 to ::v15, 16 to ::v16, 17 to ::v17, 18 to ::v18,
        19 to ::v19, 20 to ::v20, 21 to ::v21, 22 to ::v22, 23 to ::v23, 24 to ::v24,
        25 to ::v25, 26 to ::v26, 27 to ::v27, 28 to ::v28, 29 to ::v29, 30 to ::v30,
        31 to ::v31, 32 to ::v32, 33 to ::v33, 34 to ::v34, 35 to ::v35, 36 to ::v36,
        37 to ::v37, 38 to ::v38)
    var failures = 0
    for ((n, fn) in vectors) {
        val name = vecFileName(n).removeSuffix(".json")
        try {
            fn()
            println("PASS  $name")
        } catch (e: Throwable) {
            failures++
            println("FAIL  $name :: $e")
        }
    }
    val total = 38
    println("-".repeat(60))
    println("${total - failures}/$total vectors passed")
    if (failures > 0) exitProcess(1)
    println("causalontology-kotlin is CONFORMANT to the suite " +
            "(vectors frozen at specification 1.0.0).")
}

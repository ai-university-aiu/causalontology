// The Causalontology conformance runner for causalontology-kotlin.
//
// Runs every vector in conformance/vectors/ against this binding, mirroring
// bindings/python/tests/run_conformance.py exactly. An implementation is
// conformant if and only if it passes every vector; this runner exits nonzero
// on any failure.
//
// The vectors are frozen at specification 4.0.0: V01-V107 are the whole-word
// 2.0.0 baseline (Principle P7, V01-V38 re-frozen unaltered in meaning,
// V39-V107 new); V108-V119 are the 3.0.0 additions (tick unit,
// cross_stratal_seam, realized_by); V120-V137 are the 4.0.0 additions
// (attitude, predicted_occurrence, prediction_error). Symbolic identifiers
// ("occurrent:press_button", "ed25519:alice") normalize deterministically:
// symbolic object ids become scheme:sha256(name), and symbolic key names
// become real Ed25519 keypairs seeded from sha256("key:" + name), exactly as
// the Python harness does.
//
// Run from the repository root (or set CAUSALONTOLOGY_ROOT).
package org.causalontology

import kotlin.system.exitProcess

// ---------------------------------------------------------------------------
// whole-word scheme normalization (Principle P7)
// ---------------------------------------------------------------------------
private val SCHEMES = listOf(
    "occurrent", "causal_relation_object", "continuant", "realizable",
    "assertion", "enrichment", "retraction", "succession",
    "stratum", "bridge", "cross_stratal_seam", "port", "conduit", "quality",
    "token_individual", "token_occurrence", "state_assertion",
    "token_causal_claim",
    "attitude", "predicted_occurrence", "prediction_error")
private val WHOLE_WORD: Set<String> = SCHEMES.toSet() + "ed25519"
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

private const val TS_PREFIX = "2026-07-13T0"

// Build, timestamp, and sign a provenance record.
private fun signed(kind: String, body: JObj, who: String, tsI: Int = 0): JObj {
    val (secret, pub) = key(who)
    val rec = LinkedHashMap(body)
    rec["type"] = kind
    if (!rec.containsKey("timestamp")) rec["timestamp"] = "$TS_PREFIX$tsI:00:00Z"
    if (kind == "succession") {
        if (!rec.containsKey("predecessor")) rec["predecessor"] = pub
    } else {
        rec["source"] = pub
    }
    return Signing.signRecord(rec, secret, kind)
}

// A content object completed with its real content-addressed id.
private fun mk(obj: JObj): JObj {
    val o = LinkedHashMap(obj)
    o["id"] = Canonical.identify(o)
    return o
}

// ---------------------------------------------------------------------------
// builders (mirror run_conformance.py's builders)
// ---------------------------------------------------------------------------
private fun stratum(label: String, scheme: String, ordinal: Long,
                    unit: String? = null, governs: List<String>? = null): JObj {
    val o = linkedMapOf<String, Any?>(
        "type" to "stratum", "label" to label, "scheme" to scheme, "ordinal" to ordinal)
    if (unit != null) o["unit"] = unit
    if (governs != null) o["governs"] = governs
    return mk(o)
}

private fun occ(label: String, stratumId: String? = null, category: String = "event"): JObj {
    val o = linkedMapOf<String, Any?>("type" to "occurrent", "label" to label, "category" to category)
    if (stratumId != null) o["stratum"] = stratumId
    return mk(o)
}

private fun cnt(label: String, category: String = "object"): JObj =
    mk(linkedMapOf("type" to "continuant", "label" to label, "category" to category))

private fun cro(causes: List<String>, effects: List<String>, vararg extra: Pair<String, Any?>): JObj {
    val o = linkedMapOf<String, Any?>(
        "type" to "causal_relation_object", "causes" to causes, "effects" to effects)
    for ((k, v) in extra) o[k] = v
    return mk(o)
}

private fun bridge(coarse: String, fine: List<String>, relation: String): JObj =
    mk(linkedMapOf("type" to "bridge", "coarse" to coarse, "fine" to fine, "relation" to relation))

private fun port(bearer: String, label: String, direction: String,
                 accepts: List<String>, realizable: String? = null): JObj {
    val o = linkedMapOf<String, Any?>(
        "type" to "port", "bearer" to bearer, "label" to label,
        "direction" to direction, "accepts" to accepts)
    if (realizable != null) o["realizable"] = realizable
    return mk(o)
}

private fun conduit(frm: String, to: String, carries: List<String>,
                    label: String = "conn", transform: String? = null): JObj {
    val o = linkedMapOf<String, Any?>(
        "type" to "conduit", "label" to label, "from" to frm, "to" to to, "carries" to carries)
    if (transform != null) o["transform"] = transform
    return mk(o)
}

private fun quality(label: String, datatype: String, unit: String? = null,
                    stratumId: String? = null): JObj {
    val o = linkedMapOf<String, Any?>("type" to "quality", "label" to label, "datatype" to datatype)
    if (unit != null) o["unit"] = unit
    if (stratumId != null) o["stratum"] = stratumId
    return mk(o)
}

private fun individual(instantiates: String, designator: String? = null, partOf: String? = null): JObj {
    val o = linkedMapOf<String, Any?>("type" to "token_individual", "instantiates" to instantiates)
    if (designator != null) o["designator"] = designator
    if (partOf != null) o["part_of"] = partOf
    return mk(o)
}

private fun token(instantiates: String, interval: JObj, participants: List<JObj>? = null,
                  locus: String? = null): JObj {
    val o = linkedMapOf<String, Any?>(
        "type" to "token_occurrence", "instantiates" to instantiates, "interval" to interval)
    if (participants != null) o["participants"] = participants
    if (locus != null) o["locus"] = locus
    return mk(o)
}

private fun state(subject: String, qual: String, value: JObj, interval: JObj): JObj =
    mk(linkedMapOf("type" to "state_assertion", "subject" to subject,
        "quality" to qual, "value" to value, "interval" to interval))

private fun tcc(causes: List<String>, effects: List<String>, coveringLaw: String? = null,
                actualDelay: JObj? = null, counterfactual: Boolean? = null): JObj {
    val o = linkedMapOf<String, Any?>(
        "type" to "token_causal_claim", "causes" to causes, "effects" to effects)
    if (coveringLaw != null) o["covering_law"] = coveringLaw
    if (actualDelay != null) o["actual_delay"] = actualDelay
    if (counterfactual != null) o["counterfactual"] = counterfactual
    return mk(o)
}

// ---------------------------------------------------------------------------
// assertion helper
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
    // Fixed unit constants (Algorithm E).
    assertTrue(Semantics.toSeconds(1, "months") == 2629746L, "months constant")
    assertTrue(Semantics.toSeconds(1, "years") == 31556952L, "years constant")
}

// ===========================================================================
// V01 - V38: the whole-word re-freeze of the 1.0.0 suite (unaltered in meaning)
// ===========================================================================
private fun v01() {
    val inp = asObj(normalize(vec(1)["input"]))
    val (okS, whyS) = Schema.validateSchema(inp); assertTrue(okS, whyS.toString())
    val (okM, whyM) = Semantics.validateSemantics(inp); assertTrue(okM, whyM.toString())
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
    val (okS, whyS) = Schema.validateSchema(inp); assertTrue(okS, whyS.toString())
    val (okM, whyM) = Semantics.validateSemantics(inp); assertTrue(okM, whyM.toString())
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
    val s2 = InMemoryStore(enforcing = true)
    s2.putRecord(enrich(dog, mam, 1))
    s2.putRecord(enrich(mam, ani, 2))
    val bad = enrich(ani, dog, 3)
    s2.forceMergeRecord(bad)
    val (_, excluded) = s2.activeTaxonomyEdges("subsumes")
    assertTrue(excluded.size == 1 && excluded[0]["id"] == bad["id"], "wrong excluded record")
    val repair = s2.gaps("inconsistent_hierarchy")
    assertTrue(repair.any { it["id"] == bad["id"] }, "gap read missed the exclusion")
}

private fun adm(n: Int): Boolean {
    val g = asObj(vec(n)["given"])
    val c = linkedMapOf<String, Any?>(
        "causes" to listOf(sym("occurrent:c")), "effects" to listOf(sym("occurrent:e")),
        "temporal" to g["temporal"])
    return Semantics.admissible(c, asDoubleNum(g["elapsed_seconds"]))
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
    val a = s.put(LinkedHashMap(obj)); val b = s.put(LinkedHashMap(obj))
    assertTrue(a == b && s.objects.size == 1, "put is not idempotent")
}

private fun v27() {
    val s = InMemoryStore()
    val occId = s.put(linkedMapOf(
        "type" to "occurrent", "label" to "press_button", "category" to "action"))
    val entry = linkedMapOf<String, Any?>("lang" to "en", "text" to "press the button")
    val r1 = signed("enrichment", linkedMapOf("about" to occId, "field" to "aliases", "entry" to entry), "alice", 1)
    val r2 = signed("enrichment", linkedMapOf("about" to occId, "field" to "aliases", "entry" to entry), "bob", 2)
    assertTrue(s.putRecord(r1) != s.putRecord(r2), "expected two records")
    val view = asList(asObj(asObj(s.get(occId))["enrichments"])["aliases"])
    assertTrue(view.size == 1, "expected one materialized entry")
    assertTrue(asList(asObj(view[0])["contributors"]).size == 2, "expected two contributors")
}

private fun v28() {
    val s = InMemoryStore()
    val claim = linkedMapOf<String, Any?>(
        "type" to "causal_relation_object", "causes" to listOf(sym("occurrent:A")),
        "effects" to listOf(sym("occurrent:B")), "modality" to "sufficient")
    val i1 = s.put(LinkedHashMap(claim)); val i2 = s.put(LinkedHashMap(claim))
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
    val tampered = LinkedHashMap(rec); tampered["confidence"] = 0.1
    assertTrue(!Signing.verifyRecord(tampered), "tampered record must not verify")
}

private fun v31() {
    val s = InMemoryStore()
    val x = s.put(linkedMapOf(
        "type" to "causal_relation_object", "causes" to listOf(sym("occurrent:A")),
        "effects" to listOf(sym("occurrent:B"))))
    val a = signed("assertion", linkedMapOf(
        "about" to x, "evidence_type" to "observation", "confidence" to 0.8), "lab1", 1)
    s.putRecord(a)
    s.putRecord(signed("retraction", linkedMapOf("retracts" to a["id"]), "lab1", 2))
    assertTrue(s.assertionsAbout(x).isEmpty(), "retracted assertion still visible")
    val hist = s.assertionsAbout(x, includeRetracted = true)
    assertTrue(hist.size == 1 && hist[0]["retracted"] == true, "history flag missing")
    var rejected = false
    try { s.putRecord(signed("retraction", linkedMapOf("retracts" to a["id"]), "mallory", 3)) }
    catch (e: RejectedWrite) { rejected = true }
    assertTrue(rejected, "foreign retraction accepted")
}

private fun v32() {
    val s = InMemoryStore()
    val occId = s.put(linkedMapOf(
        "type" to "occurrent", "label" to "press_button", "category" to "action"))
    val e = signed("enrichment", linkedMapOf(
        "about" to occId, "field" to "aliases",
        "entry" to linkedMapOf<String, Any?>("lang" to "ja", "text" to "botan")), "bob", 1)
    s.putRecord(e)
    fun aliases(view: String): List<Any?> {
        val enr = asObj(asObj(s.get(occId, view))["enrichments"])
        return if (enr.containsKey("aliases")) asList(enr["aliases"]) else emptyList()
    }
    assertTrue(aliases("default").size == 1, "expected one alias")
    s.putRecord(signed("retraction", linkedMapOf("retracts" to e["id"]), "bob", 2))
    assertTrue(aliases("default").isEmpty(), "retracted alias still visible")
    assertTrue(aliases("history").size == 1, "history must keep the alias")
}

private fun v33() {
    val s = InMemoryStore()
    val k1 = key("K1").second; val k2 = key("K2").second
    val a = signed("assertion", linkedMapOf(
        "about" to sym("causal_relation_object:claim"), "evidence_type" to "observation",
        "confidence" to 0.9), "K1", 1)
    s.putRecord(a)
    s.putRecord(signed("succession", linkedMapOf<String, Any?>("successor" to k2), "K1", 2))
    assertTrue(k1 in s.lineage(k2) && k2 in s.lineage(k1), "lineage closure broken")
    s.putRecord(signed("retraction", linkedMapOf("retracts" to a["id"]), "K2", 3))
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
    val m1 = linkedMapOf<String, Any?>("id" to sym("causal_relation_object:m1"), "causes" to listOf(a), "effects" to listOf(b))
    val m2 = linkedMapOf<String, Any?>("id" to sym("causal_relation_object:m2"), "causes" to listOf(b), "effects" to listOf(c))
    val m3 = linkedMapOf<String, Any?>("id" to sym("causal_relation_object:m3"), "causes" to listOf(d), "effects" to listOf(c))
    val p = linkedMapOf<String, Any?>(
        "causes" to listOf(a), "effects" to listOf(c), "mechanism" to listOf(m1["id"], m2["id"]))
    assertTrue(Semantics.hierarchyConsistent(p, mapOf(
        m1["id"] as String to m1, m2["id"] as String to m2)) == "consistent", "expected consistent")
    val p2 = LinkedHashMap(p); p2["mechanism"] = listOf(m1["id"], m3["id"])
    assertTrue(Semantics.hierarchyConsistent(p2, mapOf(
        m1["id"] as String to m1, m3["id"] as String to m3)) == "inconsistent", "expected inconsistent")
    assertTrue(Semantics.hierarchyConsistent(p, mapOf(
        m1["id"] as String to m1)) == "indeterminate", "expected indeterminate")
}

private fun v37() {
    val s = InMemoryStore()
    val occId = s.put(linkedMapOf(
        "type" to "occurrent", "label" to "press_button", "category" to "action"))
    s.putRecord(signed("enrichment", linkedMapOf(
        "about" to occId, "field" to "aliases",
        "entry" to linkedMapOf<String, Any?>("lang" to "en", "text" to "Press the Button")), "alice", 1))
    assertTrue(s.resolve("Press  The   Button", "en") == listOf(occId), "alias match failed")
    assertTrue(s.resolve("press_button", "en").firstOrNull() == occId, "label match failed")
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
        "temporal" to linkedMapOf<String, Any?>("minimum_delay" to 0L, "maximum_delay" to 1L, "unit" to "seconds"),
        "modality" to "sufficient", "refines" to p))
    gapIds = s.gaps("missing_field").map { it["id"] }
    assertTrue(p !in gapIds, "the gap did not close")
    assertTrue(r !in gapIds, "the refinement itself must be complete")
}

// ===========================================================================
// V39 - V107: the 2.0.0 additions
// ===========================================================================
private fun neuro(): Map<Int, JObj> {
    val labels = mapOf(4 to "macromolecular", 5 to "subcellular", 6 to "cellular",
                       7 to "synaptic", 9 to "region", 14 to "community_and_society")
    return labels.mapValues { (o, l) -> stratum(l, "neuroendocrine", o.toLong()) }
}

private fun v39() {
    val st = stratum("cellular", "neuroendocrine", 6, "cell", listOf("cell_biology"))
    val (ok, why) = Schema.validateSchema(st); assertTrue(ok, why.toString())
}

private fun v40() {
    val bad = mk(linkedMapOf("type" to "stratum", "label" to "cellular", "ordinal" to 6L))
    val (ok, why) = Schema.validateSchema(bad, "stratum")
    assertTrue(!ok && why.any { it.contains("scheme") }, why.toString())
}

private fun v41() {
    val a = stratum("cellular", "neuroendocrine", 6)
    val b = stratum("neuronal", "neuroendocrine", 6)
    for (x in listOf(a, b)) { val (ok, why) = Schema.validateSchema(x); assertTrue(ok, why.toString()) }
    assertTrue(a["id"] != b["id"], "distinct labels must differ")
}

private fun v42() {
    val s = neuro()
    val s4p = stratum("molecular", "physics", 4)
    val c = occ("chronic_social_subordination", s[14]!!["id"] as String)
    val e = occ("gene_expression", s4p["id"] as String)
    val smap = mapOf(s[14]!!["id"] as String to s[14]!!, s4p["id"] as String to s4p)
    val omap = mapOf(c["id"] as String to c, e["id"] as String to e)
    val P = cro(listOf(c["id"] as String), listOf(e["id"] as String))
    assertTrue(Semantics.classifyCro(P, omap, smap) == "scheme_mismatch", "expected scheme_mismatch")
}

private fun v43() {
    for (x in listOf(stratum("macromolecular", "neuroendocrine", 4),
                     stratum("region", "neuroendocrine", 9))) {
        val (ok, why) = Schema.validateSchema(x); assertTrue(ok, why.toString())
    }
}

private fun v44() {
    val st = stratum("cellular", "neuroendocrine", 6)
    val o = occ("neuron_fires", st["id"] as String)
    val (okS, whyS) = Schema.validateSchema(o); assertTrue(okS, whyS.toString())
    val (okM, whyM) = Semantics.validateSemantics(o); assertTrue(okM, whyM.toString())
}

private fun v45() {
    val o = occ("press_button")
    val (ok, why) = Schema.validateSchema(o); assertTrue(ok, why.toString())
    val e = occ("light_on")
    val P = cro(listOf(o["id"] as String), listOf(e["id"] as String))
    assertTrue(Semantics.classifyCro(P, mapOf(o["id"] as String to o, e["id"] as String to e), emptyMap())
               == "unclassifiable", "expected unclassifiable")
}

private fun v46() {
    val s = neuro()
    val a = occ("depolarization", s[5]!!["id"] as String)
    val b = occ("depolarization", s[6]!!["id"] as String)
    assertTrue(a["id"] != b["id"], "same label in different strata must differ")
}

private fun bridgeFixture(relation: String): Triple<JObj, Map<String, JObj>, Map<String, JObj>> {
    val s = neuro()
    val coarse = occ("action_potential_fires", s[6]!!["id"] as String)
    val fine = listOf(occ("sodium_channels_open", s[4]!!["id"] as String),
                      occ("sodium_influx", s[4]!!["id"] as String))
    val b = bridge(coarse["id"] as String, fine.map { it["id"] as String }, relation)
    val omap = HashMap<String, JObj>()
    omap[coarse["id"] as String] = coarse
    for (f in fine) omap[f["id"] as String] = f
    val smap = mapOf(s[4]!!["id"] as String to s[4]!!, s[6]!!["id"] as String to s[6]!!)
    return Triple(b, omap, smap)
}

private fun validBridge(relation: String) {
    val (b, omap, smap) = bridgeFixture(relation)
    val (okS, whyS) = Schema.validateSchema(b); assertTrue(okS, whyS.toString())
    val (okW, whyW) = Semantics.bridgeWellformed(b, omap, smap); assertTrue(okW, whyW)
}

private fun v47() = validBridge("constitutes")
private fun v48() = validBridge("aggregates")
private fun v49() = validBridge("realizes")
private fun v50() = validBridge("supervenes_on")

private fun v51() {
    val s = neuro()
    val coarse = occ("x_coarse", s[4]!!["id"] as String)
    val fine = occ("x_fine", s[6]!!["id"] as String)
    val b = bridge(coarse["id"] as String, listOf(fine["id"] as String), "constitutes")
    val omap = mapOf(coarse["id"] as String to coarse, fine["id"] as String to fine)
    val smap = mapOf(s[4]!!["id"] as String to s[4]!!, s[6]!!["id"] as String to s[6]!!)
    assertTrue(!Semantics.bridgeWellformed(b, omap, smap).first, "coarse<fine ordinal must be malformed")
}

private fun v52() {
    val s = neuro()
    val coarse = occ("c", s[6]!!["id"] as String)
    val f1 = occ("f1", s[4]!!["id"] as String); val f2 = occ("f2", s[5]!!["id"] as String)
    val b = bridge(coarse["id"] as String, listOf(f1["id"] as String, f2["id"] as String), "constitutes")
    val omap = mapOf(coarse["id"] as String to coarse, f1["id"] as String to f1, f2["id"] as String to f2)
    val smap = mapOf(s[4]!!["id"] as String to s[4]!!, s[5]!!["id"] as String to s[5]!!, s[6]!!["id"] as String to s[6]!!)
    assertTrue(!Semantics.bridgeWellformed(b, omap, smap).first, "fine spanning strata must be malformed")
}

private fun v53() {
    val x = sym("occurrent:x"); val y = sym("occurrent:y")
    val b1 = bridge(x, listOf(y), "constitutes")
    val b2 = bridge(y, listOf(x), "constitutes")
    val edges = LinkedHashMap<String, MutableList<String>>()
    for (b in listOf(b1, b2)) {
        for (f in asList(b["fine"])) edges.getOrPut(f as String) { mutableListOf() }.add(b["coarse"] as String)
    }
    assertTrue(Semantics.hasCycle(edges), "bridge cycle must be detected")
}

private fun v54() {
    val a = stratum("cellular", "neuroendocrine", 6)
    val b = stratum("molecular", "physics", 4)
    val coarse = occ("c", a["id"] as String); val fine = occ("f", b["id"] as String)
    val br = bridge(coarse["id"] as String, listOf(fine["id"] as String), "constitutes")
    val omap = mapOf(coarse["id"] as String to coarse, fine["id"] as String to fine)
    val smap = mapOf(a["id"] as String to a, b["id"] as String to b)
    assertTrue(!Semantics.bridgeWellformed(br, omap, smap).first, "scheme mismatch must be malformed")
}

private fun v55() {
    val s = neuro()
    val coarse = occ("decision_made", s[6]!!["id"] as String)
    val f1 = occ("cascade_a", s[4]!!["id"] as String); val f2 = occ("cascade_b", s[4]!!["id"] as String)
    val b1 = bridge(coarse["id"] as String, listOf(f1["id"] as String), "realizes")
    val b2 = bridge(coarse["id"] as String, listOf(f2["id"] as String), "realizes")
    assertTrue(b1["id"] != b2["id"], "distinct bridges must differ")
    for (b in listOf(b1, b2)) { val (ok, why) = Schema.validateSchema(b); assertTrue(ok, why.toString()) }
}

private fun reachFixture(): Triple<JObj, Map<String, JObj>, List<JObj>> {
    val s = neuro()
    val ap = occ("action_potential_fires", s[6]!!["id"] as String)
    val nt = occ("neurotransmitter_released", s[6]!!["id"] as String)
    val fa = occ("calcium_enters", s[4]!!["id"] as String)
    val fb = occ("vesicle_fuses", s[4]!!["id"] as String)
    val m1 = cro(listOf(fa["id"] as String), listOf(fb["id"] as String))
    val P = cro(listOf(ap["id"] as String), listOf(nt["id"] as String), "mechanism" to listOf(m1["id"]))
    val bridges = listOf(bridge(ap["id"] as String, listOf(fa["id"] as String), "constitutes"),
                         bridge(nt["id"] as String, listOf(fb["id"] as String), "constitutes"))
    return Triple(P, mapOf(m1["id"] as String to m1), bridges)
}

private fun v56() {
    val (P, members, bridges) = reachFixture()
    assertTrue(Semantics.hierarchyConsistent(P, members, bridges) == "consistent", "expected consistent")
}

private fun v57() {
    val (P, members, _) = reachFixture()
    assertTrue(Semantics.hierarchyConsistent(P, members, emptyList()) == "inconsistent", "expected inconsistent")
}

private fun v58() {
    val (P, members, bridges) = reachFixture()
    val literal = Semantics.hierarchyConsistent(P, members, emptyList())
    val bridged = Semantics.hierarchyConsistent(P, members, bridges)
    assertTrue(literal != "consistent" && bridged == "consistent",
               "bridged reachability must differ from literal ($literal / $bridged)")
}

private fun classify(causeOrd: Int, effectOrd: Int): String {
    val s = neuro()
    val c = occ("c", s[causeOrd]!!["id"] as String); val e = occ("e", s[effectOrd]!!["id"] as String)
    val smap = mapOf(s[causeOrd]!!["id"] as String to s[causeOrd]!!, s[effectOrd]!!["id"] as String to s[effectOrd]!!)
    val omap = mapOf(c["id"] as String to c, e["id"] as String to e)
    return Semantics.classifyCro(cro(listOf(c["id"] as String), listOf(e["id"] as String)), omap, smap)
}

private fun v59() = assertTrue(classify(6, 6) == "intra_stratal", "expected intra_stratal")
private fun v60() = assertTrue(classify(6, 5) == "adjacent_stratal", "expected adjacent_stratal")
private fun v61() = assertTrue(classify(14, 4) == "skipping", "expected skipping")

private fun skipFixture(causeOrd: Int, effectOrd: Int, vararg extra: Pair<String, Any?>): Pair<JObj, String> {
    val s = neuro()
    val c = occ("c", s[causeOrd]!!["id"] as String); val e = occ("e", s[effectOrd]!!["id"] as String)
    val smap = mapOf(s[causeOrd]!!["id"] as String to s[causeOrd]!!, s[effectOrd]!!["id"] as String to s[effectOrd]!!)
    val omap = mapOf(c["id"] as String to c, e["id"] as String to e)
    val P = cro(listOf(c["id"] as String), listOf(e["id"] as String), *extra)
    return Pair(P, Semantics.classifyCro(P, omap, smap))
}

private fun v62() {
    val (P, cls) = skipFixture(14, 4)
    assertTrue(Semantics.skipGaps(P, cls) == listOf("incomplete_mechanism"), "expected incomplete_mechanism")
}

private fun v63() {
    val (P, cls) = skipFixture(14, 4, "skips" to true)
    assertTrue(Semantics.skipGaps(P, cls).isEmpty(), "skip-true absent mechanism must surface nothing")
}

private fun v64() {
    val (P, cls) = skipFixture(14, 4, "skips" to true,
        "mechanism" to listOf(sym("causal_relation_object:m")))
    assertTrue(Semantics.skipGaps(P, cls) == listOf("contradictory_skip"), "expected contradictory_skip")
    val (ok, why) = Semantics.validateSemantics(P)
    assertTrue(!ok && why.any { it.contains("contradictory_skip") }, why.toString())
}

private fun v65() {
    val (P, cls) = skipFixture(6, 6, "skips" to true)
    assertTrue(Semantics.skipGaps(P, cls) == listOf("vacuous_skip"), "expected vacuous_skip")
}

private fun v66() {
    val s = neuro()
    val c = occ("c", s[14]!!["id"] as String); val e = occ("e", s[4]!!["id"] as String)
    val absent = cro(listOf(c["id"] as String), listOf(e["id"] as String))
    val falseSkip = cro(listOf(c["id"] as String), listOf(e["id"] as String), "skips" to false)
    assertTrue(absent["id"] != falseSkip["id"], "absent skips must differ from skips=false")
}

private fun v67() {
    val s = neuro()
    val c1 = occ("c1", s[4]!!["id"] as String); val c2 = occ("c2", s[6]!!["id"] as String)
    val e = occ("e", s[6]!!["id"] as String)
    val P = cro(listOf(c1["id"] as String, c2["id"] as String), listOf(e["id"] as String))
    assertTrue(Semantics.endpointsMixed(P, mapOf(
        c1["id"] as String to c1, c2["id"] as String to c2, e["id"] as String to e)),
        "mixed endpoints expected")
}

private fun v68() {
    val P = cro(listOf(sym("occurrent:a")), listOf(sym("occurrent:b")), "modality" to "enabling")
    val (ok, why) = Schema.validateSchema(P); assertTrue(ok, why.toString())
}

private fun v69() {
    val a = linkedMapOf<String, Any?>("causes" to listOf(sym("occurrent:a")),
        "effects" to listOf(sym("occurrent:b")), "modality" to "enabling")
    val b = linkedMapOf<String, Any?>("causes" to listOf(sym("occurrent:a")),
        "effects" to listOf(sym("occurrent:b")), "modality" to "sufficient")
    assertTrue(!Semantics.conflicts(a, b), "enabling and sufficient must not conflict")
}

private fun v70() {
    val a = linkedMapOf<String, Any?>("causes" to listOf(sym("occurrent:a")),
        "effects" to listOf(sym("occurrent:b")), "modality" to "enabling")
    val b = linkedMapOf<String, Any?>("causes" to listOf(sym("occurrent:a")),
        "effects" to listOf(sym("occurrent:b")), "modality" to "preventive")
    assertTrue(Semantics.conflicts(a, b), "enabling and preventive must conflict")
}

private fun v71() {
    val b = cnt("hippocampus")
    val p = port(b["id"] as String, "perforant_path", "in", listOf(sym("occurrent:signal")))
    val (ok, why) = Schema.validateSchema(p); assertTrue(ok, why.toString())
}

private fun v72() {
    val b = cnt("hippocampus")["id"] as String
    val x = sym("occurrent:signal")
    assertTrue(port(b, "perforant_path", "in", listOf(x))["id"] !=
               port(b, "fornix", "in", listOf(x))["id"], "distinct labels must differ")
}

private fun conduitFixture(transform: Boolean = false, badCarry: Boolean = false,
                           inFrom: Boolean = false): Triple<JObj, Map<String, JObj>, Map<String, JObj>> {
    val x = sym("occurrent:motor_command"); val y = sym("occurrent:error_signal"); val z = sym("occurrent:unrelated")
    val m1 = cnt("motor_cortex")["id"] as String; val m2 = cnt("spinal_neuron")["id"] as String
    val frm = port(m1, "out_port", if (inFrom) "in" else "out", listOf(x))
    val to = port(m2, "in_port", "in", if (transform) listOf(y) else listOf(x))
    val carries = if (badCarry) listOf(z) else listOf(x)
    var xform: String? = null
    val croMap = HashMap<String, JObj>()
    if (transform) {
        val law = cro(listOf(x), listOf(y)); croMap[law["id"] as String] = law
        xform = law["id"] as String
    }
    val c = conduit(frm["id"] as String, to["id"] as String, carries, transform = xform)
    return Triple(c, mapOf(frm["id"] as String to frm, to["id"] as String to to), croMap)
}

private fun v73() {
    val (c, pmap, _) = conduitFixture()
    val (okS, whyS) = Schema.validateSchema(c); assertTrue(okS, whyS.toString())
    val (okW, whyW) = Semantics.conduitWellformed(c, pmap); assertTrue(okW, whyW)
}

private fun v74() {
    val (c, pmap, cmap) = conduitFixture(transform = true)
    val (okS, whyS) = Schema.validateSchema(c); assertTrue(okS, whyS.toString())
    val (okW, whyW) = Semantics.conduitWellformed(c, pmap, cmap); assertTrue(okW, whyW)
}

private fun v75() {
    val (c, pmap, _) = conduitFixture(badCarry = true)
    assertTrue(!Semantics.conduitWellformed(c, pmap).first, "bad carry must be malformed")
}

private fun v76() {
    val (c, pmap, _) = conduitFixture(inFrom = true)
    assertTrue(!Semantics.conduitWellformed(c, pmap).first, "in-direction from port must be malformed")
}

private fun v77() {
    val (c, pmap, cmap) = conduitFixture(transform = true)
    val (okW, whyW) = Semantics.conduitWellformed(c, pmap, cmap); assertTrue(okW, whyW)
    val law = cmap.values.first()
    assertTrue(asList(law["effects"])[0] !in asList(c["carries"]), "transform effect need not be carried")
}

private fun rlz(bearer: String, kind: String, label: String? = null): JObj {
    val o = linkedMapOf<String, Any?>("type" to "realizable", "kind" to kind, "bearer" to bearer)
    if (label != null) o["label"] = label
    return mk(o)
}

private fun v78() {
    val b = cnt("hippocampus")["id"] as String
    assertTrue(rlz(b, "disposition", "long_term_potentiation")["id"] !=
               rlz(b, "disposition", "pattern_separation")["id"], "distinct labels must differ")
}

private fun v79() {
    val b = cnt("hippocampus")["id"] as String
    val u1 = rlz(b, "disposition"); val u2 = rlz(b, "disposition")
    val (ok, why) = Schema.validateSchema(u1); assertTrue(ok, why.toString())
    assertTrue(u1["id"] == u2["id"], "same realizable must be identical")
    assertTrue(rlz(b, "disposition", "some_function")["id"] != u1["id"], "label is identity-bearing")
}

private fun v80() {
    val parent = occ("fires"); val child = occ("fires_action_potential")
    val e = linkedMapOf<String, Any?>("type" to "enrichment", "about" to child["id"],
        "field" to "occurrent_subsumes", "entry" to parent["id"])
    val (ok, why) = Semantics.validateSemantics(e); assertTrue(ok, why.toString())
}

private fun v81() {
    val a = sym("occurrent:a"); val b = sym("occurrent:b")
    assertTrue(Semantics.hasCycle(mapOf(a to listOf(b), b to listOf(a))), "cycle expected")
}

private fun v82() {
    val whole = occ("eat"); val part = occ("chew")
    val e = linkedMapOf<String, Any?>("type" to "enrichment", "about" to part["id"],
        "field" to "occurrent_part_of", "entry" to whole["id"])
    val (ok, why) = Semantics.validateSemantics(e); assertTrue(ok, why.toString())
}

private fun v83() {
    val (legalKinds, shape) = Semantics.ENRICHMENT_FIELDS["occurrent_part_of"]!!
    assertTrue(shape == "occurrent" && legalKinds == listOf("occurrent"), "field spec mismatch")
    val s = InMemoryStore()
    s.put(occ("eat")); s.put(occ("chew"))
    assertTrue(s.objects.values.none { it["type"] == "causal_relation_object" }, "no cro expected")
}

private fun v84() {
    val s = neuro()
    val a = occ("run", s[9]!!["id"] as String); val b = occ("sprint", s[6]!!["id"] as String)
    assertTrue(a["stratum"] != b["stratum"], "different strata expected")
}

private fun v85() {
    val c = cnt("human_patient")
    val ti = individual(c["id"] as String, designator = "salted_hash_abc123")
    val (ok, why) = Schema.validateSchema(ti); assertTrue(ok, why.toString())
}

private fun v86() {
    val bad = mk(linkedMapOf("type" to "token_individual", "designator" to "x"))
    val (ok, why) = Schema.validateSchema(bad, "token_individual")
    assertTrue(!ok && why.any { it.contains("instantiates") }, why.toString())
}

private fun v87() {
    val c = cnt("human_patient")["id"] as String
    assertTrue(individual(c, designator = "hash_a")["id"] !=
               individual(c, designator = "hash_b")["id"], "distinct designators must differ")
}

private fun v88() {
    val o = occ("bilateral_hippocampal_resection")
    val t = token(o["id"] as String, linkedMapOf(
        "start" to "1953-08-25T00:00:00Z", "end" to "1953-08-25T00:00:00Z"))
    val (ok, why) = Schema.validateSchema(t); assertTrue(ok, why.toString())
}

private fun v89() {
    val o = occ("amnesia_onset")["id"] as String
    val bounded = token(o, linkedMapOf("start" to "1953-08-25T00:00:00Z", "end" to "1953-08-26T00:00:00Z"))
    val instantaneous = token(o, linkedMapOf("start" to "1953-08-25T00:00:00Z"))
    val ongoing = token(o, linkedMapOf("start" to "1953-08-25T00:00:00Z", "open" to true))
    assertTrue(setOf(bounded["id"], instantaneous["id"], ongoing["id"]).size == 3, "three distinct intervals")
}

private fun v90() {
    val o = occ("resection")["id"] as String; val c = cnt("human_patient")["id"] as String
    val patient = individual(c, designator = "p")["id"] as String
    val surgeon = individual(c, designator = "s")["id"] as String
    val t = token(o, linkedMapOf("start" to "1953-08-25T00:00:00Z"),
        participants = listOf(
            linkedMapOf("role" to "patient", "filler" to patient),
            linkedMapOf("role" to "agent", "filler" to surgeon)))
    val (ok, why) = Schema.validateSchema(t); assertTrue(ok, why.toString())
}

private fun v91() {
    val q = quality("cortisol_concentration", "quantity", "ug/dL")
    val (ok, why) = Schema.validateSchema(q); assertTrue(ok, why.toString())
}

private fun stateFixture(datatype: String, value: JObj, unit: String? = null): Pair<JObj, JObj> {
    val q = quality("cortisol_concentration", datatype, unit)
    val c = cnt("human_patient")["id"] as String
    val subj = individual(c, designator = "p")["id"] as String
    val st = state(subj, q["id"] as String, value,
        linkedMapOf("start" to "2026-01-01T00:00:00Z", "end" to "2026-01-01T01:00:00Z"))
    return Pair(st, q)
}

private fun v92() {
    val (st, q) = stateFixture("quantity", linkedMapOf("quantity" to 15.0, "unit" to "ug/dL"), "ug/dL")
    val (ok, why) = Schema.validateSchema(st); assertTrue(ok, why.toString())
    assertTrue(Semantics.stateGaps(st, q).isEmpty(), "no gaps expected")
}

private fun v93() {
    val (st, q) = stateFixture("categorical", linkedMapOf("categorical" to "elevated"))
    val (ok, why) = Schema.validateSchema(st); assertTrue(ok, why.toString())
    assertTrue(Semantics.stateGaps(st, q).isEmpty(), "no gaps expected")
}

private fun v94() {
    val (st, q) = stateFixture("boolean", linkedMapOf("boolean" to true))
    val (ok, why) = Schema.validateSchema(st); assertTrue(ok, why.toString())
    assertTrue(Semantics.stateGaps(st, q).isEmpty(), "no gaps expected")
}

private fun v95() {
    val (st, q) = stateFixture("quantity", linkedMapOf("categorical" to "elevated"), "ug/dL")
    assertTrue(Semantics.stateGaps(st, q) == listOf("value_type_mismatch"), "expected value_type_mismatch")
}

private fun v96() {
    val (st, q) = stateFixture("quantity", linkedMapOf("quantity" to 15.0, "unit" to "mg/dL"), "ug/dL")
    assertTrue(Semantics.stateGaps(st, q) == listOf("unit_mismatch"), "expected unit_mismatch")
}

private fun lawAndTokens(): List<JObj> {
    val oCause = occ("resection"); val oEffect = occ("amnesia_onset")
    val law = cro(listOf(oCause["id"] as String), listOf(oEffect["id"] as String),
        "temporal" to linkedMapOf<String, Any?>("minimum_delay" to 0L, "maximum_delay" to 1L, "unit" to "days"),
        "modality" to "sufficient")
    val tCause = token(oCause["id"] as String, linkedMapOf("start" to "1953-08-25T00:00:00Z"))
    val tEffect = token(oEffect["id"] as String, linkedMapOf("start" to "1953-08-25T00:00:00Z", "open" to true))
    return listOf(law, oCause, oEffect, tCause, tEffect)
}

// A tiny 5-tuple to mirror Python's multiple return in law_and_tokens.
private data class Quint(val a: JObj, val b: JObj, val c: JObj, val d: JObj, val e: JObj)
private fun lawTokens(): Quint {
    val l = lawAndTokens(); return Quint(l[0], l[1], l[2], l[3], l[4])
}

private fun v97() {
    val q = lawTokens()
    val claim = tcc(listOf(q.d["id"] as String), listOf(q.e["id"] as String),
        coveringLaw = q.a["id"] as String,
        actualDelay = linkedMapOf("duration" to 0L, "unit" to "instant"), counterfactual = true)
    val (ok, why) = Schema.validateSchema(claim); assertTrue(ok, why.toString())
}

private fun v98() {
    val q = lawTokens()
    val claim = tcc(listOf(q.d["id"] as String), listOf(q.e["id"] as String))
    val (ok, why) = Schema.validateSchema(claim); assertTrue(ok, why.toString())
    assertTrue(!claim.containsKey("covering_law"), "covering_law must be optional")
}

private fun v99() {
    val q = lawTokens()
    assertTrue(Semantics.delayWithinWindow(
        linkedMapOf("duration" to 0L, "unit" to "instant"), asObj(q.a["temporal"])), "delay within window")
}

private fun v100() {
    val temporal = linkedMapOf<String, Any?>("minimum_delay" to 0L, "maximum_delay" to 1L, "unit" to "hours")
    assertTrue(!Semantics.delayWithinWindow(
        linkedMapOf("duration" to 5L, "unit" to "days"), temporal), "delay must be outside window")
}

private fun v101() {
    val o = occ("x")["id"] as String
    val cause = token(o, linkedMapOf("start" to "2026-01-02T00:00:00Z"))
    val effect = token(o, linkedMapOf("start" to "2026-01-01T00:00:00Z"))
    val claim = tcc(listOf(cause["id"] as String), listOf(effect["id"] as String))
    assertTrue(Semantics.retrocausal(claim, mapOf(
        cause["id"] as String to cause, effect["id"] as String to effect)), "retrocausal expected")
}

private fun v102() {
    val other = cro(listOf(sym("occurrent:foo")), listOf(sym("occurrent:bar")))
    val q = lawTokens()
    val claim = tcc(listOf(q.d["id"] as String), listOf(q.e["id"] as String), coveringLaw = other["id"] as String)
    assertTrue(Semantics.coveringLawMismatch(claim, mapOf(
        q.d["id"] as String to q.d, q.e["id"] as String to q.e), other), "mismatch expected")
}

private fun v103() {
    val a = signed("assertion", linkedMapOf(
        "about" to sym("token_occurrence:t"), "evidence_type" to "observation",
        "confidence" to 0.9), "signer")
    val (ok, why) = Schema.validateSchema(a); assertTrue(ok, why.toString())
}

private fun v104() {
    val ev = listOf(sym("token_occurrence:t1"), sym("token_causal_claim:c1"))
    val base = linkedMapOf<String, Any?>(
        "type" to "assertion", "about" to sym("causal_relation_object:law"),
        "source" to key("signer").second, "evidence_type" to "intervention",
        "strength" to 0.95, "confidence" to 0.99, "timestamp" to "2026-07-14T00:00:00Z")
    val a = LinkedHashMap(base); a["evidenced_by"] = ev
    val withId = LinkedHashMap(a); withId["id"] = Canonical.identify(a)
    val (ok, why) = Schema.validateSchema(withId); assertTrue(ok, why.toString())
    assertTrue(Canonical.identify(a) != Canonical.identify(base), "evidenced_by is identity-bearing")
}

private fun v105() {
    val a = signed("assertion", linkedMapOf(
        "about" to sym("causal_relation_object:law"), "evidence_type" to "simulation",
        "confidence" to 0.5), "signer")
    val (ok, why) = Schema.validateSchema(a); assertTrue(ok, why.toString())
    val rank = mapOf("intervention" to 0, "observation" to 1, "simulation" to 2)
    assertTrue(rank["intervention"]!! < rank["observation"]!! && rank["observation"]!! < rank["simulation"]!!,
               "evidence rank order")
}

private fun v106() {
    fun scan(node: Any?, ids: MutableList<String>) {
        when (node) {
            is String -> {
                val m = Regex("^([a-z0-9_]+):[0-9a-f]{64}$").matchEntire(node)
                if (m != null) ids.add(m.groupValues[1])
            }
            is List<*> -> node.forEach { scan(it, ids) }
            is Map<*, *> -> node.values.forEach { scan(it, ids) }
        }
    }
    for (n in 1..38) {
        val ids = mutableListOf<String>()
        scan(vec(n), ids)
        for (scheme in ids) {
            assertTrue(scheme in WHOLE_WORD, "V106: abbreviated scheme '$scheme' in vector $n")
        }
    }
    val rec = linkedMapOf<String, Any?>("type" to "occurrent", "label" to "press_button", "category" to "action")
    assertTrue(Canonical.identify(rec) == Canonical.identify(rec), "identity must be deterministic")
    assertTrue(Canonical.identify(rec).substringBefore(":") == "occurrent", "whole-word scheme expected")
}

private fun v107() {
    val hexid = "0".repeat(64)
    // NOTE: the abbreviated prefix below is intentional (the negative test);
    // it must NOT be re-minted. "c" "r" "o" is assembled to survive re-mint tools.
    val croAbbr = "c" + "r" + "o"
    val abbreviated = linkedMapOf<String, Any?>(
        "type" to "causal_relation_object", "id" to "$croAbbr:$hexid",
        "causes" to listOf("occurrent:$hexid"), "effects" to listOf("occurrent:$hexid"))
    assertTrue(!Schema.validateSchema(abbreviated, "causal_relation_object").first,
               "abbreviated scheme must be rejected")
    val abbrStr = linkedMapOf<String, Any?>(
        "type" to "stratum", "id" to "str:$hexid", "label" to "cellular",
        "scheme" to "neuroendocrine", "ordinal" to 6L)
    assertTrue(!Schema.validateSchema(abbrStr, "stratum").first, "abbreviated stratum id must be rejected")
    val whole = linkedMapOf<String, Any?>(
        "type" to "causal_relation_object", "id" to "causal_relation_object:$hexid",
        "causes" to listOf("occurrent:$hexid"), "effects" to listOf("occurrent:$hexid"))
    val (ok, why) = Schema.validateSchema(whole, "causal_relation_object"); assertTrue(ok, why.toString())
}

// ===========================================================================
// V108 - V119: the 3.0.0 additions (tick unit, cross_stratal_seam, realized_by)
// ===========================================================================
private fun seam(source: String, target: String, mechanismStatus: String,
                 chain: List<String>? = null): JObj {
    val o = linkedMapOf<String, Any?>(
        "type" to "cross_stratal_seam", "source" to source, "target" to target,
        "mechanism_status" to mechanismStatus)
    if (chain != null && chain.isNotEmpty()) o["chain"] = chain
    return mk(o)
}

private fun seamFixture(srcOrd: Int, tgtOrd: Int, mechanismStatus: String,
                        chainOrds: List<Int>? = null): Triple<JObj, Map<String, JObj>, Map<String, JObj>> {
    val s = neuro()
    val src = occ("source_event", s[srcOrd]!!["id"] as String)
    val tgt = occ("target_event", s[tgtOrd]!!["id"] as String)
    val omap = HashMap<String, JObj>()
    omap[src["id"] as String] = src
    omap[tgt["id"] as String] = tgt
    val smap = HashMap<String, JObj>()
    smap[s[srcOrd]!!["id"] as String] = s[srcOrd]!!
    smap[s[tgtOrd]!!["id"] as String] = s[tgtOrd]!!
    var chain: List<String>? = null
    if (chainOrds != null) {
        val ch = mutableListOf<String>()
        for ((i, o) in chainOrds.withIndex()) {
            val c = occ("chain_$i", s[o]!!["id"] as String)
            omap[c["id"] as String] = c
            smap[s[o]!!["id"] as String] = s[o]!!
            ch.add(c["id"] as String)
        }
        chain = ch
    }
    return Triple(seam(src["id"] as String, tgt["id"] as String, mechanismStatus, chain), omap, smap)
}

private fun conduitRealized(realizedBy: String? = null): JObj {
    val o = linkedMapOf<String, Any?>(
        "type" to "conduit", "label" to "conn",
        "from" to "port:" + "1".repeat(64),
        "to" to "port:" + "2".repeat(64),
        "carries" to listOf("occurrent:" + "3".repeat(64)))
    if (realizedBy != null) o["realized_by"] = realizedBy
    return mk(o)
}

// -- Change One: the ordinal (tick) temporal unit --
private fun v108() {
    val P = cro(listOf(sym("occurrent:a")), listOf(sym("occurrent:b")),
        "temporal" to linkedMapOf<String, Any?>(
            "minimum_delay" to 0L, "maximum_delay" to 5L, "unit" to "ticks"),
        "modality" to "sufficient")
    val (okS, whyS) = Schema.validateSchema(P); assertTrue(okS, whyS.toString())
    val (okM, whyM) = Semantics.validateSemantics(P); assertTrue(okM, whyM.toString())
}

private fun v109() {
    val P = cro(listOf(sym("occurrent:a")), listOf(sym("occurrent:b")),
        "temporal" to linkedMapOf<String, Any?>(
            "minimum_delay" to 2L, "maximum_delay" to 5L, "unit" to "ticks"))
    assertTrue(Semantics.admissible(P, 3.0), "3 ticks must be inside [2, 5]")
    assertTrue(Semantics.admissible(P, 2.0) && Semantics.admissible(P, 5.0),
        "the tick window is inclusive at both ends")
    assertTrue(!Semantics.admissible(P, 6.0) && !Semantics.admissible(P, 1.0),
        "ticks outside [2, 5] must not be admissible")
}

private fun v110() {
    val tickWin = linkedMapOf<String, Any?>(
        "minimum_delay" to 0L, "maximum_delay" to 5L, "unit" to "ticks")
    val wallWin = linkedMapOf<String, Any?>(
        "minimum_delay" to 0L, "maximum_delay" to 5L, "unit" to "seconds")
    assertTrue(Semantics.delayWithinWindow(
        linkedMapOf("duration" to 3L, "unit" to "ticks"), tickWin),
        "a tick delay must fall within a tick window")
    assertTrue(!Semantics.delayWithinWindow(
        linkedMapOf("duration" to 1L, "unit" to "ticks"), wallWin),
        "a tick delay is never within a wall-clock window")
    assertTrue(!Semantics.delayWithinWindow(
        linkedMapOf("duration" to 1L, "unit" to "seconds"), tickWin),
        "a wall-clock delay is never within a tick window")
    val a = linkedMapOf<String, Any?>(
        "causes" to listOf(sym("occurrent:a")), "effects" to listOf(sym("occurrent:b")),
        "temporal" to tickWin, "modality" to "sufficient")
    val b = linkedMapOf<String, Any?>(
        "causes" to listOf(sym("occurrent:a")), "effects" to listOf(sym("occurrent:b")),
        "temporal" to wallWin, "modality" to "preventive")
    assertTrue(!Semantics.conflicts(a, b), "disjoint dimensions -> no overlap")
    var refused = false
    try { Semantics.toSeconds(1, "ticks") } catch (e: Exception) { refused = true }
    assertTrue(refused, "to_seconds accepted ticks")
}

private fun v111() {
    fun croWith(temporal: JObj): JObj = linkedMapOf(
        "type" to "causal_relation_object", "causes" to listOf(sym("occurrent:a")),
        "effects" to listOf(sym("occurrent:b")), "modality" to "sufficient",
        "temporal" to temporal)
    val tick = croWith(linkedMapOf("minimum_delay" to 0L, "maximum_delay" to 1L, "unit" to "ticks"))
    val secs = croWith(linkedMapOf("minimum_delay" to 0L, "maximum_delay" to 1L, "unit" to "seconds"))
    assertTrue(Canonical.identify(tick) != Canonical.identify(secs), "the unit is identity-bearing")
    // a wall-clock record's identity is UNCHANGED under 3.0.0 (pinned 2.0.0 value)
    assertTrue(Canonical.identify(secs) ==
        "causal_relation_object:d8daf899daa3ee03caa6b1425cc6d4d33cef20d951e1203ffd35df29857aa43c",
        "the pinned 2.0.0 identifier must hold: got ${Canonical.identify(secs)}")
}

// -- Change Two: the managed cross-stratal seam (eighteenth kind) --
private fun v112() {
    val (sm, omap, smap) = seamFixture(14, 4, "unmodeled")
    val (okS, whyS) = Schema.validateSchema(sm); assertTrue(okS, whyS.toString())
    val (okM, whyM) = Semantics.validateSemantics(sm); assertTrue(okM, whyM.toString())
    val (okW, whyW) = Semantics.seamWellformed(sm, omap, smap); assertTrue(okW, whyW)
}

private fun v113() {
    val (a, _, _) = seamFixture(14, 4, "unmodeled")
    val (b, omap, smap) = seamFixture(14, 4, "absent")
    val (okS, whyS) = Schema.validateSchema(b); assertTrue(okS, whyS.toString())
    val (okW, whyW) = Semantics.seamWellformed(b, omap, smap); assertTrue(okW, whyW)
    assertTrue(a["id"] != b["id"], "mechanism_status must be identity-bearing")
}

private fun v114() {
    val (drawn, omap, smap) = seamFixture(14, 4, "unmodeled", listOf(9, 7, 6, 5))
    val (okS, whyS) = Schema.validateSchema(drawn); assertTrue(okS, whyS.toString())
    val (okW, whyW) = Semantics.seamWellformed(drawn, omap, smap); assertTrue(okW, whyW)
    val (bad, omap2, smap2) = seamFixture(14, 4, "absent", listOf(9, 7, 6, 5))
    val (okM, whyM) = Semantics.validateSemantics(bad)
    assertTrue(!okM && whyM.any { it.contains("contradictory_seam") },
        "semantics must reject the drawn 'absent' seam: ${whyM}")
    assertTrue(!Semantics.seamWellformed(bad, omap2, smap2).first,
        "the drawn 'absent' seam must be malformed")
}

private fun v115() {
    val (sm, omap, smap) = seamFixture(14, 4, "unmodeled")
    val s = neuro()
    assertTrue(Semantics.seamHome(sm, omap, smap) == s[14]!!["id"],
        "home must be the coarsest (max ordinal) stratum")
}

private fun v116() {
    val (adj, o1, s1) = seamFixture(6, 5, "unmodeled")   // adjacent (gap 1)
    assertTrue(!Semantics.seamWellformed(adj, o1, s1).first,
        "adjacent endpoints must be malformed")
    val (co, o2, s2) = seamFixture(6, 6, "unmodeled")    // co-stratal (gap 0)
    assertTrue(!Semantics.seamWellformed(co, o2, s2).first,
        "co-stratal endpoints must be malformed")
    val (sm, _, _) = seamFixture(14, 4, "unmodeled")
    assertTrue((sm["id"] as String).startsWith("cross_stratal_seam:"),
        "a seam must mint in the new identity scheme")
}

// -- Change Three: the realized_by reference --
private fun v117() {
    val c = conduitRealized("causal_relation_object:" + "a".repeat(64))
    val (okS, whyS) = Schema.validateSchema(c); assertTrue(okS, whyS.toString())
    val c2 = conduitRealized("native:region_stratum_predict")
    val (okS2, whyS2) = Schema.validateSchema(c2); assertTrue(okS2, whyS2.toString())  // native scheme legal
}

private fun v118() {
    val bound = conduitRealized("native:region_stratum_predict")
    val unbound = conduitRealized()
    assertTrue(bound["id"] != unbound["id"], "realized_by must be identity-bearing")
    // an unbound conduit's identity is UNCHANGED under 3.0.0 (pinned 2.0.0 value)
    assertTrue(unbound["id"] ==
        "conduit:dc4af3b1a24f0560d5ebcee488779f06ab3c78301cfb9d0c7edff80bc62e27a6",
        "the pinned 2.0.0 identifier must hold: got ${unbound["id"]}")
}

private fun v119() {
    val unbound = conduitRealized()
    val (okS, whyS) = Schema.validateSchema(unbound); assertTrue(okS, whyS.toString())  // unbound is legal
    val bad = LinkedHashMap(unbound)
    bad["realized_by"] = "not-a-scheme-qualified-reference"
    assertTrue(!Schema.validateSchema(bad, "conduit").first,
        "a malformed realized_by reference must be rejected")
}

// ===========================================================================
// V120 - V137: the 4.0.0 additions (attitude, predicted_occurrence,
// prediction_error)
// ===========================================================================
private fun attitude(holder: String, attitudeType: String, content: String): JObj =
    mk(linkedMapOf("type" to "attitude", "holder" to holder,
        "attitude_type" to attitudeType, "content" to content))

private fun predicted(instantiates: String, interval: JObj, predictor: String,
                      strength: Double? = null): JObj {
    val o = linkedMapOf<String, Any?>(
        "type" to "predicted_occurrence", "instantiates" to instantiates,
        "interval" to interval, "predictor" to predictor)
    if (strength != null) o["strength"] = strength
    return mk(o)
}

private fun predictionError(predictedId: String, discrepancy: Double,
                            observed: String? = null): JObj {
    val o = linkedMapOf<String, Any?>(
        "type" to "prediction_error", "predicted" to predictedId,
        "discrepancy" to discrepancy)
    if (observed != null) o["observed"] = observed
    return mk(o)
}

private fun tickWindow(startTick: Int, endTick: Int? = null): JObj {
    val iv = linkedMapOf<String, Any?>("start_tick" to startTick.toLong())
    if (endTick != null) iv["end_tick"] = endTick.toLong()
    return iv
}

private fun predictorId(): String {
    val c = cnt("forecasting_mind")
    return individual(c["id"] as String, designator = "predictor_p")["id"] as String
}

private fun believerId(designator: String = "holder_h"): String {
    val c = cnt("believing_mind")
    return individual(c["id"] as String, designator = designator)["id"] as String
}

// -- Group X: prediction and prediction error (Section A) --
private fun v120() {
    val o = occ("rainfall_begins")
    val p = predicted(o["id"] as String, tickWindow(3, 8), predictorId())
    val (okS, whyS) = Schema.validateSchema(p); assertTrue(okS, whyS.toString())
    val (okM, whyM) = Semantics.validateSemantics(p); assertTrue(okM, whyM.toString())
    assertTrue((p["id"] as String).startsWith("predicted_occurrence:"),
        "a forecast must mint in the new identity scheme")
    val report = Canonical.identify(linkedMapOf(
        "type" to "token_occurrence", "instantiates" to o["id"],
        "interval" to tickWindow(3, 8)), "token_occurrence")
    assertTrue(p["id"] != report, "a forecast is not a report")
    assertTrue(report.startsWith("token_occurrence:"), "the report keeps its own scheme")
}

private fun v121() {
    val o = occ("rainfall_begins")
    val wall = linkedMapOf<String, Any?>(
        "start" to "2026-07-23T00:00:00Z", "end" to "2026-07-24T00:00:00Z")
    val who = predictorId()
    val withStrength = predicted(o["id"] as String, wall, who, strength = 0.8)
    val without = predicted(o["id"] as String, wall, who)
    for (p in listOf(withStrength, without)) {
        val (okS, whyS) = Schema.validateSchema(p); assertTrue(okS, whyS.toString())
        val (okM, whyM) = Semantics.validateSemantics(p); assertTrue(okM, whyM.toString())
    }
    assertTrue(withStrength["id"] != without["id"], "strength must be identity-bearing")
}

private fun v122() {
    val o = occ("rainfall_begins")
    val bad = mk(linkedMapOf("type" to "predicted_occurrence", "instantiates" to o["id"],
        "interval" to tickWindow(3)))
    val (ok, why) = Schema.validateSchema(bad, "predicted_occurrence")
    assertTrue(!ok && why.any { it.contains("predictor") }, "expected predictor error: ${why}")
}

private fun v123() {
    val o = occ("rainfall_begins")
    val iv = linkedMapOf<String, Any?>("start" to "2026-07-23T00:00:00Z", "start_tick" to 3L)
    val both = predicted(o["id"] as String, iv, predictorId())
    val (okS, whyS) = Schema.validateSchema(both); assertTrue(okS, whyS.toString())
    val (okM, whyM) = Semantics.validateSemantics(both)
    assertTrue(!okM && whyM.any { it.contains("dimension_conflict") },
        "semantics must reject both dimensions: ${whyM}")
}

private fun v124() {
    val o = occ("rainfall_begins")
    val p = predicted(o["id"] as String, linkedMapOf("start" to "2026-07-23T00:00:00Z"), predictorId())
    val t = token(o["id"] as String, linkedMapOf("start" to "2026-07-23T06:00:00Z"))
    val err = predictionError(p["id"] as String, 0.0, observed = t["id"] as String)
    val (okS, whyS) = Schema.validateSchema(err); assertTrue(okS, whyS.toString())
    val (okM, whyM) = Semantics.validateSemantics(err); assertTrue(okM, whyM.toString())
    assertTrue(!Semantics.predictionPairingMismatch(err, p, t),
        "a matching observation is not a mismatch")
}

private fun v125() {
    val o = occ("rainfall_begins")
    val p = predicted(o["id"] as String, linkedMapOf("start" to "2026-07-23T00:00:00Z"), predictorId())
    val err = predictionError(p["id"] as String, -1.0)
    val (okS, whyS) = Schema.validateSchema(err); assertTrue(okS, whyS.toString())
    val (okM, whyM) = Semantics.validateSemantics(err); assertTrue(okM, whyM.toString())
    assertTrue(!err.containsKey("observed"), "observed must be absent")
    assertTrue(!Semantics.predictionPairingMismatch(err, p, null),
        "an unfulfilled prediction is not a mismatch")
}

private fun v126() {
    val o = occ("rainfall_begins")
    val p = predicted(o["id"] as String, tickWindow(0), predictorId())
    val bad = mk(linkedMapOf("type" to "prediction_error", "predicted" to p["id"]))
    val (ok, why) = Schema.validateSchema(bad, "prediction_error")
    assertTrue(!ok && why.any { it.contains("discrepancy") }, "expected discrepancy error: ${why}")
}

private fun v127() {
    val o = occ("rainfall_begins"); val other = occ("snowfall_begins")
    val p = predicted(o["id"] as String, linkedMapOf("start" to "2026-07-23T00:00:00Z"), predictorId())
    val t = token(other["id"] as String, linkedMapOf("start" to "2026-07-23T06:00:00Z"))
    val err = predictionError(p["id"] as String, 1.0, observed = t["id"] as String)
    val (okS, whyS) = Schema.validateSchema(err); assertTrue(okS, whyS.toString())
    assertTrue(Semantics.predictionPairingMismatch(err, p, t), "must surface a pairing mismatch")
}

// -- Group Y: attitude and theory of mind (Section B) --
private fun v128() {
    val (st, _) = stateFixture("quantity", linkedMapOf("quantity" to 15.0, "unit" to "ug/dL"), "ug/dL")
    val att = attitude(believerId(), "believes", st["id"] as String)
    val (okS, whyS) = Schema.validateSchema(att); assertTrue(okS, whyS.toString())
    val (okM, whyM) = Semantics.validateSemantics(att); assertTrue(okM, whyM.toString())
}

private fun v129() {
    val a = occ("switch_pressed"); val b = occ("light_on")
    val actual = cro(listOf(a["id"] as String), listOf(b["id"] as String), "modality" to "sufficient")
    val believed = cro(listOf(a["id"] as String), listOf(b["id"] as String), "modality" to "preventive")
    assertTrue(Semantics.conflicts(believed, actual), "the CLAIMS contradict")
    val att = attitude(believerId(), "believes", believed["id"] as String)
    val (okS, whyS) = Schema.validateSchema(att); assertTrue(okS, whyS.toString())
    val (okM, whyM) = Semantics.validateSemantics(att); assertTrue(okM, whyM.toString())  // validity unaffected
    val s = InMemoryStore()
    s.put(a); s.put(b); s.put(actual); s.put(att)
    assertTrue(s.gaps("conflict").isEmpty(), "Rule 25: NO conflict raised")
}

private fun v130() {
    val o = occ("rainfall_begins")
    val att = attitude(believerId(), "desires", o["id"] as String)
    val (okS, whyS) = Schema.validateSchema(att); assertTrue(okS, whyS.toString())
    val (okM, whyM) = Semantics.validateSemantics(att); assertTrue(okM, whyM.toString())
}

private fun v131() {
    val o = occ("press_button")
    val att = attitude(believerId(), "intends", o["id"] as String)
    val (okS, whyS) = Schema.validateSchema(att); assertTrue(okS, whyS.toString())
    val (okM, whyM) = Semantics.validateSemantics(att); assertTrue(okM, whyM.toString())
}

private fun v132() {
    val (st, _) = stateFixture("boolean", linkedMapOf("boolean" to true))
    val inner = attitude(believerId("holder_b"), "believes", st["id"] as String)
    val outer = attitude(believerId("holder_a"), "believes", inner["id"] as String)
    for (att in listOf(inner, outer)) {
        val (okS, whyS) = Schema.validateSchema(att); assertTrue(okS, whyS.toString())
        val (okM, whyM) = Semantics.validateSemantics(att); assertTrue(okM, whyM.toString())
    }
    assertTrue(outer["id"] != inner["id"], "ids must differ")
    assertTrue(outer["content"] == inner["id"], "the outer content must be the inner attitude")
}

private fun v133() {
    val o = occ("rainfall_begins")
    val bad = mk(linkedMapOf("type" to "attitude", "holder" to believerId(),
        "attitude_type" to "suspects", "content" to o["id"]))
    val (ok, why) = Schema.validateSchema(bad, "attitude")
    assertTrue(!ok && why.any { it.contains("attitude_type") }, "expected attitude_type error: ${why}")
}

private fun v134() {
    val o = occ("rainfall_begins")
    val bad = mk(linkedMapOf("type" to "attitude", "holder" to believerId(),
        "attitude_type" to "believes", "content" to o["id"], "strength" to 0.9))
    val (ok, why) = Schema.validateSchema(bad, "attitude")
    assertTrue(!ok && why.any { it.contains("strength") }, "expected strength error: ${why}")
}

private fun v135() {
    val o = occ("rainfall_begins")
    val att = attitude(believerId(), "expects", o["id"] as String)
    val a = signed("assertion", linkedMapOf("about" to att["id"],
        "evidence_type" to "observation", "confidence" to 0.9), "signer")
    val (okS, whyS) = Schema.validateSchema(a); assertTrue(okS, whyS.toString())
    assertTrue(Signing.verifyRecord(a), "the assertion must verify")
    // the HOLDER (a modeled agent) and the SOURCE (a signing key) differ
    val holder = att["holder"] as String
    assertTrue(holder.substringBefore(":") == "token_individual", "the holder must be a modeled agent")
    val source = a["source"] as String
    assertTrue(source.substringBefore(":") == "ed25519", "the source must be a signing key")
    assertTrue(holder != source, "holder and source are different things")
}

private fun v136() {
    // the V111 wall-clock Causal Relation Object, re-pinned under 4.0.0
    val secs = linkedMapOf<String, Any?>(
        "type" to "causal_relation_object", "causes" to listOf(sym("occurrent:a")),
        "effects" to listOf(sym("occurrent:b")), "modality" to "sufficient",
        "temporal" to linkedMapOf("minimum_delay" to 0L, "maximum_delay" to 1L, "unit" to "seconds"))
    assertTrue(Canonical.identify(secs) ==
        "causal_relation_object:d8daf899daa3ee03caa6b1425cc6d4d33cef20d951e1203ffd35df29857aa43c",
        "the 3.0.0 wall-clock identifier must hold under 4.0.0")
    // the V118 unbound conduit, re-pinned under 4.0.0
    val unbound = conduitRealized()
    assertTrue(unbound["id"] ==
        "conduit:dc4af3b1a24f0560d5ebcee488779f06ab3c78301cfb9d0c7edff80bc62e27a6",
        "the 3.0.0 unbound-conduit identifier must hold under 4.0.0")
}

private fun v137() {
    val hexid = "0".repeat(64)
    // The abbreviated prefixes here are the deliberate negative tests; each is
    // assembled so it survives any whole-word re-mint pass.
    val attAbbr = "a" + "t" + "t"
    val prdAbbr = "p" + "r" + "d"
    val errAbbr = "e" + "r" + "r"
    val badAtt = linkedMapOf<String, Any?>(
        "type" to "attitude", "id" to "$attAbbr:$hexid",
        "holder" to "token_individual:$hexid", "attitude_type" to "believes",
        "content" to "state_assertion:$hexid")
    assertTrue(!Schema.validateSchema(badAtt, "attitude").first,
        "abbreviated attitude scheme must be rejected")
    val badPrd = linkedMapOf<String, Any?>(
        "type" to "predicted_occurrence", "id" to "$prdAbbr:$hexid",
        "instantiates" to "occurrent:$hexid", "interval" to tickWindow(0),
        "predictor" to "token_individual:$hexid")
    assertTrue(!Schema.validateSchema(badPrd, "predicted_occurrence").first,
        "abbreviated predicted_occurrence scheme must be rejected")
    val badErr = linkedMapOf<String, Any?>(
        "type" to "prediction_error", "id" to "$errAbbr:$hexid",
        "predicted" to "predicted_occurrence:$hexid", "discrepancy" to 0.0)
    assertTrue(!Schema.validateSchema(badErr, "prediction_error").first,
        "abbreviated prediction_error scheme must be rejected")
    val wholeAtt = LinkedHashMap(badAtt); wholeAtt["id"] = "attitude:$hexid"
    val (attOk, attWhy) = Schema.validateSchema(wholeAtt, "attitude"); assertTrue(attOk, attWhy.toString())
    val wholePrd = LinkedHashMap(badPrd); wholePrd["id"] = "predicted_occurrence:$hexid"
    val (prdOk, prdWhy) = Schema.validateSchema(wholePrd, "predicted_occurrence"); assertTrue(prdOk, prdWhy.toString())
    val wholeErr = LinkedHashMap(badErr); wholeErr["id"] = "prediction_error:$hexid"
    val (errOk, errWhy) = Schema.validateSchema(wholeErr, "prediction_error"); assertTrue(errOk, errWhy.toString())
}

// ---------------------------------------------------------------------------
fun main() {
    println("causalontology-kotlin conformance run (specification 4.0.0)")
    print("internal checks (RFC 8032, RFC 8785, fixed constants) ... ")
    internalChecks()
    println("ok")
    val vectors: List<Pair<Int, () -> Unit>> = listOf(
        1 to ::v01, 2 to ::v02, 3 to ::v03, 4 to ::v04, 5 to ::v05, 6 to ::v06,
        7 to ::v07, 8 to ::v08, 9 to ::v09, 10 to ::v10, 11 to ::v11, 12 to ::v12,
        13 to ::v13, 14 to ::v14, 15 to ::v15, 16 to ::v16, 17 to ::v17, 18 to ::v18,
        19 to ::v19, 20 to ::v20, 21 to ::v21, 22 to ::v22, 23 to ::v23, 24 to ::v24,
        25 to ::v25, 26 to ::v26, 27 to ::v27, 28 to ::v28, 29 to ::v29, 30 to ::v30,
        31 to ::v31, 32 to ::v32, 33 to ::v33, 34 to ::v34, 35 to ::v35, 36 to ::v36,
        37 to ::v37, 38 to ::v38, 39 to ::v39, 40 to ::v40, 41 to ::v41, 42 to ::v42,
        43 to ::v43, 44 to ::v44, 45 to ::v45, 46 to ::v46, 47 to ::v47, 48 to ::v48,
        49 to ::v49, 50 to ::v50, 51 to ::v51, 52 to ::v52, 53 to ::v53, 54 to ::v54,
        55 to ::v55, 56 to ::v56, 57 to ::v57, 58 to ::v58, 59 to ::v59, 60 to ::v60,
        61 to ::v61, 62 to ::v62, 63 to ::v63, 64 to ::v64, 65 to ::v65, 66 to ::v66,
        67 to ::v67, 68 to ::v68, 69 to ::v69, 70 to ::v70, 71 to ::v71, 72 to ::v72,
        73 to ::v73, 74 to ::v74, 75 to ::v75, 76 to ::v76, 77 to ::v77, 78 to ::v78,
        79 to ::v79, 80 to ::v80, 81 to ::v81, 82 to ::v82, 83 to ::v83, 84 to ::v84,
        85 to ::v85, 86 to ::v86, 87 to ::v87, 88 to ::v88, 89 to ::v89, 90 to ::v90,
        91 to ::v91, 92 to ::v92, 93 to ::v93, 94 to ::v94, 95 to ::v95, 96 to ::v96,
        97 to ::v97, 98 to ::v98, 99 to ::v99, 100 to ::v100, 101 to ::v101, 102 to ::v102,
        103 to ::v103, 104 to ::v104, 105 to ::v105, 106 to ::v106, 107 to ::v107,
        108 to ::v108, 109 to ::v109, 110 to ::v110, 111 to ::v111, 112 to ::v112,
        113 to ::v113, 114 to ::v114, 115 to ::v115, 116 to ::v116, 117 to ::v117,
        118 to ::v118, 119 to ::v119, 120 to ::v120, 121 to ::v121, 122 to ::v122,
        123 to ::v123, 124 to ::v124, 125 to ::v125, 126 to ::v126, 127 to ::v127,
        128 to ::v128, 129 to ::v129, 130 to ::v130, 131 to ::v131, 132 to ::v132,
        133 to ::v133, 134 to ::v134, 135 to ::v135, 136 to ::v136, 137 to ::v137)
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
    val total = 137
    println("-".repeat(60))
    println("${total - failures}/$total vectors passed")
    if (failures > 0) exitProcess(1)
    println("causalontology-kotlin is CONFORMANT to the suite " +
            "(vectors frozen at specification 4.0.0).")
}

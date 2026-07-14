// An in-memory conformant store, ported line-for-line from the Python
// binding's CURRENT store.py.
//
// Implements the store side of the abstract operation set (spec/store.md):
// immutable content objects with idempotent put; signed, add-only provenance
// records with a "quarantined" holding pen for unverifiable writes;
// materialized enrichment views with contributors (deduplicated by canonical
// entry); retraction handling in default views (history views carry a
// "retracted" flag); succession lineage; the resolve minimum
// (label-before-alias); the deterministic cycle-breaking view rule (exclude
// the cycle-completing record with the greatest (timestamp, id)); and the
// stigmergy gap read with its five gap kinds.
package org.causalontology

val CONTENT_KINDS = setOf("occurrent", "cro", "continuant", "realizable")
val RECORD_KINDS = setOf("assertion", "enrichment", "retraction", "succession")

// An enforcing store refused a write, with the reason as the message.
class RejectedWrite(message: String) : Exception(message)

class InMemoryStore(val enforcing: Boolean = true) {

    val objects = LinkedHashMap<String, JObj>()     // id -> content object
    val records = LinkedHashMap<String, JObj>()     // id -> provenance record
    val quarantine = LinkedHashMap<String, JObj>()  // id -> record (unsigned / unverifiable)

    // ------------------------------------------------------------------ put
    // Write a content object; idempotent; returns the identifier.
    fun put(objIn: JObj, kind: String? = null): String {
        val k = kind ?: Canonical.inferKind(objIn)
        if (k !in CONTENT_KINDS) {
            throw IllegalArgumentException("put() takes content objects; use putRecord()")
        }
        val obj = LinkedHashMap(objIn)
        if (!obj.containsKey("type")) obj["type"] = k
        if (!obj.containsKey("id")) obj["id"] = Canonical.identify(obj, k)
        val id = obj["id"] as String
        if (objects.containsKey(id)) {
            return id  // immutable: identical identity is a no-op
        }
        val (okSchema, whySchema) = Schema.validateSchema(obj, k)
        if (!okSchema) throw RejectedWrite(whySchema.joinToString("; "))
        val (okSem, whySem) = Semantics.validateSemantics(obj, k)
        if (!okSem) throw RejectedWrite(whySem.joinToString("; "))
        objects[id] = obj
        return id
    }

    // Write a signed provenance record; returns the identifier.
    fun putRecord(recordIn: JObj, kind: String? = null, force: Boolean = false): String {
        val k = kind ?: Canonical.inferKind(recordIn)
        if (k !in RECORD_KINDS) {
            throw IllegalArgumentException("putRecord() takes provenance records")
        }
        val record = LinkedHashMap(recordIn)
        if (!record.containsKey("type")) record["type"] = k
        val rid = (record["id"] as? String)?.takeIf { it.isNotEmpty() }
            ?: Canonical.identify(record, k)
        record["id"] = rid
        if (records.containsKey(rid)) {
            return rid  // add-only and idempotent
        }
        if (!Signing.verifyRecord(record, k)) {
            quarantine[rid] = record
            throw RejectedWrite("unsigned or unverifiable record: quarantined")
        }
        val (ok, why) = Semantics.validateSemantics(record, k)
        if (!ok) throw RejectedWrite(why.joinToString("; "))
        if (k == "retraction" && !retractionSourceOk(record)) {
            throw RejectedWrite(
                "a retraction is valid only from the retracted record's " +
                "source or its succession lineage")
        }
        if (k == "enrichment" && enforcing && !force) {
            val field = record["field"]
            if ((field == "subsumes" || field == "part_of") && wouldCycle(record)) {
                throw RejectedWrite(
                    "would create a cycle in the materialized $field graph")
            }
        }
        records[rid] = record
        return rid
    }

    // Simulate a decentralized replica merge (no enforcement gate).
    fun forceMergeRecord(record: JObj, kind: String? = null): String =
        putRecord(record, kind, force = true)

    // ------------------------------------------------------- record queries
    private fun recordsOf(kind: String): List<JObj> =
        records.values.filter { it["type"] == kind }

    private fun retractedIds(): Set<String> =
        recordsOf("retraction").map { it["retracts"] as String }.toSet()

    private fun retractionSourceOk(retraction: JObj): Boolean {
        val target = records[retraction["retracts"]]
            ?: return true  // open world: the target may arrive later
        return retraction["source"] in lineage(target["source"] as String)
    }

    // The succession chain closure containing key (includes key).
    fun lineage(key: String): Set<String> {
        val succ = HashMap<String, String>()
        val pred = HashMap<String, String>()
        for (s in recordsOf("succession")) {
            succ[s["predecessor"] as String] = s["successor"] as String
            pred[s["successor"] as String] = s["predecessor"] as String
        }
        val chain = mutableSetOf(key)
        var cursor = key
        while (pred.containsKey(cursor)) {
            cursor = pred[cursor]!!
            if (cursor in chain) break  // guard against pathological loops
            chain.add(cursor)
        }
        cursor = key
        while (succ.containsKey(cursor)) {
            cursor = succ[cursor]!!
            if (cursor in chain) break
            chain.add(cursor)
        }
        return chain
    }

    fun assertionsAbout(identifier: String, includeRetracted: Boolean = false): List<JObj> {
        val retracted = retractedIds()
        val out = mutableListOf<JObj>()
        for (r in recordsOf("assertion")) {
            if (r["about"] != identifier) continue
            if (r["id"] in retracted) {
                if (includeRetracted) {
                    val flagged = LinkedHashMap(r)
                    flagged["retracted"] = true
                    out.add(flagged)
                }
                continue
            }
            out.add(r)
        }
        return out
    }

    fun enrichmentsAbout(identifier: String, includeRetracted: Boolean = false): List<JObj> {
        val retracted = retractedIds()
        val out = mutableListOf<JObj>()
        for (r in recordsOf("enrichment")) {
            if (r["about"] != identifier) continue
            if (r["id"] in retracted && !includeRetracted) continue
            out.add(r)
        }
        return out
    }

    // ------------------------------------------------- materialized views
    // (active, excluded) for subsumes/part_of after rule 13 cycle-breaking.
    fun activeTaxonomyEdges(field: String): Pair<List<JObj>, List<JObj>> {
        val retracted = retractedIds()
        val recs = recordsOf("enrichment")
            .filter { it["field"] == field && it["id"] !in retracted }
        val active = recs.toMutableList()
        val excluded = mutableListOf<JObj>()
        while (true) {
            val cyc = findCycleRecords(active)
            if (cyc.isEmpty()) break
            // Exclude the cycle-completing record with the LATEST timestamp,
            // ties broken by lexicographic record identifier (deterministic).
            var loser = cyc[0]
            for (r in cyc) {
                val cmpTs = (r["timestamp"] as String).compareTo(loser["timestamp"] as String)
                val cmpId = (r["id"] as String).compareTo(loser["id"] as String)
                if (cmpTs > 0 || (cmpTs == 0 && cmpId > 0)) loser = r
            }
            active.remove(loser)
            excluded.add(loser)
        }
        return Pair(active, excluded)
    }

    // A depth-first search that returns the records along a path into a cycle
    // (mirrors store.py's _find_cycle_records, including iteration order).
    private fun findCycleRecords(recs: List<JObj>): List<JObj> {
        val edges = LinkedHashMap<String, MutableList<Pair<String, JObj>>>()
        for (r in recs) {
            edges.getOrPut(r["about"] as String) { mutableListOf() }
                .add(Pair(r["entry"] as String, r))
        }
        val state = HashMap<String, Int>()
        val cycle = mutableListOf<JObj>()

        fun dfs(node: String, pathRecords: List<JObj>): Boolean {
            state[node] = 1
            for ((nxt, rec) in edges[node] ?: emptyList()) {
                if (state.getOrElse(nxt) { 0 } == 1) {
                    cycle.addAll(pathRecords + rec)
                    return true
                }
                if (state.getOrElse(nxt) { 0 } == 0) {
                    if (dfs(nxt, pathRecords + rec)) return true
                }
            }
            state[node] = 2
            return false
        }

        for (start in edges.keys.toList()) {
            if (state.getOrElse(start) { 0 } == 0 && dfs(start, emptyList())) {
                return cycle
            }
        }
        return emptyList()
    }

    private fun wouldCycle(record: JObj): Boolean {
        val retracted = retractedIds()
        val recs = recordsOf("enrichment")
            .filter { it["field"] == record["field"] && it["id"] !in retracted }
        return findCycleRecords(recs + listOf(record)).isNotEmpty()
    }

    // The object with its materialized enrichment sets and contributors.
    fun get(identifier: String, view: String = "default"): JObj? {
        val obj = objects[identifier] ?: return null
        val includeRetracted = (view == "history")
        val excludedIds = mutableSetOf<String>()
        for (field in listOf("subsumes", "part_of")) {
            val (_, excluded) = activeTaxonomyEdges(field)
            excluded.forEach { excludedIds.add(it["id"] as String) }
        }
        // field -> canonical entry key -> {entry, contributors}
        val fields = LinkedHashMap<String, LinkedHashMap<String, MutableMap<String, Any?>>>()
        for (rec in enrichmentsAbout(identifier, includeRetracted)) {
            if (rec["id"] in excludedIds && view != "history") continue
            // Contributors deduplicate by the canonical (RFC 8785) form of the
            // entry - the equivalent of Python's sorted-items tuple key.
            val entryKey = Jcs.serialize(rec["entry"])
            val slot = fields.getOrPut(rec["field"] as String) { LinkedHashMap() }
            val bucket = slot.getOrPut(entryKey) {
                linkedMapOf("entry" to rec["entry"], "contributors" to mutableListOf<JObj>())
            }
            @Suppress("UNCHECKED_CAST")
            (bucket["contributors"] as MutableList<JObj>).add(
                linkedMapOf("source" to rec["source"], "timestamp" to rec["timestamp"]))
        }
        val enrichments = LinkedHashMap<String, Any?>()
        for ((f, slot) in fields) enrichments[f] = slot.values.toList()
        if (view == "raw") {
            return linkedMapOf("object" to obj)
        }
        return linkedMapOf("object" to obj, "enrichments" to enrichments)
    }

    // -------------------------------------------------------------- resolve
    private fun canonLabel(text: String): String =
        text.trim().lowercase().split(Regex("\\s+")).filter { it.isNotEmpty() }
            .joinToString("_")

    private fun normAlias(text: String): String =
        text.split(Regex("\\s+")).filter { it.isNotEmpty() }.joinToString(" ").lowercase()

    // The conformance minimum: exact label, then alias, then nothing.
    fun resolve(text: String, lang: String? = null): List<String> {
        val labelHits = mutableListOf<String>()
        val aliasHits = mutableListOf<String>()
        val wantedLabel = canonLabel(text)
        val wantedAlias = normAlias(text)
        val retracted = retractedIds()
        for ((oid, obj) in objects) {
            if (obj["type"] !in listOf("occurrent", "continuant")) continue
            if (obj["label"] == wantedLabel) {
                labelHits.add(oid)
                continue
            }
            for (rec in recordsOf("enrichment")) {
                if (rec["about"] != oid || rec["field"] != "aliases") continue
                if (rec["id"] in retracted) continue
                val entry = asObj(rec["entry"])
                if (lang != null && entry["lang"] != lang) continue
                if (normAlias(entry["text"] as? String ?: "") == wantedAlias) {
                    aliasHits.add(oid)
                    break
                }
            }
        }
        return labelHits + aliasHits
    }

    // ---------------------------------------------------------------- gaps
    // The stigmergy read. Gap kinds per spec/store.md.
    fun gaps(kind: String? = null): List<JObj> {
        val out = mutableListOf<JObj>()
        val refined = mutableSetOf<String>()
        for (obj in objects.values) {
            val refines = obj["refines"] as? String
            if (obj["type"] == "cro" && !refines.isNullOrEmpty()) {
                val parent = objects[refines]
                if (parent != null) {
                    val (ok, _) = Semantics.refinementValid(obj, parent)
                    if (ok) refined.add(parent["id"] as String)
                }
            }
        }
        for ((oid, obj) in objects) {
            if (obj["type"] != "cro") continue
            // missing_field: lacking the temporal window or the modality -
            // mechanism and context may legitimately stay unspecified forever
            // (empty_mechanism is its own kind; absent context = context-free).
            if ((!obj.containsKey("temporal") || !obj.containsKey("modality")) &&
                oid !in refined) {
                out.add(linkedMapOf(
                    "id" to oid, "kind" to "missing_field",
                    "missing" to Semantics.isPartial(obj).second))
            }
            val mech = obj["mechanism"]
            if (!obj.containsKey("mechanism") || (mech is List<*> && mech.isEmpty())) {
                if (oid !in refined) {
                    out.add(linkedMapOf("id" to oid, "kind" to "empty_mechanism"))
                }
            }
        }
        for (field in listOf("subsumes", "part_of")) {
            val (_, excluded) = activeTaxonomyEdges(field)
            for (rec in excluded) {
                out.add(linkedMapOf(
                    "id" to rec["id"], "kind" to "inconsistent_hierarchy",
                    "note" to ("excluded by the deterministic " +
                               "cycle-breaking view rule")))
            }
        }
        // dangling_reference: a reference to an object absent from the store -
        // the red link that says "this page is wanted".
        for ((oid, obj) in objects) {
            val refs = mutableListOf<String?>()
            if (obj["type"] == "cro") {
                for (key in listOf("causes", "effects", "context", "mechanism")) {
                    val vals = obj[key] as? List<*> ?: emptyList<Any?>()
                    for (v in vals) refs.add(v as? String)
                }
                val refines = obj["refines"] as? String
                if (!refines.isNullOrEmpty()) refs.add(refines)
            } else if (obj["type"] == "realizable") {
                refs.add(obj["bearer"] as? String)
            }
            for (ref in refs) {
                if (!ref.isNullOrEmpty() && !objects.containsKey(ref)) {
                    out.add(linkedMapOf(
                        "id" to oid, "kind" to "dangling_reference", "ref" to ref))
                }
            }
        }
        // conflict: pairs of claims satisfying the formal test (rule 6).
        val cros = objects.values.filter { it["type"] == "cro" }
        for (i in cros.indices) {
            for (j in i + 1 until cros.size) {
                if (Semantics.conflicts(cros[i], cros[j])) {
                    out.add(linkedMapOf(
                        "kind" to "conflict",
                        "a" to cros[i]["id"], "b" to cros[j]["id"]))
                }
            }
        }
        return if (kind == null) out else out.filter { it["kind"] == kind }
    }
}

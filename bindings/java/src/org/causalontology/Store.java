package org.causalontology;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * An in-memory conformant store - the Java port of the Python binding's
 * InMemoryStore.
 *
 * Implements the store side of the abstract operation set (spec/store.md):
 * immutable content objects with idempotent put; signed, add-only
 * provenance records; materialized enrichment views with contributors;
 * retraction handling in default views; succession lineage; the resolve
 * minimum; the deterministic cycle-breaking view rule; and the stigmergy
 * gap read.
 */
public final class Store {

    /** An enforcing store refused a write; the reason is the message. */
    public static final class RejectedWrite extends RuntimeException {
        public RejectedWrite(String message) {
            super(message);
        }
    }

    /** The active/excluded split of a taxonomy field's enrichment records. */
    public static final class Taxonomy {
        public final List<Map<String, Object>> active;
        public final List<Map<String, Object>> excluded;

        Taxonomy(List<Map<String, Object>> active,
                 List<Map<String, Object>> excluded) {
            this.active = active;
            this.excluded = excluded;
        }
    }

    private static final Set<String> CONTENT_KINDS =
        Set.of("occurrent", "causal_relation_object", "continuant",
               "realizable", "stratum", "bridge", "cross_stratal_seam",
               "port", "conduit", "quality", "token_individual",
               "token_occurrence", "state_assertion", "token_causal_claim",
               "attitude", "predicted_occurrence", "prediction_error");
    private static final Set<String> RECORD_KINDS =
        Set.of("assertion", "enrichment", "retraction", "succession");

    /** Whether the enforcing tier's cycle gate is applied on writes. */
    public final boolean enforcing;

    /** id -> content object (insertion order preserved). */
    public final Map<String, Map<String, Object>> objects =
        new LinkedHashMap<>();

    /** id -> provenance record (insertion order preserved). */
    public final Map<String, Map<String, Object>> records =
        new LinkedHashMap<>();

    /** id -> record that arrived unsigned or unverifiable. */
    public final Map<String, Map<String, Object>> quarantine =
        new LinkedHashMap<>();

    public Store() {
        this(true);
    }

    public Store(boolean enforcing) {
        this.enforcing = enforcing;
    }

    // ------------------------------------------------------------------ put

    /** Write a content object; idempotent; returns the identifier. */
    public String put(Map<String, Object> objIn) {
        return put(objIn, null);
    }

    /** Write a content object; idempotent; returns the identifier. */
    public String put(Map<String, Object> objIn, String kind) {
        String k = kind != null ? kind : Canonical.inferKind(objIn);
        if (!CONTENT_KINDS.contains(k)) {
            throw new IllegalArgumentException(
                "put() takes content objects; use putRecord()");
        }
        Map<String, Object> obj = new LinkedHashMap<>(objIn);
        obj.putIfAbsent("type", k);
        if (!obj.containsKey("id")) {
            obj.put("id", Canonical.identify(obj, k));
        }
        String id = (String) obj.get("id");
        if (objects.containsKey(id)) {
            return id; // immutable: identical identity is a no-op
        }
        Validation schema = SchemaValidator.validateSchema(obj, k);
        if (!schema.ok) {
            throw new RejectedWrite(schema.reason());
        }
        Validation semantics = Semantics.validateSemantics(obj, k);
        if (!semantics.ok) {
            throw new RejectedWrite(semantics.reason());
        }
        objects.put(id, obj);
        return id;
    }

    /** Write a signed provenance record; returns the identifier. */
    public String putRecord(Map<String, Object> recIn) {
        return putRecordInternal(recIn, null, false);
    }

    /** Write a signed provenance record; returns the identifier. */
    public String putRecord(Map<String, Object> recIn, String kind) {
        return putRecordInternal(recIn, kind, false);
    }

    /** Simulate a decentralized replica merge (no enforcement gate). */
    public String forceMergeRecord(Map<String, Object> recIn) {
        return putRecordInternal(recIn, null, true);
    }

    /** Simulate a decentralized replica merge (no enforcement gate). */
    public String forceMergeRecord(Map<String, Object> recIn, String kind) {
        return putRecordInternal(recIn, kind, true);
    }

    private String putRecordInternal(Map<String, Object> recIn, String kind,
                                     boolean force) {
        String k = kind != null ? kind : Canonical.inferKind(recIn);
        if (!RECORD_KINDS.contains(k)) {
            throw new IllegalArgumentException(
                "putRecord() takes provenance records");
        }
        Map<String, Object> rec = new LinkedHashMap<>(recIn);
        rec.putIfAbsent("type", k);
        String rid;
        if (rec.get("id") instanceof String && !((String) rec.get("id")).isEmpty()) {
            rid = (String) rec.get("id");
        } else {
            rid = Canonical.identify(rec, k);
        }
        rec.put("id", rid);
        if (records.containsKey(rid)) {
            return rid; // add-only and idempotent
        }
        if (!Signing.verifyRecord(rec, k)) {
            quarantine.put(rid, rec);
            throw new RejectedWrite(
                "unsigned or unverifiable record: quarantined");
        }
        Validation semantics = Semantics.validateSemantics(rec, k);
        if (!semantics.ok) {
            throw new RejectedWrite(semantics.reason());
        }
        if (k.equals("retraction") && !retractionSourceOk(rec)) {
            throw new RejectedWrite(
                "a retraction is valid only from the retracted record's "
                + "source or its succession lineage");
        }
        if (k.equals("enrichment") && enforcing && !force) {
            Object field = rec.get("field");
            if (("subsumes".equals(field) || "part_of".equals(field))
                    && wouldCycle(rec)) {
                throw new RejectedWrite(
                    "would create a cycle in the materialized " + field
                    + " graph");
            }
        }
        records.put(rid, rec);
        return rid;
    }

    // ------------------------------------------------------- record queries

    private List<Map<String, Object>> recordsOf(String kind) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> rec : records.values()) {
            if (kind.equals(rec.get("type"))) {
                out.add(rec);
            }
        }
        return out;
    }

    private Set<Object> retractedIds() {
        Set<Object> out = new HashSet<>();
        for (Map<String, Object> rec : recordsOf("retraction")) {
            out.add(rec.get("retracts"));
        }
        return out;
    }

    private boolean retractionSourceOk(Map<String, Object> retraction) {
        Map<String, Object> target = records.get(retraction.get("retracts"));
        if (target == null) {
            return true; // open world: the target may arrive later
        }
        return lineage((String) target.get("source"))
            .contains(retraction.get("source"));
    }

    /** The succession chain closure containing key (includes key). */
    public Set<String> lineage(String key) {
        Map<String, String> successorOf = new HashMap<>();
        Map<String, String> predecessorOf = new HashMap<>();
        for (Map<String, Object> s : recordsOf("succession")) {
            successorOf.put((String) s.get("predecessor"),
                            (String) s.get("successor"));
            predecessorOf.put((String) s.get("successor"),
                              (String) s.get("predecessor"));
        }
        Set<String> chain = new HashSet<>();
        chain.add(key);
        String cursor = key;
        while (predecessorOf.containsKey(cursor)) {
            cursor = predecessorOf.get(cursor);
            if (!chain.add(cursor)) {
                break; // guard against a malformed succession cycle
            }
        }
        cursor = key;
        while (successorOf.containsKey(cursor)) {
            cursor = successorOf.get(cursor);
            if (!chain.add(cursor)) {
                break; // guard against a malformed succession cycle
            }
        }
        return chain;
    }

    /** The non-retracted assertions about an identifier. */
    public List<Map<String, Object>> assertionsAbout(String identifier) {
        return assertionsAbout(identifier, false);
    }

    /** Assertions about an identifier; retracted ones flagged on request. */
    public List<Map<String, Object>> assertionsAbout(String identifier,
                                                     boolean includeRetracted) {
        Set<Object> retracted = retractedIds();
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> rec : recordsOf("assertion")) {
            if (!identifier.equals(rec.get("about"))) {
                continue;
            }
            if (retracted.contains(rec.get("id"))) {
                if (includeRetracted) {
                    Map<String, Object> copy = new LinkedHashMap<>(rec);
                    copy.put("retracted", Boolean.TRUE);
                    out.add(copy);
                }
                continue;
            }
            out.add(rec);
        }
        return out;
    }

    /** The non-retracted enrichments about an identifier. */
    public List<Map<String, Object>> enrichmentsAbout(String identifier) {
        return enrichmentsAbout(identifier, false);
    }

    /** Enrichments about an identifier; retracted included on request. */
    public List<Map<String, Object>> enrichmentsAbout(String identifier,
                                                      boolean includeRetracted) {
        Set<Object> retracted = retractedIds();
        List<Map<String, Object>> out = new ArrayList<>();
        for (Map<String, Object> rec : recordsOf("enrichment")) {
            if (!identifier.equals(rec.get("about"))) {
                continue;
            }
            if (retracted.contains(rec.get("id")) && !includeRetracted) {
                continue;
            }
            out.add(rec);
        }
        return out;
    }

    // --------------------------------------------------- materialized views

    /**
     * (active, excluded) for subsumes/part_of after the rule 13
     * deterministic cycle-breaking: repeatedly exclude the
     * cycle-completing record with the LATEST timestamp, ties broken by
     * lexicographic record identifier.
     */
    public Taxonomy activeTaxonomyEdges(String field) {
        Set<Object> retracted = retractedIds();
        List<Map<String, Object>> active = new ArrayList<>();
        for (Map<String, Object> rec : recordsOf("enrichment")) {
            if (field.equals(rec.get("field"))
                    && !retracted.contains(rec.get("id"))) {
                active.add(rec);
            }
        }
        List<Map<String, Object>> excluded = new ArrayList<>();
        while (true) {
            List<Map<String, Object>> cycle = findCycleRecords(active);
            if (cycle.isEmpty()) {
                break;
            }
            Map<String, Object> loser = cycle.get(0);
            for (Map<String, Object> rec : cycle) {
                if (laterThan(rec, loser)) {
                    loser = rec;
                }
            }
            removeByIdentity(active, loser);
            excluded.add(loser);
        }
        return new Taxonomy(active, excluded);
    }

    private static boolean laterThan(Map<String, Object> a,
                                     Map<String, Object> b) {
        String tsA = (String) a.get("timestamp");
        String tsB = (String) b.get("timestamp");
        int byTimestamp = tsA.compareTo(tsB);
        if (byTimestamp != 0) {
            return byTimestamp > 0;
        }
        String idA = (String) a.get("id");
        String idB = (String) b.get("id");
        return idA.compareTo(idB) > 0;
    }

    private static void removeByIdentity(List<Map<String, Object>> list,
                                         Map<String, Object> element) {
        Iterator<Map<String, Object>> it = list.iterator();
        while (it.hasNext()) {
            if (it.next() == element) {
                it.remove();
                return;
            }
        }
    }

    /** Depth-first search for a cycle among about -> entry edges. */
    private static final class CycleFinder {
        final Map<Object, List<Object[]>> edges = new LinkedHashMap<>();
        final Map<Object, Integer> state = new HashMap<>();
        final List<Map<String, Object>> cycle = new ArrayList<>();

        CycleFinder(List<Map<String, Object>> recs) {
            for (Map<String, Object> rec : recs) {
                edges.computeIfAbsent(rec.get("about"),
                                      k -> new ArrayList<>())
                     .add(new Object[] {rec.get("entry"), rec});
            }
        }

        List<Map<String, Object>> find() {
            for (Object start : new ArrayList<>(edges.keySet())) {
                if (state.getOrDefault(start, 0) == 0
                        && dfs(start, new ArrayList<>())) {
                    return cycle;
                }
            }
            return new ArrayList<>();
        }

        @SuppressWarnings("unchecked")
        boolean dfs(Object node, List<Map<String, Object>> pathRecords) {
            state.put(node, 1);
            List<Object[]> outgoing = edges.get(node);
            if (outgoing != null) {
                for (Object[] pair : outgoing) {
                    Object next = pair[0];
                    Map<String, Object> rec = (Map<String, Object>) pair[1];
                    int nextState = state.getOrDefault(next, 0);
                    if (nextState == 1) {
                        cycle.addAll(pathRecords);
                        cycle.add(rec);
                        return true;
                    }
                    if (nextState == 0) {
                        List<Map<String, Object>> nextPath =
                            new ArrayList<>(pathRecords);
                        nextPath.add(rec);
                        if (dfs(next, nextPath)) {
                            return true;
                        }
                    }
                }
            }
            state.put(node, 2);
            return false;
        }
    }

    private static List<Map<String, Object>> findCycleRecords(
            List<Map<String, Object>> recs) {
        return new CycleFinder(recs).find();
    }

    private boolean wouldCycle(Map<String, Object> rec) {
        Set<Object> retracted = retractedIds();
        List<Map<String, Object>> recs = new ArrayList<>();
        for (Map<String, Object> existing : recordsOf("enrichment")) {
            if (rec.get("field").equals(existing.get("field"))
                    && !retracted.contains(existing.get("id"))) {
                recs.add(existing);
            }
        }
        recs.add(rec);
        return !findCycleRecords(recs).isEmpty();
    }

    /** The default view of an object. */
    public Map<String, Object> get(String identifier) {
        return get(identifier, "default");
    }

    /** The object with its materialized enrichments and contributors. */
    @SuppressWarnings("unchecked")
    public Map<String, Object> get(String identifier, String view) {
        Map<String, Object> obj = objects.get(identifier);
        if (obj == null) {
            return null;
        }
        boolean includeRetracted = "history".equals(view);
        Set<Object> excludedIds = new HashSet<>();
        for (String field : new String[] {"subsumes", "part_of"}) {
            for (Map<String, Object> rec : activeTaxonomyEdges(field).excluded) {
                excludedIds.add(rec.get("id"));
            }
        }
        // field -> (canonical entry key -> bucket with entry + contributors)
        Map<String, Map<String, Map<String, Object>>> fields =
            new LinkedHashMap<>();
        for (Map<String, Object> rec
                : enrichmentsAbout(identifier, includeRetracted)) {
            if (excludedIds.contains(rec.get("id"))
                    && !"history".equals(view)) {
                continue;
            }
            String fieldName = (String) rec.get("field");
            // The canonical serialization is a stable structural key for
            // the (field, entry) dedup (the Python binding's sorted tuple).
            String entryKey = Jcs.serialize(rec.get("entry"));
            Map<String, Map<String, Object>> slot =
                fields.computeIfAbsent(fieldName, f -> new LinkedHashMap<>());
            Map<String, Object> bucket = slot.get(entryKey);
            if (bucket == null) {
                bucket = new LinkedHashMap<>();
                bucket.put("entry", rec.get("entry"));
                bucket.put("contributors",
                           new ArrayList<Map<String, Object>>());
                slot.put(entryKey, bucket);
            }
            List<Map<String, Object>> contributors =
                (List<Map<String, Object>>) bucket.get("contributors");
            Map<String, Object> contributor = new LinkedHashMap<>();
            contributor.put("source", rec.get("source"));
            contributor.put("timestamp", rec.get("timestamp"));
            contributors.add(contributor);
        }
        Map<String, Object> enrichments = new LinkedHashMap<>();
        for (Map.Entry<String, Map<String, Map<String, Object>>> e
                : fields.entrySet()) {
            enrichments.put(e.getKey(), new ArrayList<>(e.getValue().values()));
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("object", obj);
        if ("raw".equals(view)) {
            return out;
        }
        out.put("enrichments", enrichments);
        return out;
    }

    // -------------------------------------------------------------- resolve

    private static String canonLabel(String text) {
        String lowered = text.trim().toLowerCase(Locale.ROOT);
        if (lowered.isEmpty()) {
            return "";
        }
        return String.join("_", lowered.split("\\s+"));
    }

    private static String normAlias(String text) {
        String trimmed = text.trim();
        if (trimmed.isEmpty()) {
            return "";
        }
        return String.join(" ", trimmed.split("\\s+"))
            .toLowerCase(Locale.ROOT);
    }

    /** The conformance minimum: exact label, then alias, then nothing. */
    public List<String> resolve(String text) {
        return resolve(text, null);
    }

    /** The conformance minimum: exact label, then alias, then nothing. */
    @SuppressWarnings("unchecked")
    public List<String> resolve(String text, String lang) {
        List<String> labelHits = new ArrayList<>();
        List<String> aliasHits = new ArrayList<>();
        String wantedLabel = canonLabel(text);
        String wantedAlias = normAlias(text);
        Set<Object> retracted = retractedIds();
        for (Map.Entry<String, Map<String, Object>> e : objects.entrySet()) {
            String oid = e.getKey();
            Map<String, Object> obj = e.getValue();
            Object type = obj.get("type");
            if (!"occurrent".equals(type) && !"continuant".equals(type)) {
                continue;
            }
            if (wantedLabel.equals(obj.get("label"))) {
                labelHits.add(oid);
                continue;
            }
            for (Map<String, Object> rec : recordsOf("enrichment")) {
                if (!oid.equals(rec.get("about"))
                        || !"aliases".equals(rec.get("field"))) {
                    continue;
                }
                if (retracted.contains(rec.get("id"))) {
                    continue;
                }
                Map<String, Object> entry =
                    (Map<String, Object>) rec.get("entry");
                if (lang != null && !lang.equals(entry.get("lang"))) {
                    continue;
                }
                String aliasText = "";
                if (entry.get("text") instanceof String) {
                    aliasText = (String) entry.get("text");
                }
                if (normAlias(aliasText).equals(wantedAlias)) {
                    aliasHits.add(oid);
                    break;
                }
            }
        }
        List<String> out = new ArrayList<>(labelHits);
        out.addAll(aliasHits);
        return out;
    }

    // ---------------------------------------------------------------- gaps

    /** The stigmergy read, unfiltered. */
    public List<Map<String, Object>> gaps() {
        return gaps(null);
    }

    /** The stigmergy read. Gap kinds per spec/store.md. */
    public List<Map<String, Object>> gaps(String kind) {
        List<Map<String, Object>> out = new ArrayList<>();

        // Parents that have at least one valid refinement in the store.
        Set<String> refined = new HashSet<>();
        for (Map<String, Object> obj : objects.values()) {
            if (!"causal_relation_object".equals(obj.get("type"))) {
                continue;
            }
            Object refinesObj = obj.get("refines");
            if (!(refinesObj instanceof String)
                    || ((String) refinesObj).isEmpty()) {
                continue;
            }
            Map<String, Object> parent = objects.get(refinesObj);
            if (parent == null) {
                continue;
            }
            if (Semantics.refinementValid(obj, parent).ok) {
                refined.add((String) parent.get("id"));
            }
        }

        for (Map.Entry<String, Map<String, Object>> e : objects.entrySet()) {
            String oid = e.getKey();
            Map<String, Object> obj = e.getValue();
            if (!"causal_relation_object".equals(obj.get("type"))) {
                continue;
            }
            // missing_field: lacking the temporal window or the modality -
            // mechanism and context may legitimately stay unspecified
            // forever (empty_mechanism is its own kind; absent context
            // means context-free).
            if ((!obj.containsKey("temporal") || !obj.containsKey("modality"))
                    && !refined.contains(oid)) {
                Map<String, Object> gap = new LinkedHashMap<>();
                gap.put("id", oid);
                gap.put("kind", "missing_field");
                gap.put("missing", Semantics.isPartial(obj));
                out.add(gap);
            }
            boolean emptyMechanism = !obj.containsKey("mechanism");
            if (!emptyMechanism && obj.get("mechanism") instanceof List
                    && ((List<?>) obj.get("mechanism")).isEmpty()) {
                emptyMechanism = true;
            }
            if (emptyMechanism && !refined.contains(oid)) {
                Map<String, Object> gap = new LinkedHashMap<>();
                gap.put("id", oid);
                gap.put("kind", "empty_mechanism");
                out.add(gap);
            }
        }

        for (String field : new String[] {"subsumes", "part_of"}) {
            for (Map<String, Object> rec : activeTaxonomyEdges(field).excluded) {
                Map<String, Object> gap = new LinkedHashMap<>();
                gap.put("id", rec.get("id"));
                gap.put("kind", "inconsistent_hierarchy");
                gap.put("note", "excluded by the deterministic "
                                + "cycle-breaking view rule");
                out.add(gap);
            }
        }

        // dangling_reference: a reference to an object absent from the
        // store - the red link that says "this page is wanted".
        for (Map.Entry<String, Map<String, Object>> e : objects.entrySet()) {
            String oid = e.getKey();
            Map<String, Object> obj = e.getValue();
            List<Object> refs = new ArrayList<>();
            if ("causal_relation_object".equals(obj.get("type"))) {
                addAllIfList(refs, obj.get("causes"));
                addAllIfList(refs, obj.get("effects"));
                addAllIfList(refs, obj.get("context"));
                addAllIfList(refs, obj.get("mechanism"));
                Object refinesObj = obj.get("refines");
                if (refinesObj instanceof String
                        && !((String) refinesObj).isEmpty()) {
                    refs.add(refinesObj);
                }
            } else if ("realizable".equals(obj.get("type"))) {
                refs.add(obj.get("bearer"));
            }
            for (Object ref : refs) {
                if (ref instanceof String && !((String) ref).isEmpty()
                        && !objects.containsKey(ref)) {
                    Map<String, Object> gap = new LinkedHashMap<>();
                    gap.put("id", oid);
                    gap.put("kind", "dangling_reference");
                    gap.put("ref", ref);
                    out.add(gap);
                }
            }
        }

        // conflict: pairs of claims satisfying the formal test (rule 6).
        List<Map<String, Object>> cros = new ArrayList<>();
        for (Map<String, Object> obj : objects.values()) {
            if ("causal_relation_object".equals(obj.get("type"))) {
                cros.add(obj);
            }
        }
        for (int i = 0; i < cros.size(); i++) {
            for (int j = i + 1; j < cros.size(); j++) {
                if (Semantics.conflicts(cros.get(i), cros.get(j))) {
                    Map<String, Object> gap = new LinkedHashMap<>();
                    gap.put("kind", "conflict");
                    gap.put("a", cros.get(i).get("id"));
                    gap.put("b", cros.get(j).get("id"));
                    out.add(gap);
                }
            }
        }

        if (kind != null) {
            List<Map<String, Object>> filtered = new ArrayList<>();
            for (Map<String, Object> gap : out) {
                if (kind.equals(gap.get("kind"))) {
                    filtered.add(gap);
                }
            }
            return filtered;
        }
        return out;
    }

    private static void addAllIfList(List<Object> target, Object maybeList) {
        if (maybeList instanceof List) {
            target.addAll((List<?>) maybeList);
        }
    }
}

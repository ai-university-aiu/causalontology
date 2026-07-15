package org.causalontology;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * The Causalontology conformance runner for causalontology-java.
 *
 * Runs every vector in conformance/vectors/ against this binding, exactly
 * mirroring the Python harness (bindings/python/tests/run_conformance.py).
 * An implementation is conformant if and only if it passes every vector;
 * this runner exits nonzero on any failure.
 *
 * Pre-freeze note (see conformance/README.md): the vectors carry symbolic
 * identifiers ("occurrent:press_button", "ed25519:alice"). This harness
 * normalizes them deterministically - symbolic object ids become
 * scheme:sha256(name), and symbolic key names become real Ed25519
 * keypairs seeded from sha256("key:" + name) - so the normative behaviors
 * are tested with well-formed data. The 1.0.0 freeze pins concrete bytes
 * into the vectors themselves.
 *
 * Run from bindings/java (run_conformance.sh does this); the vector
 * directory is ../../conformance/vectors and the schemas are
 * ../../spec/schema.
 */
public final class Conformance {

    private static final Path VECDIR =
        Paths.get("..", "..", "conformance", "vectors");

    private static final Set<String> SCHEMES =
        Set.of("occurrent", "causal_relation_object", "continuant",
               "realizable", "assertion", "enrichment", "retraction",
               "succession", "stratum", "bridge", "port", "conduit",
               "quality", "token_individual", "token_occurrence",
               "state_assertion", "token_causal_claim");

    private static final Map<String, Signing.Keys> KEYS = new HashMap<>();

    private Conformance() {
    }

    /** A deliberate conformance check failed. */
    static final class CheckFailed extends RuntimeException {
        CheckFailed(String message) {
            super(message);
        }
    }

    static void check(boolean condition, String message) {
        if (!condition) {
            throw new CheckFailed(message);
        }
    }

    // -----------------------------------------------------------------
    // symbolic-identifier normalization
    // -----------------------------------------------------------------

    /** A real, deterministic Ed25519 keypair for a symbolic key name. */
    static Signing.Keys key(String name) {
        return KEYS.computeIfAbsent(name, n -> Signing.keypairFromSeed(
            Canonical.sha256(("key:" + n).getBytes(StandardCharsets.UTF_8))));
    }

    /** Normalize one symbolic identifier to a well-formed one. */
    static String sym(String s) {
        int colon = s.indexOf(':');
        String scheme = s.substring(0, colon);
        String name = s.substring(colon + 1);
        if (scheme.equals("ed25519")) {
            if (name.matches("[0-9a-f]{64}")) {
                return s;
            }
            return key(name).publicId;
        }
        if (name.matches("[0-9a-f]{64}")) {
            return s;
        }
        return scheme + ":"
            + Canonical.sha256Hex(name.getBytes(StandardCharsets.UTF_8));
    }

    /** Recursively normalize symbolic identifiers and placeholders. */
    static Object normalize(Object x) {
        if (x instanceof String) {
            String s = (String) x;
            if (s.equals("<128 hex>")) {
                return "ab".repeat(64);
            }
            int colon = s.indexOf(':');
            if (colon > 0) {
                String scheme = s.substring(0, colon);
                if (SCHEMES.contains(scheme) || scheme.equals("ed25519")) {
                    return sym(s);
                }
            }
            return s;
        }
        if (x instanceof List) {
            List<Object> out = new ArrayList<>();
            for (Object v : (List<?>) x) {
                out.add(normalize(v));
            }
            return out;
        }
        if (x instanceof Map) {
            Map<String, Object> out = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : ((Map<?, ?>) x).entrySet()) {
                out.put((String) e.getKey(), normalize(e.getValue()));
            }
            return out;
        }
        return x;
    }

    // -----------------------------------------------------------------
    // vector loading and record building
    // -----------------------------------------------------------------

    static Path vectorFile(int n) {
        String glob = String.format("v%02d_*.json", n);
        List<Path> hits = new ArrayList<>();
        try (DirectoryStream<Path> stream =
                 Files.newDirectoryStream(VECDIR, glob)) {
            for (Path p : stream) {
                hits.add(p);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        check(hits.size() == 1, "vector " + n + " not found");
        return hits.get(0);
    }

    /** Load vector n's JSON file (for its structured inputs). */
    static Map<String, Object> vec(int n) {
        try {
            String text = Files.readString(vectorFile(n),
                                           StandardCharsets.UTF_8);
            return asMap(Json.parse(text));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    static String ts(int i) {
        return String.format("2026-07-13T0%d:00:00Z", i);
    }

    /** Build, timestamp, and sign a provenance record. */
    static Map<String, Object> signed(String kind, Map<String, Object> body,
                                      String who, int tsIndex) {
        Signing.Keys keys = key(who);
        Map<String, Object> rec = new LinkedHashMap<>(body);
        rec.put("type", kind);
        rec.putIfAbsent("timestamp", ts(tsIndex));
        if (kind.equals("succession")) {
            rec.putIfAbsent("predecessor", keys.publicId);
        } else {
            rec.put("source", keys.publicId);
        }
        return Signing.signRecord(rec, keys.secret, kind);
    }

    // -----------------------------------------------------------------
    // small cast helpers over the parsed JSON graph
    // -----------------------------------------------------------------

    @SuppressWarnings("unchecked")
    static Map<String, Object> asMap(Object o) {
        return (Map<String, Object>) o;
    }

    @SuppressWarnings("unchecked")
    static List<Object> asList(Object o) {
        return (List<Object>) o;
    }

    /** A LinkedHashMap from alternating key/value arguments. */
    static Map<String, Object> map(Object... keyValues) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i < keyValues.length; i += 2) {
            out.put((String) keyValues[i], keyValues[i + 1]);
        }
        return out;
    }

    // -----------------------------------------------------------------
    // internal sanity checks (not conformance vectors)
    // -----------------------------------------------------------------

    static void internalChecks() {
        // RFC 8032, TEST 1 known-answer.
        Ed25519.selfTest();
        // JCS basics.
        Map<String, Object> unsorted = new LinkedHashMap<>();
        unsorted.put("b", Long.valueOf(2L));
        unsorted.put("a", Long.valueOf(1L));
        check(Jcs.serialize(unsorted).equals("{\"a\":1,\"b\":2}"),
              "JCS key sorting failed: " + Jcs.serialize(unsorted));
        check(Jcs.serialize(Double.valueOf(1.0)).equals("1"),
              "JCS 1.0 must serialize as 1");
        check(Jcs.serialize(Double.valueOf(6.000)).equals("6"),
              "JCS 6.000 must serialize as 6");
        check(Jcs.serialize(Double.valueOf(0.7)).equals("0.7"),
              "JCS 0.7 must serialize as 0.7");
        check(Semantics.toSeconds(1, "months") == 2629746L,
              "to_seconds months constant");
        check(Semantics.toSeconds(1, "years") == 31556952L,
              "to_seconds years constant");
    }

    // -----------------------------------------------------------------
    // content-object builders (mirror the Python test builders)
    // -----------------------------------------------------------------

    /** A content object completed with its real content-addressed id. */
    static Map<String, Object> mk(Map<String, Object> obj) {
        Map<String, Object> o = new LinkedHashMap<>(obj);
        o.put("id", Canonical.identify(o, null));
        return o;
    }

    static Map<String, Object> stratum(String label, String scheme,
                                       long ordinal) {
        return stratum(label, scheme, ordinal, null, null);
    }

    static Map<String, Object> stratum(String label, String scheme,
                                       long ordinal, String unit,
                                       List<Object> governs) {
        Map<String, Object> o = map("type", "stratum", "label", label,
                                    "scheme", scheme,
                                    "ordinal", Long.valueOf(ordinal));
        if (unit != null) {
            o.put("unit", unit);
        }
        if (governs != null) {
            o.put("governs", governs);
        }
        return mk(o);
    }

    static Map<String, Object> occ(String label) {
        return occ(label, null, "event");
    }

    static Map<String, Object> occ(String label, String stratumId) {
        return occ(label, stratumId, "event");
    }

    static Map<String, Object> occ(String label, String stratumId,
                                   String category) {
        Map<String, Object> o = map("type", "occurrent", "label", label,
                                    "category", category);
        if (stratumId != null) {
            o.put("stratum", stratumId);
        }
        return mk(o);
    }

    static Map<String, Object> cnt(String label) {
        return cnt(label, "object");
    }

    static Map<String, Object> cnt(String label, String category) {
        return mk(map("type", "continuant", "label", label,
                      "category", category));
    }

    static Map<String, Object> cro(List<Object> causes, List<Object> effects) {
        return cro(causes, effects, new LinkedHashMap<>());
    }

    static Map<String, Object> cro(List<Object> causes, List<Object> effects,
                                   Map<String, Object> extra) {
        Map<String, Object> o = map("type", "causal_relation_object",
                                    "causes", causes, "effects", effects);
        o.putAll(extra);
        return mk(o);
    }

    static Map<String, Object> bridge(String coarse, List<Object> fine,
                                      String relation) {
        return mk(map("type", "bridge", "coarse", coarse, "fine", fine,
                      "relation", relation));
    }

    static Map<String, Object> port(String bearer, String label,
                                    String direction, List<Object> accepts) {
        return port(bearer, label, direction, accepts, null);
    }

    static Map<String, Object> port(String bearer, String label,
                                    String direction, List<Object> accepts,
                                    String realizable) {
        Map<String, Object> o = map("type", "port", "bearer", bearer,
                                    "label", label, "direction", direction,
                                    "accepts", accepts);
        if (realizable != null) {
            o.put("realizable", realizable);
        }
        return mk(o);
    }

    static Map<String, Object> conduit(String from, String to,
                                       List<Object> carries) {
        return conduit(from, to, carries, "conn", null);
    }

    static Map<String, Object> conduit(String from, String to,
                                       List<Object> carries, String label,
                                       String transform) {
        Map<String, Object> o = map("type", "conduit", "label", label,
                                    "from", from, "to", to,
                                    "carries", carries);
        if (transform != null) {
            o.put("transform", transform);
        }
        return mk(o);
    }

    static Map<String, Object> quality(String label, String datatype) {
        return quality(label, datatype, null);
    }

    static Map<String, Object> quality(String label, String datatype,
                                       String unit) {
        Map<String, Object> o = map("type", "quality", "label", label,
                                    "datatype", datatype);
        if (unit != null) {
            o.put("unit", unit);
        }
        return mk(o);
    }

    static Map<String, Object> individual(String instantiates) {
        return individual(instantiates, null, null);
    }

    static Map<String, Object> individual(String instantiates,
                                          String designator) {
        return individual(instantiates, designator, null);
    }

    static Map<String, Object> individual(String instantiates,
                                          String designator, String partOf) {
        Map<String, Object> o = map("type", "token_individual",
                                    "instantiates", instantiates);
        if (designator != null) {
            o.put("designator", designator);
        }
        if (partOf != null) {
            o.put("part_of", partOf);
        }
        return mk(o);
    }

    static Map<String, Object> token(String instantiates,
                                     Map<String, Object> interval) {
        return token(instantiates, interval, null);
    }

    static Map<String, Object> token(String instantiates,
                                     Map<String, Object> interval,
                                     List<Object> participants) {
        Map<String, Object> o = map("type", "token_occurrence",
                                    "instantiates", instantiates,
                                    "interval", interval);
        if (participants != null) {
            o.put("participants", participants);
        }
        return mk(o);
    }

    static Map<String, Object> state(String subject, String quality,
                                     Map<String, Object> value,
                                     Map<String, Object> interval) {
        return mk(map("type", "state_assertion", "subject", subject,
                      "quality", quality, "value", value,
                      "interval", interval));
    }

    static Map<String, Object> tcc(List<Object> causes, List<Object> effects,
                                   Map<String, Object> extra) {
        Map<String, Object> o = map("type", "token_causal_claim",
                                    "causes", causes, "effects", effects);
        o.putAll(extra);
        return mk(o);
    }

    static Map<String, Object> rlz(String bearer, String kind, String label) {
        Map<String, Object> o = map("type", "realizable", "kind", kind,
                                    "bearer", bearer);
        if (label != null) {
            o.put("label", label);
        }
        return mk(o);
    }

    /** The six-stratum neuroendocrine fixture (ordinal -> stratum object). */
    static Map<Integer, Map<String, Object>> neuro() {
        Map<Integer, String> labels = new LinkedHashMap<>();
        labels.put(4, "macromolecular");
        labels.put(5, "subcellular");
        labels.put(6, "cellular");
        labels.put(7, "synaptic");
        labels.put(9, "region");
        labels.put(14, "community_and_society");
        Map<Integer, Map<String, Object>> out = new LinkedHashMap<>();
        for (Map.Entry<Integer, String> e : labels.entrySet()) {
            out.put(e.getKey(),
                    stratum(e.getValue(), "neuroendocrine", e.getKey()));
        }
        return out;
    }

    static String id(Map<String, Object> o) {
        return (String) o.get("id");
    }

    @SafeVarargs
    static Map<String, Map<String, Object>> omap(Map<String, Object>... objs) {
        Map<String, Map<String, Object>> m = new LinkedHashMap<>();
        for (Map<String, Object> o : objs) {
            m.put(id(o), o);
        }
        return m;
    }

    // -----------------------------------------------------------------
    // shared vector shapes
    // -----------------------------------------------------------------

    static void schemaFails(int n, String mustMention) {
        Map<String, Object> input = asMap(normalize(vec(n).get("input")));
        Validation result = SchemaValidator.validateSchema(input, null);
        check(!result.ok, "expected schema-invalid");
        check(result.anyReasonContains(mustMention), result.reason());
    }

    static void semanticsFails(int n, String mustMention) {
        Map<String, Object> input = asMap(normalize(vec(n).get("input")));
        Validation result = Semantics.validateSemantics(input, null);
        check(!result.ok, "expected semantically-invalid");
        check(result.anyReasonContains(mustMention), result.reason());
    }

    static boolean adm(int n) {
        Map<String, Object> given = asMap(vec(n).get("given"));
        Map<String, Object> cro = map(
            "causes", List.of(sym("occurrent:c")),
            "effects", List.of(sym("occurrent:e")),
            "temporal", given.get("temporal"));
        double elapsed =
            ((Number) given.get("elapsed_seconds")).doubleValue();
        return Semantics.admissible(cro, elapsed);
    }

    // -----------------------------------------------------------------
    // the 38 vectors
    // -----------------------------------------------------------------

    static void v01() {
        Map<String, Object> input = asMap(normalize(vec(1).get("input")));
        Validation schema = SchemaValidator.validateSchema(input, null);
        check(schema.ok, schema.reason());
        Validation semantics = Semantics.validateSemantics(input, null);
        check(semantics.ok, semantics.reason());
    }

    static void v02() {
        Map<String, Object> input = asMap(normalize(vec(2).get("input")));
        Validation schema = SchemaValidator.validateSchema(input, null);
        check(schema.ok, schema.reason());
        Validation semantics = Semantics.validateSemantics(input, null);
        check(semantics.ok, semantics.reason());
        List<String> missing = Semantics.isPartial(input);
        check(!missing.isEmpty(), "expected a partial object");
        List<Object> expected =
            asList(asMap(vec(2).get("expect")).get("missing"));
        check(missing.equals(expected), "missing = " + missing);
    }

    static void v03() {
        schemaFails(3, "effects");
    }

    static void v04() {
        schemaFails(4, "causes");
    }

    static void v05() {
        schemaFails(5, "modality");
    }

    static void v06() {
        schemaFails(6, "colour");
    }

    static void v07() {
        schemaFails(7, "causes");
    }

    static void v08() {
        Map<String, Object> input = asMap(normalize(vec(8).get("input")));
        Validation schema = SchemaValidator.validateSchema(input, null);
        check(schema.ok, schema.reason());
    }

    static void v09() {
        schemaFails(9, "label");
    }

    static void v10() {
        schemaFails(10, "category");
    }

    static void v11() {
        Map<String, Object> input = asMap(normalize(vec(11).get("input")));
        Validation schema = SchemaValidator.validateSchema(input, null);
        check(schema.ok, schema.reason());
    }

    static void v12() {
        schemaFails(12, "confidence");
    }

    static void v13() {
        Map<String, Object> input = asMap(normalize(vec(13).get("input")));
        Validation schema = SchemaValidator.validateSchema(input, null);
        check(schema.ok, schema.reason());
        Validation semantics = Semantics.validateSemantics(input, null);
        check(semantics.ok, semantics.reason());
    }

    static void v14() {
        Map<String, Object> input = asMap(normalize(vec(14).get("input")));
        Validation schema = SchemaValidator.validateSchema(input, null);
        check(schema.ok, schema.reason());
        semanticsFails(14, "minimum_delay");
    }

    static void v15() {
        semanticsFails(15, "acyclic");
    }

    static void v16() {
        semanticsFails(16, "acyclic");
    }

    static void v17() {
        Map<String, Object> vector = vec(17);
        Map<String, Object> parent =
            asMap(normalize(asMap(vector.get("given")).get("parent")));
        Map<String, Object> child = asMap(normalize(vector.get("input")));
        Validation result = Semantics.refinementValid(child, parent);
        check(!result.ok, "expected an invalid refinement");
        check(result.reason().contains("rival"), result.reason());
    }

    static void v18() {
        semanticsFails(18, "not a legal field");
    }

    static void v19() {
        semanticsFails(19, "language-tagged");
    }

    static Map<String, Object> subsumesRecord(String about, String entry,
                                              int tsIndex) {
        return signed("enrichment",
                      map("about", about, "field", "subsumes",
                          "entry", entry),
                      "taxo", tsIndex);
    }

    static void v20() {
        String dog = sym("continuant:dog");
        String mammal = sym("continuant:mammal");
        String animal = sym("continuant:animal");
        // The enforcing tier rejects the cycle-completing write.
        Store store = new Store(true);
        store.putRecord(subsumesRecord(dog, mammal, 1));
        store.putRecord(subsumesRecord(mammal, animal, 2));
        boolean rejected = false;
        try {
            store.putRecord(subsumesRecord(animal, dog, 3));
        } catch (Store.RejectedWrite e) {
            rejected = true;
            check(e.getMessage().contains("cycle"), e.getMessage());
        }
        check(rejected, "enforcing store accepted a cycle");
        // Decentralized merge: the view breaks the cycle deterministically.
        Store replica = new Store(true);
        replica.putRecord(subsumesRecord(dog, mammal, 1));
        replica.putRecord(subsumesRecord(mammal, animal, 2));
        Map<String, Object> bad = subsumesRecord(animal, dog, 3);
        replica.forceMergeRecord(bad);
        Store.Taxonomy view = replica.activeTaxonomyEdges("subsumes");
        check(view.excluded.size() == 1,
              "expected exactly 1 excluded record, got "
              + view.excluded.size());
        check(bad.get("id").equals(view.excluded.get(0).get("id")),
              "the wrong record was excluded");
        boolean surfaced = false;
        for (Map<String, Object> gap : replica.gaps("inconsistent_hierarchy")) {
            if (bad.get("id").equals(gap.get("id"))) {
                surfaced = true;
            }
        }
        check(surfaced, "the cycle record was not surfaced as a repair gap");
    }

    static void v21() {
        check(adm(21), "expected admissible");
    }

    static void v22() {
        check(!adm(22), "expected not admissible");
    }

    static void v23() {
        check(adm(23), "expected admissible (fixed unit constants)");
    }

    static void v24() {
        Map<String, Object> vector = vec(24);
        String idA = Canonical.identify(
            asMap(normalize(vector.get("inputA"))), null);
        String idB = Canonical.identify(
            asMap(normalize(vector.get("inputB"))), null);
        check(idA.equals(idB), idA + " != " + idB);
    }

    static void v25() {
        Map<String, Object> vector = vec(25);
        String idA = Canonical.identify(
            asMap(normalize(vector.get("inputA"))), null);
        String idB = Canonical.identify(
            asMap(normalize(vector.get("inputB"))), null);
        check(idA.equals(idB), idA + " != " + idB);
    }

    static void v26() {
        Store store = new Store(true);
        Map<String, Object> obj = map("type", "occurrent",
                                      "label", "press_button",
                                      "category", "action");
        String first = store.put(new LinkedHashMap<>(obj));
        String second = store.put(new LinkedHashMap<>(obj));
        check(first.equals(second), "identifiers differ");
        check(store.objects.size() == 1, "duplicate object stored");
    }

    static void v27() {
        Store store = new Store(true);
        String occ = store.put(map("type", "occurrent",
                                   "label", "press_button",
                                   "category", "action"));
        Map<String, Object> entry = map("lang", "en",
                                        "text", "press the button");
        Map<String, Object> r1 = signed("enrichment",
            map("about", occ, "field", "aliases", "entry", entry),
            "alice", 1);
        Map<String, Object> r2 = signed("enrichment",
            map("about", occ, "field", "aliases", "entry", entry),
            "bob", 2);
        String id1 = store.putRecord(r1);
        String id2 = store.putRecord(r2);
        check(!id1.equals(id2), "expected two distinct records");
        Map<String, Object> enrichments =
            asMap(store.get(occ).get("enrichments"));
        List<Object> aliases = asList(enrichments.get("aliases"));
        check(aliases.size() == 1, "expected one materialized entry");
        List<Object> contributors =
            asList(asMap(aliases.get(0)).get("contributors"));
        check(contributors.size() == 2, "expected two contributors");
    }

    static void v28() {
        Store store = new Store(true);
        Map<String, Object> claim = map(
            "type", "causal_relation_object",
            "causes", List.of(sym("occurrent:A")),
            "effects", List.of(sym("occurrent:B")),
            "modality", "sufficient");
        String first = store.put(new LinkedHashMap<>(claim));
        String second = store.put(new LinkedHashMap<>(claim));
        check(first.equals(second), "identifiers differ");
        check(store.objects.size() == 1, "duplicate object stored");
        store.putRecord(signed("assertion",
            map("about", first, "evidence_type", "observation",
                "strength", Double.valueOf(0.8),
                "confidence", Double.valueOf(0.8)),
            "lab1", 1));
        store.putRecord(signed("assertion",
            map("about", first, "evidence_type", "observation",
                "strength", Double.valueOf(0.8),
                "confidence", Double.valueOf(0.8)),
            "lab2", 2));
        check(store.assertionsAbout(first).size() == 2,
              "expected two assertions about the one object");
    }

    static void v29() {
        Map<String, Object> rec = signed("assertion",
            map("about", sym("causal_relation_object:demo"),
                "evidence_type", "intervention",
                "strength", Double.valueOf(0.7),
                "confidence", Double.valueOf(0.9)),
            "signer", 0);
        check(Signing.verifyRecord(rec, null), "valid signature must verify");
    }

    static void v30() {
        Map<String, Object> rec = signed("assertion",
            map("about", sym("causal_relation_object:demo"),
                "evidence_type", "intervention",
                "strength", Double.valueOf(0.7),
                "confidence", Double.valueOf(0.9)),
            "signer", 0);
        Map<String, Object> tampered = new LinkedHashMap<>(rec);
        tampered.put("confidence", Double.valueOf(0.1));
        check(!Signing.verifyRecord(tampered, null),
              "tampered record must fail verification");
    }

    static void v31() {
        Store store = new Store(true);
        String x = store.put(map("type", "causal_relation_object",
                                 "causes", List.of(sym("occurrent:A")),
                                 "effects", List.of(sym("occurrent:B"))));
        Map<String, Object> assertion = signed("assertion",
            map("about", x, "evidence_type", "observation",
                "confidence", Double.valueOf(0.8)),
            "lab1", 1);
        store.putRecord(assertion);
        store.putRecord(signed("retraction",
            map("retracts", assertion.get("id")), "lab1", 2));
        check(store.assertionsAbout(x).isEmpty(),
              "retracted assertion still in the default view");
        List<Map<String, Object>> history = store.assertionsAbout(x, true);
        check(history.size() == 1, "history must keep the assertion");
        check(Boolean.TRUE.equals(history.get(0).get("retracted")),
              "history entry must be flagged retracted");
        Map<String, Object> foreign = signed("retraction",
            map("retracts", assertion.get("id")), "mallory", 3);
        boolean rejected = false;
        try {
            store.putRecord(foreign);
        } catch (Store.RejectedWrite e) {
            rejected = true;
        }
        check(rejected, "foreign retraction accepted");
        check(store.assertionsAbout(x).isEmpty(),
              "still excluded by lab1's own retraction");
        check(store.assertionsAbout(x, true).size() == 1,
              "history size changed");
    }

    static List<Object> aliasesOf(Map<String, Object> got) {
        Map<String, Object> enrichments = asMap(got.get("enrichments"));
        Object aliases = enrichments.get("aliases");
        if (aliases == null) {
            return new ArrayList<>();
        }
        return asList(aliases);
    }

    static void v32() {
        Store store = new Store(true);
        String occ = store.put(map("type", "occurrent",
                                   "label", "press_button",
                                   "category", "action"));
        Map<String, Object> enrichment = signed("enrichment",
            map("about", occ, "field", "aliases",
                "entry", map("lang", "ja", "text", "botan")),
            "bob", 1);
        store.putRecord(enrichment);
        check(aliasesOf(store.get(occ)).size() == 1,
              "expected one alias before retraction");
        store.putRecord(signed("retraction",
            map("retracts", enrichment.get("id")), "bob", 2));
        check(aliasesOf(store.get(occ)).isEmpty(),
              "retracted alias still in the default view");
        check(aliasesOf(store.get(occ, "history")).size() == 1,
              "history view must keep the alias");
    }

    static void v33() {
        Store store = new Store(true);
        String k1 = key("K1").publicId;
        String k2 = key("K2").publicId;
        Map<String, Object> assertion = signed("assertion",
            map("about", sym("causal_relation_object:claim"),
                "evidence_type", "observation",
                "confidence", Double.valueOf(0.9)),
            "K1", 1);
        store.putRecord(assertion);
        Map<String, Object> succession = signed("succession",
            map("successor", k2), "K1", 2);
        store.putRecord(succession);
        check(store.lineage(k2).contains(k1), "predecessor not in lineage");
        check(store.lineage(k1).contains(k2), "successor not in lineage");
        Map<String, Object> retraction = signed("retraction",
            map("retracts", assertion.get("id")), "K2", 3);
        store.putRecord(retraction); // successor may retract
        check(store.assertionsAbout(sym("causal_relation_object:claim")).isEmpty(),
              "successor's retraction was not honored");
    }

    static void v34() {
        Map<String, Object> given = asMap(normalize(vec(34).get("given")));
        check(Semantics.conflicts(asMap(given.get("A")),
                                  asMap(given.get("B"))),
              "expected a conflict");
    }

    static void v35() {
        Map<String, Object> given = asMap(normalize(vec(35).get("given")));
        check(!Semantics.conflicts(asMap(given.get("A")),
                                   asMap(given.get("B"))),
              "expected no conflict");
    }

    static void v36() {
        String a = sym("occurrent:A");
        String b = sym("occurrent:B");
        String c = sym("occurrent:C");
        String d = sym("occurrent:D");
        Map<String, Object> m1 = map("id", sym("causal_relation_object:m1"),
                                     "causes", List.of(a),
                                     "effects", List.of(b));
        Map<String, Object> m2 = map("id", sym("causal_relation_object:m2"),
                                     "causes", List.of(b),
                                     "effects", List.of(c));
        Map<String, Object> m3 = map("id", sym("causal_relation_object:m3"),
                                     "causes", List.of(d),
                                     "effects", List.of(c));
        Map<String, Object> parent = map(
            "causes", List.of(a),
            "effects", List.of(c),
            "mechanism", List.of(m1.get("id"), m2.get("id")));
        Map<String, Map<String, Object>> members = new LinkedHashMap<>();
        members.put((String) m1.get("id"), m1);
        members.put((String) m2.get("id"), m2);
        check("consistent".equals(
                  Semantics.hierarchyConsistent(parent, members)),
              "expected consistent");
        Map<String, Object> parent2 = new LinkedHashMap<>(parent);
        parent2.put("mechanism", List.of(m1.get("id"), m3.get("id")));
        Map<String, Map<String, Object>> members2 = new LinkedHashMap<>();
        members2.put((String) m1.get("id"), m1);
        members2.put((String) m3.get("id"), m3);
        check("inconsistent".equals(
                  Semantics.hierarchyConsistent(parent2, members2)),
              "expected inconsistent");
        Map<String, Map<String, Object>> partial = new LinkedHashMap<>();
        partial.put((String) m1.get("id"), m1);
        check("indeterminate".equals(
                  Semantics.hierarchyConsistent(parent, partial)),
              "expected indeterminate");
    }

    static void v37() {
        Store store = new Store(true);
        String occ = store.put(map("type", "occurrent",
                                   "label", "press_button",
                                   "category", "action"));
        store.putRecord(signed("enrichment",
            map("about", occ, "field", "aliases",
                "entry", map("lang", "en", "text", "Press the Button")),
            "alice", 1));
        List<String> byAlias = store.resolve("Press  The   Button", "en");
        check(byAlias.equals(List.of(occ)), "alias match failed: " + byAlias);
        List<String> byLabel = store.resolve("press_button", "en");
        check(!byLabel.isEmpty() && occ.equals(byLabel.get(0)),
              "canonical-label match must rank first: " + byLabel);
    }

    static List<Object> gapIds(List<Map<String, Object>> gaps) {
        List<Object> ids = new ArrayList<>();
        for (Map<String, Object> gap : gaps) {
            ids.add(gap.get("id"));
        }
        return ids;
    }

    static void v38() {
        Store store = new Store(true);
        String parent = store.put(map("type", "causal_relation_object",
                                      "causes", List.of(sym("occurrent:A")),
                                      "effects", List.of(sym("occurrent:B"))));
        List<Object> before = gapIds(store.gaps("missing_field"));
        check(before.contains(parent), "expected a missing_field gap");
        String refinement = store.put(map(
            "type", "causal_relation_object",
            "causes", List.of(sym("occurrent:A")),
            "effects", List.of(sym("occurrent:B")),
            "temporal", map("minimum_delay", Long.valueOf(0L),
                            "maximum_delay", Long.valueOf(1L),
                            "unit", "seconds"),
            "modality", "sufficient",
            "refines", parent));
        List<Object> after = gapIds(store.gaps("missing_field"));
        check(!after.contains(parent), "the gap did not close");
        check(!after.contains(refinement),
              "the refinement itself must be complete");
    }

    // -----------------------------------------------------------------
    // V39 - V107: the 2.0.0 additions
    // -----------------------------------------------------------------

    static void v39() {
        Map<String, Object> st = stratum("cellular", "neuroendocrine", 6,
            "cell", List.of("cell_biology"));
        Validation schema = SchemaValidator.validateSchema(st, null);
        check(schema.ok, schema.reason());
    }

    static void v40() {
        Map<String, Object> bad = mk(map("type", "stratum",
            "label", "cellular", "ordinal", Long.valueOf(6L)));
        Validation schema = SchemaValidator.validateSchema(bad, "stratum");
        check(!schema.ok && schema.anyReasonContains("scheme"),
              schema.reason());
    }

    static void v41() {
        Map<String, Object> a = stratum("cellular", "neuroendocrine", 6);
        Map<String, Object> b = stratum("neuronal", "neuroendocrine", 6);
        for (Map<String, Object> x : List.of(a, b)) {
            Validation schema = SchemaValidator.validateSchema(x, null);
            check(schema.ok, schema.reason());
        }
        check(!id(a).equals(id(b)), "same ordinal must not collide");
    }

    static void v42() {
        Map<Integer, Map<String, Object>> s = neuro();
        Map<String, Object> s4p = stratum("molecular", "physics", 4);
        Map<String, Object> c = occ("chronic_social_subordination",
                                    id(s.get(14)));
        Map<String, Object> e = occ("gene_expression", id(s4p));
        Map<String, Map<String, Object>> smap = omap(s.get(14), s4p);
        Map<String, Map<String, Object>> om = omap(c, e);
        Map<String, Object> p = cro(List.of(id(c)), List.of(id(e)));
        check("scheme_mismatch".equals(Semantics.classifyCro(p, om, smap)),
              "expected scheme_mismatch");
    }

    static void v43() {
        for (Map<String, Object> x : List.of(
                stratum("macromolecular", "neuroendocrine", 4),
                stratum("region", "neuroendocrine", 9))) {
            Validation schema = SchemaValidator.validateSchema(x, null);
            check(schema.ok, schema.reason());
        }
    }

    static void v44() {
        Map<String, Object> st = stratum("cellular", "neuroendocrine", 6);
        Map<String, Object> o = occ("neuron_fires", id(st));
        Validation schema = SchemaValidator.validateSchema(o, null);
        check(schema.ok, schema.reason());
        Validation semantics = Semantics.validateSemantics(o, null);
        check(semantics.ok, semantics.reason());
    }

    static void v45() {
        Map<String, Object> o = occ("press_button");
        Validation schema = SchemaValidator.validateSchema(o, null);
        check(schema.ok, schema.reason());
        Map<String, Object> e = occ("light_on");
        Map<String, Object> p = cro(List.of(id(o)), List.of(id(e)));
        check("unclassifiable".equals(Semantics.classifyCro(p, omap(o, e),
              new LinkedHashMap<>())), "expected unclassifiable");
    }

    static void v46() {
        Map<Integer, Map<String, Object>> s = neuro();
        Map<String, Object> a = occ("depolarization", id(s.get(5)));
        Map<String, Object> b = occ("depolarization", id(s.get(6)));
        check(!id(a).equals(id(b)), "different strata must not collide");
    }

    static Object[] bridgeFixture(String relation) {
        Map<Integer, Map<String, Object>> s = neuro();
        Map<String, Object> coarse = occ("action_potential_fires",
                                         id(s.get(6)));
        Map<String, Object> f1 = occ("sodium_channels_open", id(s.get(4)));
        Map<String, Object> f2 = occ("sodium_influx", id(s.get(4)));
        Map<String, Object> b = bridge(id(coarse), List.of(id(f1), id(f2)),
                                       relation);
        Map<String, Map<String, Object>> om = omap(coarse, f1, f2);
        Map<String, Map<String, Object>> smap = omap(s.get(4), s.get(6));
        return new Object[] {b, om, smap};
    }

    @SuppressWarnings("unchecked")
    static void validBridge(String relation) {
        Object[] fx = bridgeFixture(relation);
        Map<String, Object> b = (Map<String, Object>) fx[0];
        Map<String, Map<String, Object>> om =
            (Map<String, Map<String, Object>>) fx[1];
        Map<String, Map<String, Object>> smap =
            (Map<String, Map<String, Object>>) fx[2];
        Validation schema = SchemaValidator.validateSchema(b, null);
        check(schema.ok, schema.reason());
        Validation wf = Semantics.bridgeWellformed(b, om, smap);
        check(wf.ok, wf.reason());
    }

    static void v47() {
        validBridge("constitutes");
    }

    static void v48() {
        validBridge("aggregates");
    }

    static void v49() {
        validBridge("realizes");
    }

    static void v50() {
        validBridge("supervenes_on");
    }

    static void v51() {
        Map<Integer, Map<String, Object>> s = neuro();
        Map<String, Object> coarse = occ("x_coarse", id(s.get(4)));
        Map<String, Object> fine = occ("x_fine", id(s.get(6)));
        Map<String, Object> b = bridge(id(coarse), List.of(id(fine)),
                                       "constitutes");
        Validation wf = Semantics.bridgeWellformed(b, omap(coarse, fine),
            omap(s.get(4), s.get(6)));
        check(!wf.ok, "coarse ordinal not > fine ordinal must fail");
    }

    static void v52() {
        Map<Integer, Map<String, Object>> s = neuro();
        Map<String, Object> coarse = occ("c", id(s.get(6)));
        Map<String, Object> f1 = occ("f1", id(s.get(4)));
        Map<String, Object> f2 = occ("f2", id(s.get(5)));
        Map<String, Object> b = bridge(id(coarse), List.of(id(f1), id(f2)),
                                       "constitutes");
        Validation wf = Semantics.bridgeWellformed(b, omap(coarse, f1, f2),
            omap(s.get(4), s.get(5), s.get(6)));
        check(!wf.ok, "fine members spanning strata must fail");
    }

    static void v53() {
        String x = sym("occurrent:x");
        String y = sym("occurrent:y");
        Map<String, Object> b1 = bridge(x, List.of(y), "constitutes");
        Map<String, Object> b2 = bridge(y, List.of(x), "constitutes");
        Map<Object, List<Object>> edges = new LinkedHashMap<>();
        for (Map<String, Object> b : List.of(b1, b2)) {
            for (Object f : asList(b.get("fine"))) {
                edges.computeIfAbsent(f, k -> new ArrayList<>())
                     .add(b.get("coarse"));
            }
        }
        check(Semantics.hasCycle(edges), "expected a bridge cycle");
    }

    static void v54() {
        Map<String, Object> a = stratum("cellular", "neuroendocrine", 6);
        Map<String, Object> b = stratum("molecular", "physics", 4);
        Map<String, Object> coarse = occ("c", id(a));
        Map<String, Object> fine = occ("f", id(b));
        Map<String, Object> br = bridge(id(coarse), List.of(id(fine)),
                                        "constitutes");
        Validation wf = Semantics.bridgeWellformed(br, omap(coarse, fine),
            omap(a, b));
        check(!wf.ok, "cross-scheme bridge must fail");
    }

    static void v55() {
        Map<Integer, Map<String, Object>> s = neuro();
        Map<String, Object> coarse = occ("decision_made", id(s.get(6)));
        Map<String, Object> f1 = occ("cascade_a", id(s.get(4)));
        Map<String, Object> f2 = occ("cascade_b", id(s.get(4)));
        Map<String, Object> b1 = bridge(id(coarse), List.of(id(f1)),
                                        "realizes");
        Map<String, Object> b2 = bridge(id(coarse), List.of(id(f2)),
                                        "realizes");
        check(!id(b1).equals(id(b2)), "distinct fine sets, distinct bridges");
        for (Map<String, Object> b : List.of(b1, b2)) {
            Validation schema = SchemaValidator.validateSchema(b, null);
            check(schema.ok, schema.reason());
        }
    }

    static Object[] reachFixture() {
        Map<Integer, Map<String, Object>> s = neuro();
        Map<String, Object> ap = occ("action_potential_fires", id(s.get(6)));
        Map<String, Object> nt = occ("neurotransmitter_released", id(s.get(6)));
        Map<String, Object> fa = occ("calcium_enters", id(s.get(4)));
        Map<String, Object> fb = occ("vesicle_fuses", id(s.get(4)));
        Map<String, Object> m1 = cro(List.of(id(fa)), List.of(id(fb)));
        Map<String, Object> p = cro(List.of(id(ap)), List.of(id(nt)),
            map("mechanism", List.of(id(m1))));
        List<Map<String, Object>> bridges = List.of(
            bridge(id(ap), List.of(id(fa)), "constitutes"),
            bridge(id(nt), List.of(id(fb)), "constitutes"));
        Map<String, Map<String, Object>> members = omap(m1);
        return new Object[] {p, members, bridges};
    }

    @SuppressWarnings("unchecked")
    static void v56() {
        Object[] fx = reachFixture();
        check("consistent".equals(Semantics.hierarchyConsistent(
                (Map<String, Object>) fx[0],
                (Map<String, Map<String, Object>>) fx[1],
                (List<Map<String, Object>>) fx[2])),
              "bridged reachability should be consistent");
    }

    @SuppressWarnings("unchecked")
    static void v57() {
        Object[] fx = reachFixture();
        check("inconsistent".equals(Semantics.hierarchyConsistent(
                (Map<String, Object>) fx[0],
                (Map<String, Map<String, Object>>) fx[1])),
              "literal reachability should be inconsistent");
    }

    @SuppressWarnings("unchecked")
    static void v58() {
        Object[] fx = reachFixture();
        String literal = Semantics.hierarchyConsistent(
            (Map<String, Object>) fx[0],
            (Map<String, Map<String, Object>>) fx[1]);
        String bridged = Semantics.hierarchyConsistent(
            (Map<String, Object>) fx[0],
            (Map<String, Map<String, Object>>) fx[1],
            (List<Map<String, Object>>) fx[2]);
        check(!literal.equals("consistent") && bridged.equals("consistent"),
              "literal must differ from bridged consistency");
    }

    static String classify(int causeOrd, int effectOrd) {
        Map<Integer, Map<String, Object>> s = neuro();
        Map<String, Object> c = occ("c", id(s.get(causeOrd)));
        Map<String, Object> e = occ("e", id(s.get(effectOrd)));
        Map<String, Map<String, Object>> smap =
            omap(s.get(causeOrd), s.get(effectOrd));
        return Semantics.classifyCro(cro(List.of(id(c)), List.of(id(e))),
            omap(c, e), smap);
    }

    static void v59() {
        check("intra_stratal".equals(classify(6, 6)), "expected intra_stratal");
    }

    static void v60() {
        check("adjacent_stratal".equals(classify(6, 5)),
              "expected adjacent_stratal");
    }

    static void v61() {
        check("skipping".equals(classify(14, 4)), "expected skipping");
    }

    static Object[] skipFixture(int causeOrd, int effectOrd,
                                Map<String, Object> extra) {
        Map<Integer, Map<String, Object>> s = neuro();
        Map<String, Object> c = occ("c", id(s.get(causeOrd)));
        Map<String, Object> e = occ("e", id(s.get(effectOrd)));
        Map<String, Map<String, Object>> smap =
            omap(s.get(causeOrd), s.get(effectOrd));
        Map<String, Map<String, Object>> om = omap(c, e);
        Map<String, Object> p = cro(List.of(id(c)), List.of(id(e)), extra);
        return new Object[] {p, Semantics.classifyCro(p, om, smap)};
    }

    @SuppressWarnings("unchecked")
    static void v62() {
        Object[] fx = skipFixture(14, 4, new LinkedHashMap<>());
        check(Semantics.skipGaps((Map<String, Object>) fx[0], (String) fx[1])
                .equals(List.of("incomplete_mechanism")),
              "expected [incomplete_mechanism]");
    }

    @SuppressWarnings("unchecked")
    static void v63() {
        Object[] fx = skipFixture(14, 4, map("skips", Boolean.TRUE));
        check(Semantics.skipGaps((Map<String, Object>) fx[0], (String) fx[1])
                .isEmpty(), "skips:true absent mechanism surfaces nothing");
    }

    @SuppressWarnings("unchecked")
    static void v64() {
        Object[] fx = skipFixture(14, 4, map("skips", Boolean.TRUE,
            "mechanism", List.of(sym("causal_relation_object:m"))));
        Map<String, Object> p = (Map<String, Object>) fx[0];
        check(Semantics.skipGaps(p, (String) fx[1])
                .equals(List.of("contradictory_skip")),
              "expected [contradictory_skip]");
        Validation semantics = Semantics.validateSemantics(p, null);
        check(!semantics.ok
                && semantics.anyReasonContains("contradictory_skip"),
              semantics.reason());
    }

    @SuppressWarnings("unchecked")
    static void v65() {
        Object[] fx = skipFixture(6, 6, map("skips", Boolean.TRUE));
        check(Semantics.skipGaps((Map<String, Object>) fx[0], (String) fx[1])
                .equals(List.of("vacuous_skip")), "expected [vacuous_skip]");
    }

    static void v66() {
        Map<Integer, Map<String, Object>> s = neuro();
        Map<String, Object> c = occ("c", id(s.get(14)));
        Map<String, Object> e = occ("e", id(s.get(4)));
        Map<String, Object> absent = cro(List.of(id(c)), List.of(id(e)));
        Map<String, Object> falseSkip = cro(List.of(id(c)), List.of(id(e)),
            map("skips", Boolean.FALSE));
        check(!id(absent).equals(id(falseSkip)),
              "absent skips must differ from skips:false");
    }

    static void v67() {
        Map<Integer, Map<String, Object>> s = neuro();
        Map<String, Object> c1 = occ("c1", id(s.get(4)));
        Map<String, Object> c2 = occ("c2", id(s.get(6)));
        Map<String, Object> e = occ("e", id(s.get(6)));
        Map<String, Object> p = cro(List.of(id(c1), id(c2)), List.of(id(e)));
        check(Semantics.endpointsMixed(p, omap(c1, c2, e)),
              "expected mixed endpoints");
    }

    static void v68() {
        Map<String, Object> p = cro(List.of(sym("occurrent:a")),
            List.of(sym("occurrent:b")), map("modality", "enabling"));
        Validation schema = SchemaValidator.validateSchema(p, null);
        check(schema.ok, schema.reason());
    }

    static void v69() {
        Map<String, Object> a = map("causes", List.of(sym("occurrent:a")),
            "effects", List.of(sym("occurrent:b")), "modality", "enabling");
        Map<String, Object> b = map("causes", List.of(sym("occurrent:a")),
            "effects", List.of(sym("occurrent:b")), "modality", "sufficient");
        check(!Semantics.conflicts(a, b),
              "enabling and sufficient are compatible");
    }

    static void v70() {
        Map<String, Object> a = map("causes", List.of(sym("occurrent:a")),
            "effects", List.of(sym("occurrent:b")), "modality", "enabling");
        Map<String, Object> b = map("causes", List.of(sym("occurrent:a")),
            "effects", List.of(sym("occurrent:b")), "modality", "preventive");
        check(Semantics.conflicts(a, b),
              "preventive opposes enabling");
    }

    static void v71() {
        Map<String, Object> b = cnt("hippocampus");
        Map<String, Object> p = port(id(b), "perforant_path", "in",
            List.of(sym("occurrent:signal")));
        Validation schema = SchemaValidator.validateSchema(p, null);
        check(schema.ok, schema.reason());
    }

    static void v72() {
        String b = id(cnt("hippocampus"));
        String x = sym("occurrent:signal");
        check(!id(port(b, "perforant_path", "in", List.of(x)))
                .equals(id(port(b, "fornix", "in", List.of(x)))),
              "distinct labels, distinct ports");
    }

    static Object[] conduitFixture(boolean transform, boolean badCarry,
                                   boolean inFrom) {
        String x = sym("occurrent:motor_command");
        String y = sym("occurrent:error_signal");
        String z = sym("occurrent:unrelated");
        String m1 = id(cnt("motor_cortex"));
        String m2 = id(cnt("spinal_neuron"));
        Map<String, Object> frm = port(m1, "out_port",
            inFrom ? "in" : "out", List.of(x));
        Map<String, Object> to = port(m2, "in_port", "in",
            transform ? List.of(y) : List.of(x));
        List<Object> carries = badCarry ? List.of(z) : List.of(x);
        String xform = null;
        Map<String, Map<String, Object>> croMap = new LinkedHashMap<>();
        if (transform) {
            Map<String, Object> law = cro(List.of(x), List.of(y));
            croMap.put(id(law), law);
            xform = id(law);
        }
        Map<String, Object> c = conduit(id(frm), id(to), carries, "conn",
                                        xform);
        return new Object[] {c, omap(frm, to), croMap};
    }

    @SuppressWarnings("unchecked")
    static void v73() {
        Object[] fx = conduitFixture(false, false, false);
        Map<String, Object> c = (Map<String, Object>) fx[0];
        Map<String, Map<String, Object>> pmap =
            (Map<String, Map<String, Object>>) fx[1];
        Validation schema = SchemaValidator.validateSchema(c, null);
        check(schema.ok, schema.reason());
        Validation wf = Semantics.conduitWellformed(c, pmap);
        check(wf.ok, wf.reason());
    }

    @SuppressWarnings("unchecked")
    static void v74() {
        Object[] fx = conduitFixture(true, false, false);
        Map<String, Object> c = (Map<String, Object>) fx[0];
        Map<String, Map<String, Object>> pmap =
            (Map<String, Map<String, Object>>) fx[1];
        Map<String, Map<String, Object>> cmap =
            (Map<String, Map<String, Object>>) fx[2];
        Validation schema = SchemaValidator.validateSchema(c, null);
        check(schema.ok, schema.reason());
        Validation wf = Semantics.conduitWellformed(c, pmap, cmap);
        check(wf.ok, wf.reason());
    }

    @SuppressWarnings("unchecked")
    static void v75() {
        Object[] fx = conduitFixture(false, true, false);
        Validation wf = Semantics.conduitWellformed(
            (Map<String, Object>) fx[0],
            (Map<String, Map<String, Object>>) fx[1]);
        check(!wf.ok, "carries not accepted by from must fail");
    }

    @SuppressWarnings("unchecked")
    static void v76() {
        Object[] fx = conduitFixture(false, false, true);
        Validation wf = Semantics.conduitWellformed(
            (Map<String, Object>) fx[0],
            (Map<String, Map<String, Object>>) fx[1]);
        check(!wf.ok, "from port not out/bidirectional must fail");
    }

    @SuppressWarnings("unchecked")
    static void v77() {
        Object[] fx = conduitFixture(true, false, false);
        Map<String, Object> c = (Map<String, Object>) fx[0];
        Map<String, Map<String, Object>> pmap =
            (Map<String, Map<String, Object>>) fx[1];
        Map<String, Map<String, Object>> cmap =
            (Map<String, Map<String, Object>>) fx[2];
        Validation wf = Semantics.conduitWellformed(c, pmap, cmap);
        check(wf.ok, wf.reason());
        Map<String, Object> law = cmap.values().iterator().next();
        Object effect0 = asList(law.get("effects")).get(0);
        check(!asList(c.get("carries")).contains(effect0),
              "transform effect need not be carried");
    }

    static void v78() {
        String b = id(cnt("hippocampus"));
        check(!id(rlz(b, "disposition", "long_term_potentiation"))
                .equals(id(rlz(b, "disposition", "pattern_separation"))),
              "distinct labels, distinct realizables");
    }

    static void v79() {
        String b = id(cnt("hippocampus"));
        Map<String, Object> u1 = rlz(b, "disposition", null);
        Map<String, Object> u2 = rlz(b, "disposition", null);
        Validation schema = SchemaValidator.validateSchema(u1, null);
        check(schema.ok, schema.reason());
        check(id(u1).equals(id(u2)), "same fields, same id");
        check(!id(rlz(b, "disposition", "some_function")).equals(id(u1)),
              "adding a label changes identity");
    }

    static void v80() {
        Map<String, Object> parent = occ("fires");
        Map<String, Object> child = occ("fires_action_potential");
        Map<String, Object> e = map("type", "enrichment",
            "about", id(child), "field", "occurrent_subsumes",
            "entry", id(parent));
        Validation semantics = Semantics.validateSemantics(e, null);
        check(semantics.ok, semantics.reason());
    }

    static void v81() {
        String a = sym("occurrent:a");
        String b = sym("occurrent:b");
        Map<Object, List<Object>> edges = new LinkedHashMap<>();
        edges.put(a, List.of((Object) b));
        edges.put(b, List.of((Object) a));
        check(Semantics.hasCycle(edges), "expected a mereology cycle");
    }

    static void v82() {
        Map<String, Object> whole = occ("eat");
        Map<String, Object> part = occ("chew");
        Map<String, Object> e = map("type", "enrichment",
            "about", id(part), "field", "occurrent_part_of",
            "entry", id(whole));
        Validation semantics = Semantics.validateSemantics(e, null);
        check(semantics.ok, semantics.reason());
    }

    static void v83() {
        Semantics.FieldSpec spec =
            Semantics.ENRICHMENT_FIELDS.get("occurrent_part_of");
        check("occurrent".equals(spec.shape)
                && spec.legalKinds.equals(Set.of("occurrent")),
              "occurrent_part_of spec");
        Store store = new Store(true);
        store.put(occ("eat"));
        store.put(occ("chew"));
        boolean anyCro = false;
        for (Map<String, Object> o : store.objects.values()) {
            if ("causal_relation_object".equals(o.get("type"))) {
                anyCro = true;
            }
        }
        check(!anyCro, "no spurious causal relation objects");
    }

    static void v84() {
        Map<Integer, Map<String, Object>> s = neuro();
        Map<String, Object> a = occ("run", id(s.get(9)));
        Map<String, Object> b = occ("sprint", id(s.get(6)));
        check(!a.get("stratum").equals(b.get("stratum")),
              "different strata carried on the occurrents");
    }

    static void v85() {
        Map<String, Object> c = cnt("human_patient");
        Map<String, Object> ti = individual(id(c), "salted_hash_abc123");
        Validation schema = SchemaValidator.validateSchema(ti, null);
        check(schema.ok, schema.reason());
    }

    static void v86() {
        Map<String, Object> bad = mk(map("type", "token_individual",
            "designator", "x"));
        Validation schema =
            SchemaValidator.validateSchema(bad, "token_individual");
        check(!schema.ok && schema.anyReasonContains("instantiates"),
              schema.reason());
    }

    static void v87() {
        String c = id(cnt("human_patient"));
        check(!id(individual(c, "hash_a")).equals(id(individual(c, "hash_b"))),
              "distinct designators, distinct individuals");
    }

    static void v88() {
        Map<String, Object> o = occ("bilateral_hippocampal_resection");
        Map<String, Object> t = token(id(o), map(
            "start", "1953-08-25T00:00:00Z", "end", "1953-08-25T00:00:00Z"));
        Validation schema = SchemaValidator.validateSchema(t, null);
        check(schema.ok, schema.reason());
    }

    static void v89() {
        String o = id(occ("amnesia_onset"));
        Map<String, Object> bounded = token(o, map(
            "start", "1953-08-25T00:00:00Z", "end", "1953-08-26T00:00:00Z"));
        Map<String, Object> instantaneous = token(o, map(
            "start", "1953-08-25T00:00:00Z"));
        Map<String, Object> ongoing = token(o, map(
            "start", "1953-08-25T00:00:00Z", "open", Boolean.TRUE));
        check(Set.of(id(bounded), id(instantaneous), id(ongoing)).size() == 3,
              "three distinct interval shapes");
    }

    static void v90() {
        String o = id(occ("resection"));
        String c = id(cnt("human_patient"));
        String patient = id(individual(c, "p"));
        String surgeon = id(individual(c, "s"));
        Map<String, Object> t = token(o, map("start", "1953-08-25T00:00:00Z"),
            List.of(map("role", "patient", "filler", patient),
                    map("role", "agent", "filler", surgeon)));
        Validation schema = SchemaValidator.validateSchema(t, null);
        check(schema.ok, schema.reason());
    }

    static void v91() {
        Map<String, Object> q = quality("cortisol_concentration", "quantity",
                                        "ug/dL");
        Validation schema = SchemaValidator.validateSchema(q, null);
        check(schema.ok, schema.reason());
    }

    static Object[] stateFixture(String datatype, Map<String, Object> value,
                                 String unit) {
        Map<String, Object> q = quality("cortisol_concentration", datatype,
                                        unit);
        String c = id(cnt("human_patient"));
        String subj = id(individual(c, "p"));
        Map<String, Object> st = state(subj, id(q), value, map(
            "start", "2026-01-01T00:00:00Z", "end", "2026-01-01T01:00:00Z"));
        return new Object[] {st, q};
    }

    @SuppressWarnings("unchecked")
    static void v92() {
        Object[] fx = stateFixture("quantity",
            map("quantity", Double.valueOf(15.0), "unit", "ug/dL"), "ug/dL");
        Map<String, Object> st = (Map<String, Object>) fx[0];
        Map<String, Object> q = (Map<String, Object>) fx[1];
        Validation schema = SchemaValidator.validateSchema(st, null);
        check(schema.ok, schema.reason());
        check(Semantics.stateGaps(st, q).isEmpty(), "expected no gaps");
    }

    @SuppressWarnings("unchecked")
    static void v93() {
        Object[] fx = stateFixture("categorical",
            map("categorical", "elevated"), null);
        Map<String, Object> st = (Map<String, Object>) fx[0];
        Map<String, Object> q = (Map<String, Object>) fx[1];
        Validation schema = SchemaValidator.validateSchema(st, null);
        check(schema.ok, schema.reason());
        check(Semantics.stateGaps(st, q).isEmpty(), "expected no gaps");
    }

    @SuppressWarnings("unchecked")
    static void v94() {
        Object[] fx = stateFixture("boolean",
            map("boolean", Boolean.TRUE), null);
        Map<String, Object> st = (Map<String, Object>) fx[0];
        Map<String, Object> q = (Map<String, Object>) fx[1];
        Validation schema = SchemaValidator.validateSchema(st, null);
        check(schema.ok, schema.reason());
        check(Semantics.stateGaps(st, q).isEmpty(), "expected no gaps");
    }

    @SuppressWarnings("unchecked")
    static void v95() {
        Object[] fx = stateFixture("quantity",
            map("categorical", "elevated"), "ug/dL");
        Map<String, Object> st = (Map<String, Object>) fx[0];
        Map<String, Object> q = (Map<String, Object>) fx[1];
        check(Semantics.stateGaps(st, q).equals(List.of("value_type_mismatch")),
              "expected value_type_mismatch");
    }

    @SuppressWarnings("unchecked")
    static void v96() {
        Object[] fx = stateFixture("quantity",
            map("quantity", Double.valueOf(15.0), "unit", "mg/dL"), "ug/dL");
        Map<String, Object> st = (Map<String, Object>) fx[0];
        Map<String, Object> q = (Map<String, Object>) fx[1];
        check(Semantics.stateGaps(st, q).equals(List.of("unit_mismatch")),
              "expected unit_mismatch");
    }

    static Object[] lawAndTokens() {
        Map<String, Object> oCause = occ("resection");
        Map<String, Object> oEffect = occ("amnesia_onset");
        Map<String, Object> law = cro(List.of(id(oCause)), List.of(id(oEffect)),
            map("temporal", map("minimum_delay", Long.valueOf(0L),
                    "maximum_delay", Long.valueOf(1L), "unit", "days"),
                "modality", "sufficient"));
        Map<String, Object> tCause = token(id(oCause),
            map("start", "1953-08-25T00:00:00Z"));
        Map<String, Object> tEffect = token(id(oEffect),
            map("start", "1953-08-25T00:00:00Z", "open", Boolean.TRUE));
        return new Object[] {law, oCause, oEffect, tCause, tEffect};
    }

    @SuppressWarnings("unchecked")
    static void v97() {
        Object[] fx = lawAndTokens();
        Map<String, Object> law = (Map<String, Object>) fx[0];
        Map<String, Object> tc = (Map<String, Object>) fx[3];
        Map<String, Object> te = (Map<String, Object>) fx[4];
        Map<String, Object> claim = tcc(List.of(id(tc)), List.of(id(te)),
            map("covering_law", id(law),
                "actual_delay", map("duration", Long.valueOf(0L),
                    "unit", "instant"),
                "counterfactual", Boolean.TRUE));
        Validation schema = SchemaValidator.validateSchema(claim, null);
        check(schema.ok, schema.reason());
    }

    @SuppressWarnings("unchecked")
    static void v98() {
        Object[] fx = lawAndTokens();
        Map<String, Object> tc = (Map<String, Object>) fx[3];
        Map<String, Object> te = (Map<String, Object>) fx[4];
        Map<String, Object> claim = tcc(List.of(id(tc)), List.of(id(te)),
            new LinkedHashMap<>());
        Validation schema = SchemaValidator.validateSchema(claim, null);
        check(schema.ok, schema.reason());
        check(!claim.containsKey("covering_law"),
              "covering_law is optional and absent here");
    }

    @SuppressWarnings("unchecked")
    static void v99() {
        Object[] fx = lawAndTokens();
        Map<String, Object> law = (Map<String, Object>) fx[0];
        check(Semantics.delayWithinWindow(
                map("duration", Long.valueOf(0L), "unit", "instant"),
                asMap(law.get("temporal"))),
              "instant delay is within a 0-1 day window");
    }

    static void v100() {
        Map<String, Object> temporal = map("minimum_delay", Long.valueOf(0L),
            "maximum_delay", Long.valueOf(1L), "unit", "hours");
        check(!Semantics.delayWithinWindow(
                map("duration", Long.valueOf(5L), "unit", "days"), temporal),
              "5 days exceeds a 1-hour window");
    }

    static void v101() {
        String o = id(occ("x"));
        Map<String, Object> cause = token(o, map("start",
            "2026-01-02T00:00:00Z"));
        Map<String, Object> effect = token(o, map("start",
            "2026-01-01T00:00:00Z"));
        Map<String, Object> claim = tcc(List.of(id(cause)), List.of(id(effect)),
            new LinkedHashMap<>());
        check(Semantics.retrocausal(claim, omap(cause, effect)),
              "cause after effect is retrocausal");
    }

    @SuppressWarnings("unchecked")
    static void v102() {
        Map<String, Object> other = cro(List.of(sym("occurrent:foo")),
            List.of(sym("occurrent:bar")));
        Object[] fx = lawAndTokens();
        Map<String, Object> tc = (Map<String, Object>) fx[3];
        Map<String, Object> te = (Map<String, Object>) fx[4];
        Map<String, Object> claim = tcc(List.of(id(tc)), List.of(id(te)),
            map("covering_law", id(other)));
        check(Semantics.coveringLawMismatch(claim, omap(tc, te), other),
              "tokens do not instantiate the cited law");
    }

    static void v103() {
        Map<String, Object> a = signed("assertion", map(
            "about", sym("token_occurrence:t"),
            "evidence_type", "observation", "confidence", Double.valueOf(0.9)),
            "signer", 0);
        Validation schema = SchemaValidator.validateSchema(a, null);
        check(schema.ok, schema.reason());
    }

    static void v104() {
        List<Object> ev = List.of(sym("token_occurrence:t1"),
                                  sym("token_causal_claim:c1"));
        Map<String, Object> base = map("type", "assertion",
            "about", sym("causal_relation_object:law"),
            "source", key("signer").publicId,
            "evidence_type", "intervention",
            "strength", Double.valueOf(0.95),
            "confidence", Double.valueOf(0.99),
            "timestamp", "2026-07-14T00:00:00Z");
        Map<String, Object> a = new LinkedHashMap<>(base);
        a.put("evidenced_by", ev);
        Map<String, Object> withId = new LinkedHashMap<>(a);
        withId.put("id", Canonical.identify(a, null));
        Validation schema = SchemaValidator.validateSchema(withId, null);
        check(schema.ok, schema.reason());
        check(!Canonical.identify(a, null).equals(Canonical.identify(base,
                null)), "evidenced_by is identity-bearing");
    }

    static void v105() {
        Map<String, Object> a = signed("assertion", map(
            "about", sym("causal_relation_object:law"),
            "evidence_type", "simulation", "confidence", Double.valueOf(0.5)),
            "signer", 0);
        Validation schema = SchemaValidator.validateSchema(a, null);
        check(schema.ok, schema.reason());
    }

    static final Set<String> WHOLE_WORD;

    static {
        Set<String> ww = new java.util.HashSet<>(SCHEMES);
        ww.add("ed25519");
        WHOLE_WORD = ww;
    }

    static void scanSchemes(Object node, List<String> ids) {
        if (node instanceof String) {
            java.util.regex.Matcher m = Pattern
                .compile("^([a-z0-9_]+):[0-9a-f]{64}$")
                .matcher((String) node);
            if (m.matches()) {
                ids.add(m.group(1));
            }
        } else if (node instanceof List) {
            for (Object x : (List<?>) node) {
                scanSchemes(x, ids);
            }
        } else if (node instanceof Map) {
            for (Object x : ((Map<?, ?>) node).values()) {
                scanSchemes(x, ids);
            }
        }
    }

    static void v106() {
        for (int n = 1; n <= 38; n++) {
            List<String> ids = new ArrayList<>();
            scanSchemes(vec(n), ids);
            for (String scheme : ids) {
                check(WHOLE_WORD.contains(scheme),
                      "V106: abbreviated scheme " + scheme + " in vector " + n);
            }
        }
        Map<String, Object> rec = map("type", "occurrent",
            "label", "press_button", "category", "action");
        check(Canonical.identify(rec, null).equals(Canonical.identify(rec,
                null)), "identity is deterministic");
        check(Canonical.identify(rec, null).split(":", 2)[0].equals("occurrent"),
              "whole-word scheme prefix");
    }

    static void v107() {
        String hexid = "0".repeat(64);
        // NOTE: the abbreviated prefix below is intentional (the negative
        // test); it must NOT be re-minted. "c" "r" "o" is assembled to
        // survive re-mint tools.
        String croAbbr = "c" + "r" + "o";
        Map<String, Object> abbreviated = map("type", "causal_relation_object",
            "id", croAbbr + ":" + hexid,
            "causes", List.of("occurrent:" + hexid),
            "effects", List.of("occurrent:" + hexid));
        Validation schemaA = SchemaValidator.validateSchema(abbreviated,
            "causal_relation_object");
        check(!schemaA.ok, "abbreviated scheme must be rejected");
        Map<String, Object> abbrStr = map("type", "stratum",
            "id", "str:" + hexid, "label", "cellular",
            "scheme", "neuroendocrine", "ordinal", Long.valueOf(6L));
        Validation schemaS = SchemaValidator.validateSchema(abbrStr, "stratum");
        check(!schemaS.ok, "abbreviated str: scheme must be rejected");
        Map<String, Object> whole = map("type", "causal_relation_object",
            "id", "causal_relation_object:" + hexid,
            "causes", List.of("occurrent:" + hexid),
            "effects", List.of("occurrent:" + hexid));
        Validation schemaW = SchemaValidator.validateSchema(whole,
            "causal_relation_object");
        check(schemaW.ok, schemaW.reason());
    }

    // -----------------------------------------------------------------

    static void runVector(int n) {
        switch (n) {
            case 1: v01(); break;
            case 2: v02(); break;
            case 3: v03(); break;
            case 4: v04(); break;
            case 5: v05(); break;
            case 6: v06(); break;
            case 7: v07(); break;
            case 8: v08(); break;
            case 9: v09(); break;
            case 10: v10(); break;
            case 11: v11(); break;
            case 12: v12(); break;
            case 13: v13(); break;
            case 14: v14(); break;
            case 15: v15(); break;
            case 16: v16(); break;
            case 17: v17(); break;
            case 18: v18(); break;
            case 19: v19(); break;
            case 20: v20(); break;
            case 21: v21(); break;
            case 22: v22(); break;
            case 23: v23(); break;
            case 24: v24(); break;
            case 25: v25(); break;
            case 26: v26(); break;
            case 27: v27(); break;
            case 28: v28(); break;
            case 29: v29(); break;
            case 30: v30(); break;
            case 31: v31(); break;
            case 32: v32(); break;
            case 33: v33(); break;
            case 34: v34(); break;
            case 35: v35(); break;
            case 36: v36(); break;
            case 37: v37(); break;
            case 38: v38(); break;
            case 39: v39(); break;
            case 40: v40(); break;
            case 41: v41(); break;
            case 42: v42(); break;
            case 43: v43(); break;
            case 44: v44(); break;
            case 45: v45(); break;
            case 46: v46(); break;
            case 47: v47(); break;
            case 48: v48(); break;
            case 49: v49(); break;
            case 50: v50(); break;
            case 51: v51(); break;
            case 52: v52(); break;
            case 53: v53(); break;
            case 54: v54(); break;
            case 55: v55(); break;
            case 56: v56(); break;
            case 57: v57(); break;
            case 58: v58(); break;
            case 59: v59(); break;
            case 60: v60(); break;
            case 61: v61(); break;
            case 62: v62(); break;
            case 63: v63(); break;
            case 64: v64(); break;
            case 65: v65(); break;
            case 66: v66(); break;
            case 67: v67(); break;
            case 68: v68(); break;
            case 69: v69(); break;
            case 70: v70(); break;
            case 71: v71(); break;
            case 72: v72(); break;
            case 73: v73(); break;
            case 74: v74(); break;
            case 75: v75(); break;
            case 76: v76(); break;
            case 77: v77(); break;
            case 78: v78(); break;
            case 79: v79(); break;
            case 80: v80(); break;
            case 81: v81(); break;
            case 82: v82(); break;
            case 83: v83(); break;
            case 84: v84(); break;
            case 85: v85(); break;
            case 86: v86(); break;
            case 87: v87(); break;
            case 88: v88(); break;
            case 89: v89(); break;
            case 90: v90(); break;
            case 91: v91(); break;
            case 92: v92(); break;
            case 93: v93(); break;
            case 94: v94(); break;
            case 95: v95(); break;
            case 96: v96(); break;
            case 97: v97(); break;
            case 98: v98(); break;
            case 99: v99(); break;
            case 100: v100(); break;
            case 101: v101(); break;
            case 102: v102(); break;
            case 103: v103(); break;
            case 104: v104(); break;
            case 105: v105(); break;
            case 106: v106(); break;
            case 107: v107(); break;
            default:
                throw new IllegalArgumentException("no vector " + n);
        }
    }

    public static void main(String[] args) {
        System.out.println(
            "causalontology-java conformance run (specification 2.0.0)");
        System.out.print(
            "internal checks (RFC 8032, RFC 8785, fixed constants) ... ");
        internalChecks();
        System.out.println("ok");
        int total = 107;
        int failures = 0;
        for (int n = 1; n <= total; n++) {
            String name = vectorFile(n).getFileName().toString();
            if (name.endsWith(".json")) {
                name = name.substring(0, name.length() - ".json".length());
            }
            try {
                runVector(n);
                System.out.println("PASS  " + name);
            } catch (Exception e) {
                failures++;
                System.out.println("FAIL  " + name + " :: " + e);
            }
        }
        System.out.println("-".repeat(60));
        System.out.println((total - failures) + "/" + total
                           + " vectors passed");
        if (failures > 0) {
            System.exit(1);
        }
        System.out.println("causalontology-java is CONFORMANT to the suite "
                           + "(vectors frozen at specification 2.0.0).");
    }
}

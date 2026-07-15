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
        Set.of("occurrent", "causal_relation_object", "continuant", "realizable", "assertion", "enrichment", "retraction", "succession");

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
            default:
                throw new IllegalArgumentException("no vector " + n);
        }
    }

    public static void main(String[] args) {
        System.out.println("causalontology-java conformance run");
        System.out.print(
            "internal checks (RFC 8032 known-answer, RFC 8785 basics) ... ");
        internalChecks();
        System.out.println("ok");
        int failures = 0;
        for (int n = 1; n <= 38; n++) {
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
        System.out.println((38 - failures) + "/38 vectors passed");
        if (failures > 0) {
            System.exit(1);
        }
        System.out.println("causalontology-java is CONFORMANT to the suite "
                           + "(vectors frozen at specification 1.0.0).");
    }
}

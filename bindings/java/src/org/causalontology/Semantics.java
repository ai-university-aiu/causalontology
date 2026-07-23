package org.causalontology;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * The semantic rules beyond the schemas (spec/semantics.md).
 *
 * Local rules are checked here; store-context rules (materialized
 * acyclicity, retraction lineage) live in Store where the context exists.
 */
public final class Semantics {

    /** Rule 4: the fixed unit-conversion constants (average Gregorian). */
    public static final Map<String, Long> UNIT_SECONDS;

    /**
     * 3.0.0: the ordinal (dimensionless) temporal units. A tick is a discrete
     * step with NO wall-clock mapping; a tick window is ordered by integer
     * comparison, and an ordinal window and a wall-clock window are DIFFERENT
     * DIMENSIONS that do not compare (mixing them is never within-window and
     * never overlapping).
     */
    public static final Set<String> ORDINAL_UNITS = Set.of("ticks");

    /** The optional CRO fields, in the fixed partiality order. */
    public static final List<String> CRO_OPTIONAL_FIELDS =
        List.of("mechanism", "temporal", "modality", "context");

    // Rule 6 (amended): necessary, sufficient, contributory, enabling are
    // mutually compatible; preventive opposes all four.
    private static final Set<String> POSITIVE =
        Set.of("necessary", "sufficient", "contributory", "enabling");

    /** Rule 12: which kinds a field may enrich, and the entry shape. */
    static final class FieldSpec {
        final Set<String> legalKinds;
        final String shape;

        FieldSpec(Set<String> legalKinds, String shape) {
            this.legalKinds = legalKinds;
            this.shape = shape;
        }
    }

    static final Map<String, FieldSpec> ENRICHMENT_FIELDS;

    static {
        Map<String, Long> units = new LinkedHashMap<>();
        units.put("instant", 0L);
        units.put("seconds", 1L);
        units.put("minutes", 60L);
        units.put("hours", 3600L);
        units.put("days", 86400L);
        units.put("weeks", 604800L);
        units.put("months", 2629746L);
        units.put("years", 31556952L);
        UNIT_SECONDS = Collections.unmodifiableMap(units);

        Map<String, FieldSpec> fields = new LinkedHashMap<>();
        fields.put("aliases",
                   new FieldSpec(Set.of("occurrent", "continuant"), "alias"));
        fields.put("participants",
                   new FieldSpec(Set.of("occurrent"), "continuant"));
        fields.put("subsumes",
                   new FieldSpec(Set.of("continuant"), "continuant"));
        fields.put("part_of",
                   new FieldSpec(Set.of("continuant"), "continuant"));
        fields.put("realized_in",
                   new FieldSpec(Set.of("realizable"), "occurrent"));
        fields.put("occurrent_subsumes",
                   new FieldSpec(Set.of("occurrent"), "occurrent"));
        fields.put("occurrent_part_of",
                   new FieldSpec(Set.of("occurrent"), "occurrent"));
        ENRICHMENT_FIELDS = Collections.unmodifiableMap(fields);
    }

    private Semantics() {
    }

    /** "ordinal" for a tick-like unit, else "wallclock" (3.0.0). */
    private static String dimension(String unit) {
        return ORDINAL_UNITS.contains(unit) ? "ordinal" : "wallclock";
    }

    /**
     * A comparable magnitude WITHIN one dimension: a raw tick count for an
     * ordinal unit, seconds for a wall-clock unit. Never mix dimensions.
     */
    private static double magnitude(double value, String unit) {
        if (ORDINAL_UNITS.contains(unit)) {
            return value; // a dimensionless tick count
        }
        if (unit.equals("instant")) {
            return 0;
        }
        return value * UNIT_SECONDS.get(unit);
    }

    private static String kindOfId(String identifier) {
        int colon = identifier.indexOf(':');
        String prefix = colon >= 0 ? identifier.substring(0, colon)
                                   : identifier;
        return Canonical.KIND_OF_PREFIX.get(prefix);
    }

    /** (ok, reasons) - the locally checkable semantic rules. */
    public static Validation validateSemantics(Map<String, Object> obj,
                                               String kind) {
        String k = kind != null ? kind : Canonical.inferKind(obj);
        List<String> errors = new ArrayList<>();

        if (k.equals("causal_relation_object")) {
            Object temporalObj = obj.get("temporal");
            if (temporalObj instanceof Map) {
                Map<?, ?> temporal = (Map<?, ?>) temporalObj;
                Object minimum_delay = temporal.get("minimum_delay");
                Object maximum_delay = temporal.get("maximum_delay");
                if (minimum_delay instanceof Number && maximum_delay instanceof Number
                        && ((Number) minimum_delay).doubleValue()
                           > ((Number) maximum_delay).doubleValue()) {
                    errors.add("minimum_delay must be <= maximum_delay");
                }
            }
            String oid = null;
            if (obj.get("id") instanceof String) {
                String candidate = (String) obj.get("id");
                if (!candidate.isEmpty()) {
                    oid = candidate;
                }
            }
            if (oid != null) {
                Object mechanism = obj.get("mechanism");
                if (mechanism instanceof List
                        && ((List<?>) mechanism).contains(oid)) {
                    errors.add("mechanism must be acyclic "
                               + "(a Causal Relation Object may not contain "
                               + "itself)");
                }
                if (oid.equals(obj.get("refines"))) {
                    errors.add("refines must be acyclic");
                }
            }
            // Rule 16, clause 1 (contradictory_skip): a HARD,
            // locally-decidable contradiction between skips:true and a
            // non-empty mechanism.
            if (Boolean.TRUE.equals(obj.get("skips"))
                    && obj.get("mechanism") instanceof List
                    && !((List<?>) obj.get("mechanism")).isEmpty()) {
                errors.add("contradictory_skip: skips is true but a mechanism "
                           + "is present");
            }
        }

        if (k.equals("enrichment")) {
            Object fieldObj = obj.get("field");
            String about = "";
            if (obj.get("about") instanceof String) {
                about = (String) obj.get("about");
            }
            Object entry = obj.get("entry");
            FieldSpec spec = null;
            if (fieldObj instanceof String) {
                spec = ENRICHMENT_FIELDS.get((String) fieldObj);
            }
            if (spec != null) {
                String aboutKind = kindOfId(about);
                if (aboutKind != null && !spec.legalKinds.contains(aboutKind)) {
                    errors.add(fieldObj + " is not a legal field for a "
                               + aboutKind + " (rule 12)");
                }
                if (spec.shape.equals("alias")) {
                    boolean shaped = entry instanceof Map
                        && ((Map<?, ?>) entry).containsKey("lang")
                        && ((Map<?, ?>) entry).containsKey("text");
                    if (!shaped) {
                        errors.add("an aliases entry must be a "
                                   + "language-tagged text object");
                    }
                } else {
                    boolean shaped = entry instanceof String
                        && ((String) entry).startsWith(spec.shape + ":");
                    if (!shaped) {
                        errors.add("a " + fieldObj + " entry must be a "
                                   + spec.shape + ": identifier");
                    }
                }
            }
        }

        // 3.0.0 Rule 22, local clause: a Cross Stratal Seam that DRAWS a chain
        // has, by drawing it, a modelled intervening mechanism - so
        // mechanism_status 'absent' contradicts a present chain (the honest-
        // ignorance distinction must stay honest). The stratal well-formedness
        // (non-adjacency, adjacency of chain steps, scheme, the home rule)
        // needs the strata map and lives in seamWellformed, exactly as bridge
        // well-formedness does.
        if (k.equals("cross_stratal_seam")) {
            if (obj.get("chain") != null
                    && "absent".equals(obj.get("mechanism_status"))) {
                errors.add("contradictory_seam: a drawn chain cannot carry "
                           + "mechanism_status 'absent' (a drawn mechanism is "
                           + "not absent)");
            }
        }

        // 4.0.0 Rule 24, local clause: a predicted_occurrence's interval
        // carries exactly ONE temporal dimension - a wall-clock start (optional
        // end) or an ordinal start_tick (optional end_tick), never both and
        // never neither. Per Rule 23 the two dimensions never compare. The
        // pairing check of a prediction_error against its predicted_occurrence
        // and its observed token_occurrence needs those objects and lives in
        // predictionPairingMismatch, exactly as coveringLawMismatch does.
        if (k.equals("predicted_occurrence")) {
            Map<?, ?> iv = obj.get("interval") instanceof Map
                ? (Map<?, ?>) obj.get("interval") : Collections.emptyMap();
            boolean wall = iv.containsKey("start");
            boolean tick = iv.containsKey("start_tick");
            if (wall && tick) {
                errors.add("dimension_conflict: a predicted interval must "
                           + "carry exactly one temporal dimension, not a "
                           + "wall-clock start AND an ordinal start_tick");
            }
            if (!wall && !tick) {
                errors.add("missing_dimension: a predicted interval must "
                           + "carry a wall-clock start or an ordinal "
                           + "start_tick");
            }
        }

        return new Validation(errors.isEmpty(), errors);
    }

    /** The optional CRO fields that are unspecified (empty = complete). */
    public static List<String> isPartial(Map<String, Object> cro) {
        List<String> missing = new ArrayList<>();
        for (String field : CRO_OPTIONAL_FIELDS) {
            if (!cro.containsKey(field)) {
                missing.add(field);
            }
        }
        return missing;
    }

    /**
     * Rule 4: temporal admissibility. For a wall-clock window elapsed is in
     * seconds; for an ordinal ('ticks') window elapsed is a tick count.
     * Ordering is by magnitude WITHIN the window's own dimension (3.0.0).
     */
    public static boolean admissible(Map<String, Object> cro,
                                     double elapsed) {
        Object temporalObj = cro.get("temporal");
        if (temporalObj == null) {
            return true; // no window imposes no constraint
        }
        Map<?, ?> temporal = (Map<?, ?>) temporalObj;
        String unit = (String) temporal.get("unit");
        double lo = magnitude(
            ((Number) temporal.get("minimum_delay")).doubleValue(), unit);
        double hi = magnitude(
            ((Number) temporal.get("maximum_delay")).doubleValue(), unit);
        return lo <= elapsed && elapsed <= hi;
    }

    private static boolean windowOverlap(Map<String, Object> a,
                                         Map<String, Object> b) {
        Object taObj = a.get("temporal");
        Object tbObj = b.get("temporal");
        if (taObj == null || tbObj == null) {
            return true; // either absent counts as overlapping
        }
        Map<?, ?> ta = (Map<?, ?>) taObj;
        Map<?, ?> tb = (Map<?, ?>) tbObj;
        String unitA = (String) ta.get("unit");
        String unitB = (String) tb.get("unit");
        // 3.0.0: an ordinal window and a wall-clock window never overlap.
        if (!dimension(unitA).equals(dimension(unitB))) {
            return false;
        }
        double loA = magnitude(
            ((Number) ta.get("minimum_delay")).doubleValue(), unitA);
        double hiA = magnitude(
            ((Number) ta.get("maximum_delay")).doubleValue(), unitA);
        double loB = magnitude(
            ((Number) tb.get("minimum_delay")).doubleValue(), unitB);
        double hiB = magnitude(
            ((Number) tb.get("maximum_delay")).doubleValue(), unitB);
        return loA <= hiB && loB <= hiA;
    }

    private static boolean contextsCompatible(Map<String, Object> a,
                                              Map<String, Object> b) {
        List<?> ca = a.get("context") instanceof List
            ? (List<?>) a.get("context") : null;
        List<?> cb = b.get("context") instanceof List
            ? (List<?>) b.get("context") : null;
        if (ca == null || ca.isEmpty() || cb == null || cb.isEmpty()) {
            return true; // either absent (or empty)
        }
        Set<Object> sa = new HashSet<>(ca);
        Set<Object> sb = new HashSet<>(cb);
        return sa.equals(sb) || sb.containsAll(sa) || sa.containsAll(sb);
    }

    private static boolean sameSet(Object listA, Object listB) {
        Set<Object> sa = new HashSet<>((List<?>) listA);
        Set<Object> sb = new HashSet<>((List<?>) listB);
        return sa.equals(sb);
    }

    /** Rule 6: the formal conflict test. */
    public static boolean conflicts(Map<String, Object> a,
                                    Map<String, Object> b) {
        if (!sameSet(a.get("causes"), b.get("causes"))) {
            return false;
        }
        if (!sameSet(a.get("effects"), b.get("effects"))) {
            return false;
        }
        if (!contextsCompatible(a, b)) {
            return false;
        }
        if (!windowOverlap(a, b)) {
            return false;
        }
        Object ma = a.get("modality");
        Object mb = b.get("modality");
        boolean aPreventiveBPositive = "preventive".equals(ma)
            && mb instanceof String && POSITIVE.contains((String) mb);
        boolean bPreventiveAPositive = "preventive".equals(mb)
            && ma instanceof String && POSITIVE.contains((String) ma);
        return aPreventiveBPositive || bPreventiveAPositive;
    }

    /** Rule 3: is child a valid refinement of parent? */
    public static Validation refinementValid(Map<String, Object> child,
                                             Map<String, Object> parent) {
        if (!Objects.equals(child.get("refines"), parent.get("id"))) {
            return Validation.invalid(
                "child does not name the parent in refines");
        }
        if (!sameSet(child.get("causes"), parent.get("causes"))
                || !sameSet(child.get("effects"), parent.get("effects"))) {
            return Validation.invalid(
                "a refinement must keep the parent's causes and effects");
        }
        int added = 0;
        for (String field : CRO_OPTIONAL_FIELDS) {
            if (parent.containsKey(field)) {
                if (!Json.deepEquals(child.get(field), parent.get(field))) {
                    return Validation.invalid(
                        "a refinement may not change a field the parent "
                        + "specified; this is a rival claim");
                }
            } else if (child.containsKey(field)) {
                added++;
            }
        }
        if (added == 0) {
            return Validation.invalid(
                "a refinement must add at least one unspecified field");
        }
        return new Validation(true, List.of("valid refinement"));
    }

    /**
     * Rule 7: "consistent" | "inconsistent" | "indeterminate".
     *
     * members maps CRO identifier to CRO object for the parent's mechanism
     * entries (the store's view of them).
     */
    public static String hierarchyConsistent(
            Map<String, Object> parent,
            Map<String, Map<String, Object>> members) {
        return hierarchyConsistent(parent, members,
                                   Collections.emptyList());
    }

    /**
     * ALGORITHM B (amended Rule 7): "consistent" | "inconsistent" |
     * "indeterminate", ACROSS STRATA via bridged reachability.
     *
     * bridges: the store's bridge objects (empty -> 1.0.0 literal
     * reachability, the degenerate case N12.2.3).
     */
    public static String hierarchyConsistent(
            Map<String, Object> parent,
            Map<String, Map<String, Object>> members,
            List<Map<String, Object>> bridges) {
        List<?> mechanism = List.of();
        if (parent.get("mechanism") instanceof List) {
            mechanism = (List<?>) parent.get("mechanism");
        }
        if (mechanism.isEmpty()) {
            return "consistent"; // nothing claimed, nothing to check (N12.2.1)
        }
        Map<Object, Set<Object>> edges = new LinkedHashMap<>();
        for (Object mid : mechanism) {
            Map<String, Object> member = members.get(mid);
            if (member == null) {
                return "indeterminate"; // dangling; ignorance, not refutation
            }
            List<?> causes = (List<?>) member.get("causes");
            List<?> effects = (List<?>) member.get("effects");
            for (Object cause : causes) {
                edges.computeIfAbsent(cause, c -> new LinkedHashSet<>())
                     .addAll(effects);
            }
        }
        List<?> parentCauses = (List<?>) parent.get("causes");
        List<?> parentEffects = (List<?>) parent.get("effects");
        Map<Object, Set<Object>> bCause = new LinkedHashMap<>();
        for (Object c : parentCauses) {
            bCause.put(c, bridgeClosure(c, bridges));
        }
        Map<Object, Set<Object>> bEffect = new LinkedHashMap<>();
        for (Object e : parentEffects) {
            bEffect.put(e, bridgeClosure(e, bridges));
        }
        for (Object cause : parentCauses) {
            for (Object effect : parentEffects) {
                boolean connected = false;
                for (Object cp : bCause.get(cause)) {
                    for (Object ep : bEffect.get(effect)) {
                        if (reachable(cp, ep, edges)) {
                            connected = true;
                            break;
                        }
                    }
                    if (connected) {
                        break;
                    }
                }
                if (!connected) {
                    return "inconsistent";
                }
            }
        }
        return "consistent";
    }

    /**
     * ALGORITHM A (N12.1): every finer occurrent an occurrent resolves to,
     * following bridges downward, transitively; includes the start (N12.1.1).
     * The visited guard (N12.1.2) prevents an infinite loop on cyclic data.
     */
    public static Set<Object> bridgeClosure(
            Object occurrentId, List<Map<String, Object>> bridges) {
        Set<Object> result = new LinkedHashSet<>();
        result.add(occurrentId);
        Deque<Object> frontier = new ArrayDeque<>();
        frontier.push(occurrentId);
        Set<Object> visited = new HashSet<>();
        Map<Object, List<Map<String, Object>>> coarseIndex =
            new LinkedHashMap<>();
        for (Map<String, Object> b : bridges) {
            coarseIndex.computeIfAbsent(b.get("coarse"),
                                        k -> new ArrayList<>()).add(b);
        }
        while (!frontier.isEmpty()) {
            Object current = frontier.pop();
            if (!visited.add(current)) {
                continue;
            }
            List<Map<String, Object>> bs = coarseIndex.get(current);
            if (bs != null) {
                for (Map<String, Object> b : bs) {
                    for (Object f : (List<?>) b.get("fine")) {
                        result.add(f);
                        frontier.push(f);
                    }
                }
            }
        }
        return result;
    }

    private static boolean reachable(Object src, Object dst,
                                     Map<Object, Set<Object>> edges) {
        Set<Object> seen = new HashSet<>();
        Deque<Object> stack = new ArrayDeque<>();
        stack.push(src);
        while (!stack.isEmpty()) {
            Object node = stack.pop();
            if (node.equals(dst)) {
                return true;
            }
            if (!seen.add(node)) {
                continue;
            }
            Set<Object> next = edges.get(node);
            if (next != null) {
                for (Object n : next) {
                    stack.push(n);
                }
            }
        }
        return false;
    }

    // -----------------------------------------------------------------------
    // 2.0.0 NORMATIVE ALGORITHMS (Section 12) and rules 13-21 helpers
    // -----------------------------------------------------------------------

    private static Object stratumOf(
            Object occId, Map<String, Map<String, Object>> occMap) {
        Map<String, Object> occ = occMap.get(occId);
        return occ == null ? null : occ.get("stratum");
    }

    private static long ordinalOf(Object stratumId,
                                  Map<String, Map<String, Object>> stratumMap) {
        return ((Number) stratumMap.get(stratumId).get("ordinal")).longValue();
    }

    /**
     * ALGORITHM C (Rule 15): "intra_stratal" | "adjacent_stratal" |
     * "skipping" | "mixed" | "unclassifiable" | "scheme_mismatch".
     */
    public static String classifyCro(
            Map<String, Object> cro,
            Map<String, Map<String, Object>> occMap,
            Map<String, Map<String, Object>> stratumMap) {
        List<Object> causeStrata = new ArrayList<>();
        for (Object c : (List<?>) cro.get("causes")) {
            causeStrata.add(stratumOf(c, occMap));
        }
        List<Object> effectStrata = new ArrayList<>();
        for (Object e : (List<?>) cro.get("effects")) {
            effectStrata.add(stratumOf(e, occMap));
        }
        List<Object> all = new ArrayList<>(causeStrata);
        all.addAll(effectStrata);
        for (Object s : all) {
            if (s == null) {
                return "unclassifiable"; // surface unstratified_occurrent
            }
        }
        Set<Object> schemes = new HashSet<>();
        for (Object s : new LinkedHashSet<>(all)) {
            schemes.add(stratumMap.get(s).get("scheme"));
        }
        if (schemes.size() > 1) {
            return "scheme_mismatch"; // HARD
        }
        List<Long> cOrd = new ArrayList<>();
        for (Object s : causeStrata) {
            cOrd.add(ordinalOf(s, stratumMap));
        }
        List<Long> eOrd = new ArrayList<>();
        for (Object s : effectStrata) {
            eOrd.add(ordinalOf(s, stratumMap));
        }
        long cMax = Collections.max(cOrd);
        long cMin = Collections.min(cOrd);
        long eMax = Collections.max(eOrd);
        long eMin = Collections.min(eOrd);
        if (cMax == cMin && cMin == eMax && eMax == eMin) {
            return "intra_stratal";
        }
        long gap = Long.MAX_VALUE;
        long span = Long.MIN_VALUE;
        for (long i : cOrd) {
            for (long j : eOrd) {
                long d = Math.abs(i - j);
                gap = Math.min(gap, d);
                span = Math.max(span, d);
            }
        }
        if (span == 1) {
            return "adjacent_stratal";
        }
        if (gap > 1) {
            return "skipping";
        }
        return "mixed"; // some pairs adjacent, some skipping
    }

    /**
     * True iff causes or effects span more than one distinct stratum
     * (surfaces mixed_stratal_endpoints, an invitation; N12.3.2).
     */
    public static boolean endpointsMixed(
            Map<String, Object> cro,
            Map<String, Map<String, Object>> occMap) {
        Set<Object> cs = new HashSet<>();
        for (Object c : (List<?>) cro.get("causes")) {
            cs.add(stratumOf(c, occMap));
        }
        Set<Object> es = new HashSet<>();
        for (Object e : (List<?>) cro.get("effects")) {
            es.add(stratumOf(e, occMap));
        }
        if (cs.contains(null) || es.contains(null)) {
            return false;
        }
        return cs.size() > 1 || es.size() > 1;
    }

    private static boolean hasMechanism(Map<String, Object> cro) {
        return cro.get("mechanism") instanceof List
            && !((List<?>) cro.get("mechanism")).isEmpty();
    }

    /**
     * ALGORITHM D (Rule 16): the gaps a Causal Relation Object surfaces for
     * the skip decision. THE ASYMMETRY (clause 3) is the whole point.
     */
    public static List<String> skipGaps(Map<String, Object> cro,
                                        String classification) {
        List<String> gaps = new ArrayList<>();
        boolean hasMech = hasMechanism(cro);
        boolean skips = Boolean.TRUE.equals(cro.get("skips"));
        if (skips && hasMech) {
            gaps.add("contradictory_skip"); // HARD
            return gaps;
        }
        if (skips && !classification.equals("skipping")
                && !classification.equals("unclassifiable")) {
            gaps.add("vacuous_skip"); // invitation
        }
        if (classification.equals("skipping") && !hasMech) {
            if (skips) {
                // NOTHING: absence is a finding.
                return gaps;
            }
            gaps.add("incomplete_mechanism"); // invitation
        }
        return gaps;
    }

    /**
     * ALGORITHM E helper: normalize a delay to seconds by the fixed table.
     * 3.0.0: an ordinal ('ticks') unit is dimensionless and has NO wall-clock
     * mapping - converting one to seconds is a category error and is refused.
     */
    public static long toSeconds(long duration, String unit) {
        if (ORDINAL_UNITS.contains(unit)) {
            throw new IllegalArgumentException("'" + unit + "' is an ordinal "
                + "(dimensionless) unit and has no wall-clock seconds mapping");
        }
        if (unit.equals("instant")) {
            return 0;
        }
        return duration * UNIT_SECONDS.get(unit);
    }

    /**
     * ALGORITHM E (Rule 20): does an observed delay fall within a covering
     * law's temporal window? Inclusive at both ends (N12.5.2).
     */
    public static boolean delayWithinWindow(Map<String, Object> actualDelay,
                                            Map<String, Object> temporal) {
        if (actualDelay == null || actualDelay.isEmpty()
                || temporal == null || temporal.isEmpty()) {
            return true; // nothing to check
        }
        String delayUnit = (String) actualDelay.get("unit");
        String windowUnit = (String) temporal.get("unit");
        // 3.0.0: an ordinal delay compares to an ordinal window by integer tick
        // count; a tick delay is never within a wall-clock window (or vice
        // versa).
        if (!dimension(delayUnit).equals(dimension(windowUnit))) {
            return false;
        }
        double observed = magnitude(
            ((Number) actualDelay.get("duration")).doubleValue(), delayUnit);
        double lo = magnitude(
            ((Number) temporal.get("minimum_delay")).doubleValue(), windowUnit);
        double hi = magnitude(
            ((Number) temporal.get("maximum_delay")).doubleValue(), windowUnit);
        return lo <= observed && observed <= hi;
    }

    /**
     * Rule 14 / N3.2.1: bridge well-formedness. All of (a)-(e) must hold,
     * else malformed_bridge.
     */
    public static Validation bridgeWellformed(
            Map<String, Object> bridge,
            Map<String, Map<String, Object>> occMap,
            Map<String, Map<String, Object>> stratumMap) {
        Map<String, Object> coarse = occMap.get(bridge.get("coarse"));
        Object cs = coarse == null ? null : coarse.get("stratum");
        if (cs == null) {
            return Validation.invalid(
                "malformed_bridge: coarse has no stratum (a)");
        }
        List<Object> fineStrata = new ArrayList<>();
        for (Object f : (List<?>) bridge.get("fine")) {
            Map<String, Object> fo = occMap.get(f);
            fineStrata.add(fo == null ? null : fo.get("stratum"));
        }
        if (fineStrata.contains(null)) {
            return Validation.invalid(
                "malformed_bridge: a fine member has no stratum (b)");
        }
        if (new HashSet<>(fineStrata).size() != 1) {
            return Validation.invalid(
                "malformed_bridge: fine members span >1 stratum (c)");
        }
        Object fs = fineStrata.get(0);
        if (!stratumMap.get(cs).get("scheme")
                .equals(stratumMap.get(fs).get("scheme"))) {
            return Validation.invalid(
                "malformed_bridge: coarse and fine differ in scheme (d)");
        }
        if (!(ordinalOf(cs, stratumMap) > ordinalOf(fs, stratumMap))) {
            return Validation.invalid(
                "malformed_bridge: coarse ordinal not > fine ordinal (e)");
        }
        return new Validation(true, List.of("well-formed bridge"));
    }

    /**
     * 3.0.0 Rule 22 / Algorithm F: cross-stratal seam well-formedness. All of
     * (a)-(g) must hold, else malformed_seam. A seam is a MANAGED jump across
     * NON-ADJACENT strata; when it DRAWS a chain, the chain must be an
     * adjacent-stratum path spanning the two endpoints' strata.
     */
    public static Validation seamWellformed(
            Map<String, Object> seam,
            Map<String, Map<String, Object>> occMap,
            Map<String, Map<String, Object>> stratumMap) {
        Object srcS = stratumOf(seam.get("source"), occMap);
        Object tgtS = stratumOf(seam.get("target"), occMap);
        if (srcS == null || tgtS == null) {
            return Validation.invalid(
                "malformed_seam: an endpoint has no stratum (a)");
        }
        if (!stratumMap.get(srcS).get("scheme")
                .equals(stratumMap.get(tgtS).get("scheme"))) {
            return Validation.invalid(
                "malformed_seam: endpoints differ in scheme (b)");
        }
        long so = ordinalOf(srcS, stratumMap);
        long to = ordinalOf(tgtS, stratumMap);
        if (Math.abs(so - to) <= 1) {
            return Validation.invalid(
                "malformed_seam: endpoints are adjacent or co-stratal; a seam "
                + "is for NON-adjacent strata (c)");
        }
        Object chainObj = seam.get("chain");
        if (chainObj != null) {
            if ("absent".equals(seam.get("mechanism_status"))) {
                return Validation.invalid(
                    "malformed_seam: a drawn chain contradicts "
                    + "mechanism_status 'absent' (d)");
            }
            long lo = Math.min(so, to);
            long hi = Math.max(so, to);
            List<Long> ords = new ArrayList<>();
            for (Object oid : (List<?>) chainObj) {
                Object st = stratumOf(oid, occMap);
                if (st == null) {
                    return Validation.invalid(
                        "malformed_seam: a chain member has no stratum (e)");
                }
                if (!stratumMap.get(st).get("scheme")
                        .equals(stratumMap.get(srcS).get("scheme"))) {
                    return Validation.invalid(
                        "malformed_seam: a chain member differs in scheme (e)");
                }
                ords.add(ordinalOf(st, stratumMap));
            }
            for (long o : ords) {
                if (!(lo < o && o < hi)) {
                    return Validation.invalid(
                        "malformed_seam: a chain member is not at an "
                        + "INTERVENING stratum, strictly between the endpoints "
                        + "(f)");
                }
            }
            if (ords.size() > 1) {
                boolean allRising = true;
                boolean allFalling = true;
                for (int i = 0; i + 1 < ords.size(); i++) {
                    long d = ords.get(i + 1) - ords.get(i);
                    if (d <= 0) {
                        allRising = false;
                    }
                    if (d >= 0) {
                        allFalling = false;
                    }
                }
                if (!allRising && !allFalling) {
                    return Validation.invalid(
                        "malformed_seam: chain is not strictly monotone from "
                        + "one endpoint toward the other (g)");
                }
            }
        }
        return new Validation(true, List.of("well-formed cross_stratal_seam"));
    }

    /**
     * THE HOME RULE (3.0.0): a Cross Stratal Seam belongs to the COARSEST
     * stratum it touches - the endpoint of the greater ordinal. Returns that
     * stratum's identifier (null when an endpoint is unstratified).
     */
    public static String seamHome(
            Map<String, Object> seam,
            Map<String, Map<String, Object>> occMap,
            Map<String, Map<String, Object>> stratumMap) {
        Object srcS = stratumOf(seam.get("source"), occMap);
        Object tgtS = stratumOf(seam.get("target"), occMap);
        if (srcS == null || tgtS == null) {
            return null;
        }
        return ordinalOf(srcS, stratumMap) >= ordinalOf(tgtS, stratumMap)
            ? (String) srcS : (String) tgtS;
    }

    /** Rule 17 / N4.2.1-2: conduit well-formedness. */
    public static Validation conduitWellformed(
            Map<String, Object> conduit,
            Map<String, Map<String, Object>> portMap) {
        return conduitWellformed(conduit, portMap, null);
    }

    /** Rule 17 / N4.2.1 with the transform exception of N4.2.2. */
    public static Validation conduitWellformed(
            Map<String, Object> conduit,
            Map<String, Map<String, Object>> portMap,
            Map<String, Map<String, Object>> croMap) {
        Map<String, Object> frm = portMap.get(conduit.get("from"));
        Map<String, Object> to = portMap.get(conduit.get("to"));
        if (frm == null || to == null) {
            return Validation.invalid(
                "malformed_conduit: dangling port reference");
        }
        Object fromDir = frm.get("direction");
        if (!"out".equals(fromDir) && !"bidirectional".equals(fromDir)) {
            return Validation.invalid(
                "malformed_conduit: from port is not out/bidirectional (a)");
        }
        Object toDir = to.get("direction");
        if (!"in".equals(toDir) && !"bidirectional".equals(toDir)) {
            return Validation.invalid(
                "malformed_conduit: to port is not in/bidirectional (b)");
        }
        List<?> carries = (List<?>) conduit.get("carries");
        List<?> fromAccepts = (List<?>) frm.get("accepts");
        for (Object o : carries) {
            if (!fromAccepts.contains(o)) {
                return Validation.invalid(
                    "malformed_conduit: carries not accepted by from (c)");
            }
        }
        Object transform = conduit.get("transform");
        List<?> toAccepts = (List<?>) to.get("accepts");
        if (transform == null) {
            for (Object o : carries) {
                if (!toAccepts.contains(o)) {
                    return Validation.invalid(
                        "malformed_conduit: carries not accepted by to (d)");
                }
            }
        } else {
            Map<String, Object> law =
                croMap == null ? null : croMap.get(transform);
            if (law != null) {
                for (Object o : (List<?>) law.get("effects")) {
                    if (!toAccepts.contains(o)) {
                        return Validation.invalid(
                            "malformed_conduit: transform effects not accepted "
                            + "by to (d, relaxed per N4.2.2)");
                    }
                }
            }
        }
        return new Validation(true, List.of("well-formed conduit"));
    }

    /**
     * Rule 19 / N5.3.1-2: the HARD gaps a state assertion surfaces against
     * its quality: value_type_mismatch and/or unit_mismatch.
     */
    public static List<String> stateGaps(Map<String, Object> state,
                                         Map<String, Object> quality) {
        List<String> gaps = new ArrayList<>();
        Object dt = quality.get("datatype");
        Map<?, ?> v = state.get("value") instanceof Map
            ? (Map<?, ?>) state.get("value") : Collections.emptyMap();
        String shape = v.containsKey("quantity") ? "quantity"
            : v.containsKey("categorical") ? "categorical"
            : v.containsKey("boolean") ? "boolean" : null;
        if (!Objects.equals(shape, dt)) {
            gaps.add("value_type_mismatch");
        } else if ("quantity".equals(dt)
                && !Objects.equals(v.get("unit"), quality.get("unit"))) {
            gaps.add("unit_mismatch");
        }
        return gaps;
    }

    /**
     * Rule 20: true iff the token claim's cause/effect tokens do not
     * instantiate the covering law's causes/effects.
     */
    public static boolean coveringLawMismatch(
            Map<String, Object> tcc,
            Map<String, Map<String, Object>> tokenMap,
            Map<String, Object> law) {
        if (law == null) {
            return false;
        }
        Set<Object> lawCauses = new HashSet<>((List<?>) law.get("causes"));
        Set<Object> lawEffects = new HashSet<>((List<?>) law.get("effects"));
        for (Object c : (List<?>) tcc.get("causes")) {
            if (!lawCauses.contains(tokenMap.get(c).get("instantiates"))) {
                return true;
            }
        }
        for (Object e : (List<?>) tcc.get("effects")) {
            if (!lawEffects.contains(tokenMap.get(e).get("instantiates"))) {
                return true;
            }
        }
        return false;
    }

    /**
     * 4.0.0 Rule 24: prediction-to-observation pairing. True iff the
     * prediction error's observed token does not instantiate the occurrent its
     * predicted_occurrence instantiates (surfaces pairing_mismatch). An ABSENT
     * observed (a null observed object) is never a mismatch - it means the
     * predicted occurrence was not fulfilled by any recorded occurrence.
     */
    public static boolean predictionPairingMismatch(
            Map<String, Object> error, Map<String, Object> predicted,
            Map<String, Object> observed) {
        if (error.get("observed") == null || observed == null) {
            return false;
        }
        return !Objects.equals(observed.get("instantiates"),
                               predicted.get("instantiates"));
    }

    /**
     * Rule 21: true iff any cause token starts after any effect token (HARD;
     * retrocausal_claim). RFC 3339 UTC 'Z' strings compare lexicographically.
     */
    public static boolean retrocausal(
            Map<String, Object> tcc,
            Map<String, Map<String, Object>> tokenMap) {
        for (Object c : (List<?>) tcc.get("causes")) {
            String cstart = (String) intervalStart(tokenMap.get(c));
            for (Object e : (List<?>) tcc.get("effects")) {
                String estart = (String) intervalStart(tokenMap.get(e));
                if (cstart.compareTo(estart) > 0) {
                    return true;
                }
            }
        }
        return false;
    }

    @SuppressWarnings("unchecked")
    private static Object intervalStart(Map<String, Object> token) {
        return ((Map<String, Object>) token.get("interval")).get("start");
    }

    /**
     * Rules 4 / 6.1: true iff a directed graph (node -> successors) has a
     * cycle. Used for bridge graphs, occurrent mereology, token mereology.
     */
    public static boolean hasCycle(Map<Object, List<Object>> edges) {
        final int white = 0;
        final int grey = 1;
        final int black = 2;
        Map<Object, Integer> state = new HashMap<>();
        for (Object node : new ArrayList<>(edges.keySet())) {
            if (state.getOrDefault(node, white) == white
                    && cycleVisit(node, edges, state, grey, black)) {
                return true;
            }
        }
        return false;
    }

    private static boolean cycleVisit(Object node,
                                      Map<Object, List<Object>> edges,
                                      Map<Object, Integer> state,
                                      int grey, int black) {
        state.put(node, grey);
        List<Object> next = edges.get(node);
        if (next != null) {
            for (Object nxt : next) {
                int s = state.getOrDefault(nxt, 0);
                if (s == grey) {
                    return true;
                }
                if (s == 0 && cycleVisit(nxt, edges, state, grey, black)) {
                    return true;
                }
            }
        }
        state.put(node, black);
        return false;
    }
}

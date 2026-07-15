package org.causalontology;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
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

    /** The optional CRO fields, in the fixed partiality order. */
    public static final List<String> CRO_OPTIONAL_FIELDS =
        List.of("mechanism", "temporal", "modality", "context");

    private static final Set<String> POSITIVE =
        Set.of("necessary", "sufficient", "contributory");

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
        ENRICHMENT_FIELDS = Collections.unmodifiableMap(fields);
    }

    private Semantics() {
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

    /** Rule 4: temporal admissibility with the fixed constants. */
    public static boolean admissible(Map<String, Object> cro,
                                     double elapsedSeconds) {
        Object temporalObj = cro.get("temporal");
        if (temporalObj == null) {
            return true; // no window imposes no constraint
        }
        Map<?, ?> temporal = (Map<?, ?>) temporalObj;
        long unit = UNIT_SECONDS.get((String) temporal.get("unit"));
        double lo = ((Number) temporal.get("minimum_delay")).doubleValue() * unit;
        double hi = ((Number) temporal.get("maximum_delay")).doubleValue() * unit;
        return lo <= elapsedSeconds && elapsedSeconds <= hi;
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
        long ua = UNIT_SECONDS.get((String) ta.get("unit"));
        long ub = UNIT_SECONDS.get((String) tb.get("unit"));
        double loA = ((Number) ta.get("minimum_delay")).doubleValue() * ua;
        double hiA = ((Number) ta.get("maximum_delay")).doubleValue() * ua;
        double loB = ((Number) tb.get("minimum_delay")).doubleValue() * ub;
        double hiB = ((Number) tb.get("maximum_delay")).doubleValue() * ub;
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
        List<?> mechanism = List.of();
        if (parent.get("mechanism") instanceof List) {
            mechanism = (List<?>) parent.get("mechanism");
        }
        if (mechanism.isEmpty()) {
            return "consistent"; // nothing claimed, nothing to check
        }
        Map<Object, Set<Object>> edges = new LinkedHashMap<>();
        for (Object mid : mechanism) {
            Map<String, Object> member = members.get(mid);
            if (member == null) {
                return "indeterminate"; // a dangling_reference gap
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
        for (Object cause : parentCauses) {
            for (Object effect : parentEffects) {
                if (!reachable(cause, effect, edges)) {
                    return "inconsistent";
                }
            }
        }
        return "consistent";
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
}

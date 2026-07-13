package org.causalontology;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Canonicalization and content-addressed identity (spec/identity.md):
 *   1. take the object as JSON,
 *   2. keep only the identity-bearing fields for its kind ("type" injected),
 *   3. serialize with the JSON Canonicalization Scheme (RFC 8785),
 *   4. hash with SHA-256,
 *   5. identifier = scheme + ":" + lowercase hex digest.
 */
public final class Canonical {

    /** The identity-bearing fields per kind, exactly as canonical.py. */
    public static final Map<String, List<String>> IDENTITY_FIELDS;

    /** kind -> identifier scheme prefix. */
    public static final Map<String, String> PREFIX;

    /** identifier scheme prefix -> kind. */
    public static final Map<String, String> KIND_OF_PREFIX;

    static {
        Map<String, List<String>> fields = new LinkedHashMap<>();
        fields.put("occurrent", List.of("label", "category"));
        fields.put("cro", List.of("causes", "effects", "mechanism",
                                  "temporal", "modality", "context",
                                  "refines"));
        fields.put("continuant", List.of("label", "category"));
        fields.put("realizable", List.of("kind", "bearer"));
        fields.put("assertion", List.of("about", "source", "evidence_type",
                                        "evidence", "strength", "confidence",
                                        "timestamp"));
        fields.put("enrichment", List.of("about", "field", "entry",
                                         "source", "timestamp"));
        fields.put("retraction", List.of("retracts", "source", "timestamp"));
        fields.put("succession", List.of("predecessor", "successor",
                                         "timestamp"));
        IDENTITY_FIELDS = Collections.unmodifiableMap(fields);

        Map<String, String> prefix = new LinkedHashMap<>();
        prefix.put("occurrent", "occ");
        prefix.put("cro", "cro");
        prefix.put("continuant", "cnt");
        prefix.put("realizable", "rlz");
        prefix.put("assertion", "ast");
        prefix.put("enrichment", "enr");
        prefix.put("retraction", "ret");
        prefix.put("succession", "suc");
        PREFIX = Collections.unmodifiableMap(prefix);

        Map<String, String> reverse = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : prefix.entrySet()) {
            reverse.put(e.getValue(), e.getKey());
        }
        KIND_OF_PREFIX = Collections.unmodifiableMap(reverse);
    }

    private Canonical() {
    }

    /** Infer an object's kind from its type field, id prefix, or shape. */
    public static String inferKind(Map<String, Object> obj) {
        if (obj.containsKey("type")) {
            return (String) obj.get("type");
        }
        Object idObj = obj.get("id");
        if (idObj instanceof String) {
            String id = (String) idObj;
            int colon = id.indexOf(':');
            if (colon >= 0) {
                String pre = id.substring(0, colon);
                if (KIND_OF_PREFIX.containsKey(pre)) {
                    return KIND_OF_PREFIX.get(pre);
                }
            }
        }
        if (obj.containsKey("causes") && obj.containsKey("effects")) {
            return "cro";
        }
        if (obj.containsKey("retracts")) {
            return "retraction";
        }
        if (obj.containsKey("predecessor") && obj.containsKey("successor")) {
            return "succession";
        }
        if (obj.containsKey("field") && obj.containsKey("entry")) {
            return "enrichment";
        }
        if (obj.containsKey("evidence_type")
                || (obj.containsKey("about") && obj.containsKey("confidence"))) {
            return "assertion";
        }
        if (obj.containsKey("kind") && obj.containsKey("bearer")) {
            return "realizable";
        }
        throw new IllegalArgumentException(
            "cannot infer kind (occurrents and continuants share a shape); "
            + "pass kind explicitly");
    }

    private static String resolveKind(Map<String, Object> obj, String kind) {
        return kind != null ? kind : inferKind(obj);
    }

    /** The identity-bearing subset of an object, with type always present. */
    public static Map<String, Object> identityBearing(Map<String, Object> obj,
                                                      String kind) {
        String k = resolveKind(obj, kind);
        if (!IDENTITY_FIELDS.containsKey(k)) {
            throw new IllegalArgumentException("unknown kind: " + k);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("type", k);
        for (String field : IDENTITY_FIELDS.get(k)) {
            if (obj.containsKey(field)) {
                out.put(field, obj.get(field));
            }
        }
        return out;
    }

    /** The RFC 8785 identity-bearing bytes of an object. */
    public static byte[] canonicalize(Map<String, Object> obj, String kind) {
        String k = resolveKind(obj, kind);
        Map<String, Object> ib = identityBearing(obj, k);
        return Jcs.serialize(ib).getBytes(StandardCharsets.UTF_8);
    }

    /** The content-addressed identifier: scheme + ":" + SHA-256 hex. */
    public static String identify(Map<String, Object> obj, String kind) {
        String k = resolveKind(obj, kind);
        Map<String, Object> ib = identityBearing(obj, k);
        byte[] bytes = Jcs.serialize(ib).getBytes(StandardCharsets.UTF_8);
        return PREFIX.get(k) + ":" + sha256Hex(bytes);
    }

    /** SHA-256 digest bytes. */
    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /** SHA-256 digest as lowercase hex. */
    public static String sha256Hex(byte[] data) {
        return HexFormat.of().formatHex(sha256(data));
    }
}

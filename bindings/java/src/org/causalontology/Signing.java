package org.causalontology;

import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Record-level signing and verification (spec/provenance.md).
 *
 * The signature is computed over the record's canonical identity-bearing
 * bytes (the RFC 8785 form with id and signature removed - exactly the
 * bytes that are hashed for the record's identifier), so verification
 * needs nothing but the record itself. Ed25519 is deterministic
 * (RFC 8032): re-signing the same record with the same key yields the
 * same signature, so re-submission is idempotent.
 */
public final class Signing {

    /** A (secret seed, "ed25519:&lt;hex&gt;" source identifier) pair. */
    public static final class Keys {
        public final byte[] secret;
        public final String publicId;

        public Keys(byte[] secret, String publicId) {
            this.secret = secret;
            this.publicId = publicId;
        }
    }

    private Signing() {
    }

    /** (secret, "ed25519:&lt;hex&gt;") from a 32-byte seed. */
    public static Keys keypairFromSeed(byte[] seed32) {
        byte[] publicKey = Ed25519.secretToPublic(seed32);
        return new Keys(seed32,
                        "ed25519:" + HexFormat.of().formatHex(publicKey));
    }

    /** Return the record completed with its id and Ed25519 signature. */
    public static Map<String, Object> signRecord(Map<String, Object> rec,
                                                 byte[] secret, String kind) {
        String k = kind != null ? kind : Canonical.inferKind(rec);
        Map<String, Object> body = new LinkedHashMap<>(rec);
        body.remove("signature");
        byte[] message = Canonical.canonicalize(body, k);
        String signature = HexFormat.of().formatHex(
            Ed25519.sign(secret, message));
        Map<String, Object> out = new LinkedHashMap<>(body);
        out.put("id", Canonical.identify(body, k));
        out.put("signature", signature);
        return out;
    }

    private static String signerKeyHex(Map<String, Object> rec, String kind) {
        // A succession is signed by the predecessor key; everything else
        // by its source key.
        String field = kind.equals("succession") ? "predecessor" : "source";
        Object value = rec.get(field);
        if (!(value instanceof String)) {
            return null;
        }
        String s = (String) value;
        if (!s.startsWith("ed25519:")) {
            return null;
        }
        return s.substring("ed25519:".length());
    }

    /** True iff the record's signature verifies against its own key field. */
    public static boolean verifyRecord(Map<String, Object> rec, String kind) {
        String k = kind != null ? kind : Canonical.inferKind(rec);
        String signatureHex = null;
        if (rec.get("signature") instanceof String) {
            signatureHex = (String) rec.get("signature");
        }
        String keyHex = signerKeyHex(rec, k);
        if (signatureHex == null || signatureHex.isEmpty()
                || keyHex == null || keyHex.isEmpty()) {
            return false;
        }
        byte[] publicKey;
        byte[] signature;
        try {
            publicKey = HexFormat.of().parseHex(keyHex);
            signature = HexFormat.of().parseHex(signatureHex);
        } catch (IllegalArgumentException e) {
            return false;
        }
        Map<String, Object> body = new LinkedHashMap<>(rec);
        body.remove("signature");
        byte[] message = Canonical.canonicalize(body, k);
        return Ed25519.verify(publicKey, message, signature);
    }
}

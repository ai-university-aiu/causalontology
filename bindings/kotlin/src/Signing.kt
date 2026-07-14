// Record-level signing and verification (spec/provenance.md).
//
// The signature is computed over the record's canonical identity-bearing bytes
// (the RFC 8785 form with id and signature removed - exactly the bytes that are
// hashed for the record's identifier), so verification needs nothing but the
// record itself. Ed25519 is deterministic (RFC 8032): re-signing the same record
// with the same key yields the same signature, so re-submission is idempotent.
package org.causalontology

object Signing {

    // (secret, "ed25519:<hex>") from a 32-byte seed.
    fun keypairFromSeed(seed32: ByteArray): Pair<ByteArray, String> {
        val public = Ed25519.secretToPublic(seed32)
        return Pair(seed32, "ed25519:" + bytesToHex(public))
    }

    // Return the record completed with its id and Ed25519 signature.
    fun signRecord(record: JObj, secret: ByteArray, kind: String? = null): JObj {
        val k = kind ?: Canonical.inferKind(record)
        val body = LinkedHashMap(record)
        body.remove("signature")
        val message = Canonical.canonicalize(body, k)
        val signature = bytesToHex(Ed25519.sign(secret, message))
        val out = LinkedHashMap(body)
        out["id"] = Canonical.identify(body, k)
        out["signature"] = signature
        return out
    }

    // The hex of the key a record of this kind must verify against.
    private fun signerKeyHex(record: JObj, kind: String): String? {
        // A succession is signed by the predecessor key; everything else by source.
        val field = if (kind == "succession") "predecessor" else "source"
        val value = record[field] as? String ?: ""
        if (!value.startsWith("ed25519:")) return null
        return value.substringAfter(":")
    }

    // True iff the record's signature verifies against its own key field.
    fun verifyRecord(record: JObj, kind: String? = null): Boolean {
        val k = kind ?: Canonical.inferKind(record)
        val sigHex = record["signature"] as? String
        val keyHex = signerKeyHex(record, k)
        if (sigHex.isNullOrEmpty() || keyHex.isNullOrEmpty()) return false
        val public = hexToBytes(keyHex) ?: return false
        val signature = hexToBytes(sigHex) ?: return false
        val body = LinkedHashMap(record)
        body.remove("signature")
        val message = Canonical.canonicalize(body, k)
        return Ed25519.verify(public, message, signature)
    }
}

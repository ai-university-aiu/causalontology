// Record-level signing and verification (spec/provenance.md).
//
// The signature is computed over the record's canonical identity-bearing
// bytes (the RFC 8785 form with id and signature removed - exactly the
// bytes that are hashed for the record's identifier), so verification
// needs nothing but the record itself. Ed25519 is deterministic
// (RFC 8032): re-signing the same record with the same key yields the
// same signature, so re-submission is idempotent.

namespace Causalontology;

public static class Signing
{
    /// <summary>(secret, "ed25519:&lt;hex&gt;") from a 32-byte seed.</summary>
    public static (byte[] Secret, string PublicId) KeypairFromSeed(byte[] seed32)
    {
        var publicKey = Ed25519.SecretToPublic(seed32);
        return (seed32,
                "ed25519:" + Convert.ToHexString(publicKey).ToLowerInvariant());
    }

    /// <summary>Return the record completed with its id and Ed25519 signature.</summary>
    public static JsonMap SignRecord(JsonMap record, byte[] secret,
                                     string? kind = null)
    {
        kind ??= Canonical.InferKind(record);
        var body = record.Copy();
        body.Remove("signature");
        var message = Canonical.Canonicalize(body, kind);
        var signature = Convert.ToHexString(Ed25519.Sign(secret, message))
            .ToLowerInvariant();
        var output = body.Copy();
        output["id"] = Canonical.Identify(body, kind);
        output["signature"] = signature;
        return output;
    }

    private static string? SignerKeyHex(JsonMap record, string kind)
    {
        // a succession is signed by the predecessor key
        var field = kind == "succession" ? "predecessor" : "source";
        var value = record.GetString(field) ?? "";
        if (!value.StartsWith("ed25519:", StringComparison.Ordinal))
            return null;
        return value.Split(':', 2)[1];
    }

    /// <summary>True iff the record's signature verifies against its own key field.</summary>
    public static bool VerifyRecord(JsonMap record, string? kind = null)
    {
        kind ??= Canonical.InferKind(record);
        var sigHex = record.GetString("signature");
        var keyHex = SignerKeyHex(record, kind);
        if (string.IsNullOrEmpty(sigHex) || string.IsNullOrEmpty(keyHex))
            return false;
        byte[] publicKey, signature;
        try
        {
            publicKey = Convert.FromHexString(keyHex);
            signature = Convert.FromHexString(sigHex);
        }
        catch (FormatException)
        {
            return false;
        }
        var body = record.Copy();
        body.Remove("signature");
        var message = Canonical.Canonicalize(body, kind);
        return Ed25519.Verify(publicKey, message, signature);
    }
}

// Canonicalization and content-addressed identity (spec/identity.md):
//   1. take the object as JSON,
//   2. keep only the identity-bearing fields for its kind (with "type" injected),
//   3. serialize with the JSON Canonicalization Scheme (RFC 8785),
//   4. hash with SHA-256,
//   5. identifier = scheme + ":" + lowercase hex digest.

using System.Security.Cryptography;
using System.Text;

namespace Causalontology;

public static class Canonical
{
    public static readonly IReadOnlyDictionary<string, string[]> IdentityFields =
        new Dictionary<string, string[]>
        {
            ["occurrent"] = new[] { "label", "category" },
            ["cro"] = new[] { "causes", "effects", "mechanism", "temporal",
                              "modality", "context", "refines" },
            ["continuant"] = new[] { "label", "category" },
            ["realizable"] = new[] { "kind", "bearer" },
            ["assertion"] = new[] { "about", "source", "evidence_type",
                                    "evidence", "strength", "confidence",
                                    "timestamp" },
            ["enrichment"] = new[] { "about", "field", "entry", "source",
                                     "timestamp" },
            ["retraction"] = new[] { "retracts", "source", "timestamp" },
            ["succession"] = new[] { "predecessor", "successor", "timestamp" },
        };

    public static readonly IReadOnlyDictionary<string, string> Prefix =
        new Dictionary<string, string>
        {
            ["occurrent"] = "occ", ["cro"] = "cro", ["continuant"] = "cnt",
            ["realizable"] = "rlz", ["assertion"] = "ast",
            ["enrichment"] = "enr", ["retraction"] = "ret",
            ["succession"] = "suc",
        };

    public static readonly IReadOnlyDictionary<string, string> KindOfPrefix =
        Prefix.ToDictionary(kv => kv.Value, kv => kv.Key);

    /// <summary>Infer an object's kind from its type field, id prefix, or shape.</summary>
    public static string InferKind(JsonMap obj)
    {
        if (obj.Get("type") is string type)
            return type;
        if (obj.Get("id") is string id && id.Contains(':'))
        {
            var pre = id.Split(':', 2)[0];
            if (KindOfPrefix.TryGetValue(pre, out var kind))
                return kind;
        }
        if (obj.ContainsKey("causes") && obj.ContainsKey("effects"))
            return "cro";
        if (obj.ContainsKey("retracts"))
            return "retraction";
        if (obj.ContainsKey("predecessor") && obj.ContainsKey("successor"))
            return "succession";
        if (obj.ContainsKey("field") && obj.ContainsKey("entry"))
            return "enrichment";
        if (obj.ContainsKey("evidence_type")
            || (obj.ContainsKey("about") && obj.ContainsKey("confidence")))
            return "assertion";
        if (obj.ContainsKey("kind") && obj.ContainsKey("bearer"))
            return "realizable";
        throw new ArgumentException(
            "cannot infer kind (occurrents and continuants share a shape); "
            + "pass kind explicitly");
    }

    /// <summary>The identity-bearing subset of an object, with type always present.</summary>
    public static (string Kind, JsonMap Subset) IdentityBearing(
        JsonMap obj, string? kind = null)
    {
        kind ??= InferKind(obj);
        if (!IdentityFields.TryGetValue(kind, out var fields))
            throw new ArgumentException($"unknown kind: {kind}");
        var subset = new JsonMap { { "type", kind } };
        foreach (var field in fields)
        {
            if (obj.ContainsKey(field))
                subset[field] = obj[field];
        }
        return (kind, subset);
    }

    /// <summary>The RFC 8785 identity-bearing bytes of an object.</summary>
    public static byte[] Canonicalize(JsonMap obj, string? kind = null)
    {
        var (_, subset) = IdentityBearing(obj, kind);
        return Encoding.UTF8.GetBytes(Jcs.Serialize(subset));
    }

    /// <summary>The content-addressed identifier: scheme + ':' + SHA-256 hex.</summary>
    public static string Identify(JsonMap obj, string? kind = null)
    {
        var (resolvedKind, subset) = IdentityBearing(obj, kind);
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(Jcs.Serialize(subset)));
        return Prefix[resolvedKind] + ":" + Convert.ToHexString(digest).ToLowerInvariant();
    }
}

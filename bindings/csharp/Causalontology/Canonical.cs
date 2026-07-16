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
    // The identity-bearing fields of each of the seventeen kinds. "type" is
    // always injected, so it is not listed here. Order does not matter (JCS
    // sorts keys). 2.0.0: whole-word re-mint (Principle P7).
    public static readonly IReadOnlyDictionary<string, string[]> IdentityFields =
        new Dictionary<string, string[]>
        {
            // ---- type tier ----
            ["occurrent"] = new[] { "label", "category", "stratum" },
            ["causal_relation_object"] = new[] { "causes", "effects",
                "mechanism", "temporal", "modality", "context", "refines",
                "skips" },
            ["continuant"] = new[] { "label", "category" },
            ["realizable"] = new[] { "kind", "bearer", "label" },
            ["stratum"] = new[] { "label", "scheme", "ordinal", "unit",
                "governs" },
            ["bridge"] = new[] { "coarse", "fine", "relation" },
            ["port"] = new[] { "bearer", "label", "direction", "accepts",
                "realizable" },
            ["conduit"] = new[] { "label", "from", "to", "carries",
                "transform" },
            ["quality"] = new[] { "label", "datatype", "unit", "stratum" },
            // ---- token tier ----
            ["token_individual"] = new[] { "instantiates", "designator",
                "part_of" },
            ["token_occurrence"] = new[] { "instantiates", "interval",
                "participants", "locus", "observer" },
            ["state_assertion"] = new[] { "subject", "quality", "value",
                "interval" },
            ["token_causal_claim"] = new[] { "causes", "effects",
                "covering_law", "actual_delay", "counterfactual" },
            // ---- provenance tier ----
            ["assertion"] = new[] { "about", "source", "evidence_type",
                "evidence", "strength", "confidence", "timestamp",
                "evidenced_by" },
            ["enrichment"] = new[] { "about", "field", "entry", "source",
                "timestamp" },
            ["retraction"] = new[] { "retracts", "source", "timestamp" },
            ["succession"] = new[] { "predecessor", "successor", "timestamp" },
        };

    // Whole-word re-mint (P7): the scheme IS the type value for every kind.
    public static readonly IReadOnlyDictionary<string, string> Prefix =
        IdentityFields.Keys.ToDictionary(k => k, k => k);

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
        if (obj.ContainsKey("coarse") && obj.ContainsKey("fine"))
            return "bridge";
        if (obj.ContainsKey("causes") && obj.ContainsKey("effects"))
            return "causal_relation_object";
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

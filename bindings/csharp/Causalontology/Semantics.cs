// The semantic rules beyond the schemas (spec/semantics.md).
//
// Local rules are checked here; store-context rules (materialized
// acyclicity, retraction lineage) live in Store.cs where the context
// exists.

namespace Causalontology;

public static class Semantics
{
    /// <summary>Rule 4: the fixed unit-conversion constants (average Gregorian values).</summary>
    public static readonly IReadOnlyDictionary<string, long> UnitSeconds =
        new Dictionary<string, long>
        {
            ["instant"] = 0,
            ["seconds"] = 1,
            ["minutes"] = 60,
            ["hours"] = 3600,
            ["days"] = 86400,
            ["weeks"] = 604800,
            ["months"] = 2629746,
            ["years"] = 31556952,
        };

    /// <summary>Rule 12: enrichment field-to-kind validity and entry shapes.</summary>
    public static readonly IReadOnlyDictionary<string, (string[] LegalKinds, string Shape)>
        EnrichmentFields = new Dictionary<string, (string[], string)>
        {
            ["aliases"] = (new[] { "occurrent", "continuant" }, "alias"),
            ["participants"] = (new[] { "occurrent" }, "continuant"),
            ["subsumes"] = (new[] { "continuant" }, "continuant"),
            ["part_of"] = (new[] { "continuant" }, "continuant"),
            ["realized_in"] = (new[] { "realizable" }, "occurrent"),
        };

    public static readonly string[] CroOptionalFields =
        { "mechanism", "temporal", "modality", "context" };

    private static string? KindOfId(string identifier)
        => Canonical.KindOfPrefix.TryGetValue(
               identifier.Split(':', 2)[0], out var kind) ? kind : null;

    private static List<string> StringList(object? value)
        => value is List<object?> list
               ? list.Select(item => (string)item!).ToList()
               : new List<string>();

    /// <summary>(ok, reasons) — the locally checkable semantic rules.</summary>
    public static (bool Ok, List<string> Reasons) ValidateSemantics(
        JsonMap obj, string? kind = null)
    {
        kind ??= Canonical.InferKind(obj);
        var errors = new List<string>();

        if (kind == "causal_relation_object")
        {
            if (obj.Get("temporal") is JsonMap temporal
                && temporal.Get("minimum_delay") is not null
                && temporal.Get("maximum_delay") is not null
                && Json.ToDouble(temporal["minimum_delay"]) > Json.ToDouble(temporal["maximum_delay"]))
                errors.Add("minimum_delay must be <= maximum_delay");
            var oid = obj.GetString("id");
            if (oid is not null && StringList(obj.Get("mechanism")).Contains(oid))
                errors.Add("mechanism must be acyclic "
                           + "(a Causal Relation Object may not contain itself)");
            if (oid is not null && obj.GetString("refines") == oid)
                errors.Add("refines must be acyclic");
        }

        if (kind == "enrichment")
        {
            var field = obj.GetString("field");
            var about = obj.GetString("about") ?? "";
            var entry = obj.Get("entry");
            if (field is not null
                && EnrichmentFields.TryGetValue(field, out var spec))
            {
                var (legalKinds, shape) = spec;
                var aboutKind = KindOfId(about);
                if (aboutKind is not null && !legalKinds.Contains(aboutKind))
                    errors.Add($"{field} is not a legal field for a {aboutKind} "
                               + "(rule 12)");
                if (shape == "alias")
                {
                    if (entry is not JsonMap aliasEntry
                        || !aliasEntry.ContainsKey("lang")
                        || !aliasEntry.ContainsKey("text"))
                        errors.Add("an aliases entry must be a "
                                   + "language-tagged text object");
                }
                else
                {
                    if (entry is not string reference
                        || !reference.StartsWith(shape + ":", StringComparison.Ordinal))
                        errors.Add($"a {field} entry must be a {shape}: identifier");
                }
            }
        }

        return (errors.Count == 0, errors);
    }

    /// <summary>(partial, missing) — which optional CRO fields are unspecified.</summary>
    public static (bool Partial, List<string> Missing) IsPartial(JsonMap cro)
    {
        var missing = CroOptionalFields.Where(f => !cro.ContainsKey(f)).ToList();
        return (missing.Count > 0, missing);
    }

    /// <summary>Rule 4: temporal admissibility with the fixed constants.</summary>
    public static bool Admissible(JsonMap cro, double elapsedSeconds)
    {
        if (cro.Get("temporal") is not JsonMap temporal)
            return true; // no window imposes no constraint
        var unit = UnitSeconds[(string)temporal["unit"]!];
        var lo = Json.ToDouble(temporal["minimum_delay"]) * unit;
        var hi = Json.ToDouble(temporal["maximum_delay"]) * unit;
        return lo <= elapsedSeconds && elapsedSeconds <= hi;
    }

    private static bool WindowOverlap(JsonMap a, JsonMap b)
    {
        if (a.Get("temporal") is not JsonMap ta
            || b.Get("temporal") is not JsonMap tb)
            return true; // either absent counts as overlapping
        var ua = UnitSeconds[(string)ta["unit"]!];
        var ub = UnitSeconds[(string)tb["unit"]!];
        var loA = Json.ToDouble(ta["minimum_delay"]) * ua;
        var hiA = Json.ToDouble(ta["maximum_delay"]) * ua;
        var loB = Json.ToDouble(tb["minimum_delay"]) * ub;
        var hiB = Json.ToDouble(tb["maximum_delay"]) * ub;
        return loA <= hiB && loB <= hiA;
    }

    private static bool ContextsCompatible(JsonMap a, JsonMap b)
    {
        var ca = StringList(a.Get("context"));
        var cb = StringList(b.Get("context"));
        if (ca.Count == 0 || cb.Count == 0)
            return true; // either absent (or empty)
        var sa = new HashSet<string>(ca);
        var sb = new HashSet<string>(cb);
        return sa.SetEquals(sb) || sa.IsSubsetOf(sb) || sb.IsSubsetOf(sa);
    }

    private static readonly HashSet<string> Positive =
        new() { "necessary", "sufficient", "contributory" };

    /// <summary>Rule 6: the formal conflict test.</summary>
    public static bool Conflicts(JsonMap a, JsonMap b)
    {
        if (!new HashSet<string>(StringList(a["causes"]))
                .SetEquals(StringList(b["causes"])))
            return false;
        if (!new HashSet<string>(StringList(a["effects"]))
                .SetEquals(StringList(b["effects"])))
            return false;
        if (!ContextsCompatible(a, b))
            return false;
        if (!WindowOverlap(a, b))
            return false;
        var ma = a.GetString("modality");
        var mb = b.GetString("modality");
        return (ma == "preventive" && mb is not null && Positive.Contains(mb))
            || (mb == "preventive" && ma is not null && Positive.Contains(ma));
    }

    /// <summary>Rule 3: (ok, reason) — is child a valid refinement of parent?</summary>
    public static (bool Ok, string Reason) RefinementValid(
        JsonMap child, JsonMap parent)
    {
        if (child.GetString("refines") != parent.GetString("id"))
            return (false, "child does not name the parent in refines");
        if (!new HashSet<string>(StringList(child["causes"]))
                .SetEquals(StringList(parent["causes"]))
            || !new HashSet<string>(StringList(child["effects"]))
                   .SetEquals(StringList(parent["effects"])))
            return (false,
                    "a refinement must keep the parent's causes and effects");
        var added = 0;
        foreach (var field in CroOptionalFields)
        {
            if (parent.ContainsKey(field))
            {
                if (!Json.DeepEquals(child.Get(field), parent[field]))
                    return (false, "a refinement may not change a field the "
                                   + "parent specified; this is a rival claim");
            }
            else if (child.ContainsKey(field))
            {
                added++;
            }
        }
        if (added == 0)
            return (false, "a refinement must add at least one unspecified field");
        return (true, "valid refinement");
    }

    /// <summary>Rule 7: "consistent" | "inconsistent" | "indeterminate".</summary>
    public static string HierarchyConsistent(
        JsonMap parent, IReadOnlyDictionary<string, JsonMap> members)
    {
        var mechanism = StringList(parent.Get("mechanism"));
        if (mechanism.Count == 0)
            return "consistent"; // nothing claimed, nothing to check
        var edges = new Dictionary<string, HashSet<string>>();
        foreach (var mid in mechanism)
        {
            if (!members.TryGetValue(mid, out var member))
                return "indeterminate"; // a dangling_reference gap, not a failure
            foreach (var cause in StringList(member["causes"]))
            {
                if (!edges.TryGetValue(cause, out var targets))
                    edges[cause] = targets = new HashSet<string>();
                targets.UnionWith(StringList(member["effects"]));
            }
        }

        bool Reachable(string src, string dst)
        {
            var seen = new HashSet<string>();
            var stack = new Stack<string>();
            stack.Push(src);
            while (stack.Count > 0)
            {
                var node = stack.Pop();
                if (node == dst)
                    return true;
                if (!seen.Add(node))
                    continue;
                if (edges.TryGetValue(node, out var targets))
                {
                    foreach (var next in targets)
                        stack.Push(next);
                }
            }
            return false;
        }

        foreach (var cause in StringList(parent["causes"]))
        {
            foreach (var effect in StringList(parent["effects"]))
            {
                if (!Reachable(cause, effect))
                    return "inconsistent";
            }
        }
        return "consistent";
    }
}

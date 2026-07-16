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
            ["occurrent_subsumes"] = (new[] { "occurrent" }, "occurrent"),
            ["occurrent_part_of"] = (new[] { "occurrent" }, "occurrent"),
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
            // Rule 16, clause 1 (contradictory_skip): a HARD, locally-decidable
            // contradiction between skips:true and a non-empty mechanism.
            if (obj.Get("skips") is true
                && obj.Get("mechanism") is List<object?> mech && mech.Count > 0)
                errors.Add("contradictory_skip: skips is true but a mechanism "
                           + "is present");
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

    // Rule 6 (amended): necessary, sufficient, contributory, enabling are
    // mutually compatible; preventive opposes all four.
    private static readonly HashSet<string> Positive =
        new() { "necessary", "sufficient", "contributory", "enabling" };

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

    // =======================================================================
    // 2.0.0 NORMATIVE ALGORITHMS (Section 12)
    // =======================================================================

    /// <summary>ALGORITHM A. Every finer occurrent an occurrent resolves to,
    /// following Bridges downward, transitively (includes the start).</summary>
    public static HashSet<string> BridgeClosure(
        string occurrentId, IEnumerable<JsonMap> bridges)
    {
        var result = new HashSet<string> { occurrentId };
        var frontier = new Stack<string>();
        frontier.Push(occurrentId);
        var visited = new HashSet<string>();
        var coarseIndex = new Dictionary<string, List<JsonMap>>();
        foreach (var b in bridges)
        {
            var coarse = (string)b["coarse"]!;
            if (!coarseIndex.TryGetValue(coarse, out var list))
                coarseIndex[coarse] = list = new List<JsonMap>();
            list.Add(b);
        }
        while (frontier.Count > 0)
        {
            var current = frontier.Pop();
            if (!visited.Add(current))
                continue;
            if (!coarseIndex.TryGetValue(current, out var bs))
                continue;
            foreach (var b in bs)
                foreach (var f in StringList(b["fine"]))
                {
                    result.Add(f);
                    frontier.Push(f);
                }
        }
        return result;
    }

    private static bool PathExists(
        IReadOnlyDictionary<string, HashSet<string>> edges, string src, string dst)
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
                foreach (var next in targets)
                    stack.Push(next);
        }
        return false;
    }

    /// <summary>ALGORITHM B (amended Rule 7): "consistent" | "inconsistent" |
    /// "indeterminate", ACROSS STRATA via bridged reachability.</summary>
    public static string HierarchyConsistent(
        JsonMap parent, IReadOnlyDictionary<string, JsonMap> members,
        IEnumerable<JsonMap>? bridges = null)
    {
        bridges ??= Array.Empty<JsonMap>();
        var bridgeList = bridges as IReadOnlyList<JsonMap> ?? bridges.ToList();
        var mechanism = StringList(parent.Get("mechanism"));
        if (mechanism.Count == 0)
            return "consistent"; // nothing claimed, nothing to check
        var edges = new Dictionary<string, HashSet<string>>();
        foreach (var mid in mechanism)
        {
            if (!members.TryGetValue(mid, out var member))
                return "indeterminate"; // dangling; ignorance, not refutation
            foreach (var cause in StringList(member["causes"]))
            {
                if (!edges.TryGetValue(cause, out var targets))
                    edges[cause] = targets = new HashSet<string>();
                targets.UnionWith(StringList(member["effects"]));
            }
        }
        var bCause = StringList(parent["causes"])
            .ToDictionary(c => c, c => BridgeClosure(c, bridgeList));
        var bEffect = StringList(parent["effects"])
            .ToDictionary(e => e, e => BridgeClosure(e, bridgeList));
        foreach (var cause in StringList(parent["causes"]))
        {
            foreach (var effect in StringList(parent["effects"]))
            {
                var connected = false;
                foreach (var cp in bCause[cause])
                {
                    foreach (var ep in bEffect[effect])
                    {
                        if (PathExists(edges, cp, ep))
                        {
                            connected = true;
                            break;
                        }
                    }
                    if (connected)
                        break;
                }
                if (!connected)
                    return "inconsistent";
            }
        }
        return "consistent";
    }

    private static string? StratumOf(
        string occId, IReadOnlyDictionary<string, JsonMap> occMap)
        => occMap.TryGetValue(occId, out var o) ? o.GetString("stratum") : null;

    /// <summary>ALGORITHM C (Rule 15): the stratal classification of a CRO.</summary>
    public static string ClassifyCro(
        JsonMap cro, IReadOnlyDictionary<string, JsonMap> occMap,
        IReadOnlyDictionary<string, JsonMap> stratumMap)
    {
        var causeStrata = StringList(cro["causes"])
            .Select(c => StratumOf(c, occMap)).ToList();
        var effectStrata = StringList(cro["effects"])
            .Select(e => StratumOf(e, occMap)).ToList();
        if (causeStrata.Concat(effectStrata).Any(s => s is null))
            return "unclassifiable";
        var allStrata = new HashSet<string>(causeStrata!)
            .Union(new HashSet<string>(effectStrata!)).ToList();
        var schemes = allStrata
            .Select(s => stratumMap[s!].GetString("scheme")).Distinct().ToList();
        if (schemes.Count > 1)
            return "scheme_mismatch"; // HARD
        long Ord(string? s) => (long)Json.ToDouble(stratumMap[s!]["ordinal"]);
        var cOrd = causeStrata.Select(Ord).ToList();
        var eOrd = effectStrata.Select(Ord).ToList();
        if (cOrd.Max() == cOrd.Min() && eOrd.Max() == eOrd.Min()
            && cOrd.Max() == eOrd.Max())
            return "intra_stratal";
        var gap = (from i in cOrd from j in eOrd select Math.Abs(i - j)).Min();
        var span = (from i in cOrd from j in eOrd select Math.Abs(i - j)).Max();
        if (span == 1)
            return "adjacent_stratal";
        if (gap > 1)
            return "skipping";
        return "mixed"; // some pairs adjacent, some skipping
    }

    /// <summary>True iff causes or effects span more than one distinct stratum
    /// (surfaces mixed_stratal_endpoints, an invitation).</summary>
    public static bool EndpointsMixed(
        JsonMap cro, IReadOnlyDictionary<string, JsonMap> occMap)
    {
        var cs = StringList(cro["causes"]).Select(c => StratumOf(c, occMap))
            .ToList();
        var es = StringList(cro["effects"]).Select(e => StratumOf(e, occMap))
            .ToList();
        if (cs.Any(s => s is null) || es.Any(s => s is null))
            return false;
        return cs.Distinct().Count() > 1 || es.Distinct().Count() > 1;
    }

    /// <summary>ALGORITHM D (Rule 16): the gaps a CRO surfaces for the skip
    /// decision. The asymmetry of clause 3 is implemented exactly.</summary>
    public static List<string> SkipGaps(JsonMap cro, string classification)
    {
        var gaps = new List<string>();
        var hasMech = cro.Get("mechanism") is List<object?> m && m.Count > 0;
        var skipsTrue = cro.Get("skips") is true;
        if (skipsTrue && hasMech)
        {
            gaps.Add("contradictory_skip"); // HARD
            return gaps;
        }
        if (skipsTrue && classification != "skipping"
            && classification != "unclassifiable")
            gaps.Add("vacuous_skip"); // invitation
        if (classification == "skipping" && !hasMech)
        {
            if (skipsTrue)
            {
                // NOTHING: absence is a finding
            }
            else
            {
                gaps.Add("incomplete_mechanism"); // invitation
            }
        }
        return gaps;
    }

    /// <summary>ALGORITHM E helper: normalize a delay to seconds.</summary>
    public static long ToSeconds(long duration, string unit)
        => unit == "instant" ? 0 : duration * UnitSeconds[unit];

    /// <summary>ALGORITHM E (Rule 20): does an observed delay fall within a
    /// covering law's temporal window? Inclusive at both ends.</summary>
    public static bool DelayWithinWindow(JsonMap? actualDelay, JsonMap? temporal)
    {
        if (actualDelay is null || temporal is null)
            return true; // nothing to check
        var observed = ToSeconds(
            (long)Json.ToDouble(actualDelay["duration"]),
            (string)actualDelay["unit"]!);
        var lo = ToSeconds(
            (long)Json.ToDouble(temporal["minimum_delay"]),
            (string)temporal["unit"]!);
        var hi = ToSeconds(
            (long)Json.ToDouble(temporal["maximum_delay"]),
            (string)temporal["unit"]!);
        return lo <= observed && observed <= hi;
    }

    /// <summary>Rule 14 / N3.2.1: Bridge well-formedness. All of (a)-(e).</summary>
    public static (bool Ok, string Reason) BridgeWellformed(
        JsonMap bridge, IReadOnlyDictionary<string, JsonMap> occMap,
        IReadOnlyDictionary<string, JsonMap> stratumMap)
    {
        var cs = StratumOf((string)bridge["coarse"]!, occMap);
        if (cs is null)
            return (false, "malformed_bridge: coarse has no stratum (a)");
        var fineStrata = StringList(bridge["fine"])
            .Select(f => StratumOf(f, occMap)).ToList();
        if (fineStrata.Any(s => s is null))
            return (false, "malformed_bridge: a fine member has no stratum (b)");
        if (fineStrata.Distinct().Count() != 1)
            return (false, "malformed_bridge: fine members span >1 stratum (c)");
        var fs = fineStrata[0]!;
        if (stratumMap[cs].GetString("scheme") != stratumMap[fs].GetString("scheme"))
            return (false, "malformed_bridge: coarse and fine differ in scheme (d)");
        if (!(Json.ToDouble(stratumMap[cs]["ordinal"])
              > Json.ToDouble(stratumMap[fs]["ordinal"])))
            return (false, "malformed_bridge: coarse ordinal not > fine ordinal (e)");
        return (true, "well-formed bridge");
    }

    /// <summary>Rule 17 / N4.2.1-2: Conduit well-formedness.</summary>
    public static (bool Ok, string Reason) ConduitWellformed(
        JsonMap conduit, IReadOnlyDictionary<string, JsonMap> portMap,
        IReadOnlyDictionary<string, JsonMap>? croMap = null)
    {
        if (!portMap.TryGetValue((string)conduit["from"]!, out var frm)
            || !portMap.TryGetValue((string)conduit["to"]!, out var to))
            return (false, "malformed_conduit: dangling port reference");
        var fromDir = frm.GetString("direction");
        if (fromDir != "out" && fromDir != "bidirectional")
            return (false, "malformed_conduit: from port is not out/bidirectional (a)");
        var toDir = to.GetString("direction");
        if (toDir != "in" && toDir != "bidirectional")
            return (false, "malformed_conduit: to port is not in/bidirectional (b)");
        var carries = StringList(conduit["carries"]);
        var fromAccepts = new HashSet<string>(StringList(frm["accepts"]));
        if (!carries.All(o => fromAccepts.Contains(o)))
            return (false, "malformed_conduit: carries not accepted by from (c)");
        var toAccepts = new HashSet<string>(StringList(to["accepts"]));
        if (conduit.Get("transform") is not string transform)
        {
            if (!carries.All(o => toAccepts.Contains(o)))
                return (false, "malformed_conduit: carries not accepted by to (d)");
        }
        else
        {
            if (croMap is not null && croMap.TryGetValue(transform, out var law))
            {
                if (!StringList(law["effects"]).All(o => toAccepts.Contains(o)))
                    return (false, "malformed_conduit: transform effects not "
                                   + "accepted by to (d, relaxed per N4.2.2)");
            }
        }
        return (true, "well-formed conduit");
    }

    /// <summary>Rule 19 / N5.3.1-2: the HARD gaps a state assertion surfaces
    /// against its quality: value_type_mismatch and/or unit_mismatch.</summary>
    public static List<string> StateGaps(JsonMap state, JsonMap quality)
    {
        var gaps = new List<string>();
        var dt = quality.GetString("datatype");
        var v = state.Get("value") as JsonMap ?? new JsonMap();
        var shape = v.ContainsKey("quantity") ? "quantity"
            : v.ContainsKey("categorical") ? "categorical"
            : v.ContainsKey("boolean") ? "boolean" : null;
        if (shape != dt)
            gaps.Add("value_type_mismatch");
        else if (dt == "quantity" && v.GetString("unit") != quality.GetString("unit"))
            gaps.Add("unit_mismatch");
        return gaps;
    }

    /// <summary>Rule 20: true iff the token claim's cause/effect tokens do not
    /// instantiate the covering law's causes/effects.</summary>
    public static bool CoveringLawMismatch(
        JsonMap tcc, IReadOnlyDictionary<string, JsonMap> tokenMap, JsonMap? law)
    {
        if (law is null)
            return false;
        var lawCauses = new HashSet<string>(StringList(law["causes"]));
        var lawEffects = new HashSet<string>(StringList(law["effects"]));
        foreach (var c in StringList(tcc["causes"]))
            if (!lawCauses.Contains((string)tokenMap[c]["instantiates"]!))
                return true;
        foreach (var e in StringList(tcc["effects"]))
            if (!lawEffects.Contains((string)tokenMap[e]["instantiates"]!))
                return true;
        return false;
    }

    /// <summary>Rule 21: true iff any cause token starts after any effect token
    /// (HARD; retrocausal_claim). RFC 3339 UTC 'Z' strings compare lexically.</summary>
    public static bool Retrocausal(
        JsonMap tcc, IReadOnlyDictionary<string, JsonMap> tokenMap)
    {
        foreach (var c in StringList(tcc["causes"]))
        {
            var cstart = (string)((JsonMap)tokenMap[c]["interval"]!)["start"]!;
            foreach (var e in StringList(tcc["effects"]))
            {
                var estart = (string)((JsonMap)tokenMap[e]["interval"]!)["start"]!;
                if (string.CompareOrdinal(cstart, estart) > 0)
                    return true;
            }
        }
        return false;
    }

    /// <summary>Rules 4 / 6.1: true iff a directed graph (node -> successors)
    /// has a cycle. Used for bridge graph and occurrent/token mereology.</summary>
    public static bool HasCycle(IReadOnlyDictionary<string, List<string>> edges)
    {
        const int White = 0, Grey = 1, Black = 2;
        var state = new Dictionary<string, int>();

        bool Visit(string node)
        {
            state[node] = Grey;
            if (edges.TryGetValue(node, out var nexts))
            {
                foreach (var next in nexts)
                {
                    var s = state.TryGetValue(next, out var st) ? st : White;
                    if (s == Grey)
                        return true;
                    if (s == White && Visit(next))
                        return true;
                }
            }
            state[node] = Black;
            return false;
        }

        foreach (var n in edges.Keys.ToList())
        {
            if ((state.TryGetValue(n, out var st) ? st : White) == White && Visit(n))
                return true;
        }
        return false;
    }
}

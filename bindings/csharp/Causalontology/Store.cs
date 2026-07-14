// An in-memory conformant store.
//
// Implements the store side of the abstract operation set (spec/store.md):
// immutable content objects with idempotent put; signed, add-only
// provenance records; materialized enrichment views with contributors;
// retraction handling in default views; succession lineage; the resolve
// minimum; the deterministic cycle-breaking view rule; and the stigmergy
// gap read.
//
// Objects and records keep explicit insertion-order lists; we do not rely
// on Dictionary's de-facto ordering.

namespace Causalontology;

/// <summary>An enforcing store refused a write, with the reason in Message.</summary>
public sealed class RejectedWrite : Exception
{
    public RejectedWrite(string reason) : base(reason) { }
}

public sealed class InMemoryStore
{
    private static readonly HashSet<string> ContentKinds =
        new() { "occurrent", "cro", "continuant", "realizable" };
    private static readonly HashSet<string> RecordKinds =
        new() { "assertion", "enrichment", "retraction", "succession" };

    private readonly bool _enforcing;
    private readonly List<string> _objectOrder = new();
    private readonly Dictionary<string, JsonMap> _objects = new();
    private readonly List<string> _recordOrder = new();
    private readonly Dictionary<string, JsonMap> _records = new();
    private readonly Dictionary<string, JsonMap> _quarantine = new();

    public InMemoryStore(bool enforcing = true) => _enforcing = enforcing;

    /// <summary>The number of stored content objects.</summary>
    public int ObjectCount => _objectOrder.Count;

    /// <summary>The stored content-object identifiers in insertion order.</summary>
    public IReadOnlyList<string> ObjectIds => _objectOrder;

    /// <summary>The stored content object with this identifier, or null.</summary>
    public JsonMap? GetObject(string identifier)
        => _objects.TryGetValue(identifier, out var obj) ? obj : null;

    /// <summary>The quarantined (unsigned / unverifiable) records by id.</summary>
    public IReadOnlyDictionary<string, JsonMap> Quarantine => _quarantine;

    // ------------------------------------------------------------------ put
    /// <summary>Write a content object; idempotent; returns the identifier.</summary>
    public string Put(JsonMap obj, string? kind = null)
    {
        kind ??= Canonical.InferKind(obj);
        if (!ContentKinds.Contains(kind))
            throw new ArgumentException(
                "Put() takes content objects; use PutRecord()");
        obj = obj.Copy();
        obj.SetDefault("type", kind);
        if (!obj.ContainsKey("id"))
            obj["id"] = Canonical.Identify(obj, kind);
        var id = (string)obj["id"]!;
        if (_objects.ContainsKey(id))
            return id; // immutable: identical identity is a no-op
        var (schemaOk, schemaWhy) = SchemaValidator.ValidateSchema(obj, kind);
        if (!schemaOk)
            throw new RejectedWrite(string.Join("; ", schemaWhy));
        var (semanticsOk, semanticsWhy) = Semantics.ValidateSemantics(obj, kind);
        if (!semanticsOk)
            throw new RejectedWrite(string.Join("; ", semanticsWhy));
        _objects[id] = obj;
        _objectOrder.Add(id);
        return id;
    }

    /// <summary>Write a signed provenance record; returns the identifier.</summary>
    public string PutRecord(JsonMap record, string? kind = null)
        => PutRecordInternal(record, kind, force: false);

    /// <summary>Simulate a decentralized replica merge (no enforcement gate).</summary>
    public string ForceMergeRecord(JsonMap record, string? kind = null)
        => PutRecordInternal(record, kind, force: true);

    private string PutRecordInternal(JsonMap record, string? kind, bool force)
    {
        kind ??= Canonical.InferKind(record);
        if (!RecordKinds.Contains(kind))
            throw new ArgumentException("PutRecord() takes provenance records");
        record = record.Copy();
        record.SetDefault("type", kind);
        var rid = record.GetString("id");
        if (string.IsNullOrEmpty(rid))
            rid = Canonical.Identify(record, kind);
        record["id"] = rid;
        if (_records.ContainsKey(rid))
            return rid; // add-only and idempotent
        if (!Signing.VerifyRecord(record, kind))
        {
            _quarantine[rid] = record;
            throw new RejectedWrite("unsigned or unverifiable record: quarantined");
        }
        var (ok, why) = Semantics.ValidateSemantics(record, kind);
        if (!ok)
            throw new RejectedWrite(string.Join("; ", why));
        if (kind == "retraction" && !RetractionSourceOk(record))
            throw new RejectedWrite(
                "a retraction is valid only from the retracted record's "
                + "source or its succession lineage");
        if (kind == "enrichment" && _enforcing && !force)
        {
            var field = record.GetString("field");
            if ((field == "subsumes" || field == "part_of") && WouldCycle(record))
                throw new RejectedWrite(
                    $"would create a cycle in the materialized {field} graph");
        }
        _records[rid] = record;
        _recordOrder.Add(rid);
        return rid;
    }

    // ------------------------------------------------------- record queries
    private List<JsonMap> RecordsOf(string kind)
    {
        var output = new List<JsonMap>();
        foreach (var rid in _recordOrder)
        {
            var record = _records[rid];
            if (record.GetString("type") == kind)
                output.Add(record);
        }
        return output;
    }

    private HashSet<string> RetractedIds()
    {
        var output = new HashSet<string>();
        foreach (var record in RecordsOf("retraction"))
            output.Add((string)record["retracts"]!);
        return output;
    }

    private bool RetractionSourceOk(JsonMap retraction)
    {
        if (!_records.TryGetValue((string)retraction["retracts"]!, out var target))
            return true; // open world: the target may arrive later
        return Lineage((string)target["source"]!)
            .Contains((string)retraction["source"]!);
    }

    /// <summary>The succession chain closure containing key (includes key).</summary>
    public HashSet<string> Lineage(string key)
    {
        var successorOf = new Dictionary<string, string>();
        var predecessorOf = new Dictionary<string, string>();
        foreach (var record in RecordsOf("succession"))
        {
            successorOf[(string)record["predecessor"]!] =
                (string)record["successor"]!;
            predecessorOf[(string)record["successor"]!] =
                (string)record["predecessor"]!;
        }
        var chain = new HashSet<string> { key };
        var cursor = key;
        while (predecessorOf.TryGetValue(cursor, out var previous))
        {
            cursor = previous;
            chain.Add(cursor);
        }
        cursor = key;
        while (successorOf.TryGetValue(cursor, out var next))
        {
            cursor = next;
            chain.Add(cursor);
        }
        return chain;
    }

    /// <summary>The assertions about an identifier, retractions excluded by default.</summary>
    public List<JsonMap> AssertionsAbout(string identifier,
                                         bool includeRetracted = false)
    {
        var retracted = RetractedIds();
        var output = new List<JsonMap>();
        foreach (var record in RecordsOf("assertion"))
        {
            if (record.GetString("about") != identifier)
                continue;
            if (retracted.Contains((string)record["id"]!))
            {
                if (includeRetracted)
                {
                    // dict(r, retracted=True): a flagged copy for history reads
                    var flagged = record.Copy();
                    flagged["retracted"] = true;
                    output.Add(flagged);
                }
                continue;
            }
            output.Add(record);
        }
        return output;
    }

    /// <summary>The enrichments about an identifier, retractions excluded by default.</summary>
    public List<JsonMap> EnrichmentsAbout(string identifier,
                                          bool includeRetracted = false)
    {
        var retracted = RetractedIds();
        var output = new List<JsonMap>();
        foreach (var record in RecordsOf("enrichment"))
        {
            if (record.GetString("about") != identifier)
                continue;
            if (retracted.Contains((string)record["id"]!) && !includeRetracted)
                continue;
            output.Add(record);
        }
        return output;
    }

    // ------------------------------------------------- materialized views
    /// <summary>(active, excluded) for subsumes/part_of after rule 13 cycle-breaking.</summary>
    public (List<JsonMap> Active, List<JsonMap> Excluded)
        ActiveTaxonomyEdges(string field)
    {
        var retracted = RetractedIds();
        var records = RecordsOf("enrichment")
            .Where(r => r.GetString("field") == field
                        && !retracted.Contains((string)r["id"]!))
            .ToList();
        var active = new List<JsonMap>(records);
        var excluded = new List<JsonMap>();
        while (true)
        {
            var cycle = FindCycleRecords(active);
            if (cycle.Count == 0)
                break;
            // exclude the cycle-completing record with the LATEST timestamp,
            // ties broken by lexicographic record identifier (deterministic)
            var loser = cycle[0];
            foreach (var candidate in cycle)
            {
                var comparison = string.CompareOrdinal(
                    (string)candidate["timestamp"]!, (string)loser["timestamp"]!);
                if (comparison > 0
                    || (comparison == 0
                        && string.CompareOrdinal((string)candidate["id"]!,
                                                 (string)loser["id"]!) > 0))
                    loser = candidate;
            }
            active.Remove(loser);
            excluded.Add(loser);
        }
        return (active, excluded);
    }

    private static List<JsonMap> FindCycleRecords(List<JsonMap> records)
    {
        // edges: about -> [(entry, record)], in insertion order
        var edgeOrder = new List<string>();
        var edges = new Dictionary<string, List<(string Entry, JsonMap Record)>>();
        foreach (var record in records)
        {
            var about = (string)record["about"]!;
            if (!edges.TryGetValue(about, out var list))
            {
                edges[about] = list = new List<(string, JsonMap)>();
                edgeOrder.Add(about);
            }
            list.Add(((string)record["entry"]!, record));
        }
        var state = new Dictionary<string, int>();
        var cycle = new List<JsonMap>();

        bool Dfs(string node, List<JsonMap> pathRecords)
        {
            state[node] = 1;
            if (edges.TryGetValue(node, out var outgoing))
            {
                foreach (var (next, record) in outgoing)
                {
                    var nextState = state.TryGetValue(next, out var s) ? s : 0;
                    if (nextState == 1)
                    {
                        cycle.AddRange(pathRecords);
                        cycle.Add(record);
                        return true;
                    }
                    if (nextState == 0)
                    {
                        var extended = new List<JsonMap>(pathRecords) { record };
                        if (Dfs(next, extended))
                            return true;
                    }
                }
            }
            state[node] = 2;
            return false;
        }

        foreach (var start in edgeOrder)
        {
            var startState = state.TryGetValue(start, out var s) ? s : 0;
            if (startState == 0 && Dfs(start, new List<JsonMap>()))
                return cycle;
        }
        return new List<JsonMap>();
    }

    private bool WouldCycle(JsonMap record)
    {
        var retracted = RetractedIds();
        var records = RecordsOf("enrichment")
            .Where(r => r.GetString("field") == record.GetString("field")
                        && !retracted.Contains((string)r["id"]!))
            .ToList();
        records.Add(record);
        return FindCycleRecords(records).Count > 0;
    }

    /// <summary>The object with its materialized enrichment sets and contributors.</summary>
    public JsonMap? Get(string identifier, string view = "default")
    {
        if (!_objects.TryGetValue(identifier, out var obj))
            return null;
        var includeRetracted = view == "history";
        var excludedIds = new HashSet<string>();
        foreach (var field in new[] { "subsumes", "part_of" })
        {
            var (_, excluded) = ActiveTaxonomyEdges(field);
            foreach (var record in excluded)
                excludedIds.Add((string)record["id"]!);
        }
        // field -> entry-key -> bucket {entry, contributors}, insertion-ordered
        var fieldOrder = new List<string>();
        var fields = new Dictionary<string, (List<string> KeyOrder,
                                             Dictionary<string, JsonMap> Buckets)>();
        foreach (var record in EnrichmentsAbout(identifier, includeRetracted))
        {
            if (excludedIds.Contains((string)record["id"]!) && view != "history")
                continue;
            var fieldName = (string)record["field"]!;
            // (field, canonical-entry) dedup: JCS text is a canonical key
            // for both alias objects (sorted keys) and string entries
            var entryKey = Jcs.Serialize(record["entry"]);
            if (!fields.TryGetValue(fieldName, out var slot))
            {
                slot = (new List<string>(), new Dictionary<string, JsonMap>());
                fields[fieldName] = slot;
                fieldOrder.Add(fieldName);
            }
            if (!slot.Buckets.TryGetValue(entryKey, out var bucket))
            {
                bucket = new JsonMap
                {
                    { "entry", record["entry"] },
                    { "contributors", new List<object?>() },
                };
                slot.Buckets[entryKey] = bucket;
                slot.KeyOrder.Add(entryKey);
            }
            ((List<object?>)bucket["contributors"]!).Add(new JsonMap
            {
                { "source", record["source"] },
                { "timestamp", record["timestamp"] },
            });
        }
        var enrichments = new JsonMap();
        foreach (var fieldName in fieldOrder)
        {
            var (keyOrder, buckets) = fields[fieldName];
            var bucketList = new List<object?>();
            foreach (var key in keyOrder)
                bucketList.Add(buckets[key]);
            enrichments[fieldName] = bucketList;
        }
        if (view == "raw")
            return new JsonMap { { "object", obj } };
        return new JsonMap { { "object", obj }, { "enrichments", enrichments } };
    }

    // -------------------------------------------------------------- resolve
    private static string CanonLabel(string text)
        => string.Join("_", text.Trim().ToLowerInvariant().Split(
               (char[]?)null, StringSplitOptions.RemoveEmptyEntries));

    private static string NormAlias(string text)
        => string.Join(" ", text.Split(
               (char[]?)null, StringSplitOptions.RemoveEmptyEntries))
           .ToLowerInvariant();

    /// <summary>The conformance minimum: exact label, then alias, then nothing.</summary>
    public List<string> Resolve(string text, string? lang = null)
    {
        var labelHits = new List<string>();
        var aliasHits = new List<string>();
        var wantedLabel = CanonLabel(text);
        var wantedAlias = NormAlias(text);
        var retracted = RetractedIds();
        foreach (var oid in _objectOrder)
        {
            var obj = _objects[oid];
            var type = obj.GetString("type");
            if (type != "occurrent" && type != "continuant")
                continue;
            if (obj.GetString("label") == wantedLabel)
            {
                labelHits.Add(oid);
                continue;
            }
            foreach (var record in RecordsOf("enrichment"))
            {
                if (record.GetString("about") != oid
                    || record.GetString("field") != "aliases")
                    continue;
                if (retracted.Contains((string)record["id"]!))
                    continue;
                if (record.Get("entry") is not JsonMap entry)
                    continue;
                if (lang is not null && entry.GetString("lang") != lang)
                    continue;
                if (NormAlias(entry.GetString("text") ?? "") == wantedAlias)
                {
                    aliasHits.Add(oid);
                    break;
                }
            }
        }
        labelHits.AddRange(aliasHits);
        return labelHits;
    }

    // ---------------------------------------------------------------- gaps
    private static List<string> StringList(object? value)
        => value is List<object?> list
               ? list.Select(item => (string)item!).ToList()
               : new List<string>();

    /// <summary>The stigmergy read. Gap kinds per spec/store.md.</summary>
    public List<JsonMap> Gaps(string? kind = null)
    {
        var output = new List<JsonMap>();
        var refined = new HashSet<string>();
        foreach (var oid in _objectOrder)
        {
            var obj = _objects[oid];
            if (obj.GetString("type") == "cro"
                && obj.GetString("refines") is string parentId
                && _objects.TryGetValue(parentId, out var parent))
            {
                var (ok, _) = Semantics.RefinementValid(obj, parent);
                if (ok)
                    refined.Add((string)parent["id"]!);
            }
        }
        foreach (var oid in _objectOrder)
        {
            var obj = _objects[oid];
            if (obj.GetString("type") != "cro")
                continue;
            // missing_field: lacking the temporal window or the modality -
            // mechanism and context may legitimately stay unspecified forever
            // (empty_mechanism is its own kind; absent context = context-free).
            if ((!obj.ContainsKey("temporal") || !obj.ContainsKey("modality"))
                && !refined.Contains(oid))
            {
                var (_, missing) = Semantics.IsPartial(obj);
                output.Add(new JsonMap
                {
                    { "id", oid },
                    { "kind", "missing_field" },
                    { "missing", missing.Cast<object?>().ToList() },
                });
            }
            if (!obj.ContainsKey("mechanism")
                || (obj.Get("mechanism") is List<object?> mech && mech.Count == 0))
            {
                if (!refined.Contains(oid))
                    output.Add(new JsonMap
                    {
                        { "id", oid },
                        { "kind", "empty_mechanism" },
                    });
            }
        }
        foreach (var field in new[] { "subsumes", "part_of" })
        {
            var (_, excluded) = ActiveTaxonomyEdges(field);
            foreach (var record in excluded)
            {
                output.Add(new JsonMap
                {
                    { "id", record["id"] },
                    { "kind", "inconsistent_hierarchy" },
                    { "note", "excluded by the deterministic "
                              + "cycle-breaking view rule" },
                });
            }
        }
        // dangling_reference: a reference to an object absent from the store -
        // the red link that says "this page is wanted".
        foreach (var oid in _objectOrder)
        {
            var obj = _objects[oid];
            var references = new List<string>();
            if (obj.GetString("type") == "cro")
            {
                references.AddRange(StringList(obj.Get("causes")));
                references.AddRange(StringList(obj.Get("effects")));
                references.AddRange(StringList(obj.Get("context")));
                references.AddRange(StringList(obj.Get("mechanism")));
                if (obj.GetString("refines") is string refines)
                    references.Add(refines);
            }
            else if (obj.GetString("type") == "realizable")
            {
                if (obj.GetString("bearer") is string bearer)
                    references.Add(bearer);
            }
            foreach (var reference in references)
            {
                if (!string.IsNullOrEmpty(reference)
                    && !_objects.ContainsKey(reference))
                {
                    output.Add(new JsonMap
                    {
                        { "id", oid },
                        { "kind", "dangling_reference" },
                        { "ref", reference },
                    });
                }
            }
        }
        // conflict: pairs of claims satisfying the formal test (rule 6).
        var cros = _objectOrder
            .Select(id => _objects[id])
            .Where(o => o.GetString("type") == "cro")
            .ToList();
        for (var i = 0; i < cros.Count; i++)
        {
            for (var j = i + 1; j < cros.Count; j++)
            {
                if (Semantics.Conflicts(cros[i], cros[j]))
                {
                    output.Add(new JsonMap
                    {
                        { "kind", "conflict" },
                        { "a", cros[i]["id"] },
                        { "b", cros[j]["id"] },
                    });
                }
            }
        }
        if (kind is not null)
            output = output.Where(g => g.GetString("kind") == kind).ToList();
        return output;
    }
}

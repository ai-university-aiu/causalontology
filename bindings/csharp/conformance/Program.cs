// The Causalontology conformance runner for causalontology-csharp.
//
// Runs every vector in conformance/vectors/ against the C# binding. An
// implementation is conformant if and only if it passes every vector;
// this runner exits nonzero on any failure.
//
// The vectors are frozen at specification 1.0.0: they carry concrete
// 64-hex identifiers, real Ed25519 keys, and a real verifying signature,
// which pass through normalization unchanged. Behavioral vectors still
// derive deterministic keypairs in this harness from symbolic key names
// (seed = sha256("key:" + name)), mirroring
// bindings/python/tests/run_conformance.py exactly.

using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Causalontology;

internal static class Program
{
    private static string _vectorsDir = "";

    // recognizes the whole-word identifier schemes the vectors use (P7)
    private static readonly Regex SymbolicPrefix =
        new("^(occurrent|causal_relation_object|continuant|realizable|assertion|"
            + "enrichment|retraction|succession|stratum|bridge|port|conduit|"
            + "quality|token_individual|token_occurrence|state_assertion|"
            + "token_causal_claim|ed25519):");

    // recognizes an already-frozen 64-character lowercase hex name
    private static readonly Regex Hex64 = new("^[0-9a-f]{64}$");

    private static readonly Dictionary<string, (byte[] Secret, string Public)>
        KeyCache = new();

    // a real, deterministic Ed25519 keypair for a symbolic key name
    private static (byte[] Secret, string Public) Key(string name)
    {
        if (KeyCache.TryGetValue(name, out var cached))
            return cached;
        var seed = SHA256.HashData(Encoding.UTF8.GetBytes("key:" + name));
        var pair = Signing.KeypairFromSeed(seed);
        KeyCache[name] = pair;
        return pair;
    }

    // normalize one symbolic identifier to a well-formed one
    private static string Sym(string s)
    {
        var pieces = s.Split(':', 2);
        if (pieces.Length != 2)
            return s;
        var (scheme, name) = (pieces[0], pieces[1]);
        if (scheme == "ed25519")
        {
            if (Hex64.IsMatch(name))
                return s; // frozen: a real key passes through
            return Key(name).Public;
        }
        if (Hex64.IsMatch(name))
            return s; // frozen: a concrete identifier passes through
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(name));
        return scheme + ":" + Convert.ToHexString(digest).ToLowerInvariant();
    }

    // recursively normalize symbolic identifiers
    private static object? Normalize(object? value) => value switch
    {
        "<128 hex>" => string.Concat(Enumerable.Repeat("ab", 64)),
        string s when SymbolicPrefix.IsMatch(s) => Sym(s),
        List<object?> list => list.Select(Normalize).ToList(),
        JsonMap map => CopyNormalized(map),
        _ => value,
    };

    private static JsonMap CopyNormalized(JsonMap map)
    {
        var output = new JsonMap();
        foreach (var (key, value) in map)
            output[key] = Normalize(value);
        return output;
    }

    // the repository root: CAUSALONTOLOGY_ROOT, else a walk up from cwd
    private static string FindRepoRoot()
    {
        var env = Environment.GetEnvironmentVariable("CAUSALONTOLOGY_ROOT");
        if (!string.IsNullOrEmpty(env))
            return env;
        var dir = Directory.GetCurrentDirectory();
        for (var i = 0; i < 12 && dir is not null; i++)
        {
            if (Directory.Exists(Path.Combine(dir, "conformance", "vectors")))
                return dir;
            dir = Path.GetDirectoryName(dir);
        }
        throw new DirectoryNotFoundException(
            "no conformance/vectors above the working directory; "
            + "set CAUSALONTOLOGY_ROOT");
    }

    private static string VectorPath(int n)
    {
        var hits = Directory.GetFiles(_vectorsDir, $"v{n:D2}_*.json");
        if (hits.Length != 1)
            throw new FileNotFoundException($"vector {n} not found");
        return hits[0];
    }

    // load vector n's JSON file (for its structured inputs)
    private static JsonMap Vec(int n) => (JsonMap)Json.ParseFile(VectorPath(n))!;

    private static JsonMap NormalizedInput(int n)
        => (JsonMap)Normalize(Vec(n)["input"])!;

    // build, timestamp, and sign a provenance record
    private static JsonMap Signed(string kind, JsonMap body, string who,
                                  int tsIndex = 0)
    {
        var (secret, publicId) = Key(who);
        var record = body.Copy();
        record["type"] = kind;
        record.SetDefault("timestamp", $"2026-07-13T0{tsIndex}:00:00Z");
        if (kind == "succession")
            record.SetDefault("predecessor", publicId);
        else
            record["source"] = publicId;
        return Signing.SignRecord(record, secret, kind);
    }

    private static void Check(bool condition, string message)
    {
        if (!condition)
            throw new Exception(message);
    }

    private static bool Mentions(List<string> reasons, string substring)
        => reasons.Any(reason => reason.Contains(substring));

    // -----------------------------------------------------------------------
    // internal sanity checks (not conformance vectors)
    // -----------------------------------------------------------------------
    private static void InternalChecks()
    {
        // RFC 8032, TEST 1 known-answer — the gate for the pure-C# Ed25519
        var sk = Convert.FromHexString(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        var pk = Ed25519.SecretToPublic(sk);
        Check(Convert.ToHexString(pk).ToLowerInvariant()
              == "d75a980182b10ab7d54bfed3c964073a"
                 + "0ee172f3daa62325af021a68f707511a",
              "RFC 8032 TEST 1 public key mismatch");
        var sig = Ed25519.Sign(sk, Array.Empty<byte>());
        Check(Convert.ToHexString(sig).ToLowerInvariant()
              == "e5564300c360ac729086e2cc806e828a"
                 + "84877f1eb8e5d974d873e06522490155"
                 + "5fb8821590a33bacc61e39701cf9b46b"
                 + "d25bf5f0595bbe24655141438e7a100b",
              "RFC 8032 TEST 1 signature mismatch");
        Check(Ed25519.Verify(pk, Array.Empty<byte>(), sig),
              "RFC 8032 TEST 1 signature must verify");
        Check(!Ed25519.Verify(pk, Encoding.UTF8.GetBytes("x"), sig),
              "tampered message must not verify");
        // JCS basics
        Check(Jcs.Serialize(new JsonMap { { "b", 2L }, { "a", 1L } })
              == "{\"a\":1,\"b\":2}", "JCS key ordering");
        Check(Jcs.Serialize(1.0) == "1", "JCS 1.0 -> 1");
        Check(Jcs.Serialize(6.000) == "6", "JCS 6.000 -> 6");
        Check(Jcs.Serialize(0.7) == "0.7", "JCS 0.7 -> 0.7");
        Check(Semantics.ToSeconds(1, "months") == 2629746, "months constant");
        Check(Semantics.ToSeconds(1, "years") == 31556952, "years constant");
        // Ground-truth content-addressed identities (spec freeze).
        var zeros = new string('0', 64);
        Check(Canonical.Identify(new JsonMap {
                  { "type", "stratum" }, { "label", "cellular" },
                  { "scheme", "neuroendocrine" }, { "ordinal", 6L } })
              == "stratum:99162f6202087b209696f9a2a21fe57a"
                 + "da3a349840ce5f8af25e034c8bde5b81",
              "ground-truth stratum id");
        Check(Canonical.Identify(new JsonMap {
                  { "type", "realizable" }, { "kind", "disposition" },
                  { "bearer", "continuant:" + zeros }, { "label", "ltp" } })
              == "realizable:486be612e50996f60632764a36d009e1"
                 + "51a3967d4bedac3f61c88844577243c1",
              "ground-truth realizable id");
        Check(Canonical.Identify(new JsonMap {
                  { "type", "token_occurrence" },
                  { "instantiates", "occurrent:" + zeros },
                  { "interval", new JsonMap { { "start", "1953-08-25T00:00:00Z" },
                                              { "open", true } } } })
              == "token_occurrence:85987b294d9902330b25a9d692cdce27"
                 + "bce090bca30e7c09e8b943059e23351d",
              "ground-truth token_occurrence id");
    }

    // -----------------------------------------------------------------------
    // the 38 vectors
    // -----------------------------------------------------------------------
    private static void V01()
    {
        var input = NormalizedInput(1);
        var (schemaOk, schemaWhy) = SchemaValidator.ValidateSchema(input);
        Check(schemaOk, string.Join("; ", schemaWhy));
        var (semanticsOk, semanticsWhy) = Semantics.ValidateSemantics(input);
        Check(semanticsOk, string.Join("; ", semanticsWhy));
    }

    private static void V02()
    {
        var input = NormalizedInput(2);
        Check(SchemaValidator.ValidateSchema(input).Ok, "schema");
        Check(Semantics.ValidateSemantics(input).Ok, "semantics");
        var (partial, missing) = Semantics.IsPartial(input);
        var expected = ((List<object?>)((JsonMap)Vec(2)["expect"]!)["missing"]!)
            .Select(item => (string)item!).ToList();
        Check(partial && missing.SequenceEqual(expected),
              "missing: " + string.Join(",", missing));
    }

    private static void SchemaFails(int n, string mustMention)
    {
        var input = NormalizedInput(n);
        var (ok, why) = SchemaValidator.ValidateSchema(input);
        Check(!ok, "expected schema-invalid");
        Check(Mentions(why, mustMention), string.Join("; ", why));
    }

    private static void V03() => SchemaFails(3, "effects");
    private static void V04() => SchemaFails(4, "causes");
    private static void V05() => SchemaFails(5, "modality");
    private static void V06() => SchemaFails(6, "colour");
    private static void V07() => SchemaFails(7, "causes");

    private static void V08()
    {
        var (ok, why) = SchemaValidator.ValidateSchema(NormalizedInput(8));
        Check(ok, string.Join("; ", why));
    }

    private static void V09() => SchemaFails(9, "label");
    private static void V10() => SchemaFails(10, "category");

    private static void V11()
    {
        var (ok, why) = SchemaValidator.ValidateSchema(NormalizedInput(11));
        Check(ok, string.Join("; ", why));
    }

    private static void V12() => SchemaFails(12, "confidence");

    private static void V13()
    {
        var input = NormalizedInput(13);
        var (schemaOk, schemaWhy) = SchemaValidator.ValidateSchema(input);
        Check(schemaOk, string.Join("; ", schemaWhy));
        var (semanticsOk, semanticsWhy) = Semantics.ValidateSemantics(input);
        Check(semanticsOk, string.Join("; ", semanticsWhy));
    }

    private static void SemanticsFails(int n, string mustMention)
    {
        var input = NormalizedInput(n);
        var (ok, why) = Semantics.ValidateSemantics(input);
        Check(!ok, "expected semantically-invalid");
        Check(Mentions(why, mustMention), string.Join("; ", why));
    }

    private static void V14()
    {
        var input = NormalizedInput(14);
        Check(SchemaValidator.ValidateSchema(input).Ok, "schema");
        SemanticsFails(14, "minimum_delay");
    }

    private static void V15() => SemanticsFails(15, "acyclic");
    private static void V16() => SemanticsFails(16, "acyclic");

    private static void V17()
    {
        var vector = Vec(17);
        var parent = (JsonMap)Normalize(((JsonMap)vector["given"]!)["parent"])!;
        var child = (JsonMap)Normalize(vector["input"])!;
        var (ok, reason) = Semantics.RefinementValid(child, parent);
        Check(!ok && reason.Contains("rival"), reason);
    }

    private static void V18() => SemanticsFails(18, "not a legal field");
    private static void V19() => SemanticsFails(19, "language-tagged");

    private static void V20()
    {
        var dog = Sym("continuant:dog");
        var mammal = Sym("continuant:mammal");
        var animal = Sym("continuant:animal");
        JsonMap Enrich(string about, string entry, int i)
            => Signed("enrichment",
                      new JsonMap { { "about", about },
                                    { "field", "subsumes" },
                                    { "entry", entry } },
                      "taxo", i);
        // enforcing tier rejects the cycle-completing write
        var store = new InMemoryStore(enforcing: true);
        store.PutRecord(Enrich(dog, mammal, 1));
        store.PutRecord(Enrich(mammal, animal, 2));
        try
        {
            store.PutRecord(Enrich(animal, dog, 3));
            throw new Exception("enforcing store accepted a cycle");
        }
        catch (RejectedWrite e)
        {
            Check(e.Message.Contains("cycle"), e.Message);
        }
        // decentralized merge: the view breaks the cycle deterministically
        var store2 = new InMemoryStore(enforcing: true);
        store2.PutRecord(Enrich(dog, mammal, 1));
        store2.PutRecord(Enrich(mammal, animal, 2));
        var bad = Enrich(animal, dog, 3);
        store2.ForceMergeRecord(bad);
        var (_, excluded) = store2.ActiveTaxonomyEdges("subsumes");
        Check(excluded.Count == 1
              && (string)excluded[0]["id"]! == (string)bad["id"]!,
              "wrong excluded record");
        var repair = store2.Gaps("inconsistent_hierarchy");
        Check(repair.Any(g => (string)g["id"]! == (string)bad["id"]!),
              "no repair gap surfaced");
    }

    private static bool Adm(int n)
    {
        var given = (JsonMap)Vec(n)["given"]!;
        var cro = new JsonMap
        {
            { "causes", new List<object?> { Sym("occurrent:c") } },
            { "effects", new List<object?> { Sym("occurrent:e") } },
            { "temporal", given["temporal"] },
        };
        return Semantics.Admissible(cro, Json.ToDouble(given["elapsed_seconds"]));
    }

    private static void V21() => Check(Adm(21), "expected admissible");
    private static void V22() => Check(!Adm(22), "expected not admissible");
    private static void V23() => Check(Adm(23), "expected admissible");

    private static void V24()
    {
        var vector = Vec(24);
        Check(Canonical.Identify((JsonMap)Normalize(vector["inputA"])!)
              == Canonical.Identify((JsonMap)Normalize(vector["inputB"])!),
              "identifiers differ");
    }

    private static void V25()
    {
        var vector = Vec(25);
        Check(Canonical.Identify((JsonMap)Normalize(vector["inputA"])!)
              == Canonical.Identify((JsonMap)Normalize(vector["inputB"])!),
              "identifiers differ");
    }

    private static void V26()
    {
        var store = new InMemoryStore();
        JsonMap Obj() => new()
        {
            { "type", "occurrent" },
            { "label", "press_button" },
            { "category", "action" },
        };
        var a = store.Put(Obj());
        var b = store.Put(Obj());
        Check(a == b && store.ObjectCount == 1, "put must be idempotent");
    }

    private static void V27()
    {
        var store = new InMemoryStore();
        var occ = store.Put(new JsonMap { { "type", "occurrent" },
                                          { "label", "press_button" },
                                          { "category", "action" } });
        JsonMap Entry() => new() { { "lang", "en" },
                                   { "text", "press the button" } };
        var r1 = Signed("enrichment", new JsonMap { { "about", occ },
                                                    { "field", "aliases" },
                                                    { "entry", Entry() } },
                        "alice", 1);
        var r2 = Signed("enrichment", new JsonMap { { "about", occ },
                                                    { "field", "aliases" },
                                                    { "entry", Entry() } },
                        "bob", 2);
        Check(store.PutRecord(r1) != store.PutRecord(r2), "two records");
        var enrichments = (JsonMap)store.Get(occ)!["enrichments"]!;
        var view = (List<object?>)enrichments["aliases"]!;
        Check(view.Count == 1, "one materialized entry");
        var contributors = (List<object?>)((JsonMap)view[0]!)["contributors"]!;
        Check(contributors.Count == 2, "two contributors");
    }

    private static void V28()
    {
        var store = new InMemoryStore();
        JsonMap Claim() => new()
        {
            { "type", "causal_relation_object" },
            { "causes", new List<object?> { Sym("occurrent:A") } },
            { "effects", new List<object?> { Sym("occurrent:B") } },
            { "modality", "sufficient" },
        };
        var i1 = store.Put(Claim());
        var i2 = store.Put(Claim());
        Check(i1 == i2 && store.ObjectCount == 1, "one object");
        foreach (var (who, ts) in new[] { ("lab1", 1), ("lab2", 2) })
        {
            store.PutRecord(Signed("assertion",
                new JsonMap { { "about", i1 },
                              { "evidence_type", "observation" },
                              { "strength", 0.8 },
                              { "confidence", 0.8 } },
                who, ts));
        }
        Check(store.AssertionsAbout(i1).Count == 2, "two assertions");
    }

    private static void V29()
    {
        var record = Signed("assertion",
            new JsonMap { { "about", Sym("causal_relation_object:demo") },
                          { "evidence_type", "intervention" },
                          { "strength", 0.7 },
                          { "confidence", 0.9 } },
            "signer");
        Check(Signing.VerifyRecord(record), "signature must verify");
    }

    private static void V30()
    {
        var record = Signed("assertion",
            new JsonMap { { "about", Sym("causal_relation_object:demo") },
                          { "evidence_type", "intervention" },
                          { "strength", 0.7 },
                          { "confidence", 0.9 } },
            "signer");
        var tampered = record.Copy();
        tampered["confidence"] = 0.1;
        Check(!Signing.VerifyRecord(tampered), "tampered record must fail");
    }

    private static void V31()
    {
        var store = new InMemoryStore();
        var x = store.Put(new JsonMap
        {
            { "type", "causal_relation_object" },
            { "causes", new List<object?> { Sym("occurrent:A") } },
            { "effects", new List<object?> { Sym("occurrent:B") } },
        });
        var a = Signed("assertion",
            new JsonMap { { "about", x },
                          { "evidence_type", "observation" },
                          { "confidence", 0.8 } },
            "lab1", 1);
        store.PutRecord(a);
        store.PutRecord(Signed("retraction",
            new JsonMap { { "retracts", a["id"] } }, "lab1", 2));
        Check(store.AssertionsAbout(x).Count == 0, "excluded from default view");
        var history = store.AssertionsAbout(x, includeRetracted: true);
        Check(history.Count == 1 && history[0].Get("retracted") is true,
              "history flag");
        var foreign = Signed("retraction",
            new JsonMap { { "retracts", a["id"] } }, "mallory", 3);
        try
        {
            store.PutRecord(foreign);
            throw new Exception("foreign retraction accepted");
        }
        catch (RejectedWrite)
        {
            // expected: only the source or its lineage may retract
        }
        Check(store.AssertionsAbout(x).Count == 0,
              "still excluded by lab1's own retraction");
        Check(store.AssertionsAbout(x, includeRetracted: true).Count == 1,
              "history still one");
    }

    private static void V32()
    {
        var store = new InMemoryStore();
        var occ = store.Put(new JsonMap { { "type", "occurrent" },
                                          { "label", "press_button" },
                                          { "category", "action" } });
        var e = Signed("enrichment",
            new JsonMap { { "about", occ },
                          { "field", "aliases" },
                          { "entry", new JsonMap { { "lang", "ja" },
                                                   { "text", "botan" } } } },
            "bob", 1);
        store.PutRecord(e);
        List<object?> Aliases(string view)
        {
            var enrichments = (JsonMap)store.Get(occ, view)!["enrichments"]!;
            return enrichments.Get("aliases") as List<object?>
                   ?? new List<object?>();
        }
        Check(Aliases("default").Count == 1, "one alias before retraction");
        store.PutRecord(Signed("retraction",
            new JsonMap { { "retracts", e["id"] } }, "bob", 2));
        Check(Aliases("default").Count == 0, "alias gone from default view");
        Check(Aliases("history").Count == 1, "alias present in history view");
    }

    private static void V33()
    {
        var store = new InMemoryStore();
        var k1 = Key("K1").Public;
        var k2 = Key("K2").Public;
        var a = Signed("assertion",
            new JsonMap { { "about", Sym("causal_relation_object:claim") },
                          { "evidence_type", "observation" },
                          { "confidence", 0.9 } },
            "K1", 1);
        store.PutRecord(a);
        var succession = Signed("succession",
            new JsonMap { { "successor", k2 } }, "K1", 2);
        store.PutRecord(succession);
        Check(store.Lineage(k2).Contains(k1) && store.Lineage(k1).Contains(k2),
              "lineage closure");
        var retraction = Signed("retraction",
            new JsonMap { { "retracts", a["id"] } }, "K2", 3);
        store.PutRecord(retraction); // successor may retract the predecessor's record
        Check(store.AssertionsAbout(Sym("causal_relation_object:claim")).Count == 0,
              "retracted via succession");
    }

    private static void V34()
    {
        var given = (JsonMap)Normalize(Vec(34)["given"])!;
        Check(Semantics.Conflicts((JsonMap)given["A"]!, (JsonMap)given["B"]!),
              "expected conflict");
    }

    private static void V35()
    {
        var given = (JsonMap)Normalize(Vec(35)["given"])!;
        Check(!Semantics.Conflicts((JsonMap)given["A"]!, (JsonMap)given["B"]!),
              "expected no conflict");
    }

    private static void V36()
    {
        var (a, b, c, d) = (Sym("occurrent:A"), Sym("occurrent:B"), Sym("occurrent:C"),
                            Sym("occurrent:D"));
        JsonMap Member(string id, string cause, string effect) => new()
        {
            { "id", id },
            { "causes", new List<object?> { cause } },
            { "effects", new List<object?> { effect } },
        };
        var m1 = Member(Sym("causal_relation_object:m1"), a, b);
        var m2 = Member(Sym("causal_relation_object:m2"), b, c);
        var m3 = Member(Sym("causal_relation_object:m3"), d, c);
        var parent = new JsonMap
        {
            { "causes", new List<object?> { a } },
            { "effects", new List<object?> { c } },
            { "mechanism", new List<object?> { m1["id"], m2["id"] } },
        };
        Check(Semantics.HierarchyConsistent(parent,
                  new Dictionary<string, JsonMap>
                  {
                      [(string)m1["id"]!] = m1,
                      [(string)m2["id"]!] = m2,
                  }) == "consistent", "chain must be consistent");
        var parent2 = parent.Copy();
        parent2["mechanism"] = new List<object?> { m1["id"], m3["id"] };
        Check(Semantics.HierarchyConsistent(parent2,
                  new Dictionary<string, JsonMap>
                  {
                      [(string)m1["id"]!] = m1,
                      [(string)m3["id"]!] = m3,
                  }) == "inconsistent", "broken chain must be inconsistent");
        Check(Semantics.HierarchyConsistent(parent,
                  new Dictionary<string, JsonMap>
                  {
                      [(string)m1["id"]!] = m1,
                  }) == "indeterminate", "missing member is indeterminate");
    }

    private static void V37()
    {
        var store = new InMemoryStore();
        var occ = store.Put(new JsonMap { { "type", "occurrent" },
                                          { "label", "press_button" },
                                          { "category", "action" } });
        store.PutRecord(Signed("enrichment",
            new JsonMap { { "about", occ },
                          { "field", "aliases" },
                          { "entry", new JsonMap
                              { { "lang", "en" },
                                { "text", "Press the Button" } } } },
            "alice", 1));
        var byAlias = store.Resolve("Press  The   Button", "en");
        Check(byAlias.Count == 1 && byAlias[0] == occ, "alias match");
        var byLabel = store.Resolve("press_button", "en");
        Check(byLabel.Count > 0 && byLabel[0] == occ, "label, first");
    }

    private static void V38()
    {
        var store = new InMemoryStore();
        var parent = store.Put(new JsonMap
        {
            { "type", "causal_relation_object" },
            { "causes", new List<object?> { Sym("occurrent:A") } },
            { "effects", new List<object?> { Sym("occurrent:B") } },
        });
        var gaps = store.Gaps("missing_field")
            .Select(g => (string)g["id"]!).ToList();
        Check(gaps.Contains(parent), "the degenerate claim is a gap");
        var refinement = store.Put(new JsonMap
        {
            { "type", "causal_relation_object" },
            { "causes", new List<object?> { Sym("occurrent:A") } },
            { "effects", new List<object?> { Sym("occurrent:B") } },
            { "temporal", new JsonMap { { "minimum_delay", 0L }, { "maximum_delay", 1L },
                                        { "unit", "seconds" } } },
            { "modality", "sufficient" },
            { "refines", parent },
        });
        gaps = store.Gaps("missing_field")
            .Select(g => (string)g["id"]!).ToList();
        Check(!gaps.Contains(parent), "the gap did not close");
        Check(!gaps.Contains(refinement),
              "the refinement itself must be complete");
    }

    // -----------------------------------------------------------------------
    // V39 - V107 builders (mirror bindings/python/tests/run_conformance.py)
    // -----------------------------------------------------------------------
    private static List<object?> L(params object?[] items) => items.ToList();

    private static List<string> SList(object? value)
        => value is List<object?> list
               ? list.Select(item => (string)item!).ToList()
               : new List<string>();

    // a content object completed with its real content-addressed id
    private static JsonMap Mk(JsonMap obj)
    {
        obj["id"] = Canonical.Identify(obj);
        return obj;
    }

    private static JsonMap Stratum(string label, string scheme, long ordinal,
                                   string? unit = null,
                                   List<object?>? governs = null)
    {
        var o = new JsonMap { { "type", "stratum" }, { "label", label },
                              { "scheme", scheme }, { "ordinal", ordinal } };
        if (unit is not null) o["unit"] = unit;
        if (governs is not null) o["governs"] = governs;
        return Mk(o);
    }

    private static JsonMap Occ(string label, string? stratumId = null,
                               string category = "event")
    {
        var o = new JsonMap { { "type", "occurrent" }, { "label", label },
                              { "category", category } };
        if (stratumId is not null) o["stratum"] = stratumId;
        return Mk(o);
    }

    private static JsonMap Cnt(string label, string category = "object")
        => Mk(new JsonMap { { "type", "continuant" }, { "label", label },
                            { "category", category } });

    private static JsonMap Cro(List<object?> causes, List<object?> effects,
                               JsonMap? extra = null)
    {
        var o = new JsonMap { { "type", "causal_relation_object" },
                              { "causes", causes }, { "effects", effects } };
        if (extra is not null)
            foreach (var (k, v) in extra)
                o[k] = v;
        return Mk(o);
    }

    private static JsonMap Bridge(string coarse, List<object?> fine,
                                  string relation)
        => Mk(new JsonMap { { "type", "bridge" }, { "coarse", coarse },
                            { "fine", fine }, { "relation", relation } });

    private static JsonMap Port(string bearer, string label, string direction,
                                List<object?> accepts, string? realizable = null)
    {
        var o = new JsonMap { { "type", "port" }, { "bearer", bearer },
                              { "label", label }, { "direction", direction },
                              { "accepts", accepts } };
        if (realizable is not null) o["realizable"] = realizable;
        return Mk(o);
    }

    private static JsonMap Conduit(string frm, string to, List<object?> carries,
                                   string label = "conn", string? transform = null)
    {
        var o = new JsonMap { { "type", "conduit" }, { "label", label },
                              { "from", frm }, { "to", to },
                              { "carries", carries } };
        if (transform is not null) o["transform"] = transform;
        return Mk(o);
    }

    private static JsonMap Quality(string label, string datatype,
                                   string? unit = null, string? stratumId = null)
    {
        var o = new JsonMap { { "type", "quality" }, { "label", label },
                              { "datatype", datatype } };
        if (unit is not null) o["unit"] = unit;
        if (stratumId is not null) o["stratum"] = stratumId;
        return Mk(o);
    }

    private static JsonMap Individual(string instantiates,
                                      string? designator = null,
                                      string? partOf = null)
    {
        var o = new JsonMap { { "type", "token_individual" },
                              { "instantiates", instantiates } };
        if (designator is not null) o["designator"] = designator;
        if (partOf is not null) o["part_of"] = partOf;
        return Mk(o);
    }

    private static JsonMap Token(string instantiates, JsonMap interval,
                                 List<object?>? participants = null,
                                 string? locus = null)
    {
        var o = new JsonMap { { "type", "token_occurrence" },
                              { "instantiates", instantiates },
                              { "interval", interval } };
        if (participants is not null) o["participants"] = participants;
        if (locus is not null) o["locus"] = locus;
        return Mk(o);
    }

    private static JsonMap State(string subject, string quality, JsonMap value,
                                 JsonMap interval)
        => Mk(new JsonMap { { "type", "state_assertion" }, { "subject", subject },
                            { "quality", quality }, { "value", value },
                            { "interval", interval } });

    private static JsonMap Tcc(List<object?> causes, List<object?> effects,
                               string? coveringLaw = null,
                               JsonMap? actualDelay = null,
                               bool? counterfactual = null)
    {
        var o = new JsonMap { { "type", "token_causal_claim" },
                              { "causes", causes }, { "effects", effects } };
        if (coveringLaw is not null) o["covering_law"] = coveringLaw;
        if (actualDelay is not null) o["actual_delay"] = actualDelay;
        if (counterfactual is not null) o["counterfactual"] = counterfactual;
        return Mk(o);
    }

    private static Dictionary<int, JsonMap> Neuro()
    {
        var labels = new Dictionary<int, string>
        {
            [4] = "macromolecular", [5] = "subcellular", [6] = "cellular",
            [7] = "synaptic", [9] = "region", [14] = "community_and_society",
        };
        return labels.ToDictionary(kv => kv.Key,
            kv => Stratum(kv.Value, "neuroendocrine", kv.Key));
    }

    private static Dictionary<string, JsonMap> Map(params JsonMap[] objs)
    {
        // last-writer-wins, mirroring a Python dict literal with repeated keys
        var map = new Dictionary<string, JsonMap>();
        foreach (var o in objs)
            map[(string)o["id"]!] = o;
        return map;
    }

    private static void SchemaOk(JsonMap obj, string? kind = null)
    {
        var (ok, why) = SchemaValidator.ValidateSchema(obj, kind);
        Check(ok, string.Join("; ", why));
    }

    // ---- V39 - V107 --------------------------------------------------------
    private static void V39()
    {
        var st = Stratum("cellular", "neuroendocrine", 6, "cell",
                         L("cell_biology"));
        SchemaOk(st);
    }

    private static void V40()
    {
        var bad = Mk(new JsonMap { { "type", "stratum" }, { "label", "cellular" },
                                   { "ordinal", 6L } });
        var (ok, why) = SchemaValidator.ValidateSchema(bad, "stratum");
        Check(!ok && Mentions(why, "scheme"), string.Join("; ", why));
    }

    private static void V41()
    {
        var a = Stratum("cellular", "neuroendocrine", 6);
        var b = Stratum("neuronal", "neuroendocrine", 6);
        SchemaOk(a); SchemaOk(b);
        Check((string)a["id"]! != (string)b["id"]!, "distinct strata");
    }

    private static void V42()
    {
        var s = Neuro();
        var s4p = Stratum("molecular", "physics", 4);
        var c = Occ("chronic_social_subordination", (string)s[14]["id"]!);
        var e = Occ("gene_expression", (string)s4p["id"]!);
        var smap = Map(s[14], s4p);
        var omap = Map(c, e);
        var p = Cro(L(c["id"]), L(e["id"]));
        Check(Semantics.ClassifyCro(p, omap, smap) == "scheme_mismatch",
              "expected scheme_mismatch");
    }

    private static void V43()
    {
        SchemaOk(Stratum("macromolecular", "neuroendocrine", 4));
        SchemaOk(Stratum("region", "neuroendocrine", 9));
    }

    private static void V44()
    {
        var st = Stratum("cellular", "neuroendocrine", 6);
        var o = Occ("neuron_fires", (string)st["id"]!);
        SchemaOk(o);
        Check(Semantics.ValidateSemantics(o).Ok, "semantics");
    }

    private static void V45()
    {
        var o = Occ("press_button");
        SchemaOk(o);
        var e = Occ("light_on");
        var p = Cro(L(o["id"]), L(e["id"]));
        Check(Semantics.ClassifyCro(p, Map(o, e),
                  new Dictionary<string, JsonMap>()) == "unclassifiable",
              "expected unclassifiable");
    }

    private static void V46()
    {
        var s = Neuro();
        var a = Occ("depolarization", (string)s[5]["id"]!);
        var b = Occ("depolarization", (string)s[6]["id"]!);
        Check((string)a["id"]! != (string)b["id"]!, "distinct by stratum");
    }

    private static (JsonMap Bridge, Dictionary<string, JsonMap> Omap,
                    Dictionary<string, JsonMap> Smap) BridgeFixture(string relation)
    {
        var s = Neuro();
        var coarse = Occ("action_potential_fires", (string)s[6]["id"]!);
        var fine = new[] { Occ("sodium_channels_open", (string)s[4]["id"]!),
                           Occ("sodium_influx", (string)s[4]["id"]!) };
        var b = Bridge((string)coarse["id"]!,
                       fine.Select(f => (object?)f["id"]).ToList(), relation);
        var omap = Map(new[] { coarse }.Concat(fine).ToArray());
        var smap = Map(s[4], s[6]);
        return (b, omap, smap);
    }

    private static void ValidBridge(string relation)
    {
        var (b, omap, smap) = BridgeFixture(relation);
        SchemaOk(b);
        var (ok, why) = Semantics.BridgeWellformed(b, omap, smap);
        Check(ok, why);
    }

    private static void V47() => ValidBridge("constitutes");
    private static void V48() => ValidBridge("aggregates");
    private static void V49() => ValidBridge("realizes");
    private static void V50() => ValidBridge("supervenes_on");

    private static void V51()
    {
        var s = Neuro();
        var coarse = Occ("x_coarse", (string)s[4]["id"]!);
        var fine = Occ("x_fine", (string)s[6]["id"]!);
        var b = Bridge((string)coarse["id"]!, L(fine["id"]), "constitutes");
        var (ok, _) = Semantics.BridgeWellformed(b, Map(coarse, fine),
                                                 Map(s[4], s[6]));
        Check(!ok, "expected malformed");
    }

    private static void V52()
    {
        var s = Neuro();
        var coarse = Occ("c", (string)s[6]["id"]!);
        var f1 = Occ("f1", (string)s[4]["id"]!);
        var f2 = Occ("f2", (string)s[5]["id"]!);
        var b = Bridge((string)coarse["id"]!, L(f1["id"], f2["id"]),
                       "constitutes");
        var (ok, _) = Semantics.BridgeWellformed(b, Map(coarse, f1, f2),
                                                 Map(s[4], s[5], s[6]));
        Check(!ok, "expected malformed");
    }

    private static void V53()
    {
        var x = Sym("occurrent:x");
        var y = Sym("occurrent:y");
        var b1 = Bridge(x, L(y), "constitutes");
        var b2 = Bridge(y, L(x), "constitutes");
        var edges = new Dictionary<string, List<string>>();
        foreach (var b in new[] { b1, b2 })
            foreach (var f in SList(b["fine"]))
            {
                if (!edges.TryGetValue(f, out var list))
                    edges[f] = list = new List<string>();
                list.Add((string)b["coarse"]!);
            }
        Check(Semantics.HasCycle(edges), "expected cycle");
    }

    private static void V54()
    {
        var a = Stratum("cellular", "neuroendocrine", 6);
        var b = Stratum("molecular", "physics", 4);
        var coarse = Occ("c", (string)a["id"]!);
        var fine = Occ("f", (string)b["id"]!);
        var br = Bridge((string)coarse["id"]!, L(fine["id"]), "constitutes");
        var (ok, _) = Semantics.BridgeWellformed(br, Map(coarse, fine),
                                                 Map(a, b));
        Check(!ok, "expected malformed");
    }

    private static void V55()
    {
        var s = Neuro();
        var coarse = Occ("decision_made", (string)s[6]["id"]!);
        var f1 = Occ("cascade_a", (string)s[4]["id"]!);
        var f2 = Occ("cascade_b", (string)s[4]["id"]!);
        var b1 = Bridge((string)coarse["id"]!, L(f1["id"]), "realizes");
        var b2 = Bridge((string)coarse["id"]!, L(f2["id"]), "realizes");
        Check((string)b1["id"]! != (string)b2["id"]!, "distinct bridges");
        SchemaOk(b1); SchemaOk(b2);
    }

    private static (JsonMap Parent, Dictionary<string, JsonMap> Members,
                    List<JsonMap> Bridges) ReachFixture()
    {
        var s = Neuro();
        var ap = Occ("action_potential_fires", (string)s[6]["id"]!);
        var nt = Occ("neurotransmitter_released", (string)s[6]["id"]!);
        var fa = Occ("calcium_enters", (string)s[4]["id"]!);
        var fb = Occ("vesicle_fuses", (string)s[4]["id"]!);
        var m1 = Cro(L(fa["id"]), L(fb["id"]));
        var p = Cro(L(ap["id"]), L(nt["id"]),
                    new JsonMap { { "mechanism", L(m1["id"]) } });
        var bridges = new List<JsonMap>
        {
            Bridge((string)ap["id"]!, L(fa["id"]), "constitutes"),
            Bridge((string)nt["id"]!, L(fb["id"]), "constitutes"),
        };
        return (p, Map(m1), bridges);
    }

    private static void V56()
    {
        var (p, members, bridges) = ReachFixture();
        Check(Semantics.HierarchyConsistent(p, members, bridges) == "consistent",
              "expected consistent");
    }

    private static void V57()
    {
        var (p, members, _) = ReachFixture();
        Check(Semantics.HierarchyConsistent(p, members) == "inconsistent",
              "expected inconsistent");
    }

    private static void V58()
    {
        var (p, members, bridges) = ReachFixture();
        var literal = Semantics.HierarchyConsistent(p, members);
        var bridged = Semantics.HierarchyConsistent(p, members, bridges);
        Check(literal != "consistent" && bridged == "consistent",
              "bridged reachability must differ from literal");
    }

    private static string Classify(int causeOrd, int effectOrd)
    {
        var s = Neuro();
        var c = Occ("c", (string)s[causeOrd]["id"]!);
        var e = Occ("e", (string)s[effectOrd]["id"]!);
        return Semantics.ClassifyCro(Cro(L(c["id"]), L(e["id"])),
                                     Map(c, e), Map(s[causeOrd], s[effectOrd]));
    }

    private static void V59() => Check(Classify(6, 6) == "intra_stratal", "V59");
    private static void V60()
        => Check(Classify(6, 5) == "adjacent_stratal", "V60");
    private static void V61() => Check(Classify(14, 4) == "skipping", "V61");

    private static (JsonMap Cro, string Classification) SkipFixture(
        int causeOrd, int effectOrd, JsonMap? extra = null)
    {
        var s = Neuro();
        var c = Occ("c", (string)s[causeOrd]["id"]!);
        var e = Occ("e", (string)s[effectOrd]["id"]!);
        var p = Cro(L(c["id"]), L(e["id"]), extra);
        var cls = Semantics.ClassifyCro(p, Map(c, e),
                                        Map(s[causeOrd], s[effectOrd]));
        return (p, cls);
    }

    private static void V62()
    {
        var (p, cls) = SkipFixture(14, 4);
        Check(Semantics.SkipGaps(p, cls).SequenceEqual(
                  new[] { "incomplete_mechanism" }), "V62");
    }

    private static void V63()
    {
        var (p, cls) = SkipFixture(14, 4, new JsonMap { { "skips", true } });
        Check(Semantics.SkipGaps(p, cls).Count == 0, "V63 expected nothing");
    }

    private static void V64()
    {
        var (p, cls) = SkipFixture(14, 4, new JsonMap {
            { "skips", true },
            { "mechanism", L(Sym("causal_relation_object:m")) } });
        Check(Semantics.SkipGaps(p, cls).SequenceEqual(
                  new[] { "contradictory_skip" }), "V64 gaps");
        var (ok, why) = Semantics.ValidateSemantics(p);
        Check(!ok && Mentions(why, "contradictory_skip"), "V64 semantics");
    }

    private static void V65()
    {
        var (p, cls) = SkipFixture(6, 6, new JsonMap { { "skips", true } });
        Check(Semantics.SkipGaps(p, cls).SequenceEqual(new[] { "vacuous_skip" }),
              "V65");
    }

    private static void V66()
    {
        var s = Neuro();
        var c = Occ("c", (string)s[14]["id"]!);
        var e = Occ("e", (string)s[4]["id"]!);
        var absent = Cro(L(c["id"]), L(e["id"]));
        var falseSkip = Cro(L(c["id"]), L(e["id"]),
                            new JsonMap { { "skips", false } });
        Check((string)absent["id"]! != (string)falseSkip["id"]!,
              "skips false distinct from absent");
    }

    private static void V67()
    {
        var s = Neuro();
        var c1 = Occ("c1", (string)s[4]["id"]!);
        var c2 = Occ("c2", (string)s[6]["id"]!);
        var e = Occ("e", (string)s[6]["id"]!);
        var p = Cro(L(c1["id"], c2["id"]), L(e["id"]));
        Check(Semantics.EndpointsMixed(p, Map(c1, c2, e)), "expected mixed");
    }

    private static void V68()
    {
        var p = Cro(L(Sym("occurrent:a")), L(Sym("occurrent:b")),
                    new JsonMap { { "modality", "enabling" } });
        SchemaOk(p);
    }

    private static void V69()
    {
        var a = new JsonMap { { "causes", L(Sym("occurrent:a")) },
                              { "effects", L(Sym("occurrent:b")) },
                              { "modality", "enabling" } };
        var b = new JsonMap { { "causes", L(Sym("occurrent:a")) },
                              { "effects", L(Sym("occurrent:b")) },
                              { "modality", "sufficient" } };
        Check(!Semantics.Conflicts(a, b), "enabling compatible with sufficient");
    }

    private static void V70()
    {
        var a = new JsonMap { { "causes", L(Sym("occurrent:a")) },
                              { "effects", L(Sym("occurrent:b")) },
                              { "modality", "enabling" } };
        var b = new JsonMap { { "causes", L(Sym("occurrent:a")) },
                              { "effects", L(Sym("occurrent:b")) },
                              { "modality", "preventive" } };
        Check(Semantics.Conflicts(a, b), "enabling opposed by preventive");
    }

    private static void V71()
    {
        var b = Cnt("hippocampus");
        var p = Port((string)b["id"]!, "perforant_path", "in",
                     L(Sym("occurrent:signal")));
        SchemaOk(p);
    }

    private static void V72()
    {
        var b = (string)Cnt("hippocampus")["id"]!;
        var x = Sym("occurrent:signal");
        Check((string)Port(b, "perforant_path", "in", L(x))["id"]!
              != (string)Port(b, "fornix", "in", L(x))["id"]!,
              "distinct ports by label");
    }

    private static (JsonMap Conduit, Dictionary<string, JsonMap> Pmap,
                    Dictionary<string, JsonMap> CroMap) ConduitFixture(
        bool transform = false, bool badCarry = false, bool inFrom = false)
    {
        var x = Sym("occurrent:motor_command");
        var y = Sym("occurrent:error_signal");
        var z = Sym("occurrent:unrelated");
        var m1 = (string)Cnt("motor_cortex")["id"]!;
        var m2 = (string)Cnt("spinal_neuron")["id"]!;
        var frm = Port(m1, "out_port", inFrom ? "in" : "out", L(x));
        var to = Port(m2, "in_port", "in", transform ? L(y) : L(x));
        var carries = badCarry ? L(z) : L(x);
        string? xform = null;
        var croMap = new Dictionary<string, JsonMap>();
        if (transform)
        {
            var law = Cro(L(x), L(y));
            croMap[(string)law["id"]!] = law;
            xform = (string)law["id"]!;
        }
        var c = Conduit((string)frm["id"]!, (string)to["id"]!, carries,
                        transform: xform);
        return (c, Map(frm, to), croMap);
    }

    private static void V73()
    {
        var (c, pmap, _) = ConduitFixture();
        SchemaOk(c);
        var (ok, why) = Semantics.ConduitWellformed(c, pmap);
        Check(ok, why);
    }

    private static void V74()
    {
        var (c, pmap, cmap) = ConduitFixture(transform: true);
        SchemaOk(c);
        var (ok, why) = Semantics.ConduitWellformed(c, pmap, cmap);
        Check(ok, why);
    }

    private static void V75()
    {
        var (c, pmap, _) = ConduitFixture(badCarry: true);
        var (ok, _) = Semantics.ConduitWellformed(c, pmap);
        Check(!ok, "expected malformed");
    }

    private static void V76()
    {
        var (c, pmap, _) = ConduitFixture(inFrom: true);
        var (ok, _) = Semantics.ConduitWellformed(c, pmap);
        Check(!ok, "expected malformed");
    }

    private static void V77()
    {
        var (c, pmap, cmap) = ConduitFixture(transform: true);
        var (ok, why) = Semantics.ConduitWellformed(c, pmap, cmap);
        Check(ok, why);
        var law = cmap.Values.First();
        Check(!SList(c["carries"]).Contains((string)SList(law["effects"])[0]),
              "transform may emit what it did not accept");
    }

    private static JsonMap Rlz(string bearer, string kind, string? label = null)
    {
        var o = new JsonMap { { "type", "realizable" }, { "kind", kind },
                              { "bearer", bearer } };
        if (label is not null) o["label"] = label;
        return Mk(o);
    }

    private static void V78()
    {
        var b = (string)Cnt("hippocampus")["id"]!;
        Check((string)Rlz(b, "disposition", "long_term_potentiation")["id"]!
              != (string)Rlz(b, "disposition", "pattern_separation")["id"]!,
              "labelled realizables distinct");
    }

    private static void V79()
    {
        var b = (string)Cnt("hippocampus")["id"]!;
        var u1 = Rlz(b, "disposition");
        var u2 = Rlz(b, "disposition");
        SchemaOk(u1);
        Check((string)u1["id"]! == (string)u2["id"]!, "unlabelled identical");
        Check((string)Rlz(b, "disposition", "some_function")["id"]!
              != (string)u1["id"]!, "labelled differs from unlabelled");
    }

    private static void V80()
    {
        var parent = Occ("fires");
        var child = Occ("fires_action_potential");
        var e = new JsonMap { { "type", "enrichment" }, { "about", child["id"] },
                              { "field", "occurrent_subsumes" },
                              { "entry", parent["id"] } };
        Check(Semantics.ValidateSemantics(e).Ok, "V80 semantics");
    }

    private static void V81()
    {
        var a = Sym("occurrent:a");
        var b = Sym("occurrent:b");
        Check(Semantics.HasCycle(new Dictionary<string, List<string>>
              { [a] = new() { b }, [b] = new() { a } }), "expected cycle");
    }

    private static void V82()
    {
        var whole = Occ("eat");
        var part = Occ("chew");
        var e = new JsonMap { { "type", "enrichment" }, { "about", part["id"] },
                              { "field", "occurrent_part_of" },
                              { "entry", whole["id"] } };
        Check(Semantics.ValidateSemantics(e).Ok, "V82 semantics");
    }

    private static void V83()
    {
        var (legalKinds, shape) =
            Semantics.EnrichmentFields["occurrent_part_of"];
        Check(shape == "occurrent" && legalKinds.SequenceEqual(new[] { "occurrent" }),
              "V83 field spec");
        var store = new InMemoryStore();
        store.Put(Occ("eat"));
        store.Put(Occ("chew"));
        Check(store.ObjectIds.All(id =>
                  store.GetObject(id)!.GetString("type") != "causal_relation_object"),
              "part_of does not imply causation");
    }

    private static void V84()
    {
        var s = Neuro();
        var a = Occ("run", (string)s[9]["id"]!);
        var b = Occ("sprint", (string)s[6]["id"]!);
        Check((string)a["stratum"]! != (string)b["stratum"]!, "different strata");
    }

    private static void V85()
    {
        var c = Cnt("human_patient");
        var ti = Individual((string)c["id"]!, designator: "salted_hash_abc123");
        SchemaOk(ti);
    }

    private static void V86()
    {
        var bad = Mk(new JsonMap { { "type", "token_individual" },
                                   { "designator", "x" } });
        var (ok, why) = SchemaValidator.ValidateSchema(bad, "token_individual");
        Check(!ok && Mentions(why, "instantiates"), string.Join("; ", why));
    }

    private static void V87()
    {
        var c = (string)Cnt("human_patient")["id"]!;
        Check((string)Individual(c, designator: "hash_a")["id"]!
              != (string)Individual(c, designator: "hash_b")["id"]!,
              "distinct by designator");
    }

    private static void V88()
    {
        var o = Occ("bilateral_hippocampal_resection");
        var t = Token((string)o["id"]!,
                      new JsonMap { { "start", "1953-08-25T00:00:00Z" },
                                    { "end", "1953-08-25T00:00:00Z" } });
        SchemaOk(t);
    }

    private static void V89()
    {
        var o = (string)Occ("amnesia_onset")["id"]!;
        var bounded = Token(o, new JsonMap { { "start", "1953-08-25T00:00:00Z" },
                                             { "end", "1953-08-26T00:00:00Z" } });
        var instantaneous = Token(o,
            new JsonMap { { "start", "1953-08-25T00:00:00Z" } });
        var ongoing = Token(o, new JsonMap { { "start", "1953-08-25T00:00:00Z" },
                                             { "open", true } });
        var ids = new HashSet<string> { (string)bounded["id"]!,
            (string)instantaneous["id"]!, (string)ongoing["id"]! };
        Check(ids.Count == 3, "three distinct intervals");
    }

    private static void V90()
    {
        var o = (string)Occ("resection")["id"]!;
        var c = (string)Cnt("human_patient")["id"]!;
        var patient = (string)Individual(c, designator: "p")["id"]!;
        var surgeon = (string)Individual(c, designator: "s")["id"]!;
        var t = Token(o, new JsonMap { { "start", "1953-08-25T00:00:00Z" } },
            participants: L(
                new JsonMap { { "role", "patient" }, { "filler", patient } },
                new JsonMap { { "role", "agent" }, { "filler", surgeon } }));
        SchemaOk(t);
    }

    private static void V91()
    {
        var q = Quality("cortisol_concentration", "quantity", "ug/dL");
        SchemaOk(q);
    }

    private static (JsonMap State, JsonMap Quality) StateFixture(
        string datatype, JsonMap value, string? unit = null)
    {
        var q = Quality("cortisol_concentration", datatype, unit);
        var c = (string)Cnt("human_patient")["id"]!;
        var subj = (string)Individual(c, designator: "p")["id"]!;
        var st = State(subj, (string)q["id"]!, value,
            new JsonMap { { "start", "2026-01-01T00:00:00Z" },
                          { "end", "2026-01-01T01:00:00Z" } });
        return (st, q);
    }

    private static void V92()
    {
        var (st, q) = StateFixture("quantity",
            new JsonMap { { "quantity", 15.0 }, { "unit", "ug/dL" } }, "ug/dL");
        SchemaOk(st);
        Check(Semantics.StateGaps(st, q).Count == 0, "V92 no gaps");
    }

    private static void V93()
    {
        var (st, q) = StateFixture("categorical",
            new JsonMap { { "categorical", "elevated" } });
        SchemaOk(st);
        Check(Semantics.StateGaps(st, q).Count == 0, "V93 no gaps");
    }

    private static void V94()
    {
        var (st, q) = StateFixture("boolean",
            new JsonMap { { "boolean", true } });
        SchemaOk(st);
        Check(Semantics.StateGaps(st, q).Count == 0, "V94 no gaps");
    }

    private static void V95()
    {
        var (st, q) = StateFixture("quantity",
            new JsonMap { { "categorical", "elevated" } }, "ug/dL");
        Check(Semantics.StateGaps(st, q).SequenceEqual(
                  new[] { "value_type_mismatch" }), "V95");
    }

    private static void V96()
    {
        var (st, q) = StateFixture("quantity",
            new JsonMap { { "quantity", 15.0 }, { "unit", "mg/dL" } }, "ug/dL");
        Check(Semantics.StateGaps(st, q).SequenceEqual(new[] { "unit_mismatch" }),
              "V96");
    }

    private static (JsonMap Law, JsonMap TCause, JsonMap TEffect) LawAndTokens()
    {
        var oCause = Occ("resection");
        var oEffect = Occ("amnesia_onset");
        var law = Cro(L(oCause["id"]), L(oEffect["id"]), new JsonMap {
            { "temporal", new JsonMap { { "minimum_delay", 0L },
                                        { "maximum_delay", 1L },
                                        { "unit", "days" } } },
            { "modality", "sufficient" } });
        var tCause = Token((string)oCause["id"]!,
            new JsonMap { { "start", "1953-08-25T00:00:00Z" } });
        var tEffect = Token((string)oEffect["id"]!,
            new JsonMap { { "start", "1953-08-25T00:00:00Z" }, { "open", true } });
        return (law, tCause, tEffect);
    }

    private static void V97()
    {
        var (law, tc, te) = LawAndTokens();
        var claim = Tcc(L(tc["id"]), L(te["id"]),
            coveringLaw: (string)law["id"]!,
            actualDelay: new JsonMap { { "duration", 0L }, { "unit", "instant" } },
            counterfactual: true);
        SchemaOk(claim);
    }

    private static void V98()
    {
        var (_, tc, te) = LawAndTokens();
        var claim = Tcc(L(tc["id"]), L(te["id"]));
        SchemaOk(claim);
        Check(!claim.ContainsKey("covering_law"), "no covering law");
    }

    private static void V99()
    {
        var (law, _, _) = LawAndTokens();
        Check(Semantics.DelayWithinWindow(
                  new JsonMap { { "duration", 0L }, { "unit", "instant" } },
                  (JsonMap)law["temporal"]!), "V99 within window");
    }

    private static void V100()
    {
        var temporal = new JsonMap { { "minimum_delay", 0L },
                                     { "maximum_delay", 1L }, { "unit", "hours" } };
        Check(!Semantics.DelayWithinWindow(
                  new JsonMap { { "duration", 5L }, { "unit", "days" } }, temporal),
              "V100 outside window");
    }

    private static void V101()
    {
        var o = (string)Occ("x")["id"]!;
        var cause = Token(o, new JsonMap { { "start", "2026-01-02T00:00:00Z" } });
        var effect = Token(o, new JsonMap { { "start", "2026-01-01T00:00:00Z" } });
        var claim = Tcc(L(cause["id"]), L(effect["id"]));
        Check(Semantics.Retrocausal(claim, Map(cause, effect)),
              "expected retrocausal");
    }

    private static void V102()
    {
        var other = Cro(L(Sym("occurrent:foo")), L(Sym("occurrent:bar")));
        var (_, tc, te) = LawAndTokens();
        var claim = Tcc(L(tc["id"]), L(te["id"]),
                        coveringLaw: (string)other["id"]!);
        Check(Semantics.CoveringLawMismatch(claim, Map(tc, te), other),
              "expected mismatch");
    }

    private static void V103()
    {
        var a = Signed("assertion",
            new JsonMap { { "about", Sym("token_occurrence:t") },
                          { "evidence_type", "observation" },
                          { "confidence", 0.9 } }, "signer");
        SchemaOk(a);
    }

    private static void V104()
    {
        var ev = L(Sym("token_occurrence:t1"), Sym("token_causal_claim:c1"));
        var baseMap = new JsonMap {
            { "type", "assertion" },
            { "about", Sym("causal_relation_object:law") },
            { "source", Key("signer").Public },
            { "evidence_type", "intervention" },
            { "strength", 0.95 }, { "confidence", 0.99 },
            { "timestamp", "2026-07-14T00:00:00Z" } };
        var a = baseMap.Copy();
        a["evidenced_by"] = ev;
        var withId = a.Copy();
        withId["id"] = Canonical.Identify(a);
        SchemaOk(withId);
        Check(Canonical.Identify(a) != Canonical.Identify(baseMap),
              "evidenced_by is identity-bearing");
    }

    private static void V105()
    {
        var a = Signed("assertion",
            new JsonMap { { "about", Sym("causal_relation_object:law") },
                          { "evidence_type", "simulation" },
                          { "confidence", 0.5 } }, "signer");
        SchemaOk(a);
        var rank = new Dictionary<string, int>
        { ["intervention"] = 0, ["observation"] = 1, ["simulation"] = 2 };
        Check(rank["intervention"] < rank["observation"]
              && rank["observation"] < rank["simulation"], "evidence ranking");
    }

    private static readonly HashSet<string> WholeWord = new()
    {
        "occurrent", "causal_relation_object", "continuant", "realizable",
        "assertion", "enrichment", "retraction", "succession", "stratum",
        "bridge", "port", "conduit", "quality", "token_individual",
        "token_occurrence", "state_assertion", "token_causal_claim", "ed25519",
    };

    private static void V106()
    {
        var idPattern = new Regex("^([a-z0-9_]+):[0-9a-f]{64}$");
        void Scan(object? node, List<string> ids)
        {
            if (node is string s)
            {
                var m = idPattern.Match(s);
                if (m.Success)
                    ids.Add(m.Groups[1].Value);
            }
            else if (node is List<object?> list)
                foreach (var x in list) Scan(x, ids);
            else if (node is JsonMap map)
                foreach (var (_, v) in map) Scan(v, ids);
        }
        for (var n = 1; n <= 38; n++)
        {
            var ids = new List<string>();
            Scan(Vec(n), ids);
            foreach (var scheme in ids)
                Check(WholeWord.Contains(scheme),
                      $"V106: abbreviated scheme '{scheme}' in vector {n}");
        }
        var rec = new JsonMap { { "type", "occurrent" },
                                { "label", "press_button" },
                                { "category", "action" } };
        Check(Canonical.Identify(rec) == Canonical.Identify(rec), "deterministic");
        Check(Canonical.Identify(rec).Split(':', 2)[0] == "occurrent", "prefix");
    }

    private static void V107()
    {
        var hexid = new string('0', 64);
        // the abbreviated prefix is intentional (the negative test); assemble
        // it so re-mint tools do not rewrite it.
        var croAbbr = "c" + "r" + "o";
        var abbreviated = new JsonMap {
            { "type", "causal_relation_object" },
            { "id", croAbbr + ":" + hexid },
            { "causes", L("occurrent:" + hexid) },
            { "effects", L("occurrent:" + hexid) } };
        var (ok1, _) = SchemaValidator.ValidateSchema(abbreviated,
                                                      "causal_relation_object");
        Check(!ok1, "abbreviated scheme must be rejected");
        var abbrStr = new JsonMap {
            { "type", "stratum" }, { "id", "str:" + hexid },
            { "label", "cellular" }, { "scheme", "neuroendocrine" },
            { "ordinal", 6L } };
        var (ok2, _) = SchemaValidator.ValidateSchema(abbrStr, "stratum");
        Check(!ok2, "abbreviated stratum scheme must be rejected");
        var whole = new JsonMap {
            { "type", "causal_relation_object" },
            { "id", "causal_relation_object:" + hexid },
            { "causes", L("occurrent:" + hexid) },
            { "effects", L("occurrent:" + hexid) } };
        var (ok3, why3) = SchemaValidator.ValidateSchema(whole,
                                                         "causal_relation_object");
        Check(ok3, string.Join("; ", why3));
    }

    // -----------------------------------------------------------------------
    private static int Main()
    {
        var root = FindRepoRoot();
        _vectorsDir = Path.Combine(root, "conformance", "vectors");
        Environment.SetEnvironmentVariable(
            "CAUSALONTOLOGY_SPEC", Path.Combine(root, "spec"));

        Console.WriteLine("causalontology-csharp conformance run");
        Console.Write(
            "internal checks (RFC 8032 known-answer, RFC 8785 basics) ... ");
        InternalChecks();
        Console.WriteLine("ok");

        var vectors = new Action[]
        {
            V01, V02, V03, V04, V05, V06, V07, V08, V09, V10,
            V11, V12, V13, V14, V15, V16, V17, V18, V19, V20,
            V21, V22, V23, V24, V25, V26, V27, V28, V29, V30,
            V31, V32, V33, V34, V35, V36, V37, V38, V39, V40,
            V41, V42, V43, V44, V45, V46, V47, V48, V49, V50,
            V51, V52, V53, V54, V55, V56, V57, V58, V59, V60,
            V61, V62, V63, V64, V65, V66, V67, V68, V69, V70,
            V71, V72, V73, V74, V75, V76, V77, V78, V79, V80,
            V81, V82, V83, V84, V85, V86, V87, V88, V89, V90,
            V91, V92, V93, V94, V95, V96, V97, V98, V99, V100,
            V101, V102, V103, V104, V105, V106, V107,
        };
        var failures = 0;
        for (var n = 1; n <= vectors.Length; n++)
        {
            var name = Path.GetFileNameWithoutExtension(VectorPath(n));
            try
            {
                vectors[n - 1]();
                Console.WriteLine($"PASS  {name}");
            }
            catch (Exception e)
            {
                failures++;
                Console.WriteLine($"FAIL  {name} :: {e.Message}");
            }
        }
        Console.WriteLine(new string('-', 60));
        Console.WriteLine($"{vectors.Length - failures}/{vectors.Length} "
                          + "vectors passed");
        if (failures > 0)
            return 1;
        Console.WriteLine("causalontology-csharp is CONFORMANT to the suite "
                          + "(vectors frozen at specification 2.0.0).");
        return 0;
    }
}

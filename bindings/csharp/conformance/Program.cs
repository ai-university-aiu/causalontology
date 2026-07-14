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

    // recognizes the identifier schemes the vectors use
    private static readonly Regex SymbolicPrefix =
        new("^(occ|cro|cnt|rlz|ast|enr|ret|suc|ed25519):");

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
        SemanticsFails(14, "dmin");
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
        var dog = Sym("cnt:dog");
        var mammal = Sym("cnt:mammal");
        var animal = Sym("cnt:animal");
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
            { "causes", new List<object?> { Sym("occ:c") } },
            { "effects", new List<object?> { Sym("occ:e") } },
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
            { "type", "cro" },
            { "causes", new List<object?> { Sym("occ:A") } },
            { "effects", new List<object?> { Sym("occ:B") } },
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
            new JsonMap { { "about", Sym("cro:demo") },
                          { "evidence_type", "intervention" },
                          { "strength", 0.7 },
                          { "confidence", 0.9 } },
            "signer");
        Check(Signing.VerifyRecord(record), "signature must verify");
    }

    private static void V30()
    {
        var record = Signed("assertion",
            new JsonMap { { "about", Sym("cro:demo") },
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
            { "type", "cro" },
            { "causes", new List<object?> { Sym("occ:A") } },
            { "effects", new List<object?> { Sym("occ:B") } },
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
            new JsonMap { { "about", Sym("cro:claim") },
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
        Check(store.AssertionsAbout(Sym("cro:claim")).Count == 0,
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
        var (a, b, c, d) = (Sym("occ:A"), Sym("occ:B"), Sym("occ:C"),
                            Sym("occ:D"));
        JsonMap Member(string id, string cause, string effect) => new()
        {
            { "id", id },
            { "causes", new List<object?> { cause } },
            { "effects", new List<object?> { effect } },
        };
        var m1 = Member(Sym("cro:m1"), a, b);
        var m2 = Member(Sym("cro:m2"), b, c);
        var m3 = Member(Sym("cro:m3"), d, c);
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
            { "type", "cro" },
            { "causes", new List<object?> { Sym("occ:A") } },
            { "effects", new List<object?> { Sym("occ:B") } },
        });
        var gaps = store.Gaps("missing_field")
            .Select(g => (string)g["id"]!).ToList();
        Check(gaps.Contains(parent), "the degenerate claim is a gap");
        var refinement = store.Put(new JsonMap
        {
            { "type", "cro" },
            { "causes", new List<object?> { Sym("occ:A") } },
            { "effects", new List<object?> { Sym("occ:B") } },
            { "temporal", new JsonMap { { "dmin", 0L }, { "dmax", 1L },
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
            V31, V32, V33, V34, V35, V36, V37, V38,
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
                          + "(vectors frozen at specification 1.0.0).");
        return 0;
    }
}

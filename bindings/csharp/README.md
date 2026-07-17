# causalontology-csharp

**The C# binding of the Causalontology standard** — a faithful port of
[causalontology-py](../python/), sharing the same conformance suite.

**Zero runtime dependencies.** The .NET base class library carries
SHA-256 and SHA-512 (`System.Security.Cryptography`); Ed25519 is not in
the BCL, so it is hand-ported from the Python binding onto
`System.Numerics.BigInteger` and gated on the RFC 8032 TEST 1 known
answer before any vector runs. Requires the **.NET 8 SDK** or newer.

| Source file | Implements |
|---|---|
| `Causalontology/Json.cs` | a lossless JavaScript Object Notation (JSON) layer: a small recursive-descent parser whose numbers keep their source literal (no `.`, `e`, or `E` → `long`; otherwise `double`), and a `JsonMap` object type with an explicit key insertion-order list — we do not rely on `Dictionary`'s de-facto ordering |
| `Causalontology/Jcs.cs` | RFC 8785 (JSON Canonicalization Scheme) serialization: keys sorted by UTF-16 code units (`String.CompareOrdinal`), minimal string escapes with lowercase `\u00xx` for controls, ECMAScript-style canonical numbers (`1.0` → `1`, `0.7` stays `0.7`, `e-7` not `e-07`) |
| `Causalontology/Canonical.cs` | identity-bearing field filtering per kind and Secure Hash Algorithm 256-bit (SHA-256) content-addressed `Identify()` (spec/identity.md) |
| `Causalontology/Ed25519.cs` | Ed25519 (RFC 8032) in pure C# over `System.Numerics.BigInteger`; every field reduction is normalized with `((a % p) + p) % p` because C#'s `%` can return negatives |
| `Causalontology/Signing.cs` | record-level `SignRecord()` / `VerifyRecord()` over canonical identity-bearing bytes (spec/provenance.md); a succession verifies against its predecessor key |
| `Causalontology/SchemaValidator.cs` | validation against the seventeen JSON Schemas in `spec/schema/` (a small interpreter for exactly the keywords those schemas use) |
| `Causalontology/Semantics.cs` | the 21 semantic rules: temporal admissibility with the fixed unit constants (month = 2,629,746 s; year = 31,556,952 s), the formal conflict test, refinement validity, bridged reachability, stratal classification, the skip decision, enrichment field/shape rules, and the token-tier coherence checks |
| `Causalontology/Store.cs` | an in-memory conformant store: idempotent immutable puts, signed add-only records with quarantine, materialized enrichment views with contributors, retraction and succession lineage, the resolve minimum, the deterministic cycle-breaking view rule, and the stigmergy `Gaps()` read |
| `conformance/Program.cs` | the conformance runner: internal known-answer checks (RFC 8032 TEST 1, RFC 8785 basics), then all 107 vectors, mirroring `bindings/python/tests/run_conformance.py` exactly |

## Conformance

```
$ dotnet run --project bindings/csharp/conformance
...
107/107 vectors passed
causalontology-csharp is CONFORMANT to the suite (vectors frozen at specification 2.0.0).
```

The runner locates the repository root from the `CAUSALONTOLOGY_ROOT`
environment variable when set, otherwise by walking up from the working
directory until it finds `conformance/vectors`; the schemas are read from
`spec/schema` under the same root (overridable with `CAUSALONTOLOGY_SPEC`).

The vectors are frozen at specification 2.0.0 (2026-07-13): they carry concrete identifiers, real keys, and a real verifying signature. The harness's old normalization now simply passes frozen values through.

## Thirty-second taste

```csharp
using Causalontology;

var store = new InMemoryStore();
var press = store.Put(new JsonMap {
    { "type", "occurrent" }, { "label", "press_button" }, { "category", "action" } });
var light = store.Put(new JsonMap {
    { "type", "occurrent" }, { "label", "light_on" }, { "category", "state_change" } });
var claim = store.Put(new JsonMap {
    { "type", "causal_relation_object" },
    { "causes", new List<object?> { press } },
    { "effects", new List<object?> { light } } });

Console.WriteLine(claim);
Console.WriteLine(store.Gaps("missing_field").Count); // the degenerate claim is a visible invitation
```

## Status

Source complete and ported line-for-line from the Python binding;
verified locally with the .NET 8 SDK — `dotnet run --project
bindings/csharp/conformance` prints `107/107 vectors passed` — and built
and executed by GitHub Actions CI as well, as it is for every binding.

License: "The attribution always; no profit, no problem license." — see
the repository `LICENSE` and `NOTICE`.

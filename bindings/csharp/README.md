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
| `Causalontology/SchemaValidator.cs` | validation against the twenty-one JSON Schemas (a small interpreter for exactly the keywords those schemas use), read from `CAUSALONTOLOGY_SPEC`, else the vendored copy that travels inside the package, else the repository's `spec/schema/` |
| `spec_schema/` | the vendored copy of `spec/schema/*.schema.json`, compiled into `Causalontology.dll` as embedded resources and packed into the `.nupkg`, so an installed package validates with no repository present |
| `Causalontology/Semantics.cs` | the 25 semantic rules: temporal admissibility with the fixed unit constants (month = 2,629,746 s; year = 31,556,952 s) and the dimension-disjoint ordinal tick unit, the formal conflict test, refinement validity, bridged reachability, stratal classification, the skip decision, cross-stratal seam well-formedness with the coarsest-stratum home rule, enrichment field/shape rules, and the token-tier coherence checks including the prediction-to-observation pairing |
| `Causalontology/Store.cs` | an in-memory conformant store: idempotent immutable puts, signed add-only records with quarantine, materialized enrichment views with contributors, retraction and succession lineage, the resolve minimum, the deterministic cycle-breaking view rule, and the stigmergy `Gaps()` read |
| `conformance/Program.cs` | the conformance runner: internal known-answer checks (RFC 8032 TEST 1, RFC 8785 basics), then all 137 vectors, mirroring `bindings/python/tests/run_conformance.py` exactly |

## Conformance

```
$ dotnet run --project bindings/csharp/conformance
...
137/137 vectors passed
causalontology-csharp is CONFORMANT to the suite (vectors frozen at specification 4.0.0).
```

The runner locates the repository root from the `CAUSALONTOLOGY_ROOT`
environment variable when set, otherwise by walking up from the working
directory until it finds `conformance/vectors`, otherwise from the source
directory baked into the build; the schemas are read from `spec/schema`
under the same root (overridable with `CAUSALONTOLOGY_SPEC`).

Whenever both `spec/schema/` and `spec_schema/` are reachable the runner
compares them byte for byte and exits with `bundled schema drift` on any
difference, so the vendored copy can never go stale.

### Testing an installed package, not the repository

By default the runner is built against the repository sources
(`ProjectReference`). With `CAUSALONTOLOGY_TEST_INSTALLED` set it is built
against the published NuGet package instead (`PackageReference`), it does
not set `CAUSALONTOLOGY_SPEC` for itself, it prints `binding under test:`
with the resolved assembly path, and it refuses to run if either that
assembly or the schemas it loads come from inside the repository tree:

```
$ dotnet pack bindings/csharp/Causalontology -c Release -o /tmp/feed
$ CAUSALONTOLOGY_TEST_INSTALLED=1 dotnet restore bindings/csharp/conformance -s /tmp/feed
$ CAUSALONTOLOGY_TEST_INSTALLED=1 dotnet build bindings/csharp/conformance \
      -c Release --no-restore -o /tmp/installed
$ cd /tmp && env -u CAUSALONTOLOGY_SPEC CAUSALONTOLOGY_TEST_INSTALLED=1 \
      dotnet /tmp/installed/conformance.dll
binding under test: /tmp/installed/Causalontology.dll
schema source: bundled:/tmp/installed/spec_schema
...
137/137 vectors passed
```

The vectors are frozen at specification 4.0.0 (2026-07-22; 137 vectors, V01–V137): they carry concrete identifiers, real keys, and a real verifying signature. The harness's old normalization now simply passes frozen values through.

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
bindings/csharp/conformance` prints `137/137 vectors passed` — and built
and executed by GitHub Actions CI as well, as it is for every binding.

License: "The attribution always; no profit, no problem license." — see
the repository `LICENSE` and `NOTICE`.

# causalontology-julia

**The Julia binding of the Causalontology standard** — a faithful port of
[causalontology-py](../python/), sharing the same conformance suite.

**Standard library only.** The `SHA` standard library (which ships with
Julia) carries SHA-256 and SHA-512; everything else is implemented here:
an own order-preserving JSON parser (no JSON.jl), and a pure-Julia Ed25519
(RFC 8032) over native `BigInt` (no crypto packages). The `Project.toml`
lists only the `SHA` stdlib. Requires **Julia 1.6 or newer** (CI runs
1.10).

| Source file | Implements |
|---|---|
| `src/json.jl` | a lossless, order-preserving JSON layer: objects are association vectors (`JObj` over `Vector{Pair{String,Any}}`) because Julia's `Dict` is unordered, and numbers keep their source literal distinction (a literal without `[.eE]` parses to `Int64`, otherwise `Float64`), so `1` versus `1.0` survives to the canonicalizer |
| `src/jcs.jl` | RFC 8785 (JSON Canonicalization Scheme) serialization: sorted keys, minimal string escaping (only bytes below 0x20), ECMAScript-style canonical numbers (`1.0` → `1`, `0.7` stays `0.7`, `1.0e-7` → `1e-7`, not `e-07`) |
| `src/canonical.jl` | identity-bearing field filtering per kind and SHA-256 content-addressed `identify` (spec/identity.md) |
| `src/ed25519.jl` | pure-Julia Ed25519 (RFC 8032) over native `BigInt` with `mod`/`powermod` (floored, non-negative remainders, matching Python's `%`), verified against the RFC's TEST 1 known answer before any vector runs |
| `src/signing.jl` | record-level `sign_record` / `verify_record` over canonical identity-bearing bytes (spec/provenance.md); a succession verifies against its predecessor key |
| `src/schema.jl` | validation against the eight JSON Schemas in `spec/schema/` (a small interpreter for exactly the keywords those schemas use) |
| `src/semantics.jl` | the 13 semantic rules: temporal admissibility with the fixed unit constants (month = 2,629,746 s, year = 31,556,952 s), the formal conflict test, refinement validity, hierarchy reachability, enrichment field/shape rules |
| `src/store.jl` | an in-memory conformant store: idempotent immutable puts, signed add-only records with quarantine, materialized enrichment views with contributors, retraction and succession lineage, the resolve minimum, the deterministic cycle-breaking view rule, and the stigmergy `gaps` read — with explicit insertion-order bookkeeping (`object_order`, `record_order`), since Julia's `Dict` iterates in arbitrary order where Python's dict does not |
| `conformance.jl` | the conformance runner: internal known-answer checks (RFC 8032 TEST 1, RFC 8785 basics), then all 38 vectors, mirroring `bindings/python/tests/run_conformance.py` exactly |

## Conformance

```
$ julia bindings/julia/conformance.jl
...
38/38 vectors passed
causalontology-julia is CONFORMANT to the suite (vectors frozen at specification 1.0.0).
```

Verified locally (38/38, exit 0) and run in CI by the `julia` job of
`.github/workflows/conformance.yml` on Julia 1.10. The runner locates the
repository root relative to its own location inside `bindings/julia/`; the
schemas are read from `spec/schema` under the same root (overridable with
`CAUSALONTOLOGY_SPEC`, which names the `spec/` directory).

The vectors are frozen at specification 1.0.0 (2026-07-13): they carry
concrete identifiers, real keys, and a real verifying signature. The
harness's old normalization now simply passes frozen values through, and
the behavioral vectors derive deterministic keypairs from the seed
`sha256("key:" + name)`.

## Thirty-second taste

```julia
include("bindings/julia/src/Causalontology.jl")
using .Causalontology

s = InMemoryStore()
press = put(s, jobj("type" => "occurrent", "label" => "press_button",
                    "category" => "action"))
light = put(s, jobj("type" => "occurrent", "label" => "light_on",
                    "category" => "state"))
claim = put(s, jobj("type" => "causal_relation_object", "causes" => Any[press],
                    "effects" => Any[light]))
println(gaps(s; kind="missing_field"))  # the partial claim is a visible gap
```

## Registration

Registration in Julia's General registry is a pull-request process: a
release is registered by opening a pull request against
`JuliaRegistries/General` (normally via the Registrator bot), and the
package becomes installable by name (`pkg> add Causalontology`) only after
that pull request is merged. This binding is not yet registered; until
then, use it by `include`-ing `src/Causalontology.jl` as above, or by
`pkg> dev bindings/julia`.

## License

Apache License 2.0, the same terms as the repository root (see `LICENSE`).

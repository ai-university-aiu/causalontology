# causalontology-elixir

**The Elixir binding of the Causalontology standard** — a faithful port of
[causalontology-py](../python/), sharing the same conformance suite.

**Zero Hex dependencies.** OTP's `:crypto` application carries everything the
standard needs: Secure Hash Algorithm 256-bit (SHA-256) and Ed25519 (RFC 8032 signing and verification, with
deterministic key derivation from a 32-byte seed via
`:crypto.generate_key(:eddsa, :ed25519, seed)`). Everything else — including
the JavaScript Object Notation (JSON) layer — is hand-written from the specification. Requires
**Elixir 1.16 / OTP 26** (CI's pinned toolchain; anything newer works too).

| Source file | Implements |
|---|---|
| `lib/causalontology/json.ex` | a shape-preserving JSON parser (own recursive descent, no JSON library): the integer-versus-decimal source distinction survives to the canonicalizer because `1` parses to the Elixir integer `1` and `1.0` to the Elixir float `1.0` — distinct types |
| `lib/causalontology/jcs.ex` | RFC 8785 (JSON Canonicalization Scheme) serialization: sorted keys, minimal string escaping, ECMAScript-style canonical numbers (`1.0` → `1`, `0.7` stays `0.7`, `e-7` not `e-07`) |
| `lib/causalontology/canonical.ex` | identity-bearing field filtering per kind and SHA-256 content-addressed `identify/2` (spec/identity.md) |
| `lib/causalontology/signing.ex` | record-level `sign_record/3` / `verify_record/2` over canonical identity-bearing bytes (spec/provenance.md); a succession verifies against its predecessor key |
| `lib/causalontology/schema.ex` | validation against the twenty-one JSON Schemas in `spec/schema/` (a small interpreter for exactly the keywords those schemas use) |
| `lib/causalontology/semantics.ex` | the semantic rules: temporal admissibility with the fixed unit constants and the ordinal `ticks` dimension, the formal conflict test, refinement validity, bridged reachability, stratal classification, the skip decision, cross-stratal-seam well-formedness and the home rule, enrichment field/shape rules, the token-tier coherence checks, the predicted-interval dimension check, and the prediction-to-observation pairing |
| `lib/causalontology/store.ex` | an in-memory conformant store: idempotent immutable puts, signed add-only records with quarantine, materialized enrichment views with contributors, retraction and succession lineage, the resolve minimum, the deterministic cycle-breaking view rule, and the stigmergy `gaps/2` read — immutable-functional (`{:ok, store, id}` tuples thread the store through), with explicit insertion-order bookkeeping, since Elixir maps are unordered where Python dicts are not |
| `conformance.exs` | the conformance runner: internal known-answer checks (RFC 8032 TEST 1, RFC 8785 basics), then all 137 vectors, mirroring `bindings/python/tests/run_conformance.py` exactly; a standalone script that `Code.require_file`'s the lib modules, so no mix compile is needed |

## Conformance

```
$ cd bindings/elixir
$ elixir conformance.exs
...
137/137 vectors passed
causalontology-elixir is CONFORMANT to the suite (vectors frozen at specification 4.0.0).
```

The runner locates the repository root from the `CAUSALONTOLOGY_ROOT`
environment variable when set, otherwise from its own source location inside
`bindings/elixir/`; the schemas are read from `spec/schema` under the same
root (overridable with `CAUSALONTOLOGY_SPEC`, naming the `spec/` directory).

The V01-V107 vectors are the whole-word 2.0.0 baseline (2026-07-13): they carry
concrete identifiers, real keys, and a real verifying signature, and the
harness's normalization now simply passes those frozen values through. The
V108-V119 (3.0.0: the `ticks` unit, the cross_stratal_seam, the conduit
`realized_by`) and V120-V137 (4.0.0: the attitude, the predicted_occurrence,
the prediction_error) fixtures are built in the runner, mirroring the Python
reference exactly.

## Thirty-second taste

```elixir
alias Causalontology.Store

store = Store.new()

{:ok, store, press} =
  Store.put(store, %{"type" => "occurrent", "label" => "press_button", "category" => "action"})

{:ok, store, light} =
  Store.put(store, %{"type" => "occurrent", "label" => "light_on", "category" => "state_change"})

{:ok, store, claim} =
  Store.put(store, %{"type" => "causal_relation_object", "causes" => [press], "effects" => [light]})

# The degenerate claim is a visible invitation.
IO.inspect({claim, Store.gaps(store, "missing_field")})
```

## Status

Source complete and ported line-for-line from the Python binding; built and
executed by GitHub Actions CI (`cd bindings/elixir && elixir conformance.exs`,
on erlef/setup-beam with OTP 26 and Elixir 1.16) — there is no BEAM toolchain
on the authoring machine, so CI is the gate, as it is for every binding.

License: "The attribution always; no profit, no problem license." — see the
repository `LICENSE` and `NOTICE`.

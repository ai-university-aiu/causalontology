# causalontology-ruby

**The Ruby binding of the Causalontology standard** — a faithful port of
[causalontology-py](../python/), sharing the same conformance suite.

**Zero gems.** The Ruby standard library carries everything the standard
needs: `json` (whose parser keeps the integer-versus-decimal source
distinction — `1` parses to `Integer`, `1.0` to `Float` — so it survives to
the canonicalizer), `digest` (SHA-256 and SHA-512), and Ruby's native
bignums with three-argument `Integer#pow` for the pure-Ruby Ed25519.
Requires **Ruby 3.0 or newer** (CI runs 3.3).

| Source file | Implements |
|---|---|
| `lib/causalontology/jcs.rb` | RFC 8785 (JSON Canonicalization Scheme) serialization: sorted keys, minimal string escaping, ECMAScript-style canonical numbers (`1.0` → `1`, `0.7` stays `0.7`, `e-7` not `e-07`) |
| `lib/causalontology/canonical.rb` | identity-bearing field filtering per kind and SHA-256 content-addressed `identify` (spec/identity.md) |
| `lib/causalontology/ed25519.rb` | pure-Ruby Ed25519 (RFC 8032) over native bignums, verified against the RFC's TEST 1 known answer before any vector runs |
| `lib/causalontology/signing.rb` | record-level `sign_record` / `verify_record` over canonical identity-bearing bytes (spec/provenance.md); a succession verifies against its predecessor key |
| `lib/causalontology/schema.rb` | validation against the eight JSON Schemas in `spec/schema/` (a small interpreter for exactly the keywords those schemas use) |
| `lib/causalontology/semantics.rb` | the 13 semantic rules: temporal admissibility with the fixed unit constants, the formal conflict test, refinement validity, hierarchy reachability, enrichment field/shape rules |
| `lib/causalontology/store.rb` | an in-memory conformant store: idempotent immutable puts, signed add-only records with quarantine, materialized enrichment views with contributors, retraction and succession lineage, the resolve minimum, the deterministic cycle-breaking view rule, and the stigmergy `gaps` read — Ruby Hashes preserve insertion order, and the iteration order deliberately mirrors the reference store's |
| `conformance.rb` | the conformance runner: internal known-answer checks (RFC 8032 TEST 1, RFC 8785 basics), then all 38 vectors, mirroring `bindings/python/tests/run_conformance.py` exactly |

## Conformance

```
$ ruby bindings/ruby/conformance.rb
...
38/38 vectors passed
causalontology-ruby is CONFORMANT to the suite (vectors frozen at specification 1.0.0).
```

The runner locates the repository root from the `CAUSALONTOLOGY_ROOT`
environment variable when set, otherwise from its own location inside
`bindings/ruby/`; the schemas are read from `spec/schema` under the same
root (overridable with `CAUSALONTOLOGY_SPEC`, which names the `spec/`
directory).

The vectors are frozen at specification 1.0.0 (2026-07-13): they carry
concrete identifiers, real keys, and a real verifying signature. The
harness's old normalization now simply passes frozen values through.

## Thirty-second taste

```ruby
require_relative "lib/causalontology"

store = Causalontology::InMemoryStore.new
press = store.put({ "type" => "occurrent", "label" => "press_button",
                    "category" => "action" })
light = store.put({ "type" => "occurrent", "label" => "light_on",
                    "category" => "state_change" })
claim = store.put({ "type" => "cro", "causes" => [press],
                    "effects" => [light] })

p store.gaps("missing_field")   # the degenerate claim is a visible invitation

sk, source = Causalontology.keypair_from_seed(Digest::SHA256.digest("alice"))
store.put_record(Causalontology.sign_record(
  { "type" => "assertion", "about" => claim, "source" => source,
    "evidence_type" => "imported", "confidence" => 0.5,
    "timestamp" => "2026-07-13T00:00:00Z" }, sk))
```

## Status

Source complete and ported line-for-line from the Python binding; built and
executed by GitHub Actions CI (`ruby bindings/ruby/conformance.rb` on
Ruby 3.3 via ruby/setup-ruby) — there is no Ruby interpreter on the
authoring machine, so CI is the gate, as it is for every binding.

License: "The attribution always; no profit, no problem license." — see the
repository `LICENSE` and `NOTICE`.

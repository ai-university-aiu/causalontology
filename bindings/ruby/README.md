# causalontology-ruby

**The Ruby binding of the Causalontology standard** — a faithful port of
[causalontology-py](../python/), sharing the same conformance suite.

**Zero gems.** The Ruby standard library carries everything the standard
needs: `json` (whose parser keeps the integer-versus-decimal source
distinction — `1` parses to `Integer`, `1.0` to `Float` — so it survives to
the canonicalizer), `digest` (Secure Hash Algorithm 256-bit (SHA-256) and SHA-512), and Ruby's native
bignums with three-argument `Integer#pow` for the pure-Ruby Ed25519.
Requires **Ruby 3.0 or newer** (CI runs 3.3).

| Source file | Implements |
|---|---|
| `lib/causalontology/jcs.rb` | RFC 8785 (JSON Canonicalization Scheme) serialization: sorted keys, minimal string escaping, ECMAScript-style canonical numbers (`1.0` → `1`, `0.7` stays `0.7`, `e-7` not `e-07`) |
| `lib/causalontology/canonical.rb` | identity-bearing field filtering per kind and SHA-256 content-addressed `identify` (spec/identity.md) |
| `lib/causalontology/ed25519.rb` | pure-Ruby Ed25519 (RFC 8032) over native bignums, verified against the RFC's TEST 1 known answer before any vector runs |
| `lib/causalontology/signing.rb` | record-level `sign_record` / `verify_record` over canonical identity-bearing bytes (spec/provenance.md); a succession verifies against its predecessor key |
| `lib/causalontology/schema.rb` | validation against the twenty-one JSON Schemas vendored at `lib/causalontology/spec/schema/`, a byte-for-byte copy of `spec/schema/` that ships inside the gem (a small interpreter for exactly the keywords those schemas use) |
| `lib/causalontology/semantics.rb` | the semantic rules: temporal admissibility with the fixed unit constants (months 2629746 s, years 31556952 s) and the ordinal `ticks` dimension, the formal conflict test, refinement validity, bridged reachability, stratal classification, the skip decision, cross-stratal-seam well-formedness and the home rule, enrichment field/shape rules, the token-tier coherence checks, the predicted-interval dimension check, and the prediction-to-observation pairing |
| `lib/causalontology/store.rb` | an in-memory conformant store: idempotent immutable puts, signed add-only records with quarantine, materialized enrichment views with contributors, retraction and succession lineage, the resolve minimum, the deterministic cycle-breaking view rule, and the stigmergy `gaps` read — Ruby Hashes preserve insertion order, and the iteration order deliberately mirrors the reference store's |
| `conformance.rb` | the conformance runner: internal known-answer checks (RFC 8032 TEST 1, RFC 8785 basics), then all 137 vectors, mirroring `bindings/python/tests/run_conformance.py` exactly |

## Conformance

```
$ ruby bindings/ruby/conformance.rb
...
137/137 vectors passed
causalontology-ruby is CONFORMANT to the suite (vectors frozen at specification 4.0.0).
```

The runner locates the vectors from the `CAUSALONTOLOGY_ROOT` environment
variable when set, otherwise from its own location inside `bindings/ruby/`.

The schemas are resolved in strict precedence:

1. `$CAUSALONTOLOGY_SPEC/schema`, when that variable is set (it names the
   `spec/` directory, not the `schema/` directory);
2. the copy vendored at `lib/causalontology/spec/schema`, which travels
   inside the gem and is what an installed consumer validates against;
3. the repository-relative `spec/schema`, a last resort for a checkout in
   which the vendored copy has not been made yet.

Before running the vectors, the runner checks the vendored copy byte-for-byte
against `spec/schema` and aborts on any drift, so the published gem can never
quietly enforce a different standard than the repository states.

### Testing the installed gem rather than the working tree

By default the runner loads the working tree next to it. Set
`CAUSALONTOLOGY_TEST_INSTALLED=1` and it instead loads the binding the way a
real consumer does, through a plain `require "causalontology"` resolved by
RubyGems; it prints the path it actually loaded and aborts if that path lies
inside the repository. Without that refusal a "fresh install" check silently
exercises repository source through a relative path and reports a false pass.

```
$ cd bindings/ruby                       # RubyGems resolves manifest paths
$ gem build causalontology.gemspec -o /tmp/causalontology-4.0.0.gem
                                         # against the working directory
$ gem install --install-dir /tmp/gemhome --no-document --local \
    /tmp/causalontology-4.0.0.gem
$ cd /tmp && env -u CAUSALONTOLOGY_SPEC GEM_HOME=/tmp/gemhome GEM_PATH=/tmp/gemhome \
    CAUSALONTOLOGY_TEST_INSTALLED=1 CAUSALONTOLOGY_ROOT=/path/to/causalontology \
    ruby /tmp/gemhome/gems/causalontology-4.0.0/conformance.rb
binding under test: /tmp/gemhome/gems/causalontology-4.0.0/lib/causalontology.rb
...
137/137 vectors passed
```

The gemspec itself refuses to build if the vendored schemas are absent,
incomplete, or byte-different from `spec/schema`, so a gem that cannot
validate can never be produced in the first place.

The V01–V107 vectors are the whole-word 2.0.0 baseline (2026-07-13): they
carry concrete identifiers, real keys, and a real verifying signature, and
the harness's normalization now simply passes those frozen values through.
The V108–V119 (3.0.0: the `ticks` unit, the cross_stratal_seam, the conduit
`realized_by`) and V120–V137 (4.0.0: the attitude, the predicted_occurrence,
the prediction_error) fixtures are built in the runner, mirroring the Python
reference exactly. Twenty-one object kinds; 137 vectors, frozen at
specification 4.0.0 (2026-07-22).

## Thirty-second taste

```ruby
require_relative "lib/causalontology"

store = Causalontology::InMemoryStore.new
press = store.put({ "type" => "occurrent", "label" => "press_button",
                    "category" => "action" })
light = store.put({ "type" => "occurrent", "label" => "light_on",
                    "category" => "state_change" })
claim = store.put({ "type" => "causal_relation_object", "causes" => [press],
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

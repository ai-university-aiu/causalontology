# causalontology-php

**The PHP binding of the Causalontology standard** — a faithful port of
[causalontology-py](../python/), sharing the same conformance suite.

**Zero Composer dependencies.** The extensions bundled with every stock PHP
build carry everything the standard needs: `ext-sodium` (Ed25519 per
RFC 8032 — deterministic signatures, seed-derived keypairs), `ext-hash`
(Secure Hash Algorithm 256-bit (SHA-256)), and `ext-json`. Requires **PHP 8.2 or newer** (CI runs 8.3).

| Source file | Implements |
|---|---|
| `src/Jcs.php` | RFC 8785 (JSON Canonicalization Scheme) serialization: bytewise key ordering (equals UTF-16 code-unit order for ASCII keys), minimal string escapes, ECMAScript-style canonical numbers (`1.0` → `1`, `0.7` stays `0.7`, `e-7` not `e-07`) |
| `src/Canonical.php` | identity-bearing field filtering per kind and SHA-256 content-addressed `identify()` (spec/identity.md) |
| `src/Signing.php` | record-level `signRecord()` / `verifyRecord()` over canonical identity-bearing bytes (spec/provenance.md); a succession verifies against its predecessor key; Ed25519 via libsodium, gated on the RFC 8032 TEST 1 known answer |
| `src/SchemaValidator.php` | validation against the twenty-one JSON Schemas in `spec/schema/` (a small interpreter for exactly the keywords those schemas use) |
| `src/Semantics.php` | the semantic rules: temporal admissibility with the fixed unit constants and the ordinal `ticks` dimension, the formal conflict test, refinement validity, bridged reachability, stratal classification, the skip decision, cross-stratal-seam well-formedness and the home rule, enrichment field/shape rules, the token-tier coherence checks, the predicted-interval dimension check (Rule 24), and the prediction-to-observation pairing |
| `src/Store.php` | an in-memory conformant store (the Python binding's `InMemoryStore`): idempotent immutable puts, signed add-only records with quarantine, materialized enrichment views with contributors, retraction and succession lineage, the resolve minimum, the deterministic cycle-breaking view rule, and the stigmergy `gaps()` read |
| `src/RejectedWrite.php` | the exception an enforcing store raises when it refuses a write |
| `src/Causalontology.php` | the facade holding the declared specification version |
| `conformance.php` | the conformance runner: internal known-answer checks (RFC 8032 TEST 1, RFC 8785 basics), then all 137 vectors, mirroring `bindings/python/tests/run_conformance.py` exactly |

## Conformance

```
$ php bindings/php/conformance.php
...
137/137 vectors passed
causalontology-php is CONFORMANT to the suite (vectors frozen at specification 4.0.0).
```

The runner reads the vectors from `../../conformance/vectors` and the
schemas from `../../spec/schema` relative to its own location; the schema
location can be overridden with the environment variable
`CAUSALONTOLOGY_SPEC` (naming the `spec/` directory).

The V01-V107 vectors are the whole-word 2.0.0 baseline (2026-07-13): they
carry concrete identifiers, real keys, and a real verifying signature, and
the harness's normalization now simply passes those frozen values through.
The V108-V119 (3.0.0: the `ticks` unit, the cross_stratal_seam, the conduit
`realized_by`) and V120-V137 (4.0.0: the attitude, the predicted_occurrence,
the prediction_error) fixtures are built in the runner, mirroring the Python
reference exactly.

## PHP-specific decisions

- **Integer versus decimal survives decoding.** `json_decode(..., true)`
  keeps the source literal's distinction (`1` decodes to `int`, `1.0` to
  `float`), which is exactly what the canonical number rule needs — no
  lossless-number shim is required, unlike the Go and Java bindings.
- **PHP arrays are ordered maps.** Insertion order is preserved, so the
  store matches the Python binding's `dict` semantics with no extra
  bookkeeping; JavaScript Object Notation (JSON) object keys are cast back to `string` wherever they are
  iterated, because PHP silently turns decoded keys like `"0"` into
  integers.
- **`{}` versus `[]`.** An associative decode cannot distinguish an empty
  JSON object from an empty JSON array. Causalontology data carries empty
  ARRAYS only (`mechanism: []`, `context: []`) and never an empty object,
  so an empty PHP array serializes as `[]` — correct for every vector.
  This is the binding's one representational compromise, documented in
  `src/Jcs.php`.
- **Shortest-round-trip floats.** Non-integer floats are printed through
  `json_encode` under `serialize_precision=-1` (the PHP 8 default, pinned
  explicitly), then exponent-normalized to the ES6 shape — the same
  strategy, and the same pinned extreme-magnitude ranges, as the Python
  binding.
- **Strict comparisons everywhere.** All identifier and key comparisons
  use `===` / `in_array(..., true)`; PHP's loose `==` on numeric-looking
  strings is never relied on.

## Thirty-second taste

```php
use Causalontology\Store;

$store = new Store(true);
$press = $store->put(['type' => 'occurrent',
                      'label' => 'press_button', 'category' => 'action']);
$light = $store->put(['type' => 'occurrent',
                      'label' => 'light_on', 'category' => 'state_change']);
$claim = $store->put(['type' => 'causal_relation_object',
                      'causes' => [$press], 'effects' => [$light]]);

var_dump($store->gaps('missing_field')); // the degenerate claim is a visible invitation
```

## Status

Ported line-for-line from the Python binding and **green at 137/137
locally** (PHP 8.3 with `ext-sodium`, specification 4.0.0), with
content-addressed identifiers byte-for-byte identical to the Python
reference (the V136 witnesses re-pinned). Also executed by GitHub Actions CI
(`shivammathur/setup-php` with PHP 8.3 and `ext-sodium`, then
`php bindings/php/conformance.php`). Registry publication (a tagged Git
release picked up by the Packagist webhook) still pending.

License: "The attribution always; no profit, no problem license." — see the
repository `LICENSE` and `NOTICE`.

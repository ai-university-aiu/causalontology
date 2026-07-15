# causalontology-php

**The PHP binding of the Causalontology standard** — a faithful port of
[causalontology-py](../python/), sharing the same conformance suite.

**Zero Composer dependencies.** The extensions bundled with every stock PHP
build carry everything the standard needs: `ext-sodium` (Ed25519 per
RFC 8032 — deterministic signatures, seed-derived keypairs), `ext-hash`
(SHA-256), and `ext-json`. Requires **PHP 8.2 or newer** (CI runs 8.3).

| Source file | Implements |
|---|---|
| `src/Jcs.php` | RFC 8785 (JSON Canonicalization Scheme) serialization: bytewise key ordering (equals UTF-16 code-unit order for ASCII keys), minimal string escapes, ECMAScript-style canonical numbers (`1.0` → `1`, `0.7` stays `0.7`, `e-7` not `e-07`) |
| `src/Canonical.php` | identity-bearing field filtering per kind and SHA-256 content-addressed `identify()` (spec/identity.md) |
| `src/Signing.php` | record-level `signRecord()` / `verifyRecord()` over canonical identity-bearing bytes (spec/provenance.md); a succession verifies against its predecessor key; Ed25519 via libsodium, gated on the RFC 8032 TEST 1 known answer |
| `src/SchemaValidator.php` | validation against the eight JSON Schemas in `spec/schema/` (a small interpreter for exactly the keywords those schemas use) |
| `src/Semantics.php` | the 13 semantic rules: temporal admissibility with the fixed unit constants, the formal conflict test, refinement validity, hierarchy reachability, enrichment field/shape rules |
| `src/Store.php` | an in-memory conformant store (the Python binding's `InMemoryStore`): idempotent immutable puts, signed add-only records with quarantine, materialized enrichment views with contributors, retraction and succession lineage, the resolve minimum, the deterministic cycle-breaking view rule, and the stigmergy `gaps()` read |
| `src/RejectedWrite.php` | the exception an enforcing store raises when it refuses a write |
| `src/Causalontology.php` | the facade holding the declared specification version |
| `conformance.php` | the conformance runner: internal known-answer checks (RFC 8032 TEST 1, RFC 8785 basics), then all 38 vectors, mirroring `bindings/python/tests/run_conformance.py` exactly |

## Conformance

```
$ php bindings/php/conformance.php
...
38/38 vectors passed
causalontology-php is CONFORMANT to the suite (vectors frozen at specification 1.0.0).
```

The runner reads the vectors from `../../conformance/vectors` and the
schemas from `../../spec/schema` relative to its own location; the schema
location can be overridden with the environment variable
`CAUSALONTOLOGY_SPEC` (naming the `spec/` directory).

The vectors are frozen at specification 1.0.0 (2026-07-13): they carry
concrete identifiers, real keys, and a real verifying signature. The
harness's old normalization now simply passes frozen values through.

## PHP-specific decisions

- **Integer versus decimal survives decoding.** `json_decode(..., true)`
  keeps the source literal's distinction (`1` decodes to `int`, `1.0` to
  `float`), which is exactly what the canonical number rule needs — no
  lossless-number shim is required, unlike the Go and Java bindings.
- **PHP arrays are ordered maps.** Insertion order is preserved, so the
  store matches the Python binding's `dict` semantics with no extra
  bookkeeping; JSON object keys are cast back to `string` wherever they are
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

Source complete and ported line-for-line from the Python binding; executed
by GitHub Actions CI (`shivammathur/setup-php` with PHP 8.3 and
`ext-sodium`, then `php bindings/php/conformance.php`) — there is no PHP
runtime on the authoring machine, so CI is the gate, as it is for every
binding.

License: "The attribution always; no profit, no problem license." — see the
repository `LICENSE` and `NOTICE`.

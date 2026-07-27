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
| `src/SchemaValidator.php` | validation against the twenty-one JSON Schemas vendored at `bindings/php/spec/schema/`, a byte-for-byte copy of the repository's `spec/schema/` that ships inside the Composer package (a small interpreter for exactly the keywords those schemas use) |
| `src/Semantics.php` | the semantic rules: temporal admissibility with the fixed unit constants and the ordinal `ticks` dimension, the formal conflict test, refinement validity, bridged reachability, stratal classification, the skip decision, cross-stratal-seam well-formedness and the home rule, enrichment field/shape rules, the token-tier coherence checks, the predicted-interval dimension check (Rule 24), and the prediction-to-observation pairing |
| `src/Store.php` | an in-memory conformant store (the Python binding's `InMemoryStore`): idempotent immutable puts, signed add-only records with quarantine, materialized enrichment views with contributors, retraction and succession lineage, the resolve minimum, the deterministic cycle-breaking view rule, and the stigmergy `gaps()` read |
| `src/RejectedWrite.php` | the exception an enforcing store raises when it refuses a write |
| `src/Causalontology.php` | the facade holding the declared specification version |
| `conformance.php` | the conformance runner: internal known-answer checks (RFC 8032 TEST 1, RFC 8785 basics), then all 137 conformance checks — 38 driven by the frozen shared files in `conformance/vectors/`, 99 hand-written here — mirroring `bindings/python/tests/run_conformance.py` exactly |

## Conformance

```
$ php bindings/php/conformance.php
...
137/137 checks passed (38 from the frozen shared vectors, 99 per-binding)
causalontology-php is CONFORMANT to the suite (vectors frozen at specification 4.0.0).
```

The runner reads the shared vectors from `../../conformance/vectors` relative
to its own location.

### Where the schemas come from

`SchemaValidator` resolves the twenty-one JSON Schemas in strict precedence:

1. `$CAUSALONTOLOGY_SPEC/schema`, when that variable is set (it names the
   `spec/` directory, not the `schema/` directory);
2. the copy vendored at `bindings/php/spec/schema`, which travels inside the
   Composer package and is what an installed consumer validates against;
3. the repository-relative `../../spec/schema`, a last resort for a checkout
   in which the vendored copy has not been made yet.

Step 2 is the one that makes an installed copy safe on its own. Before it
existed, the binding validated only because Packagist serves an archive of the
whole repository, so `spec/schema` happened to arrive alongside
`bindings/php/src` and the repository-relative climb happened to land on it.
Any deployment step that prunes non-source files out of `vendor/` deleted
those schemas and the binding stopped validating at first use. The vendored
copy removes that dependence on an accident of packaging: the schemas now sit
inside the binding's own directory and travel with `bindings/php/src`
unconditionally.

Because the vendored schemas are data rather than PSR-4 source, no autoloader
entry points at them. Keep `archive.exclude` empty in `composer.json` and add
no `.gitattributes` `export-ignore` rule covering `spec/`, or the published
package silently loses the ability to validate.

Before running the checks, the runner verifies that the vendored copy is
present and complete, and — when the repository is present — that every file
is byte-for-byte identical to `spec/schema`, aborting on any drift. A
published package can therefore never quietly enforce a different standard
than the repository states, and can never be built without its schemas.

### Proving an installed copy really is self-sufficient

Lay out the package the way Composer does and delete the repository's own
`spec/` directory from it, which is exactly the pruning that used to break the
binding:

```
$ mkdir -p /tmp/app/vendor/causalontology/causalontology
$ git archive HEAD | tar -x -C /tmp/app/vendor/causalontology/causalontology
$ rm -rf /tmp/app/vendor/causalontology/causalontology/spec
$ cd /tmp && env -u CAUSALONTOLOGY_SPEC \
      php /tmp/app/vendor/causalontology/causalontology/bindings/php/conformance.php
...
schemas under test: /tmp/app/vendor/causalontology/causalontology/bindings/php/spec/schema
137/137 checks passed (38 from the frozen shared vectors, 99 per-binding)
```

The runner prints the source file and the schema directory it actually used,
so a "fresh install" check cannot silently report a pass while exercising
repository source through a relative path. Adding
`-d open_basedir=/tmp` forbids PHP from opening any path outside `/tmp` at
all, which makes the repository unreachable rather than merely unused; the run
still passes 137/137 checks.

Only V01-V38 are actually driven by the frozen shared files in
`conformance/vectors/`: those carry concrete identifiers, real keys, and a
real verifying signature as data, and the harness's normalization now simply
passes those frozen values through. The remaining files, V39-V137, are labels
only — their `operation` field reads `see bindings/*/conformance runner` — so
those 99 checks are hand-written here and share no data with any other
implementation: the 2.0.0 additions (V39-V107, the whole-word re-mint of
2026-07-13), the 3.0.0 additions (V108-V119: the `ticks` unit, the
cross_stratal_seam, the conduit `realized_by`), and the 4.0.0 additions
(V120-V137: the attitude, the predicted_occurrence, the prediction_error).
All of them mirror the Python reference exactly.

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

Ported line-for-line from the Python binding and **green at 137/137 checks
locally** (PHP 8.3 with `ext-sodium`, specification 4.0.0), with
content-addressed identifiers byte-for-byte identical to the Python
reference (the V136 witnesses re-pinned). Also executed by GitHub Actions CI
(`shivammathur/setup-php` with PHP 8.3 and `ext-sodium`, then
`php bindings/php/conformance.php`). Also green at 137/137 checks from a
Composer-shaped `vendor/causalontology/causalontology/` tree unpacked from
`git archive HEAD` with the repository's `spec/` directory deleted, run from a
working directory outside the repository with `CAUSALONTOLOGY_SPEC` stripped —
the binding's validation no longer depends on the repository being present.

License: "The attribution always; no profit, no problem license." — see the
repository `LICENSE` and `NOTICE`.

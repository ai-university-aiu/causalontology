# causalontology-perl

**The Perl binding of the Causalontology standard** — a faithful port of
[causalontology-py](../python/), sharing the same conformance suite.

**Core modules only.** Everything the standard needs ships with Perl
itself: `Digest::SHA` (Secure Hash Algorithm 256-bit (SHA-256) and SHA-512), `Math::BigInt` (the Ed25519
field arithmetic), `strict`, and `warnings`. There is nothing to install
from CPAN; any stock Perl 5.16+ runs the suite as-is.

| Source file | Implements |
|---|---|
| `lib/Causalontology/JSON.pm` | a lossless JavaScript Object Notation (JSON) layer: a small parser of its own that tags every number with its source literal (so `1` versus `1.0` survives to the canonicalizer) and keeps an explicit key-order array beside every object, since Perl hashes are unordered |
| `lib/Causalontology/JCS.pm` | RFC 8785 (JSON Canonicalization Scheme) serialization: keys sorted with `cmp` (byte order equals UTF-16 code-unit order for ASCII keys), minimal string escapes with lowercase `\u%04x` for controls, ECMAScript-style numbers (`1.0` → `1`, `0.7` stays `0.7`, `e-07` → `e-7`) |
| `lib/Causalontology/Canonical.pm` | identity-bearing field filtering per kind and SHA-256 content-addressed `identify()` (spec/identity.md) |
| `lib/Causalontology/Ed25519.pm` | Ed25519 (RFC 8032), pure Perl over `Math::BigInt`: slow but correct, gated on the RFC 8032 TEST 1 known answer before any vector runs; a fixed-base doubling table for G keeps the whole suite under ten seconds even on the pure-Perl bigint backend |
| `lib/Causalontology/Signing.pm` | record-level `sign_record()` / `verify_record()` over canonical identity-bearing bytes (spec/provenance.md); a succession verifies against its predecessor key |
| `lib/Causalontology/Schema.pm` | validation against the twenty-one JSON Schemas in `spec/schema/` (a small interpreter for exactly the keywords those schemas use) |
| `lib/Causalontology/Semantics.pm` | the semantic rules: temporal admissibility with the fixed unit constants (months 2629746 s, years 31556952 s) and the ordinal `ticks` dimension, the formal conflict test, refinement validity, bridged reachability, stratal classification, the skip decision, cross-stratal-seam well-formedness and the home rule, enrichment field/shape rules, the token-tier coherence checks, the predicted-interval dimension check, and the prediction-to-observation pairing |
| `lib/Causalontology/Store.pm` | an in-memory conformant store: idempotent immutable puts, signed add-only records with quarantine, materialized enrichment views with contributors, retraction and succession lineage, the resolve minimum, the deterministic cycle-breaking view rule, and the stigmergy `gaps()` read — with explicit insertion-order bookkeeping everywhere the Python reference iterates dicts |
| `conformance.pl` | the conformance runner: internal known-answer checks (RFC 8032 TEST 1, RFC 8785 basics), then all 137 vectors, mirroring `bindings/python/tests/run_conformance.py` exactly |

## Conformance

Verified locally (Perl 5.38, pure-Perl `Math::BigInt::Calc` backend):

```
$ perl bindings/perl/conformance.pl
...
137/137 vectors passed
causalontology-perl is CONFORMANT to the suite (vectors frozen at specification 4.0.0).
```

The runner locates the repository root from its own path (two levels up
from `bindings/perl/`), reads the vectors from `conformance/vectors`, and
reads the schemas from `spec/schema` under the same root (overridable
with the `CAUSALONTOLOGY_SPEC` environment variable, which names the
`spec/` directory).

For CI, no toolchain setup step is needed — the stock Ubuntu runner's
Perl carries every module used:

```yaml
  perl:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: conformance (137 vectors)
        run: perl bindings/perl/conformance.pl
```

The V01-V107 vectors are the whole-word 2.0.0 baseline (2026-07-13):
they carry concrete identifiers, real keys, and a real verifying
signature, and the harness's normalization now simply passes those
frozen values through; behavioral vectors derive deterministic keypairs
from the seed `sha256("key:" + name)`. The V108-V119 (3.0.0: the `ticks`
unit, the cross_stratal_seam, the conduit `realized_by`) and V120-V137
(4.0.0: the attitude, the predicted_occurrence, the prediction_error)
fixtures are built in the runner, mirroring the Python reference exactly.

## Thirty-second taste

```perl
use lib 'bindings/perl/lib';
use Causalontology;
use Causalontology::JSON qw(jobj jstr jarr);

my $store = Causalontology::Store->new(enforcing => 1);
my $press = $store->put(jobj(type => jstr('occurrent'),
    label => jstr('press_button'), category => jstr('action')));
my $light = $store->put(jobj(type => jstr('occurrent'),
    label => jstr('light_on'), category => jstr('state_change')));
my $claim = $store->put(jobj(type => jstr('causal_relation_object'),
    causes => jarr(jstr($press)), effects => jarr(jstr($light))));

# the degenerate claim is a visible invitation
print "$claim\n", scalar($store->gaps('missing_field')), " gap(s)\n";
```

## Packaging

`Makefile.PL` and `META.json` carry standard CPAN metadata (dist
`Causalontology`, version 4.0.0). Both declare only core prerequisites.

License: "The attribution always; no profit, no problem license.
(Apache 2.0 text)" — see `LICENSE` here and the repository `NOTICE`.

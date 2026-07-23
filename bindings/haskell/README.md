# causalontology-haskell

**The Haskell binding of the Causalontology standard** — a faithful port of
[causalontology-py](../python/), sharing the same conformance suite.

**GHC-bundled packages only — pure-Haskell crypto.** The binding depends on
nothing beyond what a stock GHC installation ships (`base`, `bytestring`,
`containers`, `directory`, `filepath`): Secure Hash Algorithm 256-bit (SHA-256), SHA-512, and Ed25519
(RFC 8032) are implemented by hand over `Word32`/`Word64` and `Integer`,
JSON is parsed by the binding's own lossless recursive-descent parser, and
RFC 8785 canonicalization is hand-written. All crypto is gated on known
answers before any vector runs (the SHA-256/SHA-512 empty-string digests
and the RFC 8032 TEST 1 keypair and signature). Requires **GHC 9.6 or
newer** with cabal.

| Source file | Implements |
|---|---|
| `src/Causalontology/Json.hs` | a lossless JavaScript Object Notation (JSON) value model: `JObj` is an association list (insertion order preserved, like a Python dict), and the recursive-descent parser tags numbers by their source literal, so the `1`-versus-`1.0` distinction survives to the canonicalizer; hand-written UTF-8 codec |
| `src/Causalontology/Jcs.hs` | RFC 8785 (JSON Canonicalization Scheme) serialization: code-point key order, minimal string escapes with lowercase `\uXXXX`, ECMAScript-style canonical numbers (`1.0` → `1`, `0.7` stays `0.7`, `1e-07` → `1e-7`, `1e21` → `1e+21`) via `Numeric.floatToDigits` |
| `src/Causalontology/Sha2.hs` | SHA-256 and SHA-512 (FIPS 180-4), pure Haskell over `Word32`/`Word64`, plus hex encoding |
| `src/Causalontology/Ed25519.hs` | Ed25519 (RFC 8032), ported from the Python binding's `ed25519.py` over `Integer` (Haskell's floored `mod` matches Python's `%` for these positive moduli) |
| `src/Causalontology/Canonical.hs` | identity-bearing field filtering per kind and SHA-256 content-addressed `identify` (spec/identity.md) |
| `src/Causalontology/Signing.hs` | record-level `signRecord` / `verifyRecord` over canonical identity-bearing bytes (spec/provenance.md); a succession verifies against its predecessor key |
| `src/Causalontology/Schema.hs` | validation against the twenty-one JSON Schemas in `spec/schema/` (a small interpreter for exactly the keywords those schemas use, with a tiny matcher for their regular-expression subset, including the `.` any-char and `+` quantifier of the 3.0.0 conduit realized_by pattern) |
| `src/Causalontology/Semantics.hs` | the 25 semantic rules: temporal admissibility with the fixed unit constants and the dimension-disjoint ordinal tick unit, the formal conflict test, refinement validity, bridged reachability, stratal classification, the skip decision, cross-stratal seam well-formedness with the coarsest-stratum home rule, enrichment field/shape rules, and the token-tier coherence checks including the prediction-to-observation pairing |
| `src/Causalontology/Store.hs` | an in-memory conformant store: idempotent immutable puts, signed add-only records with quarantine, materialized enrichment views with contributors, retraction and succession lineage, the resolve minimum, the deterministic cycle-breaking view rule, and the stigmergy `gaps` read — the Python store's state modeled as a `Store` record threaded through pure functions, with association-list tables so dict insertion order is preserved exactly |
| `app/Conformance.hs` | the conformance runner: internal known-answer checks (RFC 8032 TEST 1, RFC 8785 basics), then all 137 vectors, mirroring `bindings/python/tests/run_conformance.py` exactly |

## Conformance

```
$ cd bindings/haskell
$ cabal run -v0 conformance
...
137/137 vectors passed
causalontology-haskell is CONFORMANT to the suite (vectors frozen at specification 4.0.0).
```

The runner locates the repository root from the `CAUSALONTOLOGY_ROOT`
environment variable when set, otherwise by walking up from the working
directory until it finds `conformance/vectors`; the schemas are read from
`spec/schema` under the same root (overridable with `CAUSALONTOLOGY_SPEC`,
which names the `spec/` directory).

The vectors are frozen at specification 4.0.0 (2026-07-22; 137 vectors,
V01–V137): they carry concrete identifiers, real keys, and a real verifying
signature. The harness's old normalization now simply passes frozen values
through; records built at run time still use deterministic keypairs seeded
from `sha256("key:" ++ name)`, as the Python harness does.

## Thirty-second taste

```haskell
import Causalontology.Json
import Causalontology.Schema (loadSchemas)
import Causalontology.Store

main :: IO ()
main = do
  schemas <- loadSchemas "spec/schema"
  let s0 = newStore True schemas
      (Right press, s1) = put (JObj [ ("type", JStr "occurrent")
                                    , ("label", JStr "press_button")
                                    , ("category", JStr "action") ]) Nothing s0
      (Right light, s2) = put (JObj [ ("type", JStr "occurrent")
                                    , ("label", JStr "light_on")
                                    , ("category", JStr "state_change") ]) Nothing s1
      (Right claim, s3) = put (JObj [ ("type", JStr "causal_relation_object")
                                    , ("causes", JArr [JStr press])
                                    , ("effects", JArr [JStr light]) ]) Nothing s2
  print claim
  print (gaps (Just "missing_field") s3)  -- the degenerate claim is a visible invitation
```

## Status

Source complete and ported line-for-line from the Python binding; built and
executed by GitHub Actions CI
(`cd bindings/haskell && cabal update && cabal run -v0 conformance`) —
there is no GHC toolchain on the authoring machine, so CI is the gate, as
it is for every binding.

License: "The attribution always; no profit, no problem license." — see the
repository `LICENSE` and `NOTICE`.

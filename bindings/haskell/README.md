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
| `src/Causalontology/Schema.hs` | validation against the twenty-one JSON Schemas, resolved from `CAUSALONTOLOGY_SPEC`, then the copy bundled in the package at `spec_schema/`, then a repository checkout (a small interpreter for exactly the keywords those schemas use, with a tiny matcher for their regular-expression subset, including the `.` any-char and `+` quantifier of the 3.0.0 conduit realized_by pattern) |
| `src/Causalontology/Semantics.hs` | the 25 semantic rules: temporal admissibility with the fixed unit constants and the dimension-disjoint ordinal tick unit, the formal conflict test, refinement validity, bridged reachability, stratal classification, the skip decision, cross-stratal seam well-formedness with the coarsest-stratum home rule, enrichment field/shape rules, and the token-tier coherence checks including the prediction-to-observation pairing |
| `src/Causalontology/Store.hs` | an in-memory conformant store: idempotent immutable puts, signed add-only records with quarantine, materialized enrichment views with contributors, retraction and succession lineage, the resolve minimum, the deterministic cycle-breaking view rule, and the stigmergy `gaps` read — the Python store's state modeled as a `Store` record threaded through pure functions, with association-list tables so dict insertion order is preserved exactly |
| `app/Conformance.hs` | the conformance runner: internal known-answer checks (RFC 8032 TEST 1, RFC 8785 basics), then all 137 conformance checks — 38 driven by the frozen shared files in `conformance/vectors/`, 99 hand-written here — mirroring `bindings/python/tests/run_conformance.py` exactly |

## Conformance

```
$ cd bindings/haskell
$ cabal run -v0 conformance
...
137/137 checks passed (38 from the frozen shared vectors, 99 per-binding)
causalontology-haskell is CONFORMANT to the suite (vectors frozen at specification 4.0.0).
```

The runner locates the repository root from the `CAUSALONTOLOGY_ROOT`
environment variable when set, otherwise by walking up from the working
directory until it finds `conformance/vectors`. That root supplies the
vectors only; the schemas are resolved separately (see below).

### Testing an installed copy

Setting `CAUSALONTOLOGY_TEST_INSTALLED` puts the runner in installed mode:
it prints the copy of the binding it resolved and hard-fails if that copy,
the conformance binary, or the schemas still come from the repository tree.
That is what stops a "fresh install" test from silently exercising the
source checkout and reporting a false 137/137 checks passed.

```
$ cabal install exe:conformance --install-method=copy --installdir=/tmp/co/bin
$ cd /tmp && env -u CAUSALONTOLOGY_SPEC CAUSALONTOLOGY_TEST_INSTALLED=1 \
    CAUSALONTOLOGY_ROOT=/path/to/causalontology /tmp/co/bin/conformance
binding under test: ~/.local/state/cabal/store/ghc-9.6.6/causalontology-4.0.0-.../share
...
137/137 checks passed (38 from the frozen shared vectors, 99 per-binding)
```

The runner also compares the bundled schemas against `spec/schema`
byte for byte whenever both are present, and fails with `bundled schema
drift` rather than letting the vendored copy go quietly stale.

## Where the schemas come from

The twenty-one normative JSON Schemas are **vendored into the package** at
`spec_schema/` and shipped as Cabal `data-files`, so `cabal install
causalontology` gives you a binding that validates with no repository
checkout anywhere. `Causalontology.Schema` resolves them in this order:

1. `CAUSALONTOLOGY_SPEC`, which names a `spec/` directory (its `schema`
   subdirectory is read) — unchanged from earlier releases;
2. the copy bundled inside the installed package, found through
   `Paths_causalontology.getDataFileName`;
3. a repository checkout — `CAUSALONTOLOGY_ROOT/spec/schema`, else the
   nearest ancestor of the working directory holding `spec/schema` — as a
   last resort, so repo-mode development keeps working.

`loadDefaultSchemas` applies that order; `loadSchemas dir` still reads an
explicit directory. `schemaDirWithOrigin` reports which of the three won.

The shared vectors are frozen at specification 4.0.0 (2026-07-22). Of the 137
files V01–V137, only V01–V38 carry executable data — concrete identifiers,
real keys, and a real verifying signature — and the harness's old
normalization now simply passes those frozen values through. V39–V137 are
labels only (their `operation` field reads `see bindings/*/conformance
runner`), so those 99 checks are hand-written in this binding and share no
data with any other implementation; records built at run time use
deterministic keypairs seeded from `sha256("key:" ++ name)`, as the Python
harness does.

## Thirty-second taste

```haskell
import Causalontology.Json
import Causalontology.Schema (loadDefaultSchemas)
import Causalontology.Store

main :: IO ()
main = do
  schemas <- loadDefaultSchemas   -- the schemas bundled with the package
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

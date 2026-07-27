# causalontology-swift

**The Swift binding of the Causalontology standard** — a faithful port of
[causalontology-py](../python/), sharing the same conformance suite.

One dependency only:
[swift-crypto](https://github.com/apple/swift-crypto) (from 3.0.0), Apple's
Linux-compatible crypto package, used for Secure Hash Algorithm 256-bit (SHA-256) and Ed25519
(`Curve25519.Signing`). Everything else is hand-written from the
specification.

| Source file | Implements |
|---|---|
| `Sources/Causalontology/JsonValue.swift` | a lossless JavaScript Object Notation (JSON) value model with its own recursive-descent parser (integer literals stay `Int64`, floating literals stay `Double` — the 1-vs-1.0 distinction survives to the canonicalizer) |
| `Sources/Causalontology/Jcs.swift` | RFC 8785 (JSON Canonicalization Scheme) serialization: UTF-16 key order, minimal string escaping, canonical numbers |
| `Sources/Causalontology/Canonical.swift` | identity-bearing field filtering and SHA-256 content-addressed `identify()` |
| `Sources/Causalontology/Signing.swift` | record-level `signRecord()` / `verifyRecord()` over canonical identity-bearing bytes (Ed25519, RFC 8032) |
| `Sources/Causalontology/SchemaValidator.swift` | validation against the twenty-one JSON Schemas in `spec/schema/` |
| `Sources/Causalontology/Semantics.swift` | the 25 semantic rules: temporal admissibility with the fixed constants and the dimension-disjoint ordinal tick unit, formal conflict, refinement validity, bridged reachability, stratal classification, the skip decision, cross-stratal seam well-formedness with the coarsest-stratum home rule, enrichment field/shape rules, and the token-tier coherence checks including the prediction-to-observation pairing |
| `Sources/Causalontology/Store.swift` | an in-memory conformant store: idempotent immutable puts, signed add-only records, materialized enrichment views with contributors, retraction and succession lineage, the resolve minimum, the deterministic cycle-breaking view rule, and the stigmergy `gaps()` read |
| `Sources/conformance/main.swift` | the conformance runner: internal known-answer checks, then all 137 conformance checks — 38 driven by the frozen shared files in `conformance/vectors/`, 99 hand-written here |

The object model is twenty-one kinds: the eighteen of 2.0.0 plus the 3.0.0 `cross_stratal_seam` and the 4.0.0 `attitude`, `predicted_occurrence`, and `prediction_error`.

## Conformance

```
$ cd bindings/swift
$ swift run conformance
...
137/137 checks passed (38 from the frozen shared vectors, 99 per-binding)
causalontology-swift is CONFORMANT to the suite (vectors frozen at specification 4.0.0).
```

The shared vectors are frozen at specification 4.0.0 (2026-07-22). Of the 137 files V01–V137, only V01–V38 carry executable data — concrete identifiers, real keys, and a real verifying signature — and the harness's old normalization now simply passes those frozen values through. V39–V137 are labels only (their `operation` field reads `see bindings/*/conformance runner`), so those 99 checks are hand-written in this binding and share no data with any other implementation.

The runner locates the repository root from the `CAUSALONTOLOGY_ROOT`
environment variable when set, otherwise from its own source location inside
`bindings/swift/`.

### Where the schemas come from

This binding vendors no copy of its own and embeds nothing.
`SchemaValidator.defaultSchemaDirectory()` resolves, highest precedence
first: `$CAUSALONTOLOGY_SPEC/schema`, then `$CAUSALONTOLOGY_ROOT/spec/schema`,
then `spec/schema` relative to this source file's own compile-time location
(`#filePath`, five parents up).

That is safe here **only because SwiftPM is different from every other
package manager in this repository**: it resolves a dependency by cloning the
whole git repository into `.build/checkouts/`, so the repository's `spec/`
travels with the package and the `#filePath` walk lands inside the consumer's
own checkout. Verified 2026-07-27 against the published `v4.0.3` tag: a
separate SwiftPM package declaring
`.package(url: "https://github.com/ai-university-aiu/causalontology", from: "4.0.3")`,
built and run from a working directory outside this repository with both
`CAUSALONTOLOGY_SPEC` and `CAUSALONTOLOGY_ROOT` unset, validated an
`occurrent` (`ok=true`) and rejected a wrong-typed `category` (`ok=false`),
reading `.build/checkouts/causalontology/spec/schema`.

The standing hazard, stated plainly: anything that removes `spec/` from what a
consumer receives — a `.gitattributes` `export-ignore` rule, or distributing
this package as a pruned source archive rather than a git checkout — silently
takes the schemas away, which is the same defect that broke the PyPI, pub.dev
and Go artifacts. There is deliberately **no `.gitattributes` in this
repository**; do not add one that touches `spec/`.

## Thirty-second taste

```swift
import Causalontology

let store = InMemoryStore()
let press = try store.put(["type": .string("occurrent"),
                           "label": .string("press_button"),
                           "category": .string("action")])
let light = try store.put(["type": .string("occurrent"),
                           "label": .string("light_on"),
                           "category": .string("state_change")])
let claim = try store.put(["type": .string("causal_relation_object"),
                           "causes": .array([.string(press)]),
                           "effects": .array([.string(light)])])

print(store.gaps("missing_field"))   // the degenerate claim is a visible invitation
```

## Status

Source complete and ported line-for-line from the Python binding; built and
executed by GitHub Actions CI (`cd bindings/swift && swift run conformance`).
Last run locally on 2026-07-27: **137/137 checks passed**, exit 0. Note the
working directory: the `conformance` executable product is declared in
`bindings/swift/Package.swift`, not in the repository-root `Package.swift`
(which exposes the library product only), so `swift run conformance` from
the repository root fails with *no executable product named 'conformance'*.

License: "The attribution always; no profit, no problem license." — see the
repository `LICENSE` and `NOTICE`.

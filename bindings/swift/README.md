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
| `Sources/conformance/main.swift` | the conformance runner: internal known-answer checks, then all 137 vectors from `conformance/vectors/` |

The object model is twenty-one kinds: the eighteen of 2.0.0 plus the 3.0.0 `cross_stratal_seam` and the 4.0.0 `attitude`, `predicted_occurrence`, and `prediction_error`.

## Conformance

```
$ cd bindings/swift
$ swift run conformance
...
137/137 vectors passed
causalontology-swift is CONFORMANT to the suite (vectors frozen at specification 4.0.0).
```

The vectors are frozen at specification 4.0.0 (2026-07-22; 137 vectors, V01–V137): they carry concrete identifiers, real keys, and a real verifying signature. The harness's old normalization now simply passes frozen values through.

The runner locates the repository root from the `CAUSALONTOLOGY_ROOT`
environment variable when set, otherwise from its own source location inside
`bindings/swift/`.

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
executed by GitHub Actions CI (`cd bindings/swift && swift run conformance`) —
there is no Swift toolchain on the authoring machine, so CI is the gate, as
it is for every binding.

License: "The attribution always; no profit, no problem license." — see the
repository `LICENSE` and `NOTICE`.

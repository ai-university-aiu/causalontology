# causalontology-js

**The third implementation of the Causalontology standard — further proof of
language independence.** (The first is the PrologAI reference implementation;
the second is the Python binding in `bindings/python/`.)

Zero dependencies — Node.js builtins only (`node:crypto`, `node:fs`,
`node:path`). The whole SDK is a single CommonJS module,
`causalontology.js`:

| Area | Implements |
|---|---|
| canonical | RFC 8785 (JSON Canonicalization Scheme) serialization, identity-bearing field filtering, SHA-256 content-addressed `identify()`. JavaScript gets RFC 8785 primitives natively: `JSON.stringify`'s number and string serialization IS the ES6 rule the RFC is based on. |
| ed25519 | Ed25519 (RFC 8032) via `node:crypto` KeyObjects (raw 32-byte seeds and public keys wrapped in PKCS8/SPKI DER), verified against the RFC's known-answer test |
| signing | record-level `signRecord()` / `verifyRecord()` over canonical identity-bearing bytes |
| schema | validation against the eight JSON Schemas in `spec/schema/` |
| semantics | the 13 semantic rules: temporal admissibility (fixed constants), formal conflict, refinement validity, hierarchy reachability, enrichment field/shape rules |
| store | an in-memory conformant store: idempotent immutable puts, signed add-only records, materialized enrichment views with contributors, retraction and succession lineage, the resolve minimum, the deterministic cycle-breaking view rule, and the stigmergy `gaps()` read |

## API surface

```js
const {
  canonicalize, identify, identityBearing, inferKind,
  validateSchema, validateSemantics, isPartial, admissible,
  conflicts, refinementValid, hierarchyConsistent, UNIT_SECONDS,
  keypairFromSeed, signRecord, verifyRecord,
  InMemoryStore, RejectedWrite,
} = require("./causalontology.js");
```

Ed25519 is deterministic (RFC 8032), and the canonical bytes are pinned by
RFC 8785, so identifiers and signatures are byte-compatible across the
Prolog, Python, and JavaScript implementations: the same record signed with
the same key yields the same id and the same signature in all three.

## TypeScript

The binding is typed out of the box: hand-written declarations in
`causalontology.d.ts` (wired up via `"types"` in `package.json`) cover the
whole exported surface — the eight domain shapes, every function, the
`InMemoryStore` class (including the materialized-view and `gaps()` return
shapes), and `RejectedWrite`. The JavaScript module remains the single
source of logic; the declarations only describe it.

```ts
import co = require("./causalontology"); // CommonJS export= pattern

const store = new co.InMemoryStore();
const id = store.put({ label: "press_button", category: "action" }, "occurrent");
const view = store.get(id); // { object, enrichments } | null, fully typed
```

Type-check the declarations and the compile-only exercise in
`tests/type_check.ts` with:

```
$ npx tsc -p .
```

No dependencies are needed (not even `@types/node`): binary values are
declared as `Uint8Array` (`co.Bytes`), which every Node `Buffer` is.

## Conformance

```
$ node tests/run_conformance.js
...
38/38 vectors passed
causalontology-js is CONFORMANT to the suite (vectors frozen at specification 2.0.0).
```

The vectors are frozen at specification 2.0.0 (2026-07-13): they carry concrete identifiers, real keys, and a real verifying signature. The harness's old normalization now simply passes frozen values through.

## License

The attribution always; no profit, no problem license. (Apache License 2.0
text — see the repository `LICENSE` and `NOTICE`.)

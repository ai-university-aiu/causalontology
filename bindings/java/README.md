# causalontology-java

**The Java binding of the Causalontology standard** - the third
implementation, after the PrologAI reference implementation and
[causalontology-py](../python/).

Zero dependencies - JDK standard library only. Requires **JDK 17 or newer**
(Ed25519 in `java.security` needs JDK 15+; `java.util.HexFormat` needs 17;
CI runs JDK 21).

| Class | Implements |
|---|---|
| `Json` | minimal JavaScript Object Notation (JSON) parser/writer over `LinkedHashMap` / `ArrayList` / `String` / `Boolean` / `Long` / `Double` / null, preserving the integer/decimal source distinction the canonicalizer needs |
| `Jcs` | RFC 8785 (JSON Canonicalization Scheme) serialization: UTF-16 code-unit key ordering, minimal string escapes, ECMAScript-style number formatting |
| `Canonical` | identity-bearing field filtering per kind and Secure Hash Algorithm 256-bit (SHA-256) content-addressed `identify()` (spec/identity.md) |
| `Ed25519` | Ed25519 (RFC 8032): signing and verification through `java.security` `Signature("Ed25519")`; public-key derivation from a 32-byte seed via BigInteger point arithmetic (the JDK exposes no derive-public-from-private application programming interface (API)); verified against the RFC 8032 TEST 1 known answer at startup |
| `Signing` | record-level `signRecord()` / `verifyRecord()` over canonical identity-bearing bytes (spec/provenance.md); a succession verifies against its predecessor key |
| `SchemaValidator` | validation against the twenty-one JSON Schemas in `spec/schema/` (a small interpreter for exactly the keywords those schemas use) |
| `Semantics` | the 25 semantic rules: temporal admissibility with the fixed unit constants and the dimension-disjoint ordinal tick unit, the formal conflict test, refinement validity, bridged reachability, stratal classification, the skip decision, cross-stratal seam well-formedness with the coarsest-stratum home rule, enrichment field/shape rules, and the token-tier coherence checks including the prediction-to-observation pairing |
| `Store` | an in-memory conformant store: idempotent immutable puts, signed add-only records with quarantine, materialized enrichment views with contributors, retraction and succession lineage, the resolve minimum, the deterministic cycle-breaking view rule, and the stigmergy `gaps()` read |
| `Conformance` | the conformance runner: internal sanity checks, then all 137 vectors, mirroring `bindings/python/tests/run_conformance.py` exactly |

## Conformance

```
$ ./run_conformance.sh
...
137/137 vectors passed
causalontology-java is CONFORMANT to the suite (vectors frozen at specification 4.0.0).
```

The script compiles `src/` into `out/` and runs
`org.causalontology.Conformance` from `bindings/java`, so the vectors are
read from `../../conformance/vectors` and the schemas from
`../../spec/schema`. The schema location can be overridden with the system
property `causalontology.spec` or the environment variable
`CAUSALONTOLOGY_SPEC` (either names the `spec/` directory).

The vectors are frozen at specification 4.0.0 (2026-07-22; 137 vectors, V01-V137): they carry concrete identifiers, real keys, and a real verifying signature. The harness's old normalization now simply passes frozen values through.

## Status

Source complete; compiled and executed by GitHub Actions CI with JDK 21
(the CI workflow runs `bindings/java/run_conformance.sh`). There is no
local JDK on the authoring machine, so verification happens in CI.

License: "The attribution always; no profit, no problem license." - see the
repository `LICENSE` and `NOTICE`.

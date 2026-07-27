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
| `Conformance` | the conformance runner: internal sanity checks, then all 137 conformance checks (38 driven by the frozen shared vectors, 99 implemented per binding), mirroring `bindings/python/tests/run_conformance.py` exactly |

## Conformance

```
$ ./run_conformance.sh
...
137/137 checks passed (38 from the frozen shared vectors, 99 per-binding)
causalontology-java is CONFORMANT to the suite (vectors frozen at specification 4.0.0).
```

The script compiles `src/` into `out/`, copies the bundled schemas
alongside the classes, and runs `org.causalontology.Conformance` from
`bindings/java`, so the vectors are read from `../../conformance/vectors`.

## Where the schemas come from

The twenty-one JSON Schemas are **shipped inside the jar** at `/schema/`,
so the published artifact validates standalone with no repository checkout.
They are packaged from `src/main/resources/schema/`, a byte-for-byte copy of
the repository's `spec/schema/`, by the `<resources>` block in `pom.xml`, and
read back with `getResourceAsStream`.

`SchemaValidator` resolves them in exactly this order:

1. the system property `causalontology.spec`, or the environment variable
   `CAUSALONTOLOGY_SPEC` - either names the `spec/` directory;
2. the copy bundled in the artifact, on the classpath at `/schema/`;
3. `../../spec/schema` relative to the working directory, as a last resort
   for repository-mode development.

Two guards keep this honest. The conformance runner compares the bundled
copy against `spec/schema` byte-for-byte and fails with
`bundled schema drift` on any difference, so the vendored copy cannot go
stale. And when `CAUSALONTOLOGY_TEST_INSTALLED` is set, the runner prints
`binding under test: <path>` and exits nonzero if the classes were loaded
from inside the repository tree, so a "fresh install" test cannot silently
pass by exercising repository sources:

```
$ sh build_jar.sh                       # target/causalontology-4.0.0.jar
                                        # + target/test-classes (the runner)
$ cp target/causalontology-4.0.0.jar <installed>/     # or mvn install
$ cd /somewhere/outside/the/repo
$ env -u CAUSALONTOLOGY_SPEC CAUSALONTOLOGY_TEST_INSTALLED=1 \
    java -cp <repo>/bindings/java/target/test-classes:<installed>/causalontology-4.0.0.jar \
    org.causalontology.Conformance
binding under test: <installed>/causalontology-4.0.0.jar
schemas under test: bundled:jar:file:<installed>/causalontology-4.0.0.jar!/schema/occurrent.schema.json
...
137/137 checks passed (38 from the frozen shared vectors, 99 per-binding)
```

Only `target/test-classes` - the conformance runner, recompiled on its own
against the finished jar - comes from the repository there; every binding
class the run exercises is resolved from the artifact, which is what
`binding under test` reports. That mirrors the Python and JavaScript
harnesses, where the runner script is repository code and the package under
test is the installed one. The runner also refuses to run at all if
`CAUSALONTOLOGY_TEST_INSTALLED` is set and no checkout can be located, since
it could then neither read the frozen vectors nor check where the binding
came from.

`build_jar.sh` performs the pom's compile-and-package steps directly with
`javac` and `jar`, for environments without Maven: it compiles
`<sourceDirectory>src</sourceDirectory>`, copies the pom's `<resources>`
block into the class output, and packages the result - the same
`target/causalontology-4.0.0.jar` layout `mvn package` produces.

The suite is 137 checks at specification 4.0.0. Only V01-V38 are driven by the shared files in `conformance/vectors/` - those carry concrete identifiers, real keys, and a real verifying signature as data; the other 99 are implemented here and share no data with any other binding. The harness's old normalization now simply passes frozen values through.

## Status

Source complete; compiled and executed by GitHub Actions CI with JDK 21
(the CI workflow runs `bindings/java/run_conformance.sh`). Last run locally
on 2026-07-27 with JDK 21: **137/137 checks passed**, exit 0, in both
repository mode and installed mode against a jar outside the checkout.

License: "The attribution always; no profit, no problem license." - see the
repository `LICENSE` and `NOTICE`.

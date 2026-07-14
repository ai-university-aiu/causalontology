# causalontology-kotlin

**The Kotlin/Native binding of the Causalontology standard** - a faithful port
of [causalontology-py](../python/), sharing the same conformance suite.

**Pure Kotlin/Native, zero dependencies.** No kotlinx libraries, no cinterop
definitions, no JVM at runtime: the sources compile with a bare
`kotlinc-native` into a self-contained native executable. Kotlin/Native's
standard library carries no cryptography, no JSON, and no arbitrary-precision
integers, so this binding implements all three itself, exactly as the Lua
binding did: SHA-256 over Int words and SHA-512 over Long words with Kotlin's
bitwise operators, and Ed25519 (RFC 8032) over a small bignum layer of
base-2^16 IntArray limbs (Long products cannot overflow at that base). The
only OS surface is `platform.posix` file reads (fopen/fread/opendir), which
ships with the compiler. Built and verified with **Kotlin/Native 2.0.20**.

| Source file | Implements |
|---|---|
| `src/Json.kt` | a recursive-descent JSON parser over `LinkedHashMap` / `MutableList` / `String` / `Boolean` / `Long` / `Double` / null; objects preserve insertion order, and a numeric literal with no `.`/`e`/`E` parses to a **Long**, so the integer-versus-decimal source distinction (`1` versus `1.0`) survives to the canonicalizer |
| `src/Jcs.kt` | RFC 8785 (JSON Canonicalization Scheme) serialization: sorted keys, minimal string escaping, and canonical numbers mirroring the reference `_jcs_number` exactly - Longs verbatim, integral doubles below 1e21 as exact integers (via the bignum above 2^53), everything else as the shortest round-trip decimal with ES6-normalized exponents (`1.0` → `1`, `0.7` stays `0.7`, `e-07` → `e-7`); a round-trip digit minimizer guarantees shortest digits even where Kotlin/Native's `Double.toString` is not (denormals) |
| `src/Sha2.kt` | SHA-256 and SHA-512 (FIPS 180-4); SHA-512 runs in Long words with naturally wrapping adds and `ushr` logical shifts; both gated on the empty-string known answers |
| `src/Bignum.kt` | arbitrary-precision non-negative integers over base-2^16 IntArray limbs: add/sub/cmp/mul, shifts, binary modulus, small division, and exact decimal rendering |
| `src/Ed25519.kt` | Ed25519 (RFC 8032): the twisted Edwards point group in extended coordinates over the bignum layer, with a limb-aligned fold reduction (2^256 = 38 mod p), Fermat inversion, deterministic signing and verification; all field arithmetic stays non-negative (`a - b` mod p is computed as `a + p - b`); gated on the RFC 8032 TEST 1 known answer (public key, exact signature, verify, reject) |
| `src/Canonical.kt` | identity-bearing field filtering per kind and SHA-256 content-addressed `identify()` (spec/identity.md) |
| `src/Schema.kt` | validation against the eight JSON Schemas in `spec/schema/` (a small interpreter for exactly the keywords those schemas use); the schemas' four anchored pattern families are interpreted with `kotlin.text.Regex` |
| `src/Semantics.kt` | the 13 semantic rules: temporal admissibility with the fixed unit constants (month = 2,629,746 s; year = 31,556,952 s), the formal conflict test, refinement validity, hierarchy reachability, enrichment field/shape rules |
| `src/Signing.kt` | record-level `signRecord()` / `verifyRecord()` over canonical identity-bearing bytes (spec/provenance.md); a succession verifies against its predecessor key |
| `src/Store.kt` | an in-memory conformant store: idempotent immutable puts, signed add-only records with quarantine, materialized enrichment views with contributors (deduplicated by canonical entry), retraction and succession lineage, the resolve minimum (label before alias), the deterministic cycle-breaking view rule (greatest (timestamp, id) loses), `forceMergeRecord()` replica merges, and the stigmergy `gaps()` read with its five gap kinds |
| `src/Io.kt` | the single POSIX touchpoint: `readFile()`, `listDir()`, and environment lookup via `platform.posix` |
| `src/Conformance.kt` | the conformance runner: internal known-answer checks (FIPS 180-4, RFC 8032 TEST 1, RFC 8785 basics), then all 38 vectors, mirroring `bindings/python/tests/run_conformance.py` exactly |

## Conformance

```
$ bash bindings/kotlin/run_conformance.sh
...
38/38 vectors passed
causalontology-kotlin is CONFORMANT to the suite (vectors frozen at specification 1.0.0).
```

The script uses `kotlinc-native` from PATH when available and otherwise
downloads the pinned 2.0.20 prebuilt compiler to a temporary directory
(the compiler itself is a JVM application, so a JDK must be present; the
first compile also fetches Kotlin/Native's LLVM dependencies). It compiles
`src/*.kt` to `/tmp/co_conformance` and runs it from the repository root,
so the vectors are read from `conformance/vectors` and the schemas from
`spec/schema` (overridable with `CAUSALONTOLOGY_ROOT` and
`CAUSALONTOLOGY_SPEC`).

The vectors are frozen at specification 1.0.0 (2026-07-13): they carry
concrete identifiers, real keys, and a real verifying signature. The
harness's old normalization now simply passes frozen values through.

## Status

Source complete, ported line-for-line from the Python binding, and
**verified locally**: Kotlin/Native 2.0.20 on linux x86_64 compiles the
suite and runs it at 38/38 (about a second end to end). The hand-built
layers are cross-checked against the Python reference: 422
random-operand bignum and Ed25519 cases (add/sub/mul/mod/modpow at
assorted bit widths, public-key derivation, and deterministic signatures
byte-for-byte), 1232 JCS number-formatting cases (including random
64-bit patterns and denormals), and load-time known-answer gates on both
hash functions and the signature scheme.

Packaging: the natural registry for a Kotlin/Native library is **Maven
Central**, as a klib / Kotlin Multiplatform artifact; publication is
pending. The sources carry no Gradle build on purpose - conformance
needs nothing but `kotlinc-native`.

License: "The attribution always; no profit, no problem license." - see
the repository `LICENSE` and `NOTICE`.

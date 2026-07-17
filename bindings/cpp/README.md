# causalontology-cpp

**The C++ binding of the Causalontology standard** - a faithful port of
[causalontology-py](../python/), sharing the same conformance suite.

**Pure C++17, zero dependencies.** The C++ standard library carries no
JSON, no cryptography, and no big integers, so this binding hand-builds
everything - like the Lua binding, its closest cousin: Secure Hash Algorithm 256-bit (SHA-256) and
SHA-512 over `uint32_t`/`uint64_t` words, an arbitrary-precision
magnitude bignum over `std::vector<uint64_t>` limbs with
`unsigned __int128` products, and Ed25519 (RFC 8032) on top of it. Slow
but correct - intended for the conformance suite and small tools,
exactly like the pure-Python original. Requires **g++ 13 or any
C++17 compiler**; compiles clean with `-Wall -Wextra`.

| Source file | Implements |
|---|---|
| `src/json.hpp/.cpp` | a shape-preserving JavaScript Object Notation (JSON) layer: a recursive-descent parser into a `JValue` tagged variant (null, bool, `int64_t`, `double`, string, array, ordered object as `std::vector<std::pair<std::string, JValue>>` - the association vector preserves insertion order and sidesteps map ordering); a numeric literal with no `.`/`e`/`E` decodes to `int64_t`, so the integer-versus-decimal distinction (`1` versus `1.0`) survives to the canonicalizer |
| `src/jcs.hpp/.cpp` | RFC 8785 (JSON Canonicalization Scheme) serialization: sorted keys, minimal bytewise string escaping (UTF-8 is bytes; only bytes < 0x20 are escaped), ECMAScript-style canonical numbers (`1.0` → `1` via exact long-double integer printing, `0.7` stays `0.7` via `std::to_chars` shortest round-trip, exponents normalized to `e-7` / `e+21`, never `e-07`) |
| `src/sha2.hpp/.cpp` | SHA-256 and SHA-512 (FIPS 180-4); both gated on the empty-string known answers by the conformance runner |
| `src/bignum.hpp/.cpp` | the arbitrary-precision magnitude layer: `std::vector<uint64_t>` limbs, `unsigned __int128` products, add/sub/cmp/mul, shift-subtract modular reduction, square-and-multiply modpow, Fermat inversion via modpow - cross-checked against Python big integers on hundreds of random operands during development |
| `src/ed25519.hpp/.cpp` | Ed25519 (RFC 8032) ported from the Python reference over the bignum: the twisted Edwards group in extended coordinates, a fast fold reduction mod 2^255-19, deterministic signing and verification; Python's floored `%` is handled by keeping every field expression non-negative (`a - b mod p` is computed as `a + p - b`); gated on the RFC 8032 TEST 1 known answer before any vector runs |
| `src/canonical.hpp/.cpp` | identity-bearing field filtering per kind and SHA-256 content-addressed `identify()` (spec/identity.md) |
| `src/schema.hpp/.cpp` | validation against the seventeen JSON Schemas in `spec/schema/` - a small interpreter for exactly the keywords those schemas use (type, const, enum, pattern, required, properties, additionalProperties, items, minItems, minLength, minimum, maximum, oneOf, local `$ref`), with `std::regex` for the schemas' simple, ECMAScript-compatible patterns |
| `src/semantics.hpp/.cpp` | the 21 semantic rules: temporal admissibility with the fixed unit constants (months = 2,629,746 s, years = 31,556,952 s), the formal conflict test, refinement validity, bridged reachability, stratal classification, the skip decision, enrichment field/shape rules, and the token-tier coherence checks |
| `src/signing.hpp/.cpp` | record-level `sign_record()` / `verify_record()` over canonical identity-bearing bytes (spec/provenance.md); a succession verifies against its predecessor key |
| `src/store.hpp/.cpp` | an in-memory conformant store: idempotent immutable puts, signed add-only records with quarantine, materialized enrichment views with contributors (canonical-entry dedup), retraction and succession lineage, the resolve minimum (label before alias), the deterministic cycle-breaking view rule (index-based removal, max-(timestamp, id) exclusion), and the stigmergy `gaps()` read with its five gap kinds - with explicit insertion-order association vectors everywhere the Python iterates dicts |
| `conformance.cpp` | the conformance runner: internal known-answer checks (RFC 8032 TEST 1, RFC 8785 basics), then all 107 vectors, mirroring `bindings/python/tests/run_conformance.py` exactly |

## Conformance

```
$ bash bindings/cpp/run_conformance.sh
...
107/107 vectors passed
causalontology-cpp is CONFORMANT to the suite (vectors frozen at specification 2.0.0).
```

The script compiles `src/*.cpp` and `conformance.cpp` with
`g++ -std=c++17 -O2 -Wall -Wextra` into a throwaway temp directory and
runs the binary. The runner locates the repository root from the
`CAUSALONTOLOGY_ROOT` environment variable when set (the script sets it),
otherwise by walking up from the working directory until it finds
`conformance/vectors`; the schemas are read from `spec/schema` under the
same root (overridable with `CAUSALONTOLOGY_SPEC`).

The vectors are frozen at specification 2.0.0 (2026-07-13): they carry
concrete identifiers, real keys, and a real verifying signature. The
harness's old normalization now simply passes frozen values through;
behavioral vectors derive deterministic keypairs from the seed
`sha256("key:" + name)`.

A `CMakeLists.txt` is provided for downstream consumers
(`add_subdirectory`, link `causalontology`); `run_conformance.sh` does
not need it.

## Thirty-second taste

```cpp
#include "src/store.hpp"
using namespace co;

InMemoryStore store(true);
JValue press = JValue::makeObject();
press.set("type", JValue::of("occurrent"));
press.set("label", JValue::of("press_button"));
press.set("category", JValue::of("action"));
JValue light = JValue::makeObject();
light.set("type", JValue::of("occurrent"));
light.set("label", JValue::of("light_on"));
light.set("category", JValue::of("state_change"));
JValue claim = JValue::makeObject();
claim.set("type", JValue::of("causal_relation_object"));
JValue causes = JValue::makeArray();
causes.array.push_back(JValue::of(store.put(press)));
JValue effects = JValue::makeArray();
effects.array.push_back(JValue::of(store.put(light)));
claim.set("causes", causes);
claim.set("effects", effects);

// the degenerate claim is a visible invitation
std::string id = store.put(claim);
size_t open_gaps = store.gaps("missing_field").size();
```

## Status

Source complete, ported line-for-line from the Python binding, and
**verified locally**: g++ 13.3 runs the suite at 107/107, the bignum layer
is cross-checked against Python big-integer arithmetic (361
random-operand cases across add/sub/mul/mod/modpow/modinv and the shift
family, zero mismatches), record signing is cross-checked
byte-for-byte against the Python binding (same seed, same record, same
identifier and signature), and the hash functions and the signature
scheme carry known-answer gates ahead of the vectors. CI runs the same
`bash bindings/cpp/run_conformance.sh` command.

License: see `LICENSE` in this directory (a copy of the repository
license) and the repository `NOTICE`.

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
| `src/schema.hpp/.cpp` | validation against the twenty-one JSON Schemas in `spec/schema/` (read at run time, and installed alongside the library - see [Using it as a library](#using-it-as-a-library)) - a small interpreter for exactly the keywords those schemas use (type, const, enum, pattern, required, properties, additionalProperties, items, minItems, minLength, minimum, maximum, oneOf, local `$ref`), with `std::regex` for the schemas' simple, ECMAScript-compatible patterns |
| `src/semantics.hpp/.cpp` | the 25 semantic rules: temporal admissibility with the fixed unit constants (months = 2,629,746 s, years = 31,556,952 s) and the dimension-disjoint ordinal tick unit, the formal conflict test, refinement validity, bridged reachability, stratal classification, the skip decision, cross-stratal seam well-formedness with the coarsest-stratum home rule, enrichment field/shape rules, and the token-tier coherence checks including the prediction-to-observation pairing |
| `src/signing.hpp/.cpp` | record-level `sign_record()` / `verify_record()` over canonical identity-bearing bytes (spec/provenance.md); a succession verifies against its predecessor key |
| `src/store.hpp/.cpp` | an in-memory conformant store: idempotent immutable puts, signed add-only records with quarantine, materialized enrichment views with contributors (canonical-entry dedup), retraction and succession lineage, the resolve minimum (label before alias), the deterministic cycle-breaking view rule (index-based removal, max-(timestamp, id) exclusion), and the stigmergy `gaps()` read with its five gap kinds - with explicit insertion-order association vectors everywhere the Python iterates dicts |
| `conformance.cpp` | the conformance runner: internal known-answer checks (RFC 8032 TEST 1, RFC 8785 basics), then all 137 vectors, mirroring `bindings/python/tests/run_conformance.py` exactly |

## Using it as a library

```
$ cmake -S bindings/cpp -B build -DCMAKE_INSTALL_PREFIX=/usr/local
$ cmake --build build
$ cmake --install build
```

The install ships the ten headers under `include/causalontology/`, the
library, the CMake package - **and the twenty-one JSON Schemas**, at
`<prefix>/share/causalontology/spec/schema/`. It ships them because
`validate_schema()` (and therefore any strict `InMemoryStore`) reads those
documents from disk at run time: a package of headers and a `.a` alone
would throw at its consumer's first validation. The schemas installed are
the repository's normative `spec/schema/*.schema.json`, copied at install
time; `bindings/cpp/` vendors no copy of its own, so there is nothing here
that can drift from the specification.

A downstream project then needs nothing from this repository:

```cmake
find_package(causalontology CONFIG REQUIRED)
target_link_libraries(app PRIVATE causalontology::causalontology)
# find_package also sets causalontology_SCHEMA_DIR, the installed schema
# directory, should your own code want the path.
```

The library looks for the schemas in exactly this order:

1. `$CAUSALONTOLOGY_SPEC/schema`, whenever that variable is set and
   non-empty. It is the operator's override, it wins over everything below,
   and it is honored by every program that links the library - the
   conformance runner included.
2. the directory given to `co::schema_set_spec_dir()`, if the program calls
   it.
3. the installed copy above, whose absolute path CMake compiles into the
   library.

There is deliberately **no repository-relative fallback**: a library that
quietly reads a checkout it happens to sit near works on the machine that
built it and nowhere else.

So if you do not take the whole repository tree, you must let the library
find the schemas one of those three ways:

- **`add_subdirectory(bindings/cpp)` without installing.** Nothing was
  installed, so lookup 3 points into a prefix that does not exist. Export
  `CAUSALONTOLOGY_SPEC=<repository root>/spec`, or call
  `co::schema_set_spec_dir("<repository root>/spec/schema")` at startup.
- **A prefix moved after installation, or `cmake --install --prefix`
  naming a different prefix from the configured one.** The compiled-in path
  is then stale: reinstall, or export
  `CAUSALONTOLOGY_SPEC=<new prefix>/share/causalontology/spec`.
- **Headers and the `.a` copied by hand into your own tree.** Copy
  `spec/schema/` too and point `CAUSALONTOLOGY_SPEC` at its parent.
- **A source tree with no `spec/schema/` beside it** (a partial export).
  Configure with `-DCAUSALONTOLOGY_SCHEMA_SOURCE_DIR=<directory holding the
  twenty-one schemas>` so the install can still ship them.

Nothing in that list fails silently. A configure whose
`CAUSALONTOLOGY_SCHEMA_SOURCE_DIR` does not hold exactly twenty-one
`*.schema.json` files stops with a `FATAL_ERROR` instead of building an
unusable package; `find_package(causalontology)` refuses an installation
whose schema directory is missing or incomplete, naming it; and at run time
the loader throws a `std::runtime_error` naming every path it tried.

## Conformance

```
$ bash bindings/cpp/run_conformance.sh
...
137/137 vectors passed
causalontology-cpp is CONFORMANT to the suite (vectors frozen at specification 4.0.0).
```

The script compiles `src/*.cpp` and `conformance.cpp` with
`g++ -std=c++17 -O2 -Wall -Wextra` into a throwaway temp directory and
runs the binary. The runner locates the repository root from the
`CAUSALONTOLOGY_ROOT` environment variable when set (the script sets it),
otherwise by walking up from the working directory until it finds
`conformance/vectors`; the runner then points the schema loader at
`spec/schema` under that same root. `CAUSALONTOLOGY_SPEC` overrides it here
as everywhere else: `CAUSALONTOLOGY_SPEC=/nowhere bash
bindings/cpp/run_conformance.sh` fails the schema-bearing vectors with
`cannot open schema /nowhere/schema/...` rather than quietly passing.

The vectors are frozen at specification 4.0.0 (2026-07-22; 137 vectors,
V01-V137): they carry concrete identifiers, real keys, and a real
verifying signature. The harness's old normalization now simply passes
frozen values through; behavioral vectors derive deterministic keypairs
from the seed `sha256("key:" + name)`.

`run_conformance.sh` compiles the sources directly and does not use
`CMakeLists.txt`; downstream consumers do, as
[Using it as a library](#using-it-as-a-library) describes.

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
**verified locally**: g++ 13.3 runs the suite at 137/137, the bignum layer
is cross-checked against Python big-integer arithmetic (361
random-operand cases across add/sub/mul/mod/modpow/modinv and the shift
family, zero mismatches), record signing is cross-checked
byte-for-byte against the Python binding (same seed, same record, same
identifier and signature), and the hash functions and the signature
scheme carry known-answer gates ahead of the vectors. CI runs the same
`bash bindings/cpp/run_conformance.sh` command.

The **installed** package is proven the same way, not assumed: `cmake
--install` into a prefix outside the repository, then a separate project
that only does `find_package(causalontology CONFIG REQUIRED)` compiles,
links, and validates an occurrent - accepting the good object and
rejecting a wrong-typed field - with the working directory outside the
repository and the repository itself bind-mounted away behind an empty
directory, so the only schemas reachable are the installed ones. The same
binary run with `CAUSALONTOLOGY_SPEC=/POISON` fails with `cannot open
schema /POISON/schema/occurrent.schema.json`, which is what makes the
override, and the proof, real.

License: see `LICENSE` in this directory (a copy of the repository
license) and the repository `NOTICE`.

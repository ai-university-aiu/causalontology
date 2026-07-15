# causalontology-lua

**The Lua binding of the Causalontology standard** - a faithful port of
[causalontology-py](../python/), sharing the same conformance suite.

**Pure Lua 5.4, zero dependencies.** Lua's standard library carries no
cryptography, so this binding implements everything itself: SHA-256 and
SHA-512 over Lua 5.4's native 64-bit integers and bitwise operators, and
Ed25519 (RFC 8032) over a small bignum layer of base-2^24 limbs. Slow but
correct - intended for the conformance suite and small tools, exactly like
the pure-Python original. Requires **Lua 5.4** (native integers, integer
division, and bitwise operators; no LuaJIT, no C modules, no rocks).

| Source file | Implements |
|---|---|
| `causalontology/json.lua` | a shape-preserving JSON layer: objects keep explicit insertion-order key lists (Lua tables have none), arrays are tagged (so `[]` and `{}` stay distinct), and a numeric literal with no `.`/`e`/`E` decodes to a Lua **integer** via `math.tointeger`, so the integer-versus-decimal distinction (`1` versus `1.0`) survives to the canonicalizer |
| `causalontology/jcs.lua` | RFC 8785 (JSON Canonicalization Scheme) serialization: sorted keys, minimal bytewise string escaping, ECMAScript-style canonical numbers (`1.0` → `1`, `0.7` stays `0.7`, `e-7` not `e-07`) |
| `causalontology/sha2.lua` | SHA-256 and SHA-512 (FIPS 180-4); SHA-512 runs in the signed 64-bit word with naturally wrapping adds and Lua's logical shifts; both gated on empty-string known answers at load |
| `causalontology/ed25519.lua` | Ed25519 (RFC 8032): a bignum layer (base-2^24 limbs, schoolbook multiplication, fold reduction mod 2^255-19, Fermat inversion), the twisted Edwards point group in extended coordinates, deterministic signing and verification; gated on the RFC 8032 TEST 1 known answer at load |
| `causalontology/canonical.lua` | identity-bearing field filtering per kind and SHA-256 content-addressed `identify()` (spec/identity.md) |
| `causalontology/schema.lua` | validation against the eight JSON Schemas in `spec/schema/` (a small interpreter for exactly the keywords those schemas use); Lua has no regex engine, so a dedicated, regex-free matcher recognizes the schemas' four anchored pattern families (fixed-length hex, prefixed 64-hex identifiers, prefix alternations, snake_case labels) and refuses anything else |
| `causalontology/semantics.lua` | the 13 semantic rules: temporal admissibility with the fixed unit constants, the formal conflict test, refinement validity, hierarchy reachability, enrichment field/shape rules |
| `causalontology/signing.lua` | record-level `sign_record()` / `verify_record()` over canonical identity-bearing bytes (spec/provenance.md); a succession verifies against its predecessor key |
| `causalontology/store.lua` | an in-memory conformant store: idempotent immutable puts, signed add-only records with quarantine, materialized enrichment views with contributors, retraction and succession lineage, the resolve minimum, the deterministic cycle-breaking view rule, and the stigmergy `gaps()` read - with explicit insertion-order arrays everywhere the Python iterates dicts, since Lua tables have no key order |
| `conformance.lua` | the conformance runner: internal known-answer checks (RFC 8032 TEST 1, RFC 8785 basics), then all 38 vectors, mirroring `bindings/python/tests/run_conformance.py` exactly |

## Conformance

```
$ lua bindings/lua/conformance.lua
...
38/38 vectors passed
causalontology-lua is CONFORMANT to the suite (vectors frozen at specification 1.0.0).
```

The runner locates the repository root from the `CAUSALONTOLOGY_ROOT`
environment variable when set, otherwise two directories above the script;
the schemas are read from `spec/schema` under the same root (overridable
with `CAUSALONTOLOGY_SPEC`).

The vectors are frozen at specification 1.0.0 (2026-07-13): they carry
concrete identifiers, real keys, and a real verifying signature. The
harness's old normalization now simply passes frozen values through.

## Thirty-second taste

```lua
local co = require("causalontology")
local json = co.json

local store = co.new_store(true)
local press = store:put(json.obj("type", "occurrent",
                                 "label", "press_button",
                                 "category", "action"))
local light = store:put(json.obj("type", "occurrent",
                                 "label", "light_on",
                                 "category", "state_change"))
local claim = store:put(json.obj("type", "causal_relation_object",
                                 "causes", json.new_array({ press }),
                                 "effects", json.new_array({ light })))

-- the degenerate claim is a visible invitation
print(claim, #store:gaps("missing_field"))
```

## Status

Source complete, ported line-for-line from the Python binding, and
**verified locally**: a Lua 5.4.7 built from source runs the suite at
38/38, the bignum layer is cross-checked against Python big-integer
arithmetic (288 random-operand and curve-intermediate cases), and both
hash functions and the signature scheme carry load-time known-answer
gates. CI runs the same `lua bindings/lua/conformance.lua` command.

Packaging: `causalontology-1.0.0-1.rockspec` (LuaRocks, zero
dependencies).

License: "The attribution always; no profit, no problem license." - see
the repository `LICENSE` and `NOTICE`.

# causalontology-zig

**The Zig binding of the Causalontology standard** — a faithful port of
[causalontology-py](../python/), sharing the same conformance suite.

**Standard library only.** Zig's std carries everything the standard needs
natively: `std.crypto.sign.Ed25519` (RFC 8032 signing and verification;
`KeyPair.create(seed)` derives keys deterministically from a 32-byte seed,
and signing with a null noise parameter is the deterministic RFC 8032
construction), `std.crypto.hash.sha2.Sha256`, and `std.json` (whose `Value`
keeps the integer-versus-decimal source distinction — `1` parses to
`.integer`, `1.0` to `.float` — so RFC 8785 number canonicalization sees
what was written). There are no dependencies in `build.zig.zon` at all.
Pinned toolchain: **Zig 0.13.0**.

| Source file | Implements |
|---|---|
| `src/jcs.zig` | RFC 8785 (JSON Canonicalization Scheme) serialization: sorted keys, minimal string escaping, ECMAScript-style canonical numbers (`1.0` → `1`, `0.7` stays `0.7`), plus the shared JSON value helpers |
| `src/canonical.zig` | identity-bearing field filtering per kind and SHA-256 content-addressed `identify()` (spec/identity.md) |
| `src/signing.zig` | record-level `signRecord()` / `verifyRecord()` over canonical identity-bearing bytes (spec/provenance.md); a succession verifies against its predecessor key |
| `src/schema.zig` | validation against the seventeen JSON Schemas in `spec/schema/` — a small interpreter for exactly the keywords those schemas use, with dedicated matchers for the three anchored pattern families instead of a regex engine |
| `src/semantics.zig` | the 21 semantic rules: temporal admissibility with the fixed unit constants (month = 2,629,746 s; year = 31,556,952 s), the formal conflict test, refinement validity, bridged reachability, stratal classification, the skip decision, enrichment field/shape rules, and the token-tier coherence checks |
| `src/store.zig` | an in-memory conformant store: idempotent immutable puts, signed add-only records with quarantine, materialized enrichment views with contributors, retraction and succession lineage, the resolve minimum, the deterministic cycle-breaking view rule, and the stigmergy `gaps()` read — every map is an insertion-ordered `StringArrayHashMap`, never a `StringHashMap` (whose iteration order is undefined), because where the Python reference iterates dicts, insertion order is normative |
| `src/causalontology.zig` | the module root re-exporting the public API |
| `conformance.zig` | the conformance runner: internal known-answer checks (RFC 8032 TEST 1, RFC 8785 basics), then all 107 vectors, mirroring `bindings/python/tests/run_conformance.py` exactly |

## Conformance

Verified locally and run by GitHub Actions CI, both through the same
entry point:

```
$ bash bindings/zig/run_conformance.sh
...
107/107 vectors passed
causalontology-zig is CONFORMANT to the suite (vectors frozen at specification 2.0.0).
```

The script uses `zig` from PATH when present; otherwise it downloads the
pinned Zig 0.13.0 release tarball to a temp-dir cache (no root needed) and
runs `zig run bindings/zig/conformance.zig` from the repository root.
`zig build conformance` (from `bindings/zig/`, with the repository root as
the working directory of the run) does the same through the build system.

The runner locates the repository root from the `CAUSALONTOLOGY_ROOT`
environment variable when set, otherwise by walking up from the working
directory until it finds `conformance/vectors`; the schemas are read from
`spec/schema` under the same root.

The vectors are frozen at specification 2.0.0 (2026-07-13): they carry
concrete identifiers, real keys, and a real verifying signature. The
harness's old normalization now simply passes frozen values through.

## Consuming the package

Zig packages are consumed by git URL + hash — the `build.zig.zon`
manifest (name `causalontology`, version `2.0.0`) is the registry story:

```
zig fetch --save https://github.com/.../causalontology.git
```

then in your `build.zig`:

```zig
const causalontology = b.dependency("causalontology", .{});
exe.root_module.addImport("causalontology", causalontology.module("causalontology"));
```

## Thirty-second taste

```zig
const co = @import("causalontology");

var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
const a = arena.allocator();

var store = co.Store.init(a, true);
var press = co.jcs.ObjectMap.init(a);
try press.put("type", .{ .string = "occurrent" });
try press.put("label", .{ .string = "press_button" });
try press.put("category", .{ .string = "action" });
const press_id = try store.put(press, null);

// the degenerate claim below is a visible invitation: gaps("missing_field")
var light = co.jcs.ObjectMap.init(a);
try light.put("type", .{ .string = "occurrent" });
try light.put("label", .{ .string = "light_on" });
try light.put("category", .{ .string = "state_change" });
const light_id = try store.put(light, null);
_ = press_id;
_ = light_id;
```

## Status

Source complete, ported line-for-line from the Python binding, and verified
locally: 107/107 vectors passed with Zig 0.13.0, with content-addressed
identifiers byte-identical to the Python binding's. CI runs the same
`run_conformance.sh` gate.

License: "The attribution always; no profit, no problem license." — see the
repository `LICENSE` (copied here) and `NOTICE`.

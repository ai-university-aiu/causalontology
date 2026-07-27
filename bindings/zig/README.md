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
| `src/canonical.zig` | identity-bearing field filtering per kind and Secure Hash Algorithm 256-bit (SHA-256) content-addressed `identify()` (spec/identity.md) |
| `src/signing.zig` | record-level `signRecord()` / `verifyRecord()` over canonical identity-bearing bytes (spec/provenance.md); a succession verifies against its predecessor key |
| `src/schema.zig` | validation against the twenty-one JSON Schemas — a small interpreter for exactly the keywords those schemas use, with dedicated matchers for the four anchored pattern families instead of a regex engine |
| `src/spec_schema.zig` + `src/spec_schema/` | the twenty-one schemas themselves, `@embedFile`d into the library so validation needs no files on disk. Generated from `spec/schema/` by `tools/sync_spec_schema.sh`; the conformance runner re-compares them against `spec/schema/` byte-for-byte whenever a copy of the specification is reachable, so drift fails the gate |
| `src/semantics.zig` | the 25 semantic rules: temporal admissibility with the fixed unit constants (month = 2,629,746 s; year = 31,556,952 s) and the dimension-disjoint ordinal tick unit, the formal conflict test, refinement validity, bridged reachability, stratal classification, the skip decision, cross-stratal seam well-formedness with the coarsest-stratum home rule, enrichment field/shape rules, and the token-tier coherence checks including the prediction-to-observation pairing |
| `src/store.zig` | an in-memory conformant store: idempotent immutable puts, signed add-only records with quarantine, materialized enrichment views with contributors, retraction and succession lineage, the resolve minimum, the deterministic cycle-breaking view rule, and the stigmergy `gaps()` read — every map is an insertion-ordered `StringArrayHashMap`, never a `StringHashMap` (whose iteration order is undefined), because where the Python reference iterates dicts, insertion order is normative |
| `src/causalontology.zig` | the module root re-exporting the public application programming interface (API) |
| `conformance.zig` | the conformance runner: internal known-answer checks (RFC 8032 TEST 1, RFC 8785 basics), then all 137 checks — 38 driven by the frozen shared vector files, 99 hand-written here — mirroring `bindings/python/tests/run_conformance.py` exactly |

## Conformance

Verified locally and run by GitHub Actions CI, both through the same
entry point:

```
$ bash bindings/zig/run_conformance.sh
...
137/137 checks passed (38 from the frozen shared vectors, 99 per-binding)
causalontology-zig is CONFORMANT to the suite (vectors frozen at specification 4.0.0).
```

The script uses `zig` from PATH when present; otherwise it downloads the
pinned Zig 0.13.0 release tarball to a temp-dir cache (no root needed) and
runs `zig run bindings/zig/conformance.zig` from the root of the tree it
lives in. `zig build conformance` (from `bindings/zig/`) does the same
through the build system. Either works inside a package fetched with `zig
fetch`, because that package carries the vectors too.

The runner finds the **vectors** by `CAUSALONTOLOGY_ROOT` when that is set,
otherwise by walking up from the working directory, otherwise by walking up
from its own executable, until it finds `conformance/vectors`. It finds the
**schemas** nowhere: they are compiled into the library, so the run tests the
artifact a consumer gets rather than a checkout that happens to be nearby.
Set `CAUSALONTOLOGY_SPEC` to validate against a specification directory on
disk instead. Whenever `spec/schema` is reachable under the root, the runner
also compares the compiled-in schemas against it byte-for-byte, in both
directions, and fails on any drift.

The shared vector files are frozen at specification 4.0.0 (2026-07-22; 137
files, V01–V137, across twenty-one object kinds). The 38 that carry an
executable payload — V01–V38 — hold concrete identifiers, real keys, and a
real verifying signature, and the harness's old normalization now simply
passes those frozen values through; V39–V137 name their check but delegate it
to this runner.

## Consuming the package

Zig has no central registry: a package is a tarball plus a hash, so the
repository-root `build.zig.zon` (name `causalontology`, version `4.0.0`) is
the registry story. Fetch the tag tarball, which records the URL and hash in
your own `build.zig.zon`:

```
zig fetch --save https://github.com/ai-university-aiu/causalontology/archive/refs/tags/v4.0.3.tar.gz
```

then in your `build.zig`:

```zig
const causalontology = b.dependency("causalontology", .{});
exe.root_module.addImport("causalontology", causalontology.module("causalontology"));
```

and validate — **no setup call, no schema files, no checkout**:

```zig
const std = @import("std");
const co = @import("causalontology");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const a = arena.allocator();

    var obj = co.jcs.ObjectMap.init(a);
    try obj.put("type", .{ .string = "continuant" });
    try obj.put("label", .{ .string = "a_continuant" });
    try obj.put("category", .{ .string = "object" });
    try obj.put("id", .{ .string = try co.identify(a, obj, null) });

    const r = try co.validateSchema(a, .{ .object = obj }, null);
    std.debug.print("valid = {}\n", .{r.ok});   // valid = true
}
```

The allocator you pass to `validateSchema` is also the one the parsed-schema
cache lives in, so use one that outlives your validations (the arena above
does).

### Where the schemas come from

The twenty-one JSON Schemas are compiled into the library with `@embedFile`
(`src/spec_schema/`), which is why the snippet above needs nothing from the
filesystem. Precedence, highest first:

1. an explicit `co.schema.setSpecDir(allocator, "/path/to/spec/schema")` —
   optional, for validating against a specification you are editing;
2. the `CAUSALONTOLOGY_SPEC` environment variable, naming a **specification
   directory** (its `schema/` subdirectory is read), the same meaning it has
   in every other binding;
3. otherwise the compiled-in copy.

`co.schema.clearSpecDir()` drops an override; `co.schema.currentSource()`
reports which of the three is in force, and the conformance runner prints it.

### What a fetched package contains

Zig's package manager prunes the downloaded tarball to the root manifest's
`.paths` before hashing and caching it, so a package contains exactly what
that list names — and nothing else, however plainly it sits in the
repository. The list first published for 4.0.0 named only `build.zig`,
`build.zig.zon`, `bindings/zig/src` and `LICENSE`: **ten files and zero
schemas**, so a fetched package could not validate anything and no amount of
reading the repository would show it. The list now also names `bindings/zig`
entire, `spec/` (including `spec/schema/`), `conformance/vectors` (all 137),
and `NOTICE`, which is **209 files, 21 schemas, 137 vectors**. Because the
file set is hashed, the corrected package has a different hash: re-run `zig
fetch --save` rather than editing the version in place.

That last part makes a fetched package self-verifying — run the gate against
the bytes you actually received, from anywhere:

```
$ zig fetch --global-cache-dir /tmp/gc \
    https://github.com/ai-university-aiu/causalontology/archive/refs/tags/v4.0.3.tar.gz
1220...                                   # the package hash it prints
$ bash /tmp/gc/p/1220.../bindings/zig/run_conformance.sh
schemas:  compiled into this build (21 schemas, no filesystem)
...
137/137 checks passed (38 from the frozen shared vectors, 99 per-binding)
causalontology-zig is CONFORMANT to the suite (vectors frozen at specification 4.0.0).
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
locally: 137/137 checks passed with Zig 0.13.0, with content-addressed
identifiers byte-identical to the Python binding's (the V136 witnesses
re-pin two frozen 3.0.0 identifiers byte-for-byte under 4.0.0). CI runs the
same `run_conformance.sh` gate.

Verified the way a consumer meets it, too: the tarball fetched with `zig
fetch`, extracted outside any checkout, run with the repository hidden behind
a mount namespace — 21 schemas present, 137/137 checks passed, and a
consumer program that imports the module and calls `validateSchema` with no
`setSpecDir` succeeds. With `CAUSALONTOLOGY_SPEC` pointed at a nonexistent
directory the same runs fail loudly, which is what proves the environment
variable is really consulted rather than quietly ignored.

License: "The attribution always; no profit, no problem license." — see the
repository `LICENSE` (copied here) and `NOTICE`.

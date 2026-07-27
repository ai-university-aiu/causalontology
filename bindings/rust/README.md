# causalontology-rust

**The fourth locally-verified implementation of the Causalontology standard —
and the WebAssembly core.**

Dependencies are the ecosystem-vetted primitives only (`sha2`,
`ed25519-dalek`, `serde_json`, `regex`) — the standard's rule is *passes all
137 checks*, and hand-rolled curve math in a systems language is a
vulnerability, not a virtue.

## The library carries its own schemas

The twenty-one JSON Schemas are embedded at compile time — `include_str!` over
the crate's own `spec_schema/` — so `cargo add causalontology` delivers them.
The crate cannot compile without them, the library opens no file at run time,
and `validate_schema` therefore works in a consumer project that has never
seen this repository. Nothing at run time can move that source: the library
reads no environment variable at all, so `CAUSALONTOLOGY_SPEC` (which points
other bindings at a checkout) is simply ignored here.

## Conformance

The suite is **137 checks**. Thirty-eight of them (V01–V38) are driven by the
standard's shared vector files; the other 99 are hand-written in this binding
and share no data with any other implementation. The shared files live in this
repository under `conformance/vectors/` and are deliberately **not** shipped
inside any published package, in any language, so the `conformance` runner has
to be pointed at them. Inside a checkout it finds them by itself:

```
$ cd bindings/rust
$ cargo run --bin conformance
causalontology-rust conformance run (specification 4.0.0)
vectors: /path/to/causalontology/conformance/vectors (from a checkout above the working directory)
...
137/137 checks passed (38 from the frozen shared vectors, 99 per-binding)
causalontology-rust is CONFORMANT to the suite (vectors frozen at specification 4.0.0).
```

### From crates.io

`cargo run --bin conformance` only works inside this repository — in a
consumer project it fails with *no bin target named `conformance`*, because
the binary belongs to a dependency, not to your package. Install the runner
instead and hand it a vectors directory:

**crates.io serves 4.0.0 today. 4.0.1 is prepared here but is not published
yet**, so `cargo install causalontology --version 4.0.1` fails with *error:
could not find `causalontology` in registry `crates-io` with version
`=4.0.1`* (checked 2026-07-27), and 4.0.0's binary panics - see below. Until
4.0.1 reaches crates.io, install the same corrected binary from a checkout:

```
$ git clone https://github.com/ai-university-aiu/causalontology
$ cargo install --path causalontology/bindings/rust
     # once 4.0.1 is published: cargo install causalontology --version 4.0.1
$ cd /any/directory/outside/the/repository
$ conformance /path/to/causalontology/conformance/vectors
causalontology-rust conformance run (specification 4.0.0)
vectors: /path/to/causalontology/conformance/vectors (from the command line)
internal checks (RFC 8032 known-answer, RFC 8785 basics) ... ok
...
137/137 checks passed (38 from the frozen shared vectors, 99 per-binding)
causalontology-rust is CONFORMANT to the suite (vectors frozen at specification 4.0.0).
```

The vectors are resolved in this order: the command-line argument, then
`CAUSALONTOLOGY_VECTORS` (a vectors directory), then `CAUSALONTOLOGY_ROOT` (a
checkout root — the variable every other binding's runner honours), then a
checkout at or above the working directory, then the repository the binary was
compiled in. The first three are explicit requests and are authoritative: if
one of them names a directory holding no vectors, the run stops there rather
than quietly testing some other copy. An incomplete directory is refused for
the same reason. The run prints the directory it actually read, so a reported
pass can be checked rather than trusted. `conformance --help` prints this
summary.

**Version 4.0.0 of this crate ships a `conformance` binary that panics** with
`vectors dir: Os { code: 2, kind: NotFound }` on first run, wherever it is
installed: it looked for the vectors at a path relative to the repository and
accepted no argument and no environment override. The 4.0.0 *library* is
unaffected and sound — the defect is confined to the test runner, and 4.0.0 is
the only version crates.io serves. Use 4.0.1 or newer once it is published;
until then build the runner from a checkout as shown above.

The shared vector files are frozen at specification 4.0.0 (2026-07-22; 137
files, V01–V137). The 38 that carry an executable payload — V01–V38 — hold
concrete identifiers, real keys, and a real verifying signature; V39–V137 name
their check but delegate it to this runner. V01–V107 are the whole-word 2.0.0
baseline; V108–V119 are the 3.0.0 additions (the tick unit, the
`cross_stratal_seam`, the conduit `realized_by`);
V120–V137 are the 4.0.0 additions (`attitude`, `predicted_occurrence`,
`prediction_error`).

## The WebAssembly core — one audited binary, every host

Because the schemas are compiled in and the library does no filesystem access,
the same audited core compiles unchanged to `wasm32-unknown-unknown` (from a
checkout, which is where the cross-check's JavaScript counterpart lives):

```
$ cd bindings/rust
$ cargo build --lib --release --target wasm32-unknown-unknown
$ node tests/wasm_check.js
...
6/6 WASM cross-checks passed
```

The cross-check instantiates the `.wasm` in Node's runtime and proves the
core agrees **byte for byte** with the independently-conformant JavaScript
binding: identical content addresses, identical RFC 8785 bytes, embedded
schema validation working inside the sandbox, and Ed25519 verification of a
record signed by the JS binding (plus rejection of the tampered copy).

Exports (`src/wasm_abi.rs`): `co_alloc` / `co_free`, `co_identify`,
`co_canonicalize`, `co_validate`, `co_verify_record` — UTF-8 JavaScript Object Notation (JSON) in,
length-prefixed UTF-8 JSON out. Any language with a WASM runtime (browsers,
edge workers, wasmtime hosts) gets the audited core without a port.

License: "The attribution always; no profit, no problem license." — see the
repository `LICENSE` and `NOTICE`.

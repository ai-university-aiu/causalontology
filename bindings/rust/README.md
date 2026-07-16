# causalontology-rust

**The fourth locally-verified implementation of the Causalontology standard —
and the WebAssembly core.**

```
cargo run --bin conformance
...
38/38 vectors passed
causalontology-rust is CONFORMANT to the suite (vectors frozen at specification 2.0.0).
```

Dependencies are the ecosystem-vetted primitives only (`sha2`,
`ed25519-dalek`, `serde_json`, `regex`) — the standard's rule is *passes all
38 vectors*, and hand-rolled curve math in a systems language is a
vulnerability, not a virtue.

## The WebAssembly core — one audited binary, every host

The eight JSON Schemas are embedded at compile time (`include_str!`), so the
library does no filesystem access at run time and compiles unchanged to
`wasm32-unknown-unknown`:

```
cargo build --lib --release --target wasm32-unknown-unknown
node tests/wasm_check.js
...
6/6 WASM cross-checks passed
```

The cross-check instantiates the `.wasm` in Node's runtime and proves the
core agrees **byte for byte** with the independently-conformant JavaScript
binding: identical content addresses, identical RFC 8785 bytes, embedded
schema validation working inside the sandbox, and Ed25519 verification of a
record signed by the JS binding (plus rejection of the tampered copy).

Exports (`src/wasm_abi.rs`): `co_alloc` / `co_free`, `co_identify`,
`co_canonicalize`, `co_validate`, `co_verify_record` — UTF-8 JSON in,
length-prefixed UTF-8 JSON out. Any language with a WASM runtime (browsers,
edge workers, wasmtime hosts) gets the audited core without a port.

License: "The attribution always; no profit, no problem license." — see the
repository `LICENSE` and `NOTICE`.

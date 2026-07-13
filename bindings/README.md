# Bindings

Per-language implementations of the Causalontology specification. Each binding
is thin: types can be generated from `../spec/schema/`; only identity
(RFC 8785 + SHA-256), the semantic rules, and Ed25519 signing are hand-written.

| Binding | Registry | Status |
|---|---|---|
| PrologAI (`co_*` packs) | github.com/ai-university-aiu/PrologAI | reference implementation |
| [causalontology-py](python/) | **[PyPI — LIVE](https://pypi.org/project/causalontology/)** (`pip install causalontology`) | **published 1.0.0 — 38/38 conformance vectors; zero dependencies** |
| [causalontology-js](javascript/) | **[npm — LIVE](https://www.npmjs.com/package/causalontology)** (`npm install causalontology`) | **published 1.0.0 — 38/38 conformance vectors; zero dependencies; TypeScript typings included** |
| [causalontology-rust](rust/) | **[crates.io — LIVE](https://crates.io/crates/causalontology)** (`cargo add causalontology`) | **published 1.0.0 — 38/38 conformance vectors; vetted primitives only** |
| [WebAssembly core](rust/) | built from the Rust crate | **available — `wasm32-unknown-unknown` build; 6/6 cross-checks against the JS binding pass locally (byte-identical ids, canonical bytes, and Ed25519 verification)** |
| [causalontology-java](java/) | **Maven Central — LIVE** (`io.github.ai-university-aiu:causalontology:1.0.0`) | **published 1.0.0 — 38/38 conformance vectors; JDK standard library only** |
| [causalontology-swift](swift/) | Swift Package Manager (publication pending) | **available — 38/38 conformance vectors pass in CI (Swift 5.10)**; one dependency (swift-crypto) |

Every binding MUST ship `../conformance/vectors/` as its own test suite and
gate releases on it. Interoperability is through shared data and the shared
store protocol — never through a Foreign Function Interface.

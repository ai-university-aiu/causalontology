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
| [causalontology-csharp](csharp/) | NuGet (publication pending) | **verified locally — 38/38**; pure-C# Ed25519, zero runtime dependencies; `dotnet pack` clean |
| [causalontology-dart](dart/) | pub.dev (publication pending) | **verified locally — 38/38**; pure-Dart crypto, zero dependencies |
| [causalontology-perl](perl/) | CPAN (publication pending) | **verified locally — 38/38 in 8.9 s**; core modules only |
| [causalontology-lua](lua/) | LuaRocks (publication pending) | **verified locally — 38/38**; pure-Lua crypto incl. a hand-built bignum layer (288/288 cross-checks vs Python) |
| [causalontology-ruby](ruby/) | RubyGems (publication pending) | source complete, stdlib only — **verified in CI** |
| [causalontology-php](php/) | Packagist (publication pending) | source complete, bundled sodium/hash only — **verified in CI** |
| [causalontology-elixir](elixir/) | Hex (publication pending) | source complete, OTP :crypto only — **verified in CI** |
| [causalontology-haskell](haskell/) | Hackage (publication pending) | source complete, GHC-bundled packages only, pure-Haskell SHA-2 + Ed25519 — **verified in CI** |
| [causalontology-r](r/) | CRAN (submission is a human-review process, stated plainly) | source complete (sodium + openssl CRAN packages) — **verified in CI** |

Every binding MUST ship `../conformance/vectors/` as its own test suite and
gate releases on it. Interoperability is through shared data and the shared
store protocol — never through a Foreign Function Interface.

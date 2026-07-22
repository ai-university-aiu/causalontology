# Bindings

Per-language implementations of the Causalontology specification. Each binding
is thin: types can be generated from `../spec/schema/`; only identity
(RFC 8785 + SHA-256), the semantic rules, and Ed25519 signing are hand-written.

> **Honest status at specification 4.0.0 (2026-07-22).** The specification is
> now 4.0.0 (twenty-one kinds, 137 vectors), and today **only the Python
> reference binding passes the full 137-vector suite**. The other eighteen
> bindings remain at the 2.0.0 code level — each genuinely passes the 107
> vectors its row states, and none has yet implemented the 3.0.0 or 4.0.0
> delta; their folded 3.0.0-plus-4.0.0 upgrade proceeds per
> [`../docs/Causalontology_4_0_0_Release_Plan.txt`](../docs/Causalontology_4_0_0_Release_Plan.txt).
> The registries likewise still carry the 2.0.0-era packages (see
> [`../PUBLISHING.md`](../PUBLISHING.md)); a binding publishes 4.0.0 only after
> it passes all 137 vectors in its own language.

| Binding | Registry | Status |
|---|---|---|
| PrologAI (`co_*` packs) | github.com/ai-university-aiu/PrologAI | reference implementation; its CI harness is gated on V01–V119 today — its 4.0.0 port (V120–V137) is pending per the release plan |
| [causalontology-py](python/) | **[PyPI — LIVE](https://pypi.org/project/causalontology/)** (`pip install causalontology==2.0.0`) | **at 4.0.0 in this repository — 137/137 conformance vectors; zero dependencies**; the published package is still 2.0.0 (1.0.0 yanked) until the 4.0.0 release plan executes |
| [causalontology-js](javascript/) | **[npm — LIVE](https://www.npmjs.com/package/causalontology)** (`npm install causalontology`) | **published 2.0.0 — 107/107 conformance vectors; zero dependencies; TypeScript typings included** (1.0.0 deprecated) |
| [causalontology-rust](rust/) | **[crates.io — LIVE](https://crates.io/crates/causalontology)** (`cargo add causalontology`) | **published 2.0.0 — 107/107 conformance vectors; vetted primitives only** (1.0.0 yanked) |
| [WebAssembly core](rust/) | built from the Rust crate | **available — `wasm32-unknown-unknown` build; 6/6 cross-checks against the JS binding pass locally (byte-identical ids, canonical bytes, and Ed25519 verification)** |
| [causalontology-java](java/) | **Maven Central — LIVE** (`io.github.ai-university-aiu:causalontology:2.0.0`) | **published 2.0.0 — 107/107 conformance vectors; JDK standard library only** |
| [causalontology-swift](swift/) | **SwiftPM — LIVE via git tag** (`from: "2.0.0"`); Swift Package Index listing submitted ([PackageList PR #14440](https://github.com/SwiftPackageIndex/PackageList/pull/14440)) | **available — 107/107 conformance vectors pass in CI (Swift 5.10)**; one dependency (swift-crypto) |
| [causalontology-csharp](csharp/) | **[NuGet — LIVE](https://www.nuget.org/packages/causalontology)** (`dotnet add package causalontology`) | **published 2.0.0 — 107/107**; pure-C# Ed25519, zero runtime dependencies (1.0.0 unlisted) |
| [causalontology-dart](dart/) | **[pub.dev — LIVE](https://pub.dev/packages/causalontology)** (`dart pub add causalontology`) | **published 2.0.0 — 107/107**; pure-Dart crypto, zero dependencies (1.0.0 retracted) |
| [causalontology-perl](perl/) | CPAN (publication pending) | **verified locally — 107/107 in 8.9 s**; core modules only |
| [causalontology-lua](lua/) | **LuaRocks — LIVE** (`luarocks install causalontology`) | **published 2.0.0 — 107/107**; pure-Lua crypto incl. a hand-built bignum layer (1.0.0 remains listed — LuaRocks has no yank) |
| [causalontology-ruby](ruby/) | **[RubyGems — LIVE](https://rubygems.org/gems/causalontology)** (`gem install causalontology`) | **published 2.0.0 — 107/107 in CI**; stdlib only (1.0.0 yanked) |
| [causalontology-php](php/) | **[Packagist — LIVE](https://packagist.org/packages/causalontology/causalontology)** (`composer require causalontology/causalontology`) | **published 2.0.0 — 107/107 in CI**; bundled sodium/hash only (mirrors git tags; earlier tags remain) |
| [causalontology-elixir](elixir/) | **[Hex — LIVE](https://hex.pm/packages/causalontology)** (`{:causalontology, "~> 2.0"}`) | **published 2.0.0 — 107/107 in CI**; OTP :crypto only (1.0.0 retired) |
| [causalontology-haskell](haskell/) | Hackage (publication pending) | source complete, GHC-bundled packages only, pure-Haskell SHA-2 + Ed25519 — **verified in CI** |
| [causalontology-r](r/) | CRAN (submission is a human-review process, stated plainly) | source complete (sodium + openssl CRAN packages) — **verified in CI** |
| [causalontology-cpp](cpp/) | source + release (vcpkg/Conan manifests welcome) | **verified locally — 107/107, zero warnings**; zero dependencies incl. a hand-built uint64-limb bignum (361/361 cross-checks vs Python) |
| [causalontology-go](go/) | **live by Go module proxy** (`go get github.com/ai-university-aiu/causalontology/bindings/go/v2@v2.0.0`) | **published 2.0.0 — 107/107**; stdlib only; `/v2` module-path suffix, import `.../bindings/go/v2/causalontology` (resolves + downloads via proxy.golang.org, sumdb-verified; v1 line deprecated + retracted at `bindings/go/v1.0.1`) |
| [causalontology-zig](zig/) | **live by git tag** — `zig fetch --save <v2.0.1 tag tarball>` then `dep.module("causalontology")` (repo-root `build.zig.zon` at `v2.0.1` exposes the module; sources under `bindings/zig/src/`) | **verified locally — 107/107**; std-lib crypto (Zig 0.13.0), insertion-ordered maps throughout |
| [causalontology-julia](julia/) | General registry (registration is a pull-request process, stated plainly) | **verified locally — 107/107**; stdlib SHA + pure-Julia Ed25519 over BigInt; byte-parity with Python |
| [causalontology-kotlin](kotlin/) | **Maven Central — LIVE** (`io.github.ai-university-aiu:causalontology-kotlin:2.0.0`, linuxX64 klib) | **published 2.0.0** — Kotlin/Native klib built via Kotlin Multiplatform (root manifest + POSIX `expect`/`actual` IO); core is the same sources verified 107/107 on Kotlin/JVM; pure Kotlin, all crypto hand-built |

Every binding MUST ship `../conformance/vectors/` as its own test suite and
gate releases on it. Interoperability is through shared data and the shared
store protocol — never through a Foreign Function Interface.

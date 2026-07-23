# Bindings

Per-language implementations of the Causalontology specification. Each binding
is thin: types can be generated from `../spec/schema/`; only identity
(RFC 8785 + SHA-256), the semantic rules, and Ed25519 signing are hand-written.

> **Honest status at specification 4.0.0 (2026-07-22).** The specification is
> now 4.0.0 (twenty-one kinds, 137 vectors), and **all nineteen bindings — the
> Python reference plus every port — now implement the folded
> 3.0.0-plus-4.0.0 delta and pass the full 137-vector suite locally**
> (C#, Dart, Elixir, Go, Haskell, Java, Julia, Kotlin, Lua, PHP, R, Ruby,
> Swift, and Zig completed their re-baseline in the second wave; JavaScript,
> Rust, Perl, and C++ in the first). Code-green is not published: **the public
> registries still carry the 2.0.0-era packages** (see
> [`../PUBLISHING.md`](../PUBLISHING.md)), and a binding publishes 4.0.0 only
> after it passes all 137 vectors installed fresh from its registry, per
> [`../docs/Causalontology_4_0_0_Release_Plan.txt`](../docs/Causalontology_4_0_0_Release_Plan.txt).
> Publication needs the owner's registry credentials; several languages inherit
> a standing human gate (CPAN/PAUSE, Hackage, CRAN, the Julia General registry,
> the C++ vcpkg/Conan Contributor License Agreements).

| Binding | Registry | Status |
|---|---|---|
| PrologAI (`co_*` packs) | github.com/ai-university-aiu/PrologAI | reference implementation; its CI harness is gated on the full 137 canonical vectors (V01–V137) via `causal_core` 1.1.0 |
| [causalontology-py](python/) | **[PyPI — LIVE](https://pypi.org/project/causalontology/)** (`pip install causalontology==2.0.0`) | **at 4.0.0 in this repository — 137/137 conformance vectors; zero dependencies**; the published package is still 2.0.0 (1.0.0 yanked) until the 4.0.0 release plan executes |
| [causalontology-js](javascript/) | **[npm — LIVE](https://www.npmjs.com/package/causalontology)** (`npm install causalontology`) | **at 4.0.0 in this repository — 137/137 conformance vectors locally; zero dependencies; TypeScript typings included**; the published package is still 2.0.0 (1.0.0 deprecated) until the 4.0.0 release plan executes |
| [causalontology-rust](rust/) | **[crates.io — LIVE](https://crates.io/crates/causalontology)** (`cargo add causalontology`) | **at 4.0.0 in this repository — 137/137 conformance vectors locally; vetted primitives only**; the published crate is still 2.0.0 (1.0.0 yanked) until the 4.0.0 release plan executes |
| [WebAssembly core](rust/) | built from the Rust crate | **at 4.0.0 — `wasm32-unknown-unknown` build; 6/6 cross-checks against the JS binding pass locally (byte-identical ids, canonical bytes, and Ed25519 verification)** |
| [causalontology-java](java/) | **Maven Central — LIVE** (`io.github.ai-university-aiu:causalontology:2.0.0`) | **at 4.0.0 in this repository — 137/137 locally; JDK standard library only**; Maven Central still carries 2.0.0 until the 4.0.0 release plan executes |
| [causalontology-swift](swift/) | **SwiftPM — LIVE via git tag** (`from: "2.0.0"`); Swift Package Index listing submitted ([PackageList PR #14440](https://github.com/SwiftPackageIndex/PackageList/pull/14440)) | **at 4.0.0 in this repository — 137/137 locally (Swift 5.10)**; one dependency (swift-crypto); SwiftPM is tag-resolved, so publication is a fresh `v4.0.0` tag once released |
| [causalontology-csharp](csharp/) | **[NuGet — LIVE](https://www.nuget.org/packages/causalontology)** (`dotnet add package causalontology`) | **at 4.0.0 in this repository — 137/137 locally**; pure-C# Ed25519, zero runtime dependencies; NuGet still carries 2.0.0 (1.0.0 unlisted) |
| [causalontology-dart](dart/) | **[pub.dev — LIVE](https://pub.dev/packages/causalontology)** (`dart pub add causalontology`) | **at 4.0.0 in this repository — 137/137 locally**; pure-Dart crypto, zero dependencies; pub.dev still carries 2.0.0 (1.0.0 retracted) |
| [causalontology-perl](perl/) | CPAN (publication pending) | **at 4.0.0 in this repository — verified locally, 137/137**; core modules only; publication still awaits the PAUSE upload |
| [causalontology-lua](lua/) | **LuaRocks — LIVE** (`luarocks install causalontology`) | **at 4.0.0 in this repository — 137/137 locally** (new `causalontology-4.0.0-1.rockspec`); pure-Lua crypto incl. a hand-built bignum layer; LuaRocks still carries 2.0.0 (no yank) |
| [causalontology-ruby](ruby/) | **[RubyGems — LIVE](https://rubygems.org/gems/causalontology)** (`gem install causalontology`) | **at 4.0.0 in this repository — 137/137 locally**; stdlib only; RubyGems still carries 2.0.0 (1.0.0 yanked) |
| [causalontology-php](php/) | **[Packagist — LIVE](https://packagist.org/packages/causalontology/causalontology)** (`composer require causalontology/causalontology`) | **at 4.0.0 in this repository — 137/137 locally**; bundled sodium/hash only; Packagist mirrors git tags, so publication is the `v4.0.0` tag |
| [causalontology-elixir](elixir/) | **[Hex — LIVE](https://hex.pm/packages/causalontology)** (`{:causalontology, "~> 2.0"}`) | **at 4.0.0 in this repository — 137/137 locally**; OTP :crypto only; Hex still carries 2.0.0 (1.0.0 retired) |
| [causalontology-haskell](haskell/) | Hackage (publication pending) | **at 4.0.0 in this repository — 137/137 locally**; GHC-bundled packages only, pure-Haskell SHA-2 + Ed25519; publication awaits the Hackage account/token gate |
| [causalontology-r](r/) | CRAN (submission is a human-review process, stated plainly) | **at 4.0.0 in this repository — 137/137 locally** (bundled `inst/schema` refreshed to the twenty-one 4.0.0 schemas); sodium + openssl; publication awaits the CRAN human review |
| [causalontology-cpp](cpp/) | source + release (vcpkg/Conan manifests welcome) | **at 4.0.0 in this repository — verified locally, 137/137, zero warnings**; zero dependencies incl. a hand-built uint64-limb bignum; the v4.0.0 release artifacts and the vcpkg/Conan Contributor License Agreement gates are still pending |
| [causalontology-go](go/) | **live by Go module proxy** (`go get github.com/ai-university-aiu/causalontology/bindings/go/v2@v2.0.0`) | **at 4.0.0 in this repository as a new `/v4` module** (`bindings/go/v4`, import `.../bindings/go/v4/causalontology`) — 137/137 locally; stdlib only; publication is the `bindings/go/v4/v4.0.0` module tag (the `/v2` module stays live; no `/v3` was ever cut) |
| [causalontology-zig](zig/) | **live by git tag** — `zig fetch --save <tag tarball>` then `dep.module("causalontology")` (repo-root `build.zig.zon` exposes the module; sources under `bindings/zig/src/`) | **at 4.0.0 in this repository — 137/137 locally** (both manifests bumped); std-lib crypto (Zig 0.13.0); publication is a fresh `v4.0.0` tag and recorded hash |
| [causalontology-julia](julia/) | General registry (registration is a pull-request process, stated plainly) | **at 4.0.0 in this repository — 137/137 locally**; stdlib SHA + pure-Julia Ed25519 over BigInt; byte-parity with Python; publication awaits the General-registry registration |
| [causalontology-kotlin](kotlin/) | **Maven Central — LIVE** (`io.github.ai-university-aiu:causalontology-kotlin:2.0.0`, linuxX64 klib) | **at 4.0.0 in this repository — 137/137 locally on Kotlin/JVM over the shared sources**; Kotlin/Native klib built via Kotlin Multiplatform; pure Kotlin, all crypto hand-built; Maven Central still carries 2.0.0 |

Every binding MUST ship `../conformance/vectors/` as its own test suite and
gate releases on it. Interoperability is through shared data and the shared
store protocol — never through a Foreign Function Interface.

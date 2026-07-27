# Bindings

Per-language implementations of the Causalontology specification. Each binding
is thin: types can be generated from `../spec/schema/`; only identity
(RFC 8785 + SHA-256), the semantic rules, and Ed25519 signing are hand-written.

> **What `137/137` actually measures (measured 2026-07-27).** It counts
> **checks, not vector files**. 38 of the 137 are driven by the frozen shared
> files in `../conformance/vectors/` — exactly V01–V38. The other 99 are
> hand-written per binding and share no data with any other implementation:
> V39–V137 carry no executable payload at all, their `operation` field reads
> literally `"see bindings/*/conformance runner"`. So cross-binding agreement is
> enforced by shared data for V01–V38, and by nineteen separate readings of the
> same prose for the rest. Quote it as `137/137 conformance checks (38 driven by
> the frozen shared vectors; 99 implemented per binding)`. Full measurement in
> [`../PUBLISHING.md`](../PUBLISHING.md) and
> [`../conformance/README.md`](../conformance/README.md).

> **Honest status at specification 4.0.0 (2026-07-22).** The specification is
> now 4.0.0 (twenty-one kinds, 137 checks), and **all nineteen bindings — the
> Python reference plus every port — now implement the folded
> 3.0.0-plus-4.0.0 delta and pass the full 137-check suite locally**
> (C#, Dart, Elixir, Go, Haskell, Java, Julia, Kotlin, Lua, PHP, R, Ruby,
> Swift, and Zig completed their re-baseline in the second wave; JavaScript,
> Rust, Perl, and C++ in the first). Code-green is not published: **the public
> registries still carry the 2.0.0-era packages** (see
> [`../PUBLISHING.md`](../PUBLISHING.md)), and a binding publishes 4.0.0 only
> after it passes all 137 checks installed fresh from its registry, per
> [`../docs/Causalontology_4_0_0_Release_Plan.txt`](../docs/Causalontology_4_0_0_Release_Plan.txt).
> Publication needs the owner's registry credentials; several languages inherit
> a standing human gate (CPAN/PAUSE, Hackage, CRAN, the Julia General registry,
> the C++ vcpkg/Conan Contributor License Agreements).

| Binding | Registry | Status |
|---|---|---|
| PrologAI (`co_*` packs) | github.com/ai-university-aiu/PrologAI | reference implementation; its CI harness is gated on the full 137 canonical vectors (V01–V137) via `causal_core` 1.1.0 |
| [causalontology-py](python/) | **[PyPI — LIVE](https://pypi.org/project/causalontology/)** (`pip install causalontology==2.0.0`) | **4.0.0 LIVE and verified** — fresh install from PyPI, 137/137; zero dependencies. The correction shipped inside the 4.0.0 release as a build-tagged wheel |
| [causalontology-js](javascript/) | **[npm — LIVE](https://www.npmjs.com/package/causalontology)** (`npm install causalontology`) | **4.0.0 LIVE and verified** — fresh install from npm, 137/137; zero dependencies; TypeScript typings included |
| [causalontology-rust](rust/) | **[crates.io — LIVE](https://crates.io/crates/causalontology)** (`cargo add causalontology`) | **4.0.0 LIVE**; vetted primitives only. Sound by construction — the schemas are compiled in with `include_str!`, proven with the repository hidden behind a mount namespace |
| [WebAssembly core](rust/) | built from the Rust crate | **at 4.0.0 — `wasm32-unknown-unknown` build; 6/6 cross-checks against the JS binding pass locally (byte-identical ids, canonical bytes, and Ed25519 verification)** |
| [causalontology-java](java/) | **Maven Central — LIVE** (`io.github.ai-university-aiu:causalontology:2.0.0`) | **4.0.0 LIVE on Maven Central and verified** — jar downloaded from repo1.maven.org, signature checked, 137/137 with only that jar on the classpath; JDK standard library only |
| [causalontology-swift](swift/) | **SwiftPM — LIVE via git tag** (`from: "2.0.0"`); Swift Package Index listing submitted ([PackageList PR #14440](https://github.com/SwiftPackageIndex/PackageList/pull/14440)) | **at 4.0.0 in this repository — 137/137 locally (Swift 5.10)**; one dependency (swift-crypto); SwiftPM is tag-resolved, so publication is a fresh `v4.0.0` tag once released |
| [causalontology-csharp](csharp/) | **[NuGet — LIVE](https://www.nuget.org/packages/causalontology)** (`dotnet add package causalontology`) | **4.0.0 LIVE and verified** — restored from api.nuget.org into an empty cache, 137/137; pure-C# Ed25519, zero runtime dependencies |
| [causalontology-dart](dart/) | **[pub.dev — LIVE](https://pub.dev/packages/causalontology)** (`dart pub add causalontology`) | **4.0.1 LIVE and verified** — resolved fresh from pub.dev, 137/137; pure-Dart crypto, zero dependencies. 4.0.0 shipped without its schemas and is **retracted** |
| [causalontology-perl](perl/) | CPAN (publication pending) | **at 4.0.0 in this repository — verified locally, 137/137**; core modules only; publication still awaits the PAUSE upload |
| [causalontology-lua](lua/) | **LuaRocks — LIVE** (`luarocks install causalontology`) | **4.0.0-1 LIVE and verified** — installed fresh from luarocks.org into an empty tree, 137/137; pure-Lua crypto incl. a hand-built bignum layer |
| [causalontology-ruby](ruby/) | **[RubyGems — LIVE](https://rubygems.org/gems/causalontology)** (`gem install causalontology`) | **4.0.0 LIVE and verified** — installed fresh from rubygems.org into an empty gem home, 137/137; stdlib only |
| [causalontology-php](php/) | **[Packagist — LIVE](https://packagist.org/packages/causalontology/causalontology)** (`composer require causalontology/causalontology`) | **LIVE on Packagist**; bundled sodium/hash only. Now vendors its own schemas rather than relying on the whole-repository archive |
| [causalontology-elixir](elixir/) | **[Hex — LIVE](https://hex.pm/packages/causalontology)** (`{:causalontology, "~> 2.0"}`) | **4.0.0 LIVE and verified** — resolved fresh from hex.pm, 137/137; OTP :crypto only |
| [causalontology-haskell](haskell/) | Hackage (publication pending) | **at 4.0.0 in this repository — 137/137 locally**; GHC-bundled packages only, pure-Haskell SHA-2 + Ed25519; publication awaits the Hackage account/token gate |
| [causalontology-r](r/) | CRAN (submission is a human-review process, stated plainly) | **at 4.0.0 in this repository — 137/137 locally** (bundled `inst/schema` refreshed to the twenty-one 4.0.0 schemas); sodium + openssl; publication awaits the CRAN human review |
| [causalontology-cpp](cpp/) | source + release (vcpkg/Conan manifests welcome) | **at 4.0.0 in this repository — verified locally, 137/137, zero warnings**; zero dependencies incl. a hand-built uint64-limb bignum; the v4.0.0 release artifacts and the vcpkg/Conan Contributor License Agreement gates are still pending |
| [causalontology-go](go/) | **live by Go module proxy** (`go get github.com/ai-university-aiu/causalontology/bindings/go/v2@v2.0.0`) | **at 4.0.0 in this repository as a new `/v4` module** (`bindings/go/v4`, import `.../bindings/go/v4/causalontology`) — 137/137 locally; stdlib only; publication is the `bindings/go/v4/v4.0.0` module tag (the `/v2` module stays live; no `/v3` was ever cut) |
| [causalontology-zig](zig/) | **live by git tag** — `zig fetch --save <tag tarball>` then `dep.module("causalontology")` (repo-root `build.zig.zon` exposes the module; sources under `bindings/zig/src/`) | **at 4.0.0 in this repository — 137/137 locally** (both manifests bumped); std-lib crypto (Zig 0.13.0); publication is a fresh `v4.0.0` tag and recorded hash |
| [causalontology-julia](julia/) | General registry (registration is a pull-request process, stated plainly) | **at 4.0.0 in this repository — 137/137 locally**; stdlib SHA + pure-Julia Ed25519 over BigInt; byte-parity with Python; publication awaits the General-registry registration |
| [causalontology-kotlin](kotlin/) | **Maven Central — LIVE** (`io.github.ai-university-aiu:causalontology-kotlin:4.0.0`, linuxX64 klib) | **4.0.0 LIVE on Maven Central**; signature checked and the 21 schemas confirmed compiled into the klib. 137/137 on Kotlin/JVM over the shared sources. Weaker proof than the others, stated plainly: the runner cannot be pointed at a published klib the way Java's can at a jar; pure Kotlin, all crypto hand-built |

Every binding MUST ship `../conformance/vectors/` as its own test suite and
gate releases on it. Interoperability is through shared data and the shared
store protocol — never through a Foreign Function Interface.

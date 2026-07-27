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
> Rust, Perl, and C++ in the first). A binding publishes 4.0.0 only after it
> passes all 137 checks installed fresh from its registry, per
> [`../docs/Causalontology_4_0_0_Release_Plan.txt`](../docs/Causalontology_4_0_0_Release_Plan.txt).
>
> **Publication state (re-verified against the live registries 2026-07-27).**
> Thirteen channels now serve 4.0.0 or later: PyPI, npm, RubyGems, Hex, NuGet,
> LuaRocks (`4.0.0-1`), Maven Central (both `causalontology` and
> `causalontology-kotlin`), crates.io, Packagist (`v4.0.3`), pub.dev (`4.0.1`;
> `4.0.0` retracted), the Go module proxy (`bindings/go/v4@v4.0.1`; `v4.0.0`
> retracted), and Swift/Zig/C++ by the `v4.0.3` git tag. Four are not published:
> CRAN (submitted 2026-07-27, awaiting review), Hackage, CPAN, and the Julia
> General registry (registration pull request blocked on a reviewer objection).
> Those four inherit a standing human gate, as do the C++ vcpkg/Conan
> Contributor License Agreements. Per-channel detail is in
> [`../PUBLISHING.md`](../PUBLISHING.md).

| Binding | Registry | Status |
|---|---|---|
| PrologAI (`co_*` packs) | github.com/ai-university-aiu/PrologAI | reference implementation; its CI harness is gated on all 137 conformance checks (V01–V137 — 38 driven by the frozen shared vectors, 99 implemented there) via `causal_core` 1.1.0 |
| [causalontology-py](python/) | **[PyPI — LIVE](https://pypi.org/project/causalontology/)** (`pip install causalontology` - serves 4.0.0) | **4.0.0 LIVE and verified** — fresh install from PyPI, 137/137; zero dependencies. The correction shipped inside the 4.0.0 release as a build-tagged wheel |
| [causalontology-js](javascript/) | **[npm — LIVE](https://www.npmjs.com/package/causalontology)** (`npm install causalontology`) | **4.0.0 LIVE and verified** — fresh install from npm, 137/137; zero dependencies; TypeScript typings included |
| [causalontology-rust](rust/) | **[crates.io — LIVE](https://crates.io/crates/causalontology)** (`cargo add causalontology`) | **4.0.0 LIVE**; vetted primitives only. Sound by construction — the schemas are compiled in with `include_str!`, proven with the repository hidden behind a mount namespace. **`Cargo.toml` here reads 4.0.1 and crates.io serves 4.0.0**: 4.0.1 corrects the `conformance` *binary* (4.0.0's panicked on first run) and is prepared but not yet published, so `cargo install causalontology --version 4.0.1` fails today. The 4.0.0 library is unaffected |
| [WebAssembly core](rust/) | built from the Rust crate | **at 4.0.0 — `wasm32-unknown-unknown` build; 6/6 cross-checks against the JS binding pass locally (byte-identical ids, canonical bytes, and Ed25519 verification)** |
| [causalontology-java](java/) | **Maven Central — LIVE** (`io.github.ai-university-aiu:causalontology:4.0.0`) | **4.0.0 LIVE on Maven Central and verified** — jar downloaded from repo1.maven.org, signature checked, 137/137 with only that jar on the classpath; JDK standard library only |
| [causalontology-swift](swift/) | **SwiftPM — LIVE via git tag** (`.package(url: "https://github.com/ai-university-aiu/causalontology", from: "4.0.3")`); Swift Package Index listing submitted ([PackageList PR #14440](https://github.com/SwiftPackageIndex/PackageList/pull/14440)) | **4.0.0 LIVE by the `v4.0.3` tag — 137/137 locally**; one dependency (swift-crypto). SwiftPM is tag-resolved, so the tag *is* the release; the root `Package.swift` exposes the library product and the conformance runner stays in `bindings/swift/Package.swift` |
| [causalontology-csharp](csharp/) | **[NuGet — LIVE](https://www.nuget.org/packages/causalontology)** (`dotnet add package causalontology`) | **4.0.0 LIVE and verified** — restored from api.nuget.org into an empty cache, 137/137; pure-C# Ed25519, zero runtime dependencies |
| [causalontology-dart](dart/) | **[pub.dev — LIVE](https://pub.dev/packages/causalontology)** (`dart pub add causalontology`) | **4.0.1 LIVE and verified** — resolved fresh from pub.dev, 137/137; pure-Dart crypto, zero dependencies. 4.0.0 shipped without its schemas and is **retracted** |
| [causalontology-perl](perl/) | CPAN (publication pending) | **at 4.0.0 in this repository — verified locally, 137/137**; core modules only; publication still awaits the PAUSE upload |
| [causalontology-lua](lua/) | **LuaRocks — LIVE** (`luarocks install causalontology`) | **4.0.0-1 LIVE and verified** — installed fresh from luarocks.org into an empty tree, 137/137; pure-Lua crypto incl. a hand-built bignum layer |
| [causalontology-ruby](ruby/) | **[RubyGems — LIVE](https://rubygems.org/gems/causalontology)** (`gem install causalontology`) | **4.0.0 LIVE and verified** — installed fresh from rubygems.org into an empty gem home, 137/137; stdlib only |
| [causalontology-php](php/) | **[Packagist — LIVE](https://packagist.org/packages/causalontology/causalontology)** (`composer require causalontology/causalontology`) | **LIVE on Packagist at `v4.0.3`** (Packagist reads the repository-root `composer.json` and takes its versions from git tags, so the tag is the release); bundled sodium/hash only. Now vendors its own schemas rather than relying on the whole-repository archive |
| [causalontology-elixir](elixir/) | **[Hex — LIVE](https://hex.pm/packages/causalontology)** (`{:causalontology, "~> 4.0"}`) | **4.0.0 LIVE and verified** — resolved fresh from hex.pm, 137/137; OTP :crypto only |
| [causalontology-haskell](haskell/) | Hackage (publication pending) | **at 4.0.0 in this repository — 137/137 locally**; GHC-bundled packages only, pure-Haskell SHA-2 + Ed25519; publication awaits the Hackage account/token gate |
| [causalontology-r](r/) | CRAN (submission is a human-review process, stated plainly) | **at 4.0.0 in this repository — 137/137 locally** (bundled `inst/schema` refreshed to the twenty-one 4.0.0 schemas); sodium + openssl. **Submitted to CRAN 2026-07-27 and awaiting review**; not yet on cran.r-project.org |
| [causalontology-cpp](cpp/) | source + release by git tag (vcpkg/Conan manifests welcome) | **4.0.0 LIVE by the `v4.0.3` tag — verified locally, 137/137, zero warnings**; zero dependencies incl. a hand-built uint64-limb bignum; the vcpkg/Conan Contributor License Agreement gates are still pending |
| [causalontology-go](go/) | **live by Go module proxy** (`go get github.com/ai-university-aiu/causalontology/bindings/go/v4@v4.0.1`) | **4.0.0 LIVE as the `/v4` module** (`bindings/go/v4`, import `.../bindings/go/v4/causalontology`) — proxy serves `v4.0.1`; **`v4.0.0` shipped without the schemas and is retracted in `go.mod`**; 137/137 from the installed binary; stdlib only (the `/v2` module stays live at 2.0.0, 107 checks; no `/v3` was ever cut) |
| [causalontology-zig](zig/) | **live by git tag** — `zig fetch --save https://github.com/ai-university-aiu/causalontology/archive/refs/tags/v4.0.3.tar.gz` then `dep.module("causalontology")` (repo-root `build.zig.zon` exposes the module; sources under `bindings/zig/src/`) | **4.0.0 LIVE by the `v4.0.3` tag — 137/137 run against the fetched tarball itself**; std-lib crypto (Zig 0.13.0). `zig fetch` prunes to the root manifest's `.paths`, so that list is the release: it now delivers 209 files, the 21 schemas and all 137 vectors |
| [causalontology-julia](julia/) | General registry (registration is a pull-request process, stated plainly) | **at 4.0.0 in this repository — 137/137 locally**; stdlib SHA + pure-Julia Ed25519 over BigInt; byte-parity with Python. **The General-registry registration pull request is blocked on a reviewer objection**; `pkg> add Causalontology` does not resolve yet |
| [causalontology-kotlin](kotlin/) | **Maven Central — LIVE** (`io.github.ai-university-aiu:causalontology-kotlin:4.0.0`, linuxX64 klib) | **4.0.0 LIVE on Maven Central**; signature checked and the 21 schemas confirmed compiled into the klib. 137/137 on Kotlin/JVM over the shared sources. Weaker proof than the others, stated plainly: the runner cannot be pointed at a published klib the way Java's can at a jar; pure Kotlin, all crypto hand-built |

Every binding MUST ship `../conformance/vectors/` as its own test suite and
gate releases on it. Interoperability is through shared data and the shared
store protocol — never through a Foreign Function Interface.

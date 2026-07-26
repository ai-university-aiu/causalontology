# Publishing Causalontology

This page records, honestly, what is live at which version and what still
awaits an account, a registrar, or a human review. No registry credential
beyond the two named below is stored on the build machine, by design.

Status here is re-verified against the live registries, not self-reported.

> **Specification 4.0.0 note (updated 2026-07-26).** The specification in this
> repository is **4.0.0** — twenty-one object kinds, 137 conformance vectors —
> and **4.0.0 publication began on 2026-07-26 with the owner's explicit,
> per-act go-ahead**: crates.io, pub.dev, and PyPI now carry 4.0.0, and the fresh
> tags `v4.0.1` and `bindings/go/v4/v4.0.0` are pushed (the original `v4.0.0`
> tag still pins the specification-freeze commit `64b1d1a` and was not moved).
> A binding moves into a "Live at 4.0.x" table below only after a fresh
> install from its own channel passes all 137 vectors. The remaining
> registries proceed per
> [`docs/Causalontology_4_0_0_Release_Plan.txt`](docs/Causalontology_4_0_0_Release_Plan.txt).

## Live at 4.0.0 — package registries (published 2026-07-26)

| Registry | Consume with | Fresh-install proof |
|---|---|---|
| crates.io | `cargo add causalontology` | 4.0.0 published; a clean `cargo new` project added the crate from the registry and passed 137/137 (2026-07-26). 2.0.0 remains; 1.0.0 stays yanked |
| pub.dev | `dart pub add causalontology` | 4.0.0 published; a clean package resolved 4.0.0 from the registry and passed 137/137 (2026-07-26). 2.0.0 remains; 1.0.0 stays retracted |
| PyPI | `pip install causalontology` | 4.0.0 published with the owner's explicitly named go-ahead; a brand-new virtual environment installed 4.0.0 fresh from PyPI and passed 137/137 (2026-07-26). 2.0.0 remains; 1.0.0 stays yanked |

## Live at 4.0.x — git-tag channels (tags `v4.0.1` and `bindings/go/v4.0.0`, pushed 2026-07-26)

| Channel | Consume with | Fresh proof |
|---|---|---|
| Swift Package Manager | `.package(url: "https://github.com/ai-university-aiu/causalontology", from: "4.0.1")` | a fresh clone at `v4.0.1` built and passed 137/137, and a stub package resolved the dependency at exactly `4.0.1` through Swift Package Manager itself, built, and imported the library (2026-07-26). Swift Package Index listing: [PackageList PR #14440](https://github.com/SwiftPackageIndex/PackageList/pull/14440) (merge pending) |
| Zig | `zig fetch --save https://github.com/ai-university-aiu/causalontology/archive/refs/tags/v4.0.1.tar.gz`, then `dep.module("causalontology")` | pinned package hash `12207a70aedf8b9c39e929a0ce2b34dbd04a334ece6590b70fdd3fb34c7dcfe98d6f` (printed by `zig fetch`, 2026-07-26); the tag tree passed 137/137 fresh |
| Packagist (PHP) | `composer require causalontology/causalontology:^4.0` | the Packagist webhook mirrored `v4.0.1` automatically on the tag push (verified on the live index, 2026-07-26); the tag tarball passed 137/137 fresh, and the literal `composer require` spot-check closed the same day: a freshly fetched `composer.phar` installed `causalontology/causalontology` 4.0.1 from Packagist into a clean project and the vendor tree passed 137/137 |
| C++ source tarball | the [`v4.0.1` archive](https://github.com/ai-university-aiu/causalontology/archive/refs/tags/v4.0.1.tar.gz) | `bindings/cpp/run_conformance.sh` from the freshly downloaded tarball passed 137/137 (2026-07-26). The vcpkg and Conan ports stay CLA-gated below |
| Go modules / pkg.go.dev | `go get github.com/ai-university-aiu/causalontology/bindings/go/v4@v4.0.0`, then import `.../bindings/go/v4/causalontology` | the correctly named tag `bindings/go/v4.0.0` pushed 2026-07-26 with the owner's explicitly named go-ahead (the module lives in the major-version subdirectory `bindings/go/v4`, so the tag prefix drops the folder's `/v4` suffix); the module proxy resolved `v4.0.0` on the prime, and the conformance runner fetched **fresh from proxy.golang.org** (`go run .../bindings/go/v4/conformance@v4.0.0` in a clean directory) passed 137/137. The `/v2` module stays live for 2.0.x; the v1 line remains deprecated and self-retracted at `bindings/go/v1.0.1`; the earlier `bindings/go/v4/v4.0.0` tag is never consulted and remains harmless |

The `v4.0.1` tag push also triggered the release workflow, which built and
attached the GitHub Release artifacts automatically.

## Live at 2.0.0 — package registries awaiting their 4.0.0 publication

| Registry | Consume with | 1.0.0 disposition |
|---|---|---|
| npm | `npm install causalontology` | 1.0.0 deprecated |
| Maven Central (Java) | `io.github.ai-university-aiu:causalontology:2.0.0` | immutable; 1.0.0 remains |
| Maven Central (Kotlin/Native klib) | `io.github.ai-university-aiu:causalontology-kotlin:2.0.0` (linuxX64) | immutable; 1.0.0 remains |
| NuGet | `dotnet add package causalontology` | 1.0.0 unlisted |
| RubyGems | `gem install causalontology` | 1.0.0 yanked |
| Hex | `{:causalontology, "~> 2.0"}` | 1.0.0 retired (deprecated) |
| LuaRocks | `luarocks install causalontology` | no yank; 1.0.0-1 remains listed |

## Still pending — accounts, registrars, or human review

None of these is blocked on this repository; each awaits a third party or an
account action.

| Registry | Binding | What remains |
|---|---|---|
| Hackage | haskell | The sdist is built and passes `cabal check`. Needs a Hackage account + upload token, then `cabal upload --publish <sdist>`. |
| CPAN | perl | The dist tarball is built. The Perl Authors Upload Server (PAUSE) has no application programming interface (API) token; upload via the web form at pause.perl.org. |
| CRAN | r | **Ready for web-form submission.** Caveat 6c resolved: `signing.R` uses the `openssl` R package for Ed25519 (Imports, not the CLI). The export surface is a documented 22-function public API (`man/*.Rd` with runnable examples), the 17 JSON Schemas are bundled under `inst/schema` so the package works standalone, and `R CMD check --as-cran` passes with only the standard "New submission" NOTE (no WARNINGs, no ERRORs); conformance stays 107/107. Remaining is human-only: submit the built tarball at cran.r-project.org/submit.html. |
| Julia General | julia | Registration PR [General #161292](https://github.com/JuliaRegistries/General/pull/161292) is open but under contested human review; a 2.0.0 registration follows once it merges. |
| vcpkg (C++) | cpp | Port PR [microsoft/vcpkg #52892](https://github.com/microsoft/vcpkg/pull/52892), updated to 2.0.1. Blocked only on the owner's Microsoft Contributor License Agreement (comment `@microsoft-github-policy-service agree` on the PR). |
| Conan (C++) | cpp | Recipe PR [conan-io/conan-center-index #30612](https://github.com/conan-io/conan-center-index/pull/30612), updated to 2.0.1. Blocked only on signing the Contributor License Agreement at the cla-assistant link on the PR. |

## Reach beyond the direct installs

Kotlin, Scala, Clojure, and Groovy consume the Java artifact from Maven Central
as-is. Deno and Bun consume the npm package directly. Any WebAssembly host
(browsers, edge workers, wasmtime embeddings) can use the WASM core attached to
the GitHub release.

## Verify any artifact

Every published binding embeds or reads the same schemas and passed the same
107 frozen vectors of its 2.0.0 release; the conformance workflow re-proves the
binding gates on every push. To verify the current tree locally (specification
4.0.0 — the reference gate is now the full 137-vector suite), after
`source ~/toolchains/env.sh`:

```
python3 bindings/python/tests/run_conformance.py
```

The runner exits zero only on 137/137.

Maven Central artifacts are GPG-signed; see [SECURITY.md](SECURITY.md) for the
project's OpenPGP fingerprint and how to verify.

## Fetch and verify a commons snapshot (Phase two of Part 21)

The commons itself — not just the code — is published as signed snapshot dumps:
a deterministic, content-addressed bag of objects and provenance records,
committed by a Merkle root and signed with the genesis node's Ed25519 key, plus
a detached Secure Hash Algorithm 256-bit (SHA-256) checksum and signature. A dump is four files
(`*.snapshot.ndjson`, `*.snapshot.manifest.json`, `*.snapshot.sha256`,
`*.snapshot.sig`); real dumps are distributed off-repo (a GitHub Release
payload, InterPlanetary File System (IPFS), BitTorrent, or plain Hypertext Transfer Protocol Secure (HTTPS)), and a small worked example lives in
`dumps/example/`. To verify a dump end to end — no store required — and then
stand up a mirror:

```
# offline check: manifest signature, Merkle root, every hash and signature
python3 store/server/snapshot_import.py --dir dumps --verify-only

# the detached checksum is a plain sha256sum file
cd dumps && sha256sum -c commons.snapshot.sha256

# mirror it into a fresh node by verified, idempotent union-merge
python3 store/server/snapshot_import.py --dir dumps --db mirror.db
```

Pin a publisher you trust with `--trust ed25519:<hex>`. The token tier is
excluded from a default snapshot for privacy. Full format:
[`spec/snapshot.md`](spec/snapshot.md).

## Release mechanics

- Git tags drive the tag channels: `vX.Y.Z` for SwiftPM/Zig and the source
  release; `bindings/go/vX.Y.Z` for the Go module.
- GitHub Releases carry the built artifacts (wheel, sdist, npm tarball, crate,
  and the WebAssembly core). See [CHANGELOG.md](CHANGELOG.md) for what each
  release contains.
- The Maven build recipe (JDK, GPG-signed bundle, the Central Publisher Portal
  API) and the Kotlin Multiplatform klib build are recorded in the repository
  history and the `bindings/kotlin/build.gradle.kts` manifest.
- A tag push also triggers [`.github/workflows/release.yml`](.github/workflows/release.yml),
  which builds the artifacts and creates the GitHub Release.

Name-collision note: if the bare name `causalontology` is ever unavailable on a
new registry, publish under the organization scope and record the chosen name in
[bindings/README.md](bindings/README.md).

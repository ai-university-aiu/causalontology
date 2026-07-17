# Publishing Causalontology 2.0.0

The 107 vectors are frozen; every artifact below was built from the frozen tree
and verified by the conformance suite. This page records, honestly, what is live
at 2.0.0 and what still awaits an account, a registrar, or a human review. No
registry credential is stored on the build machine, by design.

Status here is re-verified against the live registries, not self-reported.

## Live at 2.0.0 — package registries

| Registry | Consume with | 1.0.0 disposition |
|---|---|---|
| PyPI | `pip install causalontology` | 1.0.0 yanked |
| npm | `npm install causalontology` | 1.0.0 deprecated |
| crates.io | `cargo add causalontology` | 1.0.0 yanked |
| Maven Central (Java) | `io.github.ai-university-aiu:causalontology:2.0.0` | immutable; 1.0.0 remains |
| Maven Central (Kotlin/Native klib) | `io.github.ai-university-aiu:causalontology-kotlin:2.0.0` (linuxX64) | immutable; 1.0.0 remains |
| NuGet | `dotnet add package causalontology` | 1.0.0 unlisted |
| RubyGems | `gem install causalontology` | 1.0.0 yanked |
| Hex | `{:causalontology, "~> 2.0"}` | 1.0.0 retired (deprecated) |
| LuaRocks | `luarocks install causalontology` | no yank; 1.0.0-1 remains listed |
| Packagist | `composer require causalontology/causalontology` | mirrors git tags; v1.x remain |
| pub.dev | `dart pub add causalontology` | 1.0.0 retracted |

## Live at 2.0.x — git-tag channels (no registry)

| Channel | Consume with | Notes |
|---|---|---|
| Swift Package Manager | `.package(url: "https://github.com/ai-university-aiu/causalontology", from: "2.0.0")` | resolves to `v2.0.1`; `Package.swift` is valid at the tag. Swift Package Index listing: [PackageList PR #14440](https://github.com/SwiftPackageIndex/PackageList/pull/14440) (merge pending) |
| Go modules / pkg.go.dev | `go get github.com/ai-university-aiu/causalontology/bindings/go/v2@v2.0.0` | the `/v2` module (Go major-version rule); import `.../bindings/go/v2/causalontology`. The v1 line is deprecated and self-retracted at `bindings/go/v1.0.1`. pkg.go.dev has indexed the `/v2` module |
| Zig | `zig fetch --save https://github.com/ai-university-aiu/causalontology/archive/refs/tags/v2.0.1.tar.gz`, then `dep.module("causalontology")` | the repository-root `build.zig.zon` at `v2.0.1` enables the clean flow; the pin hash reproduces via `zig fetch` |

## Still pending — accounts, registrars, or human review

None of these is blocked on this repository; each awaits a third party or an
account action.

| Registry | Binding | What remains |
|---|---|---|
| Hackage | haskell | The sdist is built and passes `cabal check`. Needs a Hackage account + upload token, then `cabal upload --publish <sdist>`. |
| CPAN | perl | The dist tarball is built. The Perl Authors Upload Server (PAUSE) has no API token; upload via the web form at pause.perl.org. |
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

Every binding embeds or reads the same schemas and passes the same 107 frozen
vectors; the conformance workflow re-proves all nineteen binding gates on every
push. To verify locally, after `source ~/toolchains/env.sh`:

```
python3 bindings/python/tests/run_conformance.py
```

Maven Central artifacts are GPG-signed; see [SECURITY.md](SECURITY.md) for the
project's OpenPGP fingerprint and how to verify.

## Fetch and verify a commons snapshot (Phase two of Part 21)

The commons itself — not just the code — is published as signed snapshot dumps:
a deterministic, content-addressed bag of objects and provenance records,
committed by a Merkle root and signed with the genesis node's Ed25519 key, plus
a detached SHA-256 checksum and signature. A dump is four files
(`*.snapshot.ndjson`, `*.snapshot.manifest.json`, `*.snapshot.sha256`,
`*.snapshot.sig`); real dumps are distributed off-repo (a GitHub Release
payload, IPFS, BitTorrent, or plain HTTPS), and a small worked example lives in
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

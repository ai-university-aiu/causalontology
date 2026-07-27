# Publishing Causalontology

This page records, honestly, what is live at which version and what still
awaits an account, a registrar, or a human review. No registry credential
beyond the two named below is stored on the build machine, by design.

Status here is re-verified against the live registries, not self-reported — and
on 2026-07-26 that re-verification was itself found to be unsound. The
correction is the next thing on this page, not a footnote.

> **Specification 4.0.0 note (updated 2026-07-26).** The specification in this
> repository is **4.0.0** — twenty-one object kinds, 137 conformance vectors —
> and **4.0.0 publication began on 2026-07-26 with the owner's explicit,
> per-act go-ahead**. The fresh tags `v4.0.1` and `bindings/go/v4.0.0` are
> pushed (the original `v4.0.0` tag still pins the specification-freeze commit
> `64b1d1a` and was not moved). The remaining registries proceed per
> [`docs/Causalontology_4_0_0_Release_Plan.txt`](docs/Causalontology_4_0_0_Release_Plan.txt).

## What went wrong on 2026-07-26, plainly

Three things, in order.

**The schemas were never packaged.** Every binding except Rust found the
twenty-one JSON Schemas at a path *relative to a repository checkout* —
`Path(__file__).parents[3]/'spec'/'schema'` in Python, `path.join(__dirname,
'..', '..', 'spec', 'schema')` in JavaScript, the same shape everywhere else —
and shipped no copy of its own. Inside a checkout that path exists. Inside an
installed package it does not. So the first `validate` call a real consumer
made failed with file-not-found.

**The conformance runners shadowed the artifact.** Each runner reached the
binding by relative path — `sys.path.insert`, `require('../causalontology.js')`,
`require_relative`, `import '../lib/...'` — so a run advertised as a fresh
install actually exercised the repository source sitting next to it. The
schemas it then read were the repository's own. Nothing about the package was
under test.

**Therefore the earlier proofs on this page were false.** Every
"fresh install 137/137" claim for a package registry measured the build
machine. It was not a rounding error or an optimistic reading; the number was
produced by code that could not have detected the defect. Installed for real,
the published Python wheel scores **62/137** — it contains eleven files and not
one schema — a clean Dart consumer outside a checkout throws `cannot locate
spec/schema` on its first validate, and the Go module, which ships only its own
subdirectory, delivers no `spec/schema` by `go get` at all.

**What replaced them.** Every binding that goes out through a package registry
now carries its own byte-for-byte copy of the twenty-one schemas inside that
package and prefers that copy over the repository path; `CAUSALONTOLOGY_SPEC`
still overrides both. Where the package format allows it the schemas are
compiled in rather than shipped as loose files — Rust `include_str!`, Go
`go:embed`, generated source for Dart and Kotlin — because a compiled-in copy
cannot be dropped by a packaging manifest. Fourteen bindings vendor or compile
in a copy; the five that do not (C++, Julia, PHP, Swift, Zig) reach their
consumers as the whole repository tree, and that is now stated wherever they are
listed rather than left to be inferred.

A binding enters a "Live" table below only on a run with
`CAUSALONTOLOGY_TEST_INSTALLED=1`, `CAUSALONTOLOGY_SPEC` unset, from a directory
outside the checkout, against the artifact installed into a clean location. The
runner prints the path it loaded and the directory it read schemas from, and
aborts if either lies inside the repository. Thirteen of the fourteen runners
also carry a byte-for-byte drift guard against `spec/schema`; Rust's does not
and needs none, since a Rust crate missing a schema fails to compile. The
`conformance` workflow now gates both modes on every push and re-checks every
vendored copy against `spec/schema` in a job of its own, so a binding that stops
shipping its schemas fails the build rather than the user. The full account is
in
[`docs/Causalontology_4_0_0_Release_Plan.txt`](docs/Causalontology_4_0_0_Release_Plan.txt).

## What to publish where, and at which version

The owner's rule, decided 2026-07-26 after the correction above: **a channel
whose published artifact is broken and immutable is superseded at 4.0.1; a
channel never published at 4.x ships 4.0.0 correctly the first time.** Nothing
is renumbered for tidiness. The consequence is that package versions no longer
all read the same across channels while every one of them implements
specification **4.0.0** — the specification version and the package version are
allowed to differ, and the 137 vectors are the thing that must not.

| Channel | Binding | Published now | Sound? | Version to publish | Why |
|---|---|---|---|---|---|
| crates.io | rust | 4.0.0 | yes | **none — 4.0.0 stands** | schemas compiled in with `include_str!`; the crate cannot build without them. Nothing to supersede |
| PyPI | python | **4.0.0 LIVE and CORRECT** | **yes** | **done 2026-07-27** | the correction shipped **inside the existing 4.0.0 release** as `causalontology-4.0.0-1-py3-none-any.whl`, and the two defective files were then deleted. Release 4.0.0 now holds exactly one file. `pip install causalontology==4.0.0` into a clean virtual environment resolves the build-tagged wheel unprompted, delivers all 21 schemas, and scores **137/137** with `CAUSALONTOLOGY_SPEC` poisoned then stripped, from outside any checkout. `validate_schema` returns `(True, [])` where this morning it raised `FileNotFoundError`. Permanent consequence, accepted deliberately: 4.0.0 can never carry an sdist again, so `--no-binary` at exactly 4.0.0 now fails loudly with *No matching distribution found* rather than silently installing a package that cannot validate |
| pub.dev | dart | 4.0.0 | **no** | **4.0.1** | same defect; a pub.dev version is immutable. Retract 4.0.0 as a separate act |
| Go module proxy | go (`bindings/go/v4`) | v4.0.0 | **no** | **v4.0.1**, tag `bindings/go/v4.0.1` | the published module zip carries no schemas, and module-proxy versions are immutable and cached forever — they cannot be deleted, only retracted. `retract v4.0.0` is already in `go.mod`, and takes effect only once v4.0.1 is published |
| Packagist | php | 4.0.1 (tag `v4.0.1`) | yes | **none — v4.0.1 stands** | Composer's dist archive is the whole repository, so `spec/schema` is delivered; verified by an actual `composer require` into a clean project |
| Swift Package Manager | swift | tag `v4.0.1` | yes | **none — `v4.0.1` stands** | a tag delivers the whole tree; `spec/schema` arrives with the sources |
| Zig | zig | tag `v4.0.1` | yes, with a caveat | **none — `v4.0.1` stands** | the library has no default schema path and fails loudly; the consumer supplies one. See the caveat in the tag-channel table — `build.zig.zon` does not list `spec/` among its `.paths` |
| C++ source tarball | cpp | tag `v4.0.1` | yes, with a caveat | **none — `v4.0.1` stands** | same: no default path, no silent failure; the tarball carries `spec/schema` for anyone who points at it |
| npm | javascript | **4.0.0 LIVE** | **yes** | **done 2026-07-27** | published and proved: `npm install causalontology@4.0.0` into an empty directory delivers the 21 schemas under `spec/schema/`, and the installed package scored **137/137** with `CAUSALONTOLOGY_SPEC` first poisoned then stripped, from outside any checkout. Registry shasum `953f69a4`, licence indexed as `Apache-2.0` |
| RubyGems | ruby | 2.0.0 | n/a | **4.0.0** | never published at 4.x; the gem vendors the schemas and the gemspec refuses to build without them |
| Hex | elixir | 2.0.0 | n/a | **4.0.0** | never published at 4.x; the schemas ship in `priv/schema` and `mix.exs` lists `priv` |
| NuGet | csharp | 2.0.0 | n/a | **4.0.0** | never published at 4.x; the schemas are embedded resources in the assembly *and* packed as content files |
| LuaRocks | lua | 2.0.0 | n/a | **4.0.0-1** | never published at 4.x; the rockspec installs the schemas as module paths. Note the separate rockspec fix: without `source.dir` the published rockspec could never have built from its declared source at all |
| Maven Central (Java) | java | 2.0.0 | n/a | **4.0.0** | never published at 4.x; the schemas are jar resources under `schema/` |
| Maven Central (Kotlin klib) | kotlin | 2.0.0 | n/a | **4.0.0** | never published at 4.x; the schemas are compiled into the klib as generated source |
| CPAN | perl | not published at 4.x | n/a | **4.0.0** | first 4.x release; the distribution installs the schemas beside the modules, and `MANIFEST` is checked against `spec/schema` |
| CRAN | r | not published at 4.x | n/a | **4.0.0** | first 4.x release; the schemas ship under `inst/schema` and `R CMD check` now fails if they stop shipping |
| Hackage | haskell | not published at 4.x | n/a | **4.0.0** | first 4.x release; the schemas are Cabal `data-files`, present in the sdist and in the installed store |
| Julia General | julia | not published at 4.x | n/a | **4.0.0** | first 4.x release; registration delivers the whole repository, so `spec/schema` arrives with the code |

Two acts remain per broken channel and each needs the owner's separately named
go-ahead. For pub.dev and the Go proxy the acts are: publish the superseding
version, then retract the broken one. Retraction is not deletion — a retracted
Go version is still downloadable — so the superseding release is the fix and the
retraction is only a signpost.

PyPI is deliberately different, on the owner's instruction of 2026-07-26 that
the release ship as 4.0.0 wherever that is possible. There the acts are: delete
the two broken 4.0.0 files, then upload the build-tagged wheel into the same
4.0.0 release. This is the only channel of the three where the string 4.0.0 can
be made to serve correct code, because it is the only one whose release format
holds more than one file. It buys that at the cost of an sdist that can never
exist again, and it must happen before 2026-08-09.

## Live at 4.0.0 — package registries (published 2026-07-26)

| Registry | Consume with | Fresh-install proof |
|---|---|---|
| crates.io | `cargo add causalontology` | 4.0.0 published and re-audited on 2026-07-26 as sound: the crate compiles the twenty-one schemas in with `include_str!` from its own vendored `bindings/rust/spec_schema/`, reads nothing from disk at run time, and is the only binding that never had the packaging defect. `cargo package --list` names all twenty-one `spec_schema/*.schema.json` files, and the crate could not compile without them, so the published artifact necessarily carries them. The earlier line here — "a clean `cargo new` project added the crate from the registry and passed 137/137" — is **withdrawn**: it cannot be reproduced as written, because the conformance binary looks for the vectors at `../../conformance/vectors` relative to the crate and no registry checkout has that path. The soundness claim stands on the embedding, which is checkable by anyone; the run does not. 2.0.0 remains; 1.0.0 stays yanked |

## Published but defective — awaiting a fixed release (2026-07-26)

These went out before the masked-proof defect was found. The code in this
repository is fixed and verified standalone; the corrected releases are not
published yet, because each publish and each yank is a separate act needing the
owner's explicitly named go-ahead.

| Registry | Live version | What is wrong | Fixed build, verified standalone |
|---|---|---|---|
| PyPI | **4.0.0, now correct** | *was:* shipped no schemas; truly-installed wheel scored **62/137** — every schema-validation vector failed with file-not-found | **RESOLVED 2026-07-27.** `causalontology-4.0.0-1-py3-none-any.whl` uploaded into the same release (33 entries, all 21 schemas, `Build: 1` in `WHEEL`), then the defective wheel and sdist deleted. Verified against the live registry: pip resolves the build-tagged wheel on its own, 21/21 schemas installed, **137/137** from a clean venv outside the checkout with `CAUSALONTOLOGY_SPEC` stripped. Build it only with the build number (see the comment in `pyproject.toml`); a plain build emits the burned filename and PyPI will reject it |
| pub.dev | 4.0.0 | ships no schemas; a clean consumer outside a checkout throws `cannot locate spec/schema` on the first validate (reproduced against the live registry) | **4.0.1** built: the 21 schemas are compiled in via a generated `lib/spec_schema.g.dart` (Dart has no dependable runtime path to its own data files once compiled); staged exactly as pub.dev would ship it — zero schema files present — and consumed from outside the repository: **137/137** |
| Go module proxy | `bindings/go/v4@v4.0.0` | a Go module ships only its own subdirectory, so `spec/schema` is never delivered; the runner also called `SetSchemaDir(repo)` outright, which is why the "fetched fresh from proxy.golang.org" proof passed regardless | fix in tree for **v4.0.1**: schemas compiled in with `//go:embed`, schema resolution decoupled from `CAUSALONTOLOGY_ROOT` (that variable locates vectors only), and `retract v4.0.0` added to `go.mod`. Module tree copied outside the repository, schemas served from `embed.FS`: **137/137** |

## Live at 4.0.x — git-tag channels (tag `v4.0.1`, pushed 2026-07-26)

These four escaped the packaging defect for a structural reason, re-confirmed on
2026-07-26: a git-tag channel delivers the **whole repository tree**, so
`spec/schema` arrives with the code and the repository-relative path the
bindings use is a path that actually exists on the consumer's disk. The live
`v4.0.1` archive was re-downloaded and contains all 21 schemas. (The Go module
is the exception that proves the rule — it is tag-based too, but a Go module
ships only its own subdirectory, so it got no schemas and is listed as defective
above.)

Stated precisely, because the distinction is the whole lesson: none of these
four vendors a copy of the schemas. They are correct *because of how the
channel delivers them*, not because the binding carries its own. Two of them
also require the consumer to say where the schemas are, and say so loudly rather
than guessing — which is why neither could have failed silently.

| Channel | Consume with | Fresh proof, and what it does and does not show |
|---|---|---|
| Swift Package Manager | `.package(url: "https://github.com/ai-university-aiu/causalontology", from: "4.0.1")` | a fresh clone at `v4.0.1` built and passed 137/137, and a stub package resolved the dependency at exactly `4.0.1` through Swift Package Manager itself, built, and imported the library (2026-07-26). Swift Package Index listing: [PackageList PR #14440](https://github.com/SwiftPackageIndex/PackageList/pull/14440) (merge pending). Caveat: `SchemaValidator.defaultSchemaDirectory()` derives the path from `#filePath`, so it points at the SwiftPM checkout that compiled it; move or delete that checkout and a consumer must set `CAUSALONTOLOGY_SPEC` |
| Zig | `zig fetch --save https://github.com/ai-university-aiu/causalontology/archive/refs/tags/v4.0.1.tar.gz`, then `dep.module("causalontology")` | pinned package hash `12207a70aedf8b9c39e929a0ce2b34dbd04a334ece6590b70fdd3fb34c7dcfe98d6f` (printed by `zig fetch`, 2026-07-26); the tag tree passed 137/137 fresh. Read that proof narrowly: it is a proof about the **tag tree**, not about the fetched package. `build.zig.zon` lists `.paths` as `build.zig`, `build.zig.zon`, `bindings/zig/src`, `LICENSE` — `spec/` is not among them — and `schema.zig` has no default directory at all: it returns `error.SpecDirNotSet` unless the consumer calls `setSpecDir`. A Zig consumer must therefore supply the twenty-one schemas itself. That is a documented requirement of the API, not a silent failure, but it is not the same guarantee the package registries now give |
| Packagist (PHP) | `composer require causalontology/causalontology:^4.0` | the Packagist webhook mirrored `v4.0.1` automatically on the tag push (verified on the live index, 2026-07-26); the tag tarball passed 137/137 fresh, and the literal `composer require` spot-check closed the same day: a freshly fetched `composer.phar` installed `causalontology/causalontology` 4.0.1 from Packagist into a clean project and the vendor tree passed 137/137. This one is a genuine installed-artifact proof: Composer's dist archive *is* the whole repository, so `SchemaValidator`'s `dirname(__DIR__, 3) . '/spec/schema'` resolves inside the vendor tree |
| C++ source tarball | the [`v4.0.1` archive](https://github.com/ai-university-aiu/causalontology/archive/refs/tags/v4.0.1.tar.gz) | `bindings/cpp/run_conformance.sh` from the freshly downloaded tarball passed 137/137 (2026-07-26). As with Zig, `schemaDir()` has no default: it throws unless the consumer calls `schema_set_spec_dir()` or sets `CAUSALONTOLOGY_SPEC`, and the run above works because the script points it at the tarball's own `spec/schema`. The vcpkg and Conan ports stay CLA-gated below |

The `v4.0.1` tag push also triggered the release workflow, which built and
attached the GitHub Release artifacts automatically.

## Live at 2.0.0 — package registries awaiting their 4.0.0 publication

These seven were never published at 4.x, which is the one piece of luck in this
episode: they go out correct the first time, at **4.0.0**, per the version table
above. Each now packages its own copy of the twenty-one schemas and has been
proved installed — artifact built, installed into a clean temporary location,
137/137 with `CAUSALONTOLOGY_TEST_INSTALLED=1`, `CAUSALONTOLOGY_SPEC` unset,
from a working directory outside the checkout. The 2.0.0-era packages listed
here still carry the old defect and should be treated as superseded once 4.0.0
lands.

| Registry | Consume with | 1.0.0 disposition |
|---|---|---|
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
| CRAN | r | **Ready for web-form submission.** Caveat 6c resolved: `signing.R` uses the `openssl` R package for Ed25519 (Imports, not the CLI). The export surface is a documented 22-function public API (`man/*.Rd` with runnable examples), the **21** JSON Schemas are bundled under `inst/schema` so the package works standalone — and, since 2026-07-26, `tests/bundled_schema.R` makes `R CMD check` fail if they ever stop shipping — and `R CMD check --as-cran` passes with only the standard "New submission" NOTE (no WARNINGs, no ERRORs); conformance is **137/137**. Remaining is human-only: submit the built tarball at cran.r-project.org/submit.html. |
| Julia General | julia | Registration PR [General #161292](https://github.com/JuliaRegistries/General/pull/161292) is open but under contested human review; a 2.0.0 registration follows once it merges. |
| vcpkg (C++) | cpp | Port PR [microsoft/vcpkg #52892](https://github.com/microsoft/vcpkg/pull/52892), updated to 2.0.1. Blocked only on the owner's Microsoft Contributor License Agreement (comment `@microsoft-github-policy-service agree` on the PR). |
| Conan (C++) | cpp | Recipe PR [conan-io/conan-center-index #30612](https://github.com/conan-io/conan-center-index/pull/30612), updated to 2.0.1. Blocked only on signing the Contributor License Agreement at the cla-assistant link on the PR. |

## Reach beyond the direct installs

Kotlin, Scala, Clojure, and Groovy consume the Java artifact from Maven Central
as-is. Deno and Bun consume the npm package directly. Any WebAssembly host
(browsers, edge workers, wasmtime embeddings) can use the WASM core attached to
the GitHub release.

## Verify any artifact

Every binding reads the same twenty-one schemas and is gated on the same 137
frozen vectors of specification 4.0.0; the `conformance` workflow re-proves
every binding on every push, in both modes. To verify the current tree locally,
after `source ~/toolchains/env.sh`:

```
python3 bindings/python/tests/run_conformance.py
```

The runner exits zero only on 137/137.

That check tells you the *source tree* is conformant. It deliberately tells you
nothing about the *package*, and confusing the two is what produced the false
proofs above. To verify a package, install it and run the same suite in
installed mode — the shape is the same in every language:

```
# build and install the artifact into a clean, empty location, then:
cd /somewhere/outside/the/checkout
env -u CAUSALONTOLOGY_SPEC CAUSALONTOLOGY_TEST_INSTALLED=1 \
    <the binding's conformance runner>
```

In that mode the runner prints `binding under test: <path>` and the schema
directory it actually read, and exits non-zero if either lies inside the
repository, if `CAUSALONTOLOGY_SPEC` is set (it would point the library back at
a checkout and hide the very defect the mode exists to catch), or if the
bundled schemas differ by a single byte from `spec/schema`. The per-binding
README gives the exact command. `CAUSALONTOLOGY_ROOT` may still be needed: it
locates the 137 vectors, which are test data and are deliberately not shipped
inside any package.

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

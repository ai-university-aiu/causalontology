# Publishing Causalontology

This page records, honestly, what is live at which version and what still
awaits an account, a registrar, or a human review. No registry credential
beyond the two named below is stored on the build machine, by design.

Status here is re-verified against the live registries, not self-reported — and
on 2026-07-26 that re-verification was itself found to be unsound. The
correction is the next thing on this page, not a footnote.

> **Specification 4.0.0 note (updated 2026-07-27).** The specification in this
> repository is **4.0.0** — twenty-one object kinds, 137 conformance checks of
> which 38 are driven by the frozen shared vector files (the number is measured
> and explained under "What 137/137 actually counts" below) — and **4.0.0
> publication began on 2026-07-26 with the owner's explicit, per-act
> go-ahead**. Fifteen of the nineteen bindings now have a live 4.0.x artifact,
> and fourteen of those fifteen are additionally proved installed — Rust is the
> exception, for the reason set out below. The pushed tags are `v4.0.0`, `v4.0.1`, `v4.0.2`, `v4.0.3`, `bindings/go/v4.0.0`
> and `bindings/go/v4.0.1`, and **`v4.0.3` is the tag the tag-based channels
> now point at**: Swift, Zig, Packagist (PHP), the C++ source tarball, and the
> `source.tag` in the LuaRocks rockspec. The earlier tags are left exactly
> where they are, for one reason: a pushed tag is a public, cached surface that
> a consumer may already have pinned by hash or by lockfile, so a corrected
> tree gets a new tag and an existing tag is never moved. Four bindings have
> nothing live at 4.x — Haskell, Perl, R (submitted to CRAN and in the
> reviewer's queue) and Julia — and a fifth publication is outstanding on a
> channel that is already live: crates.io's corrected **4.0.1**. Those five
> acts proceed per
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
cannot be dropped by a packaging manifest. Fourteen bindings vendored or
compiled in a copy that day; PHP and Zig joined them on 2026-07-27, taking it to
sixteen, and the C++ CMake install now copies the twenty-one schemas to
`<prefix>/share/causalontology/spec/schema` at install time. Only Julia and
Swift still rely on their channel delivering the whole repository tree, and that
is now stated wherever they are listed rather than left to be inferred.

A binding enters a "Live" table below only on a run with
`CAUSALONTOLOGY_TEST_INSTALLED=1`, `CAUSALONTOLOGY_SPEC` unset, from a directory
outside the checkout, against the artifact installed into a clean location. The
runner prints the path it loaded and the directory it read schemas from, and
aborts if either lies inside the repository. Thirteen of the fourteen runners
also carry a byte-for-byte drift guard against `spec/schema`, and the Zig and
PHP runners gained one on 2026-07-27; Rust's does not and needs none, since a
Rust crate missing a schema fails to compile. The `conformance` workflow now
gates both modes on every push and re-checks every vendored copy against
`spec/schema` in a job of its own, so a binding that stops shipping its schemas
fails the build rather than the user. The full account is
in
[`docs/Causalontology_4_0_0_Release_Plan.txt`](docs/Causalontology_4_0_0_Release_Plan.txt).

## What the audit of 2026-07-27 found, plainly

The 2026-07-26 repair covered thirteen bindings. Five live channels were left
alone: crates.io (Rust) and the four served by a git tag — Swift, Zig, Packagist
(PHP), and the C++ source tarball. Those five were believed sound on a *theory*
rather than on a measurement, and a theory that has never been measured is
exactly what produced the first round of false proofs. They were re-tested on
2026-07-27 by building the artifact a consumer actually receives, running it
from a working directory outside the checkout with `CAUSALONTOLOGY_SPEC` first
poisoned and then stripped, and — in the strongest cases — hiding the repository
behind a mount namespace and tracing every file the program opened. Four
findings.

**Zig was genuinely broken, not merely unproven.** The Zig package manager
prunes the fetched tarball to the `.paths` list in the *root* `build.zig.zon`
and hashes only what survives; anything absent from that list does not exist for
a consumer, however plainly it sits in the repository. `spec/` was not on the
list. Measured: `zig fetch` of a tarball built from the published tree produced
a package of **ten files and zero schemas**, and a consumer project that fetched
the module and called `validateSchema` died with `error.SpecDirNotSet`. The
earlier entry on this page called that "a documented requirement of the
interface" — it was a broken package. It is now fixed: the root `.paths` names
`build.zig`, `build.zig.zon`, `bindings/zig`, `spec`, `conformance/vectors`,
`LICENSE` and `NOTICE`; the
twenty-one schemas are additionally compiled into the library from
`bindings/zig/src/spec_schema/` (Zig 0.13 refuses `@embedFile` of a path outside
the module directory, so the copy has to sit beside the sources); and the
fetched package is now **209 files — 21 schemas under `spec/schema`, 21
compiled in, and all 137 vectors**, so it verifies itself against the exact
bytes received. A consumer with the repository hidden behind a mount namespace
now gets `valid = true`, and `strace` shows the program opening no schema file
at all.

**The "this channel is safe because it delivers the whole repository" reasoning
was true for three of the five, irrelevant for one, and false for one.** The
reasoning matters more than the verdict, because the reasoning is what gets
reapplied to the next channel:

- **True for Swift, the C++ source tarball, and PHP.** A git-tag archive and
  Composer's dist archive really are the whole repository tree, so `spec/schema`
  arrives with the code and the repository-relative path resolves on the
  consumer's disk. Verified, not assumed. PHP no longer *depends* on it — it now
  vendors its own twenty-one schemas under `bindings/php/spec/schema` and passes
  137/137 in a Composer-shaped vendor tree with the top-level `spec/` deleted —
  and the C++ CMake install now carries its own copy too.
- **Irrelevant for Rust.** crates.io does not ship the repository; it ships the
  `bindings/rust` subtree and nothing above it. Rust is safe for an entirely
  different reason: its twenty-one schemas live *inside* that subtree, at
  `bindings/rust/spec_schema/`, and are compiled into the library with
  `include_str!`, so the crate cannot build without them and reads nothing from
  disk at run time. Filing Rust under "whole-repository delivery" was a correct
  conclusion reached by a wrong argument, which is the most dangerous kind.
- **False for Zig.** The Zig package manager delivers what the manifest lists,
  not what the repository contains. See the finding above.

**Rust's library is sound; its conformance program could not run for a registry
consumer, and its README told people to run it.** The library was proven the
hard way: a consumer crate built against the packaged `.crate`, run from outside
any checkout with the repository bind-mounted away, printed identical output
with `CAUSALONTOLOGY_SPEC` poisoned and with it stripped, and `strace` recorded
not one syscall touching the repository. But `src/bin/conformance.rs` hardcoded
the vectors at `../../conformance/vectors` relative to `CARGO_MANIFEST_DIR`, a
path no registry checkout has, so an installed copy **panicked on first run with
exit 101**; and the published README's headline instruction, `cargo run --bin
conformance`, fails in a consumer project with *no bin target named
`conformance`* because the binary belongs to a dependency. Both are fixed in
tree at **4.0.1**: the runner resolves the vectors from a command-line argument,
then `CAUSALONTOLOGY_VECTORS`, then `CAUSALONTOLOGY_ROOT`, then a checkout at or
above the working directory, prints which directory it read and how it found it,
and exits 2 with an actionable paragraph instead of panicking. 4.0.1 is **not
published**; crates.io still serves the 4.0.0 binary and the 4.0.0 README today.
The 4.0.0 *library* is sound, so yanking 4.0.0 would punish correct library
consumers in order to punish a broken test runner; the recommendation is to
publish 4.0.1 and leave 4.0.0 listed.

**The `v4.0.0` git tag is stale for the Rust binding, and nobody should verify
the crate against it.** `v4.0.0` pins the specification-freeze commit `64b1d1a`,
which predates the binding port: at that tag `bindings/rust/Cargo.toml` declares
version **2.0.0** and `bindings/rust/spec_schema/` holds **seventeen** schemas,
not twenty-one. The crate on crates.io was published from `main` at `43d58a6`.
Anyone who checks out `v4.0.0` to audit the published crate is auditing
two-major-versions-old code. Which commit produced which live artifact, so this
cannot happen again:

| Live artifact | Built from | Not from |
|---|---|---|
| crates.io `causalontology` 4.0.0 | `main` at `43d58a6` (the same commit later tagged `v4.0.1`) | **not** `v4.0.0` — that tag carries the 2.0.0 Rust binding with 17 schemas |
| pub.dev `causalontology` 4.0.0 (defective, now retracted) | `main` at `43d58a6` | — |
| pub.dev `causalontology` 4.0.1 (live) | **no single commit — published from the working tree**, recorded as a process failure rather than reconciled. Re-measured from the downloaded archive: fourteen of its sixteen files are byte-identical to `bindings/dart/` at every commit from `3f4a23b` to `b2e00ad`, and the only two that differ are `README.md` and `bin/conformance.dart` — both outside `lib/`, both carrying the then-uncommitted "137 checks" wording. The library a consumer actually uses is therefore identical to committed code | — |
| Go `bindings/go/v4@v4.0.0` (defective, now retracted) | tag `bindings/go/v4.0.0` = `43d58a6` | not the tag `bindings/go/v4/v4.0.0`, which the toolchain never consults |
| Go `bindings/go/v4@v4.0.1` (live) | tag `bindings/go/v4.0.1` = `aeaf0e7` — confirmed against the proxy, which reports `Ref: refs/tags/bindings/go/v4.0.1`, `Hash: aeaf0e71cc1b1f1ddcddd7c70d2b59fc3076d6f8` | — |
| npm `causalontology` 4.0.0 | `main` at `e697d32` (the commit that put `LICENSE` inside the artifact) | — |
| PyPI `causalontology-4.0.0-1-py3-none-any.whl` | `main` at `e697d32` | not `v4.0.0` |
| Packagist `causalontology/causalontology` v4.0.3 (newest served) | tag `v4.0.3` = `4c12aab`; v4.0.0, v4.0.1 and v4.0.2 also remain on the index | — |
| SwiftPM / Zig / C++ tarball at `v4.0.3` | tag `v4.0.3` = `4c12aab` (they were at `v4.0.1` = `43d58a6` until 2026-07-27) | — |
| LuaRocks `causalontology 4.0.0-1` (published 2026-07-27) | rockspec `source.tag` = `v4.0.3`, confirmed on the live rockspec at luarocks.org | not `v4.0.0`, whose Lua binding is at specification 2.0.0 |

**Six live artifacts have no recorded build commit, and that is a gap in this
record rather than a detail.** RubyGems 4.0.0, Hex 4.0.0, NuGet 4.0.0, both
Maven Central artifacts, and the pub.dev 4.0.1 archive were published on
2026-07-26/27 without the commit being written down at the time. What can be
said from the artifacts themselves: the RubyGems gem's thirty-two files are
byte-identical to `bindings/ruby/` at every commit from `3f4a23b` (the
schema-bundling commit) through `b2e00ad`, and are **not** identical to current
`main` — its bundled `README.md` and `conformance.rb` predate the "137 checks"
wording sweep. The rule going forward is in the release plan: record the commit
at the moment of publish, because a registry artifact and a git tag are two
different things.

**The retracted "137 vectors" phrasing is still live on almost every published
artifact.** An earlier draft of this paragraph said "four immutable channels"
and gave Hex an all-clear. Both were wrong, and the correction was measured on
2026-07-27 by unpacking the artifacts rather than by reading registry metadata —
which is the whole lesson, because several of the misses sit *inside* archives
whose metadata field was correct.

Measured, by unpacking what each registry actually serves:

| Channel | What still says "vectors" |
|---|---|
| npm 4.0.0 | bundled `README.md` |
| PyPI 4.0.0 | wheel `METADATA` |
| RubyGems 4.0.0 | bundled `README.md` |
| **Hex 4.0.0** | **bundled `README.md`** — the hex.pm *description field* was corrected before upload, but the artifact was not. The earlier all-clear here was false |
| crates.io 4.0.0 | bundled `README.md` |
| NuGet 4.0.0 | bundled `README.md` |
| Go proxy `v4.0.1` | the module zip and the conformance binary |
| Maven Central (Java) | the POM inside the jar |
| **git tag `v4.0.3`** | **all nineteen conformance runners** |

Only the Kotlin POM and pub.dev 4.0.1 carry the corrected wording.

The `v4.0.3` row is the largest instance and the one worth understanding. That
tag serves five live channels — Swift, Zig, Packagist, the C++ tarball and the
LuaRocks `source.tag` — and it was cut **before** the sweep landed; `main` is 14
commits ahead of it. So a consumer of any of those five runs the project's own
verification step and is shown the retracted claim, inside a package whose own
`PUBLISHING.md` retracts it.

Nothing can be edited in place on the immutable channels. The `v4.0.3` instance
*can* be fixed, by cutting a tag from current `main` and re-pointing the five
channels that read it. That is a deliberate decision rather than an oversight,
and it is recorded as an open item rather than quietly left.

The tag rows above are the current state; `v4.0.3` supersedes `v4.0.1` for
every tag channel, per the next section.

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
| crates.io | rust | 4.0.0 | **library yes, conformance binary no** | **4.0.1** | the library was never defective — the schemas are compiled in with `include_str!` from `bindings/rust/spec_schema/`, inside the subtree crates.io actually ships, so the crate cannot build without them. But 4.0.0's `conformance` binary panics with exit 101 for any registry consumer, and 4.0.0's README instructs people to run it. A crates.io version is immutable, so the corrected binary and README can only reach consumers as **4.0.1**. Leave 4.0.0 listed and unyanked: the library it carries is correct |
| PyPI | python | **4.0.0 LIVE and CORRECT** | **yes** | **done 2026-07-27** | the correction shipped **inside the existing 4.0.0 release** as `causalontology-4.0.0-1-py3-none-any.whl`, and the two defective files were then deleted. Release 4.0.0 now holds exactly one file. `pip install causalontology==4.0.0` into a clean virtual environment resolves the build-tagged wheel unprompted, delivers all 21 schemas, and scores **137/137** with `CAUSALONTOLOGY_SPEC` poisoned then stripped, from outside any checkout. `validate_schema` returns `(True, [])` where this morning it raised `FileNotFoundError`. Permanent consequence, accepted deliberately: 4.0.0 can never carry an sdist again, so `--no-binary` at exactly 4.0.0 now fails loudly with *No matching distribution found* rather than silently installing a package that cannot validate |
| pub.dev | dart | **4.0.1 LIVE, 4.0.0 retracted** | **yes** | **done 2026-07-27** | published and proved: a consumer with an empty pub cache resolved 4.0.1 from pub.dev, and the `validateSchema` call that previously threw now returns `(true, [])` from outside any checkout with `CAUSALONTOLOGY_SPEC` poisoned then stripped — **137/137**. 4.0.0 is now retracted, and a consumer asking for `^4.0.0` resolves to 4.0.1. Retraction on pub.dev is reversible and does not delete: anyone already pinned to 4.0.0 keeps working, new installs simply stop choosing it |
| Go module proxy | go (`bindings/go/v4`) | **v4.0.1 LIVE, v4.0.0 retracted** | **yes** | **done 2026-07-27** | tag `bindings/go/v4.0.1` pushed, proxy primed, and proved: a clean consumer with an empty module cache resolved v4.0.1 from proxy.golang.org **with checksum verification against sum.golang.org on**, received all 21 schemas, and `ValidateSchema` returned `true` from outside any checkout with `CAUSALONTOLOGY_SPEC` poisoned then stripped. The conformance program fetched fresh from the proxy scored **137/137**. The retraction works: `go list -m -versions` now offers only v4.0.1, and a consumer still on v4.0.0 is shown the reason. Module-proxy versions are immutable and cached forever — v4.0.0 could never be deleted, only superseded and retracted |
| Packagist | php | **v4.0.3 LIVE** (v4.0.0, v4.0.1 and v4.0.2 also remain on the index) | yes | **done 2026-07-27** | 4.0.1 was and is sound — Composer's dist archive is the whole repository, so `spec/schema` is delivered, verified by an actual `composer require` into a clean project. `v4.0.3` stops that being an accident: the binding now vendors its own twenty-one schemas and passes 137/137 with the top-level `spec/` deleted. Re-checked against the live index on 2026-07-27: `repo.packagist.org` serves `v4.0.3` as the newest version, so `^4.0` now resolves there |
| Swift Package Manager | swift | **tag `v4.0.3` LIVE** | yes | **done 2026-07-27** | 4.0.1 was and is sound: a tag delivers the whole tree, so `spec/schema` arrives with the sources. `v4.0.3` is the tag that carries the rest of the repair; Swift still vendors nothing and still derives its path from `#filePath`. The tag is pushed; the 137/137 proof on record is the one run at `v4.0.1`, and it has not been re-run at `v4.0.3` — nothing in the Swift binding changed between them |
| Zig | zig | **tag `v4.0.3` LIVE** | yes — repaired (`v4.0.1` was broken) | **done 2026-07-27** | `zig fetch` prunes the tarball to the root `build.zig.zon` `.paths` list, `spec/` was not on it, and a consumer received ten files and zero schemas. `v4.0.3` lists the schemas, the specification and the vectors, and compiles the schemas into the library besides. Re-measured against the **published** `v4.0.3` tarball on 2026-07-27: `zig fetch` prints `122000cacf485f8c9e8f87cfdd428d54270200b14aa666912a3e7d53cec9600c71fa` and the fetched package holds 209 files — 21 schemas under `spec/schema`, 21 compiled in, and all 137 vectors |
| C++ source tarball | cpp | **tag `v4.0.3` LIVE** | yes, with a caveat now fixed | **done 2026-07-27** | the tarball is the whole repository, so `spec/schema` is there for anyone who points at it. The caveat was the CMake **install**, which shipped zero schemas; `v4.0.3` installs them to `<prefix>/share/causalontology/spec/schema` and refuses `find_package` on an incomplete install. The vcpkg and Conan ports stay CLA-gated, and are still at 2.0.1 |
| npm | javascript | **4.0.0 LIVE** | **yes** | **done 2026-07-27** | published and proved: `npm install causalontology@4.0.0` into an empty directory delivers the 21 schemas under `spec/schema/`, and the installed package scored **137/137** with `CAUSALONTOLOGY_SPEC` first poisoned then stripped, from outside any checkout. Registry shasum `953f69a4`, licence indexed as `Apache-2.0` |
| RubyGems | ruby | **4.0.0 LIVE** | **yes** | **done 2026-07-27** | published and proved: `gem install causalontology --version 4.0.0` from rubygems.org into an empty gem home delivers all 21 vendored schemas, and the installed gem scored **137/137** with `CAUSALONTOLOGY_SPEC` poisoned then stripped, from outside any checkout. Registry checksum `e0a0e35eb4f07a73`, 32 files. Note for whoever verifies next: the first install attempt failed with *Could not find a valid gem* purely because the local gem client's index was cached — the registry was already correct. Redirect `HOME` to a scratch directory to force a virgin index |
| Hex | elixir | **4.0.0 LIVE** | **yes** | **done 2026-07-27** | published and proved: a throwaway project depending on `{:causalontology, "~> 4.0"}` resolved 4.0.0 from hex.pm, received all 21 schemas under `priv/schema`, and scored **137/137** with `CAUSALONTOLOGY_SPEC` poisoned then stripped, from outside any checkout. Release checksum `ba3e87a8947505c2`. Publish with `mix hex.publish package --yes` — the bare form runs a docs stage that needs `ex_doc`, which this zero-dependency binding does not carry |
| NuGet | csharp | **4.0.0 LIVE** | **yes** | **done 2026-07-27** | published and proved: a consumer with an empty package cache restored 4.0.0 from api.nuget.org, and `SchemaSource()` reported `bundled:` — the package's own copy, not a repository path — with `CAUSALONTOLOGY_SPEC` poisoned then stripped, from outside any checkout. **137/137**. 42 schema entries in the `.nupkg`: the 21 twice over, embedded in the assembly *and* as content files, so either path alone would serve. Validation took about 5 minutes after push before the version became restorable — NuGet scans before publishing, unlike every other registry here |
| LuaRocks | lua | **4.0.0-1 LIVE** | **yes** | **done 2026-07-27** | published and proved: `luarocks install causalontology 4.0.0-1` into an empty tree delivered all 21 schemas and scored **137/137** with `CAUSALONTOLOGY_SPEC` poisoned then stripped, from outside any checkout. LuaRocks uploads the *rockspec*, not the code, so `source.tag` decides what a consumer fetches — it names **`v4.0.3`**, and the upload demonstrably fetched that tag. Two things had to be fixed first or this could never have worked: `source.tag` named `v4.0.0`, whose Lua binding is at specification **2.0.0**; and without `source.dir` the rockspec could not build from its own declared source at all |
| Maven Central (Java) | java | **4.0.0 LIVE** | **yes** | **done 2026-07-27** | published and proved against repo1.maven.org itself: the jar downloaded from Maven Central carries all 21 schemas under `schema/`, its `.asc` verifies against the published key `4286FBC1…83D4`, and with **only that jar and a separately compiled runner** on the classpath, from outside any checkout with `CAUSALONTOLOGY_SPEC` poisoned then stripped, it scored **137/137** — `schemas under test` naming a `jar:` URL inside the artifact. Maven Central is immutable: no delete, no replace, no yank |
| Maven Central (Kotlin klib) | kotlin | **4.0.0 LIVE** | **yes, with a weaker proof** | **done 2026-07-27** | published; the klib served by repo1.maven.org verifies against the published key and carries the schemas compiled in — 21 `$schema` declarations in its IR string table. **Stated plainly: this proof is weaker than the others.** Kotlin's runner cannot be pointed at a published klib the way Java's can now be pointed at a jar, so what is verified is that the code passes 137/137 and that the artifact genuinely contains the schemas — not an end-to-end consumer run against the klib itself |
| CPAN | perl | not published at 4.x | n/a | **4.0.0** | first 4.x release; the distribution installs the schemas beside the modules, and `MANIFEST` is checked against `spec/schema` |
| CRAN | r | not published at 4.x | n/a | **4.0.0 — SUBMITTED 2026-07-27, awaiting review** | tarball uploaded through the web form and the confirmation email clicked, so it is genuinely queued. `R CMD check --as-cran` on R 4.5.3 gave **no ERRORs, no WARNINGs**, and two NOTEs: the standard *New submission*, and *unable to verify current time* (a network limitation of the build machine, absent on CRAN's). Installed from that same tarball into an empty library and run from outside the checkout with `CAUSALONTOLOGY_SPEC` poisoned then stripped: 21/21 schemas, **137/137**. Now a human queue — CRAN is the only channel in this release with a reviewer in the loop |
| Hackage | haskell | not published at 4.x | n/a | **4.0.0** | first 4.x release; the schemas are Cabal `data-files`, present in the sdist and in the installed store |
| Julia General | julia | not published at 4.x | n/a | **4.0.0** | first 4.x release; registration delivers the whole repository, so `spec/schema` arrives with the code |

**All three broken channels are now closed, each by two separately authorized
acts.** For pub.dev and the Go proxy the acts were: publish the superseding
version, then retract the broken one — both done on 2026-07-27, and both
confirmed against the live registries (pub.dev reports 4.0.0 `retracted: true`
with 4.0.1 as `latest`; `go list -m -versions` offers only v4.0.1). Retraction
is not deletion — a retracted Go version is still downloadable — so the
superseding release was the fix and the retraction is only a signpost.

PyPI was deliberately different, on the owner's instruction of 2026-07-26 that
the release ship as 4.0.0 wherever that is possible. There the acts were:
delete the two broken 4.0.0 files, then upload the build-tagged wheel into the
same 4.0.0 release. Both were done on 2026-07-27, well inside the 2026-08-09
deadline after which PyPI stops accepting new files on a release older than
fourteen days; the release now holds exactly one file,
`causalontology-4.0.0-1-py3-none-any.whl` (33 entries, 21 schemas, `Build: 1`
in its `WHEEL` metadata, confirmed by downloading it from
files.pythonhosted.org). This was the only channel of the three where the
string 4.0.0 could be made to serve correct code, because it is the only one
whose release format holds more than one file. It bought that at the cost of an
sdist that can never exist again at 4.0.0.

Five publication acts are still outstanding: crates.io's corrected **4.0.1**
(on a channel that is already live at 4.0.0), and the four bindings never
published at 4.x — Hackage (Haskell), CPAN (Perl), CRAN (R, submitted and in
the queue) and Julia General. Each needs the owner's separately named
go-ahead, and CRAN and Julia additionally need a human reviewer.

## crates.io at 4.0.0 — the one live channel with a known defect

Every other live channel is recorded in the table above. crates.io gets its own
entry because it is the only one where the published artifact is part sound and
part broken, and the distinction matters to a consumer.

| Registry | Consume with | Fresh-install proof |
|---|---|---|
| crates.io | `cargo add causalontology` | **The library is proven sound; the 4.0.0 conformance binary and README are not, and 4.0.1 is fixed in tree but unpublished.** The crate compiles the twenty-one schemas in with `include_str!` from `bindings/rust/spec_schema/` and reads nothing from disk at run time. Note the reasoning, because the older wording here got it wrong: crates.io ships only the `bindings/rust` subtree, never the repository, so Rust is safe because the schemas live *inside* that subtree — not because of whole-repository delivery. Proven on 2026-07-27 the strong way: a consumer crate built against the packaged `.crate`, from a working directory outside every checkout, with the repository bind-mounted away behind an empty directory, printed identical output with `CAUSALONTOLOGY_SPEC` poisoned and with it stripped, and `strace` recorded no syscall touching the repository. What is **not** sound at 4.0.0: the `conformance` binary resolves the vectors at `../../conformance/vectors` relative to `CARGO_MANIFEST_DIR`, which no registry checkout has, so an installed copy panics with exit 101; and the published README's headline instruction `cargo run --bin conformance` fails in a consumer project with *no bin target named `conformance`*. Both are fixed at **4.0.1** in this tree — four ways to locate the vectors, the directory it read printed on every run, exit 2 and an actionable message instead of a panic — and 4.0.1 awaits a publish. Verify the crate against `main` at `43d58a6`, **not** against the `v4.0.0` tag, which carries the 2.0.0 Rust binding and seventeen schemas. 2.0.0 remains; 1.0.0 stays yanked |

## Published defective on 2026-07-26 — all three repaired on 2026-07-27

These three went out before the masked-proof defect was found. **All three are
now fixed on the live registries**, each by two separately authorized acts
(publish the correction, then delete or retract the broken artifact). The
history is kept rather than deleted, because what went wrong is the useful part.

| Registry | Live version now | What was wrong | The repair, verified against the live registry |
|---|---|---|---|
| PyPI | **4.0.0, now correct** | *was:* shipped no schemas; truly-installed wheel scored **62/137** — every schema-validation vector failed with file-not-found | **RESOLVED 2026-07-27.** `causalontology-4.0.0-1-py3-none-any.whl` uploaded into the same release (33 entries, all 21 schemas, `Build: 1` in `WHEEL`), then the defective wheel and sdist deleted. Verified against the live registry: pip resolves the build-tagged wheel on its own, 21/21 schemas installed, **137/137** from a clean venv outside the checkout with `CAUSALONTOLOGY_SPEC` stripped. Build it only with the build number (see the comment in `pyproject.toml`); a plain build emits the burned filename and PyPI will reject it |
| pub.dev | **4.0.1 live; 4.0.0 retracted** | *was:* shipped no schemas; a clean consumer outside a checkout threw `cannot locate spec/schema` on the first validate (reproduced against the live registry) | **RESOLVED 2026-07-27** at 4.0.1: the 21 schemas are compiled in via a generated `lib/spec_schema.g.dart` (Dart has no dependable runtime path to its own data files once compiled); staged exactly as pub.dev would ship it — zero schema files present — and consumed from outside the repository: **137/137** |
| Go module proxy | **`bindings/go/v4@v4.0.1` live; `v4.0.0` retracted** | *was:* a Go module ships only its own subdirectory, so `spec/schema` was never delivered; the runner also called `SetSchemaDir(repo)` outright, which is why the "fetched fresh from proxy.golang.org" proof passed regardless | **RESOLVED 2026-07-27** at **v4.0.1**: schemas compiled in with `//go:embed`, schema resolution decoupled from `CAUSALONTOLOGY_ROOT` (that variable locates vectors only), and `retract v4.0.0` in `go.mod`. Verified against the live proxy with checksum verification on: 21 schemas delivered, a real consumer validates, and `go run .../conformance@v4.0.1` scored **137/137**. v4.0.0 no longer appears in `go list -m -versions` |

## Live at 4.0.x — git-tag channels (tag `v4.0.3`, superseding `v4.0.1`)

**This section previously said all four of these channels escaped the packaging
defect "for a structural reason: a git-tag channel delivers the whole repository
tree." That was right about three of them and wrong about the fourth, and the
wrong part shipped a broken package.** The corrected statement:

- **Swift, PHP and the C++ tarball** really do receive the whole tree. A GitHub
  tag archive and Composer's dist archive are the repository, so `spec/schema`
  arrives with the code and the repository-relative path resolves on the
  consumer's disk. Re-confirmed by download and by an actual `composer require`.
- **Zig does not.** The Zig package manager prunes the tarball to the `.paths`
  list in the root `build.zig.zon` before hashing it. `spec/` was not on that
  list, so a `zig fetch` consumer received **ten files and zero schemas** and
  `validateSchema` failed with `error.SpecDirNotSet`. Zig is tag-based but it is
  not whole-repository; a manifest sits between the tag and the consumer, and it
  was not listing the data. (The Go module is the other exception, for a
  different reason: it ships only its own subdirectory.)

`v4.0.3` is the tag that carries the repair. What changed since `v4.0.1`: Zig
lists the schemas, the specification and the vectors in `.paths` and compiles
the schemas into the library besides; PHP vendors its own twenty-one schemas so
whole-repository delivery is no longer load-bearing for it; the C++ CMake
install ships the schemas to `<prefix>/share/causalontology/spec/schema`. Swift
is unchanged and still vendors nothing.

| Channel | Consume with | Fresh proof, and what it does and does not show |
|---|---|---|
| Swift Package Manager | `.package(url: "https://github.com/ai-university-aiu/causalontology", from: "4.0.3")` | at `v4.0.1`, a fresh clone built and passed 137/137 and a stub package resolved the dependency at exactly `4.0.1` through Swift Package Manager itself, built, and imported the library (2026-07-26); `v4.0.3` moves the same, sound arrangement forward. Swift Package Index listing: [PackageList PR #14440](https://github.com/SwiftPackageIndex/PackageList/pull/14440) — **merged 2026-07-17**, so the package is listed; the index reindexes on each new tag. Swift is the one channel still correct *only* because the tag delivers the whole tree — it vendors nothing, and `SchemaValidator.defaultSchemaDirectory()` derives its path from `#filePath`, so it points at the SwiftPM checkout that compiled it; move or delete that checkout and a consumer must set `CAUSALONTOLOGY_SPEC` |
| Zig | `zig fetch --save https://github.com/ai-university-aiu/causalontology/archive/refs/tags/v4.0.3.tar.gz`, then `dep.module("causalontology")` | **`v4.0.1` was broken here and the earlier entry on this page did not say so.** The old hash `12207a70…fe98d6f` pins a package of ten files and zero schemas. Measured on the repaired tree: the fetched package is **209 files — 21 schemas under `spec/schema`, 21 compiled into the library, and all 137 vectors** — and a consumer that calls `validateSchema` with no `setSpecDir`, no `CAUSALONTOLOGY_SPEC`, and the repository bind-mounted away behind an empty directory gets `valid = true`; `strace` shows it opening no schema file at all. The runner inside the fetched package passed 137/137 under those same conditions. Package hash `122000cacf485f8c9e8f87cfdd428d54270200b14aa666912a3e7d53cec9600c71fa`, taken from `zig fetch` run against the **published** `v4.0.3` tarball on 2026-07-27, not from a locally built one — and re-confirmed the same day by an independent `zig fetch` of that published tarball into an empty cache, which printed the identical hash and produced a package of 209 files, 21 schemas under `spec/schema`, 21 beside the sources, and 137 vectors. The earlier locally-computed estimate `12206993b2c6279008106276f92f88cf1209be3ded300d9de6f9dc5b15007a65f09c` was wrong: a package hash covers the pruned file set, and `bindings/zig` is packaged whole, so later edits to the Zig README moved it. That is the general lesson — never record a Zig hash from a tarball you built yourself. A package hash covers only the pruned file set, so this channel cannot be corrected in place: a consumer must re-run `zig fetch --save` against the new tag |
| Packagist (PHP) | `composer require causalontology/causalontology:^4.0` | the Packagist webhook mirrored `v4.0.1` automatically on the tag push (verified on the live index, 2026-07-26) and has since mirrored `v4.0.3` the same way — re-checked on 2026-07-27, `repo.packagist.org` serves `v4.0.3`, `v4.0.2`, `v4.0.1` and `v4.0.0`, so `^4.0` now resolves to `v4.0.3`. A freshly fetched `composer.phar` installed `causalontology/causalontology` 4.0.1 from Packagist into a clean project and the vendor tree passed 137/137. That is a genuine installed-artifact proof, and it depended entirely on Composer's dist archive being the whole repository. It no longer has to: at `v4.0.3` the binding carries its own `bindings/php/spec/schema`, and a Composer-shaped vendor tree **with the top-level `spec/` deleted** passes 137/137 from outside the checkout — and still passes with the repository hidden behind a mount namespace. The runner aborts before the first vector if a vendored schema is missing, so a package that cannot validate cannot pass its own suite |
| C++ source tarball | the [`v4.0.3` archive](https://github.com/ai-university-aiu/causalontology/archive/refs/tags/v4.0.3.tar.gz) | `bindings/cpp/run_conformance.sh` from the freshly downloaded `v4.0.1` tarball passed 137/137 (2026-07-26), and that remains true: the tarball is the whole repository and the script points the library at the tarball's own `spec/schema`. What that run never touched was the **CMake install**, which is how anyone consumes this as a library — it installed 15 files and **zero** schemas, so an installed consumer could not validate anything. At `v4.0.3` the install carries 36 files including all 21 schemas at `<prefix>/share/causalontology/spec/schema`, a `find_package` consumer built outside the checkout validates correctly with the repository bind-mounted away, and an incomplete install fails loudly at configure, at `find_package`, and at run time rather than silently reading the tree that built it. A second correction: the README claimed `CAUSALONTOLOGY_SPEC` overrode the schema directory, and it did not — the variable was unreachable behind an explicit `schema_set_spec_dir()` call. It is now consulted first, and the conformance run scores 62/137 when it is poisoned, which is how you can tell it is really being read. The vcpkg and Conan ports stay CLA-gated below |

Pushing `v4.0.3` also triggers the release workflow, which builds and attaches
the GitHub Release artifacts automatically. `v4.0.0`, `v4.0.1` and `v4.0.2` stay
exactly where they are and are not moved: a pushed tag is a public, cached
surface that a consumer may already have pinned, so a corrected tree gets a new
tag rather than a redefined one.

## What happened to the superseded 1.0.0 and 2.0.0 releases

This section used to list the registries still waiting for their first 4.x
publication. All but five of them have now shipped, so what is left worth
recording is the disposition of the older releases each registry still carries.
The rule differs by registry, and the differences are real rather than
oversights:

| Registry | Older releases still listed | Disposition |
|---|---|---|
| PyPI | 1.0.0, 2.0.0 | 1.0.0 yanked; 2.0.0 remains |
| crates.io | 1.0.0, 2.0.0 | 1.0.0 yanked; 2.0.0 remains |
| RubyGems | 2.0.0 | 1.0.0 yanked (a yanked gem leaves the version index); 2.0.0 remains |
| npm | 1.0.0, 2.0.0 | 1.0.0 deprecated, message *superseded by 2.0.0 (whole-word schemes, P7)*; nothing unpublished |
| NuGet | 1.0.0, 2.0.0 | 1.0.0 unlisted; NuGet has no yank and no delete |
| Hex | 1.0.0, 2.0.0 | 1.0.0 retired; 2.0.0 remains |
| pub.dev | 1.0.0, 2.0.0, 4.0.0 | 1.0.0 and 4.0.0 retracted; 2.0.0 remains |
| LuaRocks | 1.0.0-1, 2.0.0-1, 4.0.0-1 | LuaRocks has no yank, so both older rockspecs remain listed |
| Maven Central | 1.0.0, 2.0.0 (jar and klib alike) | immutable: no delete, no replace, no yank |
| Packagist | v1.0.1, v1.0.2, v2.0.0, v2.0.1, v4.0.0, v4.0.1, v4.0.2 | Packagist mirrors every git tag; nothing is removed |
| Go module proxy | `/v1` line, `/v2` line, `v4.0.0` | the v1 line is deprecated and retracted via `bindings/go/v1.0.1`; `/v2` stays live for 2.0.x; `v4.0.0` is retracted |

The 2.0.0-era packages all predate the schema-packaging repair and carry the old
defect. Treat them as superseded, not as a fallback.

## Still pending — accounts, registrars, or human review

None of these is blocked on this repository; each awaits a third party or an
account action.

| Registry | Binding | What remains |
|---|---|---|
| Hackage | haskell | The sdist is built and passes `cabal check`. Needs a Hackage account + upload token, then `cabal upload --publish <sdist>`. Confirmed unpublished on 2026-07-27: `hackage.haskell.org/package/causalontology` answers 404. |
| CPAN | perl | The dist tarball is built. The Perl Authors Upload Server (PAUSE) has no application programming interface (API) token; upload via the web form at pause.perl.org. Confirmed unpublished on 2026-07-27: the MetaCPAN release endpoint answers 404. |
| CRAN | r | **Submitted 2026-07-27, awaiting a reviewer.** Confirmed against CRAN itself the same day: `causalontology_4.0.0.tar.gz` is sitting in `cran.r-project.org/incoming/newbies/`, and the copy served from there hashes to sha256 `95195ab72c6230d3f1666258b637cd1921d5855bdbab7ecdfafba6e006085185` — the same tarball recorded here. It is genuinely queued, not merely built. (`crandb.r-pkg.org` still answers *not found*, which is what "not yet accepted" looks like; an earlier `causalontology_2.0.0.tar.gz` sits in `incoming/archive/`.) The submission itself: caveat 6c resolved, `signing.R` uses the `openssl` R package for Ed25519 (Imports, not the CLI); the export surface is a documented 22-function public API (`man/*.Rd` with runnable examples); the **21** JSON Schemas are bundled under `inst/schema` so the package works standalone, and since 2026-07-26 `tests/bundled_schema.R` makes `R CMD check` fail if they ever stop shipping; `R CMD check --as-cran` gave no ERRORs and no WARNINGs; conformance is **137/137**. The confirmation email was clicked, which is the step that silently kills a CRAN submission when it is missed. |
| Julia General | julia | Registration PR [General #161292](https://github.com/JuliaRegistries/General/pull/161292) is open and under contested human review. Read the PR carefully before quoting it: it registers **v1.0.0** (commit `12f4c6a`, the tree tagged `v1.0.2`), not 2.0.0 and not 4.0.0. Julia's registry requires the versions to land in order, so 2.0.0 and then 4.0.0 follow only once this one merges — which is why Julia is the furthest behind of all nineteen bindings on the registry side, however green it is locally. |
| vcpkg (C++) | cpp | Port PR [microsoft/vcpkg #52892](https://github.com/microsoft/vcpkg/pull/52892), still open; the port manifest on the PR head reads `"version": "2.0.1"`, confirmed 2026-07-27. Blocked only on the owner's Microsoft Contributor License Agreement (comment `@microsoft-github-policy-service agree` on the PR). Note that it is two majors behind the specification, and its description still says "passes all 38 frozen conformance vectors" — bring both to 4.0.0 when the gate clears. |
| Conan (C++) | cpp | Recipe PR [conan-io/conan-center-index #30612](https://github.com/conan-io/conan-center-index/pull/30612), still open and titled `causalontology/2.0.1: new recipe`, confirmed 2026-07-27. Blocked only on signing the Contributor License Agreement at the cla-assistant link on the PR. Same caveat as vcpkg: 2.0.1, and a 38-vector description to correct. |

## Reach beyond the direct installs

Kotlin, Scala, Clojure, and Groovy consume the Java artifact from Maven Central
as-is. Deno and Bun consume the npm package directly. Any WebAssembly host
(browsers, edge workers, wasmtime embeddings) can use the WASM core attached to
the GitHub release.

## What 137/137 actually counts

Measured on 2026-07-27, across all nineteen bindings, by tracing every file each
runner opened and then re-running each one against a vectors directory whose
contents had been replaced with `{}`. The number this whole release is gated on
does not mean what the label says, so here it is plainly.

**`137/137` counts checks, not vector files.** It is 137 hand-written,
per-language assertions. Of those, **38 are driven by the frozen shared vector
files** — exactly V01–V38 — and the other 99 share no data with any other
binding at all. Every one of the nineteen runners opens 38 vector files for
their contents and no more. Rust and Haskell do open all 137, but only to lift
the label printed on the PASS line: replace the contents of V39–V137 with `{}`
and both still print `137/137` and `CONFORMANT`.

**The cause is in the vector files, not only in the runners.** All 99 files from
V39 to V137 carry no executable payload — no `input`, no `given`, no `steps`.
Their `operation` field reads, literally, `"see bindings/*/conformance runner"`.
They are named, grouped stubs carrying an `expect` block of booleans and a prose
note. There is nothing in them to execute, so no runner could read them for
meaning even if it tried.

**The honest headline.** Not "137/137 vectors". Either:

> 137/137 conformance checks passed (38 driven by the frozen shared vectors; 99
> implemented per binding)

or, if one number is wanted, "38/38 shared data vectors + 99 per-binding
checks". A stricter figure is available and also honest: of the 38 files that
are read, only **26** change any verdict when their bytes are destroyed —
V01–V19, V21–V25, V34 and V35. Gutting all 137 files still leaves 111 checks
passing.

Independently reproduced on 2026-07-27 against the Python reference, on a copy
of the tree outside the repository, so the numbers above are not taken on
trust: replacing the contents of the 99 files V39–V137 with `{}` still prints
`137/137 checks passed` and `CONFORMANT`; replacing the contents of all 137
prints `111/137`; and deleting the 99 outright makes the runner die with an
`IndexError` on a filename glob rather than report a missing vector, which is
the "accident rather than a guard" described below. The file structure behind
that: of the 137 vector files, exactly the 38 numbered V01–V38 carry executable
data, and every one of the 99 numbered V39–V137 has an `operation` field
reading, literally, `see bindings/*/conformance runner`.

What this does and does not undermine. It does not mean the bindings are
unverified: 137 assertions per language really do run, and the schema-packaging
proofs recorded on this page are unaffected, since those turn on whether an
installed artifact can validate at all. What it does undermine is the specific
claim that the shared vector files are what makes nineteen independent
implementations agree. Today that is true for V01–V38. For V39–V137 the
nineteen bindings agree only in that nineteen ports were each written to the
same prose note.

One further measurement, because it bears on every "fresh install" proof: **only
the Rust runner detects a vectors directory that is missing files.** Delete 99
of the 137 files and Elixir, Go, Swift and Zig still report `137/137` and
`CONFORMANT`; seven more bindings happen to crash on a filename lookup, which is
an accident rather than a guard. Rust alone refuses with an accurate diagnosis
— and even Rust passes when the files are present but hollow.

The cheapest honest repair, in order of cost: stop printing the word "vectors"
for a number that counts checks; port the Rust completeness check into the other
eighteen runners; and, since each of the 99 stubs already lists in its `expect`
block every assertion the check owes, have each runner require that its check
for vector *n* answers every key in that file's `expect` object. The third makes
the file authoritative over what must be checked, which is what "137 vectors"
asserts, without a 99-file data project. None of that is done; this is a
measurement, recorded so the number is not repeated as if it meant something
else.

## Verify any artifact

Every binding reads the same twenty-one schemas and is gated on the same 137
conformance checks of specification 4.0.0 — 38 of them driven by the frozen
shared vector files, per the section above; the `conformance` workflow re-proves
every binding on every push, in both modes. To verify the current tree locally,
after `source ~/toolchains/env.sh`:

```
python3 bindings/python/tests/run_conformance.py
```

The runner exits zero only on 137/137. Re-checked 2026-07-27: it prints
`137/137 checks passed (38 from the frozen shared vectors, 99 per-binding)` and
exits 0; with `CAUSALONTOLOGY_SPEC` set to a non-existent directory it prints
`62/137` and exits 1, which is how you can tell the variable is genuinely being
read rather than ignored.

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

The three commands below are against the worked example in `dumps/example/`;
point `--dir` at whatever directory holds the four files of the dump you
actually have. (They read `--dir` literally, so `--dir dumps` fails with
`FileNotFoundError: dumps/commons.snapshot.ndjson` — the earlier version of
this page had that wrong.)

```
# offline check: manifest signature, Merkle root, every hash and signature
python3 store/server/snapshot_import.py --dir dumps/example --verify-only

# the detached checksum is a plain sha256sum file
cd dumps/example && sha256sum -c commons.snapshot.sha256

# mirror it into a fresh node by verified, idempotent union-merge
python3 store/server/snapshot_import.py --dir dumps/example --db mirror.db
```

Run 2026-07-27, those print, in order: `VERIFIED: manifest signature, Merkle
root, every identifier and every signature check out (4 content, 2
provenance)`; two `OK` lines; and `MIRRORED: snapshot verified and union-merged
(Merkle root bda5f51b…)` with 4 content objects and 2 provenance records added.

Pin a publisher you trust with `--trust ed25519:<hex>`. The token tier is
excluded from a default snapshot for privacy. Full format:
[`spec/snapshot.md`](spec/snapshot.md).

## Release mechanics

- Git tags drive the tag channels: `vX.Y.Z` for SwiftPM, Zig, Packagist and the
  source release; `bindings/go/vX.Y.Z` for the Go module, which moves on its own
  schedule. The current tags are **`v4.0.3`** for the first group and
  **`bindings/go/v4.0.1`** for the Go module. Earlier tags are never moved, only
  superseded, because a consumer may already have pinned one. Pushed to date:
  `v4.0.0`, `v4.0.1`, `v4.0.2`, `v4.0.3`, `bindings/go/v4.0.0` and
  `bindings/go/v4.0.1`, plus one harmless misnamed tag, `bindings/go/v4/v4.0.0`,
  which the Go toolchain never consults.
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

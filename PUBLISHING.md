# Publishing Causalontology 1.0.0

The vectors are frozen; every artifact below was built from the frozen tree
and verified by the conformance suite. This page records, honestly, what is
already live and what awaits the owner's registry credentials (none are
stored on the build machine, by design).

## Live now (no credentials needed - done via git tags and GitHub)

| Channel | Status | Consume with |
|---|---|---|
| GitHub Release v1.0.0 | **live** - carries the wheel, sdist, npm tarball, crate, and the WebAssembly core | the repository's Releases page |
| Swift Package Manager | **live** - SwiftPM resolves git tags directly | `.package(url: "https://github.com/ai-university-aiu/causalontology", from: "1.0.0")` |
| NuGet | **live** (published 2026-07-14) | `dotnet add package causalontology` — https://www.nuget.org/packages/causalontology |
| RubyGems | **live** (published 2026-07-14, via the publish workflow) | `gem install causalontology` — https://rubygems.org/gems/causalontology |
| Hex | **live** (published 2026-07-14, via the publish workflow) | `{:causalontology, "~> 1.0"}` — https://hex.pm/packages/causalontology |
| LuaRocks | **live** (published 2026-07-14, via the publish workflow) | `luarocks install causalontology` — https://luarocks.org/modules/search?q=causalontology |
| npm | **live** (published 2026-07-13) | `npm install causalontology` — https://www.npmjs.com/package/causalontology |
| PyPI | **live** (published 2026-07-13) | `pip install causalontology` — https://pypi.org/project/causalontology/ |
| crates.io | **live** (published 2026-07-13) | `cargo add causalontology` — https://crates.io/crates/causalontology |
| Maven Central | **live** (published 2026-07-13) | `io.github.ai-university-aiu:causalontology:1.0.0` — https://repo1.maven.org/maven2/io/github/ai-university-aiu/causalontology/1.0.0/ |
| Go modules / pkg.go.dev | **live** - Go resolves module tags directly (`bindings/go/v1.0.0`) | `go get github.com/ai-university-aiu/causalontology/bindings/go@v1.0.0` |

## Nothing awaits: every channel is live

All seven distribution channels published on 2026-07-13. The build recipe
for Maven (JDK tarball, three jars, GPG-signed bundle, the Central
Publisher API) is recorded in the repository history for the next release.

Name-collision note, stated plainly: if the bare name `causalontology` is
already claimed on a registry, publish under the organization scope instead
(`@ai-university-aiu/causalontology` on npm; `causalontology-standard` or
similar elsewhere) and record the chosen name in the bindings table.

## Verify any artifact

Every package embeds or reads the same schemas and passes the same 38
frozen vectors; the conformance workflow re-proves all eight gates on every
push. To verify locally: `python3 bindings/python/tests/run_conformance.py`.

## The nine-language wave (2026-07-13): registries awaiting the owner's accounts

All nine implementations are conformant (38/38) in the repository; each
carries its registry manifest. As before: no credential lives on the build
machine; each publish is one account + one command.

| Registry | Binding | The command (after logging in) |
|---|---|---|
| Packagist | php | submit the repository URL at packagist.org (it reads composer.json) |
| pub.dev | dart | `cd bindings/dart && dart pub publish` |
| Hackage | haskell | `cd bindings/haskell && cabal sdist && cabal upload --publish dist-newstyle/sdist/*.tar.gz` |
| CPAN | perl | PAUSE account, then upload the dist tarball at pause.perl.org |
| CRAN | r | a human-review submission process (cran.r-project.org/submit.html) — stated plainly |

## Wave two (2026-07-14): C++, Zig, Julia, Kotlin/Native

| Channel | Binding | Status / command |
|---|---|---|
| Zig packages | zig | **live by git tag** — Zig consumes git URLs + build.zig.zon; the v1.0.0 tag serves it |
| C++ | cpp | source + GitHub release; vcpkg/Conan port manifests are a welcome contribution |
| Julia General registry | julia | registration is a pull-request review process (JuliaRegistries/General) — stated plainly; Project.toml is ready |
| Maven Central (klib) | kotlin | Kotlin/Native artifact publication pending — reuses the existing verified io.github.ai-university-aiu namespace |

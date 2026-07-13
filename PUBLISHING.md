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

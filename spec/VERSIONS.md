# Specification versions

The specification under [`spec/`](.) is a living document; its current version
is declared in the title of [`causalontology.md`](causalontology.md) (presently
**3.0.0**). Each released version is frozen and permanently reachable by its git
tag, so consumers can pin an exact specification.

## Pinning a version

| Version | Git tag | What it froze |
|---|---|---|
| 3.0.0 | `v3.0.0` | The three additive elements: 18 object kinds (adds the `cross_stratal_seam`), 119 vectors (V01–V119), six normative algorithms (adds Algorithm F); the ordinal `ticks` temporal unit and the conduit `realized_by` reference. All additive and identity-preserving. |
| 2.0.1 | `v2.0.1` | 2.0.0 spec unchanged; a packaging patch (Zig root manifest). |
| 2.0.0 | `v2.0.0` | The whole-word re-mint: 17 object kinds, 107 vectors (V01–V107), five normative algorithms. |
| 1.0.0 | `v1.0.0` | The initial freeze: 8 object kinds, 38 vectors (V01–V38). |

To read the specification exactly as it was at a version, check out its tag, for
example `git show v2.0.0:spec/causalontology.md`, or browse the tag on GitHub.

The normative gate travels with the version: an implementation is conformant if
and only if it passes every vector in [`../conformance/vectors/`](../conformance/vectors/)
for the specification version it declares.

## Versioning rules

Specification versions follow Semantic Versioning, per
[`../GOVERNANCE.md`](../GOVERNANCE.md): a new object kind or a breaking change to
identity is a MAJOR version; the vectors are re-frozen once per release. Earlier
prose drafts (manuscript, outline, design) are retained under
[`../archive/`](../archive/); see [`../CHANGELOG.md`](../CHANGELOG.md) for the
per-version summary.

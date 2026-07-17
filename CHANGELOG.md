# Changelog

All notable changes to the Causalontology standard are documented here. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The conformance vectors under [`conformance/vectors/`](conformance/vectors/) are
the normative gate: an implementation is conformant if and only if it passes
every vector for the specification version it declares.

## [2.0.1] - 2026-07-16

Patch release. No specification or vector change; the frozen 107-vector suite is
unchanged.

### Added
- Repository-root `build.zig.zon` and a thin `build.zig` exposing the module
  `causalontology`, so the Zig binding is consumable via the clean
  `zig fetch --save <tag tarball>` + `dep.module("causalontology")` flow rather
  than a subdirectory-path workaround. Zig consumers pin this tag.

### Changed
- The Go v1 module line (`.../bindings/go`, without the `/v2` suffix) is
  deprecated and self-retracted at `bindings/go/v1.0.1`, steering consumers to
  the `/v2` module.

## [2.0.0] - 2026-07-15

Major release: the whole-word re-mint. This is a breaking change to identifier
schemes and object-kind coverage.

### Changed (breaking)
- **Whole-word identifier schemes (Principle P7).** Every identifier scheme,
  type value, and id prefix is now a single whole English word. The abbreviated
  1.0.0 schemes are retired, most visibly `cro` → `causal_relation_object`
  (full mapping in [NAMING.md](NAMING.md)). Abbreviated schemes are now rejected
  (vector V107).
- **Field renames.** Temporal-window fields `dmin` → `minimum_delay` and
  `dmax` → `maximum_delay`.

### Added
- **Nine new object kinds (8 → 17).** Type tier: `quality`, `stratum`, `bridge`,
  `port`, `conduit`. Token tier: `token_individual`, `token_occurrence`,
  `state_assertion`, `token_causal_claim`.
- **Sixty-nine new conformance vectors (V39 - V107)** covering the token tier,
  strata and bridges, ports and conduits, skip semantics, whole-word identity
  invariance, and abbreviated-scheme rejection. The original V01 - V38 are
  carried forward, re-frozen under the whole-word baseline (vector V106).
- **Five normative algorithms:** bridge closure, bridged reachability, stratal
  classification, skip decision, and unit normalization.
- **`evidence_type: simulation`**, the new bottom rung of the evidence ladder
  (intervention > observation > simulation).
- **Non-normative encodings** (Protocol Buffers, JSON-LD, OWL/Turtle) extended
  to all seventeen kinds with BFO/RO/PROV alignment.
- Nineteen conformant language bindings, published across eleven package
  registries and three git-tag channels (see [PUBLISHING.md](PUBLISHING.md)).

### Migration
- 1.0.0 records remain identity-stable under 2.0.0 only when written with
  whole-word schemes; the re-mint tooling maps the abbreviated forms. See
  [NAMING.md](NAMING.md) for the scheme and field mapping.

## [1.0.0] - 2026-07-13

Initial specification freeze.

### Added
- Eight object kinds (type and provenance tiers) and 38 frozen conformance
  vectors (V01 - V38).
- Content-addressed identity over RFC 8785 (JSON Canonicalization Scheme) and
  Secure Hash Algorithm 256-bit (SHA-256); record-level Ed25519 signing (RFC 8032).
- A Tier A reference store with materialized views, retraction, succession
  lineage, and the stigmergy gap read.

[2.0.1]: https://github.com/ai-university-aiu/causalontology/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/ai-university-aiu/causalontology/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/ai-university-aiu/causalontology/releases/tag/v1.0.0

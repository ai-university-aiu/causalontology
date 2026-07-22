# Changelog

All notable changes to the Causalontology standard are documented here. The
format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

The conformance vectors under [`conformance/vectors/`](conformance/vectors/) are
the normative gate: an implementation is conformant if and only if it passes
every vector for the specification version it declares.

## [4.0.0] - 2026-07-22

MAJOR release. Three additive object kinds, one coordinated conformance
re-baseline. The object model grows from eighteen kinds to TWENTY-ONE (the token
tier from four kinds to seven) and the conformance suite from 119 vectors to 137
(V01–V137, groups X, Y, and Z appended), green in the Python reference. Every
change is ADDITIVE and IDENTITY-PRESERVING: no existing record's
content-addressed identifier changes, and every 3.0.0 record stays valid and
keeps its identifier byte-for-byte under 4.0.0 (witnessed directly by vector
V136, which re-pins the exact frozen 3.0.0 bytes). This is a major version
because new object kinds and the extension of closed enumerations are, by the
standard's own rule (Locked Decision 24), a major version.

This release was GATED, not guessed. Per the standard's enforce-then-build
discipline, the change order that specifies these kinds sat HELD until the
konnectome repository's Requirements Ledger recorded, from a real build, that
the substrate could not represent something konnectome needed. Wall-1 and
Wall-2 (both 2026-07-22, konnectome build slice 11) released change-order
Sections B and A respectively: konnectome could hold a false, nested belief
about another agent privately but could not represent or share it as a signed,
evidence-graded, content-addressed record (no doxastic kind — Section B), and
its prediction loop could compute a signed, graded prediction error each tick
but could not record an EXPECTED occurrence as distinct from an OBSERVED one (a
prediction minted as a token_occurrence is byte-identical to a claim of fact —
Section A). Both findings passed the consumer-versus-ontology test, and the
owner authorized the release in writing on 2026-07-22. Sections C, D, and E of
the change order remain HELD, each awaiting its own finding.

### Added
- The **`attitude`** kind (change-order Section B): the doxastic record — a
  HOLDER (a modeled agent: a `continuant` or `token_individual`, never a
  cryptographic key), an `attitude_type` from a CLOSED enumeration (`believes`,
  `desires`, `intends`, `knows`, `expects`, `fears`), and a CONTENT reference by
  identity to any content object INCLUDING another attitude (which is what makes
  A-believes-that-B-believes-X expressible). An attitude records what the
  holder's mind CONTAINS, not what is true: its content may be FALSE without
  raising any conflict (semantics Rule 25, the doxastic quarantine), it carries
  no strength of its own (Principle P4), and it is asserted, graded, and
  retracted through the ordinary provenance layer. Vectors V128–V135.
- The **`predicted_occurrence`** kind (change-order Section A): a first-class
  EXPECTATION — a sibling of `token_occurrence` that has not (yet) happened,
  carrying the occurrent type it `instantiates`, the modeled `predictor`, an
  interval with exactly ONE temporal dimension (a wall-clock window or an
  ordinal tick window, never both and never neither — semantics Rule 24), and
  an optional, identity-bearing `strength` (the predicted probability: part of
  the PREDICTED CONTENT itself, not a provenance evaluation). A prediction is
  NOT an assertion that the thing happened; a forecast and a report of the same
  content have different identifiers. Vectors V120–V123.
- The **`prediction_error`** kind (change-order Section A): the reification of
  the comparator's reward-prediction-error signal — it pairs a
  `predicted_occurrence` with the `token_occurrence` that did or did not fulfil
  it (`observed` absent means nothing arrived), carrying the signed, graded
  `discrepancy`, read actual-minus-expected. When `observed` is present it must
  instantiate the same occurrent the prediction instantiates
  (`pairing_mismatch`, Rule 24). Vectors V124–V127.
- Semantics **Rules 24 and 25** ("a prediction is not a report"; "an attitude's
  content is quarantined") — the first new semantic rules since Rule 23.
- The **`assertion.about` widening**: an assertion may now be about any of the
  three new kinds, so the provenance layer reaches them from day one (V135).
- The **4.0.0 identity witnesses**: V136 re-pins the exact frozen 3.0.0 bytes
  unchanged under the 4.0.0 implementation, and V137 rejects abbreviated
  schemes for the three new kinds (mirroring V107).

### Notes
- Locked decisions are amended by EXTENSION (as the major-version rule allows),
  recorded as five 4.0.0 decisions: the kind enumeration to twenty-one; the
  CLOSED `attitude_type` enumeration (extensible only by a future major
  version); the doxastic quarantine, with the HOLDER forever distinct from the
  signing SOURCE; a predicted_occurrence's `strength` as predicted content — a
  deliberate, narrow extension of Principle P4, which stands for every other
  content kind; and the `assertion.about` widening. Nothing is silently
  overridden.
- Honest repair of 3.0.0 drift, done additively in this major version:
  `cross_stratal_seam` had been genuinely absent since 3.0.0 from the
  `assertion.about` pattern, from two content-kind lists in the Python
  reference's store and snapshot routing, and from the conformance runner's
  whole-word scheme list — so a seam could be minted but not asserted about or
  accepted by those store paths. All four omissions are repaired alongside the
  three new kinds (the `assertion.about` schema description names the repair),
  and a stale "fourteen content kinds" count in `spec/identity.md` is
  reconciled to seventeen (ten type-tier + seven token-tier).
- See [`docs/Causalontology_4_0_0_Release_Plan.txt`](docs/Causalontology_4_0_0_Release_Plan.txt)
  for the multi-language package-release plan, which subsumes and supersedes the
  3.0.0 plan (folding each binding's never-published 3.0.0 delta into its 4.0.0
  work); a binding does not publish 4.0.0 until it passes the 137-vector suite
  in its own language. Today the Python reference is the only binding at that
  gate.

## [3.0.0] - 2026-07-19

MAJOR release. Three additive schema elements, one coordinated conformance
re-baseline. The object model grows from seventeen kinds to EIGHTEEN and the
conformance suite from 107 vectors to 119 (V01–V119), green in the Python
reference. Every change is ADDITIVE and IDENTITY-PRESERVING: no existing record's
content-addressed identifier changes, and every 2.0.0 record that remains valid
still validates under 3.0.0 (witnessed by vectors V106, V111, V118). This is a
major version because a new object kind and the extension of closed enumerations
are, by the standard's own rule, a major version.

### Added
- The ordinal **`ticks`** temporal unit: a discrete, dimensionless step with no
  wall-clock mapping, ordered by integer comparison; a tick window and a
  wall-clock window are disjoint dimensions. Lets discrete-tick time be recorded
  natively instead of distorted into seconds. Vectors V108–V111.
- The eighteenth kind **`cross_stratal_seam`**: a managed record of a legitimate
  jump across non-adjacent strata, carrying a `mechanism_status`
  (`unmodeled` versus `absent` — the honest-ignorance distinction the boolean
  `skips` could not make), an optional drawn `chain` of intervening steps, and a
  coarsest-stratum home rule. Semantics Rule 22 / Algorithm F. Vectors V112–V116.
- The conduit **`realized_by`** reference: an optional, scheme-qualified reference
  by identity to the native law or signal that realizes a conduit's transform
  (the dynamics stay native; the standard records the binding). Unbound is legal.
  Vectors V117–V119.

### Notes
- Locked decisions are amended by EXTENSION (as the major-version rule allows):
  the kind enumeration to eighteen, the temporal-unit enumeration by `ticks`, and
  the conduit fields by `realized_by`. Nothing is silently overridden.
- See [`archive/Causalontology_3_0_0_Release_Plan.txt`](archive/Causalontology_3_0_0_Release_Plan.txt)
  (archived at 4.0.0; subsumed and superseded by the 4.0.0 release plan) for the
  multi-language package-release plan; a binding does not publish 3.0.0 until it
  passes the 119-vector suite in its own language. No binding did before 4.0.0
  arrived: the 3.0.0 delta was published in no package, which is why the 4.0.0
  plan folds it in.

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

[4.0.0]: https://github.com/ai-university-aiu/causalontology/compare/v3.0.0...v4.0.0
[3.0.0]: https://github.com/ai-university-aiu/causalontology/compare/v2.0.1...v3.0.0
[2.0.1]: https://github.com/ai-university-aiu/causalontology/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/ai-university-aiu/causalontology/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/ai-university-aiu/causalontology/releases/tag/v1.0.0

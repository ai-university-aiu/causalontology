## 4.0.1

- Packaging fix, no specification change: the twenty-one JSON Schemas of
  `spec/schema` are now embedded in the package itself as generated Dart
  source (`lib/spec_schema.g.dart`), so a consumer who installs the package
  from pub.dev can validate without a repository checkout. Before this,
  schema loading walked up from the running script looking for a
  `spec/schema` directory, which only ever exists inside the repository - so
  the first `validateSchema` call in an installed package threw.
- `CAUSALONTOLOGY_SPEC` still overrides everything, so a working tree can
  always be pointed at; the directory walk survives only as a fallback for a
  schema file the embedded map does not carry.
- `tool/embed_schemas.dart` regenerates the embedded copy, and the
  conformance runner hard-fails on any byte-level drift between the embedded
  copy and `spec/schema`.
- The conformance runner honours `CAUSALONTOLOGY_TEST_INSTALLED`: it prints
  the resolved path of the binding under test and exits nonzero if that path
  lies inside the repository, so a test of the installed package can no
  longer silently exercise the repository sources.
- Still passes all 137 conformance checks (specification 4.0.0) - 38 driven by
  the frozen shared vector files in `conformance/vectors/`, 99 implemented in
  this binding's own runner.

## 4.0.0

- Folds in the specification 3.0.0 delta: the ordinal `ticks` temporal unit (a
  tick window and a wall-clock window are disjoint dimensions; integer ordering;
  tick-to-seconds conversion is refused), the `cross_stratal_seam` kind with
  Algorithm F (non-adjacency, the drawn-chain rules, the coarsest-stratum home
  rule, and the contradictory-seam checks), and the optional identity-bearing
  `realized_by` reference on the conduit.
- Adds the three specification 4.0.0 object kinds, taking the total from 18 to
  21: `attitude` (a holder's mental state, whose content may be false and may
  nest), `predicted_occurrence` (an expectation over exactly one temporal
  dimension), and `prediction_error` (the signed discrepancy). Semantics Rules
  24 and 25 join; the assertion about-reference widens to the new kinds.
- Additive and identity-preserving: every 3.0.0 record keeps its identifier
  byte-for-byte (witness V136).
- Passes all 137 conformance checks (specification 4.0.0) - 38 driven by the
  frozen shared vector files, 99 implemented in this binding's own runner.

## 2.0.0

- Whole-word re-mint (Principle P7): every content-addressed scheme is now
  the object kind's full name, replacing the abbreviated 1.0.0 prefixes.
- Adds the nine new object kinds of specification 2.0.0, taking the total
  from 8 to 17 (the token tier, strata and bridges, ports and conduits).
- Passes all 107 conformance checks (specification 2.0.0) - 38 driven by the
  frozen shared vector files, 69 implemented in this binding's own runner.

## 1.0.0

- Initial release: the Dart binding of the Causalontology standard.
- Zero dependencies: pure-Dart SHA-256/512 and Ed25519 over BigInt.
- Passes all 38 frozen conformance vectors (specification 1.0.0).

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
- Passes all 137 frozen conformance vectors (specification 4.0.0).

## 2.0.0

- Whole-word re-mint (Principle P7): every content-addressed scheme is now
  the object kind's full name, replacing the abbreviated 1.0.0 prefixes.
- Adds the nine new object kinds of specification 2.0.0, taking the total
  from 8 to 17 (the token tier, strata and bridges, ports and conduits).
- Passes all 107 frozen conformance vectors (specification 2.0.0).

## 1.0.0

- Initial release: the Dart binding of the Causalontology standard.
- Zero dependencies: pure-Dart SHA-256/512 and Ed25519 over BigInt.
- Passes all 38 frozen conformance vectors (specification 1.0.0).

# The steroid hormone channel — the golden example (Appendix D)

This is the worked reference encoding of change order 2.0.0, Appendix D: the
**layer-skipping causal path** by which a social event at the community stratum
(ordinal 14) alters gene expression at the macromolecular stratum (ordinal 4),
without being re-encoded at any of the ten intervening strata.

It exercises: `stratum`, stratified `occurrent`s, a skipping
`causal_relation_object` with `skips: true`, Algorithm C (stratal
classification), Algorithm D (the skip decision procedure — the V62/V63
asymmetry), and the acceptance query of Section 11(8).

```
python3 examples/steroid_hormone_channel/build.py
```

Every identifier printed is the real Secure Hash Algorithm 256-bit (SHA-256) of the object's RFC 8785 canonical
identity-bearing bytes, computed by the `causalontology` binding — never
assigned.

## Why this is the acceptance test

The skipping Causal Relation Object surfaces **no gap**: the absence of a
mechanism is a *finding*, not unfinished work. Cortisol is small and lipophilic;
it crosses the capillary wall, the blood-brain barrier, the plasma membrane, the
cytoplasm, and the nuclear envelope, and binds DNA. It is not re-encoded at any
intervening stratum — it simply travels. The identical record with `skips`
absent would surface `incomplete_mechanism`, and the commons would be invited,
forever, to supply ten layers of mechanism that do not exist. That asymmetry is
the entire argument for the `skips` field, and it is proven here.

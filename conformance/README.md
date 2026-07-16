# Conformance

**An implementation is Causalontology-conformant if and only if it passes every
vector in `vectors/` for the specification version it declares.** That single
rule is what guarantees that Prolog, Python, Java, and Swift implementations
agree without sharing a line of code.

There are **107 vectors**. V01–V38 are the original suite, re-frozen unaltered
in meaning under the whole-word schemes (Principle P7); V39–V107 are the 2.0.0
additions:

| Group | Covers |
|---|---|
| A–F (V01–V38) | the original six groups: schema/semantic validity, temporal admissibility, identity, signatures, conflict/hierarchy/resolve/stigmergy |
| G–H (V39–V46) | strata and occurrent stratification |
| I (V47–V55) | bridges and stratal well-formedness |
| J (V56–V58) | **bridged reachability** — incl. V58, the negative vector that proves an implementation does BRIDGED, not literal, reachability |
| K (V59–V67) | stratal classification and the **skip asymmetry** (V62/V63) |
| L (V68–V70) | the `enabling` modality |
| M (V71–V77) | ports and conduits (pipe vs computer) |
| N (V78–V79) | the realizable identity-collision repair |
| O (V80–V84) | occurrent taxonomy and mereology |
| P (V85–V102) | the token tier (individuals, occurrences, qualities, states, token causal claims) |
| Q (V103–V105) | provenance widening, `evidenced_by`, `simulation` evidence |
| R (V106) | whole-word baseline hash equality |
| S (V107) | abbreviated scheme is rejected |

## Status: RE-FROZEN at 2.0.0 (whole-word baseline)

The vectors carry **concrete bytes**: every identifier is a real, well-formed
whole-word 64-hex identifier; every key is a real Ed25519 public key; the
signature in V11 is a real, verifying Ed25519 signature. The single coordinated
re-mint + re-freeze was applied by [`freeze_2_0_0.py`](freeze_2_0_0.py)
(deterministic and idempotent — a second run changes nothing). The original
[`freeze_1_0_0.py`](freeze_1_0_0.py) is retained for lineage.

Two honest notes. Validity vectors keep uniformly-mapped well-formed ids
rather than content addresses, because V15 and V16 deliberately test
self-reference - and a genuinely content-addressed object cannot contain
its own hash, which is exactly why the rule exists (the identity vectors,
V24-V26, exercise true content addressing at run time). And the harnesses'
old symbolic-id normalization now simply passes frozen values through - it
remains only so the harnesses stay able to run historical pre-freeze
vector sets.

## Running the suite

The Python binding ships the first executable harness:

```
python3 bindings/python/tests/run_conformance.py
```

It interprets every vector against the `causalontology` package and exits
nonzero on any failure, and is the authoritative 2.0.0 reference: **107/107
pass**. Sibling runners for the other bindings carry the whole-word re-mint;
their 2.0.0 semantic port (the nine new kinds and Algorithms A–E) is tracked as
open work, so they do not yet pass the full 2.0.0 suite.

# Conformance

**An implementation is Causalontology-conformant if and only if it passes every
vector in `vectors/` for the specification version it declares.** That single
rule is what guarantees that Prolog, Python, Java, and Swift implementations
agree without sharing a line of code.

There are 38 vectors, in six groups:

| Group | Covers |
|---|---|
| A | schema validity (including purity of content objects and the closed enumerations) |
| B | semantic validity (refinement, enrichment field/shape rules, deterministic cycle-breaking) |
| C | temporal admissibility with the fixed conversion constants |
| D | identity, RFC 8785 canonicalization, idempotent merge, corroboration |
| E | signatures, retraction, key succession |
| F | formal conflict, hierarchy reachability, the resolve minimum, the closing of a stigmergic gap |

## Status: FROZEN at 1.0.0 (2026-07-13)

The vectors carry **concrete bytes**: every identifier is a real, well-formed
64-hex identifier; every key is a real Ed25519 public key; the signature in
V11 is a real, verifying Ed25519 signature over the record's canonical
identity-bearing bytes. The freeze was applied by
[`freeze_1_0_0.py`](freeze_1_0_0.py) (deterministic and idempotent - a
second run changes nothing).

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
nonzero on any failure. Sibling runners exist for JavaScript, Rust, Java,
Swift, and Go - all eight suite gates run in Continuous Integration on
every push.

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

## Status note (pre-1.0 scaffold)

The vectors currently use **symbolic identifiers** (`cro:demo1`, `occ:A`) and
signature placeholders. When the reference canonicalizer lands
(`causalontology-py`, step 2 of the roadmap), the 1.0.0 freeze will replace
symbolic identifiers with real computed SHA-256 hashes and real Ed25519
signatures generated from published test keys. The **expected behaviors are
normative now**; the concrete bytes are pinned at freeze.

Every binding must run this suite in Continuous Integration and refuse to
publish a release that fails it.

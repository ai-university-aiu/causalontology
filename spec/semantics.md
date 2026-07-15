# Semantics: the rules beyond the schemas

A document is SCHEMA-VALID if it matches its JSON Schema, and SEMANTICALLY
VALID if it also satisfies these rules. Rules 1–12 are 1.0.0; those marked
**AMENDED** carry a 2.0.0 delta. Rules 13–21 are new in 2.0.0. The five
normative algorithms (A–E) that make rules 7, 15, 16, 19, and 20 executable are
given in Section 12 of the change order and implemented in every binding.

1. **Temporal windows.** `minimum_delay <= maximum_delay` (fields formerly
   `dmin`/`dmax`, spelled out under Principle P7).
2. **Dangling reference.** Any identifier referenced but absent from the store
   surfaces `dangling_reference`. **AMENDED**: extended to every new reference
   field (Occurrent.stratum; Bridge.coarse/.fine; Port.bearer/.accepts/
   .realizable; Conduit.from/.to/.carries/.transform; token references;
   Assertion.evidenced_by).
3. **Refinement.** R refines P validly iff: R's causes and effects equal P's;
   every field P specifies, R specifies with the same value; and R adds at
   least one field P left unspecified. NOT WEAKENED: because refines requires
   identical causes and effects it cannot span strata, which is exactly why the
   Bridge is required and is not redundant with refines.
4. **Acyclicity.** **AMENDED**: the mechanism graph, the refines graph, the
   materialized `subsumes`/`part_of` graphs, AND the bridge graph,
   `occurrent_subsumes`, `occurrent_part_of`, and token `part_of` are each
   acyclic.
5. **Strength, formally** (do-calculus). **AMENDED** to add `enabling`: the
   source's estimate of P(effects possible | do(causes), context) — the degree
   to which the causes lift the effects from impossible to possible.
6. **Conflict.** **AMENDED**: `necessary`, `sufficient`, `contributory`,
   `enabling` are mutually compatible; `preventive` opposes all four. A and B
   conflict iff equal cause sets, equal effect sets, compatible contexts,
   overlapping windows, and one modality is preventive while the other is one
   of the four positive modalities.
7. **Hierarchy consistency** (BRIDGED reachability). **AMENDED — the most
   important amendment in 2.0.0.** Build the mechanism graph, then bridge-close
   each of P's causes and effects (Algorithm A), and require that for every
   (c, e) some c' in B(c) reaches some e' in B(e). Absent members make the
   check INDETERMINATE (a dangling_reference gap), not failed. An
   implementation that does only LITERAL reachability is 1.0.0-conformant and
   2.0.0-NON-conformant; vector V58 exists to catch it.
8. **Open world.** Absence is not denial. Negative causal knowledge uses the
   preventive modality, never absence.
9. **Merge.** Per identity.md: immutable objects, add-only records, set-union.
10. **Retraction.** Valid only from the retracted record's source or lineage.
11. **Succession.** Chains define a lineage; one successor per key.
12. **Enrichment validity.** **AMENDED** — two occurrent forms added:
    aliases → occurrent, continuant (entry {lang, text}); participants →
    occurrent (entry `continuant:`); subsumes → continuant (`continuant:`);
    part_of → continuant (`continuant:`); realized_in → realizable
    (`occurrent:`); **occurrent_subsumes → occurrent (`occurrent:`)**;
    **occurrent_part_of → occurrent (`occurrent:`)**.

### New rules (2.0.0)

13. **Stratal comparability.** Two strata are comparable iff they share a
    scheme. An implementation MUST NOT compare ordinals across schemes;
    attempting it surfaces `scheme_mismatch` (HARD).
14. **Bridge well-formedness.** A Bridge is well-formed iff coarse has a
    stratum; every fine member has a stratum; all fine share ONE stratum;
    coarse and fine strata share a scheme; and coarse's ordinal is STRICTLY
    GREATER than fine's. Violation surfaces `malformed_bridge` (HARD).
15. **Stratal classification** (Algorithm C, DERIVED never asserted). Every
    Causal Relation Object all of whose endpoints are stratified in one scheme
    is exactly one of INTRA-STRATAL, ADJACENT-STRATAL (ordinals differ by 1),
    SKIPPING (differ by > 1), or MIXED. Recompute on ingest.
16. **Skip coherence** (Algorithm D). If `skips` is true, mechanism MUST be
    absent/empty (else `contradictory_skip`, HARD). `skips: true` on a
    non-SKIPPING relation surfaces `vacuous_skip`. THE ASYMMETRY: a SKIPPING
    relation with empty mechanism surfaces `incomplete_mechanism` when `skips`
    is absent/false, and NOTHING when `skips` is true. Implement it exactly.
17. **Conduit well-formedness.** As N4.2.1 with the transform exception of
    N4.2.2: a transmissive conduit's carries must be accepted by both ports; a
    computational conduit's `to` must accept its transform's effects. Violation
    surfaces `malformed_conduit` (HARD).
18. **Token instantiation.** Every `token_individual:` MUST name a
    `continuant:`; every `token_occurrence:` MUST name an `occurrent:`. Absence
    is a schema failure — there are no free-floating tokens (P1).
19. **State type and unit coherence.** The value's shape MUST match the
    quality's datatype (`value_type_mismatch`); a quantity value's unit MUST
    equal the quality's unit (`unit_mismatch`). Both HARD.
20. **Covering-law coherence.** If a token claim names a `covering_law`, each
    cause/effect token SHOULD instantiate the law's causes/effects
    (`covering_law_mismatch`), and any `actual_delay` MUST fall within the
    law's window, unit-normalized by Algorithm E (`delay_outside_window`).
21. **Temporal coherence of token causation.** For every token causal claim,
    every cause token's `interval.start` MUST be ≤ every effect token's
    (`retrocausal_claim`, HARD). Backward causation, if asserted at all, must
    be a type-level claim; the token tier will not represent it.

### Store rule (materialized acyclicity, deterministic cycle-breaking)

Enforcing tiers reject cycle-creating enrichments. Under decentralized merge, a
conformant view breaks an emergent cycle deterministically — exclude the
cycle-completing record with the LATEST timestamp (ties by lexicographic
record identifier) — and surfaces it as an `inconsistent_hierarchy` repair gap.

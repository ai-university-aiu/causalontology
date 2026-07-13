# Semantics: the rules beyond the schemas

A document is SCHEMA-VALID if it matches its JSON Schema, and SEMANTICALLY
VALID if it also satisfies these rules.

1. **Temporal windows.** `dmin <= dmax`.
2. **Acyclicity.** The mechanism graph, the refines graph, and the
   materialized `subsumes`/`part_of` graphs are acyclic.
3. **Refinement.** R refines P validly iff: R's causes and effects equal P's;
   every field P specifies, R specifies with the same value; and R adds at
   least one field P left unspecified. Changing a parent's specified value is
   a rival claim, not a refinement.
4. **Temporal admissibility** (timing as mechanism). Elapsed time and window
   convert to seconds with EXACTLY these constants: instant=0, seconds=1,
   minutes=60, hours=3600, days=86400, weeks=604800, **months=2629746**
   (30.436875 days), **years=31556952** (365.2425 days). Admissible iff
   elapsed lies in [dmin, dmax]. No window = no constraint.
5. **Strength, formally** (do-calculus). sufficient/contributory: the source's
   estimate of P(effects within window | do(causes), context). preventive:
   P(effects prevented | do(causes), context). necessary: P(no effects |
   causes absent, context). Strength (world) and confidence (source's
   sureness) are distinct.
6. **Conflict.** A and B conflict iff: equal cause sets and equal effect sets;
   compatible contexts (equal, subset, or either absent); overlapping windows
   (or either absent); and one modality is preventive while the other is
   necessary/sufficient/contributory. Conflicts are surfaced, never
   auto-resolved.
7. **Hierarchy consistency** (reachability, pinned). Mechanism graph: nodes =
   occurrent identifiers; for each member m of P.mechanism add an edge from
   every element of m.causes to every element of m.effects. P is consistent
   iff every (c, e) in P.causes x P.effects has a directed path. Absent
   members make the check INDETERMINATE (a dangling_reference gap), not
   failed; a determinate failure raises an inconsistent_hierarchy gap.
8. **Open world.** Absence is not denial. Negative causal knowledge is
   expressed with the preventive modality, never by absence.
9. **Merge.** Per identity.md: immutable objects, add-only records, set-union
   replication.
10. **Retraction.** Valid only from the retracted record's source or its
    lineage. Default views exclude retracted records; history is never
    erased; retraction is not undone (re-assert instead).
11. **Succession.** Chains define a lineage; records under any key in the
    lineage attribute to one source. One successor per key; a second is a
    surfaced conflict. Succession protects PLANNED rotation; compromise
    recovery is a governance action.
12. **Enrichment validity.** aliases -> occurrent, continuant (entry
    {lang, text}); participants -> occurrent (entry cnt:); subsumes ->
    continuant (cnt:); part_of -> continuant (cnt:); realized_in ->
    realizable (occ:). Anything else is invalid.
13. **Materialized acyclicity.** Enforcing tiers reject cycle-creating
    enrichments. Under decentralized merge, a conformant view breaks an
    emergent cycle deterministically — exclude the cycle-completing record
    with the LATEST timestamp (ties by lexicographic record identifier) — and
    surfaces it as a repair gap.

# The store: operations, protocol, resolve, pagination, tiers

## Abstract operation set (every conformant implementation)

`canonicalize`, `identify`, `validate_schema`, `validate_semantics`,
`admissible(cro, elapsed_seconds)`, `conflicts(a, b)`,
`hierarchy_consistent(cro, members, bridges)` (BRIDGED reachability, Algorithm
B), `bridge_closure`, `classify_cro`, `skip_gaps`, `delay_within_window`,
`sign`, `verify` — and against a store:
`put`, `put_record`, `get` (with materialized enrichments),
`assertions_about`, `enrichments_about`, `retractions_of`, `lineage`,
`resolve`, `query`, `gaps`.

## HTTP binding (Tier A reference)

```
POST /objects            write a content object (id recomputed; idempotent)
GET  /objects/{id}       object + materialized view; ?view=raw | ?view=history
POST /records            assertion | enrichment | retraction | succession
                         (signature verified; unsigned -> quarantine)
GET  /records/{id}
GET  /assertions?about={id}
GET  /enrichments?about={id}
GET  /retractions?about={record_id}
GET  /successions?key={ed25519_key}
GET  /resolve?text=...&lang=..
POST /query              query-by-example (below); /sparql is a SHOULD
GET  /gaps?near={id}&kind={kind}
GET  /conflicts?near={id}
```

Pagination on every list endpoint: `limit` (default 100, max 1000) and
`cursor` (opaque; response carries `next_cursor`, null on last page; cursors
valid at least one hour). Auth at Tier A: account bearer token for resource
control, in addition to per-record signatures which carry the trust.

## Query-by-example (normative minimum)

```json
{ "kind": "causal_relation_object",
  "where": { "causes_contains": "occurrent:...", "modality": "sufficient",
             "refines": "causal_relation_object:...", "about": "occurrent:...", "source": "ed25519:...",
             "is_partial": true, "missing": "temporal" },
  "limit": 100, "cursor": null }
```

MUST be implemented; SPARQL, full-text, richer patterns are SHOULD.

## Resolve (conformance minimum)

Canonical-label match (after lowercase + whitespace-to-underscore
normalization) MUST return; unretracted alias text matching case-insensitively
MUST return; ranking: canonical first, alias second, fuzzy extras (permitted,
implementation-defined) after.

## Tiers

- **A (central hosted)** — start here. One store behind the binding.
- **B (federated)** — nodes push/pull like Git.
- **C (decentralized)** — content-addressed Merkle DAG; the data model is a
  CRDT by construction (immutable objects + add-only records + set-union),
  with the deterministic cycle-breaking view rule as the only edge case.
The data model migrates A -> B -> C unchanged.

## The stigmergy read

Gap kinds returned by `gaps`: `missing_field`, `dangling_reference`,
`empty_mechanism`, `inconsistent_hierarchy`, `conflict`, `demand_supply`.
Closing them is done with `refines` objects and enrichment records; a validly
refined parent leaves the gap list — the gap visibly closes.

### The 2.0.0 gap taxonomy (twenty-one new entries)

Gaps are stigmergic invitations, EXCEPT those marked HARD, which are schema or
semantic validation failures and MUST cause rejection. Nine are HARD; twelve
are invitations.

| Gap | Kind | Meaning |
|---|---|---|
| `scheme_mismatch` | HARD | two strata compared across schemes |
| `malformed_bridge` | HARD | a Bridge violating stratal well-formedness (N3.2.1) |
| `bridge_cycle` | HARD | a cycle in the bridge graph |
| `unstratified_occurrent` | invitation | an occurrent with no stratum |
| `malformed_conduit` | HARD | a Conduit whose carries is not accepted by its ports |
| `collided_realizable` | invitation | an unlabelled realizable whose bearer bears >1 of the same kind |
| `contradictory_skip` | HARD | `skips: true` AND a non-empty mechanism |
| `vacuous_skip` | invitation | `skips: true` on a non-SKIPPING relation |
| `individual_cycle` | HARD | a cycle in token mereology |
| `stratum_mismatch` | invitation | a token whose participants' strata are incoherent with its occurrent's |
| `value_type_mismatch` | HARD | a state value whose shape ≠ its quality's datatype |
| `unit_mismatch` | HARD | a quantity state whose unit ≠ its quality's unit |
| `uncovered_causation` | invitation | a token causal claim with no covering_law — the most valuable gap |
| `delay_outside_window` | invitation | an observed delay outside the covering law's window |
| `occurrent_hierarchy_cycle` | HARD | a cycle in `occurrent_subsumes` |
| `occurrent_mereology_cycle` | HARD | a cycle in `occurrent_part_of` |
| `subsumption_crosses_strata` | invitation | `occurrent_subsumes` between different strata; a Bridge was probably meant |
| `covering_law_mismatch` | invitation | a token claim whose tokens do not instantiate its law's occurrents |
| `retrocausal_claim` | HARD | a token cause whose interval starts after its effect's |
| `mixed_stratal_endpoints` | invitation | a relation whose causes or effects span multiple strata |
| `incomplete_mechanism` | invitation | a SKIPPING relation with empty mechanism and `skips` absent (contrast `contradictory_skip`) |

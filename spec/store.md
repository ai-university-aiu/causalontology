# The store: operations, protocol, resolve, pagination, tiers

## Abstract operation set (every conformant implementation)

`canonicalize`, `identify`, `validate_schema`, `validate_semantics`,
`admissible(cro, elapsed_seconds)`, `conflicts(a, b)`,
`hierarchy_consistent(cro, members)`, `sign`, `verify` — and against a store:
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
{ "kind": "cro",
  "where": { "causes_contains": "occ:...", "modality": "sufficient",
             "refines": "cro:...", "about": "occ:...", "source": "ed25519:...",
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

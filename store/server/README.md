# The Tier A reference store (roadmap step 3 — done)

The HTTP binding of [`spec/store.md`](../../spec/store.md) over the conformant
in-memory store of [`causalontology-py`](../../bindings/python/). Zero
dependencies — Python standard library only.

## Run it

```
python3 store/server/server.py                      # http://127.0.0.1:8785
python3 store/server/server.py --token SECRET       # writes need the bearer token
python3 store/server/server.py --state store.json   # persist across restarts
python3 store/server/server.py --no-enforce         # replica mode (no write gates)
```

(The default port is 8785 — a nod to RFC 8785, the canonicalization scheme.)

## What it implements

- `POST /objects` — idempotent, content-addressed writes (`201` created /
  `200` existing)
- `POST /records` — assertions, enrichments, retractions, successions;
  **Ed25519 signatures verified**; unsigned or unverifiable records go to
  quarantine (`202`), excluded from default views; retractions checked
  against the source's succession lineage; enforcing tier rejects
  taxonomy-cycle enrichments (`422`)
- `GET /objects/{id}` — the object **with its materialized enrichment view**
  (entries + contributors); `?view=raw` and `?view=history`
- `GET /assertions|enrichments|retractions|successions` — provenance lookups;
  default views honor retractions, `?view=history` shows everything, marked
- `GET /resolve?text=&lang=` — the conformance minimum: canonical-label match
  first, case-insensitive alias match second
- `POST /query` — the query-by-example normative minimum (`kind`, `where`
  with equality / `causes_contains` / `effects_contains` / `is_partial` /
  `missing`)
- `GET /gaps?kind=&near=` — **the stigmergy read**: `missing_field`,
  `empty_mechanism`, `dangling_reference`, `inconsistent_hierarchy`,
  `conflict`
- `GET /conflicts` — the surfaced contradictions
- **Pagination everywhere**: `limit` (default 100, max 1,000) + opaque
  `cursor`; responses carry `items` and `next_cursor`
- **Auth**: bearer token for writes when configured (the token controls
  resource use; the signatures carry the trust)

## Test it

```
python3 store/server/test_server.py
...
20/20 smoke checks passed
Tier A reference store: end-to-end OK over real HTTP.
```

The smoke test drives the whole quickstart over HTTP: vocabulary, the
degenerate claim, the visible gap, the refinement that closes it, signed
assertions, quarantine, retraction, resolve, a surfaced conflict, pagination,
and auth.

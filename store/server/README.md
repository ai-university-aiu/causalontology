# The Tier A reference store (roadmap step 3 — done)

The HTTP binding of [`spec/store.md`](../../spec/store.md) over the conformant
store of [`causalontology-py`](../../bindings/python/). Zero dependencies —
Python standard library only.

By default it is now a **persistent, content-addressed node** — Phase one of
Part 21 (Commons Storage and Federation Design). See
[Persistence](#persistence-phase-one-of-part-21) below.

## Run it

```
python3 store/server/server.py                      # persistent node, http://127.0.0.1:8785
python3 store/server/server.py --db /path/store.db  # choose the database file
python3 store/server/server.py --token SECRET       # writes need the bearer token
python3 store/server/server.py --in-memory          # volatile store (data lost on exit)
python3 store/server/server.py --state store.json   # legacy JSON snapshot (in-memory)
python3 store/server/server.py --no-enforce         # replica mode (no write gates)
```

(The default port is 8785 — a nod to RFC 8785, the canonicalization scheme.)

## Persistence (Phase one of Part 21)

The node keeps its data in a durable, content-addressed
[`storage.py`](storage.py) layer instead of volatile memory — **changing where
the data lives while changing nothing about what the store does, the endpoints
it serves, or the bytes it returns.** A client cannot tell the store
restarted, except that its data survived.

- **Engine: SQLite in write-ahead-logging (WAL) mode.** SQLite ships with
  Python (zero install, zero operational setup), is ACID and crash-safe, and
  is a single portable file — the right choice for a reference node. WAL gives
  durable writes with concurrent reads. RocksDB, LMDB, and S3-compatible
  object stores are named in Part 21 as later, higher-scale options; phase one
  does not introduce them.
- **Table layout mirrors the standard's content-versus-provenance split.**
  `content` holds the immutable objects (primary key = the `scheme:hash`
  identifier); `provenance` holds the signed, add-only records (with the
  Ed25519 signature); `quarantine` holds unsigned/unverifiable records. The
  derived/index tables — `record_index`, `object_view`, `gap_registry`,
  `reputation` — are **not** sources of truth: they are reconstructable from
  content and provenance alone, rebuilt on startup when absent and after
  writes.
- **Integrity on write.** A content object is stored only if its identifier
  equals `scheme:` + SHA-256 of its canonical identity-bearing bytes
  (`spec/identity.md`); a mismatch is rejected (`422`) and never persisted.
- **Idempotent by content address.** Writing an identifier that already exists
  is a no-op, exactly as the CRDT union semantics require.
- **Configuration.** The database path comes from `--db` or the
  `CAUSALONTOLOGY_STORE_DB` / `CAUSALONTOLOGY_DATA` environment variable, with
  a default at `store/server/data/causalontology.db` (git-ignored, so a real
  database is never committed). A cold start against an existing database
  serves everything previously stored with no re-ingest step.

Phases two through four remain open roadmap (Part 21): a genesis full node plus
signed snapshot dumps, then Tier B federation with gossip and anti-entropy,
then light clients with CDN caching and hash-prefix sharding.

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

## Beyond-MVP endpoints (roadmap step 5)

- **`GET|POST /sparql`** — the SHOULD-level endpoint, as a documented subset:
  `SELECT` over one basic graph pattern (variables, prefixed names, quoted
  literals; joins across patterns), returning the SPARQL JSON results
  format. Predicates: `co:hasCause`, `co:hasEffect`, `co:hasMechanism`,
  `co:refines`, `co:modality`, `co:alias`, `co:isA`, `co:about`,
  `co:evidenceType`, `prov:wasAttributedTo`, and friends — see
  [`spec/schema/causalontology.owl.ttl`](../../spec/schema/causalontology.owl.ttl).
- **`GET /export/triples`** — the whole store as N-Triples (retraction-aware,
  cycle-broken views), for any RDF toolchain.
- **`GET /reputation?source=`** — glass-box reputation computed from the
  signed history: contributions, corroborated entries, retractions,
  evidence-grade histogram, succession-lineage aware.
- **`GET /sync/export` + `POST /sync/pull {"peer": url}`** — Tier B
  federation: pull-based set-union merge; signatures verified on entry,
  the deterministic view rules judge the union.
- Tier C lives in [`replicate.py`](replicate.py): offline bundles, set-union
  merge (commutative, associative, idempotent — tested in
  [`test_tierc.py`](test_tierc.py)), and `verify` — tamper evidence from
  content addressing and signatures alone.

Tests: `test_beyond.py` (11 checks: SPARQL, triples, reputation, two live
servers federating) and `test_tierc.py` (8 checks: the Conflict-free Replicated Data Type (CRDT) laws, identical
cycle-breaking on every replica, forged bytes caught).

Persistence: `test_persistence.py` (15 checks) drives a real `server.py`
subprocess to prove durability across a process restart, idempotent
re-writes, integrity rejection, and that the derived views rebuild
byte-identically from content and provenance alone.

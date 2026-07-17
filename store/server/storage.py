#!/usr/bin/env python3
"""Persistent, content-addressed storage for the Tier A reference node.

Phase one of Part 21 of the canon (Commons Storage and Federation Design):
harden the Tier A store from a volatile in-memory service into a durable,
content-addressed NODE - WITHOUT changing a single HTTP endpoint, response
shape, identity rule, or merge semantic. This module changes WHERE the data
lives; nothing about what the store does or the bytes it returns.

Why SQLite for phase one
------------------------
SQLite ships with Python (zero dependencies, zero operational setup), it is
ACID and crash-safe, and the whole database is one portable file - exactly the
right engine for a reference node. Enabling write-ahead logging (WAL) gives
durable writes with concurrent reads. RocksDB, LMDB, and S3-compatible object
stores are named in Part 21 as later, higher-scale options; phase one does
not introduce them.

Table layout (mirrors the standard's content-versus-provenance split)
---------------------------------------------------------------------
Sources of truth:
  content     immutable content objects; primary key = identifier
              (scheme:hash); value = the exact stored JSON the store serves.
  provenance  signed, add-only provenance records (assertion, enrichment,
              retraction, succession); primary key = identifier; the Ed25519
              signature is kept in its own column as well as in the record.
  quarantine  unsigned or unverifiable records, held out of default views.

Derived / index tables (NOT sources of truth; reconstructable from content
and provenance ALONE, rebuilt on startup when absent and after writes):
  record_index  a flat index of every provenance record (kind, about,
                retracts, predecessor, successor, source, timestamp).
  object_view   the materialized enrichment view of each content object.
  gap_registry  the six content+provenance gap kinds (the stigmergy read).
  reputation    the glass-box reputation of every contributing source.

Integrity on write
-------------------
A content object is stored only if its identifier equals
scheme + ":" + SHA-256 of its canonical identity-bearing bytes
(spec/identity.md). A mismatch is rejected as a RejectedWrite and never
persisted - the identity law, enforced durably at the storage boundary.
"""

import json
import os
import sqlite3
import threading
from collections.abc import MutableMapping
from pathlib import Path

from causalontology import InMemoryStore, RejectedWrite, identify

# The environment variable that names the database file, with a sensible
# default under a data directory in the repo (git-ignored, see .gitignore).
ENV_VARS = ("CAUSALONTOLOGY_STORE_DB", "CAUSALONTOLOGY_DATA")
DEFAULT_DB = Path(__file__).resolve().parent / "data" / "causalontology.db"

# The derived tables - everything here is a re-computable reading of the two
# source-of-truth tables, never a source of truth in its own right.
DERIVED_TABLES = ("record_index", "object_view", "gap_registry", "reputation")


def default_db_path():
    """The configured database path: the environment variable, else the default."""
    for var in ENV_VARS:
        value = os.environ.get(var)
        if value:
            return value
    return str(DEFAULT_DB)


# ---------------------------------------------------------------------------
# the SQLite backend: owns the connection, the schema, and every write
# ---------------------------------------------------------------------------
class SqliteBackend:
    """The durable engine. A single connection guarded by one lock; WAL mode
    gives durability and concurrent reads. Every method is self-contained and
    acquires the lock for exactly its own database work."""

    def __init__(self, db_path):
        self.db_path = str(db_path)
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")     # durable + concurrent reads
        self._conn.execute("PRAGMA synchronous=NORMAL")   # WAL-safe durability
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._create_schema()

    def _create_schema(self):
        with self._lock:
            c = self._conn
            c.execute("CREATE TABLE IF NOT EXISTS content ("
                      " id TEXT PRIMARY KEY, body TEXT NOT NULL)")
            c.execute("CREATE TABLE IF NOT EXISTS provenance ("
                      " id TEXT PRIMARY KEY, body TEXT NOT NULL, signature TEXT)")
            c.execute("CREATE TABLE IF NOT EXISTS quarantine ("
                      " id TEXT PRIMARY KEY, body TEXT NOT NULL)")
            c.execute("CREATE TABLE IF NOT EXISTS meta ("
                      " key TEXT PRIMARY KEY, value TEXT)")
            self._create_derived_schema()
            c.commit()

    def _create_derived_schema(self):
        c = self._conn
        c.execute("CREATE TABLE IF NOT EXISTS record_index ("
                  " id TEXT PRIMARY KEY, kind TEXT, about TEXT, retracts TEXT,"
                  " predecessor TEXT, successor TEXT, source TEXT, timestamp TEXT)")
        c.execute("CREATE TABLE IF NOT EXISTS object_view ("
                  " id TEXT PRIMARY KEY, body TEXT NOT NULL)")
        c.execute("CREATE TABLE IF NOT EXISTS gap_registry ("
                  " seq INTEGER PRIMARY KEY, body TEXT NOT NULL)")
        c.execute("CREATE TABLE IF NOT EXISTS reputation ("
                  " source TEXT PRIMARY KEY, body TEXT NOT NULL)")

    # ------------------------------------------------------- source-of-truth
    def put_content(self, obj):
        """Store an immutable content object, keyed by its identifier.

        Integrity on write: the identifier must equal the hash of the object's
        canonical identity-bearing bytes, or the write is rejected. Writing an
        identifier that already exists is a no-op (idempotent), exactly as the
        CRDT union semantics require."""
        oid = obj.get("id")
        expected = identify(obj)
        if oid != expected:
            raise RejectedWrite(
                "identifier does not match content: %s is stored under %r but "
                "its canonical bytes hash to %r" % (obj.get("type"), oid, expected))
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO content (id, body) VALUES (?, ?)",
                (oid, json.dumps(obj)))
            self._mark_dirty()
            self._conn.commit()
        return oid

    def put_record(self, record):
        """Store a signed provenance record in the add-only log, keyed by its
        identifier. Re-writing an existing record is idempotent."""
        rid = record["id"]
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO provenance (id, body, signature) "
                "VALUES (?, ?, ?)",
                (rid, json.dumps(record), record.get("signature")))
            self._mark_dirty()
            self._conn.commit()
        return rid

    def put_quarantine(self, record):
        rid = record["id"]
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO quarantine (id, body) VALUES (?, ?)",
                (rid, json.dumps(record)))
            self._conn.commit()
        return rid

    # ----------------------------------------------------- generic accessors
    def get(self, table, key):
        """Return a stored object or record by identifier, or None (absent)."""
        with self._lock:
            row = self._conn.execute(
                "SELECT body FROM %s WHERE id = ?" % table, (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def has(self, table, key):
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM %s WHERE id = ?" % table, (key,)).fetchone()
        return row is not None

    def count(self, table):
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) FROM %s" % table).fetchone()[0]

    def ids(self, table):
        with self._lock:
            return [r[0] for r in self._conn.execute(
                "SELECT id FROM %s" % table).fetchall()]

    def values(self, table):
        """Scan: every stored body, insertion order preserved by rowid."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT body FROM %s ORDER BY rowid" % table).fetchall()
        return [json.loads(r[0]) for r in rows]

    def items(self, table):
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, body FROM %s ORDER BY rowid" % table).fetchall()
        return [(r[0], json.loads(r[1])) for r in rows]

    def delete(self, table, key):
        with self._lock:
            self._conn.execute("DELETE FROM %s WHERE id = ?" % table, (key,))
            self._conn.commit()

    # ------------------------------------------------------------ meta flags
    def _mark_dirty(self):
        self._conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('derived_dirty', '1')")

    def is_dirty(self):
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key = 'derived_dirty'").fetchone()
        return row is None or row[0] != "0"

    def derived_present(self):
        """True iff every derived table exists in the database."""
        with self._lock:
            names = {r[0] for r in self._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        return all(t in names for t in DERIVED_TABLES)

    # ---------------------------------------------------- derived rebuild I/O
    def write_derived(self, record_index, object_views, gaps, reputations):
        """Replace the derived tables with a freshly computed materialization,
        then mark the derived layer clean. Called by PersistentStore, which
        computes the arguments from the source-of-truth tables alone."""
        with self._lock:
            c = self._conn
            self._create_derived_schema()
            for t in DERIVED_TABLES:
                c.execute("DELETE FROM %s" % t)
            c.executemany(
                "INSERT INTO record_index (id, kind, about, retracts, "
                "predecessor, successor, source, timestamp) "
                "VALUES (?,?,?,?,?,?,?,?)", record_index)
            c.executemany(
                "INSERT INTO object_view (id, body) VALUES (?, ?)", object_views)
            c.executemany(
                "INSERT INTO gap_registry (seq, body) VALUES (?, ?)",
                list(enumerate(gaps)))
            c.executemany(
                "INSERT INTO reputation (source, body) VALUES (?, ?)", reputations)
            c.execute(
                "INSERT OR REPLACE INTO meta (key, value) "
                "VALUES ('derived_dirty', '0')")
            c.commit()

    def drop_derived(self):
        """Drop every derived/index table (the source of truth is untouched)."""
        with self._lock:
            for t in DERIVED_TABLES:
                self._conn.execute("DROP TABLE IF EXISTS %s" % t)
            self._conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) "
                "VALUES ('derived_dirty', '1')")
            self._conn.commit()

    def dump_derived(self):
        """A deterministic snapshot of the derived tables, for equality checks."""
        with self._lock:
            c = self._conn
            return {
                "record_index": c.execute(
                    "SELECT id, kind, about, retracts, predecessor, successor, "
                    "source, timestamp FROM record_index ORDER BY id").fetchall(),
                "object_view": c.execute(
                    "SELECT id, body FROM object_view ORDER BY id").fetchall(),
                "gap_registry": c.execute(
                    "SELECT body FROM gap_registry ORDER BY seq").fetchall(),
                "reputation": c.execute(
                    "SELECT source, body FROM reputation "
                    "ORDER BY source").fetchall(),
            }

    def close(self):
        with self._lock:
            try:
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.Error:
                pass
            self._conn.commit()
            self._conn.close()


# ---------------------------------------------------------------------------
# dict-like views so the store's .objects/.records/.quarantine are durable
# ---------------------------------------------------------------------------
class _TableMap(MutableMapping):
    """A persistent stand-in for one of the store's in-memory dicts. It offers
    exactly the mapping surface InMemoryStore and the server use, so the store
    logic above it is untouched - only WHERE the bytes live changes."""

    def __init__(self, backend, table):
        self._backend = backend
        self._table = table

    def __getitem__(self, key):
        row = self._backend.get(self._table, key)
        if row is None:
            raise KeyError(key)
        return row

    def __delitem__(self, key):
        self._backend.delete(self._table, key)

    def __iter__(self):
        return iter(self._backend.ids(self._table))

    def __len__(self):
        return self._backend.count(self._table)

    def __contains__(self, key):
        return self._backend.has(self._table, key)

    def get(self, key, default=None):
        row = self._backend.get(self._table, key)
        return row if row is not None else default

    def keys(self):
        return self._backend.ids(self._table)

    def values(self):
        return self._backend.values(self._table)

    def items(self):
        return self._backend.items(self._table)

    def __setitem__(self, key, value):
        raise NotImplementedError  # subclasses route through the right write


class _ContentMap(_TableMap):
    def __setitem__(self, key, value):
        self._backend.put_content(value)  # integrity-checked, idempotent


class _ProvenanceMap(_TableMap):
    def __setitem__(self, key, value):
        self._backend.put_record(value)   # add-only, idempotent


class _QuarantineMap(_TableMap):
    def __setitem__(self, key, value):
        self._backend.put_quarantine(value)


# ---------------------------------------------------------------------------
# the persistent store: a drop-in InMemoryStore whose dicts are durable
# ---------------------------------------------------------------------------
class PersistentStore(InMemoryStore):
    """The reference Tier A node, made durable. Every method, validation gate,
    identity rule, and materialized-view computation is inherited unchanged
    from InMemoryStore; only the three dictionaries it keeps its data in are
    replaced by SQLite-backed views. A cold start against an existing database
    serves all previously stored data with no re-ingest step."""

    def __init__(self, enforcing=True, db_path=None, backend=None):
        self.enforcing = enforcing
        self.backend = backend or SqliteBackend(db_path or default_db_path())
        self.objects = _ContentMap(self.backend, "content")
        self.records = _ProvenanceMap(self.backend, "provenance")
        self.quarantine = _QuarantineMap(self.backend, "quarantine")
        # On startup rebuild the derived views if they are absent or stale, so
        # that a node coming up on an existing database is immediately whole.
        if not self.backend.derived_present() or self.backend.is_dirty():
            self.rebuild_views()

    # ------------------------------------------------ derived-view materializer
    def _materialize(self):
        """Compute the derived tables from content and provenance ALONE.

        This is the single source of the rebuild: object views, the gap
        registry, the reputation of every source, and the flat record index
        are all re-derived from the two source-of-truth tables by the very
        methods the endpoints use, so a rebuilt node is identical to a
        maintained one."""
        record_index = []
        for rid, rec in self.records.items():
            record_index.append((
                rid, rec.get("type"), rec.get("about"), rec.get("retracts"),
                rec.get("predecessor"), rec.get("successor"),
                rec.get("source"), rec.get("timestamp")))
        object_views = [
            (oid, json.dumps(self.get(oid), sort_keys=True))
            for oid in self.objects.keys()]
        gaps = [json.dumps(g, sort_keys=True) for g in self.gaps(None)]
        reputations = [
            (src, json.dumps(self._reputation(src), sort_keys=True))
            for src in sorted(self._record_sources())]
        return record_index, object_views, gaps, reputations

    def rebuild_views(self):
        """Reconstruct every derived/index table from content and provenance."""
        record_index, object_views, gaps, reputations = self._materialize()
        self.backend.write_derived(record_index, object_views, gaps, reputations)

    def _record_sources(self):
        """Every distinct contributing source key in the provenance log."""
        out = set()
        for rec in self.records.values():
            key = rec.get("source") or rec.get("predecessor")
            if key:
                out.add(key)
        return out

    def _reputation(self, source):
        """A glass-box reputation summary derived from the signed record
        history - the same shape the /reputation endpoint reads, computed here
        from the store alone so it can be materialized and rebuilt."""
        lineage = self.lineage(source)
        retracted = self._retracted_ids()
        assertions = enrichments = retractions = self_retracted = 0
        evidence = {}
        timestamps = []
        for rec in self.records.values():
            src = rec.get("source") or rec.get("predecessor")
            if src not in lineage:
                continue
            timestamps.append(rec.get("timestamp", ""))
            kind = rec.get("type")
            if kind == "assertion":
                assertions += 1
                evidence[rec["evidence_type"]] = \
                    evidence.get(rec["evidence_type"], 0) + 1
                if rec["id"] in retracted:
                    self_retracted += 1
            elif kind == "enrichment":
                enrichments += 1
            elif kind == "retraction":
                retractions += 1
        return {"source": source, "lineage_size": len(lineage),
                "assertions": assertions, "enrichments": enrichments,
                "retractions_issued": retractions,
                "self_retracted": self_retracted,
                "evidence_histogram": evidence,
                "active_since": min(timestamps) if timestamps else None}

    def close(self):
        """Flush and close the database cleanly (shutdown)."""
        self.backend.close()

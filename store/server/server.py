#!/usr/bin/env python3
"""The Causalontology Tier A reference store server (roadmap step 3).

The HTTP binding of spec/store.md over the conformant in-memory store of
causalontology-py. Zero dependencies: Python standard library only.

    python3 store/server/server.py [--port 8785] [--token SECRET]
                                   [--state store.json] [--no-enforce]

- Every list endpoint paginates with ?limit= (default 100, max 1,000) and an
  opaque ?cursor=; responses carry items and next_cursor (null on the last
  page).
- Writes require the bearer token when one is configured (the token controls
  resource use; the per-record Ed25519 signatures carry the trust).
- Unsigned or unverifiable records are accepted into quarantine only (HTTP
  202), excluded from default views, per spec/safety.md.
- By default the store is a persistent, content-addressed SQLite node
  (storage.py): durable across restarts, idempotent by content address, and
  integrity-checked on write. The database path comes from --db or the
  CAUSALONTOLOGY_STORE_DB / CAUSALONTOLOGY_DATA environment variable, with a
  default under store/server/data/. --in-memory keeps the volatile store, and
  the legacy --state JSON snapshot still works over the in-memory store.
"""

import argparse
import base64
import json
import re
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "bindings" / "python"))

from causalontology import InMemoryStore, RejectedWrite, is_partial  # noqa: E402
from causalontology import __version__ as SDK_VERSION                # noqa: E402

import federation as fed                                             # noqa: E402
import snapshot as snap                                              # noqa: E402
import sharding as shd                                               # noqa: E402

SPEC_VERSION = "1.0.0"

# Phase four - CDN-friendly caching of immutable content. A content object and a
# provenance record are IMMUTABLE and CONTENT-ADDRESSED: their name is their
# hash, so they can be cached forever with no invalidation problem. Immutable
# responses carry this header plus an ETag equal to the identifier; a CDN or
# reverse proxy may keep them indefinitely, and a light client verifies every
# byte by hash regardless of who served it, so a stale or hostile cache cannot
# deceive it. One year is the effective "forever" HTTP allows (RFC 9111).
IMMUTABLE_CACHE = "public, max-age=31536000, immutable"

# Mutable and derived views (the materialized object view, the gap registry,
# reputation, and every listing that changes as records arrive) are NOT cached
# as if immutable - they carry no-cache so an edge never serves a stale view.
MUTABLE_CACHE = "no-cache"


# ---------------------------------------------------------------------------
# pagination: opaque offset cursors, valid indefinitely on this reference
# ---------------------------------------------------------------------------
def _encode_cursor(offset):
    return base64.urlsafe_b64encode(("o:%d" % offset).encode()).decode()


def _decode_cursor(cursor):
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        if raw.startswith("o:"):
            return max(0, int(raw[2:]))
    except Exception:  # noqa: BLE001
        pass
    return 0


def paginate(items, limit, cursor):
    limit = max(1, min(int(limit or 100), 1000))
    offset = _decode_cursor(cursor) if cursor else 0
    page = items[offset:offset + limit]
    nxt = _encode_cursor(offset + limit) if offset + limit < len(items) else None
    return {"items": page, "next_cursor": nxt}


# ---------------------------------------------------------------------------
# the server
# ---------------------------------------------------------------------------
_NT_PREFIX = {"co": "https://causalontology.org/ns#",
              "prov": "http://www.w3.org/ns/prov#",
              "rdf": "http://www.w3.org/1999/02/22-rdf-syntax-ns#"}


def _nt_term(term):
    pfx, _, local = term.partition(":")
    if pfx in _NT_PREFIX:
        return "<%s%s>" % (_NT_PREFIX[pfx], local)
    return "<https://causalontology.org/id/%s>" % term


def _nt_literal(value):
    return '"%s"' % str(value).replace("\\", "\\\\").replace('"', '\\"')


# the value weights for ranking gaps ("the most valuable gaps first")
KIND_VALUE = {"conflict": 5, "inconsistent_hierarchy": 4, "missing_field": 3,
              "demand_supply": 3, "dangling_reference": 2,
              "empty_mechanism": 1}

WEAK_EVIDENCE = {"imported", "human_hint"}


class StoreServer(ThreadingHTTPServer):
    def __init__(self, addr, store, token=None, state_path=None,
                 demand_threshold=3, peers=None, federation_opts=None,
                 shard=None, shard_map=None):
        super().__init__(addr, Handler)
        self.store = store
        self.token = token
        self.state_path = state_path
        self.demand = {}                      # identifier -> read count
        self.demand_threshold = demand_threshold
        # Phase four - hash-prefix sharding. shard is a sharding.ShardConfig (the
        # slice of the identifier space this node holds), or None for a FULL node
        # that holds everything. A full node behaves exactly as it did before
        # this phase: it covers the whole space and never redirects. shard_map is
        # a sharding.ShardMap of known peers' coverage, so a request for an
        # identifier outside this node's slice is answered with a pointer to a
        # node that holds it, instead of a false "not found".
        self.partial = shard is not None
        self.shard = shard or shd.ShardConfig.full()
        self.shard_map = shard_map or shd.ShardMap()
        # Whether the public light-client / CDN read path serves the token tier.
        # Local by default (spec/safety.md): token-tier content is not exposed on
        # the public path and is not placed in public shards unless the operator
        # opts in, matching the federation and snapshot boundary exactly.
        self.serve_tokens = bool((federation_opts or {}).get("include_tokens"))
        # Live Tier B federation (Phase three), now shard-aware (Phase four).
        # Constructed inert: with no peers it adds no behavior and never touches
        # the network. main() (or a test) supplies peers and calls
        # federation.start() to go live.
        fed_opts = dict(federation_opts or {})
        self.federation = fed.FederationManager(store, peers=peers, shard=shard,
                                                **fed_opts)

    def note_demand(self, identifier):
        if identifier:
            self.demand[identifier] = self.demand.get(identifier, 0) + 1

    def demand_gaps(self):
        """The demand_supply gap kind: high demand, weak supply (spec Part 10)."""
        out = []
        for oid, obj in self.store.objects.items():
            if obj.get("type") != "causal_relation_object":
                continue
            demand = self.demand.get(oid, 0)
            if demand < self.demand_threshold:
                continue
            assertions = self.store.assertions_about(oid)
            weak = (not assertions
                    or all(a.get("evidence_type") in WEAK_EVIDENCE
                           for a in assertions))
            if weak:
                out.append({"id": oid, "kind": "demand_supply",
                            "demand": demand,
                            "note": "read %d times; %s" % (
                                demand,
                                "no assertions" if not assertions
                                else "only low-grade evidence")})
        return out

    def ranked_gaps(self, kind=None):
        """All gaps (the six kinds), each scored and sorted by value."""
        if kind == "demand_supply":
            gaps = self.demand_gaps()
        elif kind is None:
            gaps = self.store.gaps(None) + self.demand_gaps()
        else:
            gaps = self.store.gaps(kind)
        for g in gaps:
            base = KIND_VALUE.get(g.get("kind"), 1)
            if "id" in g:
                base += self.demand.get(g["id"], 0)
            elif "a" in g:  # a conflict pair
                base += max(self.demand.get(g["a"], 0),
                            self.demand.get(g["b"], 0))
            g["value"] = base
        gaps.sort(key=lambda g: (-g["value"], json.dumps(g, sort_keys=True)))
        return gaps

    # ------------------------------------------------ linked-data view
    def triples(self):
        """The store as (subject, predicate, object, is_literal) triples."""
        out = []
        store = self.store

        def emit(s, p, o, lit=False):
            out.append((s, p, o, lit))

        type_curie = {"causal_relation_object": "co:CausalRelationObject",
                      "occurrent": "co:Occurrent",
                      "continuant": "co:Continuant",
                      "realizable": "co:Realizable"}
        for oid, obj in store.objects.items():
            kind = obj.get("type")
            emit(oid, "rdf:type", type_curie.get(kind, "co:Thing"))
            if kind == "causal_relation_object":
                for c in obj.get("causes", []):
                    emit(oid, "co:hasCause", c)
                for e in obj.get("effects", []):
                    emit(oid, "co:hasEffect", e)
                for m in obj.get("mechanism", []):
                    emit(oid, "co:hasMechanism", m)
                for cx in obj.get("context", []):
                    emit(oid, "co:enablingContext", cx)
                if obj.get("refines"):
                    emit(oid, "co:refines", obj["refines"])
                if obj.get("modality"):
                    emit(oid, "co:modality", obj["modality"], True)
                if obj.get("temporal"):
                    tw = obj["temporal"]
                    emit(oid, "co:temporalDmin", str(tw["minimum_delay"]), True)
                    emit(oid, "co:temporalDmax", str(tw["maximum_delay"]), True)
                    emit(oid, "co:temporalUnit", tw["unit"], True)
            if kind in ("occurrent", "continuant"):
                emit(oid, "co:canonicalLabel", obj.get("label", ""), True)
                emit(oid, "co:category", obj.get("category", ""), True)
            if kind == "realizable":
                emit(oid, "co:bearer", obj.get("bearer"))
                emit(oid, "co:kind", obj.get("kind", ""), True)
        # materialized enrichment views (retraction-aware, cycle-broken)
        field_pred = {"aliases": "co:alias", "participants": "co:participant",
                      "subsumes": "co:isA", "part_of": "co:partOf",
                      "realized_in": "co:realizedIn"}
        for oid in store.objects:
            view = store.get(oid)
            for field, entries in view.get("enrichments", {}).items():
                pred = field_pred[field]
                for entry in entries:
                    val = entry["entry"]
                    if isinstance(val, dict):
                        emit(oid, pred, val.get("text", ""), True)
                    else:
                        emit(oid, pred, val)
        # unretracted assertions
        retracted = store._retracted_ids()
        for rec in store.records.values():
            if rec.get("type") != "assertion" or rec["id"] in retracted:
                continue
            emit(rec["id"], "rdf:type", "co:Assertion")
            emit(rec["id"], "co:about", rec["about"])
            emit(rec["id"], "prov:wasAttributedTo", rec["source"], True)
            emit(rec["id"], "co:evidenceType", rec["evidence_type"], True)
            if "strength" in rec:
                emit(rec["id"], "co:strengthEstimate", str(rec["strength"]), True)
            emit(rec["id"], "co:confidence", str(rec["confidence"]), True)
            emit(rec["id"], "prov:generatedAtTime", rec["timestamp"], True)
        return out

    # ------------------------------------------------------- reputation
    def reputation(self, source):
        """Glass-box reputation: computed from the signed record history."""
        store = self.store
        lineage = store.lineage(source)
        retracted = store._retracted_ids()
        assertions = enrichments = retractions = self_retracted = 0
        corroborated = 0
        evidence = {}
        timestamps = []
        for rec in store.records.values():
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
                for other in store.records.values():
                    if (other.get("type") == "enrichment"
                            and other["id"] != rec["id"]
                            and other.get("source") not in lineage
                            and other.get("about") == rec.get("about")
                            and other.get("field") == rec.get("field")
                            and other.get("entry") == rec.get("entry")):
                        corroborated += 1
                        break
            elif kind == "retraction":
                retractions += 1
        return {"source": source, "lineage_size": len(lineage),
                "assertions": assertions, "enrichments": enrichments,
                "retractions_issued": retractions,
                "self_retracted": self_retracted,
                "corroborated_entries": corroborated,
                "evidence_histogram": evidence,
                "active_since": min(timestamps) if timestamps else None}

    # --------------------------------------------------- Tier B federation
    def merge_bundle(self, bundle):
        """Set-union merge of a peer's export (Tier B pull)."""
        from causalontology import RejectedWrite as _RW
        counts = {"objects_added": 0, "records_added": 0, "skipped": 0}
        for obj in bundle.get("objects", []):
            if obj.get("id") in self.store.objects:
                continue
            try:
                self.store.put(obj)
                counts["objects_added"] += 1
            except (_RW, ValueError):
                counts["skipped"] += 1
        for rec in bundle.get("records", []):
            if rec.get("id") in self.store.records:
                continue
            try:
                self.store.force_merge_record(rec)
                counts["records_added"] += 1
            except (_RW, ValueError):
                counts["skipped"] += 1
        return counts

    def persist(self):
        if not self.state_path:
            return
        state = {"objects": list(self.store.objects.values()),
                 "records": list(self.store.records.values())}
        Path(self.state_path).write_text(json.dumps(state, indent=1))

    def restore(self):
        if not self.state_path or not Path(self.state_path).exists():
            return
        state = json.loads(Path(self.state_path).read_text())
        for obj in state.get("objects", []):
            self.store.objects[obj["id"]] = obj
        for rec in state.get("records", []):
            self.store.records[rec["id"]] = rec


class Handler(BaseHTTPRequestHandler):
    server_version = "causalontology-store/" + SDK_VERSION

    # ------------------------------------------------------------- plumbing
    def _send(self, code, payload, cache=MUTABLE_CACHE, etag=None,
              location=None):
        body = json.dumps(payload, indent=1).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # Every JSON response is no-cache by DEFAULT (a mutable/derived view is
        # never cached as if immutable); an immutable content response opts in to
        # long-lived caching by passing IMMUTABLE_CACHE and an ETag.
        if cache:
            self.send_header("Cache-Control", cache)
        if etag is not None:
            self.send_header("ETag", '"%s"' % etag)
        if location is not None:
            self.send_header("Location", location)
        self.end_headers()
        self.wfile.write(body)

    def _send_immutable(self, payload, identifier):
        """Serve an IMMUTABLE content response for the CDN / light-client path:
        long-lived immutable caching plus an ETag equal to the identifier (its
        hash). Honors a conditional request: If-None-Match against the same
        identifier returns 304 Not Modified, so a warm cache revalidates for
        free. The object never changes, so any cache may keep it forever."""
        inm = self.headers.get("If-None-Match", "")
        if identifier and ('"%s"' % identifier) in inm:
            self.send_response(304)
            self.send_header("ETag", '"%s"' % identifier)
            self.send_header("Cache-Control", IMMUTABLE_CACHE)
            self.end_headers()
            return None
        return self._send(200, payload, cache=IMMUTABLE_CACHE, etag=identifier)

    # ---------------------------------------------- Phase four: shard routing
    def _shard_pointer(self, identifier, path):
        """If this node is a PARTIAL node and the identifier is outside its shard,
        answer with a pointer to a node that holds it (never a false 'not
        found'). Returns True if it handled the response. A FULL node covers the
        whole space, so this is always a no-op for it - existing behavior is
        unchanged."""
        server = self.server
        if not server.partial or server.shard.covers(identifier):
            return False
        holders = server.shard_map.nodes_for(identifier)
        if holders:
            location = holders[0] + path
            # 421 Misdirected Request: "you asked the wrong node." A 4xx is not
            # transparently auto-followed by a client the way a 3xx redirect is,
            # so the light client receives the pointer, then fetches from the
            # holder and verifies the object itself - trust stays local.
            self._send(421, {"redirect": location, "id": identifier,
                             "holders": holders,
                             "reason": "identifier outside this node's shard",
                             "shard": server.shard.to_spec()},
                       location=location)
            return True
        # No known holder: honest, explicit out-of-shard signal (not a plain 404
        # that would falsely imply the identifier does not exist anywhere).
        self._send(404, {"error": "identifier outside this node's shard",
                         "out_of_shard": True, "id": identifier,
                         "shard": server.shard.to_spec(), "holders": []})
        return True

    def _token_blocked(self, is_token):
        """The public light-client / CDN read path does not serve the token tier
        unless the operator opted in (local by default, spec/safety.md)."""
        return is_token and not self.server.serve_tokens

    def _body(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length) or b"{}")

    def _authorized(self):
        if self.server.token is None:
            return True
        header = self.headers.get("Authorization", "")
        return header == "Bearer " + self.server.token

    def log_message(self, fmt, *args):  # quiet by default
        pass

    # ------------------------------------------------------------------ GET
    def do_GET(self):
        store = self.server.store
        url = urlparse(self.path)
        qs = {k: v[0] for k, v in parse_qs(url.query).items()}
        parts = [p for p in url.path.split("/") if p]
        limit, cursor = qs.get("limit"), qs.get("cursor")

        if not parts:
            return self._send(200, {
                "service": "causalontology Tier A reference store",
                "specification_version": SPEC_VERSION,
                "sdk_version": SDK_VERSION,
                "objects": len(store.objects),
                "records": len(store.records),
                "quarantined": len(store.quarantine),
                "gaps": len(self.server.ranked_gaps()),
                "demand_tracked": len(self.server.demand),
                "dashboard": "/dashboard",
                "sparql": "/sparql?query=",
                "triples": "/export/triples",
                "reputation": "/reputation?source=",
                "federation": ["GET /sync/export", "POST /sync/pull",
                               "GET /sync/manifest", "GET /sync/ids",
                               "POST /sync/announce", "POST /sync/fetch",
                               "GET /sync/peers", "POST /sync/peers"],
                "peers": self.server.federation.peers(),
                "shards": "/shards",
                "shard": self.server.shard.to_spec(),
                "partial_node": self.server.partial,
                "endpoints": [
                    "POST /objects", "GET /objects/{id}",
                    "POST /records", "GET /records/{id}",
                    "GET /assertions?about=", "GET /enrichments?about=",
                    "GET /retractions?about=", "GET /successions?key=",
                    "GET /resolve?text=&lang=", "POST /query",
                    "GET /gaps?kind=&near=", "GET /conflicts",
                    "GET /shards"]})

        if parts[0] == "objects" and len(parts) == 2:
            identifier = parts[1]
            if self._shard_pointer(identifier, url.path):
                return None
            view = qs.get("view", "default")
            result = store.get(identifier, view=view)
            if result is None:
                return self._send(404, {"error": "no such object"})
            self.server.note_demand(identifier)
            # The RAW view is the CDN / light-client path: it serves the exact,
            # immutable, content-addressed bytes a client verifies by hash. It is
            # cacheable forever (ETag = the identifier) and does not serve the
            # token tier on the public path. The DEFAULT view is the mutable
            # materialized enrichment view - never cached as if immutable.
            if view == "raw":
                if self._token_blocked(snap.is_token_content(result["object"])):
                    return self._send(404, {"error": "not in the shareable "
                                            "commons (token tier is local)"})
                return self._send_immutable(result, identifier)
            return self._send(200, result)

        if parts[0] == "records" and len(parts) == 2:
            identifier = parts[1]
            if self._shard_pointer(identifier, url.path):
                return None
            rec = store.records.get(identifier)
            if rec is None:
                return self._send(404, {"error": "no such record"})
            # A provenance record is immutable and self-authenticating by its
            # Ed25519 signature: the CDN / light-client immutable path. The token
            # tier is not served here on the public path unless opted in.
            if self._token_blocked(snap.record_touches_token(rec)):
                return self._send(404, {"error": "not in the shareable commons "
                                        "(token tier is local)"})
            return self._send_immutable(rec, identifier)

        if parts[0] == "assertions":
            include = qs.get("view") == "history"
            about = qs.get("about", "")
            self.server.note_demand(about)
            items = store.assertions_about(about, include)
            return self._send(200, paginate(items, limit, cursor))

        if parts[0] == "enrichments":
            include = qs.get("view") == "history"
            items = store.enrichments_about(qs.get("about", ""), include)
            return self._send(200, paginate(items, limit, cursor))

        if parts[0] == "retractions":
            about = qs.get("about", "")
            items = [r for r in store.records.values()
                     if r.get("type") == "retraction"
                     and r.get("retracts") == about]
            return self._send(200, paginate(items, limit, cursor))

        if parts[0] == "successions":
            key = qs.get("key", "")
            items = [r for r in store.records.values()
                     if r.get("type") == "succession"
                     and key in (r.get("predecessor"), r.get("successor"))]
            return self._send(200, paginate(items, limit, cursor))

        if parts[0] == "resolve":
            ids = store.resolve(qs.get("text", ""), qs.get("lang"))
            for hit in ids:
                self.server.note_demand(hit)
            return self._send(200, paginate(ids, limit, cursor))

        if parts[0] == "gaps":
            gaps = self.server.ranked_gaps(qs.get("kind"))
            near = qs.get("near")
            if near:
                gaps = [g for g in gaps if near in json.dumps(g)
                        or near in json.dumps(store.objects.get(g.get("id"), {}))]
            return self._send(200, paginate(gaps, limit, cursor))

        if parts[0] == "conflicts":
            pairs = self.server.ranked_gaps("conflict")
            return self._send(200, paginate(pairs, limit, cursor))

        if parts[0] == "dashboard":
            page = (Path(__file__).resolve().parents[1] / "stigmergy"
                    / "dashboard.html")
            if not page.exists():
                return self._send(404, {"error": "dashboard not installed"})
            body = page.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return None

        if parts[0] == "sparql":
            query = qs.get("query", "")
            return self._sparql(query, limit, cursor)

        if parts[0] == "export" and len(parts) == 2 and parts[1] == "triples":
            lines = []
            for s, p, o, lit in self.server.triples():
                lines.append("%s %s %s ." % (
                    _nt_term(s), _nt_term(p),
                    _nt_literal(o) if lit else _nt_term(o)))
            body = ("\n".join(lines) + "\n").encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/n-triples")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return None

        if parts[0] == "reputation":
            source = qs.get("source", "")
            if not source:
                return self._send(400, {"error": "source parameter required"})
            return self._send(200, self.server.reputation(source))

        if parts[0] == "sync" and len(parts) == 2 and parts[1] == "export":
            return self._send(200, {
                "objects": list(store.objects.values()),
                "records": list(store.records.values())})

        # Live Tier B federation (Phase three) - additive read endpoints. On a
        # PARTIAL node these advertise only the node's own shard (Phase four), so
        # a peer or light client sees exactly the slice this node holds.
        if parts[0] == "sync" and len(parts) == 2 and parts[1] == "manifest":
            return self._send(200, self.server.federation.local_manifest())

        if parts[0] == "sync" and len(parts) == 2 and parts[1] == "ids":
            ids, root, _ = self.server.federation.local_index()
            return self._send(200, {"merkle_root": root, "ids": ids})

        if parts[0] == "sync" and len(parts) == 2 and parts[1] == "peers":
            return self._send(200, {"peers": self.server.federation.peers()})

        # Phase four - the shard map: this node's own coverage plus the coverage
        # of every node it knows, so a light client or peer can find which node
        # holds a given identifier and confirm the coverage invariant (the union
        # of all shards spans the whole identifier space).
        if parts[0] == "shards":
            self_cfg = self.server.shard
            all_cfgs = [self_cfg] + list(self.server.shard_map.nodes().values())
            return self._send(200, {
                "node_shard": self_cfg.as_json(),
                "partial": self.server.partial,
                "map": self.server.shard_map.as_json(),
                "coverage": shd.coverage_report(all_cfgs)})

        return self._send(404, {"error": "unknown endpoint"})

    # ---------------------------------------------- a small SPARQL subset
    def _sparql(self, query, limit, cursor):
        """SELECT over a single basic graph pattern - the SHOULD-level
        endpoint of spec/store.md, implemented as a deliberately small,
        documented subset (variables, prefixed names, quoted literals)."""
        try:
            body = re.sub(r"PREFIX\s+\S+\s+<[^>]*>", "", query,
                          flags=re.IGNORECASE)
            m = re.search(r"SELECT\s+(.*?)\s+WHERE\s*\{(.*)\}",
                          body, flags=re.IGNORECASE | re.DOTALL)
            if not m:
                raise ValueError("expected SELECT ... WHERE { ... }")
            sel, patterns_src = m.group(1).strip(), m.group(2)
            want = None if sel == "*" else re.findall(r"\?(\w+)", sel)
            # tokenize with quoted literals kept whole; '.' separates patterns
            tokens = re.findall(r'"[^"]*"|<[^>]*>|\?\w+|\.|[^\s.]+',
                                patterns_src)
            patterns, current = [], []
            for tok in tokens + ["."]:
                if tok == ".":
                    if current:
                        if len(current) != 3:
                            raise ValueError(
                                "each pattern needs subject predicate "
                                "object: %r" % " ".join(current))
                        patterns.append(tuple(current))
                        current = []
                else:
                    current.append(tok)
        except ValueError as e:
            return self._send(400, {"error": str(e)})

        triples = self.server.triples()

        def term_matches(token, value, lit, binding):
            if token.startswith("?"):
                name = token[1:]
                if name in binding:
                    return binding[name] == (value, lit) and binding
                nb = dict(binding)
                nb[name] = (value, lit)
                return nb
            if token.startswith('"'):
                return binding if (lit and token.strip('"') == value) else None
            tok = token[1:-1] if token.startswith("<") else token
            return binding if (not lit and tok == value) else None

        solutions = [dict()]
        for s_tok, p_tok, o_tok in patterns:
            nxt = []
            for binding in solutions:
                for s, p, o, lit in triples:
                    b1 = term_matches(s_tok, s, False, binding)
                    if b1 is None:
                        continue
                    b2 = term_matches(p_tok, p, False, b1)
                    if b2 is None:
                        continue
                    b3 = term_matches(o_tok, o, lit, b2)
                    if b3 is None:
                        continue
                    nxt.append(b3)
            solutions = nxt
        variables = want if want is not None else sorted(
            {k for sol in solutions for k in sol})
        bindings = []
        seen = set()
        for sol in solutions:
            row = {}
            for v in variables:
                if v in sol:
                    value, lit = sol[v]
                    row[v] = {"type": "literal" if lit else "uri",
                              "value": value}
            key = json.dumps(row, sort_keys=True)
            if key not in seen:
                seen.add(key)
                bindings.append(row)
        page = paginate(bindings, limit, cursor)
        return self._send(200, {"head": {"vars": variables},
                                "results": {"bindings": page["items"]},
                                "next_cursor": page["next_cursor"]})

    # ----------------------------------------------------------------- POST
    def do_POST(self):
        store = self.server.store
        parts = [p for p in urlparse(self.path).path.split("/") if p]
        try:
            body = self._body()
        except Exception:  # noqa: BLE001
            return self._send(400, {"error": "invalid JSON body"})

        # Live Tier B federation (Phase three). The peer-sync endpoints are
        # SELF-AUTHENTICATING: every inbound object is verified against its own
        # hash and every record against its own signature before it is merged
        # (federation.verified_merge), so no shared bearer token is needed to
        # sync with a peer - the mathematics, not a secret, keeps a store safe.
        # These are additive; every pre-existing endpoint keeps its auth gate.
        if parts and parts[0] == "sync" and len(parts) == 2:
            if parts[1] == "announce":
                counts = self.server.federation.handle_announce(body)
                if counts["objects_added"] or counts["records_added"]:
                    self.server.persist()
                return self._send(200, counts)
            if parts[1] == "fetch":
                return self._send(200, self.server.federation.handle_fetch(body))

        if not self._authorized():
            return self._send(401, {"error": "bearer token required"})

        if parts and parts[0] == "objects":
            before = len(store.objects)
            try:
                oid = store.put(body)
            except (RejectedWrite, ValueError) as e:
                return self._send(422, {"error": str(e)})
            created = len(store.objects) > before
            self.server.persist()
            if created:
                self.server.federation.on_local_write(oid)
            return self._send(201 if created else 200,
                              {"id": oid, "created": created})

        if parts and parts[0] == "records":
            before = len(store.records)
            try:
                rid = store.put_record(body)
            except RejectedWrite as e:
                if "quarantined" in str(e):
                    self.server.persist()
                    return self._send(202, {"quarantined": True,
                                            "reason": str(e)})
                return self._send(422, {"error": str(e)})
            except ValueError as e:
                return self._send(422, {"error": str(e)})
            self.server.persist()
            if len(store.records) > before:
                self.server.federation.on_local_write(rid)
            return self._send(201, {"id": rid})

        if parts and parts[0] == "sync" and len(parts) == 2 \
                and parts[1] == "peers":
            action, url = body.get("action"), (body.get("peer") or "").strip()
            if action == "add" and url:
                return self._send(200,
                                  {"peers": self.server.federation.add_peer(url)})
            if action == "remove" and url:
                return self._send(
                    200, {"peers": self.server.federation.remove_peer(url)})
            return self._send(400, {"error": "expected {action: add|remove, "
                                             "peer: URL}"})

        if parts and parts[0] == "query":
            return self._send(200, self._query(body))

        if parts and parts[0] == "sparql":
            return self._sparql(body.get("query", ""), None, None)

        if parts and parts[0] == "sync" and len(parts) == 2 \
                and parts[1] == "pull":
            peer = body.get("peer", "").rstrip("/")
            if not peer.startswith("http"):
                return self._send(400, {"error": "peer URL required"})
            try:
                with urllib.request.urlopen(peer + "/sync/export",
                                            timeout=30) as resp:
                    bundle = json.loads(resp.read())
            except Exception as e:  # noqa: BLE001
                return self._send(502, {"error": "peer unreachable: %s" % e})
            counts = self.server.merge_bundle(bundle)
            self.server.persist()
            return self._send(200, counts)

        return self._send(404, {"error": "unknown endpoint"})

    # ------------------------------------------------- query-by-example
    def _query(self, body):
        store = self.server.store
        kind = body.get("kind")
        where = body.get("where", {})
        pool = list(store.objects.values()) + list(store.records.values())
        out = []
        for item in pool:
            if kind and item.get("type") != kind:
                continue
            ok = True
            for key, want in where.items():
                if key == "causes_contains":
                    ok = want in item.get("causes", [])
                elif key == "effects_contains":
                    ok = want in item.get("effects", [])
                elif key == "is_partial":
                    ok = (item.get("type") == "causal_relation_object"
                          and is_partial(item)[0] == want)
                elif key == "missing":
                    ok = (item.get("type") == "causal_relation_object"
                          and want in is_partial(item)[1])
                else:
                    ok = item.get(key) == want
                if not ok:
                    break
            if ok:
                out.append(item)
        return paginate(out, body.get("limit"), body.get("cursor"))


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Causalontology Tier A store")
    ap.add_argument("--port", type=int, default=8785)  # a nod to RFC 8785
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--token", default=None,
                    help="bearer token required for writes")
    ap.add_argument("--db", default=None,
                    help="SQLite database file for the persistent node (env "
                         "CAUSALONTOLOGY_STORE_DB / CAUSALONTOLOGY_DATA; "
                         "default store/server/data/causalontology.db)")
    ap.add_argument("--in-memory", action="store_true",
                    help="volatile store: keep data in memory only (lost on exit)")
    ap.add_argument("--state", default=None,
                    help="legacy JSON snapshot persistence over the in-memory store")
    ap.add_argument("--no-enforce", action="store_true",
                    help="replica mode: skip the enforcing-tier write gates")
    ap.add_argument("--demand-threshold", type=int, default=3,
                    help="reads before an unsupported claim counts as "
                         "high-demand (the demand_supply gap)")
    ap.add_argument("--peer", action="append", default=None, dest="peers",
                    help="a federation peer base URL (repeatable); adds to the "
                         "CAUSALONTOLOGY_PEERS environment list")
    ap.add_argument("--anti-entropy-interval", type=float,
                    default=fed.DEFAULT_ANTI_ENTROPY_INTERVAL,
                    help="seconds between background anti-entropy reconciliations")
    ap.add_argument("--gossip-interval", type=float,
                    default=fed.DEFAULT_GOSSIP_INTERVAL,
                    help="seconds between batched gossip flushes to peers")
    ap.add_argument("--federate-tokens", action="store_true",
                    help="opt in to federating the token tier (local by default)")
    ap.add_argument("--shard", default=None,
                    help="become a PARTIAL node holding only a hash-prefix slice "
                         "(env CAUSALONTOLOGY_SHARD): e.g. '0-3', '0-7,c-f', '5'. "
                         "Omit for a FULL node covering the whole space.")
    ap.add_argument("--shard-map", action="append", default=None,
                    dest="shard_map",
                    help="a peer's coverage, 'URL=SPEC' (repeatable; env "
                         "CAUSALONTOLOGY_SHARD_MAP, space-separated), so an "
                         "out-of-shard request is pointed at a node that holds it")
    args = ap.parse_args()

    peers = fed.peers_from_env() + [p.rstrip("/") for p in (args.peers or [])]
    peers = list(dict.fromkeys(peers))     # de-duplicate, order-preserving
    federation_opts = {
        "include_tokens": args.federate_tokens,
        "anti_entropy_interval": args.anti_entropy_interval,
        "gossip_interval": args.gossip_interval,
    }

    # Phase four - the shard this node holds, and the map of who holds what.
    import os
    shard_spec = args.shard or os.environ.get("CAUSALONTOLOGY_SHARD")
    shard = shd.ShardConfig.parse(shard_spec) if shard_spec else None
    shard_map = shd.ShardMap()
    map_entries = list(args.shard_map or [])
    map_entries += os.environ.get("CAUSALONTOLOGY_SHARD_MAP", "").split()
    for entry in map_entries:
        if "=" in entry:
            url, _, spec = entry.partition("=")
            shard_map.add(url, spec)

    persistent = None
    if args.in_memory or args.state:
        store = InMemoryStore(enforcing=not args.no_enforce)
        server = StoreServer((args.host, args.port), store,
                             token=args.token, state_path=args.state,
                             demand_threshold=args.demand_threshold,
                             peers=peers, federation_opts=federation_opts,
                             shard=shard, shard_map=shard_map)
        server.restore()
        backend = "state file %s" % args.state if args.state else "in-memory (volatile)"
    else:
        from storage import PersistentStore, default_db_path
        db_path = args.db or default_db_path()
        store = persistent = PersistentStore(enforcing=not args.no_enforce,
                                             db_path=db_path)
        server = StoreServer((args.host, args.port), store,
                             token=args.token, state_path=None,
                             demand_threshold=args.demand_threshold,
                             peers=peers, federation_opts=federation_opts,
                             shard=shard, shard_map=shard_map)
        backend = "sqlite %s" % db_path
    if peers:
        server.federation.start()           # go live: gossip + anti-entropy
    fed_note = ("federating with %d peer(s)" % len(peers) if peers
                else "no peers (stand-alone)")
    shard_note = ("partial node, shard %s" % shard.to_spec() if shard
                  else "full node (whole space)")
    print("causalontology Tier A store on http://%s:%d  "
          "(spec %s, sdk %s, %d objects, %d records) [%s; %s; %s]"
          % (args.host, server.server_address[1], SPEC_VERSION, SDK_VERSION,
             len(store.objects), len(store.records), backend, fed_note,
             shard_note))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.federation.stop()
        server.persist()
        if persistent is not None:
            persistent.close()
        print("\nstate persisted; goodbye")


if __name__ == "__main__":
    main()

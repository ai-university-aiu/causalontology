#!/usr/bin/env python3
"""The Causalontology LIGHT CLIENT: hold almost nothing, verify everything.

Phase four of Part 21 of the canon (Commons Storage and Federation Design): a
client that keeps little or no data of its own and answers queries by fetching
from full or partial nodes over HTTP (Hypertext Transfer Protocol) - yet TRUSTS
NO SERVER. Every content object it receives is checked against its own
identifier by recomputing the hash; every provenance record is checked against
its own Ed25519 signature. A lying or corrupted server - or a stale or hostile
CDN (content-delivery network) edge - is caught by the mathematics, not by
reputation, so a light client on a phone or in a browser can consume the commons
safely while storing none of it.

The trustless core (spec/identity.md, spec/provenance.md)
--------------------------------------------------------
  - identifier == scheme + ":" + SHA-256 of the object's canonical
    identity-bearing bytes. The client recomputes it with the standard's own
    canonicalization (causalontology.identify) and REJECTS any object whose
    bytes do not hash to the identifier it asked for - no matter which node or
    cache served it.
  - every provenance record carries an Ed25519 signature over its canonical
    bytes; the client verifies it with causalontology.verify_record and REJECTS
    any record whose signature does not check out.

Resolution across a sharded network (sharding.ShardMap)
-------------------------------------------------------
On a hash-prefix-sharded network no single node holds everything. The client
consults a SHARD MAP to find which node holds a given identifier, and falls back
to another node on failure. A partial node that is asked for an identifier
outside its slice answers with a POINTER (HTTP 421) to a node that does hold it;
the client follows the pointer and then verifies the object itself, so trust
never leaves the client.

Local trust and retraction (spec/safety.md)
-------------------------------------------
The SERVER never decides what a light client believes. The client applies its
own TrustPolicy (which sources, which evidence grades, which confidence floor)
to the verified records, and re-derives retraction-and-succession honoring
LOCALLY from the verified record history rather than trusting a server's
filtered view - loading the verified records into a fresh conformant store and
reading back the retraction-honored result.

Zero dependencies beyond the Python standard library and causalontology-py.
"""

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve()
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "bindings" / "python"))
sys.path.insert(0, str(ROOT / "store" / "server"))

from causalontology import (identify, verify_record,           # noqa: E402
                            InMemoryStore, RejectedWrite)
import sharding as shd                                          # noqa: E402


class VerificationError(Exception):
    """A served object or record failed its own hash or signature check. The
    client REFUSES it - this is the whole point of a light client: a failure
    here means a node or cache tried to lie, and the lie was caught."""


class ResolutionError(Exception):
    """No reachable node served a valid object/record for an identifier."""


# ---------------------------------------------------------------------------
# the consumer's own trust policy - applied locally, never by a server
# ---------------------------------------------------------------------------
class TrustPolicy:
    """What a consumer chooses to believe among VERIFIED records. Verification
    (hash + signature) is not optional and is done first; this policy is the
    SECOND, subjective gate the consumer alone controls. The default believes
    every verified assertion; tighten it by naming allowed sources, a minimum
    confidence, or acceptable evidence grades."""

    def __init__(self, allowed_sources=None, min_confidence=0.0,
                 allowed_evidence=None):
        self.allowed_sources = (set(allowed_sources)
                                if allowed_sources is not None else None)
        self.min_confidence = float(min_confidence)
        self.allowed_evidence = (set(allowed_evidence)
                                 if allowed_evidence is not None else None)

    def accepts(self, record):
        if record.get("type") != "assertion":
            return True
        if (self.allowed_sources is not None
                and record.get("source") not in self.allowed_sources):
            return False
        if float(record.get("confidence", 0.0)) < self.min_confidence:
            return False
        if (self.allowed_evidence is not None
                and record.get("evidence_type") not in self.allowed_evidence):
            return False
        return True


# ---------------------------------------------------------------------------
# the light client
# ---------------------------------------------------------------------------
class LightClient:
    """A trustless reader over one or more full or partial nodes.

    nodes       base URLs the client may query.
    shard_map   a sharding.ShardMap, so an identifier resolves to the node whose
                slice holds it (optional; without it the client tries each node).
    trust       a TrustPolicy applied to verified records (optional).
    cache       a dict-like content-addressed cache of already-verified objects
                and records (optional; safe forever, because a name is a hash).
    """

    def __init__(self, nodes=None, shard_map=None, trust=None, cache=None,
                 timeout=10.0):
        self.nodes = [n.rstrip("/") for n in (nodes or [])]
        self.shard_map = shard_map
        self.trust = trust or TrustPolicy()
        self.cache = cache if cache is not None else {}
        self.timeout = timeout

    # ------------------------------------------------------------------- HTTP
    def _get(self, base, path):
        """GET a JSON endpoint. Returns (status, body) or (None, None) on a
        network failure. Does NOT transparently follow a redirect: an out-of-
        shard pointer (HTTP 421) is returned to the caller so the client - not
        urllib - decides where to go next and still verifies what it gets."""
        req = urllib.request.Request(base + path, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
                return resp.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as e:
            raw = e.read() or b"{}"
            try:
                return e.code, json.loads(raw)
            except ValueError:
                return e.code, {}
        except (urllib.error.URLError, OSError):
            return None, None

    def _get_all(self, base, path):
        """Follow ?cursor= pagination to gather every item of a list endpoint."""
        items, cursor = [], None
        while True:
            sep = "&" if "?" in path else "?"
            full = path + (("%scursor=%s" % (sep, cursor)) if cursor else "")
            status, body = self._get(base, full)
            if status != 200 or not isinstance(body, dict):
                break
            items.extend(body.get("items", []))
            cursor = body.get("next_cursor")
            if not cursor:
                break
        return items

    # ------------------------------------------------------------- shard map
    def discover_shards(self):
        """Assemble/refresh the shard map by asking each node for its coverage
        (GET /shards). Lets a client learn who-holds-what from the nodes it
        already knows, with no central registry."""
        smap = self.shard_map or shd.ShardMap()
        for base in self.nodes:
            status, body = self._get(base, "/shards")
            if status == 200 and isinstance(body, dict):
                cfg = body.get("node_shard", {})
                if cfg.get("spec"):
                    smap.add(base, cfg["spec"])
                for entry in body.get("map", {}).get("nodes", []):
                    smap.add(entry["url"], entry["shard"]["spec"])
        self.shard_map = smap
        return smap

    def _candidate_nodes(self, identifier):
        """Nodes to try for an identifier: the shard holders first (if the map
        knows them), then every other known node as a fallback."""
        holders = (self.shard_map.nodes_for(identifier)
                   if self.shard_map else [])
        rest = [n for n in self.nodes if n not in holders]
        return holders + rest

    # -------------------------------------------------------- object fetching
    def get_object(self, identifier, use_cache=True):
        """Fetch a content object and VERIFY it by hash. Returns the object, or
        raises VerificationError if a served body does not hash to the
        identifier (a tamper, wherever it came from) or ResolutionError if no
        node served it."""
        if use_cache and identifier in self.cache:
            return self.cache[identifier]
        todo = list(self._candidate_nodes(identifier))
        seen = set()
        served_but_absent = False
        while todo:
            base = todo.pop(0).rstrip("/")
            if base in seen:
                continue
            seen.add(base)
            status, body = self._get(base, "/objects/%s?view=raw" % identifier)
            if status is None:
                continue                                   # unreachable: fall back
            if status == 421 and isinstance(body, dict):   # out-of-shard pointer
                for holder in body.get("holders", []):
                    h = holder.rstrip("/")
                    if h not in seen:
                        todo.append(h)
                continue
            if status == 200 and isinstance(body, dict) and "object" in body:
                obj = body["object"]
                # THE trustless check: recompute the identifier from the bytes.
                if identify(obj) != identifier:
                    raise VerificationError(
                        "%s served bytes that do not hash to %s - rejected"
                        % (base, identifier))
                if use_cache:
                    self.cache[identifier] = obj
                return obj
            served_but_absent = served_but_absent or (status == 404)
        raise ResolutionError(
            "no node served a valid object for %s%s" % (
                identifier,
                " (nodes reachable but do not hold it)" if served_but_absent
                else ""))

    # -------------------------------------------------------- record fetching
    def get_record(self, identifier, use_cache=True):
        """Fetch a provenance record and VERIFY its Ed25519 signature. Returns
        the record, or raises VerificationError on a bad signature (wherever it
        was served from) or ResolutionError if no node served it."""
        if use_cache and identifier in self.cache:
            return self.cache[identifier]
        todo = list(self._candidate_nodes(identifier))
        seen = set()
        while todo:
            base = todo.pop(0).rstrip("/")
            if base in seen:
                continue
            seen.add(base)
            status, body = self._get(base, "/records/%s" % identifier)
            if status is None:
                continue
            if status == 421 and isinstance(body, dict):
                for holder in body.get("holders", []):
                    h = holder.rstrip("/")
                    if h not in seen:
                        todo.append(h)
                continue
            if status == 200 and isinstance(body, dict) and body.get("id"):
                # THE trustless check: verify the signature over its own bytes.
                if not verify_record(body):
                    raise VerificationError(
                        "%s served a record whose signature does not verify "
                        "(%s) - rejected" % (base, identifier))
                if use_cache:
                    self.cache[identifier] = body
                return body
        raise ResolutionError("no node served a valid record for %s"
                              % identifier)

    # ------------------------------------------- local retraction + trust view
    def believe_about(self, about, nodes=None):
        """The assertions about an object that the consumer BELIEVES: fetched as
        the full signed history, every record verified locally, retraction and
        succession honored by RE-DERIVING them from the verified records (not by
        trusting any server's filtered view), then filtered by the client's own
        TrustPolicy. The server decides nothing here."""
        nodes = nodes or self.nodes
        assertions, retractions, successions = {}, {}, {}

        def collect(bucket, path):
            for base in nodes:
                for rec in self._get_all(base, path):
                    rid = rec.get("id")
                    if rid and rid not in bucket and verify_record(rec):
                        bucket[rid] = rec

        collect(assertions, "/assertions?about=%s&view=history" % about)
        # A retraction retracts an assertion by that assertion's id, so ask for
        # the retractions OF each assertion we found (the /retractions endpoint
        # filters by the retracted id).
        for aid in list(assertions):
            collect(retractions, "/retractions?about=%s" % aid)
        # Succession lineage of every contributing source, so an authorized
        # retraction (one from the target's own succession lineage) is honored
        # and an unauthorized one is not.
        sources = {r.get("source") for r in
                   list(assertions.values()) + list(retractions.values())
                   if r.get("source")}
        for src in sources:
            collect(successions, "/successions?key=%s" % src)

        # Re-derive locally in a fresh conformant store from verified records.
        local = InMemoryStore(enforcing=True)
        for rec in list(assertions.values()) + list(successions.values()):
            try:
                local.force_merge_record(rec)
            except (RejectedWrite, ValueError):
                pass
        for rec in retractions.values():
            try:
                local.put_record(rec)   # enforces retraction-source authorization
            except (RejectedWrite, ValueError):
                pass
        return [r for r in local.assertions_about(about)
                if self.trust.accepts(r)]

    # ------------------------------------------------------------- resolve
    def resolve(self, text, lang=None):
        """Resolve a label/alias to identifiers by asking known nodes (a read
        convenience; the objects it points at are still verified on fetch)."""
        seen, out = set(), []
        for base in self.nodes:
            path = "/resolve?text=%s" % urllib.request.quote(text)
            if lang:
                path += "&lang=%s" % urllib.request.quote(lang)
            for hit in self._get_all(base, path):
                if hit not in seen:
                    seen.add(hit)
                    out.append(hit)
        return out

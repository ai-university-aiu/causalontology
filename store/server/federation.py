#!/usr/bin/env python3
"""Live Tier B federation: gossip and anti-entropy.

Phase three of Part 21 of the canon (Commons Storage and Federation Design):
make Tier B federation LIVE. Phases one and two gave the commons a durable node
and signed, Merkle-committed snapshots; this phase makes many nodes converge to
one shared whole automatically, with no coordinator and no leader, and with
nothing trusted that is not verified.

Two mechanisms cooperate, exactly as 21.6 describes:

  GOSSIP (push on write). When a node accepts a new type-tier content object or
  provenance record - whether locally minted or received from a peer - it
  announces it onward to its configured peers. Announcements are BATCHED (a
  burst of writes is one message, not a flood), IDEMPOTENT (a peer that already
  holds an identifier does nothing), and LOOP-FREE (only records that were
  genuinely NEW to this node are gossiped onward, so an announcement does not
  circulate forever among a ring of peers).

  ANTI-ENTROPY (scheduled reconciliation). On a configurable interval a node
  reconciles with each peer to repair anything gossip missed - a dropped
  message, a peer that was offline, writes that landed out of order. It first
  compares MERKLE ROOTS over the type-tier set (the very root of the Phase-two
  snapshot manifest): equal roots mean the two are already converged and the
  pass costs one small request. Only when the roots differ does it exchange the
  ordered identifier set to compute the DELTA - the identifiers each side is
  missing - and transfer ONLY those objects and records, in bounded batches, so
  a handful of differences never ships the whole store.

INBOUND VERIFICATION IS MANDATORY. Every received content object is checked
against its own identifier (identifier == scheme + ":" + SHA-256 of its
canonical identity-bearing bytes, spec/identity.md) and every provenance record
against its own Ed25519 signature (spec/provenance.md) BEFORE it is merged. A
tampered or forged item is rejected and never merged; the rest of the batch
still merges. So a hostile or broken peer can never corrupt a store or force a
bad record in - federation moves records, and trust remains a local,
consumer-chosen policy, unchanged.

Convergence is a property of the data model, not of the protocol: the store is
a grow-only-set CRDT (content-addressed, add-only, signed), so merge is set
union - commutative, associative, idempotent - and any set of peers, syncing in
any order with any messages dropped or duplicated, reach the identical
type-tier set. Federation NEVER deletes: retraction and succession propagate as
the records they are; history is never erased by a peer.

PRIVACY - the token tier does not federate by default. Gossip and anti-entropy
operate over the SHAREABLE COMMONS only: type-tier content plus the provenance
about it, exactly the set a default snapshot carries (snapshot.collect_entries).
Token-tier records (token_individual, token_occurrence, state_assertion,
token_causal_claim) and any provenance that references them stay home unless the
operator explicitly opts in - the standard's local-by-default rule
(spec/safety.md) carried unchanged into the live network.

Zero dependencies beyond the Python standard library and causalontology-py.
"""

import json
import os
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]
                       / "bindings" / "python"))

from causalontology import identify, verify_record  # noqa: E402

# Phase-two snapshot machinery, reused verbatim so the federation's Merkle root
# is byte-for-byte the snapshot root and the token-tier boundary is identical.
import snapshot as snap  # noqa: E402

# The environment variable naming a node's peers (base URLs), space- or
# comma-separated, for example
#   CAUSALONTOLOGY_PEERS="http://a.example:8785 http://b.example:8785"
PEERS_ENV = "CAUSALONTOLOGY_PEERS"

# Defaults tuned for a reference node. The gossip interval is short so a write
# reaches peers promptly; the anti-entropy interval is longer because it is a
# background repair, not the fast path. Batch sizes bound memory and message
# size so a large delta streams in pieces rather than loading wholly at once.
DEFAULT_ANTI_ENTROPY_INTERVAL = 30.0
DEFAULT_GOSSIP_INTERVAL = 0.5
DEFAULT_BATCH = 256
DEFAULT_TIMEOUT = 10.0

# Retry/backoff for an unreachable peer: never block a local write on a peer
# being down; back off, and converge once the peer returns.
BACKOFF_BASE = 1.0
BACKOFF_MAX = 60.0


def peers_from_env(env=None):
    """The configured peer base URLs from the environment (space/comma list)."""
    raw = (env or os.environ).get(PEERS_ENV, "")
    return [p for p in raw.replace(",", " ").split() if p.strip()]


# ---------------------------------------------------------------------------
# inbound verification + union merge (the safety boundary)
# ---------------------------------------------------------------------------
def verify_object(obj):
    """True iff a content object's identifier equals the hash of its canonical
    identity-bearing bytes. A mismatch is a forged or malformed object."""
    oid = obj.get("id")
    if not isinstance(oid, str) or not oid:
        return False
    try:
        return identify(obj) == oid
    except (ValueError, KeyError, TypeError):
        return False


def verified_merge(store, objects, records, on_new=None):
    """Verify then union-merge a batch into a store.

    EVERY object is checked against its own content address and EVERY record
    against its own signature before it is merged. A failing item is rejected
    and counted; the rest of the batch still merges (a hostile peer cannot poison
    the whole exchange with one bad item). Merging an identifier the store
    already holds is a no-op (idempotent, by content address). on_new(identifier)
    is called for each genuinely new identifier, so the caller can gossip it
    onward - loop-free, because an item already held is never reported as new."""
    counts = {"objects_added": 0, "records_added": 0,
              "objects_present": 0, "records_present": 0,
              "rejected_objects": 0, "rejected_records": 0}
    for obj in objects or []:
        oid = obj.get("id")
        if oid in store.objects:
            counts["objects_present"] += 1
            continue
        if not verify_object(obj):
            counts["rejected_objects"] += 1
            continue
        try:
            store.put(obj)
        except Exception:  # noqa: BLE001  (schema/semantics/identity gate)
            counts["rejected_objects"] += 1
            continue
        counts["objects_added"] += 1
        if on_new:
            on_new(oid)
    for rec in records or []:
        rid = rec.get("id")
        if rid in store.records:
            counts["records_present"] += 1
            continue
        if not verify_record(rec):
            counts["rejected_records"] += 1
            continue
        try:
            store.force_merge_record(rec)
        except Exception:  # noqa: BLE001
            counts["rejected_records"] += 1
            continue
        counts["records_added"] += 1
        if on_new:
            on_new(rid)
    return counts


# ---------------------------------------------------------------------------
# the shareable (type-tier) view of a store: what federates
# ---------------------------------------------------------------------------
def shareable_index(store, include_tokens=False, shard=None):
    """The federated set of a store, as an ordered id list, a Merkle root, and a
    by-id map of entries. Reuses the Phase-two snapshot collection so the root
    is identical to a snapshot's and the token boundary is identical too.

    When a shard (a sharding.ShardConfig) is given, the set is narrowed to the
    identifiers this node's slice covers - the Phase-four per-shard boundary. A
    partial node thus advertises, reconciles, and serves only its own prefixes,
    so federation scales SIDEWAYS: the Merkle root a partial node compares is the
    root of its slice, and two nodes holding the same slice converge on that
    slice without either being forced to hold prefixes outside its coverage."""
    entries, _, _ = snap.collect_entries(store, include_tokens=include_tokens)
    if shard is not None:
        entries = [e for e in entries if shard.covers(e["id"])]
    lines = [snap.canonical_line(e) for e in entries]
    root = snap.merkle_root(lines)
    ids = [e["id"] for e in entries]
    by_id = {e["id"]: e for e in entries}
    return ids, root, by_id


def shareable_manifest(store, include_tokens=False, shard=None):
    """The cheap anti-entropy probe: the Merkle root and count only (over this
    node's shard when one is given)."""
    ids, root, _ = shareable_index(store, include_tokens=include_tokens,
                                   shard=shard)
    return {"merkle_root": root, "count": len(ids),
            "includes_tokens": bool(include_tokens)}


def split_by_kind(entries):
    """Partition a list of entries into (content objects, provenance records)."""
    objects, records = [], []
    for e in entries:
        kind = e.get("type")
        if kind in snap.RECORD_KINDS:
            records.append(e)
        else:
            objects.append(e)
    return objects, records


# ---------------------------------------------------------------------------
# the federation manager: one per node, owns peers, gossip, and anti-entropy
# ---------------------------------------------------------------------------
class FederationManager:
    """Wires a StoreServer into the live federation. Constructed inert: with no
    peers it does nothing and adds no behavior, so a stand-alone node is exactly
    what it was. Call start() to launch the background gossip-flush and
    anti-entropy threads; stop() to end them cleanly. Peers can be added or
    removed at any time without downtime."""

    def __init__(self, store, peers=None, include_tokens=False,
                 anti_entropy_interval=DEFAULT_ANTI_ENTROPY_INTERVAL,
                 gossip_interval=DEFAULT_GOSSIP_INTERVAL,
                 batch=DEFAULT_BATCH, timeout=DEFAULT_TIMEOUT, shard=None):
        self.store = store
        self.include_tokens = include_tokens
        # The Phase-four shard: a sharding.ShardConfig, or None for a full node.
        # When set, this node gossips, reconciles, and serves only the slice it
        # covers - per-shard federation, so the network scales sideways.
        self.shard = shard
        self.anti_entropy_interval = anti_entropy_interval
        self.gossip_interval = gossip_interval
        self.batch = max(1, int(batch))
        self.timeout = timeout

        self._peers = list(peers or [])
        self._peers_lock = threading.RLock()
        self._queue = []                      # ids pending gossip (deduplicated)
        self._queued = set()
        self._queue_lock = threading.Lock()
        self._backoff = {}                    # peer -> (next_allowed_epoch, fails)
        self._backoff_lock = threading.Lock()

        self._stop = threading.Event()
        self._threads = []
        # metrics, for tests and operators (the delta really is a delta)
        self.stats = {"announced": 0, "gossip_flushes": 0,
                      "reconciles": 0, "root_matches": 0,
                      "fetched": 0, "pushed": 0,
                      "peer_errors": 0}

    # ------------------------------------------- this node's shareable slice
    def local_index(self):
        """This node's shareable set (ordered ids, Merkle root, by-id map),
        narrowed to its shard when it is a partial node."""
        return shareable_index(self.store, include_tokens=self.include_tokens,
                               shard=self.shard)

    def local_manifest(self):
        """This node's cheap anti-entropy probe (root + count) over its slice."""
        return shareable_manifest(self.store, include_tokens=self.include_tokens,
                                  shard=self.shard)

    # ------------------------------------------------------- peer management
    def peers(self):
        with self._peers_lock:
            return list(self._peers)

    def add_peer(self, url):
        url = url.rstrip("/")
        with self._peers_lock:
            if url and url not in self._peers:
                self._peers.append(url)
        return self.peers()

    def remove_peer(self, url):
        url = url.rstrip("/")
        with self._peers_lock:
            if url in self._peers:
                self._peers.remove(url)
        return self.peers()

    # --------------------------------------------------------- lifecycle
    def start(self):
        """Launch the background gossip and anti-entropy threads (idempotent)."""
        if self._threads:
            return
        self._stop.clear()
        self._threads = [
            threading.Thread(target=self._gossip_loop, daemon=True,
                             name="federation-gossip"),
            threading.Thread(target=self._anti_entropy_loop, daemon=True,
                             name="federation-anti-entropy"),
        ]
        for t in self._threads:
            t.start()

    def stop(self):
        self._stop.set()
        for t in self._threads:
            t.join(timeout=5)
        self._threads = []

    # ----------------------------------------------------- gossip (push on write)
    def on_local_write(self, identifier):
        """Announce a newly-accepted identifier to peers. A no-op when the node
        has no peers or when the identifier is token-tier (local by default)."""
        if not identifier:
            return
        with self._peers_lock:
            if not self._peers:
                return
        if not self.include_tokens and snap._is_token_id(identifier):
            return
        # Per-shard: a partial node never gossips an identifier outside its slice.
        if self.shard is not None and not self.shard.covers(identifier):
            return
        with self._queue_lock:
            if identifier not in self._queued:
                self._queued.add(identifier)
                self._queue.append(identifier)

    def _drain_queue(self):
        with self._queue_lock:
            ids, self._queue, self._queued = self._queue, [], set()
        return ids

    def _entries_for(self, ids):
        """Resolve queued ids to their current entries, dropping any that are
        token-tier or no longer present (retracted-in-place never happens, but a
        defensive filter keeps token content from leaking)."""
        objects, records = [], []
        for i in ids:
            obj = self.store.objects.get(i)
            if obj is not None:
                if self.include_tokens or not snap.is_token_content(obj):
                    objects.append(obj)
                continue
            rec = self.store.records.get(i)
            if rec is not None:
                if self.include_tokens or not snap.record_touches_token(rec):
                    records.append(rec)
        return objects, records

    def flush_gossip(self):
        """Push all pending announcements to every peer, batched. Returns the
        number of items announced. Unreachable peers are skipped (backoff) and
        never block; the anti-entropy pass repairs whatever a skip missed."""
        ids = self._drain_queue()
        if not ids:
            return 0
        objects, records = self._entries_for(ids)
        payload_items = objects + records
        if not payload_items:
            return 0
        self.stats["gossip_flushes"] += 1
        for peer in self.peers():
            if not self._peer_ready(peer):
                continue
            ok = True
            for start in range(0, len(payload_items), self.batch):
                chunk = payload_items[start:start + self.batch]
                cobj = [e for e in chunk if e.get("type") not in snap.RECORD_KINDS]
                crec = [e for e in chunk if e.get("type") in snap.RECORD_KINDS]
                if self._post(peer, "/sync/announce",
                              {"objects": cobj, "records": crec}) is None:
                    ok = False
                    break
            if ok:
                self._peer_ok(peer)
                self.stats["announced"] += len(payload_items)
            else:
                self._peer_failed(peer)
        return len(payload_items)

    def _gossip_loop(self):
        while not self._stop.is_set():
            try:
                self.flush_gossip()
            except Exception:  # noqa: BLE001  (a background thread never dies)
                pass
            self._stop.wait(self.gossip_interval)

    # ------------------------------------------------- anti-entropy (scheduled)
    def reconcile_once(self):
        """One reconciliation pass against every configured peer."""
        summary = []
        for peer in self.peers():
            if not self._peer_ready(peer):
                continue
            summary.append(self.reconcile_with(peer))
        return summary

    def reconcile_with(self, peer):
        """Reconcile with a single peer: compare Merkle roots, and on a mismatch
        exchange only the delta. Bidirectional in one pass (pull what we lack,
        push what the peer lacks) so a single pass converges both replicas even
        if only one side's scheduler runs. Order-independent and idempotent."""
        peer = peer.rstrip("/")
        result = {"peer": peer, "root_matched": False,
                  "fetched": 0, "pushed": 0, "rejected": 0, "error": None}
        self.stats["reconciles"] += 1

        remote_manifest = self._get(peer, "/sync/manifest")
        if remote_manifest is None:
            result["error"] = "unreachable"
            self._peer_failed(peer)
            return result
        self._peer_ok(peer)

        local_ids, local_root, local_by_id = self.local_index()
        if remote_manifest.get("merkle_root") == local_root:
            # Already converged - the common case, one cheap request.
            result["root_matched"] = True
            self.stats["root_matches"] += 1
            return result

        remote = self._get(peer, "/sync/ids")
        if remote is None:
            result["error"] = "unreachable"
            self._peer_failed(peer)
            return result
        remote_ids = set(remote.get("ids", []))
        local_set = set(local_ids)

        # PULL: fetch only the ids the peer has and we lack, in bounded batches.
        # A partial node pulls ONLY ids within its own shard, so reconciling with
        # a full (or wider) peer never forces it to hold prefixes it does not
        # cover - per-shard federation.
        missing_here = [i for i in remote.get("ids", []) if i not in local_set]
        if self.shard is not None:
            missing_here = [i for i in missing_here if self.shard.covers(i)]
        for start in range(0, len(missing_here), self.batch):
            chunk = missing_here[start:start + self.batch]
            got = self._post(peer, "/sync/fetch", {"ids": chunk})
            if got is None:
                result["error"] = "unreachable"
                self._peer_failed(peer)
                return result
            counts = verified_merge(self.store, got.get("objects", []),
                                    got.get("records", []),
                                    on_new=self.on_local_write)
            result["fetched"] += counts["objects_added"] + counts["records_added"]
            result["rejected"] += (counts["rejected_objects"]
                                   + counts["rejected_records"])
            self.stats["fetched"] += counts["objects_added"] + counts["records_added"]

        # PUSH: announce only the ids we have and the peer lacks (the delta),
        # in bounded batches. The peer verifies every item on receipt.
        missing_there = [i for i in local_ids if i not in remote_ids]
        for start in range(0, len(missing_there), self.batch):
            chunk = missing_there[start:start + self.batch]
            objects, records = split_by_kind(
                [local_by_id[i] for i in chunk if i in local_by_id])
            if self._post(peer, "/sync/announce",
                          {"objects": objects, "records": records}) is None:
                result["error"] = "unreachable"
                self._peer_failed(peer)
                return result
            result["pushed"] += len(objects) + len(records)
            self.stats["pushed"] += len(objects) + len(records)
        return result

    def _anti_entropy_loop(self):
        while not self._stop.is_set():
            # a jitterless initial wait, so a freshly-started node gossips first
            self._stop.wait(self.anti_entropy_interval)
            if self._stop.is_set():
                break
            try:
                self.reconcile_once()
            except Exception:  # noqa: BLE001
                pass

    # ------------------------------------------------ inbound endpoint handlers
    def handle_announce(self, body):
        """A peer pushed us a gossip batch. Verify every item, merge the new
        ones by union, and queue the genuinely-new ones for onward gossip
        (loop-free)."""
        counts = verified_merge(self.store, body.get("objects", []),
                                body.get("records", []),
                                on_new=self.on_local_write)
        return counts

    def handle_fetch(self, body):
        """A peer asked for specific ids. Serve only shareable (type-tier) ids we
        hold; a token-tier id is silently not served (local by default), and an
        id outside this node's shard is likewise not served (per-shard)."""
        _, _, by_id = self.local_index()
        objects, records = [], []
        for i in body.get("ids", []):
            entry = by_id.get(i)
            if entry is None:
                continue
            if entry.get("type") in snap.RECORD_KINDS:
                records.append(entry)
            else:
                objects.append(entry)
        return {"objects": objects, "records": records}

    # --------------------------------------------------------- HTTP + backoff
    def _peer_ready(self, peer):
        with self._backoff_lock:
            nxt, _ = self._backoff.get(peer.rstrip("/"), (0.0, 0))
        return time.monotonic() >= nxt

    def _peer_ok(self, peer):
        with self._backoff_lock:
            self._backoff.pop(peer.rstrip("/"), None)

    def _peer_failed(self, peer):
        self.stats["peer_errors"] += 1
        with self._backoff_lock:
            _, fails = self._backoff.get(peer.rstrip("/"), (0.0, 0))
            fails += 1
            delay = min(BACKOFF_BASE * (2 ** (fails - 1)), BACKOFF_MAX)
            self._backoff[peer.rstrip("/")] = (time.monotonic() + delay, fails)

    def _get(self, peer, path):
        try:
            req = urllib.request.Request(peer + path, method="GET")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read())
        except (urllib.error.URLError, OSError, ValueError):
            return None

    def _post(self, peer, path, body):
        try:
            data = json.dumps(body).encode()
            req = urllib.request.Request(peer + path, data=data, method="POST")
            req.add_header("Content-Type", "application/json")
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read())
        except (urllib.error.URLError, OSError, ValueError):
            return None

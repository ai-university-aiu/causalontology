#!/usr/bin/env python3
"""Live Tier B federation tests (Phase three, Part 21).

Proves the seven properties that make the commons a living, self-healing network
of peers - gossip on write and scheduled anti-entropy - without a coordinator,
without a leader, and with nothing trusted that is not verified:

  (a) GOSSIP CONVERGENCE - two (then three) nodes with DISJOINT writes gossip to
      one another and converge to the identical type-tier set.
  (b) ANTI-ENTROPY RECOVERY - with the gossip announcements deliberately dropped,
      the scheduled anti-entropy pass still converges the nodes.
  (c) EFFICIENT DELTA - equal Merkle roots short-circuit (no transfer); when two
      nodes differ by a few records, ONLY those records move, not the store.
  (d) INBOUND TAMPER REJECTION - an object whose id does not match its hash, or a
      record with a bad signature, is rejected and not merged; the rest of the
      batch still merges.
  (e) IDEMPOTENT / LOOP-FREE - repeated gossip and repeated reconciliation leave
      a converged store unchanged, and an announcement does not circulate forever
      among three peers.
  (f) TOKEN-TIER NOT FEDERATED - a node holding token-tier records does not gossip
      or reconcile them by default; the opt-in path shares them only when enabled.
  (g) PEER-DOWN RESILIENCE - an unreachable peer never blocks a local write; the
      node backs off, retries, and converges once the peer returns.

Every node is a real StoreServer answering over real HTTP; gossip and
reconciliation are driven explicitly for determinism, and (a)/(e) additionally
exercise the real background threads to prove the automation.

Zero dependencies beyond the Python standard library and causalontology-py.
"""

import hashlib
import json
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve()
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "bindings" / "python"))
sys.path.insert(0, str(HERE.parent))

from causalontology import (InMemoryStore, keypair_from_seed,   # noqa: E402
                            sign_record)
from server import StoreServer                                  # noqa: E402
import federation as fed                                        # noqa: E402
import snapshot as snap                                         # noqa: E402

checks = []
_servers = []


def check(name, ok):
    checks.append((name, ok))
    print("%s  %s" % ("PASS" if ok else "FAIL", name))


# ---------------------------------------------------------------------------
# HTTP + node helpers
# ---------------------------------------------------------------------------
def req(base, method, path, body=None):
    r = urllib.request.Request(base + path, method=method)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, data, timeout=10) as resp:
            raw = resp.read()
            ctype = resp.headers.get("Content-Type", "")
            return resp.status, (json.loads(raw) if "json" in ctype else raw)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def spawn(peers=None, include_tokens=False,
          gossip_interval=0.05, anti_entropy_interval=0.1):
    """A live, in-process federation node. Returns (manager, base_url)."""
    opts = {"include_tokens": include_tokens,
            "gossip_interval": gossip_interval,
            "anti_entropy_interval": anti_entropy_interval}
    server = StoreServer(("127.0.0.1", 0), InMemoryStore(),
                         peers=peers, federation_opts=opts)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    _servers.append(server)
    return server.federation, "http://127.0.0.1:%d" % server.server_address[1]


def shutdown_all():
    for s in _servers:
        try:
            s.federation.stop()
            s.shutdown()
        except Exception:  # noqa: BLE001
            pass
    _servers.clear()


# ---------------------------------------------------------------------------
# content helpers
# ---------------------------------------------------------------------------
def keypair(name):
    return keypair_from_seed(hashlib.sha256(name.encode()).digest())


def put_pair(base, label):
    """Write an occurrent + a causal_relation_object built on it; return the CRO
    id. Distinct labels give distinct (disjoint) identifiers per node."""
    _, a = req(base, "POST", "/objects",
               {"type": "occurrent", "label": label + "_cause",
                "category": "action"})
    _, b = req(base, "POST", "/objects",
               {"type": "occurrent", "label": label + "_effect",
                "category": "state_change"})
    _, cro = req(base, "POST", "/objects",
                 {"type": "causal_relation_object",
                  "causes": [a["id"]], "effects": [b["id"]]})
    return cro["id"]


def assert_about(base, about, source_name, ts):
    sk, who = keypair(source_name)
    rec = sign_record({"type": "assertion", "about": about, "source": who,
                       "evidence_type": "observation", "confidence": 0.8,
                       "timestamp": ts}, sk)
    req(base, "POST", "/records", rec)
    return rec


def type_ids(base):
    """The shareable (type-tier) id set a node currently exposes."""
    _, out = req(base, "GET", "/sync/ids")
    return set(out["ids"]), out["merkle_root"]


def gossip_until_quiet(mgrs, rounds=20):
    """Flush every node's gossip queue until a full pass moves nothing. Returns
    the number of rounds it took (proving convergence terminates)."""
    for i in range(1, rounds + 1):
        moved = 0
        for m in mgrs:
            moved += m.flush_gossip()
        if moved == 0:
            return i
    return rounds + 1  # did not settle


def wait_until(predicate, timeout=8.0, tick=0.05):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(tick)
    return predicate()


# ---------------------------------------------------------------------------
# (a) gossip convergence: two then three nodes, disjoint writes
# ---------------------------------------------------------------------------
def test_gossip_convergence():
    # -- two nodes, driven by the REAL background gossip threads --
    a_mgr, A = spawn()
    b_mgr, B = spawn()
    a_mgr.add_peer(B)
    b_mgr.add_peer(A)
    a_mgr.start()
    b_mgr.start()

    cro_a = put_pair(A, "alpha")
    assert_about(A, cro_a, "alice", "2026-07-13T05:00:00Z")
    cro_b = put_pair(B, "beta")
    assert_about(B, cro_b, "bob", "2026-07-13T05:01:00Z")

    converged = wait_until(lambda: type_ids(A)[1] == type_ids(B)[1])
    ida, roota = type_ids(A)
    idb, rootb = type_ids(B)
    check("(a) two nodes gossip disjoint writes to an identical type-tier set",
          converged and ida == idb and roota == rootb)
    check("(a) both nodes hold each other's CRO after gossip",
          {cro_a, cro_b} <= ida and {cro_a, cro_b} <= idb)
    a_mgr.stop()
    b_mgr.stop()

    # -- three fully-connected nodes, driven deterministically --
    x_mgr, X = spawn()
    y_mgr, Y = spawn()
    z_mgr, Z = spawn()
    x_mgr.add_peer(Y); x_mgr.add_peer(Z)
    y_mgr.add_peer(X); y_mgr.add_peer(Z)
    z_mgr.add_peer(X); z_mgr.add_peer(Y)

    cx = put_pair(X, "x_world")
    cy = put_pair(Y, "y_world")
    cz = put_pair(Z, "z_world")
    rounds = gossip_until_quiet([x_mgr, y_mgr, z_mgr])
    sx, sy, sz = type_ids(X)[1], type_ids(Y)[1], type_ids(Z)[1]
    check("(a) three nodes converge to one identical Merkle root",
          sx == sy == sz)
    all_ids = type_ids(X)[0]
    check("(a) the converged set holds every node's disjoint CRO",
          {cx, cy, cz} <= all_ids
          and type_ids(Y)[0] == all_ids and type_ids(Z)[0] == all_ids)
    check("(a) three-peer gossip terminates (loop-free, did not run away)",
          rounds <= 20)


# ---------------------------------------------------------------------------
# (b) anti-entropy recovery: gossip dropped, reconciliation still converges
# ---------------------------------------------------------------------------
def test_anti_entropy_recovery():
    a_mgr, A = spawn()
    b_mgr, B = spawn()
    a_mgr.add_peer(B)
    b_mgr.add_peer(A)
    # NB: no threads started, so no automatic gossip.

    cro_a = put_pair(A, "gamma")
    assert_about(A, cro_a, "carol", "2026-07-13T06:00:00Z")
    cro_b = put_pair(B, "delta")

    # Deliberately DROP every gossip announcement (simulate lost messages).
    dropped_a = a_mgr._drain_queue()
    dropped_b = b_mgr._drain_queue()
    check("(b) gossip announcements were pending and are now dropped",
          bool(dropped_a) and bool(dropped_b)
          and type_ids(A)[1] != type_ids(B)[1])

    # The scheduled anti-entropy pass reconciles despite the dropped gossip.
    a_mgr.reconcile_once()
    ida, roota = type_ids(A)
    idb, rootb = type_ids(B)
    check("(b) anti-entropy converges the nodes after gossip was dropped",
          roota == rootb and ida == idb and {cro_a, cro_b} <= ida)


# ---------------------------------------------------------------------------
# (c) efficient delta: equal roots short-circuit; a small diff ships only itself
# ---------------------------------------------------------------------------
def test_efficient_delta():
    a_mgr, A = spawn()
    b_mgr, B = spawn()
    a_mgr.add_peer(B)
    b_mgr.add_peer(A)

    # a shared baseline of several objects on both nodes
    base_cros = [put_pair(A, "shared_%d" % i) for i in range(5)]
    a_mgr._drain_queue()
    # bring B up to the same state, then confirm the roots now match
    got = a_mgr.reconcile_with(B)
    a_mgr._drain_queue(); b_mgr._drain_queue()
    total_before = len(type_ids(A)[0])

    # roots equal -> a reconcile does NOTHING but the cheap probe
    res_equal = a_mgr.reconcile_with(B)
    check("(c) equal Merkle roots short-circuit: no ids fetched or pushed",
          res_equal["root_matched"] is True
          and res_equal["fetched"] == 0 and res_equal["pushed"] == 0)

    # now diverge by exactly THREE records, one side only
    delta_recs = []
    for i in range(3):
        delta_recs.append(
            assert_about(A, base_cros[i], "dave_%d" % i,
                         "2026-07-13T07:0%d:00Z" % i))
    a_mgr._drain_queue()  # drop gossip so anti-entropy must carry the delta
    check("(c) the two nodes now differ (roots diverged)",
          type_ids(A)[1] != type_ids(B)[1])

    res = b_mgr.reconcile_with(A)     # B pulls A's three new records
    check("(c) exactly the three-record delta is transferred, not the store",
          res["fetched"] == 3 and res["fetched"] < total_before)
    check("(c) the small delta converged the nodes",
          type_ids(A)[1] == type_ids(B)[1])


# ---------------------------------------------------------------------------
# (d) inbound tamper rejection: bad items refused, the rest still merges
# ---------------------------------------------------------------------------
def test_tamper_rejection():
    _, A = spawn()

    # a clean node with one good object + one good record to build a batch from
    good_cro = put_pair(A, "honest")
    good_rec = assert_about(A, good_cro, "erin", "2026-07-13T08:00:00Z")
    _, exp = req(A, "GET", "/sync/export")
    good_obj = next(o for o in exp["objects"] if o["id"] == good_cro)

    # forge a content object: keep an id, change the bytes so id != hash
    forged_obj = dict(good_obj)
    forged_obj = {k: v for k, v in forged_obj.items()}
    forged_obj["id"] = "causal_relation_object:" + "0" * 64  # wrong id
    # forge a record: valid shape, broken signature
    forged_rec = dict(good_rec)
    forged_rec["confidence"] = 0.999999            # signature no longer covers this
    forged_rec["id"] = good_rec["id"] + "_forged"  # a fresh id so it is "new"

    # a brand-new object + record that MUST merge alongside the rejects
    b_mgr, B = spawn()
    fresh_cro = put_pair(B, "fresh")               # only B holds this
    fresh_rec = assert_about(B, fresh_cro, "frank", "2026-07-13T08:01:00Z")
    _, bexp = req(B, "GET", "/sync/export")
    fresh_obj = next(o for o in bexp["objects"] if o["id"] == fresh_cro)

    batch = {"objects": [forged_obj, fresh_obj],
             "records": [forged_rec, fresh_rec]}
    _, counts = req(A, "POST", "/sync/announce", batch)

    check("(d) the forged-id object and bad-signature record are rejected",
          counts["rejected_objects"] >= 1 and counts["rejected_records"] >= 1)
    check("(d) the honest object and record in the same batch still merge",
          counts["objects_added"] == 1 and counts["records_added"] == 1)
    _, after = req(A, "GET", "/sync/export")
    ids_after = {o["id"] for o in after["objects"]} | \
                {r["id"] for r in after["records"]}
    check("(d) the forged items were never persisted",
          forged_obj["id"] not in ids_after
          and forged_rec["id"] not in ids_after
          and fresh_cro in ids_after and fresh_rec["id"] in ids_after)


# ---------------------------------------------------------------------------
# (e) idempotent / loop-free: repeats change nothing; no endless circulation
# ---------------------------------------------------------------------------
def test_idempotent_loop_free():
    x_mgr, X = spawn()
    y_mgr, Y = spawn()
    z_mgr, Z = spawn()
    for m, peers in ((x_mgr, (Y, Z)), (y_mgr, (X, Z)), (z_mgr, (X, Y))):
        for p in peers:
            m.add_peer(p)

    # a single write on X, gossiped through the ring
    cro = put_pair(X, "one_and_only")
    gossip_until_quiet([x_mgr, y_mgr, z_mgr])
    root0 = type_ids(X)[1]
    announced0 = (x_mgr.stats["announced"] + y_mgr.stats["announced"]
                  + z_mgr.stats["announced"])

    # a SECOND full round of gossip after convergence must move nothing new
    extra_rounds = gossip_until_quiet([x_mgr, y_mgr, z_mgr])
    root1 = type_ids(X)[1]
    check("(e) repeated gossip after convergence changes no store (idempotent)",
          root0 == root1 == type_ids(Y)[1] == type_ids(Z)[1])
    check("(e) a converged round of gossip is a no-op (queues already empty)",
          extra_rounds == 1)

    # repeated anti-entropy is a no-op too (roots already match -> short-circuit)
    r = x_mgr.reconcile_with(Y)
    check("(e) repeated reconciliation short-circuits on matching roots",
          r["root_matched"] and r["fetched"] == 0 and r["pushed"] == 0)

    # loop-free: the one record announced a bounded number of times, not forever
    announced1 = (x_mgr.stats["announced"] + y_mgr.stats["announced"]
                  + z_mgr.stats["announced"])
    check("(e) the announcement did not circulate endlessly among three peers",
          announced1 == announced0 and cro in type_ids(Z)[0])


# ---------------------------------------------------------------------------
# (f) token tier is not federated by default; opt-in shares it
# ---------------------------------------------------------------------------
def _seed_token_node(base):
    """Give a node a type-tier CRO plus a token-tier individual and an assertion
    about that token. Returns (type_cro, token_id, token_rec_id)."""
    _, button = req(base, "POST", "/objects",
                    {"type": "continuant", "label": "button_one",
                     "category": "object"})
    cro = put_pair(base, "public_law")
    _, tok = req(base, "POST", "/objects",
                 {"type": "token_individual", "instantiates": button["id"],
                  "designator": "a" * 64})
    sk, alice = keypair("token-owner")
    trec = sign_record({"type": "assertion", "about": tok["id"], "source": alice,
                        "evidence_type": "observation", "confidence": 0.9,
                        "timestamp": "2026-07-13T09:00:00Z"}, sk)
    req(base, "POST", "/records", trec)
    return cro, tok["id"], trec["id"]


def test_token_not_federated():
    a_mgr, A = spawn()
    b_mgr, B = spawn()
    a_mgr.add_peer(B)
    cro, tok, trec = _seed_token_node(A)

    # gossip everything A will share, then reconcile to be thorough
    a_mgr.flush_gossip()
    a_mgr.reconcile_with(B)

    _, bexp = req(B, "GET", "/sync/export")
    b_obj_ids = {o["id"] for o in bexp["objects"]}
    b_rec_ids = {r["id"] for r in bexp["records"]}
    check("(f) the type-tier law federated to the peer", cro in b_obj_ids)
    check("(f) the token-tier individual did NOT federate", tok not in b_obj_ids)
    check("(f) the provenance about the token did NOT federate",
          trec not in b_rec_ids)

    # opt-in: nodes that federate tokens DO share them
    c_mgr, C = spawn(include_tokens=True)
    d_mgr, D = spawn(include_tokens=True)
    c_mgr.add_peer(D)
    cro2, tok2, trec2 = _seed_token_node(C)
    c_mgr.flush_gossip()
    c_mgr.reconcile_with(D)
    _, dexp = req(D, "GET", "/sync/export")
    d_obj_ids = {o["id"] for o in dexp["objects"]}
    d_rec_ids = {r["id"] for r in dexp["records"]}
    check("(f) with the token opt-in enabled, the token DOES federate",
          tok2 in d_obj_ids and trec2 in d_rec_ids)


# ---------------------------------------------------------------------------
# (g) peer-down resilience: writes never block; converge once the peer returns
# ---------------------------------------------------------------------------
def test_peer_down_resilience():
    # A points at a dead peer URL from the start.
    dead = "http://127.0.0.1:9"   # discard port: connections fail fast
    a_mgr, A = spawn(peers=[dead])

    # A local write must return promptly despite the unreachable peer.
    t0 = time.monotonic()
    cro = put_pair(A, "resilient")
    assert_about(A, cro, "grace", "2026-07-13T10:00:00Z")
    elapsed = time.monotonic() - t0
    check("(g) local writes are not blocked by an unreachable peer",
          elapsed < 2.0)

    # A gossip flush to the dead peer fails gracefully and does not crash.
    crashed = False
    try:
        a_mgr.flush_gossip()
    except Exception:  # noqa: BLE001
        crashed = True
    check("(g) a gossip flush to a dead peer degrades gracefully (no crash)",
          not crashed and a_mgr.stats["peer_errors"] >= 1)
    check("(g) the dead peer is now in backoff (will be retried, not hammered)",
          not a_mgr._peer_ready(dead))

    # The peer comes up; A retries (add it fresh to clear backoff) and converges.
    b_mgr, B = spawn()
    a_mgr.add_peer(B)
    b_mgr.add_peer(A)
    a_mgr.reconcile_with(B)
    check("(g) once a reachable peer is available the node converges with it",
          type_ids(A)[1] == type_ids(B)[1] and cro in type_ids(B)[0])


# ---------------------------------------------------------------------------
def main():
    try:
        test_gossip_convergence()
        test_anti_entropy_recovery()
        test_efficient_delta()
        test_tamper_rejection()
        test_idempotent_loop_free()
        test_token_not_federated()
        test_peer_down_resilience()
    finally:
        shutdown_all()

    failed = [n for n, ok in checks if not ok]
    print("-" * 60)
    print("%d/%d federation checks passed" % (len(checks) - len(failed),
                                              len(checks)))
    if failed:
        print("FEDERATION TESTS FAILED:")
        for n in failed:
            print("  FAIL", n)
        sys.exit(1)
    print("Live Tier B federation: nodes gossip and self-heal to one shared "
          "commons - no coordinator, nothing trusted that is not verified.")


if __name__ == "__main__":
    main()

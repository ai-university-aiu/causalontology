#!/usr/bin/env python3
"""Light-client tests: trustless verification, hostile-cache defence, cross-shard
resolution, and local retraction/trust honoring (Phase four, Part 21).

The light client TRUSTS NO SERVER. These tests prove it:

  (a) TRUSTLESS VERIFY - a light client accepts a valid served object and a
      valid record, and REJECTS an object whose bytes were altered (its
      identifier no longer matches its hash) and a provenance record with a bad
      signature - no matter which node or cache served it.
  (c) STALE / HOSTILE CACHE CANNOT DECEIVE - a deliberately wrong cached body is
      caught by the client's hash check and rejected; a correct one is accepted
      and cached (content-addressed, so safe forever).
  (e) CROSS-SHARD RESOLUTION - asked for an identifier a node does not cover, the
      client follows the node's pointer to a holder and fetches the object,
      verifying it itself.
  (h) LOCAL TRUST + RETRACTION - the client re-derives retraction/succession
      honoring from the verified record history (not from a server's filtered
      view) and applies its own TrustPolicy; the server decides nothing.

A real StoreServer answers over real HTTP; a "hostile" server is a tiny handler
that serves deliberately corrupted bytes, to prove the client catches the lie.

Zero dependencies beyond the Python standard library and causalontology-py.
"""

import hashlib
import json
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve()
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "bindings" / "python"))
sys.path.insert(0, str(ROOT / "store" / "server"))
sys.path.insert(0, str(HERE.parent))

from causalontology import (InMemoryStore, keypair_from_seed,   # noqa: E402
                            sign_record)
from server import StoreServer                                  # noqa: E402
import sharding as shd                                          # noqa: E402
from light_client import (LightClient, TrustPolicy,             # noqa: E402
                          VerificationError, ResolutionError)

checks = []
_servers = []


def check(name, ok):
    checks.append((name, ok))
    print("%s  %s" % ("PASS" if ok else "FAIL", name))


def req(base, method, path, body=None):
    r = urllib.request.Request(base + path, method=method)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        r.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(r, data, timeout=10) as resp:
        raw = resp.read()
        return resp.status, (json.loads(raw) if raw else {})


def spawn(shard=None, shard_map=None):
    cfg = shd.ShardConfig.parse(shard) if shard else None
    server = StoreServer(("127.0.0.1", 0), InMemoryStore(),
                         federation_opts={"gossip_interval": 0.05,
                                          "anti_entropy_interval": 0.1},
                         shard=cfg, shard_map=shard_map)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    _servers.append(server)
    return server, "http://127.0.0.1:%d" % server.server_address[1]


def shutdown_all():
    for s in _servers:
        try:
            s.federation.stop()
            s.shutdown()
        except Exception:  # noqa: BLE001
            pass
    _servers.clear()


def keypair(name):
    return keypair_from_seed(hashlib.sha256(name.encode()).digest())


def put_pair(base, label):
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


def mint_in(base, cfg, prefix):
    for i in range(400):
        cro = put_pair(base, "%s_%d" % (prefix, i))
        if cfg.covers(cro):
            return cro
    raise RuntimeError("could not mint into shard")


# ---------------------------------------------------------------------------
# a deliberately HOSTILE node: serves corrupted object / record bytes
# ---------------------------------------------------------------------------
class _HostileHandler(BaseHTTPRequestHandler):
    payloads = {}   # path -> (status, json-serializable body)

    def log_message(self, *a):  # quiet
        pass

    def do_GET(self):
        path = self.path
        status, body = self.payloads.get(path, (404, {"error": "no"}))
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        # A hostile CDN even claims the content is immutable and cacheable.
        self.send_header("Cache-Control", "public, max-age=31536000, immutable")
        self.end_headers()
        self.wfile.write(raw)


def spawn_hostile(payloads):
    handler = type("H", (_HostileHandler,), {"payloads": payloads})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    _servers.append(server)
    return "http://127.0.0.1:%d" % server.server_address[1]


# ---------------------------------------------------------------------------
# (a) trustless verification of a valid object and record; rejection of tampers
# ---------------------------------------------------------------------------
def test_trustless_verify():
    node, N = spawn()
    cro = put_pair(N, "honest_obj")
    rec = assert_and_return(N, cro, "verifier", "2026-07-14T01:00:00Z")

    lc = LightClient(nodes=[N])
    obj = lc.get_object(cro)
    check("(a) a valid served object is accepted and verifies by hash",
          obj.get("id") == cro)
    got = lc.get_record(rec["id"])
    check("(a) a valid served record is accepted and its signature verifies",
          got["id"] == rec["id"])

    # Serve the SAME object with altered bytes from a hostile node: id no longer
    # matches the hash. The client must REJECT it, whichever node served it.
    _, raw = req(N, "GET", "/objects/%s?view=raw" % cro)
    tampered = dict(raw["object"])
    tampered["modality"] = "necessary"       # change identity-bearing bytes
    bad_obj_node = spawn_hostile(
        {"/objects/%s?view=raw" % cro: (200, {"object": tampered})})
    lc2 = LightClient(nodes=[bad_obj_node])
    rejected = False
    try:
        lc2.get_object(cro)
    except VerificationError:
        rejected = True
    check("(a) an object whose bytes were altered (id != hash) is REJECTED",
          rejected)

    # Serve a record with a broken signature: the client must reject it.
    forged = dict(rec)
    forged["confidence"] = 0.123456          # signature no longer covers this
    bad_rec_node = spawn_hostile(
        {"/records/%s" % rec["id"]: (200, forged)})
    lc3 = LightClient(nodes=[bad_rec_node])
    rejected_rec = False
    try:
        lc3.get_record(rec["id"])
    except VerificationError:
        rejected_rec = True
    check("(a) a provenance record with a bad signature is REJECTED", rejected_rec)


def assert_and_return(base, about, name, ts):
    sk, who = keypair(name)
    rec = sign_record({"type": "assertion", "about": about, "source": who,
                       "evidence_type": "observation", "confidence": 0.8,
                       "timestamp": ts}, sk)
    req(base, "POST", "/records", rec)
    return rec


# ---------------------------------------------------------------------------
# (c) a stale / hostile cache cannot deceive a verifying client
# ---------------------------------------------------------------------------
def test_hostile_cache():
    node, N = spawn()
    cro = put_pair(N, "cache_target")
    _, raw = req(N, "GET", "/objects/%s?view=raw" % cro)
    good = raw["object"]

    # A CDN edge that swaps in a DIFFERENT object's bytes under this identifier,
    # while advertising them as immutable-cacheable. The hash check catches it.
    other = dict(good)
    other["context"] = ["occurrent:" + "a" * 64]   # different identity bytes
    edge = spawn_hostile({"/objects/%s?view=raw" % cro: (200, {"object": other})})
    lc = LightClient(nodes=[edge])
    caught = False
    try:
        lc.get_object(cro)
    except VerificationError:
        caught = True
    check("(c) a hostile/stale cache serving wrong bytes is caught by the hash "
          "check and REJECTED", caught)
    check("(c) nothing unverified was admitted to the client cache",
          cro not in lc.cache)

    # The same client, pointed at the HONEST origin, accepts and then caches it.
    lc_ok = LightClient(nodes=[N])
    obj = lc_ok.get_object(cro)
    check("(c) the honest origin's bytes verify and are cached (safe forever)",
          obj.get("id") == cro and cro in lc_ok.cache)


# ---------------------------------------------------------------------------
# (e) the client follows a cross-shard pointer to a holder and verifies
# ---------------------------------------------------------------------------
def test_cross_shard_follow():
    holder, HOLDER = spawn(shard="0-7")
    x = mint_in(HOLDER, shd.ShardConfig.parse("0-7"), "xshard")
    smap = shd.ShardMap([(HOLDER, "0-7")])
    asker, ASKER = spawn(shard="8-f", shard_map=smap)

    # The client knows only the ASKER (which does NOT cover x). It must follow
    # the ASKER's pointer to the HOLDER and fetch+verify the object there.
    lc = LightClient(nodes=[ASKER])
    obj = lc.get_object(x)
    check("(e) the client follows a node's out-of-shard pointer to a holder",
          obj.get("id") == x)
    check("(e) the object fetched across the pointer verifies by hash",
          obj.get("id") == x and x in lc.cache)

    # With a shard map, the client resolves straight to the holder first.
    lc2 = LightClient(nodes=[HOLDER, ASKER], shard_map=smap)
    check("(e) a shard map resolves an identifier straight to its holder",
          lc2._candidate_nodes(x)[0] == HOLDER)

    # discover_shards learns coverage from the nodes themselves.
    lc3 = LightClient(nodes=[HOLDER, ASKER])
    lc3.discover_shards()
    check("(e) discover_shards learns who-holds-what from GET /shards",
          HOLDER in lc3.shard_map.nodes_for(x))


# ---------------------------------------------------------------------------
# (h) local trust policy + retraction honoring, re-derived from verified records
# ---------------------------------------------------------------------------
def test_local_trust_and_retraction():
    node, N = spawn()
    cro = put_pair(N, "trust_target")

    # two assertions from two sources, one of which the consumer will retract
    sk_a, who_a = keypair("author-A")
    a1 = sign_record({"type": "assertion", "about": cro, "source": who_a,
                      "evidence_type": "observation", "confidence": 0.9,
                      "timestamp": "2026-07-14T02:00:00Z"}, sk_a)
    req(N, "POST", "/records", a1)
    sk_b, who_b = keypair("author-B")
    a2 = sign_record({"type": "assertion", "about": cro, "source": who_b,
                      "evidence_type": "human_hint", "confidence": 0.4,
                      "timestamp": "2026-07-14T02:05:00Z"}, sk_b)
    req(N, "POST", "/records", a2)

    lc = LightClient(nodes=[N])
    believed = {r["id"] for r in lc.believe_about(cro)}
    check("(h) before any retraction the client believes both verified assertions",
          {a1["id"], a2["id"]} <= believed)

    # author-A retracts their own assertion (authorized: same source lineage).
    retr = sign_record({"type": "retraction", "retracts": a1["id"],
                        "source": who_a, "timestamp": "2026-07-14T02:10:00Z"},
                       sk_a)
    req(N, "POST", "/records", retr)
    believed2 = {r["id"] for r in lc.believe_about(cro)}
    check("(h) the client honors a valid retraction (re-derived locally)",
          a1["id"] not in believed2 and a2["id"] in believed2)

    # a consumer trust policy: only author-B's source, confidence >= 0.3
    strict = LightClient(nodes=[N],
                         trust=TrustPolicy(allowed_sources={who_b},
                                           min_confidence=0.3))
    believed3 = {r["id"] for r in strict.believe_about(cro)}
    check("(h) the consumer's own TrustPolicy is applied locally, not by a server",
          believed3 == {a2["id"]})


# ---------------------------------------------------------------------------
def main():
    try:
        test_trustless_verify()
        test_hostile_cache()
        test_cross_shard_follow()
        test_local_trust_and_retraction()
    finally:
        shutdown_all()

    failed = [n for n, ok in checks if not ok]
    print("-" * 60)
    print("%d/%d light-client checks passed"
          % (len(checks) - len(failed), len(checks)))
    if failed:
        print("LIGHT-CLIENT TESTS FAILED:")
        for n in failed:
            print("  FAIL", n)
        sys.exit(1)
    print("The light client trusts no server: it verifies every object by hash "
          "and every record by signature, resolves across shards, and decides "
          "for itself what to believe.")


if __name__ == "__main__":
    main()

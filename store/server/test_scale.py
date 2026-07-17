#!/usr/bin/env python3
"""Phase-four scale tests: CDN caching, hash-prefix sharding, per-shard
federation, and the public token boundary (Part 21).

Proves the server-side half of the scale finale - the light-client half lives in
store/client/test_light_client.py. Together they establish the seven properties
the change order gates on:

  (b) CACHE HEADERS CORRECT - immutable content responses (the raw object view
      and provenance records) carry long-lived immutable cache headers and an
      ETag equal to the identifier; mutable/derived responses (the default
      materialized view, gaps, reputation) do NOT.
  (d) SHARD COVERAGE - a partial node holds ONLY its declared prefixes; the
      union of a set of shards equals the whole store; a coverage gap is
      detected and surfaced.
  (e) CROSS-SHARD RESOLUTION - a request to a node for an out-of-shard
      identifier returns a correct pointer to a node that holds it.
  (f) PER-SHARD FEDERATION - gossip and anti-entropy converge WITHIN a shard
      without forcing a node to hold prefixes outside its coverage.
  (g) TOKEN-TIER NOT PUBLICLY SERVED - token-tier records are not returned over
      the public light-client / CDN path and are not placed in public shards by
      default; the opt-in path serves them.

Every node is a real StoreServer answering over real HTTP; sharded federation is
driven explicitly for determinism.

Zero dependencies beyond the Python standard library and causalontology-py.
"""

import hashlib
import json
import sys
import threading
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
import sharding as shd                                          # noqa: E402

checks = []
_servers = []


def check(name, ok):
    checks.append((name, ok))
    print("%s  %s" % ("PASS" if ok else "FAIL", name))


# ---------------------------------------------------------------------------
# HTTP + node helpers
# ---------------------------------------------------------------------------
def req(base, method, path, body=None):
    """Return (status, headers, body). Headers are lower-cased keys. A 4xx/5xx
    is returned, not raised, so a pointer (421) is visible to the caller."""
    r = urllib.request.Request(base + path, method=method)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, data, timeout=10) as resp:
            raw = resp.read()
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            ctype = resp.headers.get("Content-Type", "")
            return resp.status, hdrs, (json.loads(raw) if "json" in ctype
                                       and raw else raw)
    except urllib.error.HTTPError as e:
        raw = e.read() or b"{}"
        hdrs = {k.lower(): v for k, v in e.headers.items()}
        try:
            payload = json.loads(raw)
        except ValueError:
            payload = raw
        return e.code, hdrs, payload


def spawn(peers=None, include_tokens=False, shard=None, shard_map=None,
          gossip_interval=0.05, anti_entropy_interval=0.1):
    """A live, in-process node (full or partial). Returns (server, base_url)."""
    opts = {"include_tokens": include_tokens,
            "gossip_interval": gossip_interval,
            "anti_entropy_interval": anti_entropy_interval}
    cfg = shd.ShardConfig.parse(shard) if shard else None
    server = StoreServer(("127.0.0.1", 0), InMemoryStore(),
                         peers=peers, federation_opts=opts,
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
    """Write an occurrent + a causal_relation_object; return the CRO id."""
    _, _, a = req(base, "POST", "/objects",
                  {"type": "occurrent", "label": label + "_cause",
                   "category": "action"})
    _, _, b = req(base, "POST", "/objects",
                  {"type": "occurrent", "label": label + "_effect",
                   "category": "state_change"})
    _, _, cro = req(base, "POST", "/objects",
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


def sync_ids(base):
    _, _, out = req(base, "GET", "/sync/ids")
    return set(out["ids"]), out["merkle_root"]


def seed_spread(base, n):
    """Seed n CROs whose identifiers spread across the hex-nibble space."""
    return [put_pair(base, "spread_%d" % i) for i in range(n)]


# ---------------------------------------------------------------------------
# (b) cache headers: immutable content cached forever; mutable views not
# ---------------------------------------------------------------------------
def test_cache_headers():
    _, A = spawn()
    cro = put_pair(A, "cache_me")
    rec = assert_about(A, cro, "cache_source", "2026-07-14T00:00:00Z")

    # raw object view - the CDN / light-client immutable path
    st, hdrs, _ = req(A, "GET", "/objects/%s?view=raw" % cro)
    cc = hdrs.get("cache-control", "")
    check("(b) raw object is immutable-cacheable (public, immutable, long max-age)",
          st == 200 and "immutable" in cc and "public" in cc
          and "max-age=31536000" in cc)
    check("(b) raw object ETag equals its identifier (its hash)",
          hdrs.get("etag") == '"%s"' % cro)

    # a provenance record - immutable, self-authenticating
    st, hdrs, _ = req(A, "GET", "/records/%s" % rec["id"])
    check("(b) a provenance record is immutable-cacheable with ETag = its id",
          st == 200 and "immutable" in hdrs.get("cache-control", "")
          and hdrs.get("etag") == '"%s"' % rec["id"])

    # the DEFAULT materialized view - mutable, must NOT be immutable-cached
    st, hdrs, _ = req(A, "GET", "/objects/%s" % cro)
    check("(b) the default materialized object view is NOT immutable-cached",
          st == 200 and "immutable" not in hdrs.get("cache-control", "")
          and hdrs.get("etag") is None)

    # derived views: gaps and reputation - never cached as if immutable
    _, ghdrs, _ = req(A, "GET", "/gaps")
    _, rhdrs, _ = req(A, "GET", "/reputation?source=%s"
                      % rec["source"])
    check("(b) gaps and reputation are NOT immutable-cached (mutable/derived)",
          "immutable" not in ghdrs.get("cache-control", "")
          and "immutable" not in rhdrs.get("cache-control", ""))

    # a conditional revalidation on the immutable path returns 304
    st, _, _ = _conditional(A, "/objects/%s?view=raw" % cro, cro)
    check("(b) If-None-Match on an immutable object revalidates to 304",
          st == 304)


def _conditional(base, path, etag):
    r = urllib.request.Request(base + path, method="GET")
    r.add_header("If-None-Match", '"%s"' % etag)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


# ---------------------------------------------------------------------------
# (d) shard coverage + (f) per-shard federation
# ---------------------------------------------------------------------------
def test_shard_coverage_and_federation():
    # A FULL node holds the whole store; two partial nodes split it in half.
    full, F = spawn()
    all_cros = seed_spread(F, 24)
    full_ids, full_root = sync_ids(F)

    lo_cfg = shd.ShardConfig.parse("0-7")
    hi_cfg = shd.ShardConfig.parse("8-f")
    lo, LO = spawn(shard="0-7")
    hi, HI = spawn(shard="8-f")
    lo.federation.add_peer(F)
    hi.federation.add_peer(F)
    lo.federation.reconcile_with(F)   # pulls ONLY the 0-7 slice
    hi.federation.reconcile_with(F)   # pulls ONLY the 8-f slice

    lo_ids, _ = sync_ids(LO)
    hi_ids, _ = sync_ids(HI)

    check("(d) a partial node holds ONLY identifiers within its declared shard",
          all(lo_cfg.covers(i) for i in lo_ids)
          and all(hi_cfg.covers(i) for i in hi_ids))
    check("(d) neither partial node was forced to hold prefixes outside coverage",
          not any(hi_cfg.covers(i) for i in lo_ids)
          and not any(lo_cfg.covers(i) for i in hi_ids))
    check("(d) the union of the two shards equals the whole store",
          (lo_ids | hi_ids) == full_ids and lo_ids and hi_ids)

    # coverage invariant: two half-shards are complete; dropping one leaves a gap
    complete = shd.coverage_report([lo_cfg, hi_cfg])
    gap = shd.coverage_report([lo_cfg])
    check("(d) the coverage invariant holds for the full split (no gap)",
          complete["complete"] and not complete["missing"])
    check("(d) a coverage GAP is detected and surfaced (missing 8-f nibbles)",
          not gap["complete"] and set(gap["missing"]) == set("89abcdef"))

    # the gap is surfaced over the wire on /shards, too
    gapmap = shd.ShardMap([(LO, lo_cfg)])
    partial_with_gap, PG = spawn(shard="0-7", shard_map=gapmap)
    _, _, shards_doc = req(PG, "GET", "/shards")
    check("(d) GET /shards surfaces the coverage invariant (a gap is visible)",
          shards_doc["coverage"]["complete"] is False
          and "f" in shards_doc["coverage"]["missing"])

    # (f) per-shard federation: a new in-shard write reaches a same-shard peer;
    # a same-shard second node converges on the slice via anti-entropy.
    lo2, LO2 = spawn(shard="0-7")
    lo2.federation.add_peer(LO)
    lo2.federation.reconcile_with(LO)      # within-shard convergence
    lo2_ids, lo2_root = sync_ids(LO2)
    check("(f) a same-shard node converges on the slice (within-shard anti-entropy)",
          lo2_ids == lo_ids and lo2_root == sync_ids(LO)[1])

    # gossip a fresh in-shard object from F; LO (0-7) gets it, HI (8-f) does not
    in_lo = _mint_in(F, lo_cfg, "fresh_lo")
    in_hi = _mint_in(F, hi_cfg, "fresh_hi")
    lo.federation.reconcile_with(F)
    hi.federation.reconcile_with(F)
    lo_after, _ = sync_ids(LO)
    hi_after, _ = sync_ids(HI)
    check("(f) a new in-shard object federates to the shard's node",
          in_lo in lo_after and in_hi in hi_after)
    check("(f) an out-of-shard object never lands on a node that does not cover it",
          in_hi not in lo_after and in_lo not in hi_after)
    check("(f) each partial node's Merkle root differs from the full node's "
          "(it commits only its slice)",
          sync_ids(LO)[1] != full_root and sync_ids(HI)[1] != full_root)


def _mint_in(base, cfg, prefix):
    """Mint CROs until one lands in the given shard (hashes are uniform, so a
    handful of tries suffices)."""
    for i in range(400):
        cro = put_pair(base, "%s_%d" % (prefix, i))
        if cfg.covers(cro):
            return cro
    raise RuntimeError("could not mint into shard %s" % cfg.to_spec())


# ---------------------------------------------------------------------------
# (e) cross-shard resolution: an out-of-shard request is pointed at a holder
# ---------------------------------------------------------------------------
def test_cross_shard_pointer():
    # A node that holds the 0-7 slice, and a node covering 8-f that knows it.
    holder, HOLDER = spawn(shard="0-7")
    x = _mint_in(HOLDER, shd.ShardConfig.parse("0-7"), "target")

    smap = shd.ShardMap([(HOLDER, "0-7")])
    asker, ASKER = spawn(shard="8-f", shard_map=smap)

    # x is outside ASKER's shard -> ASKER must POINT, not falsely 404.
    st, hdrs, body = req(ASKER, "GET", "/objects/%s?view=raw" % x)
    check("(e) an out-of-shard request returns a pointer (HTTP 421), not a 404",
          st == 421 and isinstance(body, dict))
    check("(e) the pointer names a node that actually holds the identifier",
          body.get("holders") == [HOLDER]
          and HOLDER in (hdrs.get("location") or ""))

    # in-shard-but-absent on the ASKER is still an honest 404 (covered, not held)
    absent = "occurrent:" + "8" + "0" * 63   # in 8-f shard, not present
    st2, _, _ = req(ASKER, "GET", "/objects/%s?view=raw" % absent)
    check("(e) an in-shard-but-absent identifier is an honest 404, not a pointer",
          st2 == 404)

    # following the pointer to the holder yields the object, and it verifies
    st3, _, body3 = req(HOLDER, "GET", "/objects/%s?view=raw" % x)
    from causalontology import identify
    check("(e) the pointed-to holder serves the object and it verifies by hash",
          st3 == 200 and identify(body3["object"]) == x)


# ---------------------------------------------------------------------------
# (g) token tier is not served on the public path, nor placed in public shards
# ---------------------------------------------------------------------------
def _seed_token_node(base):
    _, _, button = req(base, "POST", "/objects",
                       {"type": "continuant", "label": "button_g",
                        "category": "object"})
    cro = put_pair(base, "public_law_g")
    _, _, tok = req(base, "POST", "/objects",
                    {"type": "token_individual", "instantiates": button["id"],
                     "designator": "b" * 64})
    sk, alice = keypair("token-owner-g")
    trec = sign_record({"type": "assertion", "about": tok["id"], "source": alice,
                        "evidence_type": "observation", "confidence": 0.9,
                        "timestamp": "2026-07-14T09:00:00Z"}, sk)
    req(base, "POST", "/records", trec)
    return cro, tok["id"], trec["id"]


def test_token_not_publicly_served():
    node, N = spawn()   # default: local-by-default, tokens not served publicly
    cro, tok, trec = _seed_token_node(N)

    st_type, _, _ = req(N, "GET", "/objects/%s?view=raw" % cro)
    st_tok, _, _ = req(N, "GET", "/objects/%s?view=raw" % tok)
    st_rec, _, _ = req(N, "GET", "/records/%s" % trec)
    check("(g) the type-tier law IS served on the public raw path", st_type == 200)
    check("(g) a token-tier object is NOT served on the public raw path (404)",
          st_tok == 404)
    check("(g) provenance about a token is NOT served on the public path (404)",
          st_rec == 404)

    ids, _ = sync_ids(N)
    check("(g) token-tier identifiers are NOT placed in the public shard set",
          cro in ids and tok not in ids and trec not in ids)

    # opt-in: a node that serves tokens does return them on the public path
    onode, ON = spawn(include_tokens=True)
    cro2, tok2, trec2 = _seed_token_node(ON)
    st_tok2, _, _ = req(ON, "GET", "/objects/%s?view=raw" % tok2)
    st_rec2, _, _ = req(ON, "GET", "/records/%s" % trec2)
    oids, _ = sync_ids(ON)
    check("(g) with the token opt-in, tokens ARE served and shared",
          st_tok2 == 200 and st_rec2 == 200 and tok2 in oids)


# ---------------------------------------------------------------------------
def main():
    try:
        test_cache_headers()
        test_shard_coverage_and_federation()
        test_cross_shard_pointer()
        test_token_not_publicly_served()
    finally:
        shutdown_all()

    failed = [n for n, ok in checks if not ok]
    print("-" * 60)
    print("%d/%d scale checks passed" % (len(checks) - len(failed), len(checks)))
    if failed:
        print("SCALE TESTS FAILED:")
        for n in failed:
            print("  FAIL", n)
        sys.exit(1)
    print("Phase four: CDN-cacheable immutable reads, hash-prefix sharding with "
          "cross-shard pointers, per-shard federation, and a token-safe public "
          "path - the commons scales sideways.")


if __name__ == "__main__":
    main()

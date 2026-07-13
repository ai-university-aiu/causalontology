#!/usr/bin/env python3
"""Beyond-MVP smoke test: SPARQL subset, triples export, reputation,
and Tier B federation (two live servers syncing by pull)."""

import hashlib
import json
import sys
import threading
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[2] / "bindings" / "python"))
sys.path.insert(0, str(HERE.parent))

from causalontology import InMemoryStore, keypair_from_seed, sign_record  # noqa: E402
from server import StoreServer                                            # noqa: E402

checks = []


def check(name, ok):
    checks.append((name, ok))
    print("%s  %s" % ("PASS" if ok else "FAIL", name))


def req(base, method, path, body=None):
    r = urllib.request.Request(base + path, method=method)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        r.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(r, data) as resp:
        raw = resp.read()
        return resp.status, (json.loads(raw)
                             if "json" in resp.headers.get("Content-Type", "")
                             else raw.decode())


def spawn():
    server = StoreServer(("127.0.0.1", 0), InMemoryStore())
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, "http://127.0.0.1:%d" % server.server_address[1]


def main():
    a_server, A = spawn()
    b_server, B = spawn()

    # seed store A with the quickstart world
    _, press = req(A, "POST", "/objects",
                   {"type": "occurrent", "label": "press_button",
                    "category": "action"})
    _, light = req(A, "POST", "/objects",
                   {"type": "occurrent", "label": "light_on",
                    "category": "state_change"})
    press, light = press["id"], light["id"]
    _, P = req(A, "POST", "/objects",
               {"type": "cro", "causes": [press], "effects": [light],
                "temporal": {"dmin": 0, "dmax": 1, "unit": "seconds"},
                "modality": "sufficient"})
    P = P["id"]
    sk, alice = keypair_from_seed(hashlib.sha256(b"alice").digest())
    ast = sign_record({"type": "assertion", "about": P, "source": alice,
                       "evidence_type": "intervention", "strength": 0.98,
                       "confidence": 0.95,
                       "timestamp": "2026-07-13T05:00:00Z"}, sk)
    req(A, "POST", "/records", ast)
    enr = sign_record({"type": "enrichment", "about": press,
                       "field": "aliases",
                       "entry": {"lang": "en", "text": "Press the Button"},
                       "source": alice,
                       "timestamp": "2026-07-13T05:01:00Z"}, sk)
    req(A, "POST", "/records", enr)

    # ---- SPARQL subset -------------------------------------------------
    q = "SELECT ?c ?e WHERE { ?x co:hasCause ?c . ?x co:hasEffect ?e . }"
    _, out = req(A, "GET", "/sparql?query=" + urllib.parse.quote(q))
    check("SPARQL: causes joined to effects",
          out["head"]["vars"] == ["c", "e"]
          and {"c": press, "e": light} ==
          {k: v["value"] for k, v in out["results"]["bindings"][0].items()})

    q = ('SELECT ?claim WHERE { ?a co:about ?claim . '
         '?a co:evidenceType "intervention" . }')
    _, out = req(A, "GET", "/sparql?query=" + urllib.parse.quote(q))
    check("SPARQL: intervention-backed claims",
          [b["claim"]["value"] for b in out["results"]["bindings"]] == [P])

    q = 'SELECT ?s WHERE { ?s co:alias "Press the Button" . }'
    _, out = req(A, "POST", "/sparql", {"query": q})
    check("SPARQL over POST: alias literal lookup",
          [b["s"]["value"] for b in out["results"]["bindings"]] == [press])

    # (a 400 raises HTTPError in urllib)
    try:
        req(A, "GET", "/sparql?query=nonsense")
        check("SPARQL: malformed query -> 400", False)
    except urllib.error.HTTPError as e:
        check("SPARQL: malformed query -> 400", e.code == 400)

    # ---- N-Triples export ---------------------------------------------
    _, nt = req(A, "GET", "/export/triples")
    check("N-Triples export carries the causal edge",
          "<https://causalontology.org/ns#hasCause>" in nt
          and "<https://causalontology.org/id/%s>" % P in nt)

    # ---- reputation -----------------------------------------------------
    _, rep = req(A, "GET", "/reputation?source="
                 + urllib.parse.quote(alice))
    check("reputation aggregates the signed history",
          rep["assertions"] == 1 and rep["enrichments"] == 1
          and rep["evidence_histogram"].get("intervention") == 1
          and rep["active_since"] == "2026-07-13T05:00:00Z")

    # ---- Tier B federation ----------------------------------------------
    _, counts = req(B, "POST", "/sync/pull", {"peer": A})
    check("B pulls A: everything arrives",
          counts["objects_added"] == 3 and counts["records_added"] == 2)
    _, viewB = req(B, "GET", "/objects/" + press)
    check("B materializes A's alias after sync",
          viewB["enrichments"]["aliases"][0]["entry"]["text"]
          == "Press the Button")

    # divergent writes on B, then A pulls back: bidirectional convergence
    sk2, bob = keypair_from_seed(hashlib.sha256(b"bob").digest())
    enr2 = sign_record({"type": "enrichment", "about": press,
                        "field": "aliases",
                        "entry": {"lang": "en", "text": "Press the Button"},
                        "source": bob,
                        "timestamp": "2026-07-13T05:02:00Z"}, sk2)
    req(B, "POST", "/records", enr2)
    _, counts = req(A, "POST", "/sync/pull", {"peer": B})
    check("A pulls B: only the new record moves (idempotent union)",
          counts["objects_added"] == 0 and counts["records_added"] == 1)
    _, viewA = req(A, "GET", "/objects/" + press)
    check("federated corroboration: one alias, two signed contributors",
          len(viewA["enrichments"]["aliases"]) == 1
          and len(viewA["enrichments"]["aliases"][0]["contributors"]) == 2)
    _, ea = req(A, "GET", "/sync/export")
    _, eb = req(B, "GET", "/sync/export")
    check("both stores converge to the same state",
          {o["id"] for o in ea["objects"]} == {o["id"] for o in eb["objects"]}
          and {r["id"] for r in ea["records"]}
          == {r["id"] for r in eb["records"]})

    a_server.shutdown()
    b_server.shutdown()
    failed = [n for n, ok in checks if not ok]
    print("-" * 60)
    print("%d/%d beyond-MVP checks passed"
          % (len(checks) - len(failed), len(checks)))
    if failed:
        sys.exit(1)
    print("SPARQL, linked-data export, reputation, and Tier B federation: "
          "all live.")


if __name__ == "__main__":
    import urllib.error  # noqa: E402  (used in the malformed-query check)
    main()

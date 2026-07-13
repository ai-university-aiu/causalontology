#!/usr/bin/env python3
"""End-to-end smoke test for the Tier A reference store.

Drives the whole quickstart over real HTTP: vocabulary, a degenerate claim,
the visible gap, the refinement that closes it, signed assertions, quarantine
of unsigned records, retraction, resolve, conflicts, pagination, and auth.
"""

import hashlib
import json
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[2] / "bindings" / "python"))
sys.path.insert(0, str(HERE.parent))

from causalontology import InMemoryStore, keypair_from_seed, sign_record  # noqa: E402
from server import StoreServer                                            # noqa: E402

TOKEN = "sesame"
checks = []


def check(name, ok):
    checks.append((name, ok))
    print("%s  %s" % ("PASS" if ok else "FAIL", name))


def req(base, method, path, body=None, token=TOKEN):
    r = urllib.request.Request(base + path, method=method)
    if token:
        r.add_header("Authorization", "Bearer " + token)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, data) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def main():
    store = InMemoryStore()
    server = StoreServer(("127.0.0.1", 0), store, token=TOKEN)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % server.server_address[1]

    # service info
    code, info = req(base, "GET", "/")
    check("service info", code == 200 and "endpoints" in info)

    # auth: a write without the bearer token is refused
    code, _ = req(base, "POST", "/objects",
                  {"type": "occurrent", "label": "x", "category": "event"},
                  token=None)
    check("write without token -> 401", code == 401)

    # vocabulary
    code, press = req(base, "POST", "/objects",
                      {"type": "occurrent", "label": "press_button",
                       "category": "action"})
    check("mint press_button -> 201", code == 201)
    code, light = req(base, "POST", "/objects",
                      {"type": "occurrent", "label": "light_on",
                       "category": "state_change"})
    check("mint light_on -> 201", code == 201)
    press, light = press["id"], light["id"]

    # idempotent re-put
    code, again = req(base, "POST", "/objects",
                      {"type": "occurrent", "label": "press_button",
                       "category": "action"})
    check("identical put is idempotent", code == 200
          and again["id"] == press and again["created"] is False)

    # the degenerate claim, and the visible gap
    code, P = req(base, "POST", "/objects",
                  {"type": "cro", "causes": [press], "effects": [light]})
    P = P["id"]
    code, gaps = req(base, "GET", "/gaps?kind=missing_field")
    check("degenerate claim appears in /gaps",
          any(g["id"] == P for g in gaps["items"]))

    # the refinement closes the gap
    code, R = req(base, "POST", "/objects",
                  {"type": "cro", "causes": [press], "effects": [light],
                   "temporal": {"dmin": 0, "dmax": 1, "unit": "seconds"},
                   "modality": "sufficient", "refines": P})
    R = R["id"]
    code, gaps = req(base, "GET", "/gaps?kind=missing_field")
    check("refinement closes the gap",
          not any(g["id"] in (P, R) for g in gaps["items"]))

    # a signed assertion lands; an unsigned one is quarantined
    sk, alice = keypair_from_seed(hashlib.sha256(b"alice").digest())
    assertion = sign_record({"type": "assertion", "about": R,
                             "source": alice,
                             "evidence_type": "intervention",
                             "strength": 0.98, "confidence": 0.95,
                             "timestamp": "2026-07-13T03:00:00Z"}, sk)
    code, out = req(base, "POST", "/records", assertion)
    check("signed assertion -> 201", code == 201)
    ast_id = out["id"]
    code, out = req(base, "POST", "/records",
                    {"type": "assertion", "about": R, "source": alice,
                     "evidence_type": "observation", "confidence": 0.5,
                     "timestamp": "2026-07-13T03:01:00Z"})
    check("unsigned record -> 202 quarantined",
          code == 202 and out["quarantined"] is True)
    code, out = req(base, "GET", "/assertions?about=" + R)
    check("assertions_about shows the signed one only",
          len(out["items"]) == 1)

    # enrichment + resolve (label first, then alias)
    enr = sign_record({"type": "enrichment", "about": press,
                       "field": "aliases",
                       "entry": {"lang": "en", "text": "Press the Button"},
                       "source": alice,
                       "timestamp": "2026-07-13T03:02:00Z"}, sk)
    code, _ = req(base, "POST", "/records", enr)
    code, out = req(base, "GET", "/objects/" + press)
    check("materialized alias with contributor",
          len(out["enrichments"]["aliases"][0]["contributors"]) == 1)
    code, out = req(base, "GET",
                    "/resolve?text=Press%20%20The%20%20%20Button&lang=en")
    check("resolve by alias (case/space-insensitive)",
          out["items"] == [press])
    code, out = req(base, "GET", "/resolve?text=press_button")
    check("resolve by canonical label", out["items"][0] == press)

    # retraction: the honest exit
    ret = sign_record({"type": "retraction", "retracts": ast_id,
                       "source": alice,
                       "timestamp": "2026-07-13T03:03:00Z"}, sk)
    code, _ = req(base, "POST", "/records", ret)
    code, out = req(base, "GET", "/assertions?about=" + R)
    check("retraction empties the default view", out["items"] == [])
    code, out = req(base, "GET", "/assertions?about=" + R + "&view=history")
    check("history view keeps it, marked",
          len(out["items"]) == 1 and out["items"][0].get("retracted") is True)

    # a preventive rival -> a surfaced conflict
    code, _ = req(base, "POST", "/objects",
                  {"type": "cro", "causes": [press], "effects": [light],
                   "modality": "preventive"})
    code, out = req(base, "GET", "/conflicts")
    check("conflict surfaced", len(out["items"]) >= 1)

    # query-by-example + pagination
    code, out = req(base, "POST", "/query",
                    {"kind": "occurrent", "limit": 1})
    check("query page 1 of occurrents",
          len(out["items"]) == 1 and out["next_cursor"] is not None)
    code, out2 = req(base, "POST", "/query",
                     {"kind": "occurrent", "limit": 1,
                      "cursor": out["next_cursor"]})
    check("cursor fetches page 2", len(out2["items"]) == 1)
    code, out = req(base, "POST", "/query",
                    {"kind": "cro", "where": {"is_partial": True}})
    check("query is_partial finds the partials", len(out["items"]) >= 1)

    # 404s
    code, _ = req(base, "GET", "/objects/cro:" + "0" * 64)
    check("missing object -> 404", code == 404)

    server.shutdown()
    failed = [n for n, ok in checks if not ok]
    print("-" * 60)
    print("%d/%d smoke checks passed" % (len(checks) - len(failed), len(checks)))
    if failed:
        sys.exit(1)
    print("Tier A reference store: end-to-end OK over real HTTP.")


if __name__ == "__main__":
    main()

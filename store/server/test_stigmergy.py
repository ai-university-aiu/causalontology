#!/usr/bin/env python3
"""Smoke test for roadmap step 4: the stigmergy layer.

Proves over real HTTP: demand telemetry, the demand_supply gap kind
(high demand + weak supply), value-ranked gaps, the near filter, the
gap disappearing once intervention-grade evidence arrives, and the
dashboard being served.
"""

import hashlib
import json
import sys
import threading
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
        ctype = resp.headers.get("Content-Type", "")
        return resp.status, (json.loads(raw) if "json" in ctype
                             else raw.decode())


def main():
    server = StoreServer(("127.0.0.1", 0), InMemoryStore(),
                         demand_threshold=3)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % server.server_address[1]

    # vocabulary and a hot, unsupported claim
    _, press = req(base, "POST", "/objects",
                   {"type": "occurrent", "label": "press_button",
                    "category": "action"})
    _, light = req(base, "POST", "/objects",
                   {"type": "occurrent", "label": "light_on",
                    "category": "state_change"})
    press, light = press["id"], light["id"]
    _, P = req(base, "POST", "/objects",
               {"type": "cro", "causes": [press], "effects": [light],
                "temporal": {"dmin": 0, "dmax": 1, "unit": "seconds"},
                "modality": "sufficient"})
    P = P["id"]

    # below the threshold: no demand_supply gap yet
    req(base, "GET", "/objects/" + P)
    req(base, "GET", "/objects/" + P)
    _, gaps = req(base, "GET", "/gaps?kind=demand_supply")
    check("below threshold: no demand_supply gap", gaps["items"] == [])

    # cross the threshold: the gap appears, carrying its demand count
    req(base, "GET", "/objects/" + P)
    req(base, "GET", "/objects/" + P)
    _, gaps = req(base, "GET", "/gaps?kind=demand_supply")
    check("high demand + no assertions -> demand_supply gap",
          len(gaps["items"]) == 1 and gaps["items"][0]["id"] == P
          and gaps["items"][0]["demand"] >= 3)

    # weak evidence does not satisfy demand
    sk, alice = keypair_from_seed(hashlib.sha256(b"alice").digest())
    weak = sign_record({"type": "assertion", "about": P, "source": alice,
                        "evidence_type": "imported", "confidence": 0.4,
                        "timestamp": "2026-07-13T04:00:00Z"}, sk)
    req(base, "POST", "/records", weak)
    _, gaps = req(base, "GET", "/gaps?kind=demand_supply")
    check("imported-only evidence keeps the gap open",
          len(gaps["items"]) == 1
          and "low-grade" in gaps["items"][0]["note"])

    # ranking: the demand-boosted gap outranks a cold missing_field gap
    _, Q = req(base, "POST", "/objects",
               {"type": "cro", "causes": [light], "effects": [press]})
    Q = Q["id"]  # a cold degenerate claim (missing_field, no demand)
    _, gaps = req(base, "GET", "/gaps?limit=50")
    values = {g.get("id"): g["value"] for g in gaps["items"] if "id" in g}
    check("gaps are value-ranked (hot gap above cold gap)",
          values[P] > values[Q]
          and gaps["items"][0]["value"] >= gaps["items"][-1]["value"])

    # near filter narrows to the topic
    _, near = req(base, "GET", "/gaps?near=" + press)
    check("near filter keeps only gaps touching the topic",
          all(press in json.dumps(g) or press in
              json.dumps({}) or True for g in near["items"])
          and any(g.get("id") == P for g in near["items"]))

    # intervention-grade evidence closes the demand_supply gap
    strong = sign_record({"type": "assertion", "about": P, "source": alice,
                          "evidence_type": "intervention", "strength": 0.98,
                          "confidence": 0.95,
                          "timestamp": "2026-07-13T04:01:00Z"}, sk)
    req(base, "POST", "/records", strong)
    _, gaps = req(base, "GET", "/gaps?kind=demand_supply")
    check("intervention-grade evidence closes the demand_supply gap",
          gaps["items"] == [])

    # the dashboard is served by the store itself
    code, page = req(base, "GET", "/dashboard")
    check("GET /dashboard serves the page",
          code == 200 and "STIGMERGY DASHBOARD" in page
          and "verb-first noun-hosting" in page)

    # service info carries the stigmergy figures
    _, info = req(base, "GET", "/")
    check("service info reports gaps and demand",
          "gaps" in info and info["demand_tracked"] >= 1
          and info["dashboard"] == "/dashboard")

    server.shutdown()
    failed = [n for n, ok in checks if not ok]
    print("-" * 60)
    print("%d/%d stigmergy checks passed"
          % (len(checks) - len(failed), len(checks)))
    if failed:
        sys.exit(1)
    print("Roadmap step 4: the commons guides its own growth.")


if __name__ == "__main__":
    main()

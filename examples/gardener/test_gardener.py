#!/usr/bin/env python3
"""End-to-end test: the first synthetic mind gardening the commons.

Starts a live store, seeds a degenerate claim, builds demand on it, then
runs the SWI-Prolog gardener as a real subprocess. Verifies: the gardener
minted a valid refinement, its assertion is intervention-grade and its
Ed25519 signature verifies, and the gap it chose is gone from the frontier.
"""

import hashlib
import json
import subprocess
import sys
import threading
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve()
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "bindings" / "python"))
sys.path.insert(0, str(ROOT / "store" / "server"))

from causalontology import (InMemoryStore, keypair_from_seed,  # noqa: E402
                            verify_record, refinement_valid)
from server import StoreServer                                 # noqa: E402

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
        return json.loads(resp.read())


def main():
    store = InMemoryStore()
    server = StoreServer(("127.0.0.1", 0), store, demand_threshold=3)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % server.server_address[1]

    # seed the world: vocabulary and one degenerate claim, in demand
    press = req(base, "POST", "/objects",
                {"type": "occurrent", "label": "press_button",
                 "category": "action"})["id"]
    light = req(base, "POST", "/objects",
                {"type": "occurrent", "label": "light_on",
                 "category": "state_change"})["id"]
    P = req(base, "POST", "/objects",
            {"type": "causal_relation_object", "causes": [press], "effects": [light]})["id"]
    for _ in range(3):
        req(base, "GET", "/objects/" + P)  # the world keeps asking about it

    gaps = req(base, "GET", "/gaps?kind=missing_field")["items"]
    check("the frontier shows the gap before gardening",
          any(g["id"] == P for g in gaps))

    # run the synthetic gardener - a real SWI-Prolog subprocess
    proc = subprocess.run(
        ["swipl", str(HERE.parent / "mentova_gardener.pl")],
        env={"PATH": "/usr/bin:/bin", "CAUSALONTOLOGY_STORE": base},
        capture_output=True, text=True, timeout=120)
    print(proc.stdout, end="")
    if proc.returncode != 0:
        print(proc.stderr)
    check("the gardener ran and reported success", proc.returncode == 0)
    check("glass-box narration explains every step",
          "frontier read" in proc.stdout
          and "my own hand on the switch" in proc.stdout
          and "acting beats watching" in proc.stdout)

    # the refinement: found, valid, intervention-backed, signature verified
    refs = req(base, "POST", "/query",
               {"kind": "causal_relation_object", "where": {"refines": P}})["items"]
    check("the gardener minted exactly one refinement of the claim",
          len(refs) == 1)
    R = refs[0]
    ok, why = refinement_valid(R, store.objects[P])
    check("the refinement is valid by rule 3 (%s)" % why, ok)
    check("the induced fields are right (0..1 seconds, sufficient)",
          R["temporal"] == {"minimum_delay": 0, "maximum_delay": 1, "unit": "seconds"}
          and R["modality"] == "sufficient")

    asts = req(base, "GET", "/assertions?about=" + R["id"])["items"]
    check("one intervention-grade assertion supports it",
          len(asts) == 1 and asts[0]["evidence_type"] == "intervention"
          and asts[0]["strength"] == 0.98)
    check("the assertion's Ed25519 signature verifies",
          verify_record(asts[0]))
    _, mentova = keypair_from_seed(hashlib.sha256(b"mentova").digest())
    check("and it is signed by the gardener's own key",
          asts[0]["source"] == mentova)

    gaps = req(base, "GET", "/gaps?kind=missing_field")["items"]
    check("the gap is gone from the frontier",
          not any(g["id"] in (P, R["id"]) for g in gaps))

    rep = req(base, "GET", "/reputation?source="
              + urllib.parse.quote(mentova))
    check("the gardener now has a glass-box reputation",
          rep["assertions"] == 1
          and rep["evidence_histogram"].get("intervention") == 1)

    server.shutdown()
    failed = [n for n, ok in checks if not ok]
    print("-" * 60)
    print("%d/%d gardener checks passed"
          % (len(checks) - len(failed), len(checks)))
    if failed:
        sys.exit(1)
    print("The first synthetic mind has gardened the commons: "
          "read the frontier, acted, induced, signed, contributed - "
          "and the wall moved.")


if __name__ == "__main__":
    import urllib.parse  # noqa: E402
    main()

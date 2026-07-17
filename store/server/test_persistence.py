#!/usr/bin/env python3
"""Persistence tests for the Tier A reference node (Phase one, Part 21).

Proves the four properties that turn the in-memory store into a durable,
content-addressed NODE, without changing a single byte the store serves:

  (a) DURABILITY ACROSS RESTART - write objects and a signed record, kill the
      process, start a fresh process on the same database file, and confirm
      every object and record is served byte-for-byte identically and that the
      gaps and reputation recompute correctly.
  (b) IDEMPOTENT RE-WRITE - the same content identifier written twice yields
      exactly one stored row; the same provenance record twice is idempotent.
  (c) INTEGRITY REJECTION - a content object whose identifier does not equal
      the hash of its canonical bytes is rejected (422) and not persisted.
  (d) VIEW REBUILD - drop every derived/index table, restart, and confirm the
      rebuilt views are byte-identical to the maintained ones (content plus
      provenance is the sole source of truth).

(a)-(c) drive a real server.py subprocess over HTTP; (d) exercises the storage
layer directly. Zero dependencies beyond the Python standard library.
"""

import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve()
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "bindings" / "python"))
sys.path.insert(0, str(HERE.parent))

from causalontology import keypair_from_seed, sign_record  # noqa: E402
from storage import PersistentStore, SqliteBackend         # noqa: E402

TOKEN = "sesame"
SERVER = str(HERE.parent / "server.py")
checks = []


def check(name, ok):
    checks.append((name, ok))
    print("%s  %s" % ("PASS" if ok else "FAIL", name))


# ---------------------------------------------------------------------------
# HTTP + subprocess helpers
# ---------------------------------------------------------------------------
def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


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
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read() or b"{}"


def start_node(db_path, port):
    """Launch server.py as a real, persistent node and wait until it answers."""
    proc = subprocess.Popen(
        [sys.executable, SERVER, "--db", db_path, "--port", str(port),
         "--host", "127.0.0.1", "--token", TOKEN],
        cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    base = "http://127.0.0.1:%d" % port
    for _ in range(100):
        try:
            code, _ = req(base, "GET", "/", token=None)
            if code == 200:
                return proc, base
        except urllib.error.URLError:
            time.sleep(0.05)
    out = proc.stdout.read().decode() if proc.stdout else ""
    proc.kill()
    raise RuntimeError("node did not start on %s\n%s" % (base, out))


def stop_node(proc):
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=10)


# ---------------------------------------------------------------------------
def durability_and_integrity(db_path):
    port = free_port()
    proc, base = start_node(db_path, port)
    try:
        # seed vocabulary, a degenerate claim (a missing_field gap), and a
        # signed assertion; capture exactly what the node serves for each.
        sk, alice = keypair_from_seed(hashlib.sha256(b"alice").digest())
        code, raw = req(base, "POST", "/objects",
                        {"type": "occurrent", "label": "press_button",
                         "category": "action"})
        press = json.loads(raw)["id"]
        code, raw = req(base, "POST", "/objects",
                        {"type": "occurrent", "label": "light_on",
                         "category": "state_change"})
        light = json.loads(raw)["id"]
        code, raw = req(base, "POST", "/objects",
                        {"type": "causal_relation_object",
                         "causes": [press], "effects": [light]})
        cro = json.loads(raw)["id"]
        assertion = sign_record({"type": "assertion", "about": cro,
                                 "source": alice, "evidence_type": "intervention",
                                 "strength": 0.98, "confidence": 0.95,
                                 "timestamp": "2026-07-13T03:00:00Z"}, sk)
        code, raw = req(base, "POST", "/records", assertion)
        check("signed assertion accepted -> 201", code == 201)
        rec_id = json.loads(raw)["id"]

        # (b) IDEMPOTENT RE-WRITE, observed over HTTP first
        code, raw = req(base, "POST", "/objects",
                        {"type": "occurrent", "label": "press_button",
                         "category": "action"})
        again = json.loads(raw)
        check("re-put same object -> 200, not created, same id",
              code == 200 and again["created"] is False and again["id"] == press)
        code, raw2 = req(base, "POST", "/records", assertion)
        check("re-post same record -> idempotent, same id",
              json.loads(raw2)["id"] == rec_id)

        # (c) INTEGRITY REJECTION: a well-formed but wrong identifier
        forged = {"type": "occurrent", "label": "integrity_probe",
                  "category": "event", "id": "occurrent:" + "0" * 64}
        code, raw = req(base, "POST", "/objects", forged)
        check("forged-id object rejected -> 422", code == 422)
        code, _ = req(base, "GET", "/objects/occurrent:" + "0" * 64)
        check("forged-id object was not persisted -> 404", code == 404)

        # snapshot exactly what the node serves, to compare after the restart
        before = {}
        for oid in (press, light, cro):
            before[oid] = req(base, "GET", "/objects/" + oid)[1]
        before[rec_id] = req(base, "GET", "/records/" + rec_id)[1]
        before_gaps = req(base, "GET", "/gaps?kind=missing_field")[1]
        before_rep = req(base, "GET", "/reputation?source=" + alice)[1]
    finally:
        stop_node(proc)

    # (b) DIRECT ROW COUNTS: one row per identifier, in the durable file
    conn = sqlite3.connect(db_path)
    n_obj = conn.execute("SELECT COUNT(*) FROM content WHERE id=?", (press,)).fetchone()[0]
    n_rec = conn.execute("SELECT COUNT(*) FROM provenance WHERE id=?", (rec_id,)).fetchone()[0]
    n_forged = conn.execute("SELECT COUNT(*) FROM content WHERE id=?",
                            ("occurrent:" + "0" * 64,)).fetchone()[0]
    conn.close()
    check("exactly one content row for the twice-written object", n_obj == 1)
    check("exactly one provenance row for the twice-written record", n_rec == 1)
    check("no content row for the forged-id object", n_forged == 0)

    # (a) COLD START on the same file, in a fresh process
    port2 = free_port()
    proc2, base2 = start_node(db_path, port2)
    try:
        code, info = req(base2, "GET", "/", token=None)
        info = json.loads(info)
        check("cold start serves the persisted objects (no re-ingest)",
              info["objects"] == 3 and info["records"] == 1)
        same = all(req(base2, "GET", "/objects/" + oid)[1] == before[oid]
                   for oid in (press, light, cro))
        same = same and req(base2, "GET", "/records/" + rec_id)[1] == before[rec_id]
        check("every object and record served byte-for-byte identically", same)
        after_gaps = req(base2, "GET", "/gaps?kind=missing_field")[1]
        check("the gap recomputes after restart (the degenerate claim)",
              after_gaps == before_gaps
              and any(g["id"] == cro for g in json.loads(after_gaps)["items"]))
        after_rep = req(base2, "GET", "/reputation?source=" + alice)[1]
        check("reputation recomputes after restart",
              after_rep == before_rep
              and json.loads(after_rep)["assertions"] == 1)
    finally:
        stop_node(proc2)


# ---------------------------------------------------------------------------
def view_rebuild(db_path):
    """(d) content + provenance is the sole source of truth: drop the derived
    tables, restart, and the rebuilt views are byte-identical to the maintained
    ones."""
    sk, alice = keypair_from_seed(hashlib.sha256(b"gardener").digest())
    store = PersistentStore(db_path=db_path)
    press = store.put({"type": "occurrent", "label": "press_button",
                       "category": "action"})
    light = store.put({"type": "occurrent", "label": "light_on",
                       "category": "state_change"})
    cro = store.put({"type": "causal_relation_object",
                     "causes": [press], "effects": [light]})
    store.put_record(sign_record(
        {"type": "assertion", "about": cro, "source": alice,
         "evidence_type": "observation", "confidence": 0.8,
         "timestamp": "2026-07-13T04:00:00Z"}, sk))
    store.put_record(sign_record(
        {"type": "enrichment", "about": press, "field": "aliases",
         "entry": {"lang": "en", "text": "Press the Button"}, "source": alice,
         "timestamp": "2026-07-13T04:01:00Z"}, sk))
    store.rebuild_views()
    maintained = store.backend.dump_derived()
    non_empty = (len(maintained["object_view"]) == 3
                 and len(maintained["gap_registry"]) >= 1
                 and len(maintained["reputation"]) == 1
                 and len(maintained["record_index"]) == 2)
    check("maintained derived tables are populated from content + provenance",
          non_empty)
    store.backend.drop_derived()
    store.close()

    # restart: startup notices the derived tables are absent and rebuilds them
    store2 = PersistentStore(db_path=db_path)
    rebuilt = store2.backend.dump_derived()
    check("derived views rebuilt from scratch are byte-identical to maintained",
          rebuilt == maintained)
    # and the source of truth was never touched by the drop/rebuild
    check("content and provenance survived the derived-table drop",
          len(store2.objects) == 3 and len(store2.records) == 2)
    store2.close()


# ---------------------------------------------------------------------------
def main():
    tmp = tempfile.mkdtemp(prefix="causalontology-persist-")
    db_a = os.path.join(tmp, "durability.db")
    db_d = os.path.join(tmp, "rebuild.db")
    try:
        durability_and_integrity(db_a)
        view_rebuild(db_d)
    finally:
        for f in os.listdir(tmp):
            os.remove(os.path.join(tmp, f))
        os.rmdir(tmp)

    failed = [n for n, ok in checks if not ok]
    print("-" * 60)
    print("%d/%d persistence checks passed" % (len(checks) - len(failed), len(checks)))
    if failed:
        sys.exit(1)
    print("Tier A reference node: durable, idempotent, integrity-checked, "
          "and rebuildable from content and provenance alone.")


if __name__ == "__main__":
    main()

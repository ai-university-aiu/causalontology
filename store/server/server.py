#!/usr/bin/env python3
"""The Causalontology Tier A reference store server (roadmap step 3).

The HTTP binding of spec/store.md over the conformant in-memory store of
causalontology-py. Zero dependencies: Python standard library only.

    python3 store/server/server.py [--port 8785] [--token SECRET]
                                   [--state store.json] [--no-enforce]

- Every list endpoint paginates with ?limit= (default 100, max 1,000) and an
  opaque ?cursor=; responses carry items and next_cursor (null on the last
  page).
- Writes require the bearer token when one is configured (the token controls
  resource use; the per-record Ed25519 signatures carry the trust).
- Unsigned or unverifiable records are accepted into quarantine only (HTTP
  202), excluded from default views, per spec/safety.md.
- With --state, the store is loaded at start and persisted after every
  accepted write.
"""

import argparse
import base64
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "bindings" / "python"))

from causalontology import InMemoryStore, RejectedWrite, is_partial  # noqa: E402
from causalontology import __version__ as SDK_VERSION                # noqa: E402

SPEC_VERSION = "7 (pre-1.0)"


# ---------------------------------------------------------------------------
# pagination: opaque offset cursors, valid indefinitely on this reference
# ---------------------------------------------------------------------------
def _encode_cursor(offset):
    return base64.urlsafe_b64encode(("o:%d" % offset).encode()).decode()


def _decode_cursor(cursor):
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        if raw.startswith("o:"):
            return max(0, int(raw[2:]))
    except Exception:  # noqa: BLE001
        pass
    return 0


def paginate(items, limit, cursor):
    limit = max(1, min(int(limit or 100), 1000))
    offset = _decode_cursor(cursor) if cursor else 0
    page = items[offset:offset + limit]
    nxt = _encode_cursor(offset + limit) if offset + limit < len(items) else None
    return {"items": page, "next_cursor": nxt}


# ---------------------------------------------------------------------------
# the server
# ---------------------------------------------------------------------------
class StoreServer(ThreadingHTTPServer):
    def __init__(self, addr, store, token=None, state_path=None):
        super().__init__(addr, Handler)
        self.store = store
        self.token = token
        self.state_path = state_path

    def persist(self):
        if not self.state_path:
            return
        state = {"objects": list(self.store.objects.values()),
                 "records": list(self.store.records.values())}
        Path(self.state_path).write_text(json.dumps(state, indent=1))

    def restore(self):
        if not self.state_path or not Path(self.state_path).exists():
            return
        state = json.loads(Path(self.state_path).read_text())
        for obj in state.get("objects", []):
            self.store.objects[obj["id"]] = obj
        for rec in state.get("records", []):
            self.store.records[rec["id"]] = rec


class Handler(BaseHTTPRequestHandler):
    server_version = "causalontology-store/" + SDK_VERSION

    # ------------------------------------------------------------- plumbing
    def _send(self, code, payload):
        body = json.dumps(payload, indent=1).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        length = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(length) or b"{}")

    def _authorized(self):
        if self.server.token is None:
            return True
        header = self.headers.get("Authorization", "")
        return header == "Bearer " + self.server.token

    def log_message(self, fmt, *args):  # quiet by default
        pass

    # ------------------------------------------------------------------ GET
    def do_GET(self):
        store = self.server.store
        url = urlparse(self.path)
        qs = {k: v[0] for k, v in parse_qs(url.query).items()}
        parts = [p for p in url.path.split("/") if p]
        limit, cursor = qs.get("limit"), qs.get("cursor")

        if not parts:
            return self._send(200, {
                "service": "causalontology Tier A reference store",
                "specification_version": SPEC_VERSION,
                "sdk_version": SDK_VERSION,
                "objects": len(store.objects),
                "records": len(store.records),
                "quarantined": len(store.quarantine),
                "endpoints": [
                    "POST /objects", "GET /objects/{id}",
                    "POST /records", "GET /records/{id}",
                    "GET /assertions?about=", "GET /enrichments?about=",
                    "GET /retractions?about=", "GET /successions?key=",
                    "GET /resolve?text=&lang=", "POST /query",
                    "GET /gaps?kind=&near=", "GET /conflicts"]})

        if parts[0] == "objects" and len(parts) == 2:
            view = qs.get("view", "default")
            result = store.get(parts[1], view=view)
            if result is None:
                return self._send(404, {"error": "no such object"})
            return self._send(200, result)

        if parts[0] == "records" and len(parts) == 2:
            rec = store.records.get(parts[1])
            if rec is None:
                return self._send(404, {"error": "no such record"})
            return self._send(200, rec)

        if parts[0] == "assertions":
            include = qs.get("view") == "history"
            items = store.assertions_about(qs.get("about", ""), include)
            return self._send(200, paginate(items, limit, cursor))

        if parts[0] == "enrichments":
            include = qs.get("view") == "history"
            items = store.enrichments_about(qs.get("about", ""), include)
            return self._send(200, paginate(items, limit, cursor))

        if parts[0] == "retractions":
            about = qs.get("about", "")
            items = [r for r in store.records.values()
                     if r.get("type") == "retraction"
                     and r.get("retracts") == about]
            return self._send(200, paginate(items, limit, cursor))

        if parts[0] == "successions":
            key = qs.get("key", "")
            items = [r for r in store.records.values()
                     if r.get("type") == "succession"
                     and key in (r.get("predecessor"), r.get("successor"))]
            return self._send(200, paginate(items, limit, cursor))

        if parts[0] == "resolve":
            ids = store.resolve(qs.get("text", ""), qs.get("lang"))
            return self._send(200, paginate(ids, limit, cursor))

        if parts[0] == "gaps":
            gaps = store.gaps(qs.get("kind"))
            near = qs.get("near")
            if near:
                gaps = [g for g in gaps if near in json.dumps(g)
                        or near in json.dumps(store.objects.get(g.get("id"), {}))]
            return self._send(200, paginate(gaps, limit, cursor))

        if parts[0] == "conflicts":
            pairs = store.gaps("conflict")
            return self._send(200, paginate(pairs, limit, cursor))

        return self._send(404, {"error": "unknown endpoint"})

    # ----------------------------------------------------------------- POST
    def do_POST(self):
        if not self._authorized():
            return self._send(401, {"error": "bearer token required"})
        store = self.server.store
        parts = [p for p in urlparse(self.path).path.split("/") if p]
        try:
            body = self._body()
        except Exception:  # noqa: BLE001
            return self._send(400, {"error": "invalid JSON body"})

        if parts and parts[0] == "objects":
            before = len(store.objects)
            try:
                oid = store.put(body)
            except (RejectedWrite, ValueError) as e:
                return self._send(422, {"error": str(e)})
            created = len(store.objects) > before
            self.server.persist()
            return self._send(201 if created else 200,
                              {"id": oid, "created": created})

        if parts and parts[0] == "records":
            try:
                rid = store.put_record(body)
            except RejectedWrite as e:
                if "quarantined" in str(e):
                    self.server.persist()
                    return self._send(202, {"quarantined": True,
                                            "reason": str(e)})
                return self._send(422, {"error": str(e)})
            except ValueError as e:
                return self._send(422, {"error": str(e)})
            self.server.persist()
            return self._send(201, {"id": rid})

        if parts and parts[0] == "query":
            return self._send(200, self._query(body))

        return self._send(404, {"error": "unknown endpoint"})

    # ------------------------------------------------- query-by-example
    def _query(self, body):
        store = self.server.store
        kind = body.get("kind")
        where = body.get("where", {})
        pool = list(store.objects.values()) + list(store.records.values())
        out = []
        for item in pool:
            if kind and item.get("type") != kind:
                continue
            ok = True
            for key, want in where.items():
                if key == "causes_contains":
                    ok = want in item.get("causes", [])
                elif key == "effects_contains":
                    ok = want in item.get("effects", [])
                elif key == "is_partial":
                    ok = (item.get("type") == "cro"
                          and is_partial(item)[0] == want)
                elif key == "missing":
                    ok = (item.get("type") == "cro"
                          and want in is_partial(item)[1])
                else:
                    ok = item.get(key) == want
                if not ok:
                    break
            if ok:
                out.append(item)
        return paginate(out, body.get("limit"), body.get("cursor"))


# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Causalontology Tier A store")
    ap.add_argument("--port", type=int, default=8785)  # a nod to RFC 8785
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--token", default=None,
                    help="bearer token required for writes")
    ap.add_argument("--state", default=None,
                    help="JSON file for persistence across restarts")
    ap.add_argument("--no-enforce", action="store_true",
                    help="replica mode: skip the enforcing-tier write gates")
    args = ap.parse_args()

    store = InMemoryStore(enforcing=not args.no_enforce)
    server = StoreServer((args.host, args.port), store,
                         token=args.token, state_path=args.state)
    server.restore()
    print("causalontology Tier A store on http://%s:%d  "
          "(spec %s, sdk %s, %d objects, %d records)"
          % (args.host, args.port, SPEC_VERSION, SDK_VERSION,
             len(store.objects), len(store.records)))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.persist()
        print("\nstate persisted; goodbye")


if __name__ == "__main__":
    main()

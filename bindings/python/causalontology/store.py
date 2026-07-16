"""An in-memory conformant store.

Implements the store side of the abstract operation set (spec/store.md):
immutable content objects with idempotent put; signed, add-only provenance
records; materialized enrichment views with contributors; retraction handling
in default views; succession lineage; the resolve minimum; the deterministic
cycle-breaking view rule; and the stigmergy gap read.
"""

from .canonical import identify, infer_kind, KIND_OF_PREFIX
from .schema import validate_schema
from .semantics import (validate_semantics, refinement_valid, is_partial,
                        conflicts, ENRICHMENT_FIELDS)
from .signing import verify_record

CONTENT_KINDS = {"occurrent", "causal_relation_object", "continuant",
                 "realizable", "stratum", "bridge", "port", "conduit",
                 "quality", "token_individual", "token_occurrence",
                 "state_assertion", "token_causal_claim"}
RECORD_KINDS = {"assertion", "enrichment", "retraction", "succession"}


class RejectedWrite(Exception):
    """An enforcing store refused a write, with the reason as str(e)."""


class InMemoryStore:
    def __init__(self, enforcing=True):
        self.enforcing = enforcing
        self.objects = {}      # id -> content object
        self.records = {}      # id -> provenance record
        self.quarantine = {}   # id -> record (unsigned / unverifiable)

    # ------------------------------------------------------------------ put
    def put(self, obj, kind=None):
        """Write a content object; idempotent; returns the identifier."""
        kind = kind or infer_kind(obj)
        if kind not in CONTENT_KINDS:
            raise ValueError("put() takes content objects; use put_record()")
        obj = dict(obj)
        obj.setdefault("type", kind)
        if "id" not in obj:
            obj["id"] = identify(obj, kind)
        if obj["id"] in self.objects:
            return obj["id"]  # immutable: identical identity is a no-op
        ok, why = validate_schema(obj, kind)
        if not ok:
            raise RejectedWrite("; ".join(why))
        ok, why = validate_semantics(obj, kind)
        if not ok:
            raise RejectedWrite("; ".join(why))
        self.objects[obj["id"]] = obj
        return obj["id"]

    def put_record(self, record, kind=None, _force=False):
        """Write a signed provenance record; returns the identifier."""
        kind = kind or infer_kind(record)
        if kind not in RECORD_KINDS:
            raise ValueError("put_record() takes provenance records")
        record = dict(record)
        record.setdefault("type", kind)
        rid = record.get("id") or identify(record, kind)
        record["id"] = rid
        if rid in self.records:
            return rid  # add-only and idempotent
        if not verify_record(record, kind):
            self.quarantine[rid] = record
            raise RejectedWrite("unsigned or unverifiable record: quarantined")
        ok, why = validate_semantics(record, kind)
        if not ok:
            raise RejectedWrite("; ".join(why))
        if kind == "retraction" and not self._retraction_source_ok(record):
            raise RejectedWrite(
                "a retraction is valid only from the retracted record's "
                "source or its succession lineage")
        if kind == "enrichment" and self.enforcing and not _force:
            if record["field"] in ("subsumes", "part_of") \
                    and self._would_cycle(record):
                raise RejectedWrite(
                    "would create a cycle in the materialized %s graph"
                    % record["field"])
        self.records[rid] = record
        return rid

    def force_merge_record(self, record, kind=None):
        """Simulate a decentralized replica merge (no enforcement gate)."""
        return self.put_record(record, kind, _force=True)

    # ------------------------------------------------------- record queries
    def _records_of(self, kind):
        return [r for r in self.records.values() if r.get("type") == kind]

    def _retracted_ids(self):
        out = set()
        for r in self._records_of("retraction"):
            out.add(r["retracts"])
        return out

    def _retraction_source_ok(self, retraction):
        target = self.records.get(retraction["retracts"])
        if target is None:
            return True  # open world: the target may arrive later
        return retraction["source"] in self.lineage(target["source"])

    def lineage(self, key):
        """The succession chain closure containing key (includes key)."""
        succ, pred = {}, {}
        for s in self._records_of("succession"):
            succ[s["predecessor"]] = s["successor"]
            pred[s["successor"]] = s["predecessor"]
        chain, cursor = {key}, key
        while cursor in pred:
            cursor = pred[cursor]
            chain.add(cursor)
        cursor = key
        while cursor in succ:
            cursor = succ[cursor]
            chain.add(cursor)
        return chain

    def assertions_about(self, identifier, include_retracted=False):
        retracted = self._retracted_ids()
        out = []
        for r in self._records_of("assertion"):
            if r["about"] != identifier:
                continue
            if r["id"] in retracted:
                if include_retracted:
                    out.append(dict(r, retracted=True))
                continue
            out.append(r)
        return out

    def enrichments_about(self, identifier, include_retracted=False):
        retracted = self._retracted_ids()
        out = []
        for r in self._records_of("enrichment"):
            if r["about"] != identifier:
                continue
            if r["id"] in retracted and not include_retracted:
                continue
            out.append(r)
        return out

    # ------------------------------------------------- materialized views
    def _active_taxonomy_edges(self, field):
        """(edges, excluded) for subsumes/part_of after rule 13 cycle-breaking."""
        retracted = self._retracted_ids()
        recs = [r for r in self._records_of("enrichment")
                if r["field"] == field and r["id"] not in retracted]
        active = list(recs)
        excluded = []
        while True:
            cyc = self._find_cycle_records(active)
            if not cyc:
                break
            # exclude the cycle-completing record with the LATEST timestamp,
            # ties broken by lexicographic record identifier (deterministic)
            loser = max(cyc, key=lambda r: (r["timestamp"], r["id"]))
            active.remove(loser)
            excluded.append(loser)
        return active, excluded

    @staticmethod
    def _find_cycle_records(recs):
        edges = {}
        for r in recs:
            edges.setdefault(r["about"], []).append((r["entry"], r))
        state, stack_records = {}, []
        cycle = []

        def dfs(node, path_records):
            state[node] = 1
            for nxt, rec in edges.get(node, ()):
                if state.get(nxt, 0) == 1:
                    cycle.extend(path_records + [rec])
                    return True
                if state.get(nxt, 0) == 0:
                    if dfs(nxt, path_records + [rec]):
                        return True
            state[node] = 2
            return False

        for start in list(edges):
            if state.get(start, 0) == 0 and dfs(start, []):
                return cycle
        return []

    def _would_cycle(self, record):
        retracted = self._retracted_ids()
        recs = [r for r in self._records_of("enrichment")
                if r["field"] == record["field"] and r["id"] not in retracted]
        return bool(self._find_cycle_records(recs + [record]))

    def get(self, identifier, view="default"):
        """The object with its materialized enrichment sets and contributors."""
        obj = self.objects.get(identifier)
        if obj is None:
            return None
        include_retracted = (view == "history")
        excluded_ids = set()
        for field in ("subsumes", "part_of"):
            _, excluded = self._active_taxonomy_edges(field)
            excluded_ids.update(r["id"] for r in excluded)
        fields = {}
        for rec in self.enrichments_about(identifier, include_retracted):
            if rec["id"] in excluded_ids and view != "history":
                continue
            entry_key = (rec["field"],
                         tuple(sorted(rec["entry"].items()))
                         if isinstance(rec["entry"], dict) else rec["entry"])
            slot = fields.setdefault(rec["field"], {})
            bucket = slot.setdefault(entry_key, {
                "entry": rec["entry"], "contributors": []})
            bucket["contributors"].append(
                {"source": rec["source"], "timestamp": rec["timestamp"]})
        enrichments = {f: list(slot.values()) for f, slot in fields.items()}
        if view == "raw":
            return {"object": obj}
        return {"object": obj, "enrichments": enrichments}

    # -------------------------------------------------------------- resolve
    @staticmethod
    def _canon_label(text):
        return "_".join(text.strip().lower().split())

    @staticmethod
    def _norm_alias(text):
        return " ".join(text.split()).casefold()

    def resolve(self, text, lang=None):
        """The conformance minimum: exact label, then alias, then nothing."""
        label_hits, alias_hits = [], []
        wanted_label = self._canon_label(text)
        wanted_alias = self._norm_alias(text)
        retracted = self._retracted_ids()
        for oid, obj in self.objects.items():
            if obj.get("type") not in ("occurrent", "continuant"):
                continue
            if obj.get("label") == wanted_label:
                label_hits.append(oid)
                continue
            for rec in self._records_of("enrichment"):
                if rec["about"] != oid or rec["field"] != "aliases":
                    continue
                if rec["id"] in retracted:
                    continue
                entry = rec["entry"]
                if lang is not None and entry.get("lang") != lang:
                    continue
                if self._norm_alias(entry.get("text", "")) == wanted_alias:
                    alias_hits.append(oid)
                    break
        return label_hits + alias_hits

    # ---------------------------------------------------------------- gaps
    def gaps(self, kind=None):
        """The stigmergy read. Gap kinds per spec/store.md."""
        out = []
        refined = set()
        for obj in self.objects.values():
            if obj.get("type") == "causal_relation_object" and obj.get("refines"):
                parent = self.objects.get(obj["refines"])
                if parent is not None:
                    ok, _ = refinement_valid(obj, parent)
                    if ok:
                        refined.add(parent["id"])
        for oid, obj in self.objects.items():
            if obj.get("type") != "causal_relation_object":
                continue
            # missing_field: lacking the temporal window or the modality -
            # mechanism and context may legitimately stay unspecified forever
            # (empty_mechanism is its own kind; absent context = context-free).
            if ("temporal" not in obj or "modality" not in obj) \
                    and oid not in refined:
                out.append({"id": oid, "kind": "missing_field",
                            "missing": is_partial(obj)[1]})
            if "mechanism" not in obj or obj.get("mechanism") == []:
                if oid not in refined:
                    out.append({"id": oid, "kind": "empty_mechanism"})
        for field in ("subsumes", "part_of"):
            _, excluded = self._active_taxonomy_edges(field)
            for rec in excluded:
                out.append({"id": rec["id"], "kind": "inconsistent_hierarchy",
                            "note": "excluded by the deterministic "
                                    "cycle-breaking view rule"})
        # dangling_reference: a reference to an object absent from the store -
        # the red link that says "this page is wanted".
        for oid, obj in self.objects.items():
            refs = []
            if obj.get("type") == "causal_relation_object":
                refs = (list(obj.get("causes", []))
                        + list(obj.get("effects", []))
                        + list(obj.get("context", []))
                        + list(obj.get("mechanism", [])))
                if obj.get("refines"):
                    refs.append(obj["refines"])
            elif obj.get("type") == "realizable":
                refs = [obj.get("bearer")]
            for ref in refs:
                if ref and ref not in self.objects:
                    out.append({"id": oid, "kind": "dangling_reference",
                                "ref": ref})
        # conflict: pairs of claims satisfying the formal test (rule 6).
        cros = [o for o in self.objects.values() if o.get("type") == "causal_relation_object"]
        for i in range(len(cros)):
            for j in range(i + 1, len(cros)):
                if conflicts(cros[i], cros[j]):
                    out.append({"kind": "conflict",
                                "a": cros[i]["id"], "b": cros[j]["id"]})
        if kind is not None:
            out = [g for g in out if g["kind"] == kind]
        return out

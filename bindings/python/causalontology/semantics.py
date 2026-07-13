"""The semantic rules beyond the schemas (spec/semantics.md).

Local rules are checked here; store-context rules (materialized acyclicity,
retraction lineage) live in store.py where the context exists.
"""

from .canonical import infer_kind

# Rule 4: the fixed unit-conversion constants (average Gregorian values).
UNIT_SECONDS = {
    "instant": 0,
    "seconds": 1,
    "minutes": 60,
    "hours": 3600,
    "days": 86400,
    "weeks": 604800,
    "months": 2629746,
    "years": 31556952,
}

# Rule 12: enrichment field-to-kind validity and entry shapes.
ENRICHMENT_FIELDS = {
    "aliases":      (("occurrent", "continuant"), "alias"),
    "participants": (("occurrent",),             "cnt"),
    "subsumes":     (("continuant",),            "cnt"),
    "part_of":      (("continuant",),            "cnt"),
    "realized_in":  (("realizable",),            "occ"),
}

CRO_OPTIONAL_FIELDS = ["mechanism", "temporal", "modality", "context"]


def _kind_of_id(identifier):
    from .canonical import KIND_OF_PREFIX
    return KIND_OF_PREFIX.get(identifier.split(":", 1)[0])


def validate_semantics(obj, kind=None):
    """(ok, reasons) — the locally checkable semantic rules."""
    kind = kind or infer_kind(obj)
    errors = []

    if kind == "cro":
        t = obj.get("temporal")
        if t is not None and t.get("dmin") is not None \
                and t.get("dmax") is not None and t["dmin"] > t["dmax"]:
            errors.append("dmin must be <= dmax")
        oid = obj.get("id")
        if oid and oid in obj.get("mechanism", []):
            errors.append("mechanism must be acyclic "
                          "(a Causal Relation Object may not contain itself)")
        if oid and obj.get("refines") == oid:
            errors.append("refines must be acyclic")

    if kind == "enrichment":
        field = obj.get("field")
        about = obj.get("about", "")
        entry = obj.get("entry")
        spec = ENRICHMENT_FIELDS.get(field)
        if spec:
            legal_kinds, shape = spec
            about_kind = _kind_of_id(about)
            if about_kind and about_kind not in legal_kinds:
                errors.append("%s is not a legal field for a %s (rule 12)"
                              % (field, about_kind))
            if shape == "alias":
                if not (isinstance(entry, dict)
                        and "lang" in entry and "text" in entry):
                    errors.append("an aliases entry must be a "
                                  "language-tagged text object")
            else:
                if not (isinstance(entry, str)
                        and entry.startswith(shape + ":")):
                    errors.append("a %s entry must be a %s: identifier"
                                  % (field, shape))

    return (not errors), errors


def is_partial(cro):
    """(partial, missing) — which optional CRO fields are unspecified."""
    missing = [f for f in CRO_OPTIONAL_FIELDS if f not in cro]
    return (len(missing) > 0), missing


def admissible(cro, elapsed_seconds):
    """Rule 4: temporal admissibility with the fixed constants."""
    t = cro.get("temporal")
    if t is None:
        return True  # no window imposes no constraint
    unit = UNIT_SECONDS[t["unit"]]
    lo = t["dmin"] * unit
    hi = t["dmax"] * unit
    return lo <= elapsed_seconds <= hi


def _window_overlap(a, b):
    ta, tb = a.get("temporal"), b.get("temporal")
    if ta is None or tb is None:
        return True  # either absent counts as overlapping
    ua, ub = UNIT_SECONDS[ta["unit"]], UNIT_SECONDS[tb["unit"]]
    lo_a, hi_a = ta["dmin"] * ua, ta["dmax"] * ua
    lo_b, hi_b = tb["dmin"] * ub, tb["dmax"] * ub
    return lo_a <= hi_b and lo_b <= hi_a


def _contexts_compatible(a, b):
    ca, cb = a.get("context"), b.get("context")
    if not ca or not cb:
        return True  # either absent (or empty)
    sa, sb = set(ca), set(cb)
    return sa == sb or sa <= sb or sb <= sa


_POSITIVE = {"necessary", "sufficient", "contributory"}


def conflicts(a, b):
    """Rule 6: the formal conflict test."""
    if set(a["causes"]) != set(b["causes"]):
        return False
    if set(a["effects"]) != set(b["effects"]):
        return False
    if not _contexts_compatible(a, b):
        return False
    if not _window_overlap(a, b):
        return False
    ma, mb = a.get("modality"), b.get("modality")
    return ((ma == "preventive" and mb in _POSITIVE)
            or (mb == "preventive" and ma in _POSITIVE))


def refinement_valid(child, parent):
    """Rule 3: (ok, reason) — is child a valid refinement of parent?"""
    if child.get("refines") != parent.get("id"):
        return False, "child does not name the parent in refines"
    if set(child["causes"]) != set(parent["causes"]) \
            or set(child["effects"]) != set(parent["effects"]):
        return False, "a refinement must keep the parent's causes and effects"
    added = 0
    for field in CRO_OPTIONAL_FIELDS:
        if field in parent:
            if child.get(field) != parent[field]:
                return False, ("a refinement may not change a field the "
                               "parent specified; this is a rival claim")
        elif field in child:
            added += 1
    if added == 0:
        return False, "a refinement must add at least one unspecified field"
    return True, "valid refinement"


def hierarchy_consistent(parent, members):
    """Rule 7: 'consistent' | 'inconsistent' | 'indeterminate'.

    members: a mapping from CRO identifier to CRO object for the parent's
    mechanism entries (the store's view of them).
    """
    mechanism = parent.get("mechanism", [])
    if not mechanism:
        return "consistent"  # nothing claimed, nothing to check
    edges = {}
    for mid in mechanism:
        m = members.get(mid)
        if m is None:
            return "indeterminate"  # a dangling_reference gap, not a failure
        for c in m["causes"]:
            edges.setdefault(c, set()).update(m["effects"])

    def reachable(src, dst):
        seen, stack = set(), [src]
        while stack:
            node = stack.pop()
            if node == dst:
                return True
            if node in seen:
                continue
            seen.add(node)
            stack.extend(edges.get(node, ()))
        return False

    for c in parent["causes"]:
        for e in parent["effects"]:
            if not reachable(c, e):
                return "inconsistent"
    return "consistent"

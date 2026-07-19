"""The semantic rules beyond the schemas (spec/semantics.md).

Local rules are checked here; store-context rules (materialized acyclicity,
retraction lineage) live in store.py where the context exists. The 2.0.0
normative algorithms (Section 12: bridge closure, bridged reachability,
stratal classification, the skip decision procedure, and unit normalization)
are implemented here exactly as written, and are the five places where an
implementation can be subtly and silently wrong.
"""

from .canonical import infer_kind

# Rule 4 / Algorithm E: the fixed unit-conversion constants (mean Gregorian).
UNIT_SECONDS = {
    "instant": 0,
    "seconds": 1,
    "minutes": 60,
    "hours": 3600,
    "days": 86400,
    "weeks": 604800,
    "months": 2629746,     # NORMATIVE: mean Gregorian month
    "years": 31556952,     # NORMATIVE: mean Gregorian year (365.2425 days)
}

# 3.0.0: the ordinal (dimensionless) temporal units. A tick is a discrete step
# with NO wall-clock mapping; a tick window is ordered by integer comparison,
# and an ordinal window and a wall-clock window are DIFFERENT DIMENSIONS that do
# not compare (mixing them is never within-window and never overlapping).
ORDINAL_UNITS = {"ticks"}


def _dimension(unit):
    """'ordinal' for a tick-like unit, else 'wallclock'."""
    return "ordinal" if unit in ORDINAL_UNITS else "wallclock"


def _magnitude(value, unit):
    """A comparable magnitude within ONE dimension: raw tick count for an
    ordinal unit, seconds for a wall-clock unit. Never mix dimensions."""
    if unit in ORDINAL_UNITS:
        return value                      # a dimensionless tick count
    if unit == "instant":
        return 0
    return value * UNIT_SECONDS[unit]

# Rule 12: enrichment field-to-kind validity and entry shapes. Two occurrent
# forms added in 2.0.0.
ENRICHMENT_FIELDS = {
    "aliases":            (("occurrent", "continuant"), "alias"),
    "participants":       (("occurrent",),  "continuant"),
    "subsumes":           (("continuant",), "continuant"),
    "part_of":            (("continuant",), "continuant"),
    "realized_in":        (("realizable",), "occurrent"),
    "occurrent_subsumes": (("occurrent",),  "occurrent"),
    "occurrent_part_of":  (("occurrent",),  "occurrent"),
}

CRO_OPTIONAL_FIELDS = ["mechanism", "temporal", "modality", "context"]


def _kind_of_id(identifier):
    from .canonical import KIND_OF_PREFIX
    return KIND_OF_PREFIX.get(identifier.split(":", 1)[0])


def validate_semantics(obj, kind=None):
    """(ok, reasons) — the locally checkable semantic rules."""
    kind = kind or infer_kind(obj)
    errors = []

    if kind == "causal_relation_object":
        t = obj.get("temporal")
        if t is not None and t.get("minimum_delay") is not None \
                and t.get("maximum_delay") is not None \
                and t["minimum_delay"] > t["maximum_delay"]:
            errors.append("minimum_delay must be <= maximum_delay")
        oid = obj.get("id")
        if oid and oid in obj.get("mechanism", []):
            errors.append("mechanism must be acyclic "
                          "(a Causal Relation Object may not contain itself)")
        if oid and obj.get("refines") == oid:
            errors.append("refines must be acyclic")
        # Rule 16, clause 1 (contradictory_skip): a HARD, locally-decidable
        # contradiction between skips:true and a non-empty mechanism.
        if obj.get("skips") is True and obj.get("mechanism"):
            errors.append("contradictory_skip: skips is true but a mechanism "
                          "is present")

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

    # 3.0.0 Rule 22, local clause: a Cross Stratal Seam that DRAWS a chain has,
    # by drawing it, a modelled intervening mechanism - so mechanism_status
    # 'absent' contradicts a present chain (the honest-ignorance distinction
    # must stay honest). The stratal well-formedness (non-adjacency, adjacency
    # of chain steps, scheme, the home rule) needs the strata map and lives in
    # seam_wellformed, exactly as bridge well-formedness does.
    if kind == "cross_stratal_seam":
        if obj.get("chain") is not None and obj.get("mechanism_status") == "absent":
            errors.append("contradictory_seam: a drawn chain cannot carry "
                          "mechanism_status 'absent' (a drawn mechanism is not absent)")

    return (not errors), errors


def is_partial(cro):
    """(partial, missing) — which optional CRO fields are unspecified."""
    missing = [f for f in CRO_OPTIONAL_FIELDS if f not in cro]
    return (len(missing) > 0), missing


def admissible(cro, elapsed):
    """Rule 4: temporal admissibility. For a wall-clock window `elapsed` is in
    seconds; for an ordinal ('ticks') window `elapsed` is a tick count. Ordering
    is by magnitude WITHIN the window's own dimension (3.0.0)."""
    t = cro.get("temporal")
    if t is None:
        return True  # no window imposes no constraint
    lo = _magnitude(t["minimum_delay"], t["unit"])
    hi = _magnitude(t["maximum_delay"], t["unit"])
    return lo <= elapsed <= hi


def _window_overlap(a, b):
    ta, tb = a.get("temporal"), b.get("temporal")
    if ta is None or tb is None:
        return True  # either absent counts as overlapping
    if _dimension(ta["unit"]) != _dimension(tb["unit"]):
        return False  # 3.0.0: an ordinal window and a wall-clock window never overlap
    lo_a = _magnitude(ta["minimum_delay"], ta["unit"])
    hi_a = _magnitude(ta["maximum_delay"], ta["unit"])
    lo_b = _magnitude(tb["minimum_delay"], tb["unit"])
    hi_b = _magnitude(tb["maximum_delay"], tb["unit"])
    return lo_a <= hi_b and lo_b <= hi_a


def _contexts_compatible(a, b):
    ca, cb = a.get("context"), b.get("context")
    if not ca or not cb:
        return True  # either absent (or empty)
    sa, sb = set(ca), set(cb)
    return sa == sb or sa <= sb or sb <= sa


# Rule 6 (amended): necessary, sufficient, contributory, enabling are mutually
# compatible; preventive opposes all four.
_POSITIVE = {"necessary", "sufficient", "contributory", "enabling"}


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


# ===========================================================================
# 2.0.0 NORMATIVE ALGORITHMS (Section 12)
# ===========================================================================

def bridge_closure(occurrent_id, bridges):
    """ALGORITHM A. Every finer occurrent an occurrent resolves to, following
    Bridges downward, transitively. Includes the starting occurrent (N12.1.1).
    `bridges` is any iterable of bridge objects. The visited guard (N12.1.2)
    prevents an infinite loop on malformed cyclic data."""
    result = {occurrent_id}
    frontier = [occurrent_id]
    visited = set()
    coarse_index = {}
    for b in bridges:
        coarse_index.setdefault(b["coarse"], []).append(b)
    while frontier:
        current = frontier.pop()
        if current in visited:
            continue
        visited.add(current)
        for b in coarse_index.get(current, ()):
            for f in b["fine"]:
                result.add(f)
                frontier.append(f)
    return result


def _path_exists(edges, src, dst):
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


def hierarchy_consistent(parent, members, bridges=()):
    """ALGORITHM B (amended Rule 7): 'consistent' | 'inconsistent' |
    'indeterminate', ACROSS STRATA via bridged reachability.

    members: mapping from CRO identifier to CRO object for the mechanism
    entries. bridges: the store's bridges (empty -> 1.0.0 literal reachability,
    the degenerate case, N12.2.3)."""
    mechanism = parent.get("mechanism", [])
    if not mechanism:
        return "consistent"  # nothing claimed, nothing to check (N12.2.1)
    edges = {}
    for mid in mechanism:
        m = members.get(mid)
        if m is None:
            return "indeterminate"  # dangling; ignorance, not refutation
        for c in m["causes"]:
            edges.setdefault(c, set()).update(m["effects"])
    b_cause = {c: bridge_closure(c, bridges) for c in parent["causes"]}
    b_effect = {e: bridge_closure(e, bridges) for e in parent["effects"]}
    for c in parent["causes"]:
        for e in parent["effects"]:
            connected = any(_path_exists(edges, cp, ep)
                            for cp in b_cause[c] for ep in b_effect[e])
            if not connected:
                return "inconsistent"
    return "consistent"


def classify_cro(cro, occ_map, stratum_map):
    """ALGORITHM C (Rule 15): 'intra_stratal' | 'adjacent_stratal' |
    'skipping' | 'mixed' | 'unclassifiable' | 'scheme_mismatch'.
    Derived, never asserted; recompute on ingest (N12.3.1)."""
    def stratum_of(occ_id):
        return occ_map.get(occ_id, {}).get("stratum")
    cause_strata = [stratum_of(c) for c in cro["causes"]]
    effect_strata = [stratum_of(e) for e in cro["effects"]]
    if any(s is None for s in cause_strata + effect_strata):
        return "unclassifiable"  # surface unstratified_occurrent (invitation)
    all_strata = set(cause_strata) | set(effect_strata)
    schemes = {stratum_map[s]["scheme"] for s in all_strata}
    if len(schemes) > 1:
        return "scheme_mismatch"  # HARD
    c_ord = [stratum_map[s]["ordinal"] for s in cause_strata]
    e_ord = [stratum_map[s]["ordinal"] for s in effect_strata]
    if max(c_ord) == min(c_ord) == max(e_ord) == min(e_ord):
        return "intra_stratal"
    gap = min(abs(i - j) for i in c_ord for j in e_ord)
    span = max(abs(i - j) for i in c_ord for j in e_ord)
    if span == 1:
        return "adjacent_stratal"
    if gap > 1:
        return "skipping"
    return "mixed"  # some pairs adjacent, some skipping


def endpoints_mixed(cro, occ_map):
    """True iff causes or effects span more than one distinct stratum
    (surfaces mixed_stratal_endpoints, an invitation; N12.3.2)."""
    def stratum_of(occ_id):
        return occ_map.get(occ_id, {}).get("stratum")
    cs = {stratum_of(c) for c in cro["causes"]}
    es = {stratum_of(e) for e in cro["effects"]}
    if None in cs or None in es:
        return False
    return len(cs) > 1 or len(es) > 1


def skip_gaps(cro, classification):
    """ALGORITHM D (Rule 16): the gaps a Causal Relation Object surfaces for
    the skip decision. THE ASYMMETRY (clause 3) is the whole point of the
    field and is implemented exactly."""
    gaps = []
    has_mech = bool(cro.get("mechanism"))
    if cro.get("skips") is True and has_mech:
        gaps.append("contradictory_skip")       # HARD
        return gaps
    if cro.get("skips") is True and classification not in (
            "skipping", "unclassifiable"):
        gaps.append("vacuous_skip")              # invitation
    if classification == "skipping" and not has_mech:
        if cro.get("skips") is True:
            pass                                 # NOTHING: absence is a finding
        else:
            gaps.append("incomplete_mechanism")  # invitation
    return gaps


def to_seconds(duration, unit):
    """ALGORITHM E helper: normalize a delay to seconds by the fixed table.
    3.0.0: an ordinal ('ticks') unit is dimensionless and has NO wall-clock
    mapping - converting one to seconds is a category error and is refused."""
    if unit in ORDINAL_UNITS:
        raise ValueError("'%s' is an ordinal (dimensionless) unit and has no "
                         "wall-clock seconds mapping" % unit)
    if unit == "instant":
        return 0
    return duration * UNIT_SECONDS[unit]


def delay_within_window(actual_delay, temporal):
    """ALGORITHM E (Rule 20): does an observed delay fall within a covering
    law's temporal window? Inclusive at both ends (N12.5.2). 3.0.0: an ordinal
    delay compares to an ordinal window by integer tick count; an ordinal delay
    and a wall-clock window (or vice versa) are different dimensions and never
    fall within one another."""
    if not actual_delay or not temporal:
        return True  # nothing to check
    if _dimension(actual_delay["unit"]) != _dimension(temporal["unit"]):
        return False  # dimension mismatch: a tick delay is not within a wall-clock window
    observed = _magnitude(actual_delay["duration"], actual_delay["unit"])
    lo = _magnitude(temporal["minimum_delay"], temporal["unit"])
    hi = _magnitude(temporal["maximum_delay"], temporal["unit"])
    return lo <= observed <= hi


# ---- Rule 14 / N3.2.1: Bridge well-formedness -----------------------------
def bridge_wellformed(bridge, occ_map, stratum_map):
    """(ok, reason). All of (a)-(e) of N3.2.1 must hold, else malformed_bridge."""
    coarse = occ_map.get(bridge["coarse"], {})
    cs = coarse.get("stratum")
    if cs is None:
        return False, "malformed_bridge: coarse has no stratum (a)"
    fine_strata = [occ_map.get(f, {}).get("stratum") for f in bridge["fine"]]
    if any(s is None for s in fine_strata):
        return False, "malformed_bridge: a fine member has no stratum (b)"
    if len(set(fine_strata)) != 1:
        return False, "malformed_bridge: fine members span >1 stratum (c)"
    fs = fine_strata[0]
    if stratum_map[cs]["scheme"] != stratum_map[fs]["scheme"]:
        return False, "malformed_bridge: coarse and fine differ in scheme (d)"
    if not stratum_map[cs]["ordinal"] > stratum_map[fs]["ordinal"]:
        return False, "malformed_bridge: coarse ordinal not > fine ordinal (e)"
    return True, "well-formed bridge"


# ---- 3.0.0 Rule 22 / Algorithm F: Cross Stratal Seam well-formedness --------
def seam_wellformed(seam, occ_map, stratum_map):
    """(ok, reason) for a Cross Stratal Seam. All of (a)-(g) must hold, else
    malformed_seam. A seam is a MANAGED jump across NON-ADJACENT strata; when it
    DRAWS a chain, the chain must be an adjacent-stratum path spanning the two
    endpoints' strata."""
    src_s = occ_map.get(seam["source"], {}).get("stratum")
    tgt_s = occ_map.get(seam["target"], {}).get("stratum")
    if src_s is None or tgt_s is None:
        return False, "malformed_seam: an endpoint has no stratum (a)"
    if stratum_map[src_s]["scheme"] != stratum_map[tgt_s]["scheme"]:
        return False, "malformed_seam: endpoints differ in scheme (b)"
    so, to_ = stratum_map[src_s]["ordinal"], stratum_map[tgt_s]["ordinal"]
    if abs(so - to_) <= 1:
        return False, ("malformed_seam: endpoints are adjacent or co-stratal; "
                       "a seam is for NON-adjacent strata (c)")
    chain = seam.get("chain")
    if chain is not None:
        if seam.get("mechanism_status") == "absent":
            return False, ("malformed_seam: a drawn chain contradicts "
                           "mechanism_status 'absent' (d)")
        lo, hi = min(so, to_), max(so, to_)
        ords = []
        for oid in chain:
            st = occ_map.get(oid, {}).get("stratum")
            if st is None:
                return False, "malformed_seam: a chain member has no stratum (e)"
            if stratum_map[st]["scheme"] != stratum_map[src_s]["scheme"]:
                return False, "malformed_seam: a chain member differs in scheme (e)"
            ords.append(stratum_map[st]["ordinal"])
        if not all(lo < o < hi for o in ords):
            return False, ("malformed_seam: a chain member is not at an "
                           "INTERVENING stratum, strictly between the endpoints (f)")
        diffs = [ords[i + 1] - ords[i] for i in range(len(ords) - 1)]
        if diffs and not (all(d > 0 for d in diffs) or all(d < 0 for d in diffs)):
            return False, ("malformed_seam: chain is not strictly monotone from "
                           "one endpoint toward the other (g)")
    return True, "well-formed cross_stratal_seam"


def seam_home(seam, occ_map, stratum_map):
    """THE HOME RULE (3.0.0): a Cross Stratal Seam belongs to the COARSEST
    stratum it touches - the endpoint of the greater ordinal. Returns that
    stratum's identifier (None if an endpoint is unstratified). A layer-to-
    stratum binding places and checks the seam by this rule."""
    src_s = occ_map.get(seam["source"], {}).get("stratum")
    tgt_s = occ_map.get(seam["target"], {}).get("stratum")
    if src_s is None or tgt_s is None:
        return None
    return src_s if stratum_map[src_s]["ordinal"] >= stratum_map[tgt_s]["ordinal"] else tgt_s


# ---- Rule 17 / N4.2.1-2: Conduit well-formedness --------------------------
def conduit_wellformed(conduit, port_map, cro_map=None):
    """(ok, reason). N4.2.1 with the transform exception of N4.2.2."""
    frm = port_map.get(conduit["from"])
    to = port_map.get(conduit["to"])
    if frm is None or to is None:
        return False, "malformed_conduit: dangling port reference"
    if frm["direction"] not in ("out", "bidirectional"):
        return False, "malformed_conduit: from port is not out/bidirectional (a)"
    if to["direction"] not in ("in", "bidirectional"):
        return False, "malformed_conduit: to port is not in/bidirectional (b)"
    carries = conduit["carries"]
    if not all(o in frm["accepts"] for o in carries):
        return False, "malformed_conduit: carries not accepted by from (c)"
    transform = conduit.get("transform")
    if transform is None:
        if not all(o in to["accepts"] for o in carries):
            return False, "malformed_conduit: carries not accepted by to (d)"
    else:
        law = (cro_map or {}).get(transform)
        if law is not None:
            if not all(o in to["accepts"] for o in law["effects"]):
                return False, ("malformed_conduit: transform effects not "
                               "accepted by to (d, relaxed per N4.2.2)")
    return True, "well-formed conduit"


# ---- Rule 19 / N5.3.1-2: State value type and unit coherence --------------
def state_gaps(state, quality):
    """The HARD gaps a state assertion surfaces against its quality:
    value_type_mismatch and/or unit_mismatch."""
    gaps = []
    dt = quality.get("datatype")
    v = state.get("value", {})
    shape = ("quantity" if "quantity" in v else
             "categorical" if "categorical" in v else
             "boolean" if "boolean" in v else None)
    if shape != dt:
        gaps.append("value_type_mismatch")
    elif dt == "quantity" and v.get("unit") != quality.get("unit"):
        gaps.append("unit_mismatch")
    return gaps


# ---- Rule 20: covering-law coherence --------------------------------------
def covering_law_mismatch(tcc, token_map, law):
    """True iff the token claim's cause/effect tokens do not instantiate the
    covering law's causes/effects (surfaces covering_law_mismatch)."""
    if not law:
        return False
    law_causes, law_effects = set(law["causes"]), set(law["effects"])
    for c in tcc["causes"]:
        if token_map[c]["instantiates"] not in law_causes:
            return True
    for e in tcc["effects"]:
        if token_map[e]["instantiates"] not in law_effects:
            return True
    return False


# ---- Rule 21: temporal coherence of token causation -----------------------
def retrocausal(tcc, token_map):
    """True iff any cause token starts after any effect token (HARD;
    retrocausal_claim). RFC 3339 UTC 'Z' strings compare lexicographically."""
    for c in tcc["causes"]:
        cstart = token_map[c]["interval"]["start"]
        for e in tcc["effects"]:
            estart = token_map[e]["interval"]["start"]
            if cstart > estart:
                return True
    return False


# ---- Rules 4 / 6.1: generic acyclicity for the new graph relations --------
def has_cycle(edges):
    """True iff a directed graph (dict node -> iterable of successors) has a
    cycle. Used for bridge graph, occurrent_subsumes, occurrent_part_of, and
    token mereology (part_of)."""
    WHITE, GREY, BLACK = 0, 1, 2
    state = {}

    def visit(node):
        state[node] = GREY
        for nxt in edges.get(node, ()):
            s = state.get(nxt, WHITE)
            if s == GREY:
                return True
            if s == WHITE and visit(nxt):
                return True
        state[node] = BLACK
        return False

    return any(state.get(n, WHITE) == WHITE and visit(n) for n in list(edges))

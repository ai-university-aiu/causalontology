# semantics.jl - the semantic rules beyond the schemas (spec/semantics.md).
#
# Local rules are checked here; store-context rules (materialized acyclicity,
# retraction lineage) live in store.jl where the context exists.

# Rule 4: the fixed unit-conversion constants (average Gregorian values).
const UNIT_SECONDS = Dict{String,Int64}(
    "instant" => 0,
    "seconds" => 1,
    "minutes" => 60,
    "hours"   => 3600,
    "days"    => 86400,
    "weeks"   => 604800,
    "months"  => 2629746,
    "years"   => 31556952,
)

# 3.0.0: the ordinal (dimensionless) temporal units.  A tick is a discrete step
# with NO wall-clock mapping; a tick window is ordered by integer comparison,
# and an ordinal window and a wall-clock window are DIFFERENT DIMENSIONS that do
# not compare (mixing them is never within-window and never overlapping).
const ORDINAL_UNITS = Set{String}(["ticks"])

"'ordinal' for a tick-like unit, else 'wallclock'."
_dimension(unit) = unit in ORDINAL_UNITS ? "ordinal" : "wallclock"

"""
A comparable magnitude within ONE dimension: raw tick count for an ordinal
unit, seconds for a wall-clock unit.  Never mix dimensions.
"""
function _magnitude(value, unit)
    unit in ORDINAL_UNITS && return value   # a dimensionless tick count
    unit == "instant" && return 0
    return value * UNIT_SECONDS[unit]
end

# Rule 12: enrichment field-to-kind validity and entry shapes.  Two occurrent
# forms added in 2.0.0.
const ENRICHMENT_FIELDS = Dict{String,Tuple{Tuple{Vararg{String}},String}}(
    "aliases"            => (("occurrent", "continuant"), "alias"),
    "participants"       => (("occurrent",),  "continuant"),
    "subsumes"           => (("continuant",), "continuant"),
    "part_of"            => (("continuant",), "continuant"),
    "realized_in"        => (("realizable",), "occurrent"),
    "occurrent_subsumes" => (("occurrent",),  "occurrent"),
    "occurrent_part_of"  => (("occurrent",),  "occurrent"),
)

const CRO_OPTIONAL_FIELDS = ["mechanism", "temporal", "modality", "context"]

_kind_of_id(identifier::AbstractString) =
    get(KIND_OF_PREFIX, String(split(identifier, ':'; limit=2)[1]), nothing)

"(ok, reasons) - the locally checkable semantic rules."
function validate_semantics(obj::JObj, kind=nothing)
    k = kind === nothing ? infer_kind(obj) : kind
    errors = String[]

    if k == "causal_relation_object"
        t = jget(obj, "temporal")
        if t !== nothing && jget(t, "minimum_delay") !== nothing &&
                jget(t, "maximum_delay") !== nothing && jget(t, "minimum_delay") > jget(t, "maximum_delay")
            push!(errors, "minimum_delay must be <= maximum_delay")
        end
        oid = jget(obj, "id")
        if oid !== nothing && oid != "" &&
                any(m -> m == oid, jget(obj, "mechanism", Any[]))
            push!(errors, "mechanism must be acyclic " *
                          "(a Causal Relation Object may not contain itself)")
        end
        if oid !== nothing && oid != "" && jget(obj, "refines") == oid
            push!(errors, "refines must be acyclic")
        end
        # Rule 16, clause 1 (contradictory_skip): a HARD, locally-decidable
        # contradiction between skips:true and a non-empty mechanism.
        if jget(obj, "skips") === true && !isempty(jget(obj, "mechanism", Any[]))
            push!(errors, "contradictory_skip: skips is true but a mechanism " *
                          "is present")
        end
    end

    if k == "enrichment"
        field = jget(obj, "field")
        about = jget(obj, "about", "")
        entry = jget(obj, "entry")
        spec = get(ENRICHMENT_FIELDS, field, nothing)
        if spec !== nothing
            legal_kinds, shape = spec
            about_kind = _kind_of_id(about)
            if about_kind !== nothing && !(about_kind in legal_kinds)
                push!(errors,
                      "$field is not a legal field for a $about_kind (rule 12)")
            end
            if shape == "alias"
                if !(entry isa JObj && jhas(entry, "lang") &&
                     jhas(entry, "text"))
                    push!(errors, "an aliases entry must be a " *
                                  "language-tagged text object")
                end
            else
                if !(entry isa AbstractString &&
                     startswith(entry, shape * ":"))
                    push!(errors,
                          "a $field entry must be a $shape: identifier")
                end
            end
        end
    end

    # 3.0.0 Rule 22, local clause: a Cross Stratal Seam that DRAWS a chain has,
    # by drawing it, a modelled intervening mechanism - so mechanism_status
    # 'absent' contradicts a present chain (the honest-ignorance distinction
    # must stay honest).  The stratal well-formedness (non-adjacency, adjacency
    # of chain steps, scheme, the home rule) needs the strata map and lives in
    # seam_wellformed, exactly as bridge well-formedness does.
    if k == "cross_stratal_seam"
        if jget(obj, "chain") !== nothing &&
                jget(obj, "mechanism_status") == "absent"
            push!(errors, "contradictory_seam: a drawn chain cannot carry " *
                          "mechanism_status 'absent' (a drawn mechanism is not " *
                          "absent)")
        end
    end

    # 4.0.0 Rule 24, local clause: a predicted_occurrence's interval carries
    # exactly ONE temporal dimension - a wall-clock start (optional end) or an
    # ordinal start_tick (optional end_tick), never both and never neither.
    # Per Rule 23 the two dimensions never compare.  The pairing check of a
    # prediction_error against its predicted_occurrence and its observed
    # token_occurrence needs those objects and lives in
    # prediction_pairing_mismatch, exactly as covering_law_mismatch does.
    if k == "predicted_occurrence"
        iv = jget(obj, "interval")
        wall = iv isa JObj && jhas(iv, "start")
        tick = iv isa JObj && jhas(iv, "start_tick")
        if wall && tick
            push!(errors, "dimension_conflict: a predicted interval must " *
                          "carry exactly one temporal dimension, not a " *
                          "wall-clock start AND an ordinal start_tick")
        end
        if !wall && !tick
            push!(errors, "missing_dimension: a predicted interval must " *
                          "carry a wall-clock start or an ordinal start_tick")
        end
    end

    return isempty(errors), errors
end

"(partial, missing) - which optional CRO fields are unspecified."
function is_partial(cro::JObj)
    missing_fields = [f for f in CRO_OPTIONAL_FIELDS if !jhas(cro, f)]
    return !isempty(missing_fields), missing_fields
end

"""
Rule 4: temporal admissibility.  For a wall-clock window `elapsed` is in
seconds; for an ordinal ('ticks') window `elapsed` is a tick count.  Ordering
is by magnitude WITHIN the window's own dimension (3.0.0).
"""
function admissible(cro::JObj, elapsed)
    t = jget(cro, "temporal")
    t === nothing && return true  # no window imposes no constraint
    lo = _magnitude(jget(t, "minimum_delay"), jget(t, "unit"))
    hi = _magnitude(jget(t, "maximum_delay"), jget(t, "unit"))
    return lo <= elapsed <= hi
end

function _window_overlap(a::JObj, b::JObj)
    ta, tb = jget(a, "temporal"), jget(b, "temporal")
    (ta === nothing || tb === nothing) && return true  # absent overlaps
    # 3.0.0: an ordinal window and a wall-clock window never overlap
    _dimension(jget(ta, "unit")) != _dimension(jget(tb, "unit")) && return false
    lo_a = _magnitude(jget(ta, "minimum_delay"), jget(ta, "unit"))
    hi_a = _magnitude(jget(ta, "maximum_delay"), jget(ta, "unit"))
    lo_b = _magnitude(jget(tb, "minimum_delay"), jget(tb, "unit"))
    hi_b = _magnitude(jget(tb, "maximum_delay"), jget(tb, "unit"))
    return lo_a <= hi_b && lo_b <= hi_a
end

function _contexts_compatible(a::JObj, b::JObj)
    ca, cb = jget(a, "context"), jget(b, "context")
    (ca === nothing || isempty(ca) || cb === nothing || isempty(cb)) &&
        return true  # either absent (or empty)
    sa, sb = Set(ca), Set(cb)
    return sa == sb || issubset(sa, sb) || issubset(sb, sa)
end

# Rule 6 (amended): necessary, sufficient, contributory, enabling are mutually
# compatible; preventive opposes all four.
const _POSITIVE = ("necessary", "sufficient", "contributory", "enabling")

"Rule 6: the formal conflict test."
function conflicts(a::JObj, b::JObj)
    Set(a["causes"]) == Set(b["causes"]) || return false
    Set(a["effects"]) == Set(b["effects"]) || return false
    _contexts_compatible(a, b) || return false
    _window_overlap(a, b) || return false
    ma, mb = jget(a, "modality"), jget(b, "modality")
    return (ma == "preventive" && mb in _POSITIVE) ||
           (mb == "preventive" && ma in _POSITIVE)
end

"Rule 3: (ok, reason) - is child a valid refinement of parent?"
function refinement_valid(child::JObj, parent::JObj)
    jget(child, "refines") == jget(parent, "id") ||
        return false, "child does not name the parent in refines"
    if Set(child["causes"]) != Set(parent["causes"]) ||
            Set(child["effects"]) != Set(parent["effects"])
        return false, "a refinement must keep the parent's causes and effects"
    end
    added = 0
    for field in CRO_OPTIONAL_FIELDS
        if jhas(parent, field)
            if jget(child, field) != jget(parent, field)
                return false, ("a refinement may not change a field the " *
                               "parent specified; this is a rival claim")
            end
        elseif jhas(child, field)
            added += 1
        end
    end
    added == 0 &&
        return false, "a refinement must add at least one unspecified field"
    return true, "valid refinement"
end

# ===========================================================================
# 2.0.0 NORMATIVE ALGORITHMS (Section 12)
# ===========================================================================

"""
ALGORITHM A.  Every finer occurrent an occurrent resolves to, following
Bridges downward, transitively.  Includes the starting occurrent (N12.1.1).
`bridges` is any iterable of bridge objects.  The visited guard (N12.1.2)
prevents an infinite loop on malformed cyclic data.
"""
function bridge_closure(occurrent_id, bridges)
    result = Set{Any}([occurrent_id])
    frontier = Any[occurrent_id]
    visited = Set{Any}()
    coarse_index = Dict{Any,Vector{Any}}()
    for b in bridges
        push!(get!(coarse_index, b["coarse"], Any[]), b)
    end
    while !isempty(frontier)
        current = pop!(frontier)
        current in visited && continue
        push!(visited, current)
        for b in get(coarse_index, current, Any[])
            for f in b["fine"]
                push!(result, f)
                push!(frontier, f)
            end
        end
    end
    return result
end

function _path_exists(edges::AbstractDict, src, dst)
    seen, stack = Set{Any}(), Any[src]
    while !isempty(stack)
        node = pop!(stack)
        node == dst && return true
        node in seen && continue
        push!(seen, node)
        for nxt in get(edges, node, Set{Any}())
            push!(stack, nxt)
        end
    end
    return false
end

"""
ALGORITHM B (amended Rule 7): "consistent" | "inconsistent" |
"indeterminate", ACROSS STRATA via bridged reachability.

members: mapping from CRO identifier to CRO object for the mechanism entries.
bridges: the store's bridges (empty -> 1.0.0 literal reachability, the
degenerate case, N12.2.3).
"""
function hierarchy_consistent(parent::JObj, members::AbstractDict, bridges=())
    mechanism = jget(parent, "mechanism", Any[])
    (mechanism === nothing || isempty(mechanism)) &&
        return "consistent"  # nothing claimed, nothing to check (N12.2.1)
    edges = Dict{Any,Set{Any}}()
    for mid in mechanism
        m = get(members, mid, nothing)
        m === nothing && return "indeterminate"  # dangling; ignorance
        for c in m["causes"]
            union!(get!(edges, c, Set{Any}()), m["effects"])
        end
    end
    b_cause = Dict{Any,Any}(c => bridge_closure(c, bridges) for c in parent["causes"])
    b_effect = Dict{Any,Any}(e => bridge_closure(e, bridges) for e in parent["effects"])
    for c in parent["causes"]
        for e in parent["effects"]
            connected = any(_path_exists(edges, cp, ep)
                            for cp in b_cause[c] for ep in b_effect[e])
            connected || return "inconsistent"
        end
    end
    return "consistent"
end

_stratum_of(occ_map::AbstractDict, occ_id) =
    jget(get(occ_map, occ_id, JObj()), "stratum")

"""
ALGORITHM C (Rule 15): "intra_stratal" | "adjacent_stratal" | "skipping" |
"mixed" | "unclassifiable" | "scheme_mismatch".  Derived, never asserted;
recompute on ingest (N12.3.1).
"""
function classify_cro(cro::JObj, occ_map::AbstractDict, stratum_map::AbstractDict)
    cause_strata = Any[_stratum_of(occ_map, c) for c in cro["causes"]]
    effect_strata = Any[_stratum_of(occ_map, e) for e in cro["effects"]]
    any(s -> s === nothing, vcat(cause_strata, effect_strata)) &&
        return "unclassifiable"  # surface unstratified_occurrent (invitation)
    all_strata = union(Set(cause_strata), Set(effect_strata))
    schemes = Set(stratum_map[s]["scheme"] for s in all_strata)
    length(schemes) > 1 && return "scheme_mismatch"  # HARD
    c_ord = [stratum_map[s]["ordinal"] for s in cause_strata]
    e_ord = [stratum_map[s]["ordinal"] for s in effect_strata]
    if maximum(c_ord) == minimum(c_ord) == maximum(e_ord) == minimum(e_ord)
        return "intra_stratal"
    end
    gap = minimum(abs(i - j) for i in c_ord for j in e_ord)
    span = maximum(abs(i - j) for i in c_ord for j in e_ord)
    span == 1 && return "adjacent_stratal"
    gap > 1 && return "skipping"
    return "mixed"  # some pairs adjacent, some skipping
end

"""
True iff causes or effects span more than one distinct stratum (surfaces
mixed_stratal_endpoints, an invitation; N12.3.2).
"""
function endpoints_mixed(cro::JObj, occ_map::AbstractDict)
    cs = Set(_stratum_of(occ_map, c) for c in cro["causes"])
    es = Set(_stratum_of(occ_map, e) for e in cro["effects"])
    (nothing in cs || nothing in es) && return false
    return length(cs) > 1 || length(es) > 1
end

"""
ALGORITHM D (Rule 16): the gaps a Causal Relation Object surfaces for the skip
decision.  THE ASYMMETRY (clause 3) is the whole point of the field and is
implemented exactly.
"""
function skip_gaps(cro::JObj, classification)
    gaps = String[]
    has_mech = !isempty(jget(cro, "mechanism", Any[]))
    if jget(cro, "skips") === true && has_mech
        push!(gaps, "contradictory_skip")       # HARD
        return gaps
    end
    if jget(cro, "skips") === true &&
            !(classification in ("skipping", "unclassifiable"))
        push!(gaps, "vacuous_skip")              # invitation
    end
    if classification == "skipping" && !has_mech
        if jget(cro, "skips") === true
            # NOTHING: absence is a finding
        else
            push!(gaps, "incomplete_mechanism")  # invitation
        end
    end
    return gaps
end

"""
ALGORITHM E helper: normalize a delay to seconds by the fixed table.  3.0.0: an
ordinal ('ticks') unit is dimensionless and has NO wall-clock mapping -
converting one to seconds is a category error and is refused.
"""
function to_seconds(duration, unit)
    unit in ORDINAL_UNITS && error("'$unit' is an ordinal (dimensionless) " *
        "unit and has no wall-clock seconds mapping")
    unit == "instant" && return 0
    return duration * UNIT_SECONDS[unit]
end

"""
ALGORITHM E (Rule 20): does an observed delay fall within a covering law's
temporal window?  Inclusive at both ends (N12.5.2).  3.0.0: an ordinal delay
compares to an ordinal window by integer tick count; an ordinal delay and a
wall-clock window (or vice versa) are different dimensions and never fall
within one another.
"""
function delay_within_window(actual_delay, temporal)
    (actual_delay === nothing || actual_delay == false ||
     temporal === nothing || temporal == false) && return true  # nothing to check
    # dimension mismatch: a tick delay is not within a wall-clock window
    _dimension(actual_delay["unit"]) != _dimension(temporal["unit"]) &&
        return false
    observed = _magnitude(actual_delay["duration"], actual_delay["unit"])
    lo = _magnitude(temporal["minimum_delay"], temporal["unit"])
    hi = _magnitude(temporal["maximum_delay"], temporal["unit"])
    return lo <= observed <= hi
end

# ---- Rule 14 / N3.2.1: Bridge well-formedness -----------------------------
"(ok, reason).  All of (a)-(e) of N3.2.1 must hold, else malformed_bridge."
function bridge_wellformed(bridge::JObj, occ_map::AbstractDict, stratum_map::AbstractDict)
    coarse = get(occ_map, bridge["coarse"], JObj())
    cs = jget(coarse, "stratum")
    cs === nothing && return false, "malformed_bridge: coarse has no stratum (a)"
    fine_strata = Any[jget(get(occ_map, f, JObj()), "stratum") for f in bridge["fine"]]
    any(s -> s === nothing, fine_strata) &&
        return false, "malformed_bridge: a fine member has no stratum (b)"
    length(Set(fine_strata)) != 1 &&
        return false, "malformed_bridge: fine members span >1 stratum (c)"
    fs = fine_strata[1]
    stratum_map[cs]["scheme"] != stratum_map[fs]["scheme"] &&
        return false, "malformed_bridge: coarse and fine differ in scheme (d)"
    !(stratum_map[cs]["ordinal"] > stratum_map[fs]["ordinal"]) &&
        return false, "malformed_bridge: coarse ordinal not > fine ordinal (e)"
    return true, "well-formed bridge"
end

# ---- 3.0.0 Rule 22 / Algorithm F: Cross Stratal Seam well-formedness -------
"""
(ok, reason) for a Cross Stratal Seam.  All of (a)-(g) must hold, else
malformed_seam.  A seam is a MANAGED jump across NON-ADJACENT strata; when it
DRAWS a chain, the chain must be an adjacent-stratum path spanning the two
endpoints' strata.
"""
function seam_wellformed(seam::JObj, occ_map::AbstractDict, stratum_map::AbstractDict)
    src_s = _stratum_of(occ_map, seam["source"])
    tgt_s = _stratum_of(occ_map, seam["target"])
    (src_s === nothing || tgt_s === nothing) &&
        return false, "malformed_seam: an endpoint has no stratum (a)"
    stratum_map[src_s]["scheme"] != stratum_map[tgt_s]["scheme"] &&
        return false, "malformed_seam: endpoints differ in scheme (b)"
    so, to_ = stratum_map[src_s]["ordinal"], stratum_map[tgt_s]["ordinal"]
    abs(so - to_) <= 1 &&
        return false, ("malformed_seam: endpoints are adjacent or co-stratal; " *
                       "a seam is for NON-adjacent strata (c)")
    chain = jget(seam, "chain")
    if chain !== nothing
        jget(seam, "mechanism_status") == "absent" &&
            return false, ("malformed_seam: a drawn chain contradicts " *
                           "mechanism_status 'absent' (d)")
        lo, hi = min(so, to_), max(so, to_)
        ords = Any[]
        for oid in chain
            st = _stratum_of(occ_map, oid)
            st === nothing &&
                return false, "malformed_seam: a chain member has no stratum (e)"
            stratum_map[st]["scheme"] != stratum_map[src_s]["scheme"] &&
                return false, "malformed_seam: a chain member differs in scheme (e)"
            push!(ords, stratum_map[st]["ordinal"])
        end
        all(o -> lo < o < hi, ords) ||
            return false, ("malformed_seam: a chain member is not at an " *
                           "INTERVENING stratum, strictly between the endpoints (f)")
        diffs = [ords[i + 1] - ords[i] for i in 1:(length(ords) - 1)]
        if !isempty(diffs) &&
                !(all(d -> d > 0, diffs) || all(d -> d < 0, diffs))
            return false, ("malformed_seam: chain is not strictly monotone from " *
                           "one endpoint toward the other (g)")
        end
    end
    return true, "well-formed cross_stratal_seam"
end

"""
THE HOME RULE (3.0.0): a Cross Stratal Seam belongs to the COARSEST stratum it
touches - the endpoint of the greater ordinal.  Returns that stratum's
identifier (nothing if an endpoint is unstratified).  A layer-to-stratum
binding places and checks the seam by this rule.
"""
function seam_home(seam::JObj, occ_map::AbstractDict, stratum_map::AbstractDict)
    src_s = _stratum_of(occ_map, seam["source"])
    tgt_s = _stratum_of(occ_map, seam["target"])
    (src_s === nothing || tgt_s === nothing) && return nothing
    return stratum_map[src_s]["ordinal"] >= stratum_map[tgt_s]["ordinal"] ?
        src_s : tgt_s
end

# ---- Rule 17 / N4.2.1-2: Conduit well-formedness --------------------------
"(ok, reason).  N4.2.1 with the transform exception of N4.2.2."
function conduit_wellformed(conduit::JObj, port_map::AbstractDict, cro_map=nothing)
    frm = get(port_map, conduit["from"], nothing)
    to = get(port_map, conduit["to"], nothing)
    (frm === nothing || to === nothing) &&
        return false, "malformed_conduit: dangling port reference"
    !(frm["direction"] in ("out", "bidirectional")) &&
        return false, "malformed_conduit: from port is not out/bidirectional (a)"
    !(to["direction"] in ("in", "bidirectional")) &&
        return false, "malformed_conduit: to port is not in/bidirectional (b)"
    carries = conduit["carries"]
    !all(o -> o in frm["accepts"], carries) &&
        return false, "malformed_conduit: carries not accepted by from (c)"
    transform = jget(conduit, "transform")
    if transform === nothing
        !all(o -> o in to["accepts"], carries) &&
            return false, "malformed_conduit: carries not accepted by to (d)"
    else
        law = cro_map === nothing ? nothing : get(cro_map, transform, nothing)
        if law !== nothing
            !all(o -> o in to["accepts"], law["effects"]) &&
                return false, ("malformed_conduit: transform effects not " *
                               "accepted by to (d, relaxed per N4.2.2)")
        end
    end
    return true, "well-formed conduit"
end

# ---- Rule 19 / N5.3.1-2: State value type and unit coherence --------------
"""
The HARD gaps a state assertion surfaces against its quality:
value_type_mismatch and/or unit_mismatch.
"""
function state_gaps(state::JObj, quality::JObj)
    gaps = String[]
    dt = jget(quality, "datatype")
    v = jget(state, "value", JObj())
    shape = jhas(v, "quantity") ? "quantity" :
            jhas(v, "categorical") ? "categorical" :
            jhas(v, "boolean") ? "boolean" : nothing
    if shape != dt
        push!(gaps, "value_type_mismatch")
    elseif dt == "quantity" && jget(v, "unit") != jget(quality, "unit")
        push!(gaps, "unit_mismatch")
    end
    return gaps
end

# ---- Rule 20: covering-law coherence --------------------------------------
"""
True iff the token claim's cause/effect tokens do not instantiate the covering
law's causes/effects (surfaces covering_law_mismatch).
"""
function covering_law_mismatch(tcc::JObj, token_map::AbstractDict, law)
    (law === nothing || law == false) && return false
    law_causes, law_effects = Set(law["causes"]), Set(law["effects"])
    for c in tcc["causes"]
        !(token_map[c]["instantiates"] in law_causes) && return true
    end
    for e in tcc["effects"]
        !(token_map[e]["instantiates"] in law_effects) && return true
    end
    return false
end

# ---- 4.0.0 Rule 24: prediction-to-observation pairing ---------------------
"""
True iff the prediction error's observed token does not instantiate the
occurrent its predicted_occurrence instantiates (surfaces pairing_mismatch).
An ABSENT observed is never a mismatch - it means the predicted occurrence was
not fulfilled by any recorded occurrence.
"""
function prediction_pairing_mismatch(err::JObj, predicted::JObj, observed)
    (jget(err, "observed") === nothing || observed === nothing) && return false
    return observed["instantiates"] != predicted["instantiates"]
end

# ---- Rule 21: temporal coherence of token causation -----------------------
"""
True iff any cause token starts after any effect token (HARD; retrocausal_claim).
RFC 3339 UTC 'Z' strings compare lexicographically.
"""
function retrocausal(tcc::JObj, token_map::AbstractDict)
    for c in tcc["causes"]
        cstart = token_map[c]["interval"]["start"]
        for e in tcc["effects"]
            estart = token_map[e]["interval"]["start"]
            cstart > estart && return true
        end
    end
    return false
end

# ---- Rules 4 / 6.1: generic acyclicity for the new graph relations --------
"""
True iff a directed graph (dict node -> iterable of successors) has a cycle.
Used for bridge graph, occurrent_subsumes, occurrent_part_of, and token
mereology (part_of).
"""
function has_cycle(edges::AbstractDict)
    WHITE, GREY, BLACK = 0, 1, 2
    state = Dict{Any,Int}()
    function visit(node)
        state[node] = GREY
        for nxt in get(edges, node, ())
            s = get(state, nxt, WHITE)
            s == GREY && return true
            (s == WHITE && visit(nxt)) && return true
        end
        state[node] = BLACK
        return false
    end
    return any(get(state, n, WHITE) == WHITE && visit(n) for n in collect(keys(edges)))
end

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

    return isempty(errors), errors
end

"(partial, missing) - which optional CRO fields are unspecified."
function is_partial(cro::JObj)
    missing_fields = [f for f in CRO_OPTIONAL_FIELDS if !jhas(cro, f)]
    return !isempty(missing_fields), missing_fields
end

"Rule 4: temporal admissibility with the fixed constants."
function admissible(cro::JObj, elapsed_seconds)
    t = jget(cro, "temporal")
    t === nothing && return true  # no window imposes no constraint
    unit = UNIT_SECONDS[jget(t, "unit")]
    lo = jget(t, "minimum_delay") * unit
    hi = jget(t, "maximum_delay") * unit
    return lo <= elapsed_seconds <= hi
end

function _window_overlap(a::JObj, b::JObj)
    ta, tb = jget(a, "temporal"), jget(b, "temporal")
    (ta === nothing || tb === nothing) && return true  # absent overlaps
    ua, ub = UNIT_SECONDS[jget(ta, "unit")], UNIT_SECONDS[jget(tb, "unit")]
    lo_a, hi_a = jget(ta, "minimum_delay") * ua, jget(ta, "maximum_delay") * ua
    lo_b, hi_b = jget(tb, "minimum_delay") * ub, jget(tb, "maximum_delay") * ub
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

"ALGORITHM E helper: normalize a delay to seconds by the fixed table."
function to_seconds(duration, unit)
    unit == "instant" && return 0
    return duration * UNIT_SECONDS[unit]
end

"""
ALGORITHM E (Rule 20): does an observed delay fall within a covering law's
temporal window?  Inclusive at both ends (N12.5.2).
"""
function delay_within_window(actual_delay, temporal)
    (actual_delay === nothing || actual_delay == false ||
     temporal === nothing || temporal == false) && return true  # nothing to check
    observed = to_seconds(actual_delay["duration"], actual_delay["unit"])
    lo = to_seconds(temporal["minimum_delay"], temporal["unit"])
    hi = to_seconds(temporal["maximum_delay"], temporal["unit"])
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

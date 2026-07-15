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

# Rule 12: enrichment field-to-kind validity and entry shapes.
const ENRICHMENT_FIELDS = Dict{String,Tuple{Tuple{Vararg{String}},String}}(
    "aliases"      => (("occurrent", "continuant"), "alias"),
    "participants" => (("occurrent",),              "continuant"),
    "subsumes"     => (("continuant",),             "continuant"),
    "part_of"      => (("continuant",),             "continuant"),
    "realized_in"  => (("realizable",),             "occurrent"),
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

const _POSITIVE = ("necessary", "sufficient", "contributory")

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

"""
Rule 7: "consistent" | "inconsistent" | "indeterminate".

members: a mapping from CRO identifier to CRO object for the parent's
mechanism entries (the store's view of them).
"""
function hierarchy_consistent(parent::JObj, members::AbstractDict)
    mechanism = jget(parent, "mechanism", Any[])
    (mechanism === nothing || isempty(mechanism)) &&
        return "consistent"  # nothing claimed, nothing to check
    edges = Dict{Any,Set{Any}}()
    for mid in mechanism
        m = get(members, mid, nothing)
        m === nothing && return "indeterminate"  # a dangling reference
        for c in m["causes"]
            union!(get!(edges, c, Set{Any}()), m["effects"])
        end
    end
    function reachable(src, dst)
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
    for c in parent["causes"], e in parent["effects"]
        reachable(c, e) || return "inconsistent"
    end
    return "consistent"
end

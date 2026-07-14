# store.jl - an in-memory conformant store.
#
# Implements the store side of the abstract operation set (spec/store.md):
# immutable content objects with idempotent put; signed, add-only provenance
# records with quarantine; materialized enrichment views with contributors;
# retraction handling in default views; succession lineage; the resolve
# minimum; the deterministic cycle-breaking view rule; and the stigmergy gap
# read.  Insertion order is tracked explicitly (object_order, record_order)
# because Julia's Dict is unordered where Python's dict is not.

const CONTENT_KINDS = ("occurrent", "cro", "continuant", "realizable")
const RECORD_KINDS = ("assertion", "enrichment", "retraction", "succession")

"An enforcing store refused a write, with the reason in msg."
struct RejectedWrite <: Exception
    msg::String
end
Base.showerror(io::IO, e::RejectedWrite) = print(io, "RejectedWrite: ", e.msg)

mutable struct InMemoryStore
    enforcing::Bool
    object_order::Vector{String}       # object ids, in insertion order
    objects::Dict{String,JObj}         # id -> content object
    record_order::Vector{String}       # record ids, in insertion order
    records::Dict{String,JObj}         # id -> provenance record
    quarantine::Dict{String,JObj}      # id -> record (unsigned/unverifiable)
end

InMemoryStore(; enforcing::Bool=true) =
    InMemoryStore(enforcing, String[], Dict{String,JObj}(),
                  String[], Dict{String,JObj}(), Dict{String,JObj}())

# ------------------------------------------------------------------ put
"Write a content object; idempotent; returns the identifier."
function put(store::InMemoryStore, obj::JObj; kind=nothing)
    k = kind === nothing ? infer_kind(obj) : kind
    k in CONTENT_KINDS ||
        throw(ArgumentError("put() takes content objects; use put_record()"))
    obj = jcopy(obj)
    jsetdefault!(obj, "type", k)
    jhas(obj, "id") || jset!(obj, "id", identify(obj, k))
    oid = obj["id"]
    haskey(store.objects, oid) &&
        return oid  # immutable: identical identity is a no-op
    ok, why = validate_schema(obj, k)
    ok || throw(RejectedWrite(join(why, "; ")))
    ok, why = validate_semantics(obj, k)
    ok || throw(RejectedWrite(join(why, "; ")))
    store.objects[oid] = obj
    push!(store.object_order, oid)
    return oid
end

"Write a signed provenance record; returns the identifier."
function put_record(store::InMemoryStore, record::JObj; kind=nothing,
                    force::Bool=false)
    k = kind === nothing ? infer_kind(record) : kind
    k in RECORD_KINDS ||
        throw(ArgumentError("put_record() takes provenance records"))
    record = jcopy(record)
    jsetdefault!(record, "type", k)
    rid = jget(record, "id")
    (rid === nothing || rid == "") && (rid = identify(record, k))
    jset!(record, "id", rid)
    haskey(store.records, rid) && return rid  # add-only and idempotent
    if !verify_record(record, k)
        store.quarantine[rid] = record
        throw(RejectedWrite("unsigned or unverifiable record: quarantined"))
    end
    ok, why = validate_semantics(record, k)
    ok || throw(RejectedWrite(join(why, "; ")))
    if k == "retraction" && !_retraction_source_ok(store, record)
        throw(RejectedWrite(
            "a retraction is valid only from the retracted record's " *
            "source or its succession lineage"))
    end
    if k == "enrichment" && store.enforcing && !force
        if jget(record, "field") in ("subsumes", "part_of") &&
                _would_cycle(store, record)
            throw(RejectedWrite(
                "would create a cycle in the materialized " *
                "$(jget(record, "field")) graph"))
        end
    end
    store.records[rid] = record
    push!(store.record_order, rid)
    return rid
end

"Simulate a decentralized replica merge (no enforcement gate)."
force_merge_record(store::InMemoryStore, record::JObj; kind=nothing) =
    put_record(store, record; kind=kind, force=true)

# ------------------------------------------------------- record queries
_records_of(store::InMemoryStore, kind) =
    JObj[store.records[rid] for rid in store.record_order
         if jget(store.records[rid], "type") == kind]

function _retracted_ids(store::InMemoryStore)
    out = Set{String}()
    for r in _records_of(store, "retraction")
        push!(out, jget(r, "retracts"))
    end
    return out
end

function _retraction_source_ok(store::InMemoryStore, retraction::JObj)
    target = get(store.records, jget(retraction, "retracts"), nothing)
    target === nothing && return true  # open world: target may arrive later
    return jget(retraction, "source") in lineage(store, jget(target, "source"))
end

"The succession chain closure containing key (includes key)."
function lineage(store::InMemoryStore, key)
    succ, pred = Dict{String,String}(), Dict{String,String}()
    for s in _records_of(store, "succession")
        succ[jget(s, "predecessor")] = jget(s, "successor")
        pred[jget(s, "successor")] = jget(s, "predecessor")
    end
    chain = Set{String}([key])
    cursor = String(key)
    while haskey(pred, cursor)
        cursor = pred[cursor]
        push!(chain, cursor)
    end
    cursor = String(key)
    while haskey(succ, cursor)
        cursor = succ[cursor]
        push!(chain, cursor)
    end
    return chain
end

function assertions_about(store::InMemoryStore, identifier;
                          include_retracted::Bool=false)
    retracted = _retracted_ids(store)
    out = JObj[]
    for r in _records_of(store, "assertion")
        jget(r, "about") == identifier || continue
        if jget(r, "id") in retracted
            if include_retracted
                rc = jcopy(r)
                jset!(rc, "retracted", true)
                push!(out, rc)
            end
            continue
        end
        push!(out, r)
    end
    return out
end

function enrichments_about(store::InMemoryStore, identifier;
                           include_retracted::Bool=false)
    retracted = _retracted_ids(store)
    out = JObj[]
    for r in _records_of(store, "enrichment")
        jget(r, "about") == identifier || continue
        (jget(r, "id") in retracted && !include_retracted) && continue
        push!(out, r)
    end
    return out
end

# ------------------------------------------------- materialized views
"(active, excluded) for subsumes/part_of after rule 13 cycle-breaking."
function _active_taxonomy_edges(store::InMemoryStore, field)
    retracted = _retracted_ids(store)
    recs = JObj[r for r in _records_of(store, "enrichment")
                if jget(r, "field") == field &&
                   !(jget(r, "id") in retracted)]
    active = copy(recs)
    excluded = JObj[]
    while true
        cyc = _find_cycle_records(active)
        isempty(cyc) && break
        # exclude the cycle-completing record with the LATEST timestamp,
        # ties broken by lexicographic record identifier (deterministic);
        # explicit strict-greater comparison keeps the FIRST of equals,
        # matching Python's max()
        loser = cyc[1]
        for r in cyc[2:end]
            if (jget(r, "timestamp"), jget(r, "id")) >
                    (jget(loser, "timestamp"), jget(loser, "id"))
                loser = r
            end
        end
        idx = findfirst(r -> r === loser, active)
        deleteat!(active, idx)
        push!(excluded, loser)
    end
    return active, excluded
end

function _find_cycle_records(recs::Vector{JObj})
    # an ordered adjacency map: about -> [(entry, record), ...]
    edge_order = String[]
    edge_map = Dict{String,Vector{Tuple{Any,JObj}}}()
    for r in recs
        about = jget(r, "about")
        if !haskey(edge_map, about)
            edge_map[about] = Tuple{Any,JObj}[]
            push!(edge_order, about)
        end
        push!(edge_map[about], (jget(r, "entry"), r))
    end
    state = Dict{String,Int}()
    cycle = JObj[]
    function dfs(node, path_records)
        state[node] = 1
        for (nxt, rec) in get(edge_map, node, Tuple{Any,JObj}[])
            st = get(state, nxt, 0)
            if st == 1
                append!(cycle, path_records)
                push!(cycle, rec)
                return true
            elseif st == 0
                dfs(nxt, vcat(path_records, JObj[rec])) && return true
            end
        end
        state[node] = 2
        return false
    end
    for start in edge_order
        if get(state, start, 0) == 0 && dfs(start, JObj[])
            return cycle
        end
    end
    return JObj[]
end

function _would_cycle(store::InMemoryStore, record::JObj)
    retracted = _retracted_ids(store)
    recs = JObj[r for r in _records_of(store, "enrichment")
                if jget(r, "field") == jget(record, "field") &&
                   !(jget(r, "id") in retracted)]
    return !isempty(_find_cycle_records(vcat(recs, JObj[record])))
end

"The object with its materialized enrichment sets and contributors."
function getobj(store::InMemoryStore, identifier; view::String="default")
    obj = get(store.objects, identifier, nothing)
    obj === nothing && return nothing
    include_retracted = (view == "history")
    excluded_ids = Set{String}()
    for field in ("subsumes", "part_of")
        _, excluded = _active_taxonomy_edges(store, field)
        for r in excluded
            push!(excluded_ids, jget(r, "id"))
        end
    end
    # field -> [(canonical entry key, bucket), ...], insertion-ordered
    field_order = String[]
    slots = Dict{String,Vector{Tuple{String,JObj}}}()
    for rec in enrichments_about(store, identifier;
                                 include_retracted=include_retracted)
        (jget(rec, "id") in excluded_ids && view != "history") && continue
        field = jget(rec, "field")
        entry = jget(rec, "entry")
        # the same entry from different contributors buckets by canonical
        # value (RFC 8785 form), the order-insensitive analogue of Python's
        # sorted-items tuple key
        ekey = _jcs(entry)
        if !haskey(slots, field)
            slots[field] = Tuple{String,JObj}[]
            push!(field_order, field)
        end
        slot = slots[field]
        bi = findfirst(t -> t[1] == ekey, slot)
        bucket = if bi === nothing
            b = jobj("entry" => entry, "contributors" => Any[])
            push!(slot, (ekey, b))
            b
        else
            slot[bi][2]
        end
        push!(jget(bucket, "contributors"),
              jobj("source" => jget(rec, "source"),
                   "timestamp" => jget(rec, "timestamp")))
    end
    enrichments = JObj()
    for f in field_order
        jset!(enrichments, f, Any[b for (_, b) in slots[f]])
    end
    view == "raw" && return jobj("object" => obj)
    return jobj("object" => obj, "enrichments" => enrichments)
end

# -------------------------------------------------------------- resolve
_canon_label(text) = join(split(lowercase(strip(text))), "_")
_norm_alias(text) = lowercase(join(split(text), " "))

"The conformance minimum: exact label, then alias, then nothing."
function resolve(store::InMemoryStore, text, lang=nothing)
    label_hits, alias_hits = String[], String[]
    wanted_label = _canon_label(text)
    wanted_alias = _norm_alias(text)
    retracted = _retracted_ids(store)
    for oid in store.object_order
        obj = store.objects[oid]
        jget(obj, "type") in ("occurrent", "continuant") || continue
        if jget(obj, "label") == wanted_label
            push!(label_hits, oid)
            continue
        end
        for rec in _records_of(store, "enrichment")
            (jget(rec, "about") == oid && jget(rec, "field") == "aliases") ||
                continue
            jget(rec, "id") in retracted && continue
            entry = jget(rec, "entry")
            (lang !== nothing && jget(entry, "lang") != lang) && continue
            if _norm_alias(jget(entry, "text", "")) == wanted_alias
                push!(alias_hits, oid)
                break
            end
        end
    end
    return vcat(label_hits, alias_hits)
end

# ---------------------------------------------------------------- gaps
"The stigmergy read.  Gap kinds per spec/store.md."
function gaps(store::InMemoryStore; kind=nothing)
    out = JObj[]
    refined = Set{String}()
    for oid in store.object_order
        obj = store.objects[oid]
        ref = jget(obj, "refines")
        if jget(obj, "type") == "cro" && ref !== nothing && ref != ""
            parent = get(store.objects, ref, nothing)
            if parent !== nothing
                ok, _ = refinement_valid(obj, parent)
                ok && push!(refined, parent["id"])
            end
        end
    end
    for oid in store.object_order
        obj = store.objects[oid]
        jget(obj, "type") == "cro" || continue
        # missing_field: lacking the temporal window or the modality -
        # mechanism and context may legitimately stay unspecified forever
        # (empty_mechanism is its own kind; absent context = context-free).
        if (!jhas(obj, "temporal") || !jhas(obj, "modality")) &&
                !(oid in refined)
            _, missing_fields = is_partial(obj)
            push!(out, jobj("id" => oid, "kind" => "missing_field",
                            "missing" => missing_fields))
        end
        if (!jhas(obj, "mechanism") || isempty(jget(obj, "mechanism"))) &&
                !(oid in refined)
            push!(out, jobj("id" => oid, "kind" => "empty_mechanism"))
        end
    end
    for field in ("subsumes", "part_of")
        _, excluded = _active_taxonomy_edges(store, field)
        for rec in excluded
            push!(out, jobj("id" => jget(rec, "id"),
                            "kind" => "inconsistent_hierarchy",
                            "note" => "excluded by the deterministic " *
                                      "cycle-breaking view rule"))
        end
    end
    # dangling_reference: a reference to an object absent from the store -
    # the red link that says "this page is wanted".
    for oid in store.object_order
        obj = store.objects[oid]
        refs = Any[]
        if jget(obj, "type") == "cro"
            append!(refs, jget(obj, "causes", Any[]))
            append!(refs, jget(obj, "effects", Any[]))
            append!(refs, jget(obj, "context", Any[]))
            append!(refs, jget(obj, "mechanism", Any[]))
            r = jget(obj, "refines")
            (r !== nothing && r != "") && push!(refs, r)
        elseif jget(obj, "type") == "realizable"
            push!(refs, jget(obj, "bearer"))
        end
        for ref in refs
            if ref !== nothing && ref != "" && !haskey(store.objects, ref)
                push!(out, jobj("id" => oid, "kind" => "dangling_reference",
                                "ref" => ref))
            end
        end
    end
    # conflict: pairs of claims satisfying the formal test (rule 6).
    cros = JObj[store.objects[oid] for oid in store.object_order
                if jget(store.objects[oid], "type") == "cro"]
    for i in 1:length(cros)
        for j in (i + 1):length(cros)
            if conflicts(cros[i], cros[j])
                push!(out, jobj("kind" => "conflict",
                                "a" => cros[i]["id"], "b" => cros[j]["id"]))
            end
        end
    end
    kind === nothing && return out
    return JObj[g for g in out if jget(g, "kind") == kind]
end

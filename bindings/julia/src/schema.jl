# schema.jl - schema validation against spec/schema/*.schema.json.
#
# A deliberately small interpreter for exactly the JSON Schema keywords the
# eight Causalontology schemas use: type, const, enum, pattern, required,
# properties, additionalProperties, items, minItems, minLength, minimum,
# maximum, oneOf, and local ref (#/defs/...).  "format" is treated as an
# annotation, as the 2020-12 draft does by default.

const SCHEMA_FILES = Dict{String,String}(
    "cro"        => "cro.schema.json",
    "occurrent"  => "occurrent.schema.json",
    "continuant" => "continuant.schema.json",
    "realizable" => "realizable.schema.json",
    "assertion"  => "assertion.schema.json",
    "enrichment" => "enrichment.schema.json",
    "retraction" => "retraction.schema.json",
    "succession" => "succession.schema.json",
)

const _schema_cache = Dict{String,JObj}()

function _schema_dir()
    env = get(ENV, "CAUSALONTOLOGY_SPEC", nothing)
    env !== nothing && return joinpath(env, "schema")
    # src/ -> julia/ -> bindings/ -> repository root
    return normpath(joinpath(@__DIR__, "..", "..", "..", "spec", "schema"))
end

function load_schema(kind)
    haskey(SCHEMA_FILES, kind) || error("unknown kind: $(repr(kind))")
    get!(_schema_cache, kind) do
        json_parse(read(joinpath(_schema_dir(), SCHEMA_FILES[kind]), String))
    end
end

function _resolve_ref(schema, root::JObj)
    while schema isa JObj && jhas(schema, "\$ref")
        ref = jget(schema, "\$ref")
        startswith(ref, "#/") || error("only local \$ref supported: $ref")
        node = root
        for part in split(ref[3:end], '/')
            node = node[String(part)]
        end
        schema = node
    end
    return schema
end

function _type_ok(value, t)
    t == "object"  && return value isa JObj
    t == "array"   && return value isa AbstractVector
    t == "string"  && return value isa AbstractString
    t == "boolean" && return value isa Bool
    # "number": Int64 or Float64, and never Bool (mirrors the Python check)
    t == "number"  && return value isa Union{Int64,Float64}
    return false
end

function _schema_check(value, schema, root::JObj, path::String,
                       errors::Vector{String})
    schema = _resolve_ref(schema, root)

    oneof = jget(schema, "oneOf")
    if oneof !== nothing
        passing = 0
        for sub in oneof
            suberrs = String[]
            _schema_check(value, sub, root, path, suberrs)
            isempty(suberrs) && (passing += 1)
        end
        passing != 1 && push!(errors,
            "$path: matches $passing of the oneOf branches (need exactly 1)")
        return
    end

    t = jget(schema, "type")
    if t !== nothing
        if !_type_ok(value, t)
            push!(errors, "$path: expected $t")
            return
        end
    end

    if jhas(schema, "const") && value != jget(schema, "const")
        push!(errors, "$path: must equal $(repr(jget(schema, "const")))")
    end
    if jhas(schema, "enum") && !any(e -> e == value, jget(schema, "enum"))
        push!(errors, "$path: $(repr(value)) not in enumeration")
    end
    if jhas(schema, "pattern") && value isa AbstractString
        if !occursin(Regex(jget(schema, "pattern")), value)
            push!(errors, "$path: $(repr(value)) does not match " *
                          jget(schema, "pattern"))
        end
    end
    if jhas(schema, "minLength") && value isa AbstractString
        length(value) < jget(schema, "minLength") &&
            push!(errors, "$path: shorter than minLength")
    end
    if jhas(schema, "minimum") && value isa Union{Int64,Float64}
        value < jget(schema, "minimum") &&
            push!(errors, "$path: below minimum $(jget(schema, "minimum"))")
    end
    if jhas(schema, "maximum") && value isa Union{Int64,Float64}
        value > jget(schema, "maximum") &&
            push!(errors, "$path: above maximum $(jget(schema, "maximum"))")
    end

    if value isa AbstractVector
        if jhas(schema, "minItems") && length(value) < jget(schema, "minItems")
            push!(errors,
                  "$path: fewer than $(jget(schema, "minItems")) items")
        end
        if jhas(schema, "items")
            for (i, item) in enumerate(value)
                # the error path keeps 0-based indices, as the reference does
                _schema_check(item, jget(schema, "items"), root,
                              "$path[$(i - 1)]", errors)
            end
        end
    end

    if value isa JObj
        props = jget(schema, "properties", JObj())
        for req in jget(schema, "required", Any[])
            jhas(value, req) ||
                push!(errors, "$path: required property '$req' missing")
        end
        if jget(schema, "additionalProperties") === false
            for k in jkeys(value)
                jhas(props, k) ||
                    push!(errors, "$path: additional property '$k'")
            end
        end
        for (k, sub) in props.pairs
            if jhas(value, k)
                _schema_check(value[k], sub, root, "$path.$k", errors)
            end
        end
    end
end

"(ok, reasons) - structural validity against the kind's JSON Schema."
function validate_schema(obj::JObj, kind=nothing)
    k = kind === nothing ? infer_kind(obj) : kind
    root = load_schema(k)
    errors = String[]
    _schema_check(obj, root, root, "\$", errors)
    return isempty(errors), errors
end

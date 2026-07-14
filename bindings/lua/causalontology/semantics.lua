-- semantics.lua - the semantic rules beyond the schemas (spec/semantics.md).
--
-- Local rules are checked here; store-context rules (materialized acyclicity,
-- retraction lineage) live in store.lua where the context exists.  A faithful
-- port of bindings/python/causalontology/semantics.py.

local json = require("causalontology.json")
local canonical = require("causalontology.canonical")

local semantics = {}

-- Rule 4: the fixed unit-conversion constants (average Gregorian values).
semantics.UNIT_SECONDS = {
  instant = 0,
  seconds = 1,
  minutes = 60,
  hours = 3600,
  days = 86400,
  weeks = 604800,
  months = 2629746,
  years = 31556952,
}

-- Rule 12: enrichment field-to-kind validity and entry shapes.
semantics.ENRICHMENT_FIELDS = {
  aliases      = { kinds = { occurrent = true, continuant = true }, shape = "alias" },
  participants = { kinds = { occurrent = true },                    shape = "cnt" },
  subsumes     = { kinds = { continuant = true },                   shape = "cnt" },
  part_of      = { kinds = { continuant = true },                   shape = "cnt" },
  realized_in  = { kinds = { realizable = true },                   shape = "occ" },
}

-- The V02-fixed order of the optional Causal Relation Object fields.
semantics.CRO_OPTIONAL_FIELDS = { "mechanism", "temporal", "modality", "context" }

local function kind_of_id(identifier)
  local prefix = identifier:match("^([^:]*):")
  return canonical.KIND_OF_PREFIX[prefix]
end

-- True iff the array contains the value.
local function contains(arr, value)
  for _, v in ipairs(arr) do
    if v == value then return true end
  end
  return false
end

-- An array of strings as a set table.
local function as_set(arr)
  local set = {}
  for _, v in ipairs(arr) do set[v] = true end
  return set
end

-- Set equality between two string arrays.
local function set_equal(a, b)
  local sa, sb = as_set(a), as_set(b)
  for k in pairs(sa) do if not sb[k] then return false end end
  for k in pairs(sb) do if not sa[k] then return false end end
  return true
end

-- True iff every member of set table sa is in set table sb.
local function subset(sa, sb)
  for k in pairs(sa) do if not sb[k] then return false end end
  return true
end

-- (ok, reasons) - the locally checkable semantic rules.
function semantics.validate_semantics(obj, kind)
  kind = kind or canonical.infer_kind(obj)
  local errors = {}

  if kind == "cro" then
    local t = obj["temporal"]
    if t ~= nil and t ~= json.null and t["dmin"] ~= nil and t["dmax"] ~= nil
        and t["dmin"] > t["dmax"] then
      errors[#errors + 1] = "dmin must be <= dmax"
    end
    local oid = obj["id"]
    if oid and obj["mechanism"] ~= nil and contains(obj["mechanism"], oid) then
      errors[#errors + 1] = "mechanism must be acyclic " ..
        "(a Causal Relation Object may not contain itself)"
    end
    if oid and obj["refines"] == oid then
      errors[#errors + 1] = "refines must be acyclic"
    end
  end

  if kind == "enrichment" then
    local field = obj["field"]
    local about = obj["about"] or ""
    local entry = obj["entry"]
    local spec = semantics.ENRICHMENT_FIELDS[field]
    if spec then
      local about_kind = kind_of_id(about)
      if about_kind and not spec.kinds[about_kind] then
        errors[#errors + 1] = string.format(
          "%s is not a legal field for a %s (rule 12)", field, about_kind)
      end
      if spec.shape == "alias" then
        if not (json.is_object(entry)
                and entry["lang"] ~= nil and entry["text"] ~= nil) then
          errors[#errors + 1] =
            "an aliases entry must be a language-tagged text object"
        end
      else
        if not (type(entry) == "string"
                and entry:sub(1, #spec.shape + 1) == spec.shape .. ":") then
          errors[#errors + 1] = string.format(
            "a %s entry must be a %s: identifier", field, spec.shape)
        end
      end
    end
  end

  return #errors == 0, errors
end

-- (partial, missing) - which optional CRO fields are unspecified.
function semantics.is_partial(cro)
  local missing = {}
  for _, field in ipairs(semantics.CRO_OPTIONAL_FIELDS) do
    if cro[field] == nil then missing[#missing + 1] = field end
  end
  return #missing > 0, missing
end

-- Rule 4: temporal admissibility with the fixed constants.
function semantics.admissible(cro, elapsed_seconds)
  local t = cro["temporal"]
  if t == nil or t == json.null then
    return true  -- no window imposes no constraint
  end
  local unit = semantics.UNIT_SECONDS[t["unit"]]
  local lo = t["dmin"] * unit
  local hi = t["dmax"] * unit
  return lo <= elapsed_seconds and elapsed_seconds <= hi
end

local function window_overlap(a, b)
  local ta, tb = a["temporal"], b["temporal"]
  if ta == nil or ta == json.null or tb == nil or tb == json.null then
    return true  -- either absent counts as overlapping
  end
  local ua = semantics.UNIT_SECONDS[ta["unit"]]
  local ub = semantics.UNIT_SECONDS[tb["unit"]]
  local lo_a, hi_a = ta["dmin"] * ua, ta["dmax"] * ua
  local lo_b, hi_b = tb["dmin"] * ub, tb["dmax"] * ub
  return lo_a <= hi_b and lo_b <= hi_a
end

local function contexts_compatible(a, b)
  local ca, cb = a["context"], b["context"]
  if ca == nil or ca == json.null or #ca == 0
      or cb == nil or cb == json.null or #cb == 0 then
    return true  -- either absent (or empty)
  end
  local sa, sb = as_set(ca), as_set(cb)
  return subset(sa, sb) or subset(sb, sa)
end

local POSITIVE = { necessary = true, sufficient = true, contributory = true }

-- Rule 6: the formal conflict test.
function semantics.conflicts(a, b)
  if not set_equal(a["causes"], b["causes"]) then return false end
  if not set_equal(a["effects"], b["effects"]) then return false end
  if not contexts_compatible(a, b) then return false end
  if not window_overlap(a, b) then return false end
  local ma, mb = a["modality"], b["modality"]
  return (ma == "preventive" and POSITIVE[mb] == true)
      or (mb == "preventive" and POSITIVE[ma] == true)
end

-- Rule 3: (ok, reason) - is child a valid refinement of parent?
function semantics.refinement_valid(child, parent)
  if child["refines"] ~= parent["id"] then
    return false, "child does not name the parent in refines"
  end
  if not set_equal(child["causes"], parent["causes"])
      or not set_equal(child["effects"], parent["effects"]) then
    return false, "a refinement must keep the parent's causes and effects"
  end
  local added = 0
  for _, field in ipairs(semantics.CRO_OPTIONAL_FIELDS) do
    if parent[field] ~= nil then
      if not json.deep_equal(child[field], parent[field]) then
        return false, "a refinement may not change a field the " ..
          "parent specified; this is a rival claim"
      end
    elseif child[field] ~= nil then
      added = added + 1
    end
  end
  if added == 0 then
    return false, "a refinement must add at least one unspecified field"
  end
  return true, "valid refinement"
end

-- Rule 7: 'consistent' | 'inconsistent' | 'indeterminate'.
--
-- members: a mapping from CRO identifier to CRO object for the parent's
-- mechanism entries (the store's view of them).
function semantics.hierarchy_consistent(parent, members)
  local mechanism = parent["mechanism"]
  if mechanism == nil or #mechanism == 0 then
    return "consistent"  -- nothing claimed, nothing to check
  end
  local edges = {}
  for _, mid in ipairs(mechanism) do
    local m = members[mid]
    if m == nil then
      return "indeterminate"  -- a dangling_reference gap, not a failure
    end
    for _, c in ipairs(m["causes"]) do
      edges[c] = edges[c] or {}
      for _, e in ipairs(m["effects"]) do
        edges[c][e] = true
      end
    end
  end

  local function reachable(src, dst)
    local seen, stack = {}, { src }
    while #stack > 0 do
      local node = table.remove(stack)
      if node == dst then return true end
      if not seen[node] then
        seen[node] = true
        for nxt in pairs(edges[node] or {}) do
          stack[#stack + 1] = nxt
        end
      end
    end
    return false
  end

  for _, c in ipairs(parent["causes"]) do
    for _, e in ipairs(parent["effects"]) do
      if not reachable(c, e) then return "inconsistent" end
    end
  end
  return "consistent"
end

return semantics

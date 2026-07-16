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

-- Rule 12: enrichment field-to-kind validity and entry shapes. Two occurrent
-- forms added in 2.0.0.
semantics.ENRICHMENT_FIELDS = {
  aliases            = { kinds = { occurrent = true, continuant = true }, shape = "alias" },
  participants       = { kinds = { occurrent = true },                    shape = "continuant" },
  subsumes           = { kinds = { continuant = true },                   shape = "continuant" },
  part_of            = { kinds = { continuant = true },                   shape = "continuant" },
  realized_in        = { kinds = { realizable = true },                   shape = "occurrent" },
  occurrent_subsumes = { kinds = { occurrent = true },                    shape = "occurrent" },
  occurrent_part_of  = { kinds = { occurrent = true },                    shape = "occurrent" },
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

  if kind == "causal_relation_object" then
    local t = obj["temporal"]
    if t ~= nil and t ~= json.null and t["minimum_delay"] ~= nil and t["maximum_delay"] ~= nil
        and t["minimum_delay"] > t["maximum_delay"] then
      errors[#errors + 1] = "minimum_delay must be <= maximum_delay"
    end
    local oid = obj["id"]
    if oid and obj["mechanism"] ~= nil and contains(obj["mechanism"], oid) then
      errors[#errors + 1] = "mechanism must be acyclic " ..
        "(a Causal Relation Object may not contain itself)"
    end
    if oid and obj["refines"] == oid then
      errors[#errors + 1] = "refines must be acyclic"
    end
    -- Rule 16, clause 1 (contradictory_skip): a HARD, locally-decidable
    -- contradiction between skips:true and a non-empty mechanism.
    local mech = obj["mechanism"]
    if obj["skips"] == true and mech ~= nil and mech ~= json.null
        and json.is_array(mech) and #mech > 0 then
      errors[#errors + 1] = "contradictory_skip: skips is true but a " ..
        "mechanism is present"
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
  local lo = t["minimum_delay"] * unit
  local hi = t["maximum_delay"] * unit
  return lo <= elapsed_seconds and elapsed_seconds <= hi
end

local function window_overlap(a, b)
  local ta, tb = a["temporal"], b["temporal"]
  if ta == nil or ta == json.null or tb == nil or tb == json.null then
    return true  -- either absent counts as overlapping
  end
  local ua = semantics.UNIT_SECONDS[ta["unit"]]
  local ub = semantics.UNIT_SECONDS[tb["unit"]]
  local lo_a, hi_a = ta["minimum_delay"] * ua, ta["maximum_delay"] * ua
  local lo_b, hi_b = tb["minimum_delay"] * ub, tb["maximum_delay"] * ub
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

-- Rule 6 (amended): necessary, sufficient, contributory, enabling are mutually
-- compatible; preventive opposes all four.
local POSITIVE = { necessary = true, sufficient = true,
                   contributory = true, enabling = true }

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

-- ===========================================================================
-- 2.0.0 NORMATIVE ALGORITHMS (Section 12)
-- ===========================================================================

-- ALGORITHM A (N12.1): every finer occurrent an occurrent resolves to,
-- following Bridges downward, transitively. Includes the starting occurrent.
-- `bridges` is any array of bridge objects. Returns a set (id -> true). The
-- visited guard prevents an infinite loop on malformed cyclic data.
function semantics.bridge_closure(occurrent_id, bridges)
  local result = { [occurrent_id] = true }
  local frontier = { occurrent_id }
  local visited = {}
  local coarse_index = {}
  for _, b in ipairs(bridges or {}) do
    local c = b["coarse"]
    coarse_index[c] = coarse_index[c] or {}
    coarse_index[c][#coarse_index[c] + 1] = b
  end
  while #frontier > 0 do
    local current = table.remove(frontier)
    if not visited[current] then
      visited[current] = true
      for _, b in ipairs(coarse_index[current] or {}) do
        for _, f in ipairs(b["fine"]) do
          result[f] = true
          frontier[#frontier + 1] = f
        end
      end
    end
  end
  return result
end

-- Reachability over an edge map (node -> set of successors).
local function path_exists(edges, src, dst)
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

-- ALGORITHM B (amended Rule 7): 'consistent' | 'inconsistent' |
-- 'indeterminate', ACROSS STRATA via bridged reachability.
--
-- members: a mapping from CRO identifier to CRO object for the mechanism
-- entries. bridges: the store's bridges (nil/empty -> 1.0.0 literal
-- reachability, the degenerate case).
function semantics.hierarchy_consistent(parent, members, bridges)
  local mechanism = parent["mechanism"]
  if mechanism == nil or mechanism == json.null or #mechanism == 0 then
    return "consistent"  -- nothing claimed, nothing to check
  end
  local edges = {}
  for _, mid in ipairs(mechanism) do
    local m = members[mid]
    if m == nil then
      return "indeterminate"  -- dangling; ignorance, not refutation
    end
    for _, c in ipairs(m["causes"]) do
      edges[c] = edges[c] or {}
      for _, e in ipairs(m["effects"]) do
        edges[c][e] = true
      end
    end
  end
  local b_cause, b_effect = {}, {}
  for _, c in ipairs(parent["causes"]) do
    b_cause[c] = semantics.bridge_closure(c, bridges)
  end
  for _, e in ipairs(parent["effects"]) do
    b_effect[e] = semantics.bridge_closure(e, bridges)
  end
  for _, c in ipairs(parent["causes"]) do
    for _, e in ipairs(parent["effects"]) do
      local connected = false
      for cp in pairs(b_cause[c]) do
        for ep in pairs(b_effect[e]) do
          if path_exists(edges, cp, ep) then connected = true break end
        end
        if connected then break end
      end
      if not connected then return "inconsistent" end
    end
  end
  return "consistent"
end

-- The stratum id of an occurrent (or nil).
local function stratum_of(occ_map, occ_id)
  local o = occ_map[occ_id]
  return o and o["stratum"] or nil
end

-- ALGORITHM C (Rule 15): 'intra_stratal' | 'adjacent_stratal' | 'skipping'
-- | 'mixed' | 'unclassifiable' | 'scheme_mismatch'. Derived, never asserted.
function semantics.classify_cro(cro, occ_map, stratum_map)
  -- collect the strata of each endpoint; a nil (unstratified) anywhere makes
  -- the relation unclassifiable (nil cannot be held in a Lua sequence, so it
  -- is detected inline rather than stored).
  local cause_strata, effect_strata = {}, {}
  for _, c in ipairs(cro["causes"]) do
    local s = stratum_of(occ_map, c)
    if s == nil then return "unclassifiable" end
    cause_strata[#cause_strata + 1] = s
  end
  for _, e in ipairs(cro["effects"]) do
    local s = stratum_of(occ_map, e)
    if s == nil then return "unclassifiable" end
    effect_strata[#effect_strata + 1] = s
  end
  local all_strata = {}
  for _, s in ipairs(cause_strata) do all_strata[s] = true end
  for _, s in ipairs(effect_strata) do all_strata[s] = true end
  local schemes = {}
  for s in pairs(all_strata) do schemes[stratum_map[s]["scheme"]] = true end
  local scheme_count = 0
  for _ in pairs(schemes) do scheme_count = scheme_count + 1 end
  if scheme_count > 1 then return "scheme_mismatch" end
  local c_ord, e_ord = {}, {}
  for _, s in ipairs(cause_strata) do c_ord[#c_ord + 1] = stratum_map[s]["ordinal"] end
  for _, s in ipairs(effect_strata) do e_ord[#e_ord + 1] = stratum_map[s]["ordinal"] end
  local function mn(t) local m = t[1] for i = 2, #t do if t[i] < m then m = t[i] end end return m end
  local function mx(t) local m = t[1] for i = 2, #t do if t[i] > m then m = t[i] end end return m end
  if mx(c_ord) == mn(c_ord) and mn(c_ord) == mx(e_ord) and mx(e_ord) == mn(e_ord) then
    return "intra_stratal"
  end
  local gap, span
  for _, i in ipairs(c_ord) do
    for _, j in ipairs(e_ord) do
      local d = math.abs(i - j)
      if gap == nil or d < gap then gap = d end
      if span == nil or d > span then span = d end
    end
  end
  if span == 1 then return "adjacent_stratal" end
  if gap > 1 then return "skipping" end
  return "mixed"
end

-- True iff causes or effects span more than one distinct stratum.
function semantics.endpoints_mixed(cro, occ_map)
  local cs, es = {}, {}
  local cs_nil, es_nil = false, false
  for _, c in ipairs(cro["causes"]) do
    local s = stratum_of(occ_map, c)
    if s == nil then cs_nil = true else cs[s] = true end
  end
  for _, e in ipairs(cro["effects"]) do
    local s = stratum_of(occ_map, e)
    if s == nil then es_nil = true else es[s] = true end
  end
  if cs_nil or es_nil then return false end
  local nc, ne = 0, 0
  for _ in pairs(cs) do nc = nc + 1 end
  for _ in pairs(es) do ne = ne + 1 end
  return nc > 1 or ne > 1
end

-- ALGORITHM D (Rule 16): the gaps a Causal Relation Object surfaces for the
-- skip decision. The asymmetry (clause 3) is the whole point of the field.
function semantics.skip_gaps(cro, classification)
  local gaps = {}
  local mech = cro["mechanism"]
  local has_mech = mech ~= nil and mech ~= json.null
      and json.is_array(mech) and #mech > 0
  if cro["skips"] == true and has_mech then
    gaps[#gaps + 1] = "contradictory_skip"       -- HARD
    return gaps
  end
  if cro["skips"] == true
      and classification ~= "skipping" and classification ~= "unclassifiable" then
    gaps[#gaps + 1] = "vacuous_skip"              -- invitation
  end
  if classification == "skipping" and not has_mech then
    if cro["skips"] == true then
      -- NOTHING: absence is a finding
    else
      gaps[#gaps + 1] = "incomplete_mechanism"    -- invitation
    end
  end
  return gaps
end

-- ALGORITHM E helper: normalize a delay to seconds by the fixed table.
function semantics.to_seconds(duration, unit)
  if unit == "instant" then return 0 end
  return duration * semantics.UNIT_SECONDS[unit]
end

-- ALGORITHM E (Rule 20): does an observed delay fall within a covering law's
-- temporal window? Inclusive at both ends.
function semantics.delay_within_window(actual_delay, temporal)
  if actual_delay == nil or actual_delay == json.null
      or temporal == nil or temporal == json.null then
    return true  -- nothing to check
  end
  local observed = semantics.to_seconds(actual_delay["duration"], actual_delay["unit"])
  local lo = semantics.to_seconds(temporal["minimum_delay"], temporal["unit"])
  local hi = semantics.to_seconds(temporal["maximum_delay"], temporal["unit"])
  return lo <= observed and observed <= hi
end

-- Rule 14 / N3.2.1: Bridge well-formedness. All of (a)-(e) must hold.
function semantics.bridge_wellformed(bridge, occ_map, stratum_map)
  local coarse = occ_map[bridge["coarse"]] or json.new_object()
  local cs = coarse["stratum"]
  if cs == nil then return false, "malformed_bridge: coarse has no stratum (a)" end
  local fine_strata = {}
  for _, f in ipairs(bridge["fine"]) do
    local fo = occ_map[f]
    fine_strata[#fine_strata + 1] = fo and fo["stratum"] or nil
    if fo == nil or fo["stratum"] == nil then
      return false, "malformed_bridge: a fine member has no stratum (b)"
    end
  end
  local first = fine_strata[1]
  for _, s in ipairs(fine_strata) do
    if s ~= first then
      return false, "malformed_bridge: fine members span >1 stratum (c)"
    end
  end
  local fs = first
  if stratum_map[cs]["scheme"] ~= stratum_map[fs]["scheme"] then
    return false, "malformed_bridge: coarse and fine differ in scheme (d)"
  end
  if not (stratum_map[cs]["ordinal"] > stratum_map[fs]["ordinal"]) then
    return false, "malformed_bridge: coarse ordinal not > fine ordinal (e)"
  end
  return true, "well-formed bridge"
end

-- Rule 17 / N4.2.1-2: Conduit well-formedness with the transform exception.
function semantics.conduit_wellformed(conduit, port_map, cro_map)
  local frm = port_map[conduit["from"]]
  local to = port_map[conduit["to"]]
  if frm == nil or to == nil then
    return false, "malformed_conduit: dangling port reference"
  end
  if frm["direction"] ~= "out" and frm["direction"] ~= "bidirectional" then
    return false, "malformed_conduit: from port is not out/bidirectional (a)"
  end
  if to["direction"] ~= "in" and to["direction"] ~= "bidirectional" then
    return false, "malformed_conduit: to port is not in/bidirectional (b)"
  end
  local carries = conduit["carries"]
  if not (function()
        for _, o in ipairs(carries) do if not contains(frm["accepts"], o) then return false end end
        return true
      end)() then
    return false, "malformed_conduit: carries not accepted by from (c)"
  end
  local transform = conduit["transform"]
  if transform == nil or transform == json.null then
    for _, o in ipairs(carries) do
      if not contains(to["accepts"], o) then
        return false, "malformed_conduit: carries not accepted by to (d)"
      end
    end
  else
    local law = cro_map and cro_map[transform] or nil
    if law ~= nil then
      for _, o in ipairs(law["effects"]) do
        if not contains(to["accepts"], o) then
          return false, "malformed_conduit: transform effects not accepted by to (d, relaxed per N4.2.2)"
        end
      end
    end
  end
  return true, "well-formed conduit"
end

-- Rule 19 / N5.3.1-2: State value type and unit coherence.
function semantics.state_gaps(state, quality)
  local gaps = {}
  local dt = quality["datatype"]
  local v = state["value"] or json.new_object()
  local shape
  if v["quantity"] ~= nil then shape = "quantity"
  elseif v["categorical"] ~= nil then shape = "categorical"
  elseif v["boolean"] ~= nil then shape = "boolean"
  else shape = nil end
  if shape ~= dt then
    gaps[#gaps + 1] = "value_type_mismatch"
  elseif dt == "quantity" and v["unit"] ~= quality["unit"] then
    gaps[#gaps + 1] = "unit_mismatch"
  end
  return gaps
end

-- Rule 20: covering-law coherence.
function semantics.covering_law_mismatch(tcc, token_map, law)
  if law == nil or law == json.null then return false end
  local law_causes, law_effects = as_set(law["causes"]), as_set(law["effects"])
  for _, c in ipairs(tcc["causes"]) do
    if not law_causes[token_map[c]["instantiates"]] then return true end
  end
  for _, e in ipairs(tcc["effects"]) do
    if not law_effects[token_map[e]["instantiates"]] then return true end
  end
  return false
end

-- Rule 21: temporal coherence of token causation. RFC 3339 UTC 'Z' strings
-- compare lexicographically.
function semantics.retrocausal(tcc, token_map)
  for _, c in ipairs(tcc["causes"]) do
    local cstart = token_map[c]["interval"]["start"]
    for _, e in ipairs(tcc["effects"]) do
      local estart = token_map[e]["interval"]["start"]
      if cstart > estart then return true end
    end
  end
  return false
end

-- Rules 4 / 6.1: generic acyclicity for the new graph relations. `edges` is a
-- map from node to an iterable of successors (a set table or an array).
function semantics.has_cycle(edges)
  local WHITE, GREY, BLACK = 0, 1, 2
  local state = {}
  local function successors(node)
    local out = {}
    local e = edges[node]
    if e == nil then return out end
    if json.is_array(e) then
      for _, v in ipairs(e) do out[#out + 1] = v end
    else
      for _, v in ipairs(e) do out[#out + 1] = v end  -- plain array too
    end
    return out
  end
  local function visit(node)
    state[node] = GREY
    for _, nxt in ipairs(successors(node)) do
      local s = state[nxt] or WHITE
      if s == GREY then return true end
      if s == WHITE and visit(nxt) then return true end
    end
    state[node] = BLACK
    return false
  end
  for node in pairs(edges) do
    if (state[node] or WHITE) == WHITE and visit(node) then return true end
  end
  return false
end

return semantics

-- store.lua - an in-memory conformant store.
--
-- Implements the store side of the abstract operation set (spec/store.md):
-- immutable content objects with idempotent put; signed, add-only provenance
-- records; materialized enrichment views with contributors; retraction
-- handling in default views; succession lineage; the resolve minimum; the
-- deterministic cycle-breaking view rule; and the stigmergy gap read.
--
-- A faithful port of bindings/python/causalontology/store.py.  Python dicts
-- iterate in insertion order; Lua tables do not, so the store keeps explicit
-- insertion-order arrays beside every map it iterates (objects, records,
-- cycle-finder nodes, view buckets), exactly as the Go port did.
--
-- A refused write raises error({ rejected = true, message = ... }); catch it
-- with pcall and test store.is_rejected(err).

local json = require("causalontology.json")
local jcs = require("causalontology.jcs")
local canonical = require("causalontology.canonical")
local schema = require("causalontology.schema")
local semantics = require("causalontology.semantics")
local signing = require("causalontology.signing")

local store = {}

local CONTENT_KINDS = {
  occurrent = true, causal_relation_object = true, continuant = true,
  realizable = true, stratum = true, bridge = true, port = true,
  conduit = true, quality = true, token_individual = true,
  token_occurrence = true, state_assertion = true, token_causal_claim = true,
}
local RECORD_KINDS = {
  assertion = true, enrichment = true, retraction = true, succession = true,
}

-- An enforcing store refused a write; the reason travels in err.message.
local function rejected(message)
  error({ rejected = true, message = message }, 0)
end

-- True iff a pcall-captured error is a RejectedWrite.
function store.is_rejected(err)
  return type(err) == "table" and err.rejected == true
end

local InMemoryStore = {}
InMemoryStore.__index = InMemoryStore

function store.new(enforcing)
  if enforcing == nil then enforcing = true end
  return setmetatable({
    enforcing = enforcing,
    objects = {},      -- id -> content object
    object_order = {}, -- ids in insertion order
    records = {},      -- id -> provenance record
    record_order = {}, -- ids in insertion order
    quarantine = {},   -- id -> record (unsigned / unverifiable)
  }, InMemoryStore)
end

-- ------------------------------------------------------------------- put

-- Write a content object; idempotent; returns the identifier.
function InMemoryStore:put(obj, kind)
  kind = kind or canonical.infer_kind(obj)
  if not CONTENT_KINDS[kind] then
    error("put() takes content objects; use put_record()", 0)
  end
  obj = json.copy_object(obj)
  json.setdefault(obj, "type", kind)
  if obj["id"] == nil then
    json.set(obj, "id", canonical.identify(obj, kind))
  end
  local oid = obj["id"]
  if self.objects[oid] ~= nil then
    return oid  -- immutable: identical identity is a no-op
  end
  local ok, why = schema.validate_schema(obj, kind)
  if not ok then rejected(table.concat(why, "; ")) end
  ok, why = semantics.validate_semantics(obj, kind)
  if not ok then rejected(table.concat(why, "; ")) end
  self.objects[oid] = obj
  self.object_order[#self.object_order + 1] = oid
  return oid
end

-- Write a signed provenance record; returns the identifier.
function InMemoryStore:put_record(record, kind, force)
  kind = kind or canonical.infer_kind(record)
  if not RECORD_KINDS[kind] then
    error("put_record() takes provenance records", 0)
  end
  record = json.copy_object(record)
  json.setdefault(record, "type", kind)
  local rid = record["id"] or canonical.identify(record, kind)
  json.set(record, "id", rid)
  if self.records[rid] ~= nil then
    return rid  -- add-only and idempotent
  end
  if not signing.verify_record(record, kind) then
    self.quarantine[rid] = record
    rejected("unsigned or unverifiable record: quarantined")
  end
  local ok, why = semantics.validate_semantics(record, kind)
  if not ok then rejected(table.concat(why, "; ")) end
  if kind == "retraction" and not self:_retraction_source_ok(record) then
    rejected("a retraction is valid only from the retracted record's " ..
             "source or its succession lineage")
  end
  if kind == "enrichment" and self.enforcing and not force then
    local field = record["field"]
    if (field == "subsumes" or field == "part_of")
        and self:_would_cycle(record) then
      rejected(string.format(
        "would create a cycle in the materialized %s graph", field))
    end
  end
  self.records[rid] = record
  self.record_order[#self.record_order + 1] = rid
  return rid
end

-- Simulate a decentralized replica merge (no enforcement gate).
function InMemoryStore:force_merge_record(record, kind)
  return self:put_record(record, kind, true)
end

-- -------------------------------------------------------- record queries

-- The records of one kind, in insertion order.
function InMemoryStore:_records_of(kind)
  local out = {}
  for _, rid in ipairs(self.record_order) do
    local r = self.records[rid]
    if r["type"] == kind then out[#out + 1] = r end
  end
  return out
end

-- The set of record identifiers named by any retraction.
function InMemoryStore:_retracted_ids()
  local out = {}
  for _, r in ipairs(self:_records_of("retraction")) do
    out[r["retracts"]] = true
  end
  return out
end

function InMemoryStore:_retraction_source_ok(retraction)
  local target = self.records[retraction["retracts"]]
  if target == nil then
    return true  -- open world: the target may arrive later
  end
  return self:lineage(target["source"])[retraction["source"]] == true
end

-- The succession chain closure containing key (includes key), as a set.
function InMemoryStore:lineage(key)
  local succ, pred = {}, {}
  for _, s in ipairs(self:_records_of("succession")) do
    succ[s["predecessor"]] = s["successor"]
    pred[s["successor"]] = s["predecessor"]
  end
  local chain = { [key] = true }
  local cursor = key
  while pred[cursor] ~= nil do
    cursor = pred[cursor]
    chain[cursor] = true
  end
  cursor = key
  while succ[cursor] ~= nil do
    cursor = succ[cursor]
    chain[cursor] = true
  end
  return chain
end

-- The assertions about an identifier; retracted ones are excluded unless
-- include_retracted, in which case they carry retracted = true.
function InMemoryStore:assertions_about(identifier, include_retracted)
  local retracted = self:_retracted_ids()
  local out = {}
  for _, r in ipairs(self:_records_of("assertion")) do
    if r["about"] == identifier then
      if retracted[r["id"]] then
        if include_retracted then
          local marked = json.copy_object(r)
          json.set(marked, "retracted", true)
          out[#out + 1] = marked
        end
      else
        out[#out + 1] = r
      end
    end
  end
  return out
end

function InMemoryStore:enrichments_about(identifier, include_retracted)
  local retracted = self:_retracted_ids()
  local out = {}
  for _, r in ipairs(self:_records_of("enrichment")) do
    if r["about"] == identifier then
      if not (retracted[r["id"]] and not include_retracted) then
        out[#out + 1] = r
      end
    end
  end
  return out
end

-- --------------------------------------------------- materialized views

-- (edges, excluded) for subsumes/part_of after rule 13 cycle-breaking.
function InMemoryStore:_active_taxonomy_edges(field)
  local retracted = self:_retracted_ids()
  local active = {}
  for _, r in ipairs(self:_records_of("enrichment")) do
    if r["field"] == field and not retracted[r["id"]] then
      active[#active + 1] = r
    end
  end
  local excluded = {}
  while true do
    local cyc = store._find_cycle_records(active)
    if #cyc == 0 then break end
    -- exclude the cycle-completing record with the LATEST timestamp,
    -- ties broken by lexicographic record identifier (deterministic)
    local loser = cyc[1]
    for i = 2, #cyc do
      local r = cyc[i]
      if r["timestamp"] > loser["timestamp"]
          or (r["timestamp"] == loser["timestamp"]
              and r["id"] > loser["id"]) then
        loser = r
      end
    end
    for i, r in ipairs(active) do
      if r == loser then table.remove(active, i) break end
    end
    excluded[#excluded + 1] = loser
  end
  return active, excluded
end

-- The records forming the first cycle found by depth-first search over the
-- about -> entry edges, or an empty list.  Node visit order is insertion
-- order of each node's first appearance as an edge source.
function store._find_cycle_records(recs)
  local edges, node_order = {}, {}
  for _, r in ipairs(recs) do
    local from = r["about"]
    if edges[from] == nil then
      edges[from] = {}
      node_order[#node_order + 1] = from
    end
    edges[from][#edges[from] + 1] = { to = r["entry"], rec = r }
  end
  local state, cycle = {}, {}

  local function dfs(node, path_records)
    state[node] = 1
    for _, edge in ipairs(edges[node] or {}) do
      if state[edge.to] == 1 then
        for _, r in ipairs(path_records) do cycle[#cycle + 1] = r end
        cycle[#cycle + 1] = edge.rec
        return true
      end
      if state[edge.to] == nil then
        local extended = {}
        for i, r in ipairs(path_records) do extended[i] = r end
        extended[#extended + 1] = edge.rec
        if dfs(edge.to, extended) then return true end
      end
    end
    state[node] = 2
    return false
  end

  for _, start in ipairs(node_order) do
    if state[start] == nil and dfs(start, {}) then return cycle end
  end
  return {}
end

function InMemoryStore:_would_cycle(record)
  local retracted = self:_retracted_ids()
  local recs = {}
  for _, r in ipairs(self:_records_of("enrichment")) do
    if r["field"] == record["field"] and not retracted[r["id"]] then
      recs[#recs + 1] = r
    end
  end
  recs[#recs + 1] = record
  return #store._find_cycle_records(recs) > 0
end

-- The object with its materialized enrichment sets and contributors.
-- Views: "default" (retractions and broken cycle edges excluded),
-- "history" (everything), "raw" (the object alone).
function InMemoryStore:get(identifier, view)
  view = view or "default"
  local obj = self.objects[identifier]
  if obj == nil then return nil end
  local include_retracted = (view == "history")
  local excluded_ids = {}
  for _, field in ipairs({ "subsumes", "part_of" }) do
    local _, excluded = self:_active_taxonomy_edges(field)
    for _, r in ipairs(excluded) do excluded_ids[r["id"]] = true end
  end
  -- fields: field -> { bucket_order = {key...}, buckets = {key -> bucket} },
  -- with field_order carrying first-seen field order (Python dict order)
  local fields, field_order = {}, {}
  for _, rec in ipairs(self:enrichments_about(identifier, include_retracted)) do
    if not (excluded_ids[rec["id"]] and view ~= "history") then
      local entry = rec["entry"]
      -- the dedup key: field + canonical form of the entry (deterministic,
      -- equivalent to Python's (field, tuple(sorted(entry.items()))) key)
      local entry_key = rec["field"] .. "\0" .. jcs.serialize(entry)
      local slot = fields[rec["field"]]
      if slot == nil then
        slot = { bucket_order = {}, buckets = {} }
        fields[rec["field"]] = slot
        field_order[#field_order + 1] = rec["field"]
      end
      local bucket = slot.buckets[entry_key]
      if bucket == nil then
        bucket = { entry = entry, contributors = {} }
        slot.buckets[entry_key] = bucket
        slot.bucket_order[#slot.bucket_order + 1] = entry_key
      end
      bucket.contributors[#bucket.contributors + 1] = {
        source = rec["source"], timestamp = rec["timestamp"],
      }
    end
  end
  local enrichments = {}
  for _, field in ipairs(field_order) do
    local slot = fields[field]
    local list = {}
    for i, key in ipairs(slot.bucket_order) do
      list[i] = slot.buckets[key]
    end
    enrichments[field] = list
  end
  if view == "raw" then
    return { object = obj }
  end
  return { object = obj, enrichments = enrichments }
end

-- --------------------------------------------------------------- resolve

-- Canonical label form: trimmed, lowercased, whitespace runs to "_".
local function canon_label(text)
  local words = {}
  for w in text:lower():gmatch("%S+") do words[#words + 1] = w end
  return table.concat(words, "_")
end

-- Alias normal form: whitespace runs to one space, casefolded.
local function norm_alias(text)
  local words = {}
  for w in text:gmatch("%S+") do words[#words + 1] = w end
  return table.concat(words, " "):lower()
end

-- The conformance minimum: exact label, then alias, then nothing.
function InMemoryStore:resolve(text, lang)
  local label_hits, alias_hits = {}, {}
  local wanted_label = canon_label(text)
  local wanted_alias = norm_alias(text)
  local retracted = self:_retracted_ids()
  for _, oid in ipairs(self.object_order) do
    local obj = self.objects[oid]
    local otype = obj["type"]
    if otype == "occurrent" or otype == "continuant" then
      if obj["label"] == wanted_label then
        label_hits[#label_hits + 1] = oid
      else
        for _, rec in ipairs(self:_records_of("enrichment")) do
          if rec["about"] == oid and rec["field"] == "aliases"
              and not retracted[rec["id"]] then
            local entry = rec["entry"]
            if not (lang ~= nil and entry["lang"] ~= lang) then
              if norm_alias(entry["text"] or "") == wanted_alias then
                alias_hits[#alias_hits + 1] = oid
                break
              end
            end
          end
        end
      end
    end
  end
  local out = {}
  for _, oid in ipairs(label_hits) do out[#out + 1] = oid end
  for _, oid in ipairs(alias_hits) do out[#out + 1] = oid end
  return out
end

-- ------------------------------------------------------------------ gaps

-- The stigmergy read.  Gap kinds per spec/store.md.
function InMemoryStore:gaps(kind)
  local out = {}
  -- the parents whose gaps a valid refinement has closed
  local refined = {}
  for _, oid in ipairs(self.object_order) do
    local obj = self.objects[oid]
    if obj["type"] == "causal_relation_object" and obj["refines"] ~= nil then
      local parent = self.objects[obj["refines"]]
      if parent ~= nil then
        local ok = semantics.refinement_valid(obj, parent)
        if ok then refined[parent["id"]] = true end
      end
    end
  end
  for _, oid in ipairs(self.object_order) do
    local obj = self.objects[oid]
    if obj["type"] == "causal_relation_object" then
      -- missing_field: lacking the temporal window or the modality -
      -- mechanism and context may legitimately stay unspecified forever
      -- (empty_mechanism is its own kind; absent context = context-free).
      if (obj["temporal"] == nil or obj["modality"] == nil)
          and not refined[oid] then
        local _, missing = semantics.is_partial(obj)
        out[#out + 1] = { id = oid, kind = "missing_field", missing = missing }
      end
      if obj["mechanism"] == nil
          or (json.is_array(obj["mechanism"]) and #obj["mechanism"] == 0) then
        if not refined[oid] then
          out[#out + 1] = { id = oid, kind = "empty_mechanism" }
        end
      end
    end
  end
  for _, field in ipairs({ "subsumes", "part_of" }) do
    local _, excluded = self:_active_taxonomy_edges(field)
    for _, rec in ipairs(excluded) do
      out[#out + 1] = {
        id = rec["id"], kind = "inconsistent_hierarchy",
        note = "excluded by the deterministic cycle-breaking view rule",
      }
    end
  end
  -- dangling_reference: a reference to an object absent from the store -
  -- the red link that says "this page is wanted".
  for _, oid in ipairs(self.object_order) do
    local obj = self.objects[oid]
    local refs = {}
    if obj["type"] == "causal_relation_object" then
      for _, list_field in ipairs({ "causes", "effects", "context", "mechanism" }) do
        for _, ref in ipairs(obj[list_field] or {}) do
          refs[#refs + 1] = ref
        end
      end
      if obj["refines"] ~= nil then refs[#refs + 1] = obj["refines"] end
    elseif obj["type"] == "realizable" then
      refs[#refs + 1] = obj["bearer"]
    end
    for _, ref in ipairs(refs) do
      if ref and self.objects[ref] == nil then
        out[#out + 1] = { id = oid, kind = "dangling_reference", ref = ref }
      end
    end
  end
  -- conflict: pairs of claims satisfying the formal test (rule 6).
  local cros = {}
  for _, oid in ipairs(self.object_order) do
    local obj = self.objects[oid]
    if obj["type"] == "causal_relation_object" then cros[#cros + 1] = obj end
  end
  for i = 1, #cros do
    for j = i + 1, #cros do
      if semantics.conflicts(cros[i], cros[j]) then
        out[#out + 1] = {
          kind = "conflict", a = cros[i]["id"], b = cros[j]["id"],
        }
      end
    end
  end
  if kind ~= nil then
    local filtered = {}
    for _, g in ipairs(out) do
      if g.kind == kind then filtered[#filtered + 1] = g end
    end
    out = filtered
  end
  return out
end

return store

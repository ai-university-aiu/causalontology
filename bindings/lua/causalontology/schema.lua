-- schema.lua - validation against spec/schema/*.schema.json.
--
-- A deliberately small interpreter for exactly the JSON Schema keywords the
-- eight Causalontology schemas use: type, const, enum, pattern, required,
-- properties, additionalProperties, items, minItems, minLength, minimum,
-- maximum, oneOf, and local $ref (#/$defs/...).  "format" is treated as an
-- annotation, as the 2020-12 draft does by default.
--
-- Lua has no regex engine, and needs none here: the schemas use only four
-- anchored pattern families, so pattern_matches() below is a small dedicated
-- validator that recognizes each family from the pattern text itself:
--   ^[0-9a-f]{N}$                    a fixed-length lowercase hex string
--   ^pre:[0-9a-f]{64}$               one prefixed 64-hex identifier
--   ^(pre1|pre2|...):[0-9a-f]{64}$   an alternation of prefixes
--   ^[a-z][a-z0-9_]*$                a lowercase snake_case label (this one
--                                    is a valid Lua pattern verbatim)
-- Any pattern outside these families raises, so a future schema change
-- cannot silently pass unvalidated.

local json = require("causalontology.json")

local schema = {}

local SCHEMA_FILES = {
  cro = "cro.schema.json",
  occurrent = "occurrent.schema.json",
  continuant = "continuant.schema.json",
  realizable = "realizable.schema.json",
  assertion = "assertion.schema.json",
  enrichment = "enrichment.schema.json",
  retraction = "retraction.schema.json",
  succession = "succession.schema.json",
}

local cache = {}

-- The spec/schema directory: CAUSALONTOLOGY_SPEC overrides, else a caller
-- (the conformance runner) sets schema.spec_dir before the first load.
schema.spec_dir = nil

local function schema_dir()
  local env = os.getenv("CAUSALONTOLOGY_SPEC")
  if env then return env .. "/schema" end
  if schema.spec_dir then return schema.spec_dir .. "/schema" end
  error("set CAUSALONTOLOGY_SPEC or schema.spec_dir to the spec/ directory", 0)
end

function schema.load_schema(kind)
  local file = SCHEMA_FILES[kind]
  if not file then error("unknown kind: " .. tostring(kind), 0) end
  if not cache[kind] then
    local path = schema_dir() .. "/" .. file
    local f = assert(io.open(path, "rb"), "cannot open schema " .. path)
    local text = f:read("a")
    f:close()
    cache[kind] = json.decode(text)
  end
  return cache[kind]
end

-- Follow local $ref pointers (#/$defs/...) inside the schema document.
local function resolve(node, root)
  while json.is_object(node) and node["$ref"] ~= nil do
    local ref = node["$ref"]
    if ref:sub(1, 2) ~= "#/" then
      error("only local $ref supported: " .. ref, 0)
    end
    local cursor = root
    for part in ref:sub(3):gmatch("[^/]+") do
      cursor = cursor[part]
    end
    node = cursor
  end
  return node
end

-- The dedicated, regex-free matcher for the schema pattern families.
local function pattern_matches(pattern, value)
  -- family 1: ^[0-9a-f]{N}$ - fixed-length lowercase hex
  local n = pattern:match("^%^%[0%-9a%-f%]{(%d+)}%$$")
  if n then
    return #value == tonumber(n) and value:match("^[0-9a-f]*$") ~= nil
  end
  -- families 2 and 3: ^pre:[0-9a-f]{64}$ / ^(pre1|pre2):[0-9a-f]{64}$
  local prefixes = pattern:match("^%^%(([%w|]+)%):%[0%-9a%-f%]{64}%$$")
                or pattern:match("^%^(%w+):%[0%-9a%-f%]{64}%$$")
  if prefixes then
    local scheme, hex = value:match("^(%w+):([0-9a-f]*)$")
    if not scheme or #hex ~= 64 then return false end
    for candidate in prefixes:gmatch("[^|]+") do
      if candidate == scheme then return true end
    end
    return false
  end
  -- family 4: ^[a-z][a-z0-9_]*$ - a valid Lua pattern verbatim
  if pattern == "^[a-z][a-z0-9_]*$" then
    return value:match("^[a-z][a-z0-9_]*$") ~= nil
  end
  error("unsupported schema pattern: " .. pattern, 0)
end

local function type_ok(value, t)
  if t == "object" then return json.is_object(value) end
  if t == "array" then return json.is_array(value) end
  if t == "string" then return type(value) == "string" end
  if t == "number" then return type(value) == "number" end
  if t == "boolean" then return type(value) == "boolean" end
  error("unsupported schema type: " .. tostring(t), 0)
end

local check  -- forward declaration

check = function(value, node, root, path, errors)
  node = resolve(node, root)

  if node["oneOf"] ~= nil then
    local passing = 0
    for _, sub in ipairs(node["oneOf"]) do
      local suberrs = {}
      check(value, sub, root, path, suberrs)
      if #suberrs == 0 then passing = passing + 1 end
    end
    if passing ~= 1 then
      errors[#errors + 1] = string.format(
        "%s: matches %d of the oneOf branches (need exactly 1)", path, passing)
    end
    return
  end

  local t = node["type"]
  if t ~= nil then
    if not type_ok(value, t) then
      errors[#errors + 1] = string.format("%s: expected %s", path, t)
      return
    end
  end

  if node["const"] ~= nil and not json.deep_equal(value, node["const"]) then
    errors[#errors + 1] = string.format(
      "%s: must equal %s", path, tostring(node["const"]))
  end
  if node["enum"] ~= nil then
    local found = false
    for _, candidate in ipairs(node["enum"]) do
      if value == candidate then found = true break end
    end
    if not found then
      errors[#errors + 1] = string.format(
        "%s: %s not in enumeration", path, tostring(value))
    end
  end
  if node["pattern"] ~= nil and type(value) == "string" then
    if not pattern_matches(node["pattern"], value) then
      errors[#errors + 1] = string.format(
        "%s: %q does not match %s", path, value, node["pattern"])
    end
  end
  if node["minLength"] ~= nil and type(value) == "string" then
    if #value < node["minLength"] then
      errors[#errors + 1] = string.format("%s: shorter than minLength", path)
    end
  end
  if node["minimum"] ~= nil and type(value) == "number" then
    if value < node["minimum"] then
      errors[#errors + 1] = string.format(
        "%s: below minimum %s", path, tostring(node["minimum"]))
    end
  end
  if node["maximum"] ~= nil and type(value) == "number" then
    if value > node["maximum"] then
      errors[#errors + 1] = string.format(
        "%s: above maximum %s", path, tostring(node["maximum"]))
    end
  end

  if json.is_array(value) then
    if node["minItems"] ~= nil and #value < node["minItems"] then
      errors[#errors + 1] = string.format(
        "%s: fewer than %d items", path, node["minItems"])
    end
    if node["items"] ~= nil then
      for i, item in ipairs(value) do
        -- 0-based item paths, matching the Python binding's messages
        check(item, node["items"], root,
              string.format("%s[%d]", path, i - 1), errors)
      end
    end
  end

  if json.is_object(value) then
    local props = node["properties"] or json.new_object()
    if node["required"] ~= nil then
      for _, req in ipairs(node["required"]) do
        if value[req] == nil then
          errors[#errors + 1] = string.format(
            "%s: required property '%s' missing", path, req)
        end
      end
    end
    if node["additionalProperties"] == false then
      for _, key in ipairs(json.keys(value)) do
        if props[key] == nil then
          errors[#errors + 1] = string.format(
            "%s: additional property '%s'", path, key)
        end
      end
    end
    for _, key in ipairs(json.keys(props)) do
      if value[key] ~= nil then
        check(value[key], props[key], root, path .. "." .. key, errors)
      end
    end
  end
end

-- (ok, reasons) - structural validity against the kind's JSON Schema.
function schema.validate_schema(obj, kind)
  local canonical = require("causalontology.canonical")
  kind = kind or canonical.infer_kind(obj)
  local root = schema.load_schema(kind)
  local errors = {}
  check(obj, root, root, "$", errors)
  return #errors == 0, errors
end

return schema

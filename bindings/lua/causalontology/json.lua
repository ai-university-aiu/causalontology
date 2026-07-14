-- json.lua - a shape-preserving JSON layer for causalontology-lua.
--
-- Lua tables give string keys no order and cannot tell an empty array from
-- an empty object, and plain tonumber() would erase the integer-versus-
-- decimal source distinction the canonicalizer needs.  This module therefore
-- decodes JSON into:
--
--   * objects: tables tagged with a private ORDER key holding the insertion
--     order of their string keys (mirroring Python's insertion-ordered dict),
--   * arrays:  tables tagged with a private IS_ARRAY key,
--   * numbers: Lua 5.4 integers when the literal carries no '.', 'e' or 'E'
--     (via math.tointeger), Lua floats otherwise,
--   * null:    the json.null sentinel (Lua nil would delete the key).
--
-- Every other module iterates objects only through json.keys(), never
-- through pairs(), so behavior is deterministic everywhere store.py
-- iterates dicts (objects, records, cycle-finder nodes, view buckets).

local json = {}

-- Private, non-string sentinel keys: they can never collide with JSON keys.
json.ORDER = setmetatable({}, { __tostring = function() return "<order>" end })
json.IS_ARRAY = setmetatable({}, { __tostring = function() return "<array>" end })
json.null = setmetatable({}, { __tostring = function() return "null" end })

-- ---------------------------------------------------------------- objects

-- A new, empty, insertion-ordered object.
function json.new_object()
  local t = {}
  t[json.ORDER] = {}
  return t
end

function json.is_object(t)
  return type(t) == "table" and rawget(t, json.ORDER) ~= nil
end

-- Set key k to value v, appending k to the order on first appearance.
-- Setting v = nil removes the key (and its order slot).
function json.set(obj, k, v)
  local order = obj[json.ORDER]
  if v == nil then
    if obj[k] ~= nil then
      obj[k] = nil
      for i, name in ipairs(order) do
        if name == k then table.remove(order, i) break end
      end
    end
    return obj
  end
  if obj[k] == nil then order[#order + 1] = k end
  obj[k] = v
  return obj
end

-- Set key k only when it is not already present (Python's dict.setdefault).
function json.setdefault(obj, k, v)
  if obj[k] == nil then json.set(obj, k, v) end
  return obj[k]
end

-- The insertion-order key list (the live array; callers must not mutate it).
function json.keys(obj)
  return obj[json.ORDER]
end

-- A shallow copy preserving insertion order (Python's dict(record)).
function json.copy_object(obj)
  local out = json.new_object()
  for _, k in ipairs(obj[json.ORDER]) do
    json.set(out, k, obj[k])
  end
  return out
end

-- Build an ordered object from a flat list of key, value pairs.
function json.obj(...)
  local out = json.new_object()
  local args = table.pack(...)
  for i = 1, args.n, 2 do
    json.set(out, args[i], args[i + 1])
  end
  return out
end

-- ----------------------------------------------------------------- arrays

-- A new tagged array, optionally wrapping an existing sequence.
function json.new_array(list)
  local t = list or {}
  t[json.IS_ARRAY] = true
  return t
end

function json.is_array(t)
  return type(t) == "table" and rawget(t, json.IS_ARRAY) ~= nil
end

-- A shallow copy of a tagged array.
function json.copy_array(arr)
  local out = json.new_array()
  for i, v in ipairs(arr) do out[i] = v end
  return out
end

-- ------------------------------------------------------------ deep equal

-- Deep structural equality with Python semantics: objects compare by key
-- set and values (order-insensitive), arrays elementwise, and 1 == 1.0.
function json.deep_equal(a, b)
  if a == b then return true end
  if json.is_object(a) and json.is_object(b) then
    local ka, kb = json.keys(a), json.keys(b)
    if #ka ~= #kb then return false end
    for _, k in ipairs(ka) do
      if b[k] == nil or not json.deep_equal(a[k], b[k]) then return false end
    end
    return true
  end
  if json.is_array(a) and json.is_array(b) then
    if #a ~= #b then return false end
    for i = 1, #a do
      if not json.deep_equal(a[i], b[i]) then return false end
    end
    return true
  end
  return false
end

-- ----------------------------------------------------------------- parser

local function parse_error(text, pos, why)
  error(string.format("JSON parse error at byte %d: %s", pos, why), 0)
end

local function skip_ws(text, pos)
  local _, stop = text:find("^[ \t\r\n]*", pos)
  return stop + 1
end

-- Encode one Unicode code point as UTF-8 bytes (for \uXXXX escapes).
local function utf8_encode(cp)
  return utf8.char(cp)
end

local function parse_string(text, pos)
  -- pos points at the opening quote
  local out, i = {}, pos + 1
  while true do
    local c = text:sub(i, i)
    if c == "" then parse_error(text, i, "unterminated string") end
    if c == '"' then
      return table.concat(out), i + 1
    elseif c == "\\" then
      local esc = text:sub(i + 1, i + 1)
      if esc == '"' then out[#out + 1] = '"'; i = i + 2
      elseif esc == "\\" then out[#out + 1] = "\\"; i = i + 2
      elseif esc == "/" then out[#out + 1] = "/"; i = i + 2
      elseif esc == "b" then out[#out + 1] = "\b"; i = i + 2
      elseif esc == "f" then out[#out + 1] = "\f"; i = i + 2
      elseif esc == "n" then out[#out + 1] = "\n"; i = i + 2
      elseif esc == "r" then out[#out + 1] = "\r"; i = i + 2
      elseif esc == "t" then out[#out + 1] = "\t"; i = i + 2
      elseif esc == "u" then
        local hex = text:sub(i + 2, i + 5)
        if not hex:match("^%x%x%x%x$") then
          parse_error(text, i, "bad \\u escape")
        end
        local cp = tonumber(hex, 16)
        i = i + 6
        -- combine a UTF-16 surrogate pair into one code point
        if cp >= 0xD800 and cp <= 0xDBFF and text:sub(i, i + 1) == "\\u" then
          local hex2 = text:sub(i + 2, i + 5)
          local lo = tonumber(hex2, 16)
          if lo and lo >= 0xDC00 and lo <= 0xDFFF then
            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)
            i = i + 6
          end
        end
        out[#out + 1] = utf8_encode(cp)
      else
        parse_error(text, i, "bad escape")
      end
    else
      out[#out + 1] = c
      i = i + 1
    end
  end
end

local parse_value  -- forward declaration

local function parse_number(text, pos)
  -- capture the whole numeric literal so its shape decides the Lua subtype
  local lit = text:match("^-?%d+%.?%d*[eE]?[%+%-]?%d*", pos)
  -- trim any over-capture from the loose pattern above
  lit = lit:match("^-?%d+%.%d+[eE][%+%-]?%d+")
        or lit:match("^-?%d+%.%d+")
        or lit:match("^-?%d+[eE][%+%-]?%d+")
        or lit:match("^-?%d+")
  if not lit then parse_error(text, pos, "bad number") end
  local n = tonumber(lit)
  -- the shape rule: integer when the literal has no '.', 'e' or 'E'
  if not lit:find("[%.eE]") then
    n = math.tointeger(n) or n
  end
  return n, pos + #lit
end

local function parse_array(text, pos)
  local arr = json.new_array()
  pos = skip_ws(text, pos + 1)
  if text:sub(pos, pos) == "]" then return arr, pos + 1 end
  while true do
    local v
    v, pos = parse_value(text, pos)
    arr[#arr + 1] = v
    pos = skip_ws(text, pos)
    local c = text:sub(pos, pos)
    if c == "," then
      pos = skip_ws(text, pos + 1)
    elseif c == "]" then
      return arr, pos + 1
    else
      parse_error(text, pos, "expected ',' or ']'")
    end
  end
end

local function parse_object(text, pos)
  local obj = json.new_object()
  pos = skip_ws(text, pos + 1)
  if text:sub(pos, pos) == "}" then return obj, pos + 1 end
  while true do
    if text:sub(pos, pos) ~= '"' then
      parse_error(text, pos, "expected object key")
    end
    local k, v
    k, pos = parse_string(text, pos)
    pos = skip_ws(text, pos)
    if text:sub(pos, pos) ~= ":" then parse_error(text, pos, "expected ':'") end
    pos = skip_ws(text, pos + 1)
    v, pos = parse_value(text, pos)
    json.set(obj, k, v)
    pos = skip_ws(text, pos)
    local c = text:sub(pos, pos)
    if c == "," then
      pos = skip_ws(text, pos + 1)
    elseif c == "}" then
      return obj, pos + 1
    else
      parse_error(text, pos, "expected ',' or '}'")
    end
  end
end

parse_value = function(text, pos)
  pos = skip_ws(text, pos)
  local c = text:sub(pos, pos)
  if c == "{" then return parse_object(text, pos) end
  if c == "[" then return parse_array(text, pos) end
  if c == '"' then return parse_string(text, pos) end
  if c == "t" and text:sub(pos, pos + 3) == "true" then return true, pos + 4 end
  if c == "f" and text:sub(pos, pos + 4) == "false" then return false, pos + 5 end
  if c == "n" and text:sub(pos, pos + 3) == "null" then return json.null, pos + 4 end
  if c == "-" or c:match("%d") then return parse_number(text, pos) end
  parse_error(text, pos, "unexpected character " .. string.format("%q", c))
end

-- Decode a JSON document into the shape-preserving representation above.
function json.decode(text)
  local value, pos = parse_value(text, 1)
  pos = skip_ws(text, pos)
  if pos <= #text then parse_error(text, pos, "trailing garbage") end
  return value
end

return json

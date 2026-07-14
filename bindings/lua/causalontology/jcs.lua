-- jcs.lua - RFC 8785 (JSON Canonicalization Scheme) serialization.
--
-- Ports the serialization half of bindings/python/causalontology/canonical.py:
-- sorted keys, minimal string escaping, and ECMAScript-style canonical
-- numbers (1.0 -> "1", 0.7 stays "0.7", exponents as e-7 / e+21, never e-07).
--
-- Lua strings are byte arrays; JCS escaping touches only bytes below 0x20
-- plus '"' and '\\', so operating bytewise is exactly correct for UTF-8 text.
-- Key sorting is bytewise, which for UTF-8 equals code-point order and, for
-- the ASCII keys the standard uses, equals the RFC's UTF-16 code-unit order.

local json = require("causalontology.json")

local jcs = {}

-- The two-character escapes RFC 8785 mandates.
local ESCAPES = {
  ['"'] = '\\"', ["\\"] = "\\\\", ["\b"] = "\\b", ["\t"] = "\\t",
  ["\n"] = "\\n", ["\f"] = "\\f", ["\r"] = "\\r",
}

local function jcs_string(s)
  local parts = { '"' }
  for i = 1, #s do
    local ch = s:sub(i, i)
    local esc = ESCAPES[ch]
    if esc then
      parts[#parts + 1] = esc
    elseif ch:byte() < 0x20 then
      parts[#parts + 1] = string.format("\\u%04x", ch:byte())
    else
      parts[#parts + 1] = ch
    end
  end
  parts[#parts + 1] = '"'
  return table.concat(parts)
end

-- The shortest decimal string that round-trips to exactly this float
-- (what Python's repr and ES6's ToString produce for our value range).
local function shortest_float(x)
  for _, fmt in ipairs({ "%.15g", "%.16g", "%.17g" }) do
    local s = string.format(fmt, x)
    if tonumber(s) == x then return s end
  end
  return string.format("%.17g", x)  -- unreachable: %.17g always round-trips
end

-- Normalize a C-style exponent to the ES6 shape: 1e-07 -> 1e-7, 1e+21 stays.
local function normalize_exponent(s)
  local mant, sign, digits = s:match("^(.-)[eE]([%+%-]?)(%d+)$")
  if not mant then return s end
  digits = digits:gsub("^0+", "")
  if digits == "" then digits = "0" end
  if sign == "" or sign == "+" then sign = "+" end
  return mant .. "e" .. sign .. digits
end

local function jcs_number(n)
  if math.type(n) == "integer" then
    return string.format("%d", n)
  end
  -- floats from here on
  if n ~= n or n == math.huge or n == -math.huge then
    error("NaN and Infinity are not permitted (RFC 8785)", 0)
  end
  if n == 0 then return "0" end
  -- an integral float below 1e21 prints as a plain integer (ES6 rule)
  if n == math.floor(n) and math.abs(n) < 1e21 then
    return string.format("%.0f", n)  -- exact below 2**53, our whole range
  end
  return normalize_exponent(shortest_float(n))
end

local function serialize(value)
  if value == json.null then
    return "null"
  elseif value == true then
    return "true"
  elseif value == false then
    return "false"
  elseif type(value) == "number" then
    return jcs_number(value)
  elseif type(value) == "string" then
    return jcs_string(value)
  elseif json.is_array(value) then
    local parts = {}
    for i, v in ipairs(value) do parts[i] = serialize(v) end
    return "[" .. table.concat(parts, ",") .. "]"
  elseif json.is_object(value) then
    -- sort a copy of the key list; bytewise order (see the module header)
    local keys = {}
    for i, k in ipairs(json.keys(value)) do keys[i] = k end
    table.sort(keys)
    local parts = {}
    for i, k in ipairs(keys) do
      parts[i] = jcs_string(k) .. ":" .. serialize(value[k])
    end
    return "{" .. table.concat(parts, ",") .. "}"
  end
  error("cannot canonicalize a " .. type(value), 0)
end

-- The RFC 8785 canonical text of a decoded JSON value.
function jcs.serialize(value)
  return serialize(value)
end

return jcs

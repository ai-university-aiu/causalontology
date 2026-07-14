-- causalontology - the Lua binding of the Causalontology standard.
--
-- A faithful port of causalontology-py: pure Lua 5.4, zero dependencies,
-- conformant when it passes every vector in conformance/vectors/ (run
-- bindings/lua/conformance.lua).
--
-- Causalontology is a verb-first noun-hosting ontology: reality is what
-- happens, and things are its participants.

local canonical = require("causalontology.canonical")
local schema = require("causalontology.schema")
local semantics = require("causalontology.semantics")
local signing = require("causalontology.signing")
local store = require("causalontology.store")
local json = require("causalontology.json")
local jcs = require("causalontology.jcs")
local sha2 = require("causalontology.sha2")
local ed25519 = require("causalontology.ed25519")

local M = {}

M._VERSION = "1.0.0"  -- specification 1.0.0 (vectors frozen 2026-07-13)

M.canonicalize = canonical.canonicalize
M.identify = canonical.identify
M.identity_bearing = canonical.identity_bearing
M.infer_kind = canonical.infer_kind
M.validate_schema = schema.validate_schema
M.validate_semantics = semantics.validate_semantics
M.is_partial = semantics.is_partial
M.admissible = semantics.admissible
M.conflicts = semantics.conflicts
M.refinement_valid = semantics.refinement_valid
M.hierarchy_consistent = semantics.hierarchy_consistent
M.UNIT_SECONDS = semantics.UNIT_SECONDS
M.keypair_from_seed = signing.keypair_from_seed
M.sign_record = signing.sign_record
M.verify_record = signing.verify_record
M.new_store = store.new
M.is_rejected = store.is_rejected

-- the underlying modules, for callers that need them directly
M.json = json
M.jcs = jcs
M.sha2 = sha2
M.ed25519 = ed25519
M.schema = schema
M.store = store

return M

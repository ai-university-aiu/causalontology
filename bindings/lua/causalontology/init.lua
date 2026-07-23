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

M._VERSION = "4.0.0"  -- specification 4.0.0 (attitude, predicted_occurrence, prediction_error)

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
-- 2.0.0 normative algorithms and rules
M.bridge_closure = semantics.bridge_closure
M.classify_cro = semantics.classify_cro
M.endpoints_mixed = semantics.endpoints_mixed
M.skip_gaps = semantics.skip_gaps
M.to_seconds = semantics.to_seconds
M.delay_within_window = semantics.delay_within_window
M.bridge_wellformed = semantics.bridge_wellformed
M.conduit_wellformed = semantics.conduit_wellformed
M.state_gaps = semantics.state_gaps
M.covering_law_mismatch = semantics.covering_law_mismatch
M.retrocausal = semantics.retrocausal
M.has_cycle = semantics.has_cycle
-- 3.0.0 additions
M.ORDINAL_UNITS = semantics.ORDINAL_UNITS
M.seam_wellformed = semantics.seam_wellformed
M.seam_home = semantics.seam_home
-- 4.0.0 additions
M.prediction_pairing_mismatch = semantics.prediction_pairing_mismatch
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

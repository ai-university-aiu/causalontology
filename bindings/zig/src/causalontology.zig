//! causalontology - the Zig binding of the Causalontology standard.
//!
//! Standard library only: std.crypto.hash.sha2.Sha256 for identity,
//! std.crypto.sign.Ed25519 for provenance, std.json for the lossless value
//! layer. Conformant when it passes every vector in conformance/vectors/
//! (run bindings/zig/run_conformance.sh from the repository root).
//!
//! Causalontology is a verb-first noun-hosting ontology: reality is what
//! happens, and things are its participants.

/// Specification 4.0.0 (vectors frozen 2026-07-22; 137 vectors, twenty-one
/// kinds). Adds, over 2.0.0, the folded 3.0.0 delta (the ordinal ticks unit,
/// the cross_stratal_seam kind with Algorithm F, the conduit realized_by
/// reference) and the 4.0.0 delta (the attitude, predicted_occurrence, and
/// prediction_error kinds; Rules 24 and 25; the widened assertion about-ref).
pub const version = "4.0.0";

pub const jcs = @import("jcs.zig");
pub const canonical = @import("canonical.zig");
pub const schema = @import("schema.zig");
pub const semantics = @import("semantics.zig");
pub const signing = @import("signing.zig");
pub const store = @import("store.zig");

pub const canonicalize = canonical.canonicalize;
pub const identify = canonical.identify;
pub const identityBearing = canonical.identityBearing;
pub const inferKind = canonical.inferKind;
pub const validateSchema = schema.validateSchema;
pub const validateSemantics = semantics.validateSemantics;
pub const isPartial = semantics.isPartial;
pub const admissible = semantics.admissible;
pub const conflicts = semantics.conflicts;
pub const refinementValid = semantics.refinementValid;
pub const hierarchyConsistent = semantics.hierarchyConsistent;
// 3.0.0 / 4.0.0 additions.
pub const seamWellformed = semantics.seamWellformed;
pub const seamHome = semantics.seamHome;
pub const predictionPairingMismatch = semantics.predictionPairingMismatch;
pub const keypairFromSeed = signing.keypairFromSeed;
pub const signRecord = signing.signRecord;
pub const verifyRecord = signing.verifyRecord;
pub const Store = store.Store;

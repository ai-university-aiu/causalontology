//! causalontology - the Rust binding of the Causalontology standard.
//!
//! Causalontology is a verb-first noun-hosting ontology: reality is what
//! happens, and things are its participants. This crate implements the
//! full abstract operation set - RFC 8785 canonicalization, SHA-256
//! content-addressed identity, Ed25519 record signing, the twenty-one
//! embedded JSON Schemas, the semantic rules, and an in-memory conformant
//! store - and is conformant when it passes every vector in
//! conformance/vectors/ (cargo run --bin conformance).
//!
//! The schemas are embedded at compile time, so the library does no
//! filesystem access at run time and compiles unchanged to WebAssembly
//! (wasm32-unknown-unknown): one audited core for every host.

pub mod canonical;
pub mod schema;
pub mod semantics;
pub mod signing;
pub mod store;
pub mod wasm_abi;

pub use canonical::{canonicalize, identify, identity_bearing, infer_kind, jcs};
pub use schema::validate_schema;
pub use semantics::{admissible, bridge_closure, bridge_wellformed, classify_cro,
                    conduit_wellformed, conflicts, covering_law_mismatch,
                    delay_within_window, endpoints_mixed, has_cycle,
                    hierarchy_consistent, is_ordinal_unit, is_partial,
                    prediction_pairing_mismatch, refinement_valid, retrocausal,
                    seam_home, seam_wellformed, skip_gaps, state_gaps,
                    to_seconds, unit_seconds, validate_semantics};
pub use signing::{keypair_from_seed, sign_record, verify_record};
pub use store::{InMemoryStore, RejectedWrite};

/// The specification version this binding tracks.
pub const SPEC_VERSION: &str = "4.0.0";

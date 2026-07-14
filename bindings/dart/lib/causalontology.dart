/// causalontology - the Dart binding of the Causalontology standard.
///
/// A faithful port of causalontology-py, sharing the same conformance
/// suite: zero dependencies, conformant when it passes every vector in
/// conformance/vectors/ (run bin/conformance.dart).
///
/// Causalontology is a verb-first noun-hosting ontology: reality is what
/// happens, and things are its participants.
library;

export 'canonical.dart'
    show canonicalize, identify, identityBearing, inferKind, hexEncode, hexDecode;
export 'jcs.dart' show jcs;
export 'schema.dart' show validateSchema, deepEquals;
export 'semantics.dart'
    show
        validateSemantics,
        isPartial,
        admissible,
        conflicts,
        refinementValid,
        hierarchyConsistent,
        unitSeconds;
export 'signing.dart' show keypairFromSeed, signRecord, verifyRecord;
export 'store.dart' show InMemoryStore, RejectedWrite;

/// Specification 1.0.0 (vectors frozen 2026-07-13).
const String causalontologyVersion = '1.0.0';

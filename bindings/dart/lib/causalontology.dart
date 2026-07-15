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
        bridgeClosure,
        classifyCro,
        endpointsMixed,
        skipGaps,
        toSeconds,
        delayWithinWindow,
        bridgeWellformed,
        conduitWellformed,
        stateGaps,
        coveringLawMismatch,
        retrocausal,
        hasCycle,
        enrichmentFields,
        unitSeconds;
export 'signing.dart' show keypairFromSeed, signRecord, verifyRecord;
export 'store.dart' show InMemoryStore, RejectedWrite;

/// Specification 2.0.0 (whole-word re-mint; vectors frozen 2026-07-15).
const String causalontologyVersion = '2.0.0';

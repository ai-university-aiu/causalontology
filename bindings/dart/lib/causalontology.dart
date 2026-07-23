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
        seamWellformed,
        seamHome,
        conduitWellformed,
        stateGaps,
        coveringLawMismatch,
        predictionPairingMismatch,
        retrocausal,
        hasCycle,
        enrichmentFields,
        unitSeconds,
        ordinalUnits;
export 'signing.dart' show keypairFromSeed, signRecord, verifyRecord;
export 'store.dart' show InMemoryStore, RejectedWrite;

/// Specification 4.0.0 (attitude, predicted_occurrence, prediction_error).
const String causalontologyVersion = '4.0.0';

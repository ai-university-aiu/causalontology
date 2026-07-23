<?php

/* causalontology - the PHP binding of the Causalontology standard.
 *
 * A faithful port of causalontology-py (bindings/python/), sharing the same
 * conformance suite: bundled extensions only (sodium for Ed25519, hash for
 * SHA-256, json for parsing), zero Composer dependencies, conformant when it
 * passes every vector in conformance/vectors/ (run conformance.php).
 *
 * Causalontology is a verb-first noun-hosting ontology: reality is what
 * happens, and things are its participants.
 */

declare(strict_types=1);

namespace Causalontology;

/**
 * The binding's facade: the specification version it declares, and nothing
 * else - each concern lives in its own class (Jcs, Canonical, Signing,
 * SchemaValidator, Semantics, Store).
 */
final class Causalontology
{
    /** Specification 4.0.0 (attitude, predicted_occurrence, prediction_error). */
    public const VERSION = '4.0.0';

    /** A namespace holder, never an instance. */
    private function __construct()
    {
    }
}

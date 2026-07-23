<?php

/* Canonicalization and content-addressed identity.
 *
 * Implements the identity procedure of spec/identity.md:
 *   1. take the object as JSON,
 *   2. keep only the identity-bearing fields for its kind (with "type"
 *      injected),
 *   3. serialize with the JSON Canonicalization Scheme (RFC 8785),
 *   4. hash with SHA-256,
 *   5. identifier = scheme + ":" + lowercase hex digest.
 */

declare(strict_types=1);

namespace Causalontology;

final class Canonical
{
    /**
     * The identity-bearing fields of each of the twenty-one kinds (3.0.0 adds
     * the cross_stratal_seam; the conduit gains realized_by; 4.0.0 adds the
     * attitude, the predicted_occurrence, and the prediction_error - all
     * additive and identity-preserving, so a record that omits a new field
     * keeps its earlier identifier byte-for-byte, and the new kinds open new
     * identity schemes that disturb no existing record). "type" is always
     * injected, so it is not listed here. Order does not matter (JCS sorts
     * keys). 2.0.0: every identifier scheme is a whole English word
     * (Principle P7); scheme = type value = id prefix.
     */
    public const IDENTITY_FIELDS = [
        // ---- type tier ----
        'occurrent'  => ['label', 'category', 'stratum'],
        'causal_relation_object' => ['causes', 'effects', 'mechanism', 'temporal',
                                     'modality', 'context', 'refines', 'skips'],
        'continuant' => ['label', 'category'],
        'realizable' => ['kind', 'bearer', 'label'],
        'stratum'    => ['label', 'scheme', 'ordinal', 'unit', 'governs'],
        'bridge'     => ['coarse', 'fine', 'relation'],
        'cross_stratal_seam' => ['source', 'target', 'mechanism_status', 'chain'],
        'port'       => ['bearer', 'label', 'direction', 'accepts', 'realizable'],
        'conduit'    => ['label', 'from', 'to', 'carries', 'transform', 'realized_by'],
        'quality'    => ['label', 'datatype', 'unit', 'stratum'],
        // ---- token tier ----
        'token_individual'   => ['instantiates', 'designator', 'part_of'],
        'token_occurrence'   => ['instantiates', 'interval', 'participants',
                                 'locus', 'observer'],
        'state_assertion'    => ['subject', 'quality', 'value', 'interval'],
        'token_causal_claim' => ['causes', 'effects', 'covering_law',
                                 'actual_delay', 'counterfactual'],
        'attitude'             => ['holder', 'attitude_type', 'content'],
        'predicted_occurrence' => ['instantiates', 'interval', 'predictor',
                                   'strength'],
        'prediction_error'     => ['predicted', 'observed', 'discrepancy'],
        // ---- provenance tier ----
        'assertion'  => ['about', 'source', 'evidence_type', 'evidence', 'strength',
                         'confidence', 'timestamp', 'evidenced_by'],
        'enrichment' => ['about', 'field', 'entry', 'source', 'timestamp'],
        'retraction' => ['retracts', 'source', 'timestamp'],
        'succession' => ['predecessor', 'successor', 'timestamp'],
    ];

    /** The identifier scheme prefix per kind (whole-word: scheme = kind). */
    public const PREFIX = [
        'occurrent'              => 'occurrent',
        'causal_relation_object' => 'causal_relation_object',
        'continuant'             => 'continuant',
        'realizable'             => 'realizable',
        'stratum'                => 'stratum',
        'bridge'                 => 'bridge',
        'cross_stratal_seam'     => 'cross_stratal_seam',
        'port'                   => 'port',
        'conduit'                => 'conduit',
        'quality'                => 'quality',
        'token_individual'       => 'token_individual',
        'token_occurrence'       => 'token_occurrence',
        'state_assertion'        => 'state_assertion',
        'token_causal_claim'     => 'token_causal_claim',
        'attitude'               => 'attitude',
        'predicted_occurrence'   => 'predicted_occurrence',
        'prediction_error'       => 'prediction_error',
        'assertion'              => 'assertion',
        'enrichment'             => 'enrichment',
        'retraction'             => 'retraction',
        'succession'             => 'succession',
    ];

    /** The inverse of PREFIX: scheme prefix back to kind. */
    public const KIND_OF_PREFIX = [
        'occurrent'              => 'occurrent',
        'causal_relation_object' => 'causal_relation_object',
        'continuant'             => 'continuant',
        'realizable'             => 'realizable',
        'stratum'                => 'stratum',
        'bridge'                 => 'bridge',
        'cross_stratal_seam'     => 'cross_stratal_seam',
        'port'                   => 'port',
        'conduit'                => 'conduit',
        'quality'                => 'quality',
        'token_individual'       => 'token_individual',
        'token_occurrence'       => 'token_occurrence',
        'state_assertion'        => 'state_assertion',
        'token_causal_claim'     => 'token_causal_claim',
        'attitude'               => 'attitude',
        'predicted_occurrence'   => 'predicted_occurrence',
        'prediction_error'       => 'prediction_error',
        'assertion'              => 'assertion',
        'enrichment'             => 'enrichment',
        'retraction'             => 'retraction',
        'succession'             => 'succession',
    ];

    /** A static utility class, never an instance. */
    private function __construct()
    {
    }

    /** Infer an object's kind from its type field, id prefix, or shape. */
    public static function inferKind(array $obj): string
    {
        if (array_key_exists('type', $obj)) {
            return (string) $obj['type'];
        }
        if (isset($obj['id']) && is_string($obj['id']) && str_contains($obj['id'], ':')) {
            $prefix = explode(':', $obj['id'], 2)[0];
            if (isset(self::KIND_OF_PREFIX[$prefix])) {
                return self::KIND_OF_PREFIX[$prefix];
            }
        }
        if (array_key_exists('coarse', $obj) && array_key_exists('fine', $obj)) {
            return 'bridge';
        }
        if (array_key_exists('causes', $obj) && array_key_exists('effects', $obj)) {
            return 'causal_relation_object';
        }
        if (array_key_exists('retracts', $obj)) {
            return 'retraction';
        }
        if (array_key_exists('predecessor', $obj) && array_key_exists('successor', $obj)) {
            return 'succession';
        }
        if (array_key_exists('field', $obj) && array_key_exists('entry', $obj)) {
            return 'enrichment';
        }
        if (array_key_exists('evidence_type', $obj)
                || (array_key_exists('about', $obj) && array_key_exists('confidence', $obj))) {
            return 'assertion';
        }
        if (array_key_exists('kind', $obj) && array_key_exists('bearer', $obj)) {
            return 'realizable';
        }
        throw new \InvalidArgumentException(
            'cannot infer kind (occurrents and continuants share a shape); '
            . 'pass kind explicitly');
    }

    /**
     * The identity-bearing subset of an object, with type always present.
     *
     * @return array{0: string, 1: array} [kind, identity-bearing subset]
     */
    public static function identityBearing(array $obj, ?string $kind = null): array
    {
        $kind ??= self::inferKind($obj);
        if (!isset(self::IDENTITY_FIELDS[$kind])) {
            throw new \InvalidArgumentException('unknown kind: ' . var_export($kind, true));
        }
        $out = ['type' => $kind];
        foreach (self::IDENTITY_FIELDS[$kind] as $field) {
            if (array_key_exists($field, $obj)) {
                $out[$field] = $obj[$field];
            }
        }
        return [$kind, $out];
    }

    /** The RFC 8785 identity-bearing bytes of an object. */
    public static function canonicalize(array $obj, ?string $kind = null): string
    {
        [, $identityBearing] = self::identityBearing($obj, $kind);
        return Jcs::serialize($identityBearing);
    }

    /** The content-addressed identifier: scheme + ':' + SHA-256 hex. */
    public static function identify(array $obj, ?string $kind = null): string
    {
        [$kind, $identityBearing] = self::identityBearing($obj, $kind);
        $digest = hash('sha256', Jcs::serialize($identityBearing));
        return self::PREFIX[$kind] . ':' . $digest;
    }
}

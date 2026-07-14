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
    /** The identity-bearing fields per kind (spec/identity.md). */
    public const IDENTITY_FIELDS = [
        'occurrent'  => ['label', 'category'],
        'cro'        => ['causes', 'effects', 'mechanism', 'temporal', 'modality',
                         'context', 'refines'],
        'continuant' => ['label', 'category'],
        'realizable' => ['kind', 'bearer'],
        'assertion'  => ['about', 'source', 'evidence_type', 'evidence', 'strength',
                         'confidence', 'timestamp'],
        'enrichment' => ['about', 'field', 'entry', 'source', 'timestamp'],
        'retraction' => ['retracts', 'source', 'timestamp'],
        'succession' => ['predecessor', 'successor', 'timestamp'],
    ];

    /** The identifier scheme prefix per kind. */
    public const PREFIX = [
        'occurrent'  => 'occ',
        'cro'        => 'cro',
        'continuant' => 'cnt',
        'realizable' => 'rlz',
        'assertion'  => 'ast',
        'enrichment' => 'enr',
        'retraction' => 'ret',
        'succession' => 'suc',
    ];

    /** The inverse of PREFIX: scheme prefix back to kind. */
    public const KIND_OF_PREFIX = [
        'occ' => 'occurrent',
        'cro' => 'cro',
        'cnt' => 'continuant',
        'rlz' => 'realizable',
        'ast' => 'assertion',
        'enr' => 'enrichment',
        'ret' => 'retraction',
        'suc' => 'succession',
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
        if (array_key_exists('causes', $obj) && array_key_exists('effects', $obj)) {
            return 'cro';
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

<?php

/* The semantic rules beyond the schemas (spec/semantics.md).
 *
 * Local rules are checked here; store-context rules (materialized
 * acyclicity, retraction lineage) live in Store where the context exists.
 */

declare(strict_types=1);

namespace Causalontology;

final class Semantics
{
    /** Rule 4: the fixed unit-conversion constants (average Gregorian values). */
    public const UNIT_SECONDS = [
        'instant' => 0,
        'seconds' => 1,
        'minutes' => 60,
        'hours'   => 3600,
        'days'    => 86400,
        'weeks'   => 604800,
        'months'  => 2629746,
        'years'   => 31556952,
    ];

    /** Rule 12: enrichment field-to-kind validity and entry shapes. */
    public const ENRICHMENT_FIELDS = [
        'aliases'      => [['occurrent', 'continuant'], 'alias'],
        'participants' => [['occurrent'],               'continuant'],
        'subsumes'     => [['continuant'],              'continuant'],
        'part_of'      => [['continuant'],              'continuant'],
        'realized_in'  => [['realizable'],              'occurrent'],
    ];

    /** The optional CRO fields, in the order is_partial reports them. */
    public const CRO_OPTIONAL_FIELDS = ['mechanism', 'temporal', 'modality', 'context'];

    /** The positive modalities of the rule 6 conflict test. */
    private const POSITIVE_MODALITIES = ['necessary', 'sufficient', 'contributory'];

    /** A static utility class, never an instance. */
    private function __construct()
    {
    }

    /** The kind an identifier's scheme prefix names, or null. */
    private static function kindOfId(string $identifier): ?string
    {
        return Canonical::KIND_OF_PREFIX[explode(':', $identifier, 2)[0]] ?? null;
    }

    /**
     * [ok, reasons] - the locally checkable semantic rules.
     *
     * @return array{0: bool, 1: list<string>}
     */
    public static function validateSemantics(array $obj, ?string $kind = null): array
    {
        $kind ??= Canonical::inferKind($obj);
        $errors = [];

        if ($kind === 'causal_relation_object') {
            $temporal = $obj['temporal'] ?? null;
            if (is_array($temporal)
                    && ($temporal['minimum_delay'] ?? null) !== null
                    && ($temporal['maximum_delay'] ?? null) !== null
                    && $temporal['minimum_delay'] > $temporal['maximum_delay']) {
                $errors[] = 'minimum_delay must be <= maximum_delay';
            }
            $oid = $obj['id'] ?? null;
            if (is_string($oid) && $oid !== ''
                    && is_array($obj['mechanism'] ?? null)
                    && in_array($oid, $obj['mechanism'], true)) {
                $errors[] = 'mechanism must be acyclic '
                          . '(a Causal Relation Object may not contain itself)';
            }
            if (is_string($oid) && $oid !== '' && ($obj['refines'] ?? null) === $oid) {
                $errors[] = 'refines must be acyclic';
            }
        }

        if ($kind === 'enrichment') {
            $field = $obj['field'] ?? null;
            $about = $obj['about'] ?? '';
            $entry = $obj['entry'] ?? null;
            $spec = is_string($field) ? (self::ENRICHMENT_FIELDS[$field] ?? null) : null;
            if ($spec !== null) {
                [$legalKinds, $shape] = $spec;
                $aboutKind = is_string($about) ? self::kindOfId($about) : null;
                if ($aboutKind !== null && !in_array($aboutKind, $legalKinds, true)) {
                    $errors[] = sprintf('%s is not a legal field for a %s (rule 12)',
                                        $field, $aboutKind);
                }
                if ($shape === 'alias') {
                    if (!(Jcs::isMap($entry)
                            && array_key_exists('lang', $entry)
                            && array_key_exists('text', $entry))) {
                        $errors[] = 'an aliases entry must be a '
                                  . 'language-tagged text object';
                    }
                } elseif (!(is_string($entry) && str_starts_with($entry, $shape . ':'))) {
                    $errors[] = sprintf('a %s entry must be a %s: identifier',
                                        $field, $shape);
                }
            }
        }

        return [$errors === [], $errors];
    }

    /**
     * [partial, missing] - which optional CRO fields are unspecified.
     *
     * @return array{0: bool, 1: list<string>}
     */
    public static function isPartial(array $cro): array
    {
        $missing = [];
        foreach (self::CRO_OPTIONAL_FIELDS as $field) {
            if (!array_key_exists($field, $cro)) {
                $missing[] = $field;
            }
        }
        return [$missing !== [], $missing];
    }

    /** Rule 4: temporal admissibility with the fixed constants. */
    public static function admissible(array $cro, int|float $elapsedSeconds): bool
    {
        $temporal = $cro['temporal'] ?? null;
        if ($temporal === null) {
            return true; // no window imposes no constraint
        }
        $unit = self::UNIT_SECONDS[$temporal['unit']];
        $lo = $temporal['minimum_delay'] * $unit;
        $hi = $temporal['maximum_delay'] * $unit;
        return $lo <= $elapsedSeconds && $elapsedSeconds <= $hi;
    }

    /** A list of strings as a set: values become keys. */
    private static function asSet(array $items): array
    {
        $set = [];
        foreach ($items as $item) {
            $set[(string) $item] = true;
        }
        return $set;
    }

    /** True iff every key of set $a is present in set $b. */
    private static function isSubset(array $a, array $b): bool
    {
        foreach ($a as $key => $unused) {
            if (!isset($b[$key])) {
                return false;
            }
        }
        return true;
    }

    /** True iff the two sets hold the same keys. */
    private static function setsEqual(array $a, array $b): bool
    {
        return count($a) === count($b) && self::isSubset($a, $b);
    }

    /** Do the two windows overlap (absent counts as overlapping)? */
    private static function windowOverlap(array $a, array $b): bool
    {
        $ta = $a['temporal'] ?? null;
        $tb = $b['temporal'] ?? null;
        if ($ta === null || $tb === null) {
            return true; // either absent counts as overlapping
        }
        $ua = self::UNIT_SECONDS[$ta['unit']];
        $ub = self::UNIT_SECONDS[$tb['unit']];
        $loA = $ta['minimum_delay'] * $ua;
        $hiA = $ta['maximum_delay'] * $ua;
        $loB = $tb['minimum_delay'] * $ub;
        $hiB = $tb['maximum_delay'] * $ub;
        return $loA <= $hiB && $loB <= $hiA;
    }

    /** Are the contexts compatible (equal or one a subset of the other)? */
    private static function contextsCompatible(array $a, array $b): bool
    {
        $ca = $a['context'] ?? null;
        $cb = $b['context'] ?? null;
        if (empty($ca) || empty($cb)) {
            return true; // either absent (or empty)
        }
        $sa = self::asSet($ca);
        $sb = self::asSet($cb);
        return self::setsEqual($sa, $sb)
            || self::isSubset($sa, $sb)
            || self::isSubset($sb, $sa);
    }

    /** Rule 6: the formal conflict test. */
    public static function conflicts(array $a, array $b): bool
    {
        if (!self::setsEqual(self::asSet($a['causes']), self::asSet($b['causes']))) {
            return false;
        }
        if (!self::setsEqual(self::asSet($a['effects']), self::asSet($b['effects']))) {
            return false;
        }
        if (!self::contextsCompatible($a, $b)) {
            return false;
        }
        if (!self::windowOverlap($a, $b)) {
            return false;
        }
        $ma = $a['modality'] ?? null;
        $mb = $b['modality'] ?? null;
        return ($ma === 'preventive' && in_array($mb, self::POSITIVE_MODALITIES, true))
            || ($mb === 'preventive' && in_array($ma, self::POSITIVE_MODALITIES, true));
    }

    /**
     * Rule 3: [ok, reason] - is child a valid refinement of parent?
     *
     * @return array{0: bool, 1: string}
     */
    public static function refinementValid(array $child, array $parent): array
    {
        if (($child['refines'] ?? null) !== ($parent['id'] ?? null)) {
            return [false, 'child does not name the parent in refines'];
        }
        if (!self::setsEqual(self::asSet($child['causes']), self::asSet($parent['causes']))
                || !self::setsEqual(self::asSet($child['effects']), self::asSet($parent['effects']))) {
            return [false, "a refinement must keep the parent's causes and effects"];
        }
        $added = 0;
        foreach (self::CRO_OPTIONAL_FIELDS as $field) {
            if (array_key_exists($field, $parent)) {
                if (!Jcs::equal($child[$field] ?? null, $parent[$field])) {
                    return [false, 'a refinement may not change a field the '
                                 . 'parent specified; this is a rival claim'];
                }
            } elseif (array_key_exists($field, $child)) {
                $added++;
            }
        }
        if ($added === 0) {
            return [false, 'a refinement must add at least one unspecified field'];
        }
        return [true, 'valid refinement'];
    }

    /**
     * Rule 7: 'consistent' | 'inconsistent' | 'indeterminate'.
     *
     * $members maps CRO identifier to CRO object for the parent's mechanism
     * entries (the store's view of them).
     */
    public static function hierarchyConsistent(array $parent, array $members): string
    {
        $mechanism = $parent['mechanism'] ?? [];
        if ($mechanism === []) {
            return 'consistent'; // nothing claimed, nothing to check
        }
        $edges = [];
        foreach ($mechanism as $memberId) {
            $member = $members[$memberId] ?? null;
            if ($member === null) {
                return 'indeterminate'; // a dangling_reference gap, not a failure
            }
            foreach ($member['causes'] as $cause) {
                foreach ($member['effects'] as $effect) {
                    $edges[$cause][$effect] = true;
                }
            }
        }

        $reachable = static function (string $src, string $dst) use ($edges): bool {
            $seen = [];
            $stack = [$src];
            while ($stack !== []) {
                $node = array_pop($stack);
                if ($node === $dst) {
                    return true;
                }
                if (isset($seen[$node])) {
                    continue;
                }
                $seen[$node] = true;
                foreach (array_keys($edges[$node] ?? []) as $next) {
                    $stack[] = (string) $next;
                }
            }
            return false;
        };

        foreach ($parent['causes'] as $cause) {
            foreach ($parent['effects'] as $effect) {
                if (!$reachable((string) $cause, (string) $effect)) {
                    return 'inconsistent';
                }
            }
        }
        return 'consistent';
    }
}

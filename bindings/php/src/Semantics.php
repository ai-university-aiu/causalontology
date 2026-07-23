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

    /**
     * 3.0.0: the ordinal (dimensionless) temporal units. A tick is a discrete
     * step with NO wall-clock mapping; a tick window is ordered by integer
     * comparison, and an ordinal window and a wall-clock window are DIFFERENT
     * DIMENSIONS that do not compare (mixing them is never within-window and
     * never overlapping).
     */
    public const ORDINAL_UNITS = ['ticks' => true];

    /**
     * Rule 12: enrichment field-to-kind validity and entry shapes. Two
     * occurrent forms added in 2.0.0.
     */
    public const ENRICHMENT_FIELDS = [
        'aliases'            => [['occurrent', 'continuant'], 'alias'],
        'participants'       => [['occurrent'],               'continuant'],
        'subsumes'           => [['continuant'],              'continuant'],
        'part_of'            => [['continuant'],              'continuant'],
        'realized_in'        => [['realizable'],              'occurrent'],
        'occurrent_subsumes' => [['occurrent'],               'occurrent'],
        'occurrent_part_of'  => [['occurrent'],               'occurrent'],
    ];

    /** The optional CRO fields, in the order is_partial reports them. */
    public const CRO_OPTIONAL_FIELDS = ['mechanism', 'temporal', 'modality', 'context'];

    /**
     * Rule 6 (amended): necessary, sufficient, contributory, enabling are
     * mutually compatible; preventive opposes all four.
     */
    private const POSITIVE_MODALITIES = ['necessary', 'sufficient', 'contributory', 'enabling'];

    /** A static utility class, never an instance. */
    private function __construct()
    {
    }

    /** The kind an identifier's scheme prefix names, or null. */
    private static function kindOfId(string $identifier): ?string
    {
        return Canonical::KIND_OF_PREFIX[explode(':', $identifier, 2)[0]] ?? null;
    }

    /** 'ordinal' for a tick-like unit, else 'wallclock'. */
    private static function dimension(string $unit): string
    {
        return isset(self::ORDINAL_UNITS[$unit]) ? 'ordinal' : 'wallclock';
    }

    /**
     * A comparable magnitude within ONE dimension: the raw tick count for an
     * ordinal unit, seconds for a wall-clock unit. Never mix dimensions.
     */
    private static function magnitude(int|float $value, string $unit): int|float
    {
        if (isset(self::ORDINAL_UNITS[$unit])) {
            return $value; // a dimensionless tick count
        }
        if ($unit === 'instant') {
            return 0;
        }
        return $value * self::UNIT_SECONDS[$unit];
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
            // Rule 16, clause 1 (contradictory_skip): a HARD, locally-decidable
            // contradiction between skips:true and a non-empty mechanism.
            if (($obj['skips'] ?? null) === true && !empty($obj['mechanism'])) {
                $errors[] = 'contradictory_skip: skips is true but a mechanism '
                          . 'is present';
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

        // 3.0.0 Rule 22, local clause: a Cross Stratal Seam that DRAWS a chain
        // has, by drawing it, a modelled intervening mechanism - so
        // mechanism_status 'absent' contradicts a present chain (the
        // honest-ignorance distinction must stay honest). The stratal
        // well-formedness (non-adjacency, adjacency of chain steps, scheme, the
        // home rule) needs the strata map and lives in seamWellformed, exactly
        // as bridge well-formedness does.
        if ($kind === 'cross_stratal_seam') {
            if (($obj['chain'] ?? null) !== null && ($obj['mechanism_status'] ?? null) === 'absent') {
                $errors[] = 'contradictory_seam: a drawn chain cannot carry '
                          . "mechanism_status 'absent' (a drawn mechanism is not absent)";
            }
        }

        // 4.0.0 Rule 24, local clause: a predicted_occurrence's interval
        // carries exactly ONE temporal dimension - a wall-clock start (optional
        // end) or an ordinal start_tick (optional end_tick), never both and
        // never neither. Per Rule 23 the two dimensions never compare. The
        // pairing check of a prediction_error against its predicted_occurrence
        // and its observed token_occurrence needs those objects and lives in
        // predictionPairingMismatch, exactly as coveringLawMismatch does.
        if ($kind === 'predicted_occurrence') {
            $iv = $obj['interval'] ?? null;
            $iv = is_array($iv) ? $iv : [];
            $wall = array_key_exists('start', $iv);
            $tick = array_key_exists('start_tick', $iv);
            if ($wall && $tick) {
                $errors[] = 'dimension_conflict: a predicted interval must '
                          . 'carry exactly one temporal dimension, not a '
                          . 'wall-clock start AND an ordinal start_tick';
            }
            if (!$wall && !$tick) {
                $errors[] = 'missing_dimension: a predicted interval must '
                          . 'carry a wall-clock start or an ordinal start_tick';
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

    /**
     * Rule 4: temporal admissibility. For a wall-clock window $elapsed is in
     * seconds; for an ordinal ('ticks') window $elapsed is a tick count.
     * Ordering is by magnitude WITHIN the window's own dimension (3.0.0).
     */
    public static function admissible(array $cro, int|float $elapsed): bool
    {
        $temporal = $cro['temporal'] ?? null;
        if ($temporal === null) {
            return true; // no window imposes no constraint
        }
        $lo = self::magnitude($temporal['minimum_delay'], $temporal['unit']);
        $hi = self::magnitude($temporal['maximum_delay'], $temporal['unit']);
        return $lo <= $elapsed && $elapsed <= $hi;
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
        // 3.0.0: an ordinal window and a wall-clock window never overlap.
        if (self::dimension($ta['unit']) !== self::dimension($tb['unit'])) {
            return false;
        }
        $loA = self::magnitude($ta['minimum_delay'], $ta['unit']);
        $hiA = self::magnitude($ta['maximum_delay'], $ta['unit']);
        $loB = self::magnitude($tb['minimum_delay'], $tb['unit']);
        $hiB = self::magnitude($tb['maximum_delay'], $tb['unit']);
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

    // =======================================================================
    // 2.0.0 NORMATIVE ALGORITHMS (Section 12)
    // =======================================================================

    /**
     * ALGORITHM A. Every finer occurrent an occurrent resolves to, following
     * Bridges downward, transitively. Includes the starting occurrent
     * (N12.1.1). The visited guard (N12.1.2) prevents an infinite loop on
     * malformed cyclic data.
     *
     * @param  list<array> $bridges
     * @return array<string, true> the closure as a set of occurrent ids
     */
    public static function bridgeClosure(string $occurrentId, array $bridges): array
    {
        $result = [$occurrentId => true];
        $frontier = [$occurrentId];
        $visited = [];
        $coarseIndex = [];
        foreach ($bridges as $bridge) {
            $coarseIndex[(string) $bridge['coarse']][] = $bridge;
        }
        while ($frontier !== []) {
            $current = array_pop($frontier);
            if (isset($visited[$current])) {
                continue;
            }
            $visited[$current] = true;
            foreach ($coarseIndex[$current] ?? [] as $bridge) {
                foreach ($bridge['fine'] as $fine) {
                    $fine = (string) $fine;
                    $result[$fine] = true;
                    $frontier[] = $fine;
                }
            }
        }
        return $result;
    }

    /** True iff dst is reachable from src through the edge map. */
    private static function pathExists(array $edges, string $src, string $dst): bool
    {
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
    }

    /**
     * ALGORITHM B (amended Rule 7): 'consistent' | 'inconsistent' |
     * 'indeterminate', ACROSS STRATA via bridged reachability.
     *
     * $members maps CRO identifier to CRO object for the mechanism entries.
     * $bridges is the store's bridges (empty -> 1.0.0 literal reachability,
     * the degenerate case, N12.2.3).
     *
     * @param  list<array> $bridges
     */
    public static function hierarchyConsistent(array $parent, array $members, array $bridges = []): string
    {
        $mechanism = $parent['mechanism'] ?? [];
        if ($mechanism === []) {
            return 'consistent'; // nothing claimed, nothing to check (N12.2.1)
        }
        $edges = [];
        foreach ($mechanism as $memberId) {
            $member = $members[$memberId] ?? null;
            if ($member === null) {
                return 'indeterminate'; // dangling; ignorance, not refutation
            }
            foreach ($member['causes'] as $cause) {
                foreach ($member['effects'] as $effect) {
                    $edges[(string) $cause][(string) $effect] = true;
                }
            }
        }
        $bCause = [];
        foreach ($parent['causes'] as $cause) {
            $bCause[(string) $cause] = self::bridgeClosure((string) $cause, $bridges);
        }
        $bEffect = [];
        foreach ($parent['effects'] as $effect) {
            $bEffect[(string) $effect] = self::bridgeClosure((string) $effect, $bridges);
        }
        foreach ($parent['causes'] as $cause) {
            foreach ($parent['effects'] as $effect) {
                $connected = false;
                foreach (array_keys($bCause[(string) $cause]) as $cp) {
                    foreach (array_keys($bEffect[(string) $effect]) as $ep) {
                        if (self::pathExists($edges, (string) $cp, (string) $ep)) {
                            $connected = true;
                            break 2;
                        }
                    }
                }
                if (!$connected) {
                    return 'inconsistent';
                }
            }
        }
        return 'consistent';
    }

    /** The stratum id of an occurrent, via the occurrent map (or null). */
    private static function stratumOf(array $occMap, string $occId): ?string
    {
        $occ = $occMap[$occId] ?? null;
        $stratum = is_array($occ) ? ($occ['stratum'] ?? null) : null;
        return is_string($stratum) ? $stratum : null;
    }

    /**
     * ALGORITHM C (Rule 15): 'intra_stratal' | 'adjacent_stratal' |
     * 'skipping' | 'mixed' | 'unclassifiable' | 'scheme_mismatch'.
     * Derived, never asserted; recompute on ingest (N12.3.1).
     */
    public static function classifyCro(array $cro, array $occMap, array $stratumMap): string
    {
        $causeStrata = [];
        foreach ($cro['causes'] as $c) {
            $causeStrata[] = self::stratumOf($occMap, (string) $c);
        }
        $effectStrata = [];
        foreach ($cro['effects'] as $e) {
            $effectStrata[] = self::stratumOf($occMap, (string) $e);
        }
        foreach (array_merge($causeStrata, $effectStrata) as $s) {
            if ($s === null) {
                return 'unclassifiable'; // surface unstratified_occurrent
            }
        }
        $allStrata = array_unique(array_merge($causeStrata, $effectStrata));
        $schemes = [];
        foreach ($allStrata as $s) {
            $schemes[(string) $stratumMap[$s]['scheme']] = true;
        }
        if (count($schemes) > 1) {
            return 'scheme_mismatch'; // HARD
        }
        $cOrd = [];
        foreach ($causeStrata as $s) {
            $cOrd[] = $stratumMap[$s]['ordinal'];
        }
        $eOrd = [];
        foreach ($effectStrata as $s) {
            $eOrd[] = $stratumMap[$s]['ordinal'];
        }
        if (max($cOrd) === min($cOrd) && min($cOrd) === max($eOrd) && max($eOrd) === min($eOrd)) {
            return 'intra_stratal';
        }
        $gap = null;
        $span = null;
        foreach ($cOrd as $i) {
            foreach ($eOrd as $j) {
                $d = abs($i - $j);
                $gap = $gap === null ? $d : min($gap, $d);
                $span = $span === null ? $d : max($span, $d);
            }
        }
        if ($span === 1) {
            return 'adjacent_stratal';
        }
        if ($gap > 1) {
            return 'skipping';
        }
        return 'mixed'; // some pairs adjacent, some skipping
    }

    /**
     * True iff causes or effects span more than one distinct stratum
     * (surfaces mixed_stratal_endpoints, an invitation; N12.3.2).
     */
    public static function endpointsMixed(array $cro, array $occMap): bool
    {
        $cs = [];
        foreach ($cro['causes'] as $c) {
            $cs[] = self::stratumOf($occMap, (string) $c);
        }
        $es = [];
        foreach ($cro['effects'] as $e) {
            $es[] = self::stratumOf($occMap, (string) $e);
        }
        if (in_array(null, $cs, true) || in_array(null, $es, true)) {
            return false;
        }
        return count(array_unique($cs)) > 1 || count(array_unique($es)) > 1;
    }

    /**
     * ALGORITHM D (Rule 16): the gaps a Causal Relation Object surfaces for
     * the skip decision. THE ASYMMETRY (clause 3) is the whole point of the
     * field and is implemented exactly.
     *
     * @return list<string>
     */
    public static function skipGaps(array $cro, string $classification): array
    {
        $gaps = [];
        $hasMech = !empty($cro['mechanism']);
        if (($cro['skips'] ?? null) === true && $hasMech) {
            $gaps[] = 'contradictory_skip'; // HARD
            return $gaps;
        }
        if (($cro['skips'] ?? null) === true
                && !in_array($classification, ['skipping', 'unclassifiable'], true)) {
            $gaps[] = 'vacuous_skip'; // invitation
        }
        if ($classification === 'skipping' && !$hasMech) {
            if (($cro['skips'] ?? null) === true) {
                // NOTHING: absence is a finding
            } else {
                $gaps[] = 'incomplete_mechanism'; // invitation
            }
        }
        return $gaps;
    }

    /**
     * ALGORITHM E helper: normalize a delay to seconds by the fixed table.
     * 3.0.0: an ordinal ('ticks') unit is dimensionless and has NO wall-clock
     * mapping - converting one to seconds is a category error and is refused.
     */
    public static function toSeconds(int|float $duration, string $unit): int|float
    {
        if (isset(self::ORDINAL_UNITS[$unit])) {
            throw new \InvalidArgumentException(
                "'" . $unit . "' is an ordinal (dimensionless) unit and has no "
                . 'wall-clock seconds mapping');
        }
        if ($unit === 'instant') {
            return 0;
        }
        return $duration * self::UNIT_SECONDS[$unit];
    }

    /**
     * ALGORITHM E (Rule 20): does an observed delay fall within a covering
     * law's temporal window? Inclusive at both ends (N12.5.2). 3.0.0: an
     * ordinal delay compares to an ordinal window by integer tick count; an
     * ordinal delay and a wall-clock window (or vice versa) are different
     * dimensions and never fall within one another.
     */
    public static function delayWithinWindow(?array $actualDelay, ?array $temporal): bool
    {
        if (empty($actualDelay) || empty($temporal)) {
            return true; // nothing to check
        }
        // dimension mismatch: a tick delay is not within a wall-clock window.
        if (self::dimension($actualDelay['unit']) !== self::dimension($temporal['unit'])) {
            return false;
        }
        $observed = self::magnitude($actualDelay['duration'], $actualDelay['unit']);
        $lo = self::magnitude($temporal['minimum_delay'], $temporal['unit']);
        $hi = self::magnitude($temporal['maximum_delay'], $temporal['unit']);
        return $lo <= $observed && $observed <= $hi;
    }

    /**
     * Rule 14 / N3.2.1: Bridge well-formedness. All of (a)-(e) must hold,
     * else malformed_bridge.
     *
     * @return array{0: bool, 1: string}
     */
    public static function bridgeWellformed(array $bridge, array $occMap, array $stratumMap): array
    {
        $cs = self::stratumOf($occMap, (string) $bridge['coarse']);
        if ($cs === null) {
            return [false, 'malformed_bridge: coarse has no stratum (a)'];
        }
        $fineStrata = [];
        foreach ($bridge['fine'] as $f) {
            $s = self::stratumOf($occMap, (string) $f);
            if ($s === null) {
                return [false, 'malformed_bridge: a fine member has no stratum (b)'];
            }
            $fineStrata[] = $s;
        }
        if (count(array_unique($fineStrata)) !== 1) {
            return [false, 'malformed_bridge: fine members span >1 stratum (c)'];
        }
        $fs = $fineStrata[0];
        if ($stratumMap[$cs]['scheme'] !== $stratumMap[$fs]['scheme']) {
            return [false, 'malformed_bridge: coarse and fine differ in scheme (d)'];
        }
        if (!($stratumMap[$cs]['ordinal'] > $stratumMap[$fs]['ordinal'])) {
            return [false, 'malformed_bridge: coarse ordinal not > fine ordinal (e)'];
        }
        return [true, 'well-formed bridge'];
    }

    /**
     * 3.0.0 Rule 22 / Algorithm F: Cross Stratal Seam well-formedness. All of
     * (a)-(g) must hold, else malformed_seam. A seam is a MANAGED jump across
     * NON-ADJACENT strata; when it DRAWS a chain, the chain must be an
     * adjacent-stratum path spanning the two endpoints' strata.
     *
     * @return array{0: bool, 1: string}
     */
    public static function seamWellformed(array $seam, array $occMap, array $stratumMap): array
    {
        $srcS = self::stratumOf($occMap, (string) $seam['source']);
        $tgtS = self::stratumOf($occMap, (string) $seam['target']);
        if ($srcS === null || $tgtS === null) {
            return [false, 'malformed_seam: an endpoint has no stratum (a)'];
        }
        if ($stratumMap[$srcS]['scheme'] !== $stratumMap[$tgtS]['scheme']) {
            return [false, 'malformed_seam: endpoints differ in scheme (b)'];
        }
        $so = $stratumMap[$srcS]['ordinal'];
        $to = $stratumMap[$tgtS]['ordinal'];
        if (abs($so - $to) <= 1) {
            return [false, 'malformed_seam: endpoints are adjacent or co-stratal; '
                         . 'a seam is for NON-adjacent strata (c)'];
        }
        $chain = $seam['chain'] ?? null;
        if ($chain !== null) {
            if (($seam['mechanism_status'] ?? null) === 'absent') {
                return [false, 'malformed_seam: a drawn chain contradicts '
                             . "mechanism_status 'absent' (d)"];
            }
            $lo = min($so, $to);
            $hi = max($so, $to);
            $ords = [];
            foreach ($chain as $oid) {
                $st = self::stratumOf($occMap, (string) $oid);
                if ($st === null) {
                    return [false, 'malformed_seam: a chain member has no stratum (e)'];
                }
                if ($stratumMap[$st]['scheme'] !== $stratumMap[$srcS]['scheme']) {
                    return [false, 'malformed_seam: a chain member differs in scheme (e)'];
                }
                $ords[] = $stratumMap[$st]['ordinal'];
            }
            foreach ($ords as $o) {
                if (!($lo < $o && $o < $hi)) {
                    return [false, 'malformed_seam: a chain member is not at an '
                                 . 'INTERVENING stratum, strictly between the endpoints (f)'];
                }
            }
            $count = count($ords);
            $diffs = [];
            for ($i = 0; $i < $count - 1; $i++) {
                $diffs[] = $ords[$i + 1] - $ords[$i];
            }
            if ($diffs !== []) {
                $allPositive = true;
                $allNegative = true;
                foreach ($diffs as $d) {
                    if ($d <= 0) {
                        $allPositive = false;
                    }
                    if ($d >= 0) {
                        $allNegative = false;
                    }
                }
                if (!($allPositive || $allNegative)) {
                    return [false, 'malformed_seam: chain is not strictly monotone from '
                                 . 'one endpoint toward the other (g)'];
                }
            }
        }
        return [true, 'well-formed cross_stratal_seam'];
    }

    /**
     * THE HOME RULE (3.0.0): a Cross Stratal Seam belongs to the COARSEST
     * stratum it touches - the endpoint of the greater ordinal. Returns that
     * stratum's identifier (null if an endpoint is unstratified).
     */
    public static function seamHome(array $seam, array $occMap, array $stratumMap): ?string
    {
        $srcS = self::stratumOf($occMap, (string) $seam['source']);
        $tgtS = self::stratumOf($occMap, (string) $seam['target']);
        if ($srcS === null || $tgtS === null) {
            return null;
        }
        return $stratumMap[$srcS]['ordinal'] >= $stratumMap[$tgtS]['ordinal'] ? $srcS : $tgtS;
    }

    /**
     * Rule 17 / N4.2.1-2: Conduit well-formedness, with the transform
     * exception of N4.2.2.
     *
     * @return array{0: bool, 1: string}
     */
    public static function conduitWellformed(array $conduit, array $portMap, ?array $croMap = null): array
    {
        $frm = $portMap[$conduit['from']] ?? null;
        $to = $portMap[$conduit['to']] ?? null;
        if ($frm === null || $to === null) {
            return [false, 'malformed_conduit: dangling port reference'];
        }
        if (!in_array($frm['direction'], ['out', 'bidirectional'], true)) {
            return [false, 'malformed_conduit: from port is not out/bidirectional (a)'];
        }
        if (!in_array($to['direction'], ['in', 'bidirectional'], true)) {
            return [false, 'malformed_conduit: to port is not in/bidirectional (b)'];
        }
        $carries = $conduit['carries'];
        foreach ($carries as $o) {
            if (!in_array($o, $frm['accepts'], true)) {
                return [false, 'malformed_conduit: carries not accepted by from (c)'];
            }
        }
        $transform = $conduit['transform'] ?? null;
        if ($transform === null) {
            foreach ($carries as $o) {
                if (!in_array($o, $to['accepts'], true)) {
                    return [false, 'malformed_conduit: carries not accepted by to (d)'];
                }
            }
        } else {
            $law = ($croMap ?? [])[$transform] ?? null;
            if ($law !== null) {
                foreach ($law['effects'] as $o) {
                    if (!in_array($o, $to['accepts'], true)) {
                        return [false, 'malformed_conduit: transform effects not '
                                     . 'accepted by to (d, relaxed per N4.2.2)'];
                    }
                }
            }
        }
        return [true, 'well-formed conduit'];
    }

    /**
     * Rule 19 / N5.3.1-2: the HARD gaps a state assertion surfaces against
     * its quality: value_type_mismatch and/or unit_mismatch.
     *
     * @return list<string>
     */
    public static function stateGaps(array $state, array $quality): array
    {
        $gaps = [];
        $dt = $quality['datatype'] ?? null;
        $v = $state['value'] ?? [];
        $shape = array_key_exists('quantity', $v) ? 'quantity'
            : (array_key_exists('categorical', $v) ? 'categorical'
            : (array_key_exists('boolean', $v) ? 'boolean' : null));
        if ($shape !== $dt) {
            $gaps[] = 'value_type_mismatch';
        } elseif ($dt === 'quantity' && ($v['unit'] ?? null) !== ($quality['unit'] ?? null)) {
            $gaps[] = 'unit_mismatch';
        }
        return $gaps;
    }

    /**
     * Rule 20: true iff the token claim's cause/effect tokens do not
     * instantiate the covering law's causes/effects (surfaces
     * covering_law_mismatch).
     */
    public static function coveringLawMismatch(array $tcc, array $tokenMap, ?array $law): bool
    {
        if (empty($law)) {
            return false;
        }
        $lawCauses = self::asSet($law['causes']);
        $lawEffects = self::asSet($law['effects']);
        foreach ($tcc['causes'] as $c) {
            if (!isset($lawCauses[(string) $tokenMap[$c]['instantiates']])) {
                return true;
            }
        }
        foreach ($tcc['effects'] as $e) {
            if (!isset($lawEffects[(string) $tokenMap[$e]['instantiates']])) {
                return true;
            }
        }
        return false;
    }

    /**
     * 4.0.0 Rule 24: prediction-to-observation pairing. True iff the prediction
     * error's observed token does not instantiate the occurrent its
     * predicted_occurrence instantiates (surfaces pairing_mismatch). An ABSENT
     * observed is never a mismatch - it means the predicted occurrence was not
     * fulfilled by any recorded occurrence.
     */
    public static function predictionPairingMismatch(array $error, array $predicted, ?array $observed): bool
    {
        if (($error['observed'] ?? null) === null || $observed === null) {
            return false;
        }
        return $observed['instantiates'] !== $predicted['instantiates'];
    }

    /**
     * Rule 21: true iff any cause token starts after any effect token (HARD;
     * retrocausal_claim). RFC 3339 UTC 'Z' strings compare lexicographically.
     */
    public static function retrocausal(array $tcc, array $tokenMap): bool
    {
        foreach ($tcc['causes'] as $c) {
            $cstart = (string) $tokenMap[$c]['interval']['start'];
            foreach ($tcc['effects'] as $e) {
                $estart = (string) $tokenMap[$e]['interval']['start'];
                if (strcmp($cstart, $estart) > 0) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Rules 4 / 6.1: true iff a directed graph (node -> iterable of
     * successors) has a cycle. Used for the bridge graph, occurrent_subsumes,
     * occurrent_part_of, and token mereology (part_of).
     */
    public static function hasCycle(array $edges): bool
    {
        $state = []; // node -> 1 (grey) | 2 (black); absent = white
        $visit = function ($node) use (&$visit, &$state, $edges): bool {
            $state[$node] = 1;
            foreach ($edges[$node] ?? [] as $next) {
                $s = $state[$next] ?? 0;
                if ($s === 1) {
                    return true;
                }
                if ($s === 0 && $visit($next)) {
                    return true;
                }
            }
            $state[$node] = 2;
            return false;
        };
        foreach (array_keys($edges) as $node) {
            if (($state[$node] ?? 0) === 0 && $visit($node)) {
                return true;
            }
        }
        return false;
    }
}

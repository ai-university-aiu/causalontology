<?php

/* An in-memory conformant store.
 *
 * Implements the store side of the abstract operation set (spec/store.md):
 * immutable content objects with idempotent put; signed, add-only
 * provenance records; materialized enrichment views with contributors;
 * retraction handling in default views; succession lineage; the resolve
 * minimum; the deterministic cycle-breaking view rule; and the stigmergy
 * gap read.
 *
 * PHP arrays are ordered maps (insertion order preserved), so iteration
 * order matches the Python binding's dicts with no extra bookkeeping. All
 * identifier keys carry a ':' and therefore never collide with PHP's
 * numeric-string key coercion.
 */

declare(strict_types=1);

namespace Causalontology;

final class Store
{
    /** The immutable content kinds. */
    public const CONTENT_KINDS = ['occurrent', 'causal_relation_object', 'continuant',
        'realizable', 'stratum', 'bridge', 'cross_stratal_seam', 'port', 'conduit',
        'quality', 'token_individual', 'token_occurrence', 'state_assertion',
        'token_causal_claim', 'attitude', 'predicted_occurrence', 'prediction_error'];

    /** The four signed provenance record kinds. */
    public const RECORD_KINDS = ['assertion', 'enrichment', 'retraction', 'succession'];

    /** Does this store enforce the write gates (versus merge-only)? */
    public bool $enforcing;

    /** @var array<string, array> id -> content object */
    public array $objects = [];

    /** @var array<string, array> id -> provenance record */
    public array $records = [];

    /** @var array<string, array> id -> record (unsigned / unverifiable) */
    public array $quarantine = [];

    public function __construct(bool $enforcing = true)
    {
        $this->enforcing = $enforcing;
    }

    // ------------------------------------------------------------------ put

    /** Write a content object; idempotent; returns the identifier. */
    public function put(array $obj, ?string $kind = null): string
    {
        $kind ??= Canonical::inferKind($obj);
        if (!in_array($kind, self::CONTENT_KINDS, true)) {
            throw new \InvalidArgumentException('put() takes content objects; use putRecord()');
        }
        if (!array_key_exists('type', $obj)) {
            $obj['type'] = $kind;
        }
        if (!array_key_exists('id', $obj)) {
            $obj['id'] = Canonical::identify($obj, $kind);
        }
        $id = (string) $obj['id'];
        if (array_key_exists($id, $this->objects)) {
            return $id; // immutable: identical identity is a no-op
        }
        [$ok, $why] = SchemaValidator::validateSchema($obj, $kind);
        if (!$ok) {
            throw new RejectedWrite(implode('; ', $why));
        }
        [$ok, $why] = Semantics::validateSemantics($obj, $kind);
        if (!$ok) {
            throw new RejectedWrite(implode('; ', $why));
        }
        $this->objects[$id] = $obj;
        return $id;
    }

    /** Write a signed provenance record; returns the identifier. */
    public function putRecord(array $record, ?string $kind = null, bool $force = false): string
    {
        $kind ??= Canonical::inferKind($record);
        if (!in_array($kind, self::RECORD_KINDS, true)) {
            throw new \InvalidArgumentException('putRecord() takes provenance records');
        }
        if (!array_key_exists('type', $record)) {
            $record['type'] = $kind;
        }
        $rid = $record['id'] ?? null;
        if (!is_string($rid) || $rid === '') {
            $rid = Canonical::identify($record, $kind);
        }
        $record['id'] = $rid;
        if (array_key_exists($rid, $this->records)) {
            return $rid; // add-only and idempotent
        }
        if (!Signing::verifyRecord($record, $kind)) {
            $this->quarantine[$rid] = $record;
            throw new RejectedWrite('unsigned or unverifiable record: quarantined');
        }
        [$ok, $why] = Semantics::validateSemantics($record, $kind);
        if (!$ok) {
            throw new RejectedWrite(implode('; ', $why));
        }
        if ($kind === 'retraction' && !$this->retractionSourceOk($record)) {
            throw new RejectedWrite(
                "a retraction is valid only from the retracted record's "
                . 'source or its succession lineage');
        }
        if ($kind === 'enrichment' && $this->enforcing && !$force) {
            $field = $record['field'] ?? null;
            if (($field === 'subsumes' || $field === 'part_of')
                    && $this->wouldCycle($record)) {
                throw new RejectedWrite(
                    'would create a cycle in the materialized ' . $field . ' graph');
            }
        }
        $this->records[$rid] = $record;
        return $rid;
    }

    /** Simulate a decentralized replica merge (no enforcement gate). */
    public function forceMergeRecord(array $record, ?string $kind = null): string
    {
        return $this->putRecord($record, $kind, true);
    }

    // ------------------------------------------------------- record queries

    /** @return list<array> every record of one kind, in insertion order */
    private function recordsOf(string $kind): array
    {
        $out = [];
        foreach ($this->records as $record) {
            if (($record['type'] ?? null) === $kind) {
                $out[] = $record;
            }
        }
        return $out;
    }

    /** @return array<string, true> the set of retracted record identifiers */
    private function retractedIds(): array
    {
        $out = [];
        foreach ($this->recordsOf('retraction') as $record) {
            $out[$record['retracts']] = true;
        }
        return $out;
    }

    /** May this retraction's source retract its target (lineage rule)? */
    private function retractionSourceOk(array $retraction): bool
    {
        $target = $this->records[$retraction['retracts']] ?? null;
        if ($target === null) {
            return true; // open world: the target may arrive later
        }
        return in_array($retraction['source'],
                        $this->lineage((string) $target['source']), true);
    }

    /**
     * The succession chain closure containing key (includes key).
     *
     * @return list<string>
     */
    public function lineage(string $key): array
    {
        $succ = [];
        $pred = [];
        foreach ($this->recordsOf('succession') as $record) {
            $succ[$record['predecessor']] = $record['successor'];
            $pred[$record['successor']] = $record['predecessor'];
        }
        $chain = [$key => true];
        $cursor = $key;
        while (isset($pred[$cursor])) {
            $cursor = (string) $pred[$cursor];
            if (isset($chain[$cursor])) {
                break; // defensive: a cyclic chain must not loop forever
            }
            $chain[$cursor] = true;
        }
        $cursor = $key;
        while (isset($succ[$cursor])) {
            $cursor = (string) $succ[$cursor];
            if (isset($chain[$cursor])) {
                break; // defensive: a cyclic chain must not loop forever
            }
            $chain[$cursor] = true;
        }
        return array_keys($chain);
    }

    /** @return list<array> assertions about one identifier (default view) */
    public function assertionsAbout(string $identifier, bool $includeRetracted = false): array
    {
        $retracted = $this->retractedIds();
        $out = [];
        foreach ($this->recordsOf('assertion') as $record) {
            if (($record['about'] ?? null) !== $identifier) {
                continue;
            }
            if (isset($retracted[$record['id']])) {
                if ($includeRetracted) {
                    $record['retracted'] = true; // the history flag
                    $out[] = $record;
                }
                continue;
            }
            $out[] = $record;
        }
        return $out;
    }

    /** @return list<array> enrichments about one identifier */
    public function enrichmentsAbout(string $identifier, bool $includeRetracted = false): array
    {
        $retracted = $this->retractedIds();
        $out = [];
        foreach ($this->recordsOf('enrichment') as $record) {
            if (($record['about'] ?? null) !== $identifier) {
                continue;
            }
            if (isset($retracted[$record['id']]) && !$includeRetracted) {
                continue;
            }
            $out[] = $record;
        }
        return $out;
    }

    // ------------------------------------------------- materialized views

    /**
     * [active, excluded] for subsumes/part_of after rule 13 cycle-breaking.
     *
     * @return array{0: list<array>, 1: list<array>}
     */
    public function activeTaxonomyEdges(string $field): array
    {
        $retracted = $this->retractedIds();
        $active = [];
        foreach ($this->recordsOf('enrichment') as $record) {
            if (($record['field'] ?? null) === $field && !isset($retracted[$record['id']])) {
                $active[] = $record;
            }
        }
        $excluded = [];
        while (true) {
            $cycle = self::findCycleRecords($active);
            if ($cycle === []) {
                break;
            }
            // Exclude the cycle-completing record with the LATEST timestamp,
            // ties broken by lexicographic record identifier (deterministic).
            $loser = $cycle[0];
            foreach ($cycle as $record) {
                $byTimestamp = strcmp((string) $record['timestamp'], (string) $loser['timestamp']);
                if ($byTimestamp > 0
                        || ($byTimestamp === 0
                            && strcmp((string) $record['id'], (string) $loser['id']) > 0)) {
                    $loser = $record;
                }
            }
            foreach ($active as $index => $record) {
                if ($record['id'] === $loser['id']) {
                    unset($active[$index]);
                    break;
                }
            }
            $active = array_values($active);
            $excluded[] = $loser;
        }
        return [$active, $excluded];
    }

    /**
     * The records forming the first directed cycle found, or [].
     *
     * @return list<array>
     */
    private static function findCycleRecords(array $records): array
    {
        $edges = [];
        foreach ($records as $record) {
            $edges[$record['about']][] = [$record['entry'], $record];
        }
        $state = []; // node -> 1 (on the stack) | 2 (done); absent = unvisited
        $cycle = [];

        $dfs = function (string $node, array $pathRecords) use (&$dfs, &$state, &$cycle, $edges): bool {
            $state[$node] = 1;
            foreach ($edges[$node] ?? [] as [$next, $record]) {
                $next = (string) $next;
                if (($state[$next] ?? 0) === 1) {
                    foreach ($pathRecords as $pathRecord) {
                        $cycle[] = $pathRecord;
                    }
                    $cycle[] = $record;
                    return true;
                }
                if (($state[$next] ?? 0) === 0) {
                    $path = $pathRecords;
                    $path[] = $record;
                    if ($dfs($next, $path)) {
                        return true;
                    }
                }
            }
            $state[$node] = 2;
            return false;
        };

        foreach (array_keys($edges) as $start) {
            $start = (string) $start;
            if (($state[$start] ?? 0) === 0 && $dfs($start, [])) {
                return $cycle;
            }
        }
        return [];
    }

    /** Would adding this record close a cycle in its taxonomy field? */
    private function wouldCycle(array $record): bool
    {
        $retracted = $this->retractedIds();
        $candidates = [];
        foreach ($this->recordsOf('enrichment') as $existing) {
            if (($existing['field'] ?? null) === $record['field']
                    && !isset($retracted[$existing['id']])) {
                $candidates[] = $existing;
            }
        }
        $candidates[] = $record;
        return self::findCycleRecords($candidates) !== [];
    }

    /** The object with its materialized enrichment sets and contributors. */
    public function get(string $identifier, string $view = 'default'): ?array
    {
        $obj = $this->objects[$identifier] ?? null;
        if ($obj === null) {
            return null;
        }
        $includeRetracted = ($view === 'history');
        $excludedIds = [];
        foreach (['subsumes', 'part_of'] as $field) {
            [, $excluded] = $this->activeTaxonomyEdges($field);
            foreach ($excluded as $record) {
                $excludedIds[$record['id']] = true;
            }
        }
        $fields = []; // field -> canonical entry key -> bucket
        foreach ($this->enrichmentsAbout($identifier, $includeRetracted) as $record) {
            if (isset($excludedIds[$record['id']]) && $view !== 'history') {
                continue;
            }
            $entry = $record['entry'];
            // Dedup key: the canonical entry form - one bucket per entry.
            $entryKey = is_array($entry) ? Jcs::serialize($entry) : (string) $entry;
            $fieldName = (string) $record['field'];
            if (!isset($fields[$fieldName][$entryKey])) {
                $fields[$fieldName][$entryKey] = ['entry' => $entry, 'contributors' => []];
            }
            $fields[$fieldName][$entryKey]['contributors'][] = [
                'source'    => $record['source'],
                'timestamp' => $record['timestamp'],
            ];
        }
        $enrichments = [];
        foreach ($fields as $fieldName => $slot) {
            $enrichments[$fieldName] = array_values($slot);
        }
        if ($view === 'raw') {
            return ['object' => $obj];
        }
        return ['object' => $obj, 'enrichments' => $enrichments];
    }

    // -------------------------------------------------------------- resolve

    /** The canonical-label form of free text: lowercase snake_case. */
    private static function canonLabel(string $text): string
    {
        $words = preg_split('~\s+~', trim($text), -1, PREG_SPLIT_NO_EMPTY);
        return strtolower(implode('_', $words ?: []));
    }

    /** The normalized alias form: single-spaced, lowercased. */
    private static function normAlias(string $text): string
    {
        $words = preg_split('~\s+~', trim($text), -1, PREG_SPLIT_NO_EMPTY);
        return strtolower(implode(' ', $words ?: []));
    }

    /**
     * The conformance minimum: exact label, then alias, then nothing.
     *
     * @return list<string>
     */
    public function resolve(string $text, ?string $lang = null): array
    {
        $labelHits = [];
        $aliasHits = [];
        $wantedLabel = self::canonLabel($text);
        $wantedAlias = self::normAlias($text);
        $retracted = $this->retractedIds();
        foreach ($this->objects as $oid => $obj) {
            $oid = (string) $oid;
            $type = $obj['type'] ?? null;
            if ($type !== 'occurrent' && $type !== 'continuant') {
                continue;
            }
            if (($obj['label'] ?? null) === $wantedLabel) {
                $labelHits[] = $oid;
                continue;
            }
            foreach ($this->recordsOf('enrichment') as $record) {
                if (($record['about'] ?? null) !== $oid
                        || ($record['field'] ?? null) !== 'aliases') {
                    continue;
                }
                if (isset($retracted[$record['id']])) {
                    continue;
                }
                $entry = $record['entry'];
                if (!is_array($entry)) {
                    continue;
                }
                if ($lang !== null && ($entry['lang'] ?? null) !== $lang) {
                    continue;
                }
                if (self::normAlias((string) ($entry['text'] ?? '')) === $wantedAlias) {
                    $aliasHits[] = $oid;
                    break;
                }
            }
        }
        return array_merge($labelHits, $aliasHits); // label hits rank first
    }

    // ---------------------------------------------------------------- gaps

    /**
     * The stigmergy read. Gap kinds per spec/store.md.
     *
     * @return list<array>
     */
    public function gaps(?string $kind = null): array
    {
        $out = [];
        $refined = [];
        foreach ($this->objects as $obj) {
            if (($obj['type'] ?? null) === 'causal_relation_object' && !empty($obj['refines'])) {
                $parent = $this->objects[$obj['refines']] ?? null;
                if ($parent !== null) {
                    [$ok, ] = Semantics::refinementValid($obj, $parent);
                    if ($ok) {
                        $refined[(string) $parent['id']] = true;
                    }
                }
            }
        }
        foreach ($this->objects as $oid => $obj) {
            $oid = (string) $oid;
            if (($obj['type'] ?? null) !== 'causal_relation_object') {
                continue;
            }
            // missing_field: lacking the temporal window or the modality -
            // mechanism and context may legitimately stay unspecified forever
            // (empty_mechanism is its own kind; absent context = context-free).
            if ((!array_key_exists('temporal', $obj) || !array_key_exists('modality', $obj))
                    && !isset($refined[$oid])) {
                $out[] = ['id' => $oid, 'kind' => 'missing_field',
                          'missing' => Semantics::isPartial($obj)[1]];
            }
            if (!array_key_exists('mechanism', $obj) || ($obj['mechanism'] ?? null) === []) {
                if (!isset($refined[$oid])) {
                    $out[] = ['id' => $oid, 'kind' => 'empty_mechanism'];
                }
            }
        }
        foreach (['subsumes', 'part_of'] as $field) {
            [, $excluded] = $this->activeTaxonomyEdges($field);
            foreach ($excluded as $record) {
                $out[] = ['id' => $record['id'], 'kind' => 'inconsistent_hierarchy',
                          'note' => 'excluded by the deterministic '
                                  . 'cycle-breaking view rule'];
            }
        }
        // dangling_reference: a reference to an object absent from the store -
        // the red link that says "this page is wanted".
        foreach ($this->objects as $oid => $obj) {
            $oid = (string) $oid;
            $refs = [];
            $type = $obj['type'] ?? null;
            if ($type === 'causal_relation_object') {
                $refs = array_merge(
                    $obj['causes'] ?? [],
                    $obj['effects'] ?? [],
                    $obj['context'] ?? [],
                    $obj['mechanism'] ?? []);
                if (!empty($obj['refines'])) {
                    $refs[] = $obj['refines'];
                }
            } elseif ($type === 'realizable') {
                $refs = [$obj['bearer'] ?? null];
            }
            foreach ($refs as $ref) {
                if (is_string($ref) && $ref !== ''
                        && !array_key_exists($ref, $this->objects)) {
                    $out[] = ['id' => $oid, 'kind' => 'dangling_reference', 'ref' => $ref];
                }
            }
        }
        // conflict: pairs of claims satisfying the formal test (rule 6).
        $cros = [];
        foreach ($this->objects as $obj) {
            if (($obj['type'] ?? null) === 'causal_relation_object') {
                $cros[] = $obj;
            }
        }
        $count = count($cros);
        for ($i = 0; $i < $count; $i++) {
            for ($j = $i + 1; $j < $count; $j++) {
                if (Semantics::conflicts($cros[$i], $cros[$j])) {
                    $out[] = ['kind' => 'conflict',
                              'a' => $cros[$i]['id'], 'b' => $cros[$j]['id']];
                }
            }
        }
        if ($kind !== null) {
            $out = array_values(array_filter(
                $out, static fn (array $gap): bool => $gap['kind'] === $kind));
        }
        return $out;
    }
}

<?php

/* The Causalontology conformance runner for causalontology-php (spec 2.0.0).
 *
 * Runs every vector in conformance/vectors/ against the PHP binding. An
 * implementation is conformant if and only if it passes every vector; this
 * runner exits nonzero on any failure. Vectors are the whole-word 2.0.0
 * baseline (Principle P7): V01-V38 re-frozen unaltered in meaning, V39-V107
 * new. This runner reproduces every vNN assertion of the Python reference
 * (bindings/python/tests/run_conformance.py) with the same fixtures.
 *
 * Usage: php bindings/php/conformance.php
 */

declare(strict_types=1);

// The binding is dependency-free: load the concerns directly, in dependency
// order, so the runner works without any Composer autoloader.
require __DIR__ . '/src/Causalontology.php';
require __DIR__ . '/src/Jcs.php';
require __DIR__ . '/src/Canonical.php';
require __DIR__ . '/src/SchemaValidator.php';
require __DIR__ . '/src/Semantics.php';
require __DIR__ . '/src/Signing.php';
require __DIR__ . '/src/RejectedWrite.php';
require __DIR__ . '/src/Store.php';

use Causalontology\Canonical;
use Causalontology\Jcs;
use Causalontology\RejectedWrite;
use Causalontology\SchemaValidator;
use Causalontology\Semantics;
use Causalontology\Signing;
use Causalontology\Store;

// The runner needs ext-sodium (bundled with PHP since 7.2) for Ed25519.
if (!extension_loaded('sodium')) {
    fwrite(STDERR, "causalontology-php requires ext-sodium (bundled with PHP since 7.2)\n");
    exit(1);
}
if (PHP_VERSION_ID < 80200) {
    fwrite(STDERR, "causalontology-php requires PHP 8.2 or newer\n");
    exit(1);
}

// bindings/php/conformance.php -> two levels below the repository root.
define('CO_VECDIR', __DIR__ . '/../../conformance/vectors');

// The seventeen whole-word schemes (Principle P7), plus ed25519 for keys.
const CO_SCHEMES = ['occurrent', 'causal_relation_object', 'continuant', 'realizable',
    'assertion', 'enrichment', 'retraction', 'succession', 'stratum', 'bridge',
    'port', 'conduit', 'quality', 'token_individual', 'token_occurrence',
    'state_assertion', 'token_causal_claim'];

// ---------------------------------------------------------------------------
// small assertion helper
// ---------------------------------------------------------------------------

/** Throw (failing the current vector) unless the condition holds. */
function assertTrue(bool $condition, string $message = 'assertion failed'): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
}

// ---------------------------------------------------------------------------
// symbolic-identifier normalization (Principle P7)
// ---------------------------------------------------------------------------

/**
 * A real, deterministic Ed25519 keypair for a symbolic key name.
 *
 * @return array{0: string, 1: string} [32-byte seed, 'ed25519:<hex>']
 */
function keyPair(string $name): array
{
    static $keys = [];
    if (!isset($keys[$name])) {
        $seed = hash('sha256', 'key:' . $name, true);
        $keys[$name] = Signing::keypairFromSeed($seed);
    }
    return $keys[$name];
}

/** Normalize one symbolic identifier to a well-formed one. */
function sym(string $s): string
{
    $colon = strpos($s, ':');
    $scheme = substr($s, 0, (int) $colon);
    $name = substr($s, (int) $colon + 1);
    if ($scheme === 'ed25519') {
        if (preg_match('~^[0-9a-f]{64}$~', $name) === 1) {
            return $s; // a real key passes through
        }
        return keyPair($name)[1];
    }
    if (preg_match('~^[0-9a-f]{64}$~', $name) === 1) {
        return $s; // a real identifier passes through
    }
    return $scheme . ':' . hash('sha256', $name);
}

/** Recursively normalize symbolic identifiers and placeholders. */
function normalize(mixed $x): mixed
{
    if (is_string($x)) {
        if ($x === '<128 hex>') {
            return str_repeat('ab', 64);
        }
        $pattern = '~^(' . implode('|', array_merge(CO_SCHEMES, ['ed25519'])) . '):~';
        if (preg_match($pattern, $x) === 1) {
            return sym($x);
        }
        return $x;
    }
    if (is_array($x)) {
        $out = [];
        foreach ($x as $key => $value) {
            $out[$key] = normalize($value); // keys (and list-ness) preserved
        }
        return $out;
    }
    return $x;
}

/** Load vector n's JSON file (for its structured inputs). */
function vec(int $n): array
{
    $hits = glob(CO_VECDIR . sprintf('/v%02d_*.json', $n));
    assertTrue(is_array($hits) && count($hits) === 1, "vector $n not found");
    $raw = file_get_contents($hits[0]);
    assertTrue($raw !== false, "vector $n unreadable");
    return json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
}

/** The stem of vector n's file name, for the report lines. */
function vecName(int $n): string
{
    $hits = glob(CO_VECDIR . sprintf('/v%02d_*.json', $n));
    assertTrue(is_array($hits) && count($hits) === 1, "vector $n not found");
    return basename($hits[0], '.json');
}

/** Build, timestamp, and sign a provenance record. */
function signed(string $kind, array $body, string $who, int $tsIndex = 0): array
{
    [$secret, $publicId] = keyPair($who);
    $record = $body;
    $record['type'] = $kind;
    if (!array_key_exists('timestamp', $record)) {
        $record['timestamp'] = sprintf('2026-07-13T0%d:00:00Z', $tsIndex);
    }
    if ($kind === 'succession') {
        if (!array_key_exists('predecessor', $record)) {
            $record['predecessor'] = $publicId;
        }
    } else {
        $record['source'] = $publicId;
    }
    return Signing::signRecord($record, $secret, $kind);
}

/** A content object completed with its real content-addressed id. */
function mk(array $o): array
{
    $o['id'] = Canonical::identify($o);
    return $o;
}

// ---------------------------------------------------------------------------
// content builders (mirroring the Python reference)
// ---------------------------------------------------------------------------

function stratum(string $label, string $scheme, int $ordinal,
                 ?string $unit = null, ?array $governs = null): array
{
    $o = ['type' => 'stratum', 'label' => $label, 'scheme' => $scheme, 'ordinal' => $ordinal];
    if ($unit !== null) {
        $o['unit'] = $unit;
    }
    if ($governs !== null) {
        $o['governs'] = $governs;
    }
    return mk($o);
}

function occ(string $label, ?string $stratumId = null, string $category = 'event'): array
{
    $o = ['type' => 'occurrent', 'label' => $label, 'category' => $category];
    if ($stratumId !== null) {
        $o['stratum'] = $stratumId;
    }
    return mk($o);
}

function cnt(string $label, string $category = 'object'): array
{
    return mk(['type' => 'continuant', 'label' => $label, 'category' => $category]);
}

function cro(array $causes, array $effects, array $kw = []): array
{
    $o = ['type' => 'causal_relation_object', 'causes' => $causes, 'effects' => $effects];
    foreach ($kw as $k => $v) {
        $o[$k] = $v;
    }
    return mk($o);
}

function bridge(string $coarse, array $fine, string $relation): array
{
    return mk(['type' => 'bridge', 'coarse' => $coarse, 'fine' => $fine,
               'relation' => $relation]);
}

function port(string $bearer, string $label, string $direction,
              array $accepts, ?string $realizable = null): array
{
    $o = ['type' => 'port', 'bearer' => $bearer, 'label' => $label,
          'direction' => $direction, 'accepts' => $accepts];
    if ($realizable !== null) {
        $o['realizable'] = $realizable;
    }
    return mk($o);
}

function conduit(string $frm, string $to, array $carries,
                 string $label = 'conn', ?string $transform = null): array
{
    $o = ['type' => 'conduit', 'label' => $label, 'from' => $frm, 'to' => $to,
          'carries' => $carries];
    if ($transform !== null) {
        $o['transform'] = $transform;
    }
    return mk($o);
}

function quality(string $label, string $datatype,
                 ?string $unit = null, ?string $stratumId = null): array
{
    $o = ['type' => 'quality', 'label' => $label, 'datatype' => $datatype];
    if ($unit !== null) {
        $o['unit'] = $unit;
    }
    if ($stratumId !== null) {
        $o['stratum'] = $stratumId;
    }
    return mk($o);
}

function individual(string $instantiates, ?string $designator = null,
                    ?string $partOf = null): array
{
    $o = ['type' => 'token_individual', 'instantiates' => $instantiates];
    if ($designator !== null) {
        $o['designator'] = $designator;
    }
    if ($partOf !== null) {
        $o['part_of'] = $partOf;
    }
    return mk($o);
}

function token(string $instantiates, array $interval,
               ?array $participants = null, ?string $locus = null): array
{
    $o = ['type' => 'token_occurrence', 'instantiates' => $instantiates,
          'interval' => $interval];
    if ($participants !== null) {
        $o['participants'] = $participants;
    }
    if ($locus !== null) {
        $o['locus'] = $locus;
    }
    return mk($o);
}

function state(string $subject, string $qual, array $value, array $interval): array
{
    return mk(['type' => 'state_assertion', 'subject' => $subject, 'quality' => $qual,
               'value' => $value, 'interval' => $interval]);
}

function tcc(array $causes, array $effects, ?string $coveringLaw = null,
             ?array $actualDelay = null, ?bool $counterfactual = null): array
{
    $o = ['type' => 'token_causal_claim', 'causes' => $causes, 'effects' => $effects];
    if ($coveringLaw !== null) {
        $o['covering_law'] = $coveringLaw;
    }
    if ($actualDelay !== null) {
        $o['actual_delay'] = $actualDelay;
    }
    if ($counterfactual !== null) {
        $o['counterfactual'] = $counterfactual;
    }
    return mk($o);
}

function rlz(string $bearer, string $kind, ?string $label = null): array
{
    $o = ['type' => 'realizable', 'kind' => $kind, 'bearer' => $bearer];
    if ($label !== null) {
        $o['label'] = $label;
    }
    return mk($o);
}

// ---------------------------------------------------------------------------
// shared fixtures
// ---------------------------------------------------------------------------

/** The neuroendocrine stratum stack, keyed by ordinal. */
function neuro(): array
{
    $labels = [4 => 'macromolecular', 5 => 'subcellular', 6 => 'cellular',
               7 => 'synaptic', 9 => 'region', 14 => 'community_and_society'];
    $out = [];
    foreach ($labels as $ordinal => $label) {
        $out[$ordinal] = stratum($label, 'neuroendocrine', $ordinal);
    }
    return $out;
}

/** @return array{0: array, 1: array, 2: array} [bridge, occMap, stratumMap] */
function bridgeFixture(string $relation): array
{
    $s = neuro();
    $coarse = occ('action_potential_fires', $s[6]['id']);
    $fine = [occ('sodium_channels_open', $s[4]['id']),
             occ('sodium_influx', $s[4]['id'])];
    $b = bridge($coarse['id'], [$fine[0]['id'], $fine[1]['id']], $relation);
    $omap = [$coarse['id'] => $coarse];
    foreach ($fine as $f) {
        $omap[$f['id']] = $f;
    }
    $smap = [$s[4]['id'] => $s[4], $s[6]['id'] => $s[6]];
    return [$b, $omap, $smap];
}

/** @return array{0: array, 1: array, 2: array} [parent, members, bridges] */
function reachFixture(): array
{
    $s = neuro();
    $ap = occ('action_potential_fires', $s[6]['id']);
    $nt = occ('neurotransmitter_released', $s[6]['id']);
    $fa = occ('calcium_enters', $s[4]['id']);
    $fb = occ('vesicle_fuses', $s[4]['id']);
    $m1 = cro([$fa['id']], [$fb['id']]);
    $P = cro([$ap['id']], [$nt['id']], ['mechanism' => [$m1['id']]]);
    $bridges = [bridge($ap['id'], [$fa['id']], 'constitutes'),
                bridge($nt['id'], [$fb['id']], 'constitutes')];
    return [$P, [$m1['id'] => $m1], $bridges];
}

/** classify_cro over the neuro stack for a single cause/effect ordinal pair. */
function classifyOf(int $causeOrd, int $effectOrd): string
{
    $s = neuro();
    $c = occ('c', $s[$causeOrd]['id']);
    $e = occ('e', $s[$effectOrd]['id']);
    $smap = [$s[$causeOrd]['id'] => $s[$causeOrd], $s[$effectOrd]['id'] => $s[$effectOrd]];
    $omap = [$c['id'] => $c, $e['id'] => $e];
    return Semantics::classifyCro(cro([$c['id']], [$e['id']]), $omap, $smap);
}

/** @return array{0: array, 1: string} [cro, classification] */
function skipFixture(int $causeOrd, int $effectOrd, array $kw = []): array
{
    $s = neuro();
    $c = occ('c', $s[$causeOrd]['id']);
    $e = occ('e', $s[$effectOrd]['id']);
    $smap = [$s[$causeOrd]['id'] => $s[$causeOrd], $s[$effectOrd]['id'] => $s[$effectOrd]];
    $omap = [$c['id'] => $c, $e['id'] => $e];
    $P = cro([$c['id']], [$e['id']], $kw);
    return [$P, Semantics::classifyCro($P, $omap, $smap)];
}

/** @return array{0: array, 1: array, 2: array} [conduit, portMap, croMap] */
function conduitFixture(bool $transform = false, bool $badCarry = false, bool $inFrom = false): array
{
    $x = sym('occurrent:motor_command');
    $y = sym('occurrent:error_signal');
    $z = sym('occurrent:unrelated');
    $m1 = cnt('motor_cortex')['id'];
    $m2 = cnt('spinal_neuron')['id'];
    $frm = port($m1, 'out_port', $inFrom ? 'in' : 'out', [$x]);
    $to = port($m2, 'in_port', 'in', $transform ? [$y] : [$x]);
    $carries = $badCarry ? [$z] : [$x];
    $xform = null;
    $croMap = [];
    if ($transform) {
        $law = cro([$x], [$y]);
        $croMap[$law['id']] = $law;
        $xform = $law['id'];
    }
    $c = conduit($frm['id'], $to['id'], $carries, 'conn', $xform);
    return [$c, [$frm['id'] => $frm, $to['id'] => $to], $croMap];
}

/** @return array{0: array, 1: array, 2: array, 3: array, 4: array} */
function lawAndTokens(): array
{
    $oCause = occ('resection');
    $oEffect = occ('amnesia_onset');
    $law = cro([$oCause['id']], [$oEffect['id']],
               ['temporal' => ['minimum_delay' => 0, 'maximum_delay' => 1, 'unit' => 'days'],
                'modality' => 'sufficient']);
    $tCause = token($oCause['id'], ['start' => '1953-08-25T00:00:00Z']);
    $tEffect = token($oEffect['id'], ['start' => '1953-08-25T00:00:00Z', 'open' => true]);
    return [$law, $oCause, $oEffect, $tCause, $tEffect];
}

/** @return array{0: array, 1: array} [state, quality] */
function stateFixture(string $datatype, array $value, ?string $unit = null): array
{
    $q = quality('cortisol_concentration', $datatype, $unit);
    $c = cnt('human_patient')['id'];
    $subj = individual($c, 'p')['id'];
    $st = state($subj, $q['id'], $value,
                ['start' => '2026-01-01T00:00:00Z', 'end' => '2026-01-01T01:00:00Z']);
    return [$st, $q];
}

// ---------------------------------------------------------------------------
// internal sanity checks (not conformance vectors)
// ---------------------------------------------------------------------------

function internalChecks(): void
{
    $seed = hex2bin('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
    assertTrue(is_string($seed), 'hex2bin failed on the RFC 8032 seed');
    $public = Signing::secretToPublic($seed);
    assertTrue(bin2hex($public)
        === 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
        'RFC 8032 TEST 1 public key mismatch: ' . bin2hex($public));
    $signature = Signing::sign($seed, '');
    assertTrue(Signing::verify($public, '', $signature),
        'RFC 8032 TEST 1 signature did not verify');
    assertTrue(!Signing::verify($public, 'x', $signature),
        'RFC 8032 signature verified a different message');
    assertTrue(Jcs::serialize(['b' => 2, 'a' => 1]) === '{"a":1,"b":2}',
        'JCS key sort failed');
    assertTrue(Jcs::serialize(1.0) === '1' && Jcs::serialize(6.000) === '6'
            && Jcs::serialize(0.7) === '0.7',
        'JCS number serialization failed');
    assertTrue(Jcs::serialize([]) === '[]',
        'an empty array must serialize as []');
    assertTrue(Semantics::toSeconds(1, 'months') === 2629746, 'to_seconds months');
    assertTrue(Semantics::toSeconds(1, 'years') === 31556952, 'to_seconds years');
}

// ---------------------------------------------------------------------------
// shared vector helpers
// ---------------------------------------------------------------------------

/** Assert vector n is schema-invalid with a reason naming $mustMention. */
function schemaFails(int $n, string $mustMention): void
{
    $input = normalize(vec($n)['input']);
    [$ok, $why] = SchemaValidator::validateSchema($input);
    assertTrue(!$ok, 'expected schema-invalid');
    $found = false;
    foreach ($why as $reason) {
        if (str_contains($reason, $mustMention)) {
            $found = true;
            break;
        }
    }
    assertTrue($found, implode('; ', $why));
}

/** Assert vector n is semantically invalid with a reason naming $mustMention. */
function semanticsFails(int $n, string $mustMention): void
{
    $input = normalize(vec($n)['input']);
    [$ok, $why] = Semantics::validateSemantics($input);
    assertTrue(!$ok, 'expected semantically-invalid');
    $found = false;
    foreach ($why as $reason) {
        if (str_contains($reason, $mustMention)) {
            $found = true;
            break;
        }
    }
    assertTrue($found, implode('; ', $why));
}

/** The admissibility of vector n's temporal window and elapsed seconds. */
function adm(int $n): bool
{
    $given = vec($n)['given'];
    $cro = ['causes' => [sym('occurrent:c')], 'effects' => [sym('occurrent:e')],
            'temporal' => $given['temporal']];
    return Semantics::admissible($cro, $given['elapsed_seconds']);
}

/** Recursively collect scheme:64hex identifiers (for V106). */
function scanIds(mixed $node, array &$ids): void
{
    if (is_string($node)) {
        if (preg_match('~^([a-z0-9_]+):[0-9a-f]{64}$~', $node, $m) === 1) {
            $ids[] = $m[1];
        }
    } elseif (is_array($node)) {
        foreach ($node as $value) {
            scanIds($value, $ids);
        }
    }
}

// ---------------------------------------------------------------------------
// the 107 vectors
// ---------------------------------------------------------------------------

/** @return array<string, callable(): void> the vector suite, v01..v107 */
function vectorSuite(): array
{
    $v = [];

    // --- V01 - V38: the whole-word re-freeze of the 1.0.0 suite ---
    $v['v01'] = function (): void {
        $input = normalize(vec(1)['input']);
        [$ok, $why] = SchemaValidator::validateSchema($input);
        assertTrue($ok, implode('; ', $why));
        [$ok, $why] = Semantics::validateSemantics($input);
        assertTrue($ok, implode('; ', $why));
    };
    $v['v02'] = function (): void {
        $input = normalize(vec(2)['input']);
        assertTrue(SchemaValidator::validateSchema($input)[0], 'schema');
        assertTrue(Semantics::validateSemantics($input)[0], 'semantics');
        [$partial, $missing] = Semantics::isPartial($input);
        assertTrue($partial && $missing === vec(2)['expect']['missing'],
            'missing = ' . json_encode($missing));
    };
    $v['v03'] = fn () => schemaFails(3, 'effects');
    $v['v04'] = fn () => schemaFails(4, 'causes');
    $v['v05'] = fn () => schemaFails(5, 'modality');
    $v['v06'] = fn () => schemaFails(6, 'colour');
    $v['v07'] = fn () => schemaFails(7, 'causes');
    $v['v08'] = function (): void {
        [$ok, $why] = SchemaValidator::validateSchema(normalize(vec(8)['input']));
        assertTrue($ok, implode('; ', $why));
    };
    $v['v09'] = fn () => schemaFails(9, 'label');
    $v['v10'] = fn () => schemaFails(10, 'category');
    $v['v11'] = function (): void {
        [$ok, $why] = SchemaValidator::validateSchema(normalize(vec(11)['input']));
        assertTrue($ok, implode('; ', $why));
    };
    $v['v12'] = fn () => schemaFails(12, 'confidence');
    $v['v13'] = function (): void {
        $input = normalize(vec(13)['input']);
        [$ok, $why] = SchemaValidator::validateSchema($input);
        assertTrue($ok, implode('; ', $why));
        [$ok, $why] = Semantics::validateSemantics($input);
        assertTrue($ok, implode('; ', $why));
    };
    $v['v14'] = function (): void {
        $input = normalize(vec(14)['input']);
        assertTrue(SchemaValidator::validateSchema($input)[0], 'schema should pass');
        semanticsFails(14, 'minimum_delay');
    };
    $v['v15'] = fn () => semanticsFails(15, 'acyclic');
    $v['v16'] = fn () => semanticsFails(16, 'acyclic');
    $v['v17'] = function (): void {
        $vector = vec(17);
        $parent = normalize($vector['given']['parent']);
        $child = normalize($vector['input']);
        [$ok, $reason] = Semantics::refinementValid($child, $parent);
        assertTrue(!$ok && str_contains($reason, 'rival'), $reason);
    };
    $v['v18'] = fn () => semanticsFails(18, 'not a legal field');
    $v['v19'] = fn () => semanticsFails(19, 'language-tagged');
    $v['v20'] = function (): void {
        $dog = sym('continuant:dog');
        $mammal = sym('continuant:mammal');
        $animal = sym('continuant:animal');
        $enrich = fn (string $about, string $entry, int $i): array =>
            signed('enrichment',
                   ['about' => $about, 'field' => 'subsumes', 'entry' => $entry],
                   'taxo', $i);
        $store = new Store(true);
        $store->putRecord($enrich($dog, $mammal, 1));
        $store->putRecord($enrich($mammal, $animal, 2));
        $threw = false;
        try {
            $store->putRecord($enrich($animal, $dog, 3));
        } catch (RejectedWrite $e) {
            assertTrue(str_contains($e->getMessage(), 'cycle'), $e->getMessage());
            $threw = true;
        }
        assertTrue($threw, 'enforcing store accepted a cycle');
        $store2 = new Store(true);
        $store2->putRecord($enrich($dog, $mammal, 1));
        $store2->putRecord($enrich($mammal, $animal, 2));
        $bad = $enrich($animal, $dog, 3);
        $store2->forceMergeRecord($bad);
        [, $excluded] = $store2->activeTaxonomyEdges('subsumes');
        assertTrue(count($excluded) === 1 && $excluded[0]['id'] === $bad['id'],
            'wrong record excluded');
        $repairSeen = false;
        foreach ($store2->gaps('inconsistent_hierarchy') as $gap) {
            if ($gap['id'] === $bad['id']) {
                $repairSeen = true;
            }
        }
        assertTrue($repairSeen, 'no repair gap emitted');
    };
    $v['v21'] = fn () => assertTrue(adm(21) === true, 'expected admissible');
    $v['v22'] = fn () => assertTrue(adm(22) === false, 'expected inadmissible');
    $v['v23'] = fn () => assertTrue(adm(23) === true, 'expected admissible');
    $v['v24'] = function (): void {
        $vector = vec(24);
        assertTrue(Canonical::identify(normalize($vector['inputA']))
                === Canonical::identify(normalize($vector['inputB'])),
            'key order changed identity');
    };
    $v['v25'] = function (): void {
        $vector = vec(25);
        assertTrue(Canonical::identify(normalize($vector['inputA']))
                === Canonical::identify(normalize($vector['inputB'])),
            'number formatting changed identity');
    };
    $v['v26'] = function (): void {
        $store = new Store();
        $obj = ['type' => 'occurrent', 'label' => 'press_button', 'category' => 'action'];
        assertTrue($store->put($obj) === $store->put($obj) && count($store->objects) === 1,
            'put not idempotent');
    };
    $v['v27'] = function (): void {
        $store = new Store();
        $occ = $store->put(['type' => 'occurrent', 'label' => 'press_button',
                            'category' => 'action']);
        $entry = ['lang' => 'en', 'text' => 'press the button'];
        $r1 = signed('enrichment', ['about' => $occ, 'field' => 'aliases',
                                    'entry' => $entry], 'alice', 1);
        $r2 = signed('enrichment', ['about' => $occ, 'field' => 'aliases',
                                    'entry' => $entry], 'bob', 2);
        assertTrue($store->putRecord($r1) !== $store->putRecord($r2), 'expected two records');
        $view = $store->get($occ)['enrichments']['aliases'] ?? [];
        assertTrue(count($view) === 1 && count($view[0]['contributors']) === 2,
            'expected one entry with two contributors');
    };
    $v['v28'] = function (): void {
        $store = new Store();
        $claim = ['type' => 'causal_relation_object', 'causes' => [sym('occurrent:A')],
                  'effects' => [sym('occurrent:B')], 'modality' => 'sufficient'];
        assertTrue($store->put($claim) === $store->put($claim) && count($store->objects) === 1,
            'expected one object');
        $x = $store->put($claim);
        foreach ([['lab1', 1], ['lab2', 2]] as [$who, $ts]) {
            $store->putRecord(signed('assertion',
                ['about' => $x, 'evidence_type' => 'observation',
                 'strength' => 0.8, 'confidence' => 0.8], $who, $ts));
        }
        assertTrue(count($store->assertionsAbout($x)) === 2, 'expected two assertions');
    };
    $v['v29'] = function (): void {
        $record = signed('assertion', ['about' => sym('causal_relation_object:demo'),
                                       'evidence_type' => 'intervention',
                                       'strength' => 0.7, 'confidence' => 0.9], 'signer');
        assertTrue(Signing::verifyRecord($record) === true, 'valid signature did not verify');
    };
    $v['v30'] = function (): void {
        $record = signed('assertion', ['about' => sym('causal_relation_object:demo'),
                                       'evidence_type' => 'intervention',
                                       'strength' => 0.7, 'confidence' => 0.9], 'signer');
        $record['confidence'] = 0.1;
        assertTrue(Signing::verifyRecord($record) === false, 'tampered record verified');
    };
    $v['v31'] = function (): void {
        $store = new Store();
        $x = $store->put(['type' => 'causal_relation_object', 'causes' => [sym('occurrent:A')],
                          'effects' => [sym('occurrent:B')]]);
        $assertion = signed('assertion', ['about' => $x, 'evidence_type' => 'observation',
                                          'confidence' => 0.8], 'lab1', 1);
        $store->putRecord($assertion);
        $store->putRecord(signed('retraction', ['retracts' => $assertion['id']], 'lab1', 2));
        assertTrue($store->assertionsAbout($x) === [], 'retracted assertion visible');
        $history = $store->assertionsAbout($x, true);
        assertTrue(count($history) === 1 && $history[0]['retracted'] === true, 'history wrong');
        $threw = false;
        try {
            $store->putRecord(signed('retraction', ['retracts' => $assertion['id']], 'mallory', 3));
        } catch (RejectedWrite) {
            $threw = true;
        }
        assertTrue($threw, 'foreign retraction accepted');
    };
    $v['v32'] = function (): void {
        $store = new Store();
        $occ = $store->put(['type' => 'occurrent', 'label' => 'press_button',
                            'category' => 'action']);
        $enrichment = signed('enrichment', ['about' => $occ, 'field' => 'aliases',
                             'entry' => ['lang' => 'ja', 'text' => 'botan']], 'bob', 1);
        $store->putRecord($enrichment);
        assertTrue(count($store->get($occ)['enrichments']['aliases'] ?? []) === 1,
            'enrichment missing');
        $store->putRecord(signed('retraction', ['retracts' => $enrichment['id']], 'bob', 2));
        assertTrue(($store->get($occ)['enrichments']['aliases'] ?? []) === [],
            'retracted enrichment still visible');
        $history = $store->get($occ, 'history')['enrichments']['aliases'] ?? [];
        assertTrue(count($history) === 1, 'history view lost the enrichment');
    };
    $v['v33'] = function (): void {
        $store = new Store();
        $k1 = keyPair('K1')[1];
        $k2 = keyPair('K2')[1];
        $assertion = signed('assertion', ['about' => sym('causal_relation_object:claim'),
                            'evidence_type' => 'observation', 'confidence' => 0.9], 'K1', 1);
        $store->putRecord($assertion);
        $store->putRecord(signed('succession', ['successor' => $k2], 'K1', 2));
        assertTrue(in_array($k1, $store->lineage($k2), true)
                && in_array($k2, $store->lineage($k1), true), 'lineage broken');
        $store->putRecord(signed('retraction', ['retracts' => $assertion['id']], 'K2', 3));
        assertTrue($store->assertionsAbout(sym('causal_relation_object:claim')) === [],
            'successor retraction not honored');
    };
    $v['v34'] = function (): void {
        $given = normalize(vec(34)['given']);
        assertTrue(Semantics::conflicts($given['A'], $given['B']) === true, 'expected a conflict');
    };
    $v['v35'] = function (): void {
        $given = normalize(vec(35)['given']);
        assertTrue(Semantics::conflicts($given['A'], $given['B']) === false, 'expected no conflict');
    };
    $v['v36'] = function (): void {
        $a = sym('occurrent:A');
        $b = sym('occurrent:B');
        $c = sym('occurrent:C');
        $d = sym('occurrent:D');
        $m1 = ['id' => sym('causal_relation_object:m1'), 'causes' => [$a], 'effects' => [$b]];
        $m2 = ['id' => sym('causal_relation_object:m2'), 'causes' => [$b], 'effects' => [$c]];
        $m3 = ['id' => sym('causal_relation_object:m3'), 'causes' => [$d], 'effects' => [$c]];
        $P = ['causes' => [$a], 'effects' => [$c], 'mechanism' => [$m1['id'], $m2['id']]];
        assertTrue(Semantics::hierarchyConsistent($P, [$m1['id'] => $m1, $m2['id'] => $m2]) === 'consistent',
            'chain should be consistent');
        $P2 = $P;
        $P2['mechanism'] = [$m1['id'], $m3['id']];
        assertTrue(Semantics::hierarchyConsistent($P2, [$m1['id'] => $m1, $m3['id'] => $m3]) === 'inconsistent',
            'broken chain should be inconsistent');
        assertTrue(Semantics::hierarchyConsistent($P, [$m1['id'] => $m1]) === 'indeterminate',
            'missing member should be indeterminate');
    };
    $v['v37'] = function (): void {
        $store = new Store();
        $occ = $store->put(['type' => 'occurrent', 'label' => 'press_button',
                            'category' => 'action']);
        $store->putRecord(signed('enrichment', ['about' => $occ, 'field' => 'aliases',
                          'entry' => ['lang' => 'en', 'text' => 'Press the Button']], 'alice', 1));
        assertTrue($store->resolve('Press  The   Button', 'en') === [$occ], 'alias resolve failed');
        assertTrue(($store->resolve('press_button', 'en')[0] ?? null) === $occ, 'label resolve failed');
    };
    $v['v38'] = function (): void {
        $store = new Store();
        $parent = $store->put(['type' => 'causal_relation_object', 'causes' => [sym('occurrent:A')],
                               'effects' => [sym('occurrent:B')]]);
        $gapIds = array_map(fn (array $g): string => $g['id'], $store->gaps('missing_field'));
        assertTrue(in_array($parent, $gapIds, true), 'the bare CRO must be a gap');
        $refinement = $store->put(['type' => 'causal_relation_object', 'causes' => [sym('occurrent:A')],
                                   'effects' => [sym('occurrent:B')],
                                   'temporal' => ['minimum_delay' => 0, 'maximum_delay' => 1,
                                                  'unit' => 'seconds'],
                                   'modality' => 'sufficient', 'refines' => $parent]);
        $gapIds = array_map(fn (array $g): string => $g['id'], $store->gaps('missing_field'));
        assertTrue(!in_array($parent, $gapIds, true), 'the gap did not close');
        assertTrue(!in_array($refinement, $gapIds, true), 'the refinement itself must be complete');
    };

    // --- V39 - V107: the 2.0.0 additions ---
    $v['v39'] = function (): void {
        $st = stratum('cellular', 'neuroendocrine', 6, 'cell', ['cell_biology']);
        [$ok, $why] = SchemaValidator::validateSchema($st);
        assertTrue($ok, implode('; ', $why));
    };
    $v['v40'] = function (): void {
        $bad = mk(['type' => 'stratum', 'label' => 'cellular', 'ordinal' => 6]);
        [$ok, $why] = SchemaValidator::validateSchema($bad, 'stratum');
        $found = false;
        foreach ($why as $w) {
            if (str_contains($w, 'scheme')) {
                $found = true;
            }
        }
        assertTrue(!$ok && $found, implode('; ', $why));
    };
    $v['v41'] = function (): void {
        $a = stratum('cellular', 'neuroendocrine', 6);
        $b = stratum('neuronal', 'neuroendocrine', 6);
        foreach ([$a, $b] as $x) {
            [$ok, $why] = SchemaValidator::validateSchema($x);
            assertTrue($ok, implode('; ', $why));
        }
        assertTrue($a['id'] !== $b['id'], 'distinct strata share an id');
    };
    $v['v42'] = function (): void {
        $s = neuro();
        $s4p = stratum('molecular', 'physics', 4);
        $c = occ('chronic_social_subordination', $s[14]['id']);
        $e = occ('gene_expression', $s4p['id']);
        $smap = [$s[14]['id'] => $s[14], $s4p['id'] => $s4p];
        $omap = [$c['id'] => $c, $e['id'] => $e];
        $P = cro([$c['id']], [$e['id']]);
        assertTrue(Semantics::classifyCro($P, $omap, $smap) === 'scheme_mismatch', 'expected scheme_mismatch');
    };
    $v['v43'] = function (): void {
        foreach ([stratum('macromolecular', 'neuroendocrine', 4),
                  stratum('region', 'neuroendocrine', 9)] as $x) {
            [$ok, $why] = SchemaValidator::validateSchema($x);
            assertTrue($ok, implode('; ', $why));
        }
    };
    $v['v44'] = function (): void {
        $st = stratum('cellular', 'neuroendocrine', 6);
        $o = occ('neuron_fires', $st['id']);
        [$ok, $why] = SchemaValidator::validateSchema($o);
        assertTrue($ok, implode('; ', $why));
        [$ok, $why] = Semantics::validateSemantics($o);
        assertTrue($ok, implode('; ', $why));
    };
    $v['v45'] = function (): void {
        $o = occ('press_button');
        [$ok, $why] = SchemaValidator::validateSchema($o);
        assertTrue($ok, implode('; ', $why));
        $e = occ('light_on');
        $P = cro([$o['id']], [$e['id']]);
        assertTrue(Semantics::classifyCro($P, [$o['id'] => $o, $e['id'] => $e], []) === 'unclassifiable',
            'expected unclassifiable');
    };
    $v['v46'] = function (): void {
        $s = neuro();
        $a = occ('depolarization', $s[5]['id']);
        $b = occ('depolarization', $s[6]['id']);
        assertTrue($a['id'] !== $b['id'], 'same label, different stratum must differ');
    };
    $validBridge = function (string $relation): void {
        [$b, $omap, $smap] = bridgeFixture($relation);
        [$ok, $why] = SchemaValidator::validateSchema($b);
        assertTrue($ok, implode('; ', $why));
        [$ok, $why] = Semantics::bridgeWellformed($b, $omap, $smap);
        assertTrue($ok, $why);
    };
    $v['v47'] = fn () => $validBridge('constitutes');
    $v['v48'] = fn () => $validBridge('aggregates');
    $v['v49'] = fn () => $validBridge('realizes');
    $v['v50'] = fn () => $validBridge('supervenes_on');
    $v['v51'] = function (): void {
        $s = neuro();
        $coarse = occ('x_coarse', $s[4]['id']);
        $fine = occ('x_fine', $s[6]['id']);
        $b = bridge($coarse['id'], [$fine['id']], 'constitutes');
        $omap = [$coarse['id'] => $coarse, $fine['id'] => $fine];
        $smap = [$s[4]['id'] => $s[4], $s[6]['id'] => $s[6]];
        assertTrue(!Semantics::bridgeWellformed($b, $omap, $smap)[0], 'coarse ordinal < fine must fail');
    };
    $v['v52'] = function (): void {
        $s = neuro();
        $coarse = occ('c', $s[6]['id']);
        $f1 = occ('f1', $s[4]['id']);
        $f2 = occ('f2', $s[5]['id']);
        $b = bridge($coarse['id'], [$f1['id'], $f2['id']], 'constitutes');
        $omap = [$coarse['id'] => $coarse, $f1['id'] => $f1, $f2['id'] => $f2];
        $smap = [$s[4]['id'] => $s[4], $s[5]['id'] => $s[5], $s[6]['id'] => $s[6]];
        assertTrue(!Semantics::bridgeWellformed($b, $omap, $smap)[0], 'fine spanning strata must fail');
    };
    $v['v53'] = function (): void {
        $x = sym('occurrent:x');
        $y = sym('occurrent:y');
        $b1 = bridge($x, [$y], 'constitutes');
        $b2 = bridge($y, [$x], 'constitutes');
        $edges = [];
        foreach ([$b1, $b2] as $b) {
            foreach ($b['fine'] as $f) {
                $edges[(string) $f][] = $b['coarse'];
            }
        }
        assertTrue(Semantics::hasCycle($edges) === true, 'expected a cycle');
    };
    $v['v54'] = function (): void {
        $a = stratum('cellular', 'neuroendocrine', 6);
        $b = stratum('molecular', 'physics', 4);
        $coarse = occ('c', $a['id']);
        $fine = occ('f', $b['id']);
        $br = bridge($coarse['id'], [$fine['id']], 'constitutes');
        $omap = [$coarse['id'] => $coarse, $fine['id'] => $fine];
        $smap = [$a['id'] => $a, $b['id'] => $b];
        assertTrue(!Semantics::bridgeWellformed($br, $omap, $smap)[0], 'cross-scheme bridge must fail');
    };
    $v['v55'] = function (): void {
        $s = neuro();
        $coarse = occ('decision_made', $s[6]['id']);
        $f1 = occ('cascade_a', $s[4]['id']);
        $f2 = occ('cascade_b', $s[4]['id']);
        $b1 = bridge($coarse['id'], [$f1['id']], 'realizes');
        $b2 = bridge($coarse['id'], [$f2['id']], 'realizes');
        assertTrue($b1['id'] !== $b2['id'], 'distinct bridges share an id');
        foreach ([$b1, $b2] as $b) {
            [$ok, $why] = SchemaValidator::validateSchema($b);
            assertTrue($ok, implode('; ', $why));
        }
    };
    $v['v56'] = function (): void {
        [$P, $members, $bridges] = reachFixture();
        assertTrue(Semantics::hierarchyConsistent($P, $members, $bridges) === 'consistent',
            'bridged reachability should be consistent');
    };
    $v['v57'] = function (): void {
        [$P, $members] = reachFixture();
        assertTrue(Semantics::hierarchyConsistent($P, $members, []) === 'inconsistent',
            'literal reachability should be inconsistent');
    };
    $v['v58'] = function (): void {
        [$P, $members, $bridges] = reachFixture();
        $literal = Semantics::hierarchyConsistent($P, $members, []);
        $bridged = Semantics::hierarchyConsistent($P, $members, $bridges);
        assertTrue($literal !== 'consistent' && $bridged === 'consistent',
            'literal must differ from bridged');
    };
    $v['v59'] = fn () => assertTrue(classifyOf(6, 6) === 'intra_stratal', 'expected intra_stratal');
    $v['v60'] = fn () => assertTrue(classifyOf(6, 5) === 'adjacent_stratal', 'expected adjacent_stratal');
    $v['v61'] = fn () => assertTrue(classifyOf(14, 4) === 'skipping', 'expected skipping');
    $v['v62'] = function (): void {
        [$P, $cls] = skipFixture(14, 4);
        assertTrue(Semantics::skipGaps($P, $cls) === ['incomplete_mechanism'],
            'skips absent must surface incomplete_mechanism');
    };
    $v['v63'] = function (): void {
        [$P, $cls] = skipFixture(14, 4, ['skips' => true]);
        assertTrue(Semantics::skipGaps($P, $cls) === [], 'skips true must surface nothing');
    };
    $v['v64'] = function (): void {
        [$P, $cls] = skipFixture(14, 4, ['skips' => true,
            'mechanism' => [sym('causal_relation_object:m')]]);
        assertTrue(Semantics::skipGaps($P, $cls) === ['contradictory_skip'], 'expected contradictory_skip');
        [$ok, $why] = Semantics::validateSemantics($P);
        $found = false;
        foreach ($why as $w) {
            if (str_contains($w, 'contradictory_skip')) {
                $found = true;
            }
        }
        assertTrue(!$ok && $found, implode('; ', $why));
    };
    $v['v65'] = function (): void {
        [$P, $cls] = skipFixture(6, 6, ['skips' => true]);
        assertTrue(Semantics::skipGaps($P, $cls) === ['vacuous_skip'], 'expected vacuous_skip');
    };
    $v['v66'] = function (): void {
        $s = neuro();
        $c = occ('c', $s[14]['id']);
        $e = occ('e', $s[4]['id']);
        $absent = cro([$c['id']], [$e['id']]);
        $false = cro([$c['id']], [$e['id']], ['skips' => false]);
        assertTrue($absent['id'] !== $false['id'], 'absent and skips:false must differ');
    };
    $v['v67'] = function (): void {
        $s = neuro();
        $c1 = occ('c1', $s[4]['id']);
        $c2 = occ('c2', $s[6]['id']);
        $e = occ('e', $s[6]['id']);
        $P = cro([$c1['id'], $c2['id']], [$e['id']]);
        assertTrue(Semantics::endpointsMixed($P, [$c1['id'] => $c1, $c2['id'] => $c2, $e['id'] => $e]) === true,
            'expected mixed endpoints');
    };
    $v['v68'] = function (): void {
        $P = cro([sym('occurrent:a')], [sym('occurrent:b')], ['modality' => 'enabling']);
        [$ok, $why] = SchemaValidator::validateSchema($P);
        assertTrue($ok, implode('; ', $why));
    };
    $v['v69'] = function (): void {
        $a = ['causes' => [sym('occurrent:a')], 'effects' => [sym('occurrent:b')], 'modality' => 'enabling'];
        $b = ['causes' => [sym('occurrent:a')], 'effects' => [sym('occurrent:b')], 'modality' => 'sufficient'];
        assertTrue(Semantics::conflicts($a, $b) === false, 'positive modalities must not conflict');
    };
    $v['v70'] = function (): void {
        $a = ['causes' => [sym('occurrent:a')], 'effects' => [sym('occurrent:b')], 'modality' => 'enabling'];
        $b = ['causes' => [sym('occurrent:a')], 'effects' => [sym('occurrent:b')], 'modality' => 'preventive'];
        assertTrue(Semantics::conflicts($a, $b) === true, 'enabling vs preventive must conflict');
    };
    $v['v71'] = function (): void {
        $b = cnt('hippocampus');
        $p = port($b['id'], 'perforant_path', 'in', [sym('occurrent:signal')]);
        [$ok, $why] = SchemaValidator::validateSchema($p);
        assertTrue($ok, implode('; ', $why));
    };
    $v['v72'] = function (): void {
        $b = cnt('hippocampus')['id'];
        $x = sym('occurrent:signal');
        assertTrue(port($b, 'perforant_path', 'in', [$x])['id']
                !== port($b, 'fornix', 'in', [$x])['id'], 'distinct ports share an id');
    };
    $v['v73'] = function (): void {
        [$c, $pmap] = conduitFixture();
        [$ok, $why] = SchemaValidator::validateSchema($c);
        assertTrue($ok, implode('; ', $why));
        [$ok, $why] = Semantics::conduitWellformed($c, $pmap);
        assertTrue($ok, $why);
    };
    $v['v74'] = function (): void {
        [$c, $pmap, $cmap] = conduitFixture(true);
        [$ok, $why] = SchemaValidator::validateSchema($c);
        assertTrue($ok, implode('; ', $why));
        [$ok, $why] = Semantics::conduitWellformed($c, $pmap, $cmap);
        assertTrue($ok, $why);
    };
    $v['v75'] = function (): void {
        [$c, $pmap] = conduitFixture(false, true);
        assertTrue(!Semantics::conduitWellformed($c, $pmap)[0], 'bad carry must fail');
    };
    $v['v76'] = function (): void {
        [$c, $pmap] = conduitFixture(false, false, true);
        assertTrue(!Semantics::conduitWellformed($c, $pmap)[0], 'in from-port must fail');
    };
    $v['v77'] = function (): void {
        [$c, $pmap, $cmap] = conduitFixture(true);
        [$ok, $why] = Semantics::conduitWellformed($c, $pmap, $cmap);
        assertTrue($ok, $why);
        $law = array_values($cmap)[0];
        assertTrue(!in_array($law['effects'][0], $c['carries'], true),
            'transform effect must not be carried');
    };
    $v['v78'] = function (): void {
        $b = cnt('hippocampus')['id'];
        assertTrue(rlz($b, 'disposition', 'long_term_potentiation')['id']
                !== rlz($b, 'disposition', 'pattern_separation')['id'], 'labels must distinguish');
    };
    $v['v79'] = function (): void {
        $b = cnt('hippocampus')['id'];
        $u1 = rlz($b, 'disposition');
        $u2 = rlz($b, 'disposition');
        [$ok, $why] = SchemaValidator::validateSchema($u1);
        assertTrue($ok, implode('; ', $why));
        assertTrue($u1['id'] === $u2['id'], 'unlabelled realizables must coincide');
        assertTrue(rlz($b, 'disposition', 'some_function')['id'] !== $u1['id'], 'label must distinguish');
    };
    $v['v80'] = function (): void {
        $parent = occ('fires');
        $child = occ('fires_action_potential');
        $e = ['type' => 'enrichment', 'about' => $child['id'],
              'field' => 'occurrent_subsumes', 'entry' => $parent['id']];
        [$ok, $why] = Semantics::validateSemantics($e);
        assertTrue($ok, implode('; ', $why));
    };
    $v['v81'] = function (): void {
        $a = sym('occurrent:a');
        $b = sym('occurrent:b');
        assertTrue(Semantics::hasCycle([$a => [$b], $b => [$a]]) === true, 'expected a cycle');
    };
    $v['v82'] = function (): void {
        $whole = occ('eat');
        $part = occ('chew');
        $e = ['type' => 'enrichment', 'about' => $part['id'],
              'field' => 'occurrent_part_of', 'entry' => $whole['id']];
        [$ok, $why] = Semantics::validateSemantics($e);
        assertTrue($ok, implode('; ', $why));
    };
    $v['v83'] = function (): void {
        [$legalKinds, $shape] = Semantics::ENRICHMENT_FIELDS['occurrent_part_of'];
        assertTrue($shape === 'occurrent' && $legalKinds === ['occurrent'], 'field spec wrong');
        $store = new Store();
        $store->put(occ('eat'));
        $store->put(occ('chew'));
        foreach ($store->objects as $o) {
            assertTrue(($o['type'] ?? null) !== 'causal_relation_object', 'unexpected CRO');
        }
    };
    $v['v84'] = function (): void {
        $s = neuro();
        $a = occ('run', $s[9]['id']);
        $b = occ('sprint', $s[6]['id']);
        assertTrue($a['stratum'] !== $b['stratum'], 'strata must differ');
    };
    $v['v85'] = function (): void {
        $c = cnt('human_patient');
        $ti = individual($c['id'], 'salted_hash_abc123');
        [$ok, $why] = SchemaValidator::validateSchema($ti);
        assertTrue($ok, implode('; ', $why));
    };
    $v['v86'] = function (): void {
        $bad = mk(['type' => 'token_individual', 'designator' => 'x']);
        [$ok, $why] = SchemaValidator::validateSchema($bad, 'token_individual');
        $found = false;
        foreach ($why as $w) {
            if (str_contains($w, 'instantiates')) {
                $found = true;
            }
        }
        assertTrue(!$ok && $found, implode('; ', $why));
    };
    $v['v87'] = function (): void {
        $c = cnt('human_patient')['id'];
        assertTrue(individual($c, 'hash_a')['id'] !== individual($c, 'hash_b')['id'],
            'designators must distinguish');
    };
    $v['v88'] = function (): void {
        $o = occ('bilateral_hippocampal_resection');
        $t = token($o['id'], ['start' => '1953-08-25T00:00:00Z', 'end' => '1953-08-25T00:00:00Z']);
        [$ok, $why] = SchemaValidator::validateSchema($t);
        assertTrue($ok, implode('; ', $why));
    };
    $v['v89'] = function (): void {
        $o = occ('amnesia_onset')['id'];
        $bounded = token($o, ['start' => '1953-08-25T00:00:00Z', 'end' => '1953-08-26T00:00:00Z']);
        $instantaneous = token($o, ['start' => '1953-08-25T00:00:00Z']);
        $ongoing = token($o, ['start' => '1953-08-25T00:00:00Z', 'open' => true]);
        $ids = [$bounded['id'] => true, $instantaneous['id'] => true, $ongoing['id'] => true];
        assertTrue(count($ids) === 3, 'three intervals must be distinct');
    };
    $v['v90'] = function (): void {
        $o = occ('resection')['id'];
        $c = cnt('human_patient')['id'];
        $patient = individual($c, 'p')['id'];
        $surgeon = individual($c, 's')['id'];
        $t = token($o, ['start' => '1953-08-25T00:00:00Z'],
                   [['role' => 'patient', 'filler' => $patient],
                    ['role' => 'agent', 'filler' => $surgeon]]);
        [$ok, $why] = SchemaValidator::validateSchema($t);
        assertTrue($ok, implode('; ', $why));
    };
    $v['v91'] = function (): void {
        $q = quality('cortisol_concentration', 'quantity', 'ug/dL');
        [$ok, $why] = SchemaValidator::validateSchema($q);
        assertTrue($ok, implode('; ', $why));
    };
    $v['v92'] = function (): void {
        [$st, $q] = stateFixture('quantity', ['quantity' => 15.0, 'unit' => 'ug/dL'], 'ug/dL');
        [$ok, $why] = SchemaValidator::validateSchema($st);
        assertTrue($ok, implode('; ', $why));
        assertTrue(Semantics::stateGaps($st, $q) === [], 'expected no gaps');
    };
    $v['v93'] = function (): void {
        [$st, $q] = stateFixture('categorical', ['categorical' => 'elevated']);
        [$ok, $why] = SchemaValidator::validateSchema($st);
        assertTrue($ok, implode('; ', $why));
        assertTrue(Semantics::stateGaps($st, $q) === [], 'expected no gaps');
    };
    $v['v94'] = function (): void {
        [$st, $q] = stateFixture('boolean', ['boolean' => true]);
        [$ok, $why] = SchemaValidator::validateSchema($st);
        assertTrue($ok, implode('; ', $why));
        assertTrue(Semantics::stateGaps($st, $q) === [], 'expected no gaps');
    };
    $v['v95'] = function (): void {
        [$st, $q] = stateFixture('quantity', ['categorical' => 'elevated'], 'ug/dL');
        assertTrue(Semantics::stateGaps($st, $q) === ['value_type_mismatch'], 'expected value_type_mismatch');
    };
    $v['v96'] = function (): void {
        [$st, $q] = stateFixture('quantity', ['quantity' => 15.0, 'unit' => 'mg/dL'], 'ug/dL');
        assertTrue(Semantics::stateGaps($st, $q) === ['unit_mismatch'], 'expected unit_mismatch');
    };
    $v['v97'] = function (): void {
        [$law, , , $tc, $te] = lawAndTokens();
        $claim = tcc([$tc['id']], [$te['id']], $law['id'],
                     ['duration' => 0, 'unit' => 'instant'], true);
        [$ok, $why] = SchemaValidator::validateSchema($claim);
        assertTrue($ok, implode('; ', $why));
    };
    $v['v98'] = function (): void {
        [, , , $tc, $te] = lawAndTokens();
        $claim = tcc([$tc['id']], [$te['id']]);
        [$ok, $why] = SchemaValidator::validateSchema($claim);
        assertTrue($ok, implode('; ', $why));
        assertTrue(!array_key_exists('covering_law', $claim), 'covering_law must be absent');
    };
    $v['v99'] = function (): void {
        [$law] = lawAndTokens();
        assertTrue(Semantics::delayWithinWindow(['duration' => 0, 'unit' => 'instant'],
                                                $law['temporal']) === true, 'expected within window');
    };
    $v['v100'] = function (): void {
        $temporal = ['minimum_delay' => 0, 'maximum_delay' => 1, 'unit' => 'hours'];
        assertTrue(Semantics::delayWithinWindow(['duration' => 5, 'unit' => 'days'], $temporal) === false,
            'expected outside window');
    };
    $v['v101'] = function (): void {
        $o = occ('x')['id'];
        $cause = token($o, ['start' => '2026-01-02T00:00:00Z']);
        $effect = token($o, ['start' => '2026-01-01T00:00:00Z']);
        $claim = tcc([$cause['id']], [$effect['id']]);
        assertTrue(Semantics::retrocausal($claim, [$cause['id'] => $cause, $effect['id'] => $effect]) === true,
            'expected retrocausal');
    };
    $v['v102'] = function (): void {
        $other = cro([sym('occurrent:foo')], [sym('occurrent:bar')]);
        [, , , $tc, $te] = lawAndTokens();
        $claim = tcc([$tc['id']], [$te['id']], $other['id']);
        assertTrue(Semantics::coveringLawMismatch($claim, [$tc['id'] => $tc, $te['id'] => $te], $other) === true,
            'expected covering_law_mismatch');
    };
    $v['v103'] = function (): void {
        $a = signed('assertion', ['about' => sym('token_occurrence:t'),
                                  'evidence_type' => 'observation', 'confidence' => 0.9], 'signer');
        [$ok, $why] = SchemaValidator::validateSchema($a);
        assertTrue($ok, implode('; ', $why));
    };
    $v['v104'] = function (): void {
        $ev = [sym('token_occurrence:t1'), sym('token_causal_claim:c1')];
        $base = ['type' => 'assertion', 'about' => sym('causal_relation_object:law'),
                 'source' => keyPair('signer')[1], 'evidence_type' => 'intervention',
                 'strength' => 0.95, 'confidence' => 0.99, 'timestamp' => '2026-07-14T00:00:00Z'];
        $a = $base;
        $a['evidenced_by'] = $ev;
        $withId = $a;
        $withId['id'] = Canonical::identify($a);
        [$ok, $why] = SchemaValidator::validateSchema($withId);
        assertTrue($ok, implode('; ', $why));
        assertTrue(Canonical::identify($a) !== Canonical::identify($base),
            'evidenced_by must be identity-bearing');
    };
    $v['v105'] = function (): void {
        $a = signed('assertion', ['about' => sym('causal_relation_object:law'),
                                  'evidence_type' => 'simulation', 'confidence' => 0.5], 'signer');
        [$ok, $why] = SchemaValidator::validateSchema($a);
        assertTrue($ok, implode('; ', $why));
        $rank = ['intervention' => 0, 'observation' => 1, 'simulation' => 2];
        assertTrue($rank['intervention'] < $rank['observation'] && $rank['observation'] < $rank['simulation'],
            'evidence rank order wrong');
    };
    $v['v106'] = function (): void {
        $wholeWord = array_merge(CO_SCHEMES, ['ed25519']);
        for ($n = 1; $n <= 38; $n++) {
            $ids = [];
            scanIds(vec($n), $ids);
            foreach ($ids as $scheme) {
                assertTrue(in_array($scheme, $wholeWord, true),
                    "V106: abbreviated scheme '$scheme' in vector $n");
            }
        }
        $rec = ['type' => 'occurrent', 'label' => 'press_button', 'category' => 'action'];
        assertTrue(Canonical::identify($rec) === Canonical::identify($rec), 'identity nondeterministic');
        assertTrue(explode(':', Canonical::identify($rec), 2)[0] === 'occurrent', 'wrong scheme');
    };
    $v['v107'] = function (): void {
        $hexid = str_repeat('0', 64);
        // The abbreviated prefix below is intentional (the negative test); it
        // must NOT be re-minted. "c" "r" "o" is assembled to survive re-mint tools.
        $croAbbr = 'c' . 'r' . 'o';
        $abbreviated = ['type' => 'causal_relation_object', 'id' => $croAbbr . ':' . $hexid,
                        'causes' => ['occurrent:' . $hexid], 'effects' => ['occurrent:' . $hexid]];
        assertTrue(!SchemaValidator::validateSchema($abbreviated, 'causal_relation_object')[0],
            'abbreviated scheme must be rejected');
        $abbrStr = ['type' => 'stratum', 'id' => 'str:' . $hexid, 'label' => 'cellular',
                    'scheme' => 'neuroendocrine', 'ordinal' => 6];
        assertTrue(!SchemaValidator::validateSchema($abbrStr, 'stratum')[0],
            'abbreviated str: must be rejected');
        $whole = ['type' => 'causal_relation_object', 'id' => 'causal_relation_object:' . $hexid,
                  'causes' => ['occurrent:' . $hexid], 'effects' => ['occurrent:' . $hexid]];
        [$ok, $why] = SchemaValidator::validateSchema($whole, 'causal_relation_object');
        assertTrue($ok, implode('; ', $why));
    };

    return $v;
}

// ---------------------------------------------------------------------------

function main(): void
{
    echo "causalontology-php conformance run (specification 2.0.0)\n";
    echo 'internal checks (RFC 8032, RFC 8785, fixed constants) ... ';
    internalChecks();
    echo "ok\n";
    $vectors = vectorSuite();
    $failures = 0;
    $total = 107;
    for ($n = 1; $n <= $total; $n++) {
        $key = sprintf('v%02d', $n);
        $name = vecName($n);
        try {
            $vectors[$key]();
            echo 'PASS  ' . $name . "\n";
        } catch (Throwable $e) {
            $failures++;
            echo 'FAIL  ' . $name . ' :: ' . get_class($e) . ': ' . $e->getMessage() . "\n";
        }
    }
    echo str_repeat('-', 60) . "\n";
    echo ($total - $failures) . '/' . $total . " vectors passed\n";
    if ($failures > 0) {
        exit(1);
    }
    echo "causalontology-php is CONFORMANT to the suite "
       . "(vectors frozen at specification 2.0.0).\n";
}

main();

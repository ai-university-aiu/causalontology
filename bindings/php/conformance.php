<?php

/* The Causalontology conformance runner for causalontology-php.
 *
 * Runs every vector in conformance/vectors/ against the PHP binding. An
 * implementation is conformant if and only if it passes every vector; this
 * runner exits nonzero on any failure.
 *
 * The vectors are frozen at specification 1.0.0 (2026-07-13): they carry
 * concrete 64-hex identifiers, real Ed25519 keys, and a real verifying
 * signature. The old symbolic-id normalization below now simply passes
 * frozen values through - it remains only so the harness stays able to run
 * historical pre-freeze vector sets (symbolic object ids become
 * scheme:sha256(name); symbolic key names become real Ed25519 keypairs
 * seeded from sha256("key:" + name)).
 *
 * Usage: php bindings/php/conformance.php
 */

declare(strict_types=1);

// The binding is dependency-free: load the six concerns directly, in
// dependency order, so the runner works without any Composer autoloader.
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
// The binding targets PHP 8.2 or newer (readonly-safe syntax, array_is_list).
if (PHP_VERSION_ID < 80200) {
    fwrite(STDERR, "causalontology-php requires PHP 8.2 or newer\n");
    exit(1);
}

// bindings/php/conformance.php -> two levels below the repository root.
define('CO_VECDIR', __DIR__ . '/../../conformance/vectors');

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
// symbolic-identifier normalization (pass-through for frozen vectors)
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
            return $s; // frozen: a real key passes through
        }
        return keyPair($name)[1];
    }
    if (preg_match('~^[0-9a-f]{64}$~', $name) === 1) {
        return $s; // frozen: a real identifier passes through
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
        if (preg_match('~^(occ|cro|cnt|rlz|ast|enr|ret|suc|ed25519):~', $x) === 1) {
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
    // associative decode preserves the int-versus-float source distinction
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

// ---------------------------------------------------------------------------
// internal sanity checks (not conformance vectors)
// ---------------------------------------------------------------------------

function internalChecks(): void
{
    // RFC 8032, TEST 1 known-answer: the seed, the derived public key, and
    // the deterministic signature of the empty message.
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
    assertTrue(bin2hex($signature)
        === 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155'
          . '5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
        'RFC 8032 TEST 1 signature bytes mismatch');
    // JCS basics: key sorting and canonical numbers.
    assertTrue(Jcs::serialize(['b' => 2, 'a' => 1]) === '{"a":1,"b":2}',
        'JCS key sort failed');
    assertTrue(Jcs::serialize(1.0) === '1' && Jcs::serialize(6.000) === '6'
            && Jcs::serialize(0.7) === '0.7',
        'JCS number serialization failed');
    assertTrue(Jcs::serialize([]) === '[]',
        'an empty array must serialize as []');
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
    $cro = ['causes' => [sym('occ:c')], 'effects' => [sym('occ:e')],
            'temporal' => $given['temporal']];
    return Semantics::admissible($cro, $given['elapsed_seconds']);
}

// ---------------------------------------------------------------------------
// the 38 vectors
// ---------------------------------------------------------------------------

/** @return array<string, callable(): void> the vector suite, v01..v38 */
function vectorSuite(): array
{
    $vectors = [];

    $vectors['v01'] = function (): void {
        $input = normalize(vec(1)['input']);
        [$ok, $why] = SchemaValidator::validateSchema($input);
        assertTrue($ok, implode('; ', $why));
        [$ok, $why] = Semantics::validateSemantics($input);
        assertTrue($ok, implode('; ', $why));
    };

    $vectors['v02'] = function (): void {
        $input = normalize(vec(2)['input']);
        assertTrue(SchemaValidator::validateSchema($input)[0], 'schema');
        assertTrue(Semantics::validateSemantics($input)[0], 'semantics');
        [$partial, $missing] = Semantics::isPartial($input);
        assertTrue($partial && $missing === vec(2)['expect']['missing'],
            'missing = ' . json_encode($missing));
    };

    $vectors['v03'] = fn () => schemaFails(3, 'effects');
    $vectors['v04'] = fn () => schemaFails(4, 'causes');
    $vectors['v05'] = fn () => schemaFails(5, 'modality');
    $vectors['v06'] = fn () => schemaFails(6, 'colour');
    $vectors['v07'] = fn () => schemaFails(7, 'causes');

    $vectors['v08'] = function (): void {
        [$ok, $why] = SchemaValidator::validateSchema(normalize(vec(8)['input']));
        assertTrue($ok, implode('; ', $why));
    };

    $vectors['v09'] = fn () => schemaFails(9, 'label');
    $vectors['v10'] = fn () => schemaFails(10, 'category');

    $vectors['v11'] = function (): void {
        [$ok, $why] = SchemaValidator::validateSchema(normalize(vec(11)['input']));
        assertTrue($ok, implode('; ', $why));
    };

    $vectors['v12'] = fn () => schemaFails(12, 'confidence');

    $vectors['v13'] = function (): void {
        $input = normalize(vec(13)['input']);
        [$ok, $why] = SchemaValidator::validateSchema($input);
        assertTrue($ok, implode('; ', $why));
        [$ok, $why] = Semantics::validateSemantics($input);
        assertTrue($ok, implode('; ', $why));
    };

    $vectors['v14'] = function (): void {
        $input = normalize(vec(14)['input']);
        assertTrue(SchemaValidator::validateSchema($input)[0], 'schema should pass');
        semanticsFails(14, 'dmin');
    };

    $vectors['v15'] = fn () => semanticsFails(15, 'acyclic');
    $vectors['v16'] = fn () => semanticsFails(16, 'acyclic');

    $vectors['v17'] = function (): void {
        $vector = vec(17);
        $parent = normalize($vector['given']['parent']);
        $child = normalize($vector['input']);
        [$ok, $reason] = Semantics::refinementValid($child, $parent);
        assertTrue(!$ok && str_contains($reason, 'rival'), $reason);
    };

    $vectors['v18'] = fn () => semanticsFails(18, 'not a legal field');
    $vectors['v19'] = fn () => semanticsFails(19, 'language-tagged');

    $vectors['v20'] = function (): void {
        $dog = sym('cnt:dog');
        $mammal = sym('cnt:mammal');
        $animal = sym('cnt:animal');
        $enrich = fn (string $about, string $entry, int $i): array =>
            signed('enrichment',
                   ['about' => $about, 'field' => 'subsumes', 'entry' => $entry],
                   'taxo', $i);
        // enforcing tier rejects the cycle-completing write
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
        // decentralized merge: the view breaks the cycle deterministically
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

    $vectors['v21'] = fn () => assertTrue(adm(21) === true, 'expected admissible');
    $vectors['v22'] = fn () => assertTrue(adm(22) === false, 'expected inadmissible');
    $vectors['v23'] = fn () => assertTrue(adm(23) === true, 'expected admissible');

    $vectors['v24'] = function (): void {
        $vector = vec(24);
        assertTrue(Canonical::identify(normalize($vector['inputA']))
                === Canonical::identify(normalize($vector['inputB'])),
            'key order changed identity');
    };

    $vectors['v25'] = function (): void {
        $vector = vec(25);
        assertTrue(Canonical::identify(normalize($vector['inputA']))
                === Canonical::identify(normalize($vector['inputB'])),
            'number formatting changed identity');
    };

    $vectors['v26'] = function (): void {
        $store = new Store();
        $obj = ['type' => 'occurrent', 'label' => 'press_button',
                'category' => 'action'];
        $first = $store->put($obj);
        $second = $store->put($obj);
        assertTrue($first === $second && count($store->objects) === 1,
            'put not idempotent');
    };

    $vectors['v27'] = function (): void {
        $store = new Store();
        $occ = $store->put(['type' => 'occurrent', 'label' => 'press_button',
                            'category' => 'action']);
        $entry = ['lang' => 'en', 'text' => 'press the button'];
        $r1 = signed('enrichment', ['about' => $occ, 'field' => 'aliases',
                                    'entry' => $entry], 'alice', 1);
        $r2 = signed('enrichment', ['about' => $occ, 'field' => 'aliases',
                                    'entry' => $entry], 'bob', 2);
        assertTrue($store->putRecord($r1) !== $store->putRecord($r2),
            'expected two records');
        $view = $store->get($occ)['enrichments']['aliases'] ?? [];
        assertTrue(count($view) === 1 && count($view[0]['contributors']) === 2,
            'expected one entry with two contributors');
    };

    $vectors['v28'] = function (): void {
        $store = new Store();
        $claim = ['type' => 'cro', 'causes' => [sym('occ:A')],
                  'effects' => [sym('occ:B')], 'modality' => 'sufficient'];
        $first = $store->put($claim);
        $second = $store->put($claim);
        assertTrue($first === $second && count($store->objects) === 1,
            'expected one object');
        foreach ([['lab1', 1], ['lab2', 2]] as [$who, $ts]) {
            $store->putRecord(signed('assertion',
                ['about' => $first, 'evidence_type' => 'observation',
                 'strength' => 0.8, 'confidence' => 0.8], $who, $ts));
        }
        assertTrue(count($store->assertionsAbout($first)) === 2,
            'expected two assertions');
    };

    $vectors['v29'] = function (): void {
        $record = signed('assertion', ['about' => sym('cro:demo'),
                                       'evidence_type' => 'intervention',
                                       'strength' => 0.7, 'confidence' => 0.9],
                         'signer');
        assertTrue(Signing::verifyRecord($record) === true,
            'valid signature did not verify');
    };

    $vectors['v30'] = function (): void {
        $record = signed('assertion', ['about' => sym('cro:demo'),
                                       'evidence_type' => 'intervention',
                                       'strength' => 0.7, 'confidence' => 0.9],
                         'signer');
        $tampered = $record;
        $tampered['confidence'] = 0.1;
        assertTrue(Signing::verifyRecord($tampered) === false,
            'tampered record verified');
    };

    $vectors['v31'] = function (): void {
        $store = new Store();
        $x = $store->put(['type' => 'cro', 'causes' => [sym('occ:A')],
                          'effects' => [sym('occ:B')]]);
        $assertion = signed('assertion',
            ['about' => $x, 'evidence_type' => 'observation',
             'confidence' => 0.8], 'lab1', 1);
        $store->putRecord($assertion);
        $store->putRecord(signed('retraction', ['retracts' => $assertion['id']],
                                 'lab1', 2));
        assertTrue($store->assertionsAbout($x) === [],
            'retracted assertion visible');
        $history = $store->assertionsAbout($x, true);
        assertTrue(count($history) === 1 && $history[0]['retracted'] === true,
            'history wrong');
        $foreign = signed('retraction', ['retracts' => $assertion['id']],
                          'mallory', 3);
        $threw = false;
        try {
            $store->putRecord($foreign);
        } catch (RejectedWrite $e) {
            $threw = true;
        }
        assertTrue($threw, 'foreign retraction accepted');
        assertTrue($store->assertionsAbout($x) === [],    // still lab1's own
            'default view changed');
        assertTrue(count($store->assertionsAbout($x, true)) === 1,
            'history changed');
    };

    $vectors['v32'] = function (): void {
        $store = new Store();
        $occ = $store->put(['type' => 'occurrent', 'label' => 'press_button',
                            'category' => 'action']);
        $enrichment = signed('enrichment',
            ['about' => $occ, 'field' => 'aliases',
             'entry' => ['lang' => 'ja', 'text' => 'botan']], 'bob', 1);
        $store->putRecord($enrichment);
        assertTrue(count($store->get($occ)['enrichments']['aliases'] ?? []) === 1,
            'enrichment missing');
        $store->putRecord(signed('retraction',
            ['retracts' => $enrichment['id']], 'bob', 2));
        assertTrue(($store->get($occ)['enrichments']['aliases'] ?? []) === [],
            'retracted enrichment still visible');
        $history = $store->get($occ, 'history')['enrichments']['aliases'] ?? [];
        assertTrue(count($history) === 1, 'history view lost the enrichment');
    };

    $vectors['v33'] = function (): void {
        $store = new Store();
        $k1 = keyPair('K1')[1];
        $k2 = keyPair('K2')[1];
        $assertion = signed('assertion',
            ['about' => sym('cro:claim'), 'evidence_type' => 'observation',
             'confidence' => 0.9], 'K1', 1);
        $store->putRecord($assertion);
        $succession = signed('succession', ['successor' => $k2], 'K1', 2);
        $store->putRecord($succession);
        assertTrue(in_array($k1, $store->lineage($k2), true)
                && in_array($k2, $store->lineage($k1), true),
            'lineage broken');
        $retraction = signed('retraction', ['retracts' => $assertion['id']],
                             'K2', 3);
        $store->putRecord($retraction); // successor retracts predecessor's
        assertTrue($store->assertionsAbout(sym('cro:claim')) === [],
            'successor retraction not honored');
    };

    $vectors['v34'] = function (): void {
        $given = normalize(vec(34)['given']);
        assertTrue(Semantics::conflicts($given['A'], $given['B']) === true,
            'expected a conflict');
    };

    $vectors['v35'] = function (): void {
        $given = normalize(vec(35)['given']);
        assertTrue(Semantics::conflicts($given['A'], $given['B']) === false,
            'expected no conflict');
    };

    $vectors['v36'] = function (): void {
        $a = sym('occ:A');
        $b = sym('occ:B');
        $c = sym('occ:C');
        $d = sym('occ:D');
        $m1 = ['id' => sym('cro:m1'), 'causes' => [$a], 'effects' => [$b]];
        $m2 = ['id' => sym('cro:m2'), 'causes' => [$b], 'effects' => [$c]];
        $m3 = ['id' => sym('cro:m3'), 'causes' => [$d], 'effects' => [$c]];
        $parent = ['causes' => [$a], 'effects' => [$c],
                   'mechanism' => [$m1['id'], $m2['id']]];
        assertTrue(Semantics::hierarchyConsistent(
                $parent, [$m1['id'] => $m1, $m2['id'] => $m2]) === 'consistent',
            'chain should be consistent');
        $parent2 = $parent;
        $parent2['mechanism'] = [$m1['id'], $m3['id']];
        assertTrue(Semantics::hierarchyConsistent(
                $parent2, [$m1['id'] => $m1, $m3['id'] => $m3]) === 'inconsistent',
            'broken chain should be inconsistent');
        assertTrue(Semantics::hierarchyConsistent(
                $parent, [$m1['id'] => $m1]) === 'indeterminate',
            'missing member should be indeterminate');
    };

    $vectors['v37'] = function (): void {
        $store = new Store();
        $occ = $store->put(['type' => 'occurrent', 'label' => 'press_button',
                            'category' => 'action']);
        $store->putRecord(signed('enrichment',
            ['about' => $occ, 'field' => 'aliases',
             'entry' => ['lang' => 'en', 'text' => 'Press the Button']],
            'alice', 1));
        assertTrue($store->resolve('Press  The   Button', 'en') === [$occ],
            'alias resolve failed');                       // alias match
        assertTrue(($store->resolve('press_button', 'en')[0] ?? null) === $occ,
            'label resolve failed');                       // label, first
    };

    $vectors['v38'] = function (): void {
        $store = new Store();
        $parent = $store->put(['type' => 'cro', 'causes' => [sym('occ:A')],
                               'effects' => [sym('occ:B')]]);
        $gapIds = array_map(fn (array $g): string => $g['id'],
                            $store->gaps('missing_field'));
        assertTrue(in_array($parent, $gapIds, true),
            'the bare CRO must be a gap');
        $refinement = $store->put(['type' => 'cro', 'causes' => [sym('occ:A')],
                                   'effects' => [sym('occ:B')],
                                   'temporal' => ['dmin' => 0, 'dmax' => 1,
                                                  'unit' => 'seconds'],
                                   'modality' => 'sufficient',
                                   'refines' => $parent]);
        $gapIds = array_map(fn (array $g): string => $g['id'],
                            $store->gaps('missing_field'));
        assertTrue(!in_array($parent, $gapIds, true), 'the gap did not close');
        assertTrue(!in_array($refinement, $gapIds, true),
            'the refinement itself must be complete');
    };

    return $vectors;
}

// ---------------------------------------------------------------------------

function main(): void
{
    echo "causalontology-php conformance run\n";
    echo 'internal checks (RFC 8032 known-answer, RFC 8785 basics) ... ';
    internalChecks();
    echo "ok\n";
    $vectors = vectorSuite();
    $failures = 0;
    for ($n = 1; $n <= 38; $n++) {
        $key = sprintf('v%02d', $n);
        $name = vecName($n);
        try {
            $vectors[$key]();
            echo 'PASS  ' . $name . "\n";
        } catch (Throwable $e) {
            $failures++;
            echo 'FAIL  ' . $name . ' :: ' . get_class($e) . ': '
               . $e->getMessage() . "\n";
        }
    }
    $total = 38;
    echo str_repeat('-', 60) . "\n";
    echo ($total - $failures) . '/' . $total . " vectors passed\n";
    if ($failures > 0) {
        exit(1);
    }
    echo "causalontology-php is CONFORMANT to the suite "
       . "(vectors frozen at specification 1.0.0).\n";
}

main();

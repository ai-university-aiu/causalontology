/// The Causalontology conformance runner for causalontology-dart.
///
/// Runs every vector in conformance/vectors/ against the Dart binding. An
/// implementation is conformant if and only if it passes every vector; this
/// runner exits nonzero on any failure. It mirrors
/// bindings/python/tests/run_conformance.py exactly.
///
/// The vectors are frozen at specification 1.0.0: they carry concrete
/// 64-hex identifiers and real Ed25519 keys, which the old symbolic
/// normalization now simply passes through unchanged; behavioral vectors
/// still derive deterministic keypairs from seed sha256("key:" + name).
library;

import 'dart:convert';
import 'dart:io';

import '../lib/causalontology.dart';
import '../lib/ed25519.dart' as ed25519;
import '../lib/sha2.dart';

// ---------------------------------------------------------------------------
// repository location
// ---------------------------------------------------------------------------

/// The repository root: CAUSALONTOLOGY_ROOT when set, otherwise found by
/// walking up from this script and from the working directory until a
/// conformance/vectors directory appears.
Directory repoRoot() {
  final env = Platform.environment['CAUSALONTOLOGY_ROOT'];
  if (env != null && env.isNotEmpty) {
    return Directory(env);
  }
  final starts = [File.fromUri(Platform.script).parent, Directory.current];
  for (final start in starts) {
    var dir = start.absolute;
    while (true) {
      if (Directory('${dir.path}/conformance/vectors').existsSync()) {
        return dir;
      }
      final parent = dir.parent;
      if (parent.path == dir.path) break;
      dir = parent;
    }
  }
  throw StateError('cannot locate conformance/vectors; '
      'set CAUSALONTOLOGY_ROOT');
}

late final Directory vecDir =
    Directory('${repoRoot().path}/conformance/vectors');

// ---------------------------------------------------------------------------
// symbolic-identifier normalization
// ---------------------------------------------------------------------------

const List<String> _schemes = [
  'occurrent', 'causal_relation_object', 'continuant', 'realizable', 'assertion', 'enrichment', 'retraction', 'succession',
];

final Map<String, (List<int>, String)> _keys = {};

final RegExp _hex64 = RegExp(r'^[0-9a-f]{64}$');
final RegExp _symbolic = RegExp('^(${_schemes.join('|')}|ed25519):');

/// A real, deterministic Ed25519 keypair for a symbolic key name.
(List<int>, String) key(String name) {
  return _keys.putIfAbsent(
      name, () => keypairFromSeed(sha256(utf8.encode('key:$name'))));
}

/// Normalize one symbolic identifier to a well-formed one.
String sym(String s) {
  final i = s.indexOf(':');
  final scheme = s.substring(0, i);
  final name = s.substring(i + 1);
  if (scheme == 'ed25519') {
    if (_hex64.hasMatch(name)) {
      return s; // frozen: a real key passes through
    }
    return key(name).$2;
  }
  if (_hex64.hasMatch(name)) {
    return s;
  }
  return '$scheme:${hexEncode(sha256(utf8.encode(name)))}';
}

/// Recursively normalize symbolic identifiers and placeholders.
Object? normalize(Object? x) {
  if (x is String) {
    if (x == '<128 hex>') {
      return 'ab' * 64;
    }
    if (_symbolic.hasMatch(x)) {
      return sym(x);
    }
    return x;
  }
  if (x is List) {
    return x.map(normalize).toList();
  }
  if (x is Map) {
    return {for (final e in x.entries) e.key as String: normalize(e.value)};
  }
  return x;
}

Map<String, dynamic> normMap(Object? x) =>
    (normalize(x) as Map).cast<String, dynamic>();

/// Load vector n's JSON file (for its structured inputs).
Map<String, dynamic> vec(int n) {
  final file = vecFile(n);
  return (jsonDecode(file.readAsStringSync()) as Map).cast<String, dynamic>();
}

File vecFile(int n) {
  final nn = n.toString().padLeft(2, '0');
  final pattern = RegExp('^v${nn}_.*\\.json\$');
  final hits = vecDir
      .listSync()
      .whereType<File>()
      .where((f) => pattern.hasMatch(f.uri.pathSegments.last))
      .toList();
  if (hits.length != 1) {
    throw StateError('vector $n not found');
  }
  return hits.first;
}

String ts(int i) => '2026-07-13T0$i:00:00Z';

/// Build, timestamp, and sign a provenance record.
Map<String, dynamic> signed(String kind, Map<String, dynamic> body, String who,
    [int tsI = 0]) {
  final (secret, pub) = key(who);
  final rec = Map<String, dynamic>.from(body);
  rec['type'] = kind;
  rec.putIfAbsent('timestamp', () => ts(tsI));
  if (kind == 'succession') {
    rec.putIfAbsent('predecessor', () => pub);
  } else {
    rec['source'] = pub;
  }
  return signRecord(rec, secret, kind);
}

// ---------------------------------------------------------------------------
// assertion helpers
// ---------------------------------------------------------------------------

void check(bool condition, [Object? detail]) {
  if (!condition) {
    throw AssertionError(detail ?? 'check failed');
  }
}

bool sameList(List a, List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// internal sanity checks (not conformance vectors)
// ---------------------------------------------------------------------------

void internalChecks() {
  // SHA-2 empty-string known answers gate the pure-Dart hashes.
  check(
      hexEncode(sha256(const [])) ==
          'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      'sha256 empty KAT');
  check(hexEncode(sha512(const [])).startsWith('cf83e135'),
      'sha512 empty KAT');
  // RFC 8032, TEST 1 known-answer.
  final sk = hexDecode(
      '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60')!;
  final pk = ed25519.secretToPublic(sk);
  check(
      hexEncode(pk) ==
          'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
      hexEncode(pk));
  final sig = ed25519.sign(sk, const []);
  check(ed25519.verify(pk, const [], sig), 'RFC 8032 TEST 1 verify');
  check(!ed25519.verify(pk, utf8.encode('x'), sig), 'tamper must fail');
  // JCS basics.
  check(jcs({'b': 2, 'a': 1}) == '{"a":1,"b":2}', 'JCS key order');
  check(jcs(1.0) == '1' && jcs(6.000) == '6' && jcs(0.7) == '0.7',
      'JCS numbers');
}

// ---------------------------------------------------------------------------
// the 38 vectors
// ---------------------------------------------------------------------------

void v01() {
  final inp = normMap(vec(1)['input']);
  final (ok1, why1) = validateSchema(inp);
  check(ok1, why1);
  final (ok2, why2) = validateSemantics(inp);
  check(ok2, why2);
}

void v02() {
  final v = vec(2);
  final inp = normMap(v['input']);
  final (ok1, _) = validateSchema(inp);
  check(ok1);
  final (ok2, _) = validateSemantics(inp);
  check(ok2);
  final (partial, missing) = isPartial(inp);
  final expected = ((v['expect'] as Map)['missing'] as List).cast<String>();
  check(partial && sameList(missing, expected), missing);
}

void schemaFails(int n, String mustMention) {
  final inp = normMap(vec(n)['input']);
  final (ok, why) = validateSchema(inp);
  check(!ok, 'expected schema-invalid');
  check(why.any((w) => w.contains(mustMention)), why);
}

void v03() => schemaFails(3, 'effects');
void v04() => schemaFails(4, 'causes');
void v05() => schemaFails(5, 'modality');
void v06() => schemaFails(6, 'colour');
void v07() => schemaFails(7, 'causes');

void v08() {
  final (ok, why) = validateSchema(normMap(vec(8)['input']));
  check(ok, why);
}

void v09() => schemaFails(9, 'label');
void v10() => schemaFails(10, 'category');

void v11() {
  final (ok, why) = validateSchema(normMap(vec(11)['input']));
  check(ok, why);
}

void v12() => schemaFails(12, 'confidence');

void v13() {
  final inp = normMap(vec(13)['input']);
  final (ok1, why1) = validateSchema(inp);
  check(ok1, why1);
  final (ok2, why2) = validateSemantics(inp);
  check(ok2, why2);
}

void semanticsFails(int n, String mustMention) {
  final inp = normMap(vec(n)['input']);
  final (ok, why) = validateSemantics(inp);
  check(!ok, 'expected semantically-invalid');
  check(why.any((w) => w.contains(mustMention)), why);
}

void v14() {
  final inp = normMap(vec(14)['input']);
  final (ok, _) = validateSchema(inp);
  check(ok);
  semanticsFails(14, 'minimum_delay');
}

void v15() => semanticsFails(15, 'acyclic');
void v16() => semanticsFails(16, 'acyclic');

void v17() {
  final v = vec(17);
  final parent = normMap((v['given'] as Map)['parent']);
  final child = normMap(v['input']);
  final (ok, reason) = refinementValid(child, parent);
  check(!ok && reason.contains('rival'), reason);
}

void v18() => semanticsFails(18, 'not a legal field');
void v19() => semanticsFails(19, 'language-tagged');

void v20() {
  final dog = sym('continuant:dog'), mam = sym('continuant:mammal'), ani = sym('continuant:animal');
  Map<String, dynamic> enrich(String about, String entry, int i) => signed(
      'enrichment', {'about': about, 'field': 'subsumes', 'entry': entry},
      'taxo', i);
  // Enforcing tier rejects the cycle-completing write.
  final s = InMemoryStore(true);
  s.putRecord(enrich(dog, mam, 1));
  s.putRecord(enrich(mam, ani, 2));
  var rejected = false;
  try {
    s.putRecord(enrich(ani, dog, 3));
  } on RejectedWrite catch (e) {
    rejected = true;
    check(e.message.contains('cycle'), e.message);
  }
  check(rejected, 'enforcing store accepted a cycle');
  // Decentralized merge: the view breaks the cycle deterministically.
  final s2 = InMemoryStore(true);
  s2.putRecord(enrich(dog, mam, 1));
  s2.putRecord(enrich(mam, ani, 2));
  final bad = enrich(ani, dog, 3);
  s2.forceMergeRecord(bad);
  final (_, excluded) = s2.activeTaxonomyEdges('subsumes');
  check(excluded.length == 1 && excluded.first['id'] == bad['id'], excluded);
  final repair = s2.gaps('inconsistent_hierarchy');
  check(repair.any((g) => g['id'] == bad['id']), repair);
}

bool adm(int n) {
  final g = (vec(n)['given'] as Map).cast<String, dynamic>();
  final cro = <String, dynamic>{
    'causes': [sym('occurrent:c')],
    'effects': [sym('occurrent:e')],
    'temporal': g['temporal'],
  };
  return admissible(cro, g['elapsed_seconds'] as num);
}

void v21() => check(adm(21) == true);
void v22() => check(adm(22) == false);
void v23() => check(adm(23) == true);

void v24() {
  final v = vec(24);
  check(identify(normMap(v['inputA'])) == identify(normMap(v['inputB'])));
}

void v25() {
  final v = vec(25);
  check(identify(normMap(v['inputA'])) == identify(normMap(v['inputB'])));
}

void v26() {
  final s = InMemoryStore();
  final obj = {'type': 'occurrent', 'label': 'press_button', 'category': 'action'};
  final a = s.put(Map<String, dynamic>.from(obj));
  final b = s.put(Map<String, dynamic>.from(obj));
  check(a == b && s.objects.length == 1);
}

void v27() {
  final s = InMemoryStore();
  final occ = s.put({
    'type': 'occurrent', 'label': 'press_button', 'category': 'action',
  });
  final entry = {'lang': 'en', 'text': 'press the button'};
  final r1 = signed('enrichment',
      {'about': occ, 'field': 'aliases', 'entry': entry}, 'alice', 1);
  final r2 = signed('enrichment',
      {'about': occ, 'field': 'aliases', 'entry': entry}, 'bob', 2);
  check(s.putRecord(r1) != s.putRecord(r2)); // two records
  final view =
      (s.get(occ)!['enrichments'] as Map)['aliases'] as List;
  check(view.length == 1 &&
      ((view.first as Map)['contributors'] as List).length == 2);
}

void v28() {
  final s = InMemoryStore();
  final claim = <String, dynamic>{
    'type': 'causal_relation_object',
    'causes': [sym('occurrent:A')],
    'effects': [sym('occurrent:B')],
    'modality': 'sufficient',
  };
  final i1 = s.put(Map<String, dynamic>.from(claim));
  final i2 = s.put(Map<String, dynamic>.from(claim));
  check(i1 == i2 && s.objects.length == 1);
  for (final (who, tsI) in [('lab1', 1), ('lab2', 2)]) {
    s.putRecord(signed('assertion', {
      'about': i1,
      'evidence_type': 'observation',
      'strength': 0.8,
      'confidence': 0.8,
    }, who, tsI));
  }
  check(s.assertionsAbout(i1).length == 2);
}

void v29() {
  final rec = signed('assertion', {
    'about': sym('causal_relation_object:demo'),
    'evidence_type': 'intervention',
    'strength': 0.7,
    'confidence': 0.9,
  }, 'signer');
  check(verifyRecord(rec) == true);
}

void v30() {
  final rec = signed('assertion', {
    'about': sym('causal_relation_object:demo'),
    'evidence_type': 'intervention',
    'strength': 0.7,
    'confidence': 0.9,
  }, 'signer');
  final tampered = Map<String, dynamic>.from(rec)..['confidence'] = 0.1;
  check(verifyRecord(tampered) == false);
}

void v31() {
  final s = InMemoryStore();
  final x = s.put({
    'type': 'causal_relation_object',
    'causes': [sym('occurrent:A')],
    'effects': [sym('occurrent:B')],
  });
  final a = signed('assertion',
      {'about': x, 'evidence_type': 'observation', 'confidence': 0.8},
      'lab1', 1);
  s.putRecord(a);
  s.putRecord(signed('retraction', {'retracts': a['id']}, 'lab1', 2));
  check(s.assertionsAbout(x).isEmpty);
  final hist = s.assertionsAbout(x, true);
  check(hist.length == 1 && hist.first['retracted'] == true);
  final foreign = signed('retraction', {'retracts': a['id']}, 'mallory', 3);
  var rejected = false;
  try {
    s.putRecord(foreign);
  } on RejectedWrite {
    rejected = true;
  }
  check(rejected, 'foreign retraction accepted');
  check(s.assertionsAbout(x).isEmpty); // still excluded by lab1's own
  check(s.assertionsAbout(x, true).length == 1);
}

void v32() {
  final s = InMemoryStore();
  final occ = s.put({
    'type': 'occurrent', 'label': 'press_button', 'category': 'action',
  });
  final e = signed('enrichment', {
    'about': occ,
    'field': 'aliases',
    'entry': {'lang': 'ja', 'text': 'botan'},
  }, 'bob', 1);
  s.putRecord(e);
  check(((s.get(occ)!['enrichments'] as Map)['aliases'] as List?)?.length == 1);
  s.putRecord(signed('retraction', {'retracts': e['id']}, 'bob', 2));
  check(((s.get(occ)!['enrichments'] as Map)['aliases'] as List?) == null ||
      ((s.get(occ)!['enrichments'] as Map)['aliases'] as List).isEmpty);
  final hist =
      (s.get(occ, 'history')!['enrichments'] as Map)['aliases'] as List?;
  check(hist != null && hist.length == 1);
}

void v33() {
  final s = InMemoryStore();
  final (_, k1) = key('K1');
  final (_, k2) = key('K2');
  final a = signed('assertion', {
    'about': sym('causal_relation_object:claim'),
    'evidence_type': 'observation',
    'confidence': 0.9,
  }, 'K1', 1);
  s.putRecord(a);
  final succ = signed('succession', {'successor': k2}, 'K1', 2);
  s.putRecord(succ);
  check(s.lineage(k2).contains(k1) && s.lineage(k1).contains(k2));
  final r = signed('retraction', {'retracts': a['id']}, 'K2', 3);
  s.putRecord(r); // successor may retract the predecessor's record
  check(s.assertionsAbout(sym('causal_relation_object:claim')).isEmpty);
}

void v34() {
  final g = normMap(vec(34)['given']);
  check(conflicts((g['A'] as Map).cast<String, dynamic>(),
          (g['B'] as Map).cast<String, dynamic>()) ==
      true);
}

void v35() {
  final g = normMap(vec(35)['given']);
  check(conflicts((g['A'] as Map).cast<String, dynamic>(),
          (g['B'] as Map).cast<String, dynamic>()) ==
      false);
}

void v36() {
  final a = sym('occurrent:A'), b = sym('occurrent:B'), c = sym('occurrent:C'), d = sym('occurrent:D');
  final m1 = <String, dynamic>{'id': sym('causal_relation_object:m1'), 'causes': [a], 'effects': [b]};
  final m2 = <String, dynamic>{'id': sym('causal_relation_object:m2'), 'causes': [b], 'effects': [c]};
  final m3 = <String, dynamic>{'id': sym('causal_relation_object:m3'), 'causes': [d], 'effects': [c]};
  final p = <String, dynamic>{
    'causes': [a],
    'effects': [c],
    'mechanism': [m1['id'], m2['id']],
  };
  check(hierarchyConsistent(p, {m1['id'] as String: m1, m2['id'] as String: m2}) ==
      'consistent');
  final p2 = Map<String, dynamic>.from(p)
    ..['mechanism'] = [m1['id'], m3['id']];
  check(hierarchyConsistent(p2, {m1['id'] as String: m1, m3['id'] as String: m3}) ==
      'inconsistent');
  check(hierarchyConsistent(p, {m1['id'] as String: m1}) == 'indeterminate');
}

void v37() {
  final s = InMemoryStore();
  final occ = s.put({
    'type': 'occurrent', 'label': 'press_button', 'category': 'action',
  });
  s.putRecord(signed('enrichment', {
    'about': occ,
    'field': 'aliases',
    'entry': {'lang': 'en', 'text': 'Press the Button'},
  }, 'alice', 1));
  check(sameList(s.resolve('Press  The   Button', 'en'), [occ])); // alias
  check(s.resolve('press_button', 'en').first == occ); // label, first
}

void v38() {
  final s = InMemoryStore();
  final p = s.put({
    'type': 'causal_relation_object',
    'causes': [sym('occurrent:A')],
    'effects': [sym('occurrent:B')],
  });
  var gapIds = s.gaps('missing_field').map((g) => g['id']).toList();
  check(gapIds.contains(p));
  final r = s.put({
    'type': 'causal_relation_object',
    'causes': [sym('occurrent:A')],
    'effects': [sym('occurrent:B')],
    'temporal': {'minimum_delay': 0, 'maximum_delay': 1, 'unit': 'seconds'},
    'modality': 'sufficient',
    'refines': p,
  });
  gapIds = s.gaps('missing_field').map((g) => g['id']).toList();
  check(!gapIds.contains(p), 'the gap did not close');
  check(!gapIds.contains(r), 'the refinement itself must be complete');
}

// ---------------------------------------------------------------------------

void main() {
  print('causalontology-dart conformance run');
  stdout.write(
      'internal checks (RFC 8032 known-answer, RFC 8785 basics) ... ');
  internalChecks();
  print('ok');
  final vectors = <void Function()>[
    v01, v02, v03, v04, v05, v06, v07, v08, v09, v10,
    v11, v12, v13, v14, v15, v16, v17, v18, v19, v20,
    v21, v22, v23, v24, v25, v26, v27, v28, v29, v30,
    v31, v32, v33, v34, v35, v36, v37, v38,
  ];
  var failures = 0;
  for (var n = 1; n <= 38; n++) {
    final name = vecFile(n)
        .uri
        .pathSegments
        .last
        .replaceFirst(RegExp(r'\.json$'), '');
    try {
      vectors[n - 1]();
      print('PASS  $name');
    } catch (e) {
      failures++;
      print('FAIL  $name :: $e');
    }
  }
  const total = 38;
  print('-' * 60);
  print('${total - failures}/$total vectors passed');
  if (failures > 0) {
    exit(1);
  }
  print('causalontology-dart is CONFORMANT to the suite '
      '(vectors frozen at specification 1.0.0).');
}

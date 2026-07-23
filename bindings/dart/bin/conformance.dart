/// The Causalontology conformance runner for causalontology-dart.
///
/// Runs every vector in conformance/vectors/ against the Dart binding. An
/// implementation is conformant if and only if it passes every vector; this
/// runner exits nonzero on any failure. It mirrors
/// bindings/python/tests/run_conformance.py exactly.
///
/// Vectors V01-V107 are the whole-word 2.0.0 baseline (Principle P7): V01-V38
/// re-frozen unaltered in meaning, V39-V107 new. V108-V119 are the 3.0.0
/// additions (the ticks unit, the cross_stratal_seam, the conduit realized_by);
/// V120-V137 are the 4.0.0 additions (attitude, predicted_occurrence,
/// prediction_error).
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
// whole-word scheme normalization (Principle P7)
// ---------------------------------------------------------------------------

const List<String> _schemes = [
  'occurrent', 'causal_relation_object', 'continuant', 'realizable',
  'assertion', 'enrichment', 'retraction', 'succession',
  'stratum', 'bridge', 'cross_stratal_seam', 'port', 'conduit', 'quality',
  'token_individual', 'token_occurrence', 'state_assertion',
  'token_causal_claim',
  'attitude', 'predicted_occurrence', 'prediction_error',
];
final Set<String> wholeWord = {..._schemes, 'ed25519'};

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
    if (_hex64.hasMatch(name)) return s;
    return key(name).$2;
  }
  if (_hex64.hasMatch(name)) return s;
  return '$scheme:${hexEncode(sha256(utf8.encode(name)))}';
}

/// Recursively normalize symbolic identifiers and placeholders.
Object? normalize(Object? x) {
  if (x is String) {
    if (x == '<128 hex>') return 'ab' * 64;
    if (_symbolic.hasMatch(x)) return sym(x);
    return x;
  }
  if (x is List) return x.map(normalize).toList();
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

/// A content object completed with its real content-addressed id.
Map<String, dynamic> mk(Map<String, dynamic> obj) {
  final o = Map<String, dynamic>.from(obj);
  o['id'] = identify(o);
  return o;
}

// ---------------------------------------------------------------------------
// builders (mirror the Python helpers)
// ---------------------------------------------------------------------------

Map<String, dynamic> stratum(String label, String scheme, int ordinal,
    {String? unit, List<String>? governs}) {
  final o = <String, dynamic>{
    'type': 'stratum', 'label': label, 'scheme': scheme, 'ordinal': ordinal,
  };
  if (unit != null) o['unit'] = unit;
  if (governs != null) o['governs'] = governs;
  return mk(o);
}

Map<String, dynamic> occ(String label,
    [String? stratumId, String category = 'event']) {
  final o = <String, dynamic>{
    'type': 'occurrent', 'label': label, 'category': category,
  };
  if (stratumId != null) o['stratum'] = stratumId;
  return mk(o);
}

Map<String, dynamic> cnt(String label, [String category = 'object']) =>
    mk({'type': 'continuant', 'label': label, 'category': category});

Map<String, dynamic> cro(List causes, List effects,
    [Map<String, dynamic> extra = const {}]) {
  final o = <String, dynamic>{
    'type': 'causal_relation_object', 'causes': causes, 'effects': effects,
  };
  o.addAll(extra);
  return mk(o);
}

Map<String, dynamic> bridge(String coarse, List<String> fine, String relation) =>
    mk({'type': 'bridge', 'coarse': coarse, 'fine': fine, 'relation': relation});

Map<String, dynamic> port(String bearer, String label, String direction,
    List<String> accepts, [String? realizable]) {
  final o = <String, dynamic>{
    'type': 'port', 'bearer': bearer, 'label': label,
    'direction': direction, 'accepts': accepts,
  };
  if (realizable != null) o['realizable'] = realizable;
  return mk(o);
}

Map<String, dynamic> conduit(String frm, String to, List<String> carries,
    {String label = 'conn', String? transform}) {
  final o = <String, dynamic>{
    'type': 'conduit', 'label': label, 'from': frm, 'to': to,
    'carries': carries,
  };
  if (transform != null) o['transform'] = transform;
  return mk(o);
}

Map<String, dynamic> quality(String label, String datatype,
    [String? unit, String? stratumId]) {
  final o = <String, dynamic>{
    'type': 'quality', 'label': label, 'datatype': datatype,
  };
  if (unit != null) o['unit'] = unit;
  if (stratumId != null) o['stratum'] = stratumId;
  return mk(o);
}

Map<String, dynamic> individual(String instantiates,
    {String? designator, String? partOf}) {
  final o = <String, dynamic>{
    'type': 'token_individual', 'instantiates': instantiates,
  };
  if (designator != null) o['designator'] = designator;
  if (partOf != null) o['part_of'] = partOf;
  return mk(o);
}

Map<String, dynamic> token(String instantiates, Map<String, dynamic> interval,
    {List<Map<String, dynamic>>? participants, String? locus}) {
  final o = <String, dynamic>{
    'type': 'token_occurrence', 'instantiates': instantiates,
    'interval': interval,
  };
  if (participants != null) o['participants'] = participants;
  if (locus != null) o['locus'] = locus;
  return mk(o);
}

Map<String, dynamic> state(String subject, String qual,
        Map<String, dynamic> value, Map<String, dynamic> interval) =>
    mk({
      'type': 'state_assertion', 'subject': subject, 'quality': qual,
      'value': value, 'interval': interval,
    });

Map<String, dynamic> tcc(List causes, List effects,
    {String? coveringLaw,
    Map<String, dynamic>? actualDelay,
    bool? counterfactual}) {
  final o = <String, dynamic>{
    'type': 'token_causal_claim', 'causes': causes, 'effects': effects,
  };
  if (coveringLaw != null) o['covering_law'] = coveringLaw;
  if (actualDelay != null) o['actual_delay'] = actualDelay;
  if (counterfactual != null) o['counterfactual'] = counterfactual;
  return mk(o);
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
  check(
      hexEncode(sha256(const [])) ==
          'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      'sha256 empty KAT');
  check(hexEncode(sha512(const [])).startsWith('cf83e135'),
      'sha512 empty KAT');
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
  check(jcs({'b': 2, 'a': 1}) == '{"a":1,"b":2}', 'JCS key order');
  check(jcs(1.0) == '1' && jcs(6.000) == '6' && jcs(0.7) == '0.7',
      'JCS numbers');
  check(toSeconds(1, 'months') == 2629746, 'months constant');
  check(toSeconds(1, 'years') == 31556952, 'years constant');
}

// ---------------------------------------------------------------------------
// V01 - V38: the whole-word re-freeze of the 1.0.0 suite
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
  final dog = sym('continuant:dog'),
      mam = sym('continuant:mammal'),
      ani = sym('continuant:animal');
  Map<String, dynamic> enrich(String about, String entry, int i) => signed(
      'enrichment', {'about': about, 'field': 'subsumes', 'entry': entry},
      'taxo', i);
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
  final c = <String, dynamic>{
    'causes': [sym('occurrent:c')],
    'effects': [sym('occurrent:e')],
    'temporal': g['temporal'],
  };
  return admissible(c, g['elapsed_seconds'] as num);
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
  final obj = {
    'type': 'occurrent', 'label': 'press_button', 'category': 'action',
  };
  final a = s.put(Map<String, dynamic>.from(obj));
  final b = s.put(Map<String, dynamic>.from(obj));
  check(a == b && s.objects.length == 1);
}

void v27() {
  final s = InMemoryStore();
  final occid = s.put({
    'type': 'occurrent', 'label': 'press_button', 'category': 'action',
  });
  final entry = {'lang': 'en', 'text': 'press the button'};
  final r1 = signed('enrichment',
      {'about': occid, 'field': 'aliases', 'entry': entry}, 'alice', 1);
  final r2 = signed('enrichment',
      {'about': occid, 'field': 'aliases', 'entry': entry}, 'bob', 2);
  check(s.putRecord(r1) != s.putRecord(r2));
  final view = (s.get(occid)!['enrichments'] as Map)['aliases'] as List;
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
}

void v32() {
  final s = InMemoryStore();
  final occid = s.put({
    'type': 'occurrent', 'label': 'press_button', 'category': 'action',
  });
  final e = signed('enrichment', {
    'about': occid,
    'field': 'aliases',
    'entry': {'lang': 'ja', 'text': 'botan'},
  }, 'bob', 1);
  s.putRecord(e);
  check(
      ((s.get(occid)!['enrichments'] as Map)['aliases'] as List?)?.length == 1);
  s.putRecord(signed('retraction', {'retracts': e['id']}, 'bob', 2));
  check(((s.get(occid)!['enrichments'] as Map)['aliases'] as List?) == null ||
      ((s.get(occid)!['enrichments'] as Map)['aliases'] as List).isEmpty);
  final hist =
      (s.get(occid, 'history')!['enrichments'] as Map)['aliases'] as List?;
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
  s.putRecord(signed('succession', {'successor': k2}, 'K1', 2));
  check(s.lineage(k2).contains(k1) && s.lineage(k1).contains(k2));
  s.putRecord(signed('retraction', {'retracts': a['id']}, 'K2', 3));
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
  final a = sym('occurrent:A'),
      b = sym('occurrent:B'),
      c = sym('occurrent:C'),
      d = sym('occurrent:D');
  final m1 = <String, dynamic>{
    'id': sym('causal_relation_object:m1'), 'causes': [a], 'effects': [b],
  };
  final m2 = <String, dynamic>{
    'id': sym('causal_relation_object:m2'), 'causes': [b], 'effects': [c],
  };
  final m3 = <String, dynamic>{
    'id': sym('causal_relation_object:m3'), 'causes': [d], 'effects': [c],
  };
  final p = <String, dynamic>{
    'causes': [a], 'effects': [c], 'mechanism': [m1['id'], m2['id']],
  };
  check(hierarchyConsistent(
          p, {m1['id'] as String: m1, m2['id'] as String: m2}) ==
      'consistent');
  final p2 = Map<String, dynamic>.from(p)..['mechanism'] = [m1['id'], m3['id']];
  check(hierarchyConsistent(
          p2, {m1['id'] as String: m1, m3['id'] as String: m3}) ==
      'inconsistent');
  check(hierarchyConsistent(p, {m1['id'] as String: m1}) == 'indeterminate');
}

void v37() {
  final s = InMemoryStore();
  final occid = s.put({
    'type': 'occurrent', 'label': 'press_button', 'category': 'action',
  });
  s.putRecord(signed('enrichment', {
    'about': occid,
    'field': 'aliases',
    'entry': {'lang': 'en', 'text': 'Press the Button'},
  }, 'alice', 1));
  check(sameList(s.resolve('Press  The   Button', 'en'), [occid]));
  check(s.resolve('press_button', 'en').first == occid);
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
// V39 - V107: the 2.0.0 additions
// ---------------------------------------------------------------------------

Map<int, Map<String, dynamic>> neuro() {
  const labels = {
    4: 'macromolecular', 5: 'subcellular', 6: 'cellular',
    7: 'synaptic', 9: 'region', 14: 'community_and_society',
  };
  return {
    for (final o in labels.keys) o: stratum(labels[o]!, 'neuroendocrine', o),
  };
}

void v39() {
  final st = stratum('cellular', 'neuroendocrine', 6,
      unit: 'cell', governs: ['cell_biology']);
  final (ok, why) = validateSchema(st);
  check(ok, why);
}

void v40() {
  final bad = mk({'type': 'stratum', 'label': 'cellular', 'ordinal': 6});
  final (ok, why) = validateSchema(bad, 'stratum');
  check(!ok && why.any((w) => w.contains('scheme')), why);
}

void v41() {
  final a = stratum('cellular', 'neuroendocrine', 6);
  final b = stratum('neuronal', 'neuroendocrine', 6);
  for (final x in [a, b]) {
    final (ok, why) = validateSchema(x);
    check(ok, why);
  }
  check(a['id'] != b['id']);
}

void v42() {
  final s = neuro();
  final s4p = stratum('molecular', 'physics', 4);
  final c = occ('chronic_social_subordination', s[14]!['id'] as String);
  final e = occ('gene_expression', s4p['id'] as String);
  final smap = <String, Map<String, dynamic>>{
    s[14]!['id'] as String: s[14]!, s4p['id'] as String: s4p,
  };
  final omap = <String, Map<String, dynamic>>{
    c['id'] as String: c, e['id'] as String: e,
  };
  final p = cro([c['id']], [e['id']]);
  check(classifyCro(p, omap, smap) == 'scheme_mismatch');
}

void v43() {
  for (final x in [
    stratum('macromolecular', 'neuroendocrine', 4),
    stratum('region', 'neuroendocrine', 9),
  ]) {
    final (ok, why) = validateSchema(x);
    check(ok, why);
  }
}

void v44() {
  final st = stratum('cellular', 'neuroendocrine', 6);
  final o = occ('neuron_fires', st['id'] as String);
  var (ok, why) = validateSchema(o);
  check(ok, why);
  (ok, why) = validateSemantics(o);
  check(ok, why);
}

void v45() {
  final o = occ('press_button');
  final (ok, why) = validateSchema(o);
  check(ok, why);
  final e = occ('light_on');
  final p = cro([o['id']], [e['id']]);
  check(classifyCro(p, {o['id'] as String: o, e['id'] as String: e},
          const {}) ==
      'unclassifiable');
}

void v46() {
  final s = neuro();
  final a = occ('depolarization', s[5]!['id'] as String);
  final b = occ('depolarization', s[6]!['id'] as String);
  check(a['id'] != b['id']);
}

(Map<String, dynamic>, Map<String, Map<String, dynamic>>,
    Map<String, Map<String, dynamic>>) bridgeFixture(String relation) {
  final s = neuro();
  final coarse = occ('action_potential_fires', s[6]!['id'] as String);
  final fine = [
    occ('sodium_channels_open', s[4]!['id'] as String),
    occ('sodium_influx', s[4]!['id'] as String),
  ];
  final b = bridge(coarse['id'] as String,
      [for (final f in fine) f['id'] as String], relation);
  final omap = <String, Map<String, dynamic>>{coarse['id'] as String: coarse};
  for (final f in fine) {
    omap[f['id'] as String] = f;
  }
  final smap = <String, Map<String, dynamic>>{
    s[4]!['id'] as String: s[4]!, s[6]!['id'] as String: s[6]!,
  };
  return (b, omap, smap);
}

void validBridge(String relation) {
  final (b, omap, smap) = bridgeFixture(relation);
  final (ok1, why1) = validateSchema(b);
  check(ok1, why1);
  final (ok2, why2) = bridgeWellformed(b, omap, smap);
  check(ok2, why2);
}

void v47() => validBridge('constitutes');
void v48() => validBridge('aggregates');
void v49() => validBridge('realizes');
void v50() => validBridge('supervenes_on');

void v51() {
  final s = neuro();
  final coarse = occ('x_coarse', s[4]!['id'] as String);
  final fine = occ('x_fine', s[6]!['id'] as String);
  final b = bridge(coarse['id'] as String, [fine['id'] as String],
      'constitutes');
  final omap = <String, Map<String, dynamic>>{
    coarse['id'] as String: coarse, fine['id'] as String: fine,
  };
  final smap = <String, Map<String, dynamic>>{
    s[4]!['id'] as String: s[4]!, s[6]!['id'] as String: s[6]!,
  };
  final (ok, _) = bridgeWellformed(b, omap, smap);
  check(!ok);
}

void v52() {
  final s = neuro();
  final coarse = occ('c', s[6]!['id'] as String);
  final f1 = occ('f1', s[4]!['id'] as String);
  final f2 = occ('f2', s[5]!['id'] as String);
  final b = bridge(coarse['id'] as String,
      [f1['id'] as String, f2['id'] as String], 'constitutes');
  final omap = <String, Map<String, dynamic>>{
    coarse['id'] as String: coarse,
    f1['id'] as String: f1,
    f2['id'] as String: f2,
  };
  final smap = <String, Map<String, dynamic>>{
    s[4]!['id'] as String: s[4]!,
    s[5]!['id'] as String: s[5]!,
    s[6]!['id'] as String: s[6]!,
  };
  final (ok, _) = bridgeWellformed(b, omap, smap);
  check(!ok);
}

void v53() {
  final x = sym('occurrent:x'), y = sym('occurrent:y');
  final b1 = bridge(x, [y], 'constitutes');
  final b2 = bridge(y, [x], 'constitutes');
  final edges = <String, List<String>>{};
  for (final b in [b1, b2]) {
    for (final f in (b['fine'] as List).cast<String>()) {
      edges.putIfAbsent(f, () => []).add(b['coarse'] as String);
    }
  }
  check(hasCycle(edges) == true);
}

void v54() {
  final a = stratum('cellular', 'neuroendocrine', 6);
  final b = stratum('molecular', 'physics', 4);
  final coarse = occ('c', a['id'] as String);
  final fine = occ('f', b['id'] as String);
  final br = bridge(coarse['id'] as String, [fine['id'] as String],
      'constitutes');
  final omap = <String, Map<String, dynamic>>{
    coarse['id'] as String: coarse, fine['id'] as String: fine,
  };
  final smap = <String, Map<String, dynamic>>{
    a['id'] as String: a, b['id'] as String: b,
  };
  final (ok, _) = bridgeWellformed(br, omap, smap);
  check(!ok);
}

void v55() {
  final s = neuro();
  final coarse = occ('decision_made', s[6]!['id'] as String);
  final f1 = occ('cascade_a', s[4]!['id'] as String);
  final f2 = occ('cascade_b', s[4]!['id'] as String);
  final b1 = bridge(coarse['id'] as String, [f1['id'] as String], 'realizes');
  final b2 = bridge(coarse['id'] as String, [f2['id'] as String], 'realizes');
  check(b1['id'] != b2['id']);
  for (final b in [b1, b2]) {
    final (ok, why) = validateSchema(b);
    check(ok, why);
  }
}

(Map<String, dynamic>, Map<String, Map<String, dynamic>>,
    List<Map<String, dynamic>>) reachFixture() {
  final s = neuro();
  final ap = occ('action_potential_fires', s[6]!['id'] as String);
  final nt = occ('neurotransmitter_released', s[6]!['id'] as String);
  final fa = occ('calcium_enters', s[4]!['id'] as String);
  final fb = occ('vesicle_fuses', s[4]!['id'] as String);
  final m1 = cro([fa['id']], [fb['id']]);
  final p = cro([ap['id']], [nt['id']], {'mechanism': [m1['id']]});
  final bridges = [
    bridge(ap['id'] as String, [fa['id'] as String], 'constitutes'),
    bridge(nt['id'] as String, [fb['id'] as String], 'constitutes'),
  ];
  return (p, {m1['id'] as String: m1}, bridges);
}

void v56() {
  final (p, members, bridges) = reachFixture();
  check(hierarchyConsistent(p, members, bridges) == 'consistent');
}

void v57() {
  final (p, members, _) = reachFixture();
  check(hierarchyConsistent(p, members, const []) == 'inconsistent');
}

void v58() {
  final (p, members, bridges) = reachFixture();
  final literal = hierarchyConsistent(p, members, const []);
  final bridged = hierarchyConsistent(p, members, bridges);
  check(literal != 'consistent' && bridged == 'consistent');
}

String classify(int causeOrd, int effectOrd) {
  final s = neuro();
  final c = occ('c', s[causeOrd]!['id'] as String);
  final e = occ('e', s[effectOrd]!['id'] as String);
  final smap = <String, Map<String, dynamic>>{
    s[causeOrd]!['id'] as String: s[causeOrd]!,
    s[effectOrd]!['id'] as String: s[effectOrd]!,
  };
  final omap = <String, Map<String, dynamic>>{
    c['id'] as String: c, e['id'] as String: e,
  };
  return classifyCro(cro([c['id']], [e['id']]), omap, smap);
}

void v59() => check(classify(6, 6) == 'intra_stratal');
void v60() => check(classify(6, 5) == 'adjacent_stratal');
void v61() => check(classify(14, 4) == 'skipping');

(Map<String, dynamic>, String) skipFixture(int causeOrd, int effectOrd,
    [Map<String, dynamic> extra = const {}]) {
  final s = neuro();
  final c = occ('c', s[causeOrd]!['id'] as String);
  final e = occ('e', s[effectOrd]!['id'] as String);
  final smap = <String, Map<String, dynamic>>{
    s[causeOrd]!['id'] as String: s[causeOrd]!,
    s[effectOrd]!['id'] as String: s[effectOrd]!,
  };
  final omap = <String, Map<String, dynamic>>{
    c['id'] as String: c, e['id'] as String: e,
  };
  final p = cro([c['id']], [e['id']], extra);
  return (p, classifyCro(p, omap, smap));
}

void v62() {
  final (p, cls) = skipFixture(14, 4);
  check(sameList(skipGaps(p, cls), ['incomplete_mechanism']));
}

void v63() {
  final (p, cls) = skipFixture(14, 4, {'skips': true});
  check(skipGaps(p, cls).isEmpty);
}

void v64() {
  final (p, cls) = skipFixture(14, 4,
      {'skips': true, 'mechanism': [sym('causal_relation_object:m')]});
  check(sameList(skipGaps(p, cls), ['contradictory_skip']));
  final (ok, why) = validateSemantics(p);
  check(!ok && why.any((w) => w.contains('contradictory_skip')), why);
}

void v65() {
  final (p, cls) = skipFixture(6, 6, {'skips': true});
  check(sameList(skipGaps(p, cls), ['vacuous_skip']));
}

void v66() {
  final s = neuro();
  final c = occ('c', s[14]!['id'] as String);
  final e = occ('e', s[4]!['id'] as String);
  final absent = cro([c['id']], [e['id']]);
  final falseSkip = cro([c['id']], [e['id']], {'skips': false});
  check(absent['id'] != falseSkip['id']);
}

void v67() {
  final s = neuro();
  final c1 = occ('c1', s[4]!['id'] as String);
  final c2 = occ('c2', s[6]!['id'] as String);
  final e = occ('e', s[6]!['id'] as String);
  final p = cro([c1['id'], c2['id']], [e['id']]);
  check(endpointsMixed(p, {
        c1['id'] as String: c1,
        c2['id'] as String: c2,
        e['id'] as String: e,
      }) ==
      true);
}

void v68() {
  final p = cro([sym('occurrent:a')], [sym('occurrent:b')],
      {'modality': 'enabling'});
  final (ok, why) = validateSchema(p);
  check(ok, why);
}

void v69() {
  final a = {
    'causes': [sym('occurrent:a')], 'effects': [sym('occurrent:b')],
    'modality': 'enabling',
  };
  final b = {
    'causes': [sym('occurrent:a')], 'effects': [sym('occurrent:b')],
    'modality': 'sufficient',
  };
  check(conflicts(a, b) == false);
}

void v70() {
  final a = {
    'causes': [sym('occurrent:a')], 'effects': [sym('occurrent:b')],
    'modality': 'enabling',
  };
  final b = {
    'causes': [sym('occurrent:a')], 'effects': [sym('occurrent:b')],
    'modality': 'preventive',
  };
  check(conflicts(a, b) == true);
}

void v71() {
  final b = cnt('hippocampus');
  final p = port(b['id'] as String, 'perforant_path', 'in',
      [sym('occurrent:signal')]);
  final (ok, why) = validateSchema(p);
  check(ok, why);
}

void v72() {
  final b = cnt('hippocampus')['id'] as String;
  final x = sym('occurrent:signal');
  check(port(b, 'perforant_path', 'in', [x])['id'] !=
      port(b, 'fornix', 'in', [x])['id']);
}

(Map<String, dynamic>, Map<String, Map<String, dynamic>>,
        Map<String, Map<String, dynamic>>)
    conduitFixture(
        {bool transform = false, bool badCarry = false, bool inFrom = false}) {
  final x = sym('occurrent:motor_command');
  final y = sym('occurrent:error_signal');
  final z = sym('occurrent:unrelated');
  final m1 = cnt('motor_cortex')['id'] as String;
  final m2 = cnt('spinal_neuron')['id'] as String;
  final frm = port(m1, 'out_port', inFrom ? 'in' : 'out', [x]);
  final to = port(m2, 'in_port', 'in', transform ? [y] : [x]);
  final carries = badCarry ? [z] : [x];
  String? xform;
  final croMap = <String, Map<String, dynamic>>{};
  if (transform) {
    final law = cro([x], [y]);
    croMap[law['id'] as String] = law;
    xform = law['id'] as String;
  }
  final c = conduit(frm['id'] as String, to['id'] as String, carries,
      transform: xform);
  return (
    c,
    {frm['id'] as String: frm, to['id'] as String: to},
    croMap,
  );
}

void v73() {
  final (c, pmap, _) = conduitFixture();
  final (ok1, why1) = validateSchema(c);
  check(ok1, why1);
  final (ok2, why2) = conduitWellformed(c, pmap);
  check(ok2, why2);
}

void v74() {
  final (c, pmap, cmap) = conduitFixture(transform: true);
  final (ok1, why1) = validateSchema(c);
  check(ok1, why1);
  final (ok2, why2) = conduitWellformed(c, pmap, cmap);
  check(ok2, why2);
}

void v75() {
  final (c, pmap, _) = conduitFixture(badCarry: true);
  final (ok, _) = conduitWellformed(c, pmap);
  check(!ok);
}

void v76() {
  final (c, pmap, _) = conduitFixture(inFrom: true);
  final (ok, _) = conduitWellformed(c, pmap);
  check(!ok);
}

void v77() {
  final (c, pmap, cmap) = conduitFixture(transform: true);
  final (ok, why) = conduitWellformed(c, pmap, cmap);
  check(ok, why);
  final law = cmap.values.first;
  check(!(c['carries'] as List).contains((law['effects'] as List).first));
}

Map<String, dynamic> rlz(String bearer, String kind, [String? label]) {
  final o = <String, dynamic>{'type': 'realizable', 'kind': kind, 'bearer': bearer};
  if (label != null) o['label'] = label;
  return mk(o);
}

void v78() {
  final b = cnt('hippocampus')['id'] as String;
  check(rlz(b, 'disposition', 'long_term_potentiation')['id'] !=
      rlz(b, 'disposition', 'pattern_separation')['id']);
}

void v79() {
  final b = cnt('hippocampus')['id'] as String;
  final u1 = rlz(b, 'disposition');
  final u2 = rlz(b, 'disposition');
  final (ok, why) = validateSchema(u1);
  check(ok, why);
  check(u1['id'] == u2['id']);
  check(rlz(b, 'disposition', 'some_function')['id'] != u1['id']);
}

void v80() {
  final parent = occ('fires');
  final child = occ('fires_action_potential');
  final e = {
    'type': 'enrichment', 'about': child['id'],
    'field': 'occurrent_subsumes', 'entry': parent['id'],
  };
  final (ok, why) = validateSemantics(e);
  check(ok, why);
}

void v81() {
  final a = sym('occurrent:a'), b = sym('occurrent:b');
  check(hasCycle({a: [b], b: [a]}) == true);
}

void v82() {
  final whole = occ('eat');
  final part = occ('chew');
  final e = {
    'type': 'enrichment', 'about': part['id'],
    'field': 'occurrent_part_of', 'entry': whole['id'],
  };
  final (ok, why) = validateSemantics(e);
  check(ok, why);
}

void v83() {
  final (legalKinds, shape) = enrichmentFields['occurrent_part_of']!;
  check(shape == 'occurrent' && sameList(legalKinds, ['occurrent']));
  final s = InMemoryStore();
  s.put(occ('eat'));
  s.put(occ('chew'));
  check(!s.objects.values
      .any((o) => o['type'] == 'causal_relation_object'));
}

void v84() {
  final s = neuro();
  final a = occ('run', s[9]!['id'] as String);
  final b = occ('sprint', s[6]!['id'] as String);
  check(a['stratum'] != b['stratum']);
}

void v85() {
  final c = cnt('human_patient');
  final ti = individual(c['id'] as String, designator: 'salted_hash_abc123');
  final (ok, why) = validateSchema(ti);
  check(ok, why);
}

void v86() {
  final bad = mk({'type': 'token_individual', 'designator': 'x'});
  final (ok, why) = validateSchema(bad, 'token_individual');
  check(!ok && why.any((w) => w.contains('instantiates')), why);
}

void v87() {
  final c = cnt('human_patient')['id'] as String;
  check(individual(c, designator: 'hash_a')['id'] !=
      individual(c, designator: 'hash_b')['id']);
}

void v88() {
  final o = occ('bilateral_hippocampal_resection');
  final t = token(o['id'] as String,
      {'start': '1953-08-25T00:00:00Z', 'end': '1953-08-25T00:00:00Z'});
  final (ok, why) = validateSchema(t);
  check(ok, why);
}

void v89() {
  final o = occ('amnesia_onset')['id'] as String;
  final bounded = token(o,
      {'start': '1953-08-25T00:00:00Z', 'end': '1953-08-26T00:00:00Z'});
  final instantaneous = token(o, {'start': '1953-08-25T00:00:00Z'});
  final ongoing =
      token(o, {'start': '1953-08-25T00:00:00Z', 'open': true});
  check({bounded['id'], instantaneous['id'], ongoing['id']}.length == 3);
}

void v90() {
  final o = occ('resection')['id'] as String;
  final c = cnt('human_patient')['id'] as String;
  final patient = individual(c, designator: 'p')['id'] as String;
  final surgeon = individual(c, designator: 's')['id'] as String;
  final t = token(o, {'start': '1953-08-25T00:00:00Z'}, participants: [
    {'role': 'patient', 'filler': patient},
    {'role': 'agent', 'filler': surgeon},
  ]);
  final (ok, why) = validateSchema(t);
  check(ok, why);
}

void v91() {
  final q = quality('cortisol_concentration', 'quantity', 'ug/dL');
  final (ok, why) = validateSchema(q);
  check(ok, why);
}

(Map<String, dynamic>, Map<String, dynamic>) stateFixture(
    String datatype, Map<String, dynamic> value,
    [String? unit]) {
  final q = quality('cortisol_concentration', datatype, unit);
  final c = cnt('human_patient')['id'] as String;
  final subj = individual(c, designator: 'p')['id'] as String;
  final st = state(subj, q['id'] as String, value,
      {'start': '2026-01-01T00:00:00Z', 'end': '2026-01-01T01:00:00Z'});
  return (st, q);
}

void v92() {
  final (st, q) =
      stateFixture('quantity', {'quantity': 15.0, 'unit': 'ug/dL'}, 'ug/dL');
  final (ok, why) = validateSchema(st);
  check(ok, why);
  check(stateGaps(st, q).isEmpty);
}

void v93() {
  final (st, q) = stateFixture('categorical', {'categorical': 'elevated'});
  final (ok, why) = validateSchema(st);
  check(ok, why);
  check(stateGaps(st, q).isEmpty);
}

void v94() {
  final (st, q) = stateFixture('boolean', {'boolean': true});
  final (ok, why) = validateSchema(st);
  check(ok, why);
  check(stateGaps(st, q).isEmpty);
}

void v95() {
  final (st, q) =
      stateFixture('quantity', {'categorical': 'elevated'}, 'ug/dL');
  check(sameList(stateGaps(st, q), ['value_type_mismatch']));
}

void v96() {
  final (st, q) =
      stateFixture('quantity', {'quantity': 15.0, 'unit': 'mg/dL'}, 'ug/dL');
  check(sameList(stateGaps(st, q), ['unit_mismatch']));
}

(Map<String, dynamic>, Map<String, dynamic>, Map<String, dynamic>,
    Map<String, dynamic>, Map<String, dynamic>) lawAndTokens() {
  final oCause = occ('resection');
  final oEffect = occ('amnesia_onset');
  final law = cro([oCause['id']], [oEffect['id']], {
    'temporal': {'minimum_delay': 0, 'maximum_delay': 1, 'unit': 'days'},
    'modality': 'sufficient',
  });
  final tCause = token(oCause['id'] as String, {'start': '1953-08-25T00:00:00Z'});
  final tEffect = token(oEffect['id'] as String,
      {'start': '1953-08-25T00:00:00Z', 'open': true});
  return (law, oCause, oEffect, tCause, tEffect);
}

void v97() {
  final (law, _, _, tc, te) = lawAndTokens();
  final claim = tcc([tc['id']], [te['id']],
      coveringLaw: law['id'] as String,
      actualDelay: {'duration': 0, 'unit': 'instant'},
      counterfactual: true);
  final (ok, why) = validateSchema(claim);
  check(ok, why);
}

void v98() {
  final (_, _, _, tc, te) = lawAndTokens();
  final claim = tcc([tc['id']], [te['id']]);
  final (ok, why) = validateSchema(claim);
  check(ok, why);
  check(!claim.containsKey('covering_law'));
}

void v99() {
  final (law, _, _, _, _) = lawAndTokens();
  check(delayWithinWindow({'duration': 0, 'unit': 'instant'},
          (law['temporal'] as Map).cast<String, dynamic>()) ==
      true);
}

void v100() {
  final temporal = {'minimum_delay': 0, 'maximum_delay': 1, 'unit': 'hours'};
  check(delayWithinWindow({'duration': 5, 'unit': 'days'}, temporal) == false);
}

void v101() {
  final o = occ('x')['id'] as String;
  final cause = token(o, {'start': '2026-01-02T00:00:00Z'});
  final effect = token(o, {'start': '2026-01-01T00:00:00Z'});
  final claim = tcc([cause['id']], [effect['id']]);
  check(retrocausal(claim, {
        cause['id'] as String: cause,
        effect['id'] as String: effect,
      }) ==
      true);
}

void v102() {
  final other = cro([sym('occurrent:foo')], [sym('occurrent:bar')]);
  final (_, _, _, tc, te) = lawAndTokens();
  final claim =
      tcc([tc['id']], [te['id']], coveringLaw: other['id'] as String);
  check(coveringLawMismatch(claim,
          {tc['id'] as String: tc, te['id'] as String: te}, other) ==
      true);
}

void v103() {
  final a = signed('assertion', {
    'about': sym('token_occurrence:t'),
    'evidence_type': 'observation',
    'confidence': 0.9,
  }, 'signer');
  final (ok, why) = validateSchema(a);
  check(ok, why);
}

void v104() {
  final ev = [sym('token_occurrence:t1'), sym('token_causal_claim:c1')];
  final base = <String, dynamic>{
    'type': 'assertion',
    'about': sym('causal_relation_object:law'),
    'source': key('signer').$2,
    'evidence_type': 'intervention',
    'strength': 0.95,
    'confidence': 0.99,
    'timestamp': '2026-07-14T00:00:00Z',
  };
  final a = Map<String, dynamic>.from(base)..['evidenced_by'] = ev;
  final withId = Map<String, dynamic>.from(a)..['id'] = identify(a);
  final (ok, why) = validateSchema(withId);
  check(ok, why);
  check(identify(a) != identify(base)); // evidenced_by is identity-bearing
}

void v105() {
  final a = signed('assertion', {
    'about': sym('causal_relation_object:law'),
    'evidence_type': 'simulation',
    'confidence': 0.5,
  }, 'signer');
  final (ok, why) = validateSchema(a);
  check(ok, why);
  const rank = {'intervention': 0, 'observation': 1, 'simulation': 2};
  check(rank['intervention']! < rank['observation']! &&
      rank['observation']! < rank['simulation']!);
}

final RegExp _idRe = RegExp(r'^([a-z0-9_]+):[0-9a-f]{64}$');

void _scan(Object? node, List<String> ids) {
  if (node is String) {
    final m = _idRe.firstMatch(node);
    if (m != null) ids.add(m.group(1)!);
  } else if (node is List) {
    for (final x in node) {
      _scan(x, ids);
    }
  } else if (node is Map) {
    for (final x in node.values) {
      _scan(x, ids);
    }
  }
}

void v106() {
  for (var n = 1; n <= 38; n++) {
    final ids = <String>[];
    _scan(vec(n), ids);
    for (final scheme in ids) {
      check(wholeWord.contains(scheme),
          'V106: abbreviated scheme $scheme in vector $n');
    }
  }
  final rec = {
    'type': 'occurrent', 'label': 'press_button', 'category': 'action',
  };
  check(identify(rec) == identify(rec));
  check(identify(rec).split(':').first == 'occurrent');
}

void v107() {
  final hexid = '0' * 64;
  // NOTE: the abbreviated prefix below is intentional (the negative test);
  // it must NOT be re-minted. 'c' 'r' 'o' is assembled to survive re-mint tools.
  final croAbbr = 'c' 'r' 'o';
  final abbreviated = {
    'type': 'causal_relation_object', 'id': '$croAbbr:$hexid',
    'causes': ['occurrent:$hexid'],
    'effects': ['occurrent:$hexid'],
  };
  var (ok, _) = validateSchema(abbreviated, 'causal_relation_object');
  check(!ok, 'abbreviated scheme must be rejected');
  final abbrStr = {
    'type': 'stratum', 'id': 'str:$hexid', 'label': 'cellular',
    'scheme': 'neuroendocrine', 'ordinal': 6,
  };
  (ok, _) = validateSchema(abbrStr, 'stratum');
  check(!ok);
  final whole = {
    'type': 'causal_relation_object',
    'id': 'causal_relation_object:$hexid',
    'causes': ['occurrent:$hexid'],
    'effects': ['occurrent:$hexid'],
  };
  final (ok2, why2) = validateSchema(whole, 'causal_relation_object');
  check(ok2, why2);
}

// ---------------------------------------------------------------------------
// V108 - V119: the 3.0.0 additions (tick unit, cross_stratal_seam, realized_by)
// ---------------------------------------------------------------------------

/// A temporal window (a Causal Relation Object's delay bounds and unit).
Map<String, dynamic> temporal(num min, num max, String unit) => {
      'minimum_delay': min, 'maximum_delay': max, 'unit': unit,
    };

/// An observed delay (a duration and its unit).
Map<String, dynamic> duration(num dur, String unit) =>
    {'duration': dur, 'unit': unit};

/// A cross_stratal_seam content object completed with its id.
Map<String, dynamic> seam(String source, String target, String mechanismStatus,
    [List<String>? chain]) {
  final o = <String, dynamic>{
    'type': 'cross_stratal_seam', 'source': source, 'target': target,
    'mechanism_status': mechanismStatus,
  };
  if (chain != null && chain.isNotEmpty) o['chain'] = chain;
  return mk(o);
}

/// Build a seam over the neuro fixture: (seam, occMap, stratumMap).
(Map<String, dynamic>, Map<String, Map<String, dynamic>>,
        Map<String, Map<String, dynamic>>)
    seamFixture(int srcOrd, int tgtOrd, String mechanismStatus,
        [List<int>? chainOrds]) {
  final s = neuro();
  final src = occ('source_event', s[srcOrd]!['id'] as String);
  final tgt = occ('target_event', s[tgtOrd]!['id'] as String);
  final omap = <String, Map<String, dynamic>>{
    src['id'] as String: src, tgt['id'] as String: tgt,
  };
  final smap = <String, Map<String, dynamic>>{
    s[srcOrd]!['id'] as String: s[srcOrd]!,
    s[tgtOrd]!['id'] as String: s[tgtOrd]!,
  };
  List<String>? chain;
  if (chainOrds != null) {
    chain = [];
    var i = 0;
    for (final o in chainOrds) {
      final c = occ('chain_$i', s[o]!['id'] as String);
      omap[c['id'] as String] = c;
      smap[s[o]!['id'] as String] = s[o]!;
      chain.add(c['id'] as String);
      i++;
    }
  }
  return (
    seam(src['id'] as String, tgt['id'] as String, mechanismStatus, chain),
    omap,
    smap,
  );
}

/// A conduit with an optional realized_by reference, completed with its id.
Map<String, dynamic> conduitRealized([String? realizedBy]) {
  final o = <String, dynamic>{
    'type': 'conduit', 'label': 'conn',
    'from': 'port:${'1' * 64}', 'to': 'port:${'2' * 64}',
    'carries': ['occurrent:${'3' * 64}'],
  };
  if (realizedBy != null) o['realized_by'] = realizedBy;
  return mk(o);
}

// -- Change One: the ordinal (tick) temporal unit --
void v108() {
  final p = cro([sym('occurrent:a')], [sym('occurrent:b')], {
    'temporal': temporal(0, 5, 'ticks'), 'modality': 'sufficient',
  });
  var (ok, why) = validateSchema(p);
  check(ok, why);
  (ok, why) = validateSemantics(p);
  check(ok, why);
}

void v109() {
  final p = cro([sym('occurrent:a')], [sym('occurrent:b')], {
    'temporal': temporal(2, 5, 'ticks'),
  });
  check(admissible(p, 3), '3 ticks inside [2, 5]');
  check(admissible(p, 2) && admissible(p, 5), 'endpoints are admissible');
  check(!admissible(p, 6) && !admissible(p, 1),
      'outside the tick window is not admissible');
}

void v110() {
  final tickWindow = temporal(0, 5, 'ticks');
  final wallWindow = temporal(0, 5, 'seconds');
  check(delayWithinWindow(duration(3, 'ticks'), tickWindow),
      '3 ticks within the tick window');
  check(!delayWithinWindow(duration(1, 'ticks'), wallWindow),
      'a tick delay is not within a wall-clock window');
  check(!delayWithinWindow(duration(1, 'seconds'), tickWindow),
      'a seconds delay is not within a tick window');
  final a = <String, dynamic>{
    'causes': [sym('occurrent:a')], 'effects': [sym('occurrent:b')],
    'temporal': tickWindow, 'modality': 'sufficient',
  };
  final b = <String, dynamic>{
    'causes': [sym('occurrent:a')], 'effects': [sym('occurrent:b')],
    'temporal': wallWindow, 'modality': 'preventive',
  };
  check(!conflicts(a, b), 'disjoint dimensions do not overlap');
  var refused = false;
  try {
    toSeconds(1, 'ticks');
  } catch (_) {
    refused = true;
  }
  check(refused, 'toSeconds must refuse an ordinal unit');
}

void v111() {
  Map<String, dynamic> base() => {
        'type': 'causal_relation_object',
        'causes': [sym('occurrent:a')], 'effects': [sym('occurrent:b')],
        'modality': 'sufficient',
      };
  final tick = base()..['temporal'] = temporal(0, 1, 'ticks');
  final secs = base()..['temporal'] = temporal(0, 1, 'seconds');
  check(identify(tick) != identify(secs), 'the unit is identity-bearing');
  // a wall-clock record's identity is UNCHANGED under 3.0.0 (pinned 2.0.0)
  check(
      identify(secs) ==
          'causal_relation_object:'
              'd8daf899daa3ee03caa6b1425cc6d4d33cef20d951e1203ffd35df29857aa43c',
      'the wall-clock CRO identity is pinned');
}

// -- Change Two: the managed cross-stratal seam (eighteenth kind) --
void v112() {
  final (sm, omap, smap) = seamFixture(14, 4, 'unmodeled');
  var (ok, why) = validateSchema(sm);
  check(ok, why);
  (ok, why) = validateSemantics(sm);
  check(ok, why);
  final (ok2, why2) = seamWellformed(sm, omap, smap);
  check(ok2, why2);
}

void v113() {
  final (a, _, _) = seamFixture(14, 4, 'unmodeled');
  final (b, omap, smap) = seamFixture(14, 4, 'absent');
  final (ok, why) = validateSchema(b);
  check(ok, why);
  final (ok2, why2) = seamWellformed(b, omap, smap);
  check(ok2, why2);
  check(a['id'] != b['id'], 'mechanism_status is identity-bearing');
}

void v114() {
  final (drawn, omap, smap) = seamFixture(14, 4, 'unmodeled', [9, 7, 6, 5]);
  final (ok, why) = validateSchema(drawn);
  check(ok, why);
  final (ok2, why2) = seamWellformed(drawn, omap, smap);
  check(ok2, why2);
  final (bad, omap2, smap2) = seamFixture(14, 4, 'absent', [9, 7, 6, 5]);
  final (okBad, whyBad) = validateSemantics(bad);
  check(!okBad && whyBad.any((w) => w.contains('contradictory_seam')),
      'contradictory_seam: ${whyBad.join('; ')}');
  final (ok3, _) = seamWellformed(bad, omap2, smap2);
  check(!ok3, 'a drawn chain with absent status is malformed');
}

void v115() {
  final (sm, omap, smap) = seamFixture(14, 4, 'unmodeled');
  final s = neuro();
  check(seamHome(sm, omap, smap) == s[14]!['id'],
      'the home is the coarsest (max ordinal) stratum');
}

void v116() {
  final (adj, o1, s1) = seamFixture(6, 5, 'unmodeled'); // adjacent (gap 1)
  final (ok1, _) = seamWellformed(adj, o1, s1);
  check(!ok1, 'an adjacent seam is malformed');
  final (co, o2, s2) = seamFixture(6, 6, 'unmodeled'); // co-stratal (gap 0)
  final (ok2, _) = seamWellformed(co, o2, s2);
  check(!ok2, 'a co-stratal seam is malformed');
  final (sm, _, _) = seamFixture(14, 4, 'unmodeled');
  check((sm['id'] as String).startsWith('cross_stratal_seam:'),
      'a new identity scheme');
}

// -- Change Three: the realized_by reference --
void v117() {
  final c = conduitRealized('causal_relation_object:${'a' * 64}');
  var (ok, why) = validateSchema(c);
  check(ok, why);
  final c2 = conduitRealized('native:region_stratum_predict');
  (ok, why) = validateSchema(c2);
  check(ok, why); // a native scheme reference is legal
}

void v118() {
  final bound = conduitRealized('native:region_stratum_predict');
  final unbound = conduitRealized();
  check(bound['id'] != unbound['id'], 'realized_by is identity-bearing');
  // an unbound conduit's identity is UNCHANGED under 3.0.0 (pinned 2.0.0)
  check(
      unbound['id'] ==
          'conduit:'
              'dc4af3b1a24f0560d5ebcee488779f06ab3c78301cfb9d0c7edff80bc62e27a6',
      'the unbound conduit identity is pinned');
}

void v119() {
  final unbound = conduitRealized();
  final (ok, why) = validateSchema(unbound);
  check(ok, why); // unbound is legal
  final bad = Map<String, dynamic>.from(unbound);
  bad['realized_by'] = 'not-a-scheme-qualified-reference';
  final (okBad, _) = validateSchema(bad, 'conduit');
  check(!okBad, 'a malformed realized_by reference is rejected');
}

// ---------------------------------------------------------------------------
// V120 - V137: the 4.0.0 additions (attitude, predicted_occurrence,
// prediction_error)
// ---------------------------------------------------------------------------

/// An attitude content object completed with its id.
Map<String, dynamic> attitude(
        String holder, String attitudeType, String content) =>
    mk({
      'type': 'attitude', 'holder': holder,
      'attitude_type': attitudeType, 'content': content,
    });

/// A predicted_occurrence content object completed with its id.
Map<String, dynamic> predicted(String instantiates,
    Map<String, dynamic> interval, String predictor,
    [num? strength]) {
  final o = <String, dynamic>{
    'type': 'predicted_occurrence', 'instantiates': instantiates,
    'interval': interval, 'predictor': predictor,
  };
  if (strength != null) o['strength'] = strength;
  return mk(o);
}

/// A prediction_error content object completed with its id.
Map<String, dynamic> predictionError(String predictedId, num discrepancy,
    [String? observed]) {
  final o = <String, dynamic>{
    'type': 'prediction_error', 'predicted': predictedId,
    'discrepancy': discrepancy,
  };
  if (observed != null) o['observed'] = observed;
  return mk(o);
}

/// An interval carrying the ordinal (tick) dimension.
Map<String, dynamic> tickInterval(int startTick, [int? endTick]) {
  final o = <String, dynamic>{'start_tick': startTick};
  if (endTick != null) o['end_tick'] = endTick;
  return o;
}

/// A modeled predicting agent (a token individual), by identity.
String predictorId() {
  final c = cnt('forecasting_mind');
  return individual(c['id'] as String, designator: 'predictor_p')['id']
      as String;
}

/// A modeled believing agent (a token individual), by identity.
String believerId([String designator = 'holder_h']) {
  final c = cnt('believing_mind');
  return individual(c['id'] as String, designator: designator)['id'] as String;
}

// -- Group X: prediction and prediction error (Section A) --
void v120() {
  final o = occ('rainfall_begins');
  final p = predicted(o['id'] as String, tickInterval(3, 8), predictorId());
  var (ok, why) = validateSchema(p);
  check(ok, why);
  (ok, why) = validateSemantics(p);
  check(ok, why);
  check((p['id'] as String).startsWith('predicted_occurrence:'),
      'a new identity scheme');
  final report = identify({
    'type': 'token_occurrence', 'instantiates': o['id'],
    'interval': tickInterval(3, 8),
  }, 'token_occurrence');
  check(p['id'] != report, 'a forecast is not a report');
  check(report.startsWith('token_occurrence:'),
      'the report is a token_occurrence');
}

void v121() {
  final o = occ('rainfall_begins');
  final wall = <String, dynamic>{
    'start': '2026-07-23T00:00:00Z', 'end': '2026-07-24T00:00:00Z',
  };
  final who = predictorId();
  final withStrength = predicted(o['id'] as String, wall, who, 0.8);
  final without = predicted(o['id'] as String, wall, who);
  for (final p in [withStrength, without]) {
    var (ok, why) = validateSchema(p);
    check(ok, why);
    (ok, why) = validateSemantics(p);
    check(ok, why);
  }
  check(withStrength['id'] != without['id'], 'strength is identity-bearing');
}

void v122() {
  final o = occ('rainfall_begins');
  final bad = mk({
    'type': 'predicted_occurrence', 'instantiates': o['id'],
    'interval': tickInterval(3),
  });
  final (ok, why) = validateSchema(bad, 'predicted_occurrence');
  check(!ok && why.any((w) => w.contains('predictor')),
      'predictor is required: ${why.join('; ')}');
}

void v123() {
  final o = occ('rainfall_begins');
  final iv = <String, dynamic>{
    'start': '2026-07-23T00:00:00Z', 'start_tick': 3,
  };
  final both = predicted(o['id'] as String, iv, predictorId());
  var (ok, why) = validateSchema(both);
  check(ok, why);
  (ok, why) = validateSemantics(both);
  check(!ok && why.any((w) => w.contains('dimension_conflict')),
      'dimension_conflict: ${why.join('; ')}');
}

void v124() {
  final o = occ('rainfall_begins');
  final p = predicted(
      o['id'] as String, {'start': '2026-07-23T00:00:00Z'}, predictorId());
  final t = token(o['id'] as String, {'start': '2026-07-23T06:00:00Z'});
  final err = predictionError(p['id'] as String, 0.0, t['id'] as String);
  var (ok, why) = validateSchema(err);
  check(ok, why);
  (ok, why) = validateSemantics(err);
  check(ok, why);
  check(!predictionPairingMismatch(err, p, t), 'no pairing mismatch');
}

void v125() {
  final o = occ('rainfall_begins');
  final p = predicted(
      o['id'] as String, {'start': '2026-07-23T00:00:00Z'}, predictorId());
  final err = predictionError(p['id'] as String, -1.0);
  var (ok, why) = validateSchema(err);
  check(ok, why);
  (ok, why) = validateSemantics(err);
  check(ok, why);
  check(!err.containsKey('observed'), 'observed is absent');
  check(!predictionPairingMismatch(err, p, null),
      'an absent observed is never a mismatch');
}

void v126() {
  final o = occ('rainfall_begins');
  final p = predicted(o['id'] as String, tickInterval(0), predictorId());
  final bad = mk({'type': 'prediction_error', 'predicted': p['id']});
  final (ok, why) = validateSchema(bad, 'prediction_error');
  check(!ok && why.any((w) => w.contains('discrepancy')),
      'discrepancy is required: ${why.join('; ')}');
}

void v127() {
  final o = occ('rainfall_begins');
  final other = occ('snowfall_begins');
  final p = predicted(
      o['id'] as String, {'start': '2026-07-23T00:00:00Z'}, predictorId());
  final t = token(other['id'] as String, {'start': '2026-07-23T06:00:00Z'});
  final err = predictionError(p['id'] as String, 1.0, t['id'] as String);
  final (ok, why) = validateSchema(err);
  check(ok, why);
  check(predictionPairingMismatch(err, p, t), 'pairing mismatch');
}

// -- Group Y: attitude and theory of mind (Section B) --
void v128() {
  final (st, _) =
      stateFixture('quantity', {'quantity': 15.0, 'unit': 'ug/dL'}, 'ug/dL');
  final att = attitude(believerId(), 'believes', st['id'] as String);
  var (ok, why) = validateSchema(att);
  check(ok, why);
  (ok, why) = validateSemantics(att);
  check(ok, why);
}

void v129() {
  final a = occ('switch_pressed');
  final b = occ('light_on');
  final actual = cro([a['id']], [b['id']], {'modality': 'sufficient'});
  final believed = cro([a['id']], [b['id']], {'modality': 'preventive'});
  check(conflicts(believed, actual), 'the claims contradict');
  final att = attitude(believerId(), 'believes', believed['id'] as String);
  var (ok, why) = validateSchema(att);
  check(ok, why);
  (ok, why) = validateSemantics(att);
  check(ok, why); // validity unaffected
  final s = InMemoryStore();
  s.put(a);
  s.put(b);
  s.put(actual);
  s.put(att);
  check(s.gaps('conflict').isEmpty,
      'Rule 25: no conflict raised for a quarantined belief');
}

void v130() {
  final o = occ('rainfall_begins');
  final att = attitude(believerId(), 'desires', o['id'] as String);
  var (ok, why) = validateSchema(att);
  check(ok, why);
  (ok, why) = validateSemantics(att);
  check(ok, why);
}

void v131() {
  final o = occ('press_button');
  final att = attitude(believerId(), 'intends', o['id'] as String);
  var (ok, why) = validateSchema(att);
  check(ok, why);
  (ok, why) = validateSemantics(att);
  check(ok, why);
}

void v132() {
  final (st, _) = stateFixture('boolean', {'boolean': true});
  final inner =
      attitude(believerId('holder_b'), 'believes', st['id'] as String);
  final outer =
      attitude(believerId('holder_a'), 'believes', inner['id'] as String);
  for (final att in [inner, outer]) {
    var (ok, why) = validateSchema(att);
    check(ok, why);
    (ok, why) = validateSemantics(att);
    check(ok, why);
  }
  check(outer['id'] != inner['id'], 'distinct ids');
  check(outer['content'] == inner['id'], 'nested content');
}

void v133() {
  final o = occ('rainfall_begins');
  final bad = mk({
    'type': 'attitude', 'holder': believerId(),
    'attitude_type': 'suspects', 'content': o['id'],
  });
  final (ok, why) = validateSchema(bad, 'attitude');
  check(!ok && why.any((w) => w.contains('attitude_type')),
      'attitude_type is a closed enumeration: ${why.join('; ')}');
}

void v134() {
  final o = occ('rainfall_begins');
  final bad = mk({
    'type': 'attitude', 'holder': believerId(),
    'attitude_type': 'believes', 'content': o['id'], 'strength': 0.9,
  });
  final (ok, why) = validateSchema(bad, 'attitude');
  check(!ok && why.any((w) => w.contains('strength')),
      'an attitude carries no strength: ${why.join('; ')}');
}

void v135() {
  final o = occ('rainfall_begins');
  final att = attitude(believerId(), 'expects', o['id'] as String);
  final a = signed('assertion', {
    'about': att['id'], 'evidence_type': 'observation', 'confidence': 0.9,
  }, 'signer');
  final (ok, why) = validateSchema(a);
  check(ok, why);
  check(verifyRecord(a), 'the assertion verifies');
  // the HOLDER (a modeled agent) and the SOURCE (a signing key) differ
  check((att['holder'] as String).split(':').first == 'token_individual',
      'the holder is a modeled agent');
  check((a['source'] as String).split(':').first == 'ed25519',
      'the source is a signing key');
  check(att['holder'] != a['source'], 'the holder and the source differ');
}

void v136() {
  // the V111 wall-clock Causal Relation Object, re-pinned under 4.0.0
  final secs = <String, dynamic>{
    'type': 'causal_relation_object', 'causes': [sym('occurrent:a')],
    'effects': [sym('occurrent:b')], 'modality': 'sufficient',
    'temporal': temporal(0, 1, 'seconds'),
  };
  check(
      identify(secs) ==
          'causal_relation_object:'
              'd8daf899daa3ee03caa6b1425cc6d4d33cef20d951e1203ffd35df29857aa43c',
      'the wall-clock CRO identity holds under 4.0.0');
  // the V118 unbound conduit, re-pinned under 4.0.0
  final unbound = conduitRealized();
  check(
      unbound['id'] ==
          'conduit:'
              'dc4af3b1a24f0560d5ebcee488779f06ab3c78301cfb9d0c7edff80bc62e27a6',
      'the unbound conduit identity holds under 4.0.0');
}

void v137() {
  final hexid = '0' * 64;
  // NOTE: the abbreviated prefixes are intentional (the negative test); they
  // must NOT be re-minted. Each is assembled to survive re-mint tools.
  final attAbbr = 'a' 't' 't';
  final prdAbbr = 'p' 'r' 'd';
  final errAbbr = 'e' 'r' 'r';
  final badAtt = <String, dynamic>{
    'type': 'attitude', 'id': '$attAbbr:$hexid',
    'holder': 'token_individual:$hexid', 'attitude_type': 'believes',
    'content': 'state_assertion:$hexid',
  };
  var (ok, _) = validateSchema(badAtt, 'attitude');
  check(!ok, 'the abbreviated attitude scheme must be rejected');
  final badPrd = <String, dynamic>{
    'type': 'predicted_occurrence', 'id': '$prdAbbr:$hexid',
    'instantiates': 'occurrent:$hexid', 'interval': tickInterval(0),
    'predictor': 'token_individual:$hexid',
  };
  (ok, _) = validateSchema(badPrd, 'predicted_occurrence');
  check(!ok, 'the abbreviated predicted_occurrence scheme must be rejected');
  final badErr = <String, dynamic>{
    'type': 'prediction_error', 'id': '$errAbbr:$hexid',
    'predicted': 'predicted_occurrence:$hexid', 'discrepancy': 0.0,
  };
  (ok, _) = validateSchema(badErr, 'prediction_error');
  check(!ok, 'the abbreviated prediction_error scheme must be rejected');
  final wholeAtt = Map<String, dynamic>.from(badAtt)
    ..['id'] = 'attitude:$hexid';
  var (ok2, why2) = validateSchema(wholeAtt, 'attitude');
  check(ok2, 'the whole-word attitude validates: ${why2.join('; ')}');
  final wholePrd = Map<String, dynamic>.from(badPrd)
    ..['id'] = 'predicted_occurrence:$hexid';
  (ok2, why2) = validateSchema(wholePrd, 'predicted_occurrence');
  check(ok2,
      'the whole-word predicted_occurrence validates: ${why2.join('; ')}');
  final wholeErr = Map<String, dynamic>.from(badErr)
    ..['id'] = 'prediction_error:$hexid';
  (ok2, why2) = validateSchema(wholeErr, 'prediction_error');
  check(ok2, 'the whole-word prediction_error validates: ${why2.join('; ')}');
}

// ---------------------------------------------------------------------------

void main() {
  print('causalontology-dart conformance run (specification 4.0.0)');
  stdout.write(
      'internal checks (RFC 8032, RFC 8785, fixed constants) ... ');
  internalChecks();
  print('ok');
  final vectors = <void Function()>[
    v01, v02, v03, v04, v05, v06, v07, v08, v09, v10,
    v11, v12, v13, v14, v15, v16, v17, v18, v19, v20,
    v21, v22, v23, v24, v25, v26, v27, v28, v29, v30,
    v31, v32, v33, v34, v35, v36, v37, v38, v39, v40,
    v41, v42, v43, v44, v45, v46, v47, v48, v49, v50,
    v51, v52, v53, v54, v55, v56, v57, v58, v59, v60,
    v61, v62, v63, v64, v65, v66, v67, v68, v69, v70,
    v71, v72, v73, v74, v75, v76, v77, v78, v79, v80,
    v81, v82, v83, v84, v85, v86, v87, v88, v89, v90,
    v91, v92, v93, v94, v95, v96, v97, v98, v99, v100,
    v101, v102, v103, v104, v105, v106, v107, v108, v109, v110,
    v111, v112, v113, v114, v115, v116, v117, v118, v119, v120,
    v121, v122, v123, v124, v125, v126, v127, v128, v129, v130,
    v131, v132, v133, v134, v135, v136, v137,
  ];
  const total = 137;
  var failures = 0;
  for (var n = 1; n <= total; n++) {
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
  print('-' * 60);
  print('${total - failures}/$total vectors passed');
  if (failures > 0) {
    exit(1);
  }
  print('causalontology-dart is CONFORMANT to the suite '
      '(vectors frozen at specification 4.0.0).');
}

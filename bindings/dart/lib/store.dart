/// An in-memory conformant store.
///
/// Implements the store side of the abstract operation set (spec/store.md):
/// immutable content objects with idempotent put; signed, add-only
/// provenance records; materialized enrichment views with contributors;
/// retraction handling in default views; succession lineage; the resolve
/// minimum; the deterministic cycle-breaking view rule; and the stigmergy
/// gap read.
///
/// Dart's default Map literal is a LinkedHashMap, so `objects` and
/// `records` iterate in insertion order - deliberately mirroring the
/// iteration order of the Python reference (dicts preserve insertion
/// order), which the resolve and view orderings depend on.
library;

import 'canonical.dart';
import 'jcs.dart';
import 'schema.dart';
import 'semantics.dart';
import 'signing.dart';

const Set<String> contentKinds = {'occurrent', 'causal_relation_object', 'continuant', 'realizable'};
const Set<String> recordKinds = {'assertion', 'enrichment', 'retraction', 'succession'};

/// An enforcing store refused a write, with the reason as [message].
class RejectedWrite implements Exception {
  final String message;
  RejectedWrite(this.message);
  @override
  String toString() => message;
}

class InMemoryStore {
  final bool enforcing;
  final Map<String, Map<String, dynamic>> objects = {}; // id -> content object
  final Map<String, Map<String, dynamic>> records = {}; // id -> provenance record
  final Map<String, Map<String, dynamic>> quarantine = {}; // unverifiable records

  InMemoryStore([this.enforcing = true]);

  // ---------------------------------------------------------------- put
  /// Write a content object; idempotent; returns the identifier.
  String put(Map<String, dynamic> obj, [String? kind]) {
    final k = kind ?? inferKind(obj);
    if (!contentKinds.contains(k)) {
      throw ArgumentError('put() takes content objects; use putRecord()');
    }
    final copy = Map<String, dynamic>.from(obj);
    copy.putIfAbsent('type', () => k);
    if (!copy.containsKey('id')) {
      copy['id'] = identify(copy, k);
    }
    final id = copy['id'] as String;
    if (objects.containsKey(id)) {
      return id; // immutable: identical identity is a no-op
    }
    final (schemaOk, schemaWhy) = validateSchema(copy, k);
    if (!schemaOk) {
      throw RejectedWrite(schemaWhy.join('; '));
    }
    final (semOk, semWhy) = validateSemantics(copy, k);
    if (!semOk) {
      throw RejectedWrite(semWhy.join('; '));
    }
    objects[id] = copy;
    return id;
  }

  /// Write a signed provenance record; returns the identifier.
  String putRecord(Map<String, dynamic> record,
      [String? kind, bool force = false]) {
    final k = kind ?? inferKind(record);
    if (!recordKinds.contains(k)) {
      throw ArgumentError('putRecord() takes provenance records');
    }
    final copy = Map<String, dynamic>.from(record);
    copy.putIfAbsent('type', () => k);
    final rid = (copy['id'] as String?) ?? identify(copy, k);
    copy['id'] = rid;
    if (records.containsKey(rid)) {
      return rid; // add-only and idempotent
    }
    if (!verifyRecord(copy, k)) {
      quarantine[rid] = copy;
      throw RejectedWrite('unsigned or unverifiable record: quarantined');
    }
    final (semOk, semWhy) = validateSemantics(copy, k);
    if (!semOk) {
      throw RejectedWrite(semWhy.join('; '));
    }
    if (k == 'retraction' && !_retractionSourceOk(copy)) {
      throw RejectedWrite(
          "a retraction is valid only from the retracted record's "
          'source or its succession lineage');
    }
    if (k == 'enrichment' && enforcing && !force) {
      final field = copy['field'] as String;
      if ((field == 'subsumes' || field == 'part_of') && _wouldCycle(copy)) {
        throw RejectedWrite(
            'would create a cycle in the materialized $field graph');
      }
    }
    records[rid] = copy;
    return rid;
  }

  /// Simulate a decentralized replica merge (no enforcement gate).
  String forceMergeRecord(Map<String, dynamic> record, [String? kind]) {
    return putRecord(record, kind, true);
  }

  // ----------------------------------------------------- record queries
  List<Map<String, dynamic>> _recordsOf(String kind) {
    return records.values.where((r) => r['type'] == kind).toList();
  }

  Set<String> _retractedIds() {
    final out = <String>{};
    for (final r in _recordsOf('retraction')) {
      out.add(r['retracts'] as String);
    }
    return out;
  }

  bool _retractionSourceOk(Map<String, dynamic> retraction) {
    final target = records[retraction['retracts'] as String];
    if (target == null) {
      return true; // open world: the target may arrive later
    }
    return lineage(target['source'] as String)
        .contains(retraction['source'] as String);
  }

  /// The succession chain closure containing key (includes key).
  Set<String> lineage(String key) {
    final succ = <String, String>{};
    final pred = <String, String>{};
    for (final s in _recordsOf('succession')) {
      succ[s['predecessor'] as String] = s['successor'] as String;
      pred[s['successor'] as String] = s['predecessor'] as String;
    }
    final chain = <String>{key};
    var cursor = key;
    while (pred.containsKey(cursor)) {
      cursor = pred[cursor]!;
      chain.add(cursor);
    }
    cursor = key;
    while (succ.containsKey(cursor)) {
      cursor = succ[cursor]!;
      chain.add(cursor);
    }
    return chain;
  }

  List<Map<String, dynamic>> assertionsAbout(String identifier,
      [bool includeRetracted = false]) {
    final retracted = _retractedIds();
    final out = <Map<String, dynamic>>[];
    for (final r in _recordsOf('assertion')) {
      if (r['about'] != identifier) continue;
      if (retracted.contains(r['id'])) {
        if (includeRetracted) {
          out.add(Map<String, dynamic>.from(r)..['retracted'] = true);
        }
        continue;
      }
      out.add(r);
    }
    return out;
  }

  List<Map<String, dynamic>> enrichmentsAbout(String identifier,
      [bool includeRetracted = false]) {
    final retracted = _retractedIds();
    final out = <Map<String, dynamic>>[];
    for (final r in _recordsOf('enrichment')) {
      if (r['about'] != identifier) continue;
      if (retracted.contains(r['id']) && !includeRetracted) continue;
      out.add(r);
    }
    return out;
  }

  // ------------------------------------------------- materialized views
  /// (active, excluded) for subsumes/part_of after rule 13 cycle-breaking.
  (List<Map<String, dynamic>>, List<Map<String, dynamic>>)
      activeTaxonomyEdges(String field) {
    final retracted = _retractedIds();
    final recs = _recordsOf('enrichment')
        .where((r) => r['field'] == field && !retracted.contains(r['id']))
        .toList();
    final active = List<Map<String, dynamic>>.from(recs);
    final excluded = <Map<String, dynamic>>[];
    while (true) {
      final cyc = _findCycleRecords(active);
      if (cyc.isEmpty) break;
      // Exclude the cycle-completing record with the LATEST timestamp,
      // ties broken by lexicographic record identifier (deterministic).
      var loser = cyc.first;
      for (final r in cyc.skip(1)) {
        final cmp = (r['timestamp'] as String)
            .compareTo(loser['timestamp'] as String);
        if (cmp > 0 ||
            (cmp == 0 &&
                (r['id'] as String).compareTo(loser['id'] as String) > 0)) {
          loser = r;
        }
      }
      active.remove(loser);
      excluded.add(loser);
    }
    return (active, excluded);
  }

  static List<Map<String, dynamic>> _findCycleRecords(
      List<Map<String, dynamic>> recs) {
    final edges = <String, List<(String, Map<String, dynamic>)>>{};
    for (final r in recs) {
      edges
          .putIfAbsent(r['about'] as String, () => [])
          .add((r['entry'] as String, r));
    }
    final state = <String, int>{};
    final cycle = <Map<String, dynamic>>[];

    bool dfs(String node, List<Map<String, dynamic>> pathRecords) {
      state[node] = 1;
      for (final (nxt, rec)
          in edges[node] ?? const <(String, Map<String, dynamic>)>[]) {
        if ((state[nxt] ?? 0) == 1) {
          cycle
            ..addAll(pathRecords)
            ..add(rec);
          return true;
        }
        if ((state[nxt] ?? 0) == 0) {
          if (dfs(nxt, [...pathRecords, rec])) return true;
        }
      }
      state[node] = 2;
      return false;
    }

    for (final start in edges.keys.toList()) {
      if ((state[start] ?? 0) == 0 && dfs(start, [])) {
        return cycle;
      }
    }
    return [];
  }

  bool _wouldCycle(Map<String, dynamic> record) {
    final retracted = _retractedIds();
    final recs = _recordsOf('enrichment')
        .where((r) =>
            r['field'] == record['field'] && !retracted.contains(r['id']))
        .toList();
    return _findCycleRecords([...recs, record]).isNotEmpty;
  }

  /// The object with its materialized enrichment sets and contributors.
  Map<String, dynamic>? get(String identifier, [String view = 'default']) {
    final obj = objects[identifier];
    if (obj == null) return null;
    final includeRetracted = view == 'history';
    final excludedIds = <String>{};
    for (final field in ['subsumes', 'part_of']) {
      final (_, excluded) = activeTaxonomyEdges(field);
      excludedIds.addAll(excluded.map((r) => r['id'] as String));
    }
    // field -> canonical entry key -> {"entry": ..., "contributors": [...]}
    final fields = <String, Map<String, Map<String, dynamic>>>{};
    for (final rec in enrichmentsAbout(identifier, includeRetracted)) {
      if (excludedIds.contains(rec['id']) && view != 'history') continue;
      // Canonical-entry dedup: the RFC 8785 form of the entry (sorted keys)
      // plays the role of Python's sorted-items tuple.
      final entryKey = jcs(rec['entry']);
      final slot = fields.putIfAbsent(rec['field'] as String, () => {});
      final bucket = slot.putIfAbsent(entryKey,
          () => {'entry': rec['entry'], 'contributors': <Map<String, dynamic>>[]});
      (bucket['contributors'] as List).add({
        'source': rec['source'],
        'timestamp': rec['timestamp'],
      });
    }
    final enrichments = <String, List<Map<String, dynamic>>>{
      for (final e in fields.entries) e.key: e.value.values.toList(),
    };
    if (view == 'raw') {
      return {'object': obj};
    }
    return {'object': obj, 'enrichments': enrichments};
  }

  // ------------------------------------------------------------ resolve
  static String _canonLabel(String text) {
    final words = text
        .trim()
        .toLowerCase()
        .split(RegExp(r'\s+'))
        .where((w) => w.isNotEmpty);
    return words.join('_');
  }

  static String _normAlias(String text) {
    final words =
        text.split(RegExp(r'\s+')).where((w) => w.isNotEmpty);
    return words.join(' ').toLowerCase();
  }

  /// The conformance minimum: exact label, then alias, then nothing.
  List<String> resolve(String text, [String? lang]) {
    final labelHits = <String>[];
    final aliasHits = <String>[];
    final wantedLabel = _canonLabel(text);
    final wantedAlias = _normAlias(text);
    final retracted = _retractedIds();
    for (final entry in objects.entries) {
      final oid = entry.key;
      final obj = entry.value;
      if (obj['type'] != 'occurrent' && obj['type'] != 'continuant') continue;
      if (obj['label'] == wantedLabel) {
        labelHits.add(oid);
        continue;
      }
      for (final rec in _recordsOf('enrichment')) {
        if (rec['about'] != oid || rec['field'] != 'aliases') continue;
        if (retracted.contains(rec['id'])) continue;
        final e = rec['entry'] as Map;
        if (lang != null && e['lang'] != lang) continue;
        if (_normAlias((e['text'] as String?) ?? '') == wantedAlias) {
          aliasHits.add(oid);
          break;
        }
      }
    }
    return [...labelHits, ...aliasHits];
  }

  // --------------------------------------------------------------- gaps
  /// The stigmergy read. Gap kinds per spec/store.md.
  List<Map<String, dynamic>> gaps([String? kind]) {
    var out = <Map<String, dynamic>>[];
    final refined = <String>{};
    for (final obj in objects.values) {
      final refines = obj['refines'];
      if (obj['type'] == 'causal_relation_object' && refines is String && refines.isNotEmpty) {
        final parent = objects[refines];
        if (parent != null) {
          final (ok, _) = refinementValid(obj, parent);
          if (ok) {
            refined.add(parent['id'] as String);
          }
        }
      }
    }
    for (final entry in objects.entries) {
      final oid = entry.key;
      final obj = entry.value;
      if (obj['type'] != 'causal_relation_object') continue;
      // missing_field: lacking the temporal window or the modality -
      // mechanism and context may legitimately stay unspecified forever
      // (empty_mechanism is its own kind; absent context = context-free).
      if ((!obj.containsKey('temporal') || !obj.containsKey('modality')) &&
          !refined.contains(oid)) {
        out.add({'id': oid, 'kind': 'missing_field', 'missing': isPartial(obj).$2});
      }
      final mech = obj['mechanism'];
      if (!obj.containsKey('mechanism') || (mech is List && mech.isEmpty)) {
        if (!refined.contains(oid)) {
          out.add({'id': oid, 'kind': 'empty_mechanism'});
        }
      }
    }
    for (final field in ['subsumes', 'part_of']) {
      final (_, excluded) = activeTaxonomyEdges(field);
      for (final rec in excluded) {
        out.add({
          'id': rec['id'],
          'kind': 'inconsistent_hierarchy',
          'note': 'excluded by the deterministic cycle-breaking view rule',
        });
      }
    }
    // dangling_reference: a reference to an object absent from the store -
    // the red link that says "this page is wanted".
    for (final entry in objects.entries) {
      final oid = entry.key;
      final obj = entry.value;
      var refs = <String?>[];
      if (obj['type'] == 'causal_relation_object') {
        refs = [
          ...((obj['causes'] as List?) ?? const []).cast<String>(),
          ...((obj['effects'] as List?) ?? const []).cast<String>(),
          ...((obj['context'] as List?) ?? const []).cast<String>(),
          ...((obj['mechanism'] as List?) ?? const []).cast<String>(),
        ];
        final refines = obj['refines'];
        if (refines is String && refines.isNotEmpty) {
          refs.add(refines);
        }
      } else if (obj['type'] == 'realizable') {
        refs = [obj['bearer'] as String?];
      }
      for (final ref in refs) {
        if (ref != null && ref.isNotEmpty && !objects.containsKey(ref)) {
          out.add({'id': oid, 'kind': 'dangling_reference', 'ref': ref});
        }
      }
    }
    // conflict: pairs of claims satisfying the formal test (rule 6).
    final cros = objects.values.where((o) => o['type'] == 'causal_relation_object').toList();
    for (var i = 0; i < cros.length; i++) {
      for (var j = i + 1; j < cros.length; j++) {
        if (conflicts(cros[i], cros[j])) {
          out.add({'kind': 'conflict', 'a': cros[i]['id'], 'b': cros[j]['id']});
        }
      }
    }
    if (kind != null) {
      out = out.where((g) => g['kind'] == kind).toList();
    }
    return out;
  }
}

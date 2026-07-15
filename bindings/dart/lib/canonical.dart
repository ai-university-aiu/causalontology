/// Canonicalization and content-addressed identity.
///
/// Implements the identity procedure of spec/identity.md:
///   1. take the object as JSON,
///   2. keep only the identity-bearing fields for its kind (with "type"
///      injected),
///   3. serialize with the JSON Canonicalization Scheme (RFC 8785),
///   4. hash with SHA-256,
///   5. identifier = scheme + ":" + lowercase hex digest.
library;

import 'dart:convert';

import 'jcs.dart';
import 'sha2.dart';

const Map<String, List<String>> identityFields = {
  'occurrent': ['label', 'category'],
  'causal_relation_object': [
    'causes', 'effects', 'mechanism', 'temporal', 'modality',
    'context', 'refines',
  ],
  'continuant': ['label', 'category'],
  'realizable': ['kind', 'bearer'],
  'assertion': [
    'about', 'source', 'evidence_type', 'evidence', 'strength',
    'confidence', 'timestamp',
  ],
  'enrichment': ['about', 'field', 'entry', 'source', 'timestamp'],
  'retraction': ['retracts', 'source', 'timestamp'],
  'succession': ['predecessor', 'successor', 'timestamp'],
};

const Map<String, String> prefixOfKind = {
  'occurrent': 'occurrent', 'causal_relation_object': 'causal_relation_object', 'continuant': 'continuant', 'realizable': 'realizable',
  'assertion': 'assertion', 'enrichment': 'enrichment', 'retraction': 'retraction',
  'succession': 'succession',
};

final Map<String, String> kindOfPrefix = {
  for (final e in prefixOfKind.entries) e.value: e.key,
};

/// Lowercase hex of a byte list.
String hexEncode(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

/// Bytes of an even-length lowercase/uppercase hex string, or null.
List<int>? hexDecode(String s) {
  if (s.length.isOdd || !RegExp(r'^[0-9a-fA-F]*$').hasMatch(s)) return null;
  final out = <int>[];
  for (var i = 0; i < s.length; i += 2) {
    out.add(int.parse(s.substring(i, i + 2), radix: 16));
  }
  return out;
}

/// Infer an object's kind from its type field, id prefix, or shape.
String inferKind(Map<String, dynamic> obj) {
  if (obj.containsKey('type')) {
    return obj['type'] as String;
  }
  final id = obj['id'];
  if (id is String && id.contains(':')) {
    final pre = id.split(':').first;
    if (kindOfPrefix.containsKey(pre)) {
      return kindOfPrefix[pre]!;
    }
  }
  if (obj.containsKey('causes') && obj.containsKey('effects')) return 'causal_relation_object';
  if (obj.containsKey('retracts')) return 'retraction';
  if (obj.containsKey('predecessor') && obj.containsKey('successor')) {
    return 'succession';
  }
  if (obj.containsKey('field') && obj.containsKey('entry')) return 'enrichment';
  if (obj.containsKey('evidence_type') ||
      (obj.containsKey('about') && obj.containsKey('confidence'))) {
    return 'assertion';
  }
  if (obj.containsKey('kind') && obj.containsKey('bearer')) return 'realizable';
  throw ArgumentError(
      'cannot infer kind (occurrents and continuants share a shape); '
      'pass kind explicitly');
}

/// The identity-bearing subset of an object, with type always present.
(String, Map<String, dynamic>) identityBearing(Map<String, dynamic> obj,
    [String? kind]) {
  final k = kind ?? inferKind(obj);
  if (!identityFields.containsKey(k)) {
    throw ArgumentError('unknown kind: $k');
  }
  final out = <String, dynamic>{'type': k};
  for (final field in identityFields[k]!) {
    if (obj.containsKey(field)) {
      out[field] = obj[field];
    }
  }
  return (k, out);
}

/// The RFC 8785 identity-bearing bytes of an object.
List<int> canonicalize(Map<String, dynamic> obj, [String? kind]) {
  final (_, ib) = identityBearing(obj, kind);
  return utf8.encode(jcs(ib));
}

/// The content-addressed identifier: scheme + ':' + SHA-256 hex.
String identify(Map<String, dynamic> obj, [String? kind]) {
  final (k, ib) = identityBearing(obj, kind);
  final digest = sha256(utf8.encode(jcs(ib)));
  return '${prefixOfKind[k]!}:${hexEncode(digest)}';
}

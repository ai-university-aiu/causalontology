/// Schema validation against spec/schema/*.schema.json.
///
/// A deliberately small interpreter for exactly the JSON Schema keywords the
/// seventeen Causalontology schemas use: type, const, enum, pattern, required,
/// properties, additionalProperties, items, minItems, minLength, minimum,
/// maximum, oneOf, local $ref (#/$defs/...), and cross-file $ref to a sibling
/// schema (https://causalontology.org/schema/<file>.schema.json#/...).
/// "format" is treated as an annotation, as the 2020-12 draft does by default.
library;

import 'dart:convert';
import 'dart:io';

import 'canonical.dart';

/// kind -> schema file. Three token kinds keep their original 1.0.0-reserved
/// file names (individual/token/state); the id scheme is the whole word.
const Map<String, String> schemaFiles = {
  'occurrent': 'occurrent.schema.json',
  'causal_relation_object': 'causal_relation_object.schema.json',
  'continuant': 'continuant.schema.json',
  'realizable': 'realizable.schema.json',
  'stratum': 'stratum.schema.json',
  'bridge': 'bridge.schema.json',
  'port': 'port.schema.json',
  'conduit': 'conduit.schema.json',
  'quality': 'quality.schema.json',
  'token_individual': 'individual.schema.json',
  'token_occurrence': 'token.schema.json',
  'state_assertion': 'state.schema.json',
  'token_causal_claim': 'token_causal_claim.schema.json',
  'assertion': 'assertion.schema.json',
  'enrichment': 'enrichment.schema.json',
  'retraction': 'retraction.schema.json',
  'succession': 'succession.schema.json',
};

const String _base = 'https://causalontology.org/schema/';

/// Cache keyed by schema-file name (cross-file $ref shares this cache).
final Map<String, Map<String, dynamic>> _cache = {};

/// Locate the repository's spec/schema directory: the CAUSALONTOLOGY_SPEC
/// environment variable (naming the spec/ directory) wins; otherwise walk
/// up from this library's own location, then from the working directory,
/// until a spec/schema directory is found.
Directory schemaDir() {
  final env = Platform.environment['CAUSALONTOLOGY_SPEC'];
  if (env != null && env.isNotEmpty) {
    return Directory('$env${Platform.pathSeparator}schema');
  }
  final starts = <Directory>[
    File.fromUri(Platform.script).parent,
    Directory.current,
  ];
  for (final start in starts) {
    var dir = start.absolute;
    while (true) {
      final candidate = Directory(
          '${dir.path}${Platform.pathSeparator}spec${Platform.pathSeparator}schema');
      if (candidate.existsSync()) return candidate;
      final parent = dir.parent;
      if (parent.path == dir.path) break;
      dir = parent;
    }
  }
  throw StateError('cannot locate spec/schema; set CAUSALONTOLOGY_SPEC');
}

Map<String, dynamic> _loadFile(String filename) {
  return _cache.putIfAbsent(filename, () {
    final path = '${schemaDir().path}${Platform.pathSeparator}$filename';
    return jsonDecode(File(path).readAsStringSync()) as Map<String, dynamic>;
  });
}

Map<String, dynamic> loadSchema(String kind) {
  if (!schemaFiles.containsKey(kind)) {
    throw ArgumentError('unknown kind: $kind');
  }
  return _loadFile(schemaFiles[kind]!);
}

Map<String, dynamic> _navigate(Map<String, dynamic> doc, String pointer) {
  dynamic node = doc;
  for (final part in pointer.split('/')) {
    if (part.isEmpty) continue;
    node = (node as Map)[part];
  }
  return (node as Map).cast<String, dynamic>();
}

/// Resolve local and cross-file $refs to a concrete schema node + its root.
(Map<String, dynamic>, Map<String, dynamic>) _resolve(
    Map<String, dynamic> schema, Map<String, dynamic> root) {
  var node = schema;
  var r = root;
  while (node.containsKey(r'$ref')) {
    final ref = node[r'$ref'] as String;
    if (ref.startsWith('#/')) {
      node = _navigate(r, ref.substring(2));
    } else if (ref.startsWith(_base)) {
      final rest = ref.substring(_base.length);
      final hashIdx = rest.indexOf('#/');
      final filename = hashIdx < 0 ? rest : rest.substring(0, hashIdx);
      final pointer = hashIdx < 0 ? '' : rest.substring(hashIdx + 2);
      r = _loadFile(filename);
      node = pointer.isEmpty ? r : _navigate(r, pointer);
    } else {
      throw ArgumentError('unsupported \$ref: $ref');
    }
  }
  return (node, r);
}

/// Deep structural equality over the JSON model (maps, lists, scalars).
bool deepEquals(Object? a, Object? b) {
  if (a is Map && b is Map) {
    if (a.length != b.length) return false;
    for (final key in a.keys) {
      if (!b.containsKey(key) || !deepEquals(a[key], b[key])) return false;
    }
    return true;
  }
  if (a is List && b is List) {
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (!deepEquals(a[i], b[i])) return false;
    }
    return true;
  }
  if (a is num && b is num && a is! bool && b is! bool) {
    return a == b; // 1 == 1.0 holds in Dart, matching Python's ==
  }
  return a == b;
}

bool _typeMatches(Object? value, String t) {
  switch (t) {
    case 'object':
      return value is Map;
    case 'array':
      return value is List;
    case 'string':
      return value is String;
    case 'number':
      return value is num && value is! bool;
    case 'integer':
      return value is int;
    case 'boolean':
      return value is bool;
    default:
      throw ArgumentError('unknown schema type: $t');
  }
}

void _check(Object? value, Map<String, dynamic> schemaNode,
    Map<String, dynamic> rootIn, String path, List<String> errors) {
  final (schema, root) = _resolve(schemaNode, rootIn);

  if (schema.containsKey('oneOf')) {
    var passing = 0;
    for (final sub in schema['oneOf'] as List) {
      final suberrs = <String>[];
      _check(value, (sub as Map).cast<String, dynamic>(), root, path, suberrs);
      if (suberrs.isEmpty) passing++;
    }
    if (passing != 1) {
      errors.add('$path: matches $passing of the oneOf branches '
          '(need exactly 1)');
    }
    return;
  }

  final t = schema['type'] as String?;
  if (t != null) {
    if (!_typeMatches(value, t)) {
      errors.add('$path: expected $t');
      return;
    }
  }

  if (schema.containsKey('const') && !deepEquals(value, schema['const'])) {
    errors.add('$path: must equal ${schema['const']}');
  }
  if (schema.containsKey('enum') &&
      !(schema['enum'] as List).any((e) => deepEquals(value, e))) {
    errors.add('$path: $value not in enumeration');
  }
  if (schema.containsKey('pattern') && value is String) {
    if (!RegExp(schema['pattern'] as String).hasMatch(value)) {
      errors.add("$path: '$value' does not match ${schema['pattern']}");
    }
  }
  if (schema.containsKey('minLength') && value is String) {
    if (value.length < (schema['minLength'] as num)) {
      errors.add('$path: shorter than minLength');
    }
  }
  if (schema.containsKey('minimum') && value is num && value is! bool) {
    if (value < (schema['minimum'] as num)) {
      errors.add('$path: below minimum ${schema['minimum']}');
    }
  }
  if (schema.containsKey('maximum') && value is num && value is! bool) {
    if (value > (schema['maximum'] as num)) {
      errors.add('$path: above maximum ${schema['maximum']}');
    }
  }

  if (value is List) {
    if (schema.containsKey('minItems') &&
        value.length < (schema['minItems'] as num)) {
      errors.add('$path: fewer than ${schema['minItems']} items');
    }
    if (schema.containsKey('items')) {
      for (var i = 0; i < value.length; i++) {
        _check(value[i], (schema['items'] as Map).cast<String, dynamic>(),
            root, '$path[$i]', errors);
      }
    }
  }

  if (value is Map) {
    final props = (schema['properties'] as Map?)?.cast<String, dynamic>() ??
        <String, dynamic>{};
    for (final req in (schema['required'] as List?) ?? const []) {
      if (!value.containsKey(req)) {
        errors.add("$path: required property '$req' missing");
      }
    }
    if (schema['additionalProperties'] == false) {
      for (final key in value.keys) {
        if (!props.containsKey(key)) {
          errors.add("$path: additional property '$key'");
        }
      }
    }
    for (final entry in props.entries) {
      if (value.containsKey(entry.key)) {
        _check(value[entry.key], (entry.value as Map).cast<String, dynamic>(),
            root, '$path.${entry.key}', errors);
      }
    }
  }
}

/// (ok, reasons) - structural validity against the kind's JSON Schema.
(bool, List<String>) validateSchema(Map<String, dynamic> obj, [String? kind]) {
  final k = kind ?? inferKind(obj);
  final root = loadSchema(k);
  final errors = <String>[];
  _check(obj, root, root, r'$', errors);
  return (errors.isEmpty, errors);
}

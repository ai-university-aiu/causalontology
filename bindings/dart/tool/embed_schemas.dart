/// Regenerates lib/spec_schema.g.dart from spec/schema/*.schema.json.
///
/// Dart offers no reliable runtime path to a package's own data files once
/// the program is compiled, so the twenty-one schemas are embedded as source
/// constants - the same choice the Rust binding makes with include_str!.
/// Run from bindings/dart: dart run tool/embed_schemas.dart
library;

import 'dart:convert';
import 'dart:io';

String quote(String s) => s
    .replaceAll(r'\', r'\\')
    .replaceAll(r'$', r'\$')
    .replaceAll("'", r"\'")
    .replaceAll('\n', r'\n');

void main() {
  final specDir = Directory('../../spec/schema');
  if (!specDir.existsSync()) {
    stderr.writeln('cannot find ../../spec/schema; run from bindings/dart');
    exit(1);
  }
  final files = specDir
      .listSync()
      .whereType<File>()
      .where((f) => f.path.endsWith('.schema.json'))
      .toList()
    ..sort((a, b) => a.path.compareTo(b.path));

  if (files.length != 21) {
    stderr.writeln('expected 21 schemas, found ${files.length}');
    exit(1);
  }

  final buf = StringBuffer()
    ..writeln('// GENERATED FILE - DO NOT EDIT BY HAND.')
    ..writeln('//')
    ..writeln('// The twenty-one whole-word schemas of spec/schema, embedded at compile')
    ..writeln('// time so the published pub.dev package validates standalone - no')
    ..writeln('// repository checkout and no CAUSALONTOLOGY_SPEC needed. This mirrors the')
    ..writeln("// Rust binding's include_str! vendoring. Dart offers no reliable runtime")
    ..writeln("// path to a package's own data files once compiled, so embedding is the")
    ..writeln('// only form that survives AOT.')
    ..writeln('//')
    ..writeln('// Regenerate with: dart run tool/embed_schemas.dart  (from bindings/dart)')
    ..writeln('library;')
    ..writeln()
    ..writeln('const Map<String, String> embeddedSchemas = {');

  for (final f in files) {
    final text = f.readAsStringSync();
    jsonDecode(text); // fail loudly on malformed input
    final name = f.uri.pathSegments.last;
    buf
      ..writeln("  '$name':")
      ..writeln("      '${quote(text)}',");
  }
  buf.writeln('};');

  File('lib/spec_schema.g.dart').writeAsStringSync(buf.toString());
  stdout.writeln('embedded ${files.length} schemas into lib/spec_schema.g.dart');
}

/// RFC 8785 (JSON Canonicalization Scheme) serialization.
///
/// Operates on the plain Dart JSON model produced by `dart:convert`'s
/// `jsonDecode` on the Dart VM, which is lossless for Causalontology's
/// purposes: `1` decodes to `int`, `1.0` decodes to `double`, and object
/// key order is preserved (`Map` literals and decoded maps are
/// `LinkedHashMap`s).
///
/// The number serialization implements the RFC 8785 rules for the value
/// ranges Causalontology uses (integers, integer-valued floats, and short
/// decimals); full ECMAScript exponent formatting for extreme magnitudes is
/// pinned at the 1.0.0 conformance freeze.
library;

const Map<String, String> _escapes = {
  '"': '\\"',
  '\\': '\\\\',
  '\b': '\\b',
  '\t': '\\t',
  '\n': '\\n',
  '\f': '\\f',
  '\r': '\\r',
};

/// The RFC 8785 serialization of a JSON string.
String jcsString(String s) {
  final parts = StringBuffer('"');
  for (final unit in s.codeUnits) {
    final ch = String.fromCharCode(unit);
    if (_escapes.containsKey(ch)) {
      parts.write(_escapes[ch]);
    } else if (unit < 0x20) {
      parts.write('\\u${unit.toRadixString(16).padLeft(4, '0')}');
    } else {
      parts.writeCharCode(unit);
    }
  }
  parts.write('"');
  return parts.toString();
}

/// The RFC 8785 serialization of a JSON number (int or double).
String jcsNumber(num n) {
  if (n is int) {
    return n.toString();
  }
  final d = n.toDouble();
  if (!d.isFinite) {
    throw ArgumentError('NaN and Infinity are not permitted (RFC 8785)');
  }
  if (d == 0) {
    return '0';
  }
  if (d == d.truncateToDouble() && d.abs() < 1e21) {
    // Integer-valued doubles below 1e21 serialize as integers; BigInt keeps
    // exactness beyond the signed-64-bit range (e.g. 1e20).
    return BigInt.from(d).toString();
  }
  // Dart's double.toString is the shortest round-trip decimal and already
  // matches the ES6 exponent shapes for our range ("0.7", "1e-7", "1e+21");
  // normalize defensively anyway (strip leading zeros, force the sign).
  var r = d.toString();
  final eIndex = r.indexOf('e');
  if (eIndex >= 0) {
    final mant = r.substring(0, eIndex);
    var exp = r.substring(eIndex + 1);
    final sign = exp.startsWith('-') ? '-' : '+';
    exp = exp.replaceFirst(RegExp(r'^[+-]?0*'), '');
    if (exp.isEmpty) exp = '0';
    r = '${mant}e$sign$exp';
  }
  return r;
}

/// The RFC 8785 serialization of any JSON value.
String jcs(Object? value) {
  if (value == null) {
    return 'null';
  }
  if (value is bool) {
    return value ? 'true' : 'false';
  }
  if (value is num) {
    return jcsNumber(value);
  }
  if (value is String) {
    return jcsString(value);
  }
  if (value is List) {
    return '[${value.map(jcs).join(',')}]';
  }
  if (value is Map) {
    // RFC 8785 sorts member names by UTF-16 code units, which is exactly
    // Dart's String.compareTo ordering.
    final keys = value.keys.cast<String>().toList()..sort();
    return '{${keys.map((k) => '${jcsString(k)}:${jcs(value[k])}').join(',')}}';
  }
  throw ArgumentError('cannot canonicalize ${value.runtimeType}');
}

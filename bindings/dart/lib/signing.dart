/// Record-level signing and verification (spec/provenance.md).
///
/// The signature is computed over the record's canonical identity-bearing
/// bytes (the RFC 8785 form with id and signature removed - exactly the
/// bytes that are hashed for the record's identifier), so verification needs
/// nothing but the record itself. Ed25519 is deterministic (RFC 8032):
/// re-signing the same record with the same key yields the same signature,
/// so re-submission is idempotent.
library;

import 'canonical.dart';
import 'ed25519.dart' as ed25519;

/// (secret, 'ed25519:hex-public') from a 32-byte seed.
(List<int>, String) keypairFromSeed(List<int> seed32) {
  final public = ed25519.secretToPublic(seed32);
  return (seed32, 'ed25519:${hexEncode(public)}');
}

/// Return the record completed with its id and Ed25519 signature.
Map<String, dynamic> signRecord(Map<String, dynamic> record, List<int> secret,
    [String? kind]) {
  final k = kind ?? inferKind(record);
  final body = Map<String, dynamic>.from(record)..remove('signature');
  final message = canonicalize(body, k);
  final signature = hexEncode(ed25519.sign(secret, message));
  final out = Map<String, dynamic>.from(body);
  out['id'] = identify(body, k);
  out['signature'] = signature;
  return out;
}

String? _signerKeyHex(Map<String, dynamic> record, String kind) {
  // A succession is signed by the predecessor key; everything else by source.
  final field = kind == 'succession' ? 'predecessor' : 'source';
  final value = record[field];
  if (value is! String || !value.startsWith('ed25519:')) return null;
  return value.substring('ed25519:'.length);
}

/// True iff the record's signature verifies against its own key field.
bool verifyRecord(Map<String, dynamic> record, [String? kind]) {
  final k = kind ?? inferKind(record);
  final sigHex = record['signature'];
  final keyHex = _signerKeyHex(record, k);
  if (sigHex is! String || sigHex.isEmpty || keyHex == null) return false;
  final public = hexDecode(keyHex);
  final signature = hexDecode(sigHex);
  if (public == null || signature == null) return false;
  final body = Map<String, dynamic>.from(record)..remove('signature');
  final message = canonicalize(body, k);
  return ed25519.verify(public, message, signature);
}

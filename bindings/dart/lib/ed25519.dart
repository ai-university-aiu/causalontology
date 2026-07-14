/// Ed25519 digital signatures (RFC 8032), pure Dart, zero dependencies.
///
/// Slow but correct: intended for the conformance suite and for small tools.
/// Production stores should use an optimized library; the signatures are
/// byte-compatible either way (Ed25519 is deterministic, RFC 8032).
///
/// All field arithmetic runs over BigInt. Dart's BigInt `%` is Euclidean
/// (the result is always non-negative for a positive modulus), which is
/// exactly the normalization the reference Python code relies on.
library;

import 'dart:typed_data';

import 'sha2.dart';

final BigInt _p = (BigInt.one << 255) - BigInt.from(19);
final BigInt _q =
    (BigInt.one << 252) + BigInt.parse('27742317777372353535851937790883648493');

BigInt _modpInv(BigInt x) => x.modPow(_p - BigInt.two, _p);

final BigInt _d = (BigInt.from(-121665) * _modpInv(BigInt.from(121666))) % _p;
final BigInt _modpSqrtM1 =
    BigInt.two.modPow((_p - BigInt.one) ~/ BigInt.from(4), _p);

/// An extended-coordinates point (X, Y, Z, T).
class _Point {
  final BigInt x, y, z, t;
  const _Point(this.x, this.y, this.z, this.t);
}

_Point _pointAdd(_Point p, _Point q) {
  final a = ((p.y - p.x) * (q.y - q.x)) % _p;
  final b = ((p.y + p.x) * (q.y + q.x)) % _p;
  final c = (BigInt.two * p.t * q.t * _d) % _p;
  final d = (BigInt.two * p.z * q.z) % _p;
  final e = b - a, f = d - c, g = d + c, h = b + a;
  return _Point((e * f) % _p, (g * h) % _p, (f * g) % _p, (e * h) % _p);
}

_Point _pointMul(BigInt s, _Point p) {
  var q = _Point(BigInt.zero, BigInt.one, BigInt.one, BigInt.zero); // neutral
  var base = p;
  var k = s;
  while (k > BigInt.zero) {
    if (k.isOdd) {
      q = _pointAdd(q, base);
    }
    base = _pointAdd(base, base);
    k >>= 1;
  }
  return q;
}

bool _pointEqual(_Point p, _Point q) {
  if ((p.x * q.z - q.x * p.z) % _p != BigInt.zero) return false;
  if ((p.y * q.z - q.y * p.z) % _p != BigInt.zero) return false;
  return true;
}

BigInt? _recoverX(BigInt y, int sign) {
  if (y >= _p) return null;
  final x2 = ((y * y - BigInt.one) * _modpInv(_d * y * y + BigInt.one)) % _p;
  if (x2 == BigInt.zero) {
    return sign != 0 ? null : BigInt.zero;
  }
  var x = x2.modPow((_p + BigInt.from(3)) ~/ BigInt.from(8), _p);
  if ((x * x - x2) % _p != BigInt.zero) {
    x = (x * _modpSqrtM1) % _p;
  }
  if ((x * x - x2) % _p != BigInt.zero) {
    return null;
  }
  if ((x & BigInt.one).toInt() != sign) {
    x = _p - x;
  }
  return x;
}

final BigInt _gy = (BigInt.from(4) * _modpInv(BigInt.from(5))) % _p;
final BigInt _gx = _recoverX(_gy, 0)!;
final _Point _g = _Point(_gx, _gy, BigInt.one, (_gx * _gy) % _p);

Uint8List _toBytesLE(BigInt n, int length) {
  final out = Uint8List(length);
  var v = n;
  final mask = BigInt.from(0xff);
  for (var i = 0; i < length; i++) {
    out[i] = (v & mask).toInt();
    v >>= 8;
  }
  return out;
}

BigInt _fromBytesLE(List<int> bytes) {
  var v = BigInt.zero;
  for (var i = bytes.length - 1; i >= 0; i--) {
    v = (v << 8) | BigInt.from(bytes[i]);
  }
  return v;
}

Uint8List _pointCompress(_Point p) {
  final zinv = _modpInv(p.z);
  final x = (p.x * zinv) % _p;
  final y = (p.y * zinv) % _p;
  return _toBytesLE(y | ((x & BigInt.one) << 255), 32);
}

_Point? _pointDecompress(List<int> s) {
  if (s.length != 32) return null;
  var y = _fromBytesLE(s);
  final sign = (y >> 255).toInt();
  y &= (BigInt.one << 255) - BigInt.one;
  final x = _recoverX(y, sign);
  if (x == null) return null;
  return _Point(x, y, BigInt.one, (x * y) % _p);
}

/// (clamped scalar, prefix) from a 32-byte secret key.
(BigInt, Uint8List) _secretExpand(List<int> secret) {
  if (secret.length != 32) {
    throw ArgumentError('secret key must be 32 bytes');
  }
  final h = sha512(secret);
  var a = _fromBytesLE(h.sublist(0, 32));
  a &= (BigInt.one << 254) - BigInt.from(8);
  a |= BigInt.one << 254;
  return (a, Uint8List.fromList(h.sublist(32)));
}

BigInt _sha512ModQ(List<int> s) => _fromBytesLE(sha512(s)) % _q;

/// The 32-byte public key for a 32-byte secret key.
Uint8List secretToPublic(List<int> secret) {
  final (a, _) = _secretExpand(secret);
  return _pointCompress(_pointMul(a, _g));
}

/// The 64-byte Ed25519 signature of msg under the 32-byte secret key.
Uint8List sign(List<int> secret, List<int> msg) {
  final (a, prefix) = _secretExpand(secret);
  final aBytes = _pointCompress(_pointMul(a, _g));
  final r = _sha512ModQ([...prefix, ...msg]);
  final rs = _pointCompress(_pointMul(r, _g));
  final h = _sha512ModQ([...rs, ...aBytes, ...msg]);
  final s = (r + h * a) % _q;
  return Uint8List.fromList([...rs, ..._toBytesLE(s, 32)]);
}

/// True iff signature is a valid Ed25519 signature of msg under public.
bool verify(List<int> public, List<int> msg, List<int> signature) {
  if (public.length != 32 || signature.length != 64) return false;
  final aPoint = _pointDecompress(public);
  if (aPoint == null) return false;
  final rs = signature.sublist(0, 32);
  final rPoint = _pointDecompress(rs);
  if (rPoint == null) return false;
  final s = _fromBytesLE(signature.sublist(32));
  if (s >= _q) return false;
  final h = _sha512ModQ([...rs, ...public, ...msg]);
  final sB = _pointMul(s, _g);
  final hA = _pointMul(h, aPoint);
  return _pointEqual(sB, _pointAdd(rPoint, hA));
}

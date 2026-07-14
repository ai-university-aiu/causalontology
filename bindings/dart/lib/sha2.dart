/// Pure-Dart SHA-256 and SHA-512 (FIPS 180-4). Zero dependencies.
///
/// SHA-256 works in 32-bit words masked into Dart's 64-bit ints; SHA-512
/// works directly in Dart's 64-bit two's-complement ints, whose wrapping
/// addition and shifts (`>>>` for logical right shift) give the unsigned
/// 64-bit arithmetic the algorithm needs on the Dart VM.
///
/// Both are gated by known-answer tests in the conformance runner
/// (empty-string digests; RFC 8032 TEST 1 exercises SHA-512 further).
library;

import 'dart:typed_data';

// ---------------------------------------------------------------------- 256

const List<int> _k256 = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const int _m32 = 0xFFFFFFFF;

int _rotr32(int x, int n) => ((x >>> n) | (x << (32 - n))) & _m32;

/// The 32-byte SHA-256 digest of a byte message.
Uint8List sha256(List<int> message) {
  final padded = _pad(message, 64, 8);
  final h = <int>[
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ];
  final w = List<int>.filled(64, 0);
  for (var block = 0; block < padded.length; block += 64) {
    for (var t = 0; t < 16; t++) {
      final o = block + t * 4;
      w[t] = (padded[o] << 24) |
          (padded[o + 1] << 16) |
          (padded[o + 2] << 8) |
          padded[o + 3];
    }
    for (var t = 16; t < 64; t++) {
      final s0 = _rotr32(w[t - 15], 7) ^ _rotr32(w[t - 15], 18) ^ (w[t - 15] >>> 3);
      final s1 = _rotr32(w[t - 2], 17) ^ _rotr32(w[t - 2], 19) ^ (w[t - 2] >>> 10);
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) & _m32;
    }
    var a = h[0], b = h[1], c = h[2], d = h[3];
    var e = h[4], f = h[5], g = h[6], hh = h[7];
    for (var t = 0; t < 64; t++) {
      final s1 = _rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25);
      final ch = (e & f) ^ ((~e & _m32) & g);
      final t1 = (hh + s1 + ch + _k256[t] + w[t]) & _m32;
      final s0 = _rotr32(a, 2) ^ _rotr32(a, 13) ^ _rotr32(a, 22);
      final maj = (a & b) ^ (a & c) ^ (b & c);
      final t2 = (s0 + maj) & _m32;
      hh = g; g = f; f = e; e = (d + t1) & _m32;
      d = c; c = b; b = a; a = (t1 + t2) & _m32;
    }
    h[0] = (h[0] + a) & _m32; h[1] = (h[1] + b) & _m32;
    h[2] = (h[2] + c) & _m32; h[3] = (h[3] + d) & _m32;
    h[4] = (h[4] + e) & _m32; h[5] = (h[5] + f) & _m32;
    h[6] = (h[6] + g) & _m32; h[7] = (h[7] + hh) & _m32;
  }
  final out = Uint8List(32);
  for (var i = 0; i < 8; i++) {
    out[i * 4] = (h[i] >>> 24) & 0xff;
    out[i * 4 + 1] = (h[i] >>> 16) & 0xff;
    out[i * 4 + 2] = (h[i] >>> 8) & 0xff;
    out[i * 4 + 3] = h[i] & 0xff;
  }
  return out;
}

// ---------------------------------------------------------------------- 512

const List<int> _k512 = [
  0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
  0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
  0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
  0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
  0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
  0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
  0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
  0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
  0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
  0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
  0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
  0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
  0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
  0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
  0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
  0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
  0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
  0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
  0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
  0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

int _rotr64(int x, int n) => (x >>> n) | (x << (64 - n));

/// The 64-byte SHA-512 digest of a byte message.
Uint8List sha512(List<int> message) {
  final padded = _pad(message, 128, 16);
  final h = <int>[
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
  ];
  final w = List<int>.filled(80, 0);
  for (var block = 0; block < padded.length; block += 128) {
    for (var t = 0; t < 16; t++) {
      final o = block + t * 8;
      var word = 0;
      for (var b = 0; b < 8; b++) {
        word = (word << 8) | padded[o + b];
      }
      w[t] = word;
    }
    for (var t = 16; t < 80; t++) {
      final s0 = _rotr64(w[t - 15], 1) ^ _rotr64(w[t - 15], 8) ^ (w[t - 15] >>> 7);
      final s1 = _rotr64(w[t - 2], 19) ^ _rotr64(w[t - 2], 61) ^ (w[t - 2] >>> 6);
      w[t] = w[t - 16] + s0 + w[t - 7] + s1;
    }
    var a = h[0], b = h[1], c = h[2], d = h[3];
    var e = h[4], f = h[5], g = h[6], hh = h[7];
    for (var t = 0; t < 80; t++) {
      final s1 = _rotr64(e, 14) ^ _rotr64(e, 18) ^ _rotr64(e, 41);
      final ch = (e & f) ^ (~e & g);
      final t1 = hh + s1 + ch + _k512[t] + w[t];
      final s0 = _rotr64(a, 28) ^ _rotr64(a, 34) ^ _rotr64(a, 39);
      final maj = (a & b) ^ (a & c) ^ (b & c);
      final t2 = s0 + maj;
      hh = g; g = f; f = e; e = d + t1;
      d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  }
  final out = Uint8List(64);
  for (var i = 0; i < 8; i++) {
    for (var b = 0; b < 8; b++) {
      out[i * 8 + b] = (h[i] >>> (56 - 8 * b)) & 0xff;
    }
  }
  return out;
}

/// Merkle-Damgard padding: 0x80, zeros, then the bit length big-endian in
/// the final `lengthBytes` bytes (8 for SHA-256, 16 for SHA-512; message
/// sizes here never overflow 64 bits, so the upper length bytes stay zero).
Uint8List _pad(List<int> message, int blockSize, int lengthBytes) {
  final bitLength = message.length * 8;
  var padLength = blockSize - ((message.length + 1 + lengthBytes) % blockSize);
  if (padLength == blockSize) padLength = 0;
  final total = message.length + 1 + padLength + lengthBytes;
  final out = Uint8List(total);
  out.setRange(0, message.length, message);
  out[message.length] = 0x80;
  for (var i = 0; i < 8; i++) {
    out[total - 1 - i] = (bitLength >>> (8 * i)) & 0xff;
  }
  return out;
}

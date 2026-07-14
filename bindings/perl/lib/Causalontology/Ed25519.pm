# Causalontology::Ed25519 - Ed25519 digital signatures (RFC 8032),
# pure Perl over Math::BigInt (a core module), standard library only.
#
# A faithful port of bindings/python/causalontology/ed25519.py. Slow but
# correct: intended for the conformance suite and for small tools.
# Production stores should use an optimized library; the signatures are
# byte-compatible either way (Ed25519 is deterministic, RFC 8032).
#
# Two Perl-specific notes, verified up front:
#   - Math::BigInt's % / bmod return a NON-NEGATIVE result for a positive
#     modulus (checked with a negative operand), matching Python's %.
#   - a fixed-base doubling table for the base point G roughly halves the
#     dominant cost (most scalar multiplications here are by G).

package Causalontology::Ed25519;

use strict;
use warnings;
use Exporter 'import';
use Math::BigInt;
use Digest::SHA qw(sha512);

our @EXPORT_OK = qw(secret_to_public sign verify);

# the field prime p = 2^255 - 19
my $p = Math::BigInt->new(2)->bpow(255)->bsub(19);
# the group order q = 2^252 + 27742317777372353535851937790883648493
my $q = Math::BigInt->new(2)->bpow(252)
    ->badd(Math::BigInt->new('27742317777372353535851937790883648493'));

my $ZERO = Math::BigInt->new(0);
my $ONE  = Math::BigInt->new(1);
my $TWO  = Math::BigInt->new(2);

# fixed exponents, precomputed once (NOTE: bdiv in list context returns
# (quotient, remainder), so exact powers of two use brsft instead)
my $EXP_INV  = $p->copy->bsub(2);            # p - 2, for Fermat inversion
my $EXP_SQRT = $p->copy->bsub(1)->brsft(2);  # (p - 1) / 4
my $EXP_X    = $p->copy->badd(3)->brsft(3);  # (p + 3) / 8

# modular inverse by Fermat: x^(p-2) mod p
sub _modp_inv {
    my ($x) = @_;
    return $x->copy->bmodpow($EXP_INV, $p);
}

# the twisted Edwards curve constant d = -121665 / 121666 mod p
my $d = (Math::BigInt->new(-121665) * _modp_inv(Math::BigInt->new(121666))) % $p;
# sqrt(-1) mod p, used by point decompression
my $modp_sqrt_m1 = $TWO->copy->bmodpow($EXP_SQRT, $p);

# extended homogeneous point addition (RFC 8032 section 5.1.4)
sub _point_add {
    my ($P, $Q) = @_;
    my $A = (($P->[1] - $P->[0]) * ($Q->[1] - $Q->[0])) % $p;
    my $B = (($P->[1] + $P->[0]) * ($Q->[1] + $Q->[0])) % $p;
    my $C = ($TWO * $P->[3] * $Q->[3] * $d) % $p;
    my $D = ($TWO * $P->[2] * $Q->[2]) % $p;
    my ($E, $F, $G, $H) = ($B - $A, $D - $C, $D + $C, $B + $A);
    return [($E * $F) % $p, ($G * $H) % $p, ($F * $G) % $p, ($E * $H) % $p];
}

# the neutral element of the group
sub _neutral { return [$ZERO->copy, $ONE->copy, $ONE->copy, $ZERO->copy] }

# double-and-add scalar multiplication of an arbitrary point
sub _point_mul {
    my ($s, $P) = @_;
    my $Q = _neutral();
    # walk the scalar's bits from least significant to most significant
    my $bits = reverse substr($s->as_bin, 2);
    for my $i (0 .. length($bits) - 1) {
        $Q = _point_add($Q, $P) if substr($bits, $i, 1) eq '1';
        $P = _point_add($P, $P);
    }
    return $Q;
}

# projective equality: cross-multiply to avoid inversions
sub _point_equal {
    my ($P, $Q) = @_;
    return 0 if (($P->[0] * $Q->[2] - $Q->[0] * $P->[2]) % $p)->is_zero == 0;
    return 0 if (($P->[1] * $Q->[2] - $Q->[1] * $P->[2]) % $p)->is_zero == 0;
    return 1;
}

# recover the x coordinate from y and the sign bit (RFC 8032 section 5.1.3)
sub _recover_x {
    my ($y, $sign) = @_;
    return undef if $y >= $p;
    my $x2 = (($y * $y - $ONE) * _modp_inv(($d * $y * $y + $ONE) % $p)) % $p;
    if ($x2->is_zero) {
        return $sign ? undef : $ZERO->copy;
    }
    my $x = $x2->copy->bmodpow($EXP_X, $p);
    if ((($x * $x - $x2) % $p)->is_zero == 0) {
        $x = ($x * $modp_sqrt_m1) % $p;
    }
    return undef if (($x * $x - $x2) % $p)->is_zero == 0;
    $x = $p - $x if ($x->copy->band($ONE)->numify) != $sign;
    return $x;
}

# the base point G of the group
my $g_y = (Math::BigInt->new(4) * _modp_inv(Math::BigInt->new(5))) % $p;
my $g_x = _recover_x($g_y, 0);
my $G = [$g_x, $g_y, $ONE->copy, ($g_x * $g_y) % $p];

# a fixed-base table: $G_POW[i] holds 2^i * G, filled once
my @G_POW;
{
    my $P = $G;
    for my $i (0 .. 255) {
        $G_POW[$i] = $P;
        $P = _point_add($P, $P);
    }
}

# scalar multiplication of the base point using the doubling table
sub _point_mul_base {
    my ($s) = @_;
    my $Q = _neutral();
    my $bits = reverse substr($s->as_bin, 2);
    for my $i (0 .. length($bits) - 1) {
        $Q = _point_add($Q, $G_POW[$i]) if substr($bits, $i, 1) eq '1';
    }
    return $Q;
}

# compress a point to its 32-byte little-endian wire form
sub _point_compress {
    my ($P) = @_;
    my $zinv = _modp_inv($P->[2]);
    my $x = ($P->[0] * $zinv) % $p;
    my $y = ($P->[1] * $zinv) % $p;
    my $n = $y->copy->bior(($x->copy->band($ONE))->blsft(255));
    return _int_to_le32($n);
}

# decompress 32 little-endian bytes back to a point (undef when invalid)
sub _point_decompress {
    my ($s) = @_;
    return undef if length($s) != 32;
    my $y = _le_to_int($s);
    my $sign = $y->copy->brsft(255)->numify;
    $y = $y->copy->band($TWO->copy->bpow(255)->bsub(1));
    my $x = _recover_x($y, $sign);
    return undef unless defined $x;
    return [$x, $y, $ONE->copy, ($x * $y) % $p];
}

# little-endian bytes -> Math::BigInt
sub _le_to_int {
    my ($bytes) = @_;
    my $hex = unpack 'H*', scalar reverse $bytes;
    return Math::BigInt->from_hex($hex);
}

# Math::BigInt -> exactly 32 little-endian bytes
sub _int_to_le32 {
    my ($n) = @_;
    my $hex = substr($n->as_hex, 2);
    $hex = ('0' x (64 - length $hex)) . $hex;
    return scalar reverse pack 'H*', $hex;
}

# clamp the secret scalar and return (a, prefix) per RFC 8032
sub _secret_expand {
    my ($secret) = @_;
    die "secret key must be 32 bytes\n" if length($secret) != 32;
    my $h = sha512($secret);
    my $a = _le_to_int(substr $h, 0, 32);
    $a = $a->band($TWO->copy->bpow(254)->bsub(8));
    $a = $a->bior($TWO->copy->bpow(254));
    return ($a, substr $h, 32);
}

# SHA-512 of a byte string, reduced mod the group order
sub _sha512_modq {
    my ($s) = @_;
    return _le_to_int(sha512($s)) % $q;
}

# cache of secret -> [clamped scalar a, prefix, compressed public A]
my %EXPANDED;

sub _expand_cached {
    my ($secret) = @_;
    my $k = unpack 'H*', $secret;
    unless (exists $EXPANDED{$k}) {
        my ($a, $prefix) = _secret_expand($secret);
        my $A = _point_compress(_point_mul_base($a));
        $EXPANDED{$k} = [$a, $prefix, $A];
    }
    return @{ $EXPANDED{$k} };
}

# The 32-byte public key for a 32-byte secret key.
sub secret_to_public {
    my ($secret) = @_;
    my (undef, undef, $A) = _expand_cached($secret);
    return $A;
}

# The 64-byte Ed25519 signature of msg under the 32-byte secret key.
sub sign {
    my ($secret, $msg) = @_;
    my ($a, $prefix, $A) = _expand_cached($secret);
    my $r = _sha512_modq($prefix . $msg);
    my $Rs = _point_compress(_point_mul_base($r));
    my $h = _sha512_modq($Rs . $A . $msg);
    my $s = ($r + $h * $a) % $q;
    return $Rs . _int_to_le32($s);
}

# True iff signature is a valid Ed25519 signature of msg under public.
sub verify {
    my ($public, $msg, $signature) = @_;
    return 0 if length($public) != 32 || length($signature) != 64;
    my $A = _point_decompress($public);
    return 0 unless defined $A;
    my $Rs = substr $signature, 0, 32;
    my $R = _point_decompress($Rs);
    return 0 unless defined $R;
    my $s = _le_to_int(substr $signature, 32);
    return 0 if $s >= $q;
    my $h = _sha512_modq($Rs . $public . $msg);
    my $sB = _point_mul_base($s);
    my $hA = _point_mul($h, $A);
    return _point_equal($sB, _point_add($R, $hA));
}

1;

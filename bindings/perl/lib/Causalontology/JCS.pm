# Causalontology::JCS - RFC 8785 (JSON Canonicalization Scheme) serialization.
#
# Mirrors bindings/python/causalontology/canonical.py's _jcs exactly:
# keys sorted with byte order (equal to UTF-16 code-unit order for the
# ASCII keys the standard uses), minimal string escapes with lowercase
# \u%04x for the remaining controls, and ECMAScript-style numbers
# (integer literals verbatim; integral floats below 1e21 as integers;
# 0.7 stays "0.7"; exponents normalized to e-7 / e+NN form).

package Causalontology::JCS;

use strict;
use warnings;
use Exporter 'import';
use Causalontology::JSON qw(okeys oget aitems);

our @EXPORT_OK = qw(jcs jcs_string jcs_number);

my %ESCAPES = (
    '"'  => '\\"',
    "\\" => '\\\\',
    "\b" => '\\b',
    "\t" => '\\t',
    "\n" => '\\n',
    "\f" => '\\f',
    "\r" => '\\r',
);

sub jcs_string {
    my ($s) = @_;
    my $out = '"';
    for my $ch (split //, $s) {
        if (exists $ESCAPES{$ch}) {
            $out .= $ESCAPES{$ch};
        }
        elsif (ord($ch) < 0x20) {
            $out .= sprintf '\\u%04x', ord $ch;
        }
        else {
            $out .= $ch;  # bytes >= 0x20 pass through untouched
        }
    }
    return $out . '"';
}

sub jcs_number {
    my ($lit) = @_;
    # an integer literal (no '.', 'e', or 'E') is already canonical JSON
    return $lit if $lit !~ /[.eE]/;
    my $f = 0 + $lit;
    return '0' if $f == 0;
    # an integral float below 1e21 prints as an integer (RFC 8785 / ES6)
    if ($f == int($f) && abs($f) < 1e21) {
        return sprintf '%.0f', $f;
    }
    # shortest round-trip decimal, exactly what Python's repr() produces
    my $r;
    for my $precision (1 .. 17) {
        my $candidate = sprintf '%.*g', $precision, $f;
        if (0 + $candidate == $f) { $r = $candidate; last }
    }
    # normalize the exponent: 1e-07 -> 1e-7, keep e+NN as ES6 does
    if ($r =~ /^(.*)e(.*)$/i) {
        my ($mant, $exp) = ($1, $2);
        my $sign = ($exp =~ /^-/) ? '-' : '+';
        (my $digits = $exp) =~ s/^[+-]//;
        $digits =~ s/^0+//;
        $digits = '0' if $digits eq '';
        $r = $mant . 'e' . $sign . $digits;
    }
    return $r;
}

sub jcs {
    my ($value) = @_;
    die "cannot canonicalize an undefined value\n" unless defined $value;
    my $t = $value->[0];
    return 'null'                            if $t eq 'null';
    return ($value->[1] ? 'true' : 'false')  if $t eq 'bool';
    return jcs_number($value->[1])           if $t eq 'num';
    return jcs_string($value->[1])           if $t eq 'str';
    if ($t eq 'arr') {
        return '[' . join(',', map { jcs($_) } aitems($value)) . ']';
    }
    if ($t eq 'obj') {
        # sort with cmp: byte order == UTF-16 code-unit order for ASCII keys
        my @sorted = sort { $a cmp $b } okeys($value);
        return '{' . join(',', map {
            jcs_string($_) . ':' . jcs(oget($value, $_))
        } @sorted) . '}';
    }
    die "cannot canonicalize a value tagged '$t'\n";
}

1;

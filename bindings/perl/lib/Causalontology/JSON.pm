# Causalontology::JSON - a lossless JSON layer for the Perl binding.
#
# Perl's stock JSON modules erase the two distinctions the canonicalizer
# needs: the integer-versus-decimal source shape of a number (1 versus 1.0)
# and the insertion order of object keys (Perl hashes are unordered). This
# tiny parser therefore tags every value:
#
#   string  ->  ['str', $bytes]
#   number  ->  ['num', $literal]         (the source literal, verbatim)
#   boolean ->  ['bool', 0|1]
#   null    ->  ['null']
#   array   ->  ['arr', [ @values ]]
#   object  ->  ['obj', [ @keys ], { key => value }]   (keys keep order)
#
# Input is treated as raw bytes; strings are byte strings (UTF-8 encoded
# where non-ASCII), which is exactly what RFC 8785 hashing needs.

package Causalontology::JSON;

use strict;
use warnings;
use Exporter 'import';

our @EXPORT_OK = qw(
    decode_json jstr jnum jbool jnull jarr jobj
    is_str is_num is_bool is_null is_arr is_obj
    sval nval bval aitems okeys ohas oget oset odel oclone jeq tag
);

# ---------------------------------------------------------------- builders
sub jstr  { return ['str',  $_[0]] }
sub jnum  { return ['num',  $_[0]] }
sub jbool { return ['bool', $_[0] ? 1 : 0] }
sub jnull { return ['null'] }
sub jarr  { return ['arr',  [@_]] }

sub jobj {
    my @pairs = @_;
    my (@keys, %map);
    while (@pairs) {
        my $k = shift @pairs;
        my $v = shift @pairs;
        push @keys, $k unless exists $map{$k};
        $map{$k} = $v;
    }
    return ['obj', \@keys, \%map];
}

# ------------------------------------------------------------- inspectors
sub tag     { return $_[0][0] }
sub is_str  { return ref $_[0] eq 'ARRAY' && $_[0][0] eq 'str' }
sub is_num  { return ref $_[0] eq 'ARRAY' && $_[0][0] eq 'num' }
sub is_bool { return ref $_[0] eq 'ARRAY' && $_[0][0] eq 'bool' }
sub is_null { return ref $_[0] eq 'ARRAY' && $_[0][0] eq 'null' }
sub is_arr  { return ref $_[0] eq 'ARRAY' && $_[0][0] eq 'arr' }
sub is_obj  { return ref $_[0] eq 'ARRAY' && $_[0][0] eq 'obj' }

sub sval { return $_[0][1] }          # the byte string of a 'str'
sub nval { return 0 + $_[0][1] }      # the numeric value of a 'num'
sub bval { return $_[0][1] }          # the 0|1 of a 'bool'
sub aitems { return @{ $_[0][1] } }   # the values of an 'arr'

# ------------------------------------------------- ordered-object helpers
sub okeys { return @{ $_[0][1] } }

sub ohas { my ($o, $k) = @_; return exists $o->[2]{$k} }

sub oget { my ($o, $k) = @_; return $o->[2]{$k} }

sub oset {
    my ($o, $k, $v) = @_;
    push @{ $o->[1] }, $k unless exists $o->[2]{$k};
    $o->[2]{$k} = $v;
    return $o;
}

sub odel {
    my ($o, $k) = @_;
    return $o unless exists $o->[2]{$k};
    delete $o->[2]{$k};
    @{ $o->[1] } = grep { $_ ne $k } @{ $o->[1] };
    return $o;
}

# A shallow copy of an object (fresh key list and map, shared values),
# the equivalent of Python's dict(obj).
sub oclone {
    my ($o) = @_;
    return ['obj', [@{ $o->[1] }], { %{ $o->[2] } }];
}

# ------------------------------------------------------------ deep equality
# Structural equality with Python semantics: objects compare by key set and
# values (order-insensitive); numbers compare by canonical numeric form, so
# 1 == 1.0 exactly as in the reference binding.
sub jeq {
    my ($a, $b) = @_;
    return 0 if !defined $a || !defined $b;
    my ($ta, $tb) = ($a->[0], $b->[0]);
    return 0 unless $ta eq $tb;
    if ($ta eq 'str')  { return $a->[1] eq $b->[1] ? 1 : 0 }
    if ($ta eq 'num')  {
        require Causalontology::JCS;
        return Causalontology::JCS::jcs_number($a->[1])
            eq Causalontology::JCS::jcs_number($b->[1]) ? 1 : 0;
    }
    if ($ta eq 'bool') { return $a->[1] == $b->[1] ? 1 : 0 }
    if ($ta eq 'null') { return 1 }
    if ($ta eq 'arr') {
        my @xa = @{ $a->[1] };
        my @xb = @{ $b->[1] };
        return 0 unless @xa == @xb;
        for my $i (0 .. $#xa) {
            return 0 unless jeq($xa[$i], $xb[$i]);
        }
        return 1;
    }
    if ($ta eq 'obj') {
        my @ka = sort keys %{ $a->[2] };
        my @kb = sort keys %{ $b->[2] };
        return 0 unless @ka == @kb;
        for my $i (0 .. $#ka) {
            return 0 unless $ka[$i] eq $kb[$i];
            return 0 unless jeq($a->[2]{ $ka[$i] }, $b->[2]{ $kb[$i] });
        }
        return 1;
    }
    return 0;
}

# ----------------------------------------------------------------- parser
# A plain recursive-descent JSON parser over a byte string.
{
    my ($text, $pos, $len);

    sub decode_json {
        ($text, $pos) = ($_[0], 0);
        $len = length $text;
        my $value = _parse_value();
        _skip_ws();
        die "trailing garbage at byte $pos in JSON input\n" if $pos < $len;
        return $value;
    }

    sub _skip_ws {
        $pos++ while $pos < $len
            && index(" \t\n\r", substr($text, $pos, 1)) >= 0;
    }

    sub _parse_value {
        _skip_ws();
        die "unexpected end of JSON input\n" if $pos >= $len;
        my $c = substr($text, $pos, 1);
        return _parse_object() if $c eq '{';
        return _parse_array()  if $c eq '[';
        return _parse_string() if $c eq '"';
        if (substr($text, $pos, 4) eq 'true')  { $pos += 4; return jbool(1) }
        if (substr($text, $pos, 5) eq 'false') { $pos += 5; return jbool(0) }
        if (substr($text, $pos, 4) eq 'null')  { $pos += 4; return jnull() }
        return _parse_number();
    }

    sub _parse_object {
        $pos++;  # consume '{'
        my $obj = jobj();
        _skip_ws();
        if (substr($text, $pos, 1) eq '}') { $pos++; return $obj }
        while (1) {
            _skip_ws();
            die "expected object key at byte $pos\n"
                unless substr($text, $pos, 1) eq '"';
            my $key = sval(_parse_string());
            _skip_ws();
            die "expected ':' at byte $pos\n"
                unless substr($text, $pos, 1) eq ':';
            $pos++;
            oset($obj, $key, _parse_value());
            _skip_ws();
            my $c = substr($text, $pos, 1);
            if ($c eq ',') { $pos++; next }
            if ($c eq '}') { $pos++; return $obj }
            die "expected ',' or '}' at byte $pos\n";
        }
    }

    sub _parse_array {
        $pos++;  # consume '['
        my @items;
        _skip_ws();
        if (substr($text, $pos, 1) eq ']') { $pos++; return ['arr', \@items] }
        while (1) {
            push @items, _parse_value();
            _skip_ws();
            my $c = substr($text, $pos, 1);
            if ($c eq ',') { $pos++; next }
            if ($c eq ']') { $pos++; return ['arr', \@items] }
            die "expected ',' or ']' at byte $pos\n";
        }
    }

    sub _parse_string {
        $pos++;  # consume opening quote
        my $out = '';
        while (1) {
            die "unterminated string\n" if $pos >= $len;
            my $c = substr($text, $pos, 1);
            if ($c eq '"') { $pos++; return jstr($out) }
            if ($c eq "\\") {
                my $e = substr($text, $pos + 1, 1);
                $pos += 2;
                if    ($e eq '"')  { $out .= '"' }
                elsif ($e eq "\\") { $out .= "\\" }
                elsif ($e eq '/')  { $out .= '/' }
                elsif ($e eq 'b')  { $out .= "\b" }
                elsif ($e eq 'f')  { $out .= "\f" }
                elsif ($e eq 'n')  { $out .= "\n" }
                elsif ($e eq 'r')  { $out .= "\r" }
                elsif ($e eq 't')  { $out .= "\t" }
                elsif ($e eq 'u') {
                    my $hex = substr($text, $pos, 4);
                    $pos += 4;
                    my $cp = hex $hex;
                    # a UTF-16 surrogate pair encodes one supplementary char
                    if ($cp >= 0xD800 && $cp <= 0xDBFF
                            && substr($text, $pos, 2) eq "\\u") {
                        my $lo = hex substr($text, $pos + 2, 4);
                        $pos += 6;
                        $cp = 0x10000 + (($cp - 0xD800) << 10)
                                      + ($lo - 0xDC00);
                    }
                    $out .= _utf8_bytes($cp);
                }
                else { die "bad escape '\\$e' in string\n" }
                next;
            }
            $out .= $c;
            $pos++;
        }
    }

    sub _utf8_bytes {
        my ($cp) = @_;
        return chr $cp if $cp < 0x80;
        if ($cp < 0x800) {
            return chr(0xC0 | ($cp >> 6)) . chr(0x80 | ($cp & 0x3F));
        }
        if ($cp < 0x10000) {
            return chr(0xE0 | ($cp >> 12))
                 . chr(0x80 | (($cp >> 6) & 0x3F))
                 . chr(0x80 | ($cp & 0x3F));
        }
        return chr(0xF0 | ($cp >> 18))
             . chr(0x80 | (($cp >> 12) & 0x3F))
             . chr(0x80 | (($cp >> 6) & 0x3F))
             . chr(0x80 | ($cp & 0x3F));
    }

    sub _parse_number {
        if (substr($text, $pos) =~ /\A(-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/) {
            my $lit = $1;
            $pos += length $lit;
            return jnum($lit);  # the literal shape is preserved verbatim
        }
        die "invalid JSON number at byte $pos\n";
    }
}

1;

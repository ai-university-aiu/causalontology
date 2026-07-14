# Causalontology::Schema - validation against spec/schema/*.schema.json.
#
# A deliberately small interpreter for exactly the JSON Schema keywords the
# eight Causalontology schemas use: type, const, enum, pattern, required,
# properties, additionalProperties, items, minItems, minLength, minimum,
# maximum, oneOf, and local $ref (#/$defs/...). "format" is treated as an
# annotation, as the 2020-12 draft does by default. Mirrors
# bindings/python/causalontology/schema.py.

package Causalontology::Schema;

use strict;
use warnings;
use Exporter 'import';
use File::Basename qw(dirname);
use Cwd qw(abs_path);
use Causalontology::JSON qw(
    decode_json okeys ohas oget sval nval bval aitems jeq
    is_str is_num is_bool is_arr is_obj is_null
);

our @EXPORT_OK = qw(validate_schema load_schema);

my %SCHEMA_FILES = (
    cro        => 'cro.schema.json',
    occurrent  => 'occurrent.schema.json',
    continuant => 'continuant.schema.json',
    realizable => 'realizable.schema.json',
    assertion  => 'assertion.schema.json',
    enrichment => 'enrichment.schema.json',
    retraction => 'retraction.schema.json',
    succession => 'succession.schema.json',
);

my %CACHE;

# spec/schema under the repository root (or $CAUSALONTOLOGY_SPEC/schema)
sub _schema_dir {
    if ($ENV{CAUSALONTOLOGY_SPEC}) {
        return $ENV{CAUSALONTOLOGY_SPEC} . '/schema';
    }
    # this file lives at <root>/bindings/perl/lib/Causalontology/Schema.pm
    my $here = abs_path(__FILE__);
    my $root = dirname(dirname(dirname(dirname(dirname($here)))));
    return $root . '/spec/schema';
}

sub load_schema {
    my ($kind) = @_;
    die "unknown kind: '$kind'\n" unless exists $SCHEMA_FILES{$kind};
    unless (exists $CACHE{$kind}) {
        my $path = _schema_dir() . '/' . $SCHEMA_FILES{$kind};
        open my $fh, '<:raw', $path or die "cannot open $path: $!\n";
        local $/;
        my $raw = <$fh>;
        close $fh;
        $CACHE{$kind} = decode_json($raw);
    }
    return $CACHE{$kind};
}

# follow local $ref chains (#/$defs/...) within the same schema document
sub _resolve {
    my ($schema, $root) = @_;
    while (ohas($schema, '$ref')) {
        my $ref = sval(oget($schema, '$ref'));
        die "only local \$ref supported: '$ref'\n" unless $ref =~ /^#\//;
        my $node = $root;
        for my $part (split /\//, substr($ref, 2)) {
            $node = oget($node, $part);
        }
        $schema = $node;
    }
    return $schema;
}

# tag expected for each JSON Schema type name
my %TYPE_TAG = (
    object => 'obj', array => 'arr', string => 'str',
    number => 'num', boolean => 'bool',
);

sub _check {
    my ($value, $schema, $root, $path, $errors) = @_;
    $schema = _resolve($schema, $root);

    if (ohas($schema, 'oneOf')) {
        my $passing = 0;
        for my $sub (aitems(oget($schema, 'oneOf'))) {
            my @suberrs;
            _check($value, $sub, $root, $path, \@suberrs);
            $passing++ unless @suberrs;
        }
        if ($passing != 1) {
            push @$errors, "$path: matches $passing of the oneOf branches "
                         . "(need exactly 1)";
        }
        return;
    }

    if (ohas($schema, 'type')) {
        my $t = sval(oget($schema, 'type'));
        unless ($value->[0] eq $TYPE_TAG{$t}) {
            push @$errors, "$path: expected $t";
            return;
        }
    }

    if (ohas($schema, 'const')) {
        unless (jeq($value, oget($schema, 'const'))) {
            my $want = is_str(oget($schema, 'const'))
                ? "'" . sval(oget($schema, 'const')) . "'"
                : 'the const value';
            push @$errors, "$path: must equal $want";
        }
    }
    if (ohas($schema, 'enum')) {
        my $hit = 0;
        for my $candidate (aitems(oget($schema, 'enum'))) {
            if (jeq($value, $candidate)) { $hit = 1; last }
        }
        unless ($hit) {
            my $shown = is_str($value) ? "'" . sval($value) . "'" : 'value';
            push @$errors, "$path: $shown not in enumeration";
        }
    }
    if (ohas($schema, 'pattern') && is_str($value)) {
        my $pattern = sval(oget($schema, 'pattern'));
        unless (sval($value) =~ /$pattern/) {
            push @$errors, "$path: '" . sval($value)
                         . "' does not match $pattern";
        }
    }
    if (ohas($schema, 'minLength') && is_str($value)) {
        if (length(sval($value)) < nval(oget($schema, 'minLength'))) {
            push @$errors, "$path: shorter than minLength";
        }
    }
    if (ohas($schema, 'minimum') && is_num($value)) {
        if (nval($value) < nval(oget($schema, 'minimum'))) {
            push @$errors, "$path: below minimum "
                         . oget($schema, 'minimum')->[1];
        }
    }
    if (ohas($schema, 'maximum') && is_num($value)) {
        if (nval($value) > nval(oget($schema, 'maximum'))) {
            push @$errors, "$path: above maximum "
                         . oget($schema, 'maximum')->[1];
        }
    }

    if (is_arr($value)) {
        my @items = aitems($value);
        if (ohas($schema, 'minItems')
                && @items < nval(oget($schema, 'minItems'))) {
            push @$errors, "$path: fewer than "
                         . oget($schema, 'minItems')->[1] . ' items';
        }
        if (ohas($schema, 'items')) {
            my $i = 0;
            for my $item (@items) {
                _check($item, oget($schema, 'items'), $root,
                       $path . "[$i]", $errors);
                $i++;
            }
        }
    }

    if (is_obj($value)) {
        my $props = ohas($schema, 'properties')
            ? oget($schema, 'properties') : undef;
        if (ohas($schema, 'required')) {
            for my $req (aitems(oget($schema, 'required'))) {
                my $name = sval($req);
                unless (ohas($value, $name)) {
                    push @$errors,
                        "$path: required property '$name' missing";
                }
            }
        }
        if (ohas($schema, 'additionalProperties')
                && is_bool(oget($schema, 'additionalProperties'))
                && !bval(oget($schema, 'additionalProperties'))) {
            for my $key (okeys($value)) {
                unless ($props && ohas($props, $key)) {
                    push @$errors, "$path: additional property '$key'";
                }
            }
        }
        if ($props) {
            for my $key (okeys($props)) {
                if (ohas($value, $key)) {
                    _check(oget($value, $key), oget($props, $key), $root,
                           "$path.$key", $errors);
                }
            }
        }
    }
}

# (ok, reasons) - structural validity against the kind's JSON Schema.
sub validate_schema {
    my ($obj, $kind) = @_;
    require Causalontology::Canonical;
    $kind ||= Causalontology::Canonical::infer_kind($obj);
    my $root = load_schema($kind);
    my @errors;
    _check($obj, $root, $root, '$', \@errors);
    return ((@errors ? 0 : 1), \@errors);
}

1;

# Causalontology::Schema - validation against spec/schema/*.schema.json.
#
# A deliberately small interpreter for exactly the JSON Schema keywords the
# twenty-one Causalontology schemas use: type, const, enum, pattern, required,
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

# kind -> schema file. Three token kinds keep their original 1.0.0-reserved
# file names (individual/token/state); the id scheme is the whole word.
my %SCHEMA_FILES = (
    occurrent  => 'occurrent.schema.json',
    causal_relation_object => 'causal_relation_object.schema.json',
    continuant => 'continuant.schema.json',
    realizable => 'realizable.schema.json',
    stratum    => 'stratum.schema.json',
    bridge     => 'bridge.schema.json',
    cross_stratal_seam => 'cross_stratal_seam.schema.json',
    port       => 'port.schema.json',
    conduit    => 'conduit.schema.json',
    quality    => 'quality.schema.json',
    token_individual   => 'individual.schema.json',
    token_occurrence   => 'token.schema.json',
    state_assertion    => 'state.schema.json',
    token_causal_claim => 'token_causal_claim.schema.json',
    attitude             => 'attitude.schema.json',
    predicted_occurrence => 'predicted_occurrence.schema.json',
    prediction_error     => 'prediction_error.schema.json',
    assertion  => 'assertion.schema.json',
    enrichment => 'enrichment.schema.json',
    retraction => 'retraction.schema.json',
    succession => 'succession.schema.json',
);

my $BASE = 'https://causalontology.org/schema/';
my %CACHE;       # kind -> parsed schema
my %FILE_CACHE;  # filename -> parsed schema

# load a schema document by its file name (for cross-file $ref)
sub _load_file {
    my ($filename) = @_;
    unless (exists $FILE_CACHE{$filename}) {
        my $path = _schema_dir() . '/' . $filename;
        open my $fh, '<:raw', $path or die "cannot open $path: $!\n";
        local $/;
        my $raw = <$fh>;
        close $fh;
        $FILE_CACHE{$filename} = decode_json($raw);
    }
    return $FILE_CACHE{$filename};
}

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
    $CACHE{$kind} = _load_file($SCHEMA_FILES{$kind}) unless exists $CACHE{$kind};
    return $CACHE{$kind};
}

# navigate a JSON pointer (already stripped of a leading marker) within a doc
sub _navigate {
    my ($doc, $pointer) = @_;
    my $node = $doc;
    for my $part (split m{/}, $pointer) {
        next if $part eq '';
        $node = oget($node, $part);
    }
    return $node;
}

# follow local and cross-file $ref chains; returns the resolved (schema, root),
# swapping the root document when a cross-file reference is taken.
sub _resolve {
    my ($schema, $root) = @_;
    while (is_obj($schema) && ohas($schema, '$ref')) {
        my $ref = sval(oget($schema, '$ref'));
        if ($ref =~ m{^#/}) {
            $schema = _navigate($root, substr($ref, 2));
        }
        elsif (index($ref, $BASE) == 0) {
            my $rest = substr($ref, length $BASE);
            my ($filename, $pointer) = split /#\//, $rest, 2;
            $root = _load_file($filename);
            $schema = (defined $pointer && length $pointer)
                ? _navigate($root, $pointer) : $root;
        }
        else {
            die "unsupported \$ref: '$ref'\n";
        }
    }
    return ($schema, $root);
}

# tag expected for each JSON Schema type name
my %TYPE_TAG = (
    object => 'obj', array => 'arr', string => 'str',
    number => 'num', boolean => 'bool',
);

sub _check {
    my ($value, $schema, $root, $path, $errors) = @_;
    ($schema, $root) = _resolve($schema, $root);

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
        my $type_ok;
        if ($t eq 'integer') {
            # an integer is a number whose source literal has no '.', 'e', 'E'
            $type_ok = is_num($value) && $value->[1] !~ /[.eE]/;
        }
        else {
            $type_ok = defined $TYPE_TAG{$t} && $value->[0] eq $TYPE_TAG{$t};
        }
        unless ($type_ok) {
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

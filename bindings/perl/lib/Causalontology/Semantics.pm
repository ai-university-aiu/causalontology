# Causalontology::Semantics - the semantic rules beyond the schemas
# (spec/semantics.md), mirroring bindings/python/causalontology/semantics.py.
#
# Local rules are checked here; store-context rules (materialized
# acyclicity, retraction lineage) live in Store.pm where the context exists.

package Causalontology::Semantics;

use strict;
use warnings;
use Exporter 'import';
use Causalontology::JSON qw(
    ohas oget sval nval aitems is_str is_obj jeq
);
use Causalontology::Canonical qw(infer_kind %KIND_OF_PREFIX);

our @EXPORT_OK = qw(
    validate_semantics is_partial admissible conflicts refinement_valid
    hierarchy_consistent %UNIT_SECONDS %ENRICHMENT_FIELDS @CRO_OPTIONAL_FIELDS
);

# Rule 4: the fixed unit-conversion constants (average Gregorian values).
our %UNIT_SECONDS = (
    instant => 0,
    seconds => 1,
    minutes => 60,
    hours   => 3600,
    days    => 86400,
    weeks   => 604800,
    months  => 2629746,
    years   => 31556952,
);

# Rule 12: enrichment field-to-kind validity and entry shapes.
our %ENRICHMENT_FIELDS = (
    aliases     => [['occurrent', 'continuant'], 'alias'],
    participants => [['occurrent'],              'cnt'],
    subsumes    => [['continuant'],              'cnt'],
    part_of     => [['continuant'],              'cnt'],
    realized_in => [['realizable'],              'occ'],
);

our @CRO_OPTIONAL_FIELDS = ('mechanism', 'temporal', 'modality', 'context');

# the kind named by an identifier's scheme prefix (undef when unknown)
sub _kind_of_id {
    my ($identifier) = @_;
    my ($pre) = split /:/, $identifier, 2;
    return $KIND_OF_PREFIX{$pre};
}

# (ok, reasons) - the locally checkable semantic rules.
sub validate_semantics {
    my ($obj, $kind) = @_;
    $kind ||= infer_kind($obj);
    my @errors;

    if ($kind eq 'cro') {
        if (ohas($obj, 'temporal')) {
            my $t = oget($obj, 'temporal');
            if (is_obj($t) && ohas($t, 'dmin') && ohas($t, 'dmax')
                    && nval(oget($t, 'dmin')) > nval(oget($t, 'dmax'))) {
                push @errors, 'dmin must be <= dmax';
            }
        }
        my $oid = ohas($obj, 'id') ? sval(oget($obj, 'id')) : undef;
        if ($oid && ohas($obj, 'mechanism')) {
            for my $m (aitems(oget($obj, 'mechanism'))) {
                if (is_str($m) && sval($m) eq $oid) {
                    push @errors, 'mechanism must be acyclic '
                        . '(a Causal Relation Object may not contain itself)';
                    last;
                }
            }
        }
        if ($oid && ohas($obj, 'refines')
                && sval(oget($obj, 'refines')) eq $oid) {
            push @errors, 'refines must be acyclic';
        }
    }

    if ($kind eq 'enrichment') {
        my $field = ohas($obj, 'field') ? sval(oget($obj, 'field')) : '';
        my $about = ohas($obj, 'about') ? sval(oget($obj, 'about')) : '';
        my $entry = ohas($obj, 'entry') ? oget($obj, 'entry') : undef;
        my $spec = $ENRICHMENT_FIELDS{$field};
        if ($spec) {
            my ($legal_kinds, $shape) = @$spec;
            my $about_kind = _kind_of_id($about);
            if ($about_kind
                    && !grep { $_ eq $about_kind } @$legal_kinds) {
                push @errors,
                    "$field is not a legal field for a $about_kind (rule 12)";
            }
            if ($shape eq 'alias') {
                unless (defined $entry && is_obj($entry)
                        && ohas($entry, 'lang') && ohas($entry, 'text')) {
                    push @errors, 'an aliases entry must be a '
                                . 'language-tagged text object';
                }
            }
            else {
                unless (defined $entry && is_str($entry)
                        && index(sval($entry), $shape . ':') == 0) {
                    push @errors,
                        "a $field entry must be a $shape: identifier";
                }
            }
        }
    }

    return ((@errors ? 0 : 1), \@errors);
}

# (partial, missing) - which optional CRO fields are unspecified.
sub is_partial {
    my ($cro) = @_;
    my @missing = grep { !ohas($cro, $_) } @CRO_OPTIONAL_FIELDS;
    return ((@missing ? 1 : 0), \@missing);
}

# Rule 4: temporal admissibility with the fixed constants.
sub admissible {
    my ($cro, $elapsed_seconds) = @_;
    return 1 unless ohas($cro, 'temporal');  # no window, no constraint
    my $t = oget($cro, 'temporal');
    my $unit = $UNIT_SECONDS{ sval(oget($t, 'unit')) };
    my $lo = nval(oget($t, 'dmin')) * $unit;
    my $hi = nval(oget($t, 'dmax')) * $unit;
    return ($lo <= $elapsed_seconds && $elapsed_seconds <= $hi) ? 1 : 0;
}

# do two temporal windows overlap? (either absent counts as overlapping)
sub _window_overlap {
    my ($a, $b) = @_;
    return 1 unless ohas($a, 'temporal') && ohas($b, 'temporal');
    my ($ta, $tb) = (oget($a, 'temporal'), oget($b, 'temporal'));
    my $ua = $UNIT_SECONDS{ sval(oget($ta, 'unit')) };
    my $ub = $UNIT_SECONDS{ sval(oget($tb, 'unit')) };
    my ($lo_a, $hi_a) = (nval(oget($ta, 'dmin')) * $ua,
                         nval(oget($ta, 'dmax')) * $ua);
    my ($lo_b, $hi_b) = (nval(oget($tb, 'dmin')) * $ub,
                         nval(oget($tb, 'dmax')) * $ub);
    return ($lo_a <= $hi_b && $lo_b <= $hi_a) ? 1 : 0;
}

# are two context sets compatible? (either absent or empty, or nested)
sub _contexts_compatible {
    my ($a, $b) = @_;
    my @ca = ohas($a, 'context') ? map { sval($_) } aitems(oget($a, 'context')) : ();
    my @cb = ohas($b, 'context') ? map { sval($_) } aitems(oget($b, 'context')) : ();
    return 1 if !@ca || !@cb;
    my %sa = map { $_ => 1 } @ca;
    my %sb = map { $_ => 1 } @cb;
    my $a_in_b = !grep { !exists $sb{$_} } keys %sa;
    my $b_in_a = !grep { !exists $sa{$_} } keys %sb;
    return ($a_in_b || $b_in_a) ? 1 : 0;
}

my %POSITIVE = (necessary => 1, sufficient => 1, contributory => 1);

# the id set of a list-valued field, as a hash for set comparison
sub _id_set {
    my ($obj, $field) = @_;
    my %set;
    if (ohas($obj, $field)) {
        $set{ sval($_) } = 1 for aitems(oget($obj, $field));
    }
    return \%set;
}

# do two id sets hold exactly the same members?
sub _set_equal {
    my ($x, $y) = @_;
    return 0 unless keys(%$x) == keys(%$y);
    for (keys %$x) { return 0 unless exists $y->{$_} }
    return 1;
}

# Rule 6: the formal conflict test.
sub conflicts {
    my ($a, $b) = @_;
    return 0 unless _set_equal(_id_set($a, 'causes'), _id_set($b, 'causes'));
    return 0 unless _set_equal(_id_set($a, 'effects'), _id_set($b, 'effects'));
    return 0 unless _contexts_compatible($a, $b);
    return 0 unless _window_overlap($a, $b);
    my $ma = ohas($a, 'modality') ? sval(oget($a, 'modality')) : '';
    my $mb = ohas($b, 'modality') ? sval(oget($b, 'modality')) : '';
    return (($ma eq 'preventive' && $POSITIVE{$mb})
         || ($mb eq 'preventive' && $POSITIVE{$ma})) ? 1 : 0;
}

# Rule 3: (ok, reason) - is child a valid refinement of parent?
sub refinement_valid {
    my ($child, $parent) = @_;
    my $child_refines = ohas($child, 'refines')
        ? sval(oget($child, 'refines')) : undef;
    my $parent_id = ohas($parent, 'id') ? sval(oget($parent, 'id')) : undef;
    # mirror Python's != on optional strings: two absent values compare equal
    my $names_parent = (!defined $child_refines && !defined $parent_id)
        || (defined $child_refines && defined $parent_id
            && $child_refines eq $parent_id);
    unless ($names_parent) {
        return (0, 'child does not name the parent in refines');
    }
    unless (_set_equal(_id_set($child, 'causes'), _id_set($parent, 'causes'))
         && _set_equal(_id_set($child, 'effects'),
                       _id_set($parent, 'effects'))) {
        return (0, "a refinement must keep the parent's causes and effects");
    }
    my $added = 0;
    for my $field (@CRO_OPTIONAL_FIELDS) {
        if (ohas($parent, $field)) {
            unless (ohas($child, $field)
                    && jeq(oget($child, $field), oget($parent, $field))) {
                return (0, 'a refinement may not change a field the '
                         . 'parent specified; this is a rival claim');
            }
        }
        elsif (ohas($child, $field)) {
            $added++;
        }
    }
    if ($added == 0) {
        return (0, 'a refinement must add at least one unspecified field');
    }
    return (1, 'valid refinement');
}

# Rule 7: 'consistent' | 'inconsistent' | 'indeterminate'.
# members: a hashref from CRO identifier to CRO object for the parent's
# mechanism entries (the store's view of them).
sub hierarchy_consistent {
    my ($parent, $members) = @_;
    my @mechanism = ohas($parent, 'mechanism')
        ? map { sval($_) } aitems(oget($parent, 'mechanism')) : ();
    return 'consistent' unless @mechanism;  # nothing claimed, nothing checked
    my %edges;
    for my $mid (@mechanism) {
        my $m = $members->{$mid};
        return 'indeterminate' unless defined $m;  # a dangling_reference gap
        for my $c (map { sval($_) } aitems(oget($m, 'causes'))) {
            push @{ $edges{$c} },
                map { sval($_) } aitems(oget($m, 'effects'));
        }
    }
    my $reachable = sub {
        my ($src, $dst) = @_;
        my (%seen, @stack);
        @stack = ($src);
        while (@stack) {
            my $node = pop @stack;
            return 1 if $node eq $dst;
            next if $seen{$node}++;
            push @stack, @{ $edges{$node} || [] };
        }
        return 0;
    };
    for my $c (map { sval($_) } aitems(oget($parent, 'causes'))) {
        for my $e (map { sval($_) } aitems(oget($parent, 'effects'))) {
            return 'inconsistent' unless $reachable->($c, $e);
        }
    }
    return 'consistent';
}

1;

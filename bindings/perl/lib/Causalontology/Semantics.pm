# Causalontology::Semantics - the semantic rules beyond the schemas
# (spec/semantics.md), mirroring bindings/python/causalontology/semantics.py.
#
# Local rules are checked here; store-context rules (materialized
# acyclicity, retraction lineage) live in Store.pm where the context exists.

package Causalontology::Semantics;

use strict;
use warnings;
use Exporter 'import';
use List::Util qw(min max);
use Causalontology::JSON qw(
    ohas oget sval nval bval aitems is_str is_bool is_obj is_arr jeq
);
use Causalontology::Canonical qw(infer_kind %KIND_OF_PREFIX);

our @EXPORT_OK = qw(
    validate_semantics is_partial admissible conflicts refinement_valid
    hierarchy_consistent bridge_closure classify_cro endpoints_mixed
    skip_gaps to_seconds delay_within_window bridge_wellformed
    seam_wellformed seam_home conduit_wellformed state_gaps
    covering_law_mismatch prediction_pairing_mismatch retrocausal has_cycle
    %UNIT_SECONDS %ORDINAL_UNITS %ENRICHMENT_FIELDS @CRO_OPTIONAL_FIELDS
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

# 3.0.0: the ordinal (dimensionless) temporal units. A tick is a discrete step
# with NO wall-clock mapping; a tick window is ordered by integer comparison,
# and an ordinal window and a wall-clock window are DIFFERENT DIMENSIONS that do
# not compare (mixing them is never within-window and never overlapping).
our %ORDINAL_UNITS = (ticks => 1);

# 'ordinal' for a tick-like unit, else 'wallclock'.
sub _dimension {
    my ($unit) = @_;
    return $ORDINAL_UNITS{$unit} ? 'ordinal' : 'wallclock';
}

# A comparable magnitude within ONE dimension: raw tick count for an ordinal
# unit, seconds for a wall-clock unit. Never mix dimensions.
sub _magnitude {
    my ($value, $unit) = @_;
    return $value if $ORDINAL_UNITS{$unit};   # a dimensionless tick count
    return 0 if $unit eq 'instant';
    return $value * $UNIT_SECONDS{$unit};
}

# Rule 12: enrichment field-to-kind validity and entry shapes. Two occurrent
# forms added in 2.0.0.
our %ENRICHMENT_FIELDS = (
    aliases     => [['occurrent', 'continuant'], 'alias'],
    participants => [['occurrent'],              'continuant'],
    subsumes    => [['continuant'],              'continuant'],
    part_of     => [['continuant'],              'continuant'],
    realized_in => [['realizable'],              'occurrent'],
    occurrent_subsumes => [['occurrent'],        'occurrent'],
    occurrent_part_of  => [['occurrent'],        'occurrent'],
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

    if ($kind eq 'causal_relation_object') {
        if (ohas($obj, 'temporal')) {
            my $t = oget($obj, 'temporal');
            if (is_obj($t) && ohas($t, 'minimum_delay') && ohas($t, 'maximum_delay')
                    && nval(oget($t, 'minimum_delay')) > nval(oget($t, 'maximum_delay'))) {
                push @errors, 'minimum_delay must be <= maximum_delay';
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
        # Rule 16, clause 1 (contradictory_skip): a HARD, locally-decidable
        # contradiction between skips:true and a non-empty mechanism.
        if (ohas($obj, 'skips') && is_bool(oget($obj, 'skips'))
                && bval(oget($obj, 'skips'))
                && ohas($obj, 'mechanism') && is_arr(oget($obj, 'mechanism'))
                && scalar(aitems(oget($obj, 'mechanism'))) > 0) {
            push @errors, 'contradictory_skip: skips is true but a mechanism '
                        . 'is present';
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

    # 3.0.0 Rule 22, local clause: a Cross Stratal Seam that DRAWS a chain has,
    # by drawing it, a modelled intervening mechanism - so mechanism_status
    # 'absent' contradicts a present chain (the honest-ignorance distinction
    # must stay honest). The stratal well-formedness (non-adjacency, adjacency
    # of chain steps, scheme, the home rule) needs the strata map and lives in
    # seam_wellformed, exactly as bridge well-formedness does.
    if ($kind eq 'cross_stratal_seam') {
        if (ohas($obj, 'chain')
                && ohas($obj, 'mechanism_status')
                && sval(oget($obj, 'mechanism_status')) eq 'absent') {
            push @errors, 'contradictory_seam: a drawn chain cannot carry '
                . "mechanism_status 'absent' (a drawn mechanism is not absent)";
        }
    }

    # 4.0.0 Rule 24, local clause: a predicted_occurrence's interval carries
    # exactly ONE temporal dimension - a wall-clock start (optional end) or an
    # ordinal start_tick (optional end_tick), never both and never neither.
    # Per Rule 23 the two dimensions never compare. The pairing check of a
    # prediction_error against its predicted_occurrence and its observed
    # token_occurrence needs those objects and lives in
    # prediction_pairing_mismatch, exactly as covering_law_mismatch does.
    if ($kind eq 'predicted_occurrence') {
        my $iv = ohas($obj, 'interval') ? oget($obj, 'interval') : undef;
        my $wall = (defined $iv && is_obj($iv) && ohas($iv, 'start')) ? 1 : 0;
        my $tick = (defined $iv && is_obj($iv) && ohas($iv, 'start_tick')) ? 1 : 0;
        if ($wall && $tick) {
            push @errors, 'dimension_conflict: a predicted interval must '
                . 'carry exactly one temporal dimension, not a '
                . 'wall-clock start AND an ordinal start_tick';
        }
        if (!$wall && !$tick) {
            push @errors, 'missing_dimension: a predicted interval must '
                . 'carry a wall-clock start or an ordinal start_tick';
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

# Rule 4: temporal admissibility. For a wall-clock window $elapsed is in
# seconds; for an ordinal ('ticks') window $elapsed is a tick count. Ordering is
# by magnitude WITHIN the window's own dimension (3.0.0).
sub admissible {
    my ($cro, $elapsed) = @_;
    return 1 unless ohas($cro, 'temporal');  # no window, no constraint
    my $t = oget($cro, 'temporal');
    my $unit = sval(oget($t, 'unit'));
    my $lo = _magnitude(nval(oget($t, 'minimum_delay')), $unit);
    my $hi = _magnitude(nval(oget($t, 'maximum_delay')), $unit);
    return ($lo <= $elapsed && $elapsed <= $hi) ? 1 : 0;
}

# do two temporal windows overlap? (either absent counts as overlapping)
sub _window_overlap {
    my ($a, $b) = @_;
    return 1 unless ohas($a, 'temporal') && ohas($b, 'temporal');
    my ($ta, $tb) = (oget($a, 'temporal'), oget($b, 'temporal'));
    my ($ua, $ub) = (sval(oget($ta, 'unit')), sval(oget($tb, 'unit')));
    # 3.0.0: an ordinal window and a wall-clock window never overlap
    return 0 if _dimension($ua) ne _dimension($ub);
    my ($lo_a, $hi_a) = (_magnitude(nval(oget($ta, 'minimum_delay')), $ua),
                         _magnitude(nval(oget($ta, 'maximum_delay')), $ua));
    my ($lo_b, $hi_b) = (_magnitude(nval(oget($tb, 'minimum_delay')), $ub),
                         _magnitude(nval(oget($tb, 'maximum_delay')), $ub));
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

# Rule 6 (amended): necessary, sufficient, contributory, enabling are mutually
# compatible; preventive opposes all four.
my %POSITIVE = (necessary => 1, sufficient => 1, contributory => 1,
                enabling => 1);

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

# ALGORITHM A. Every finer occurrent an occurrent resolves to, following
# Bridges downward, transitively (includes the starting occurrent; N12.1.1).
# $bridges is an arrayref of bridge objects; a visited guard prevents an
# infinite loop on malformed cyclic data (N12.1.2). Returns a hashref set.
sub bridge_closure {
    my ($occurrent_id, $bridges) = @_;
    my %result = ($occurrent_id => 1);
    my @frontier = ($occurrent_id);
    my %visited;
    my %coarse_index;
    for my $b (@{ $bridges || [] }) {
        push @{ $coarse_index{ sval(oget($b, 'coarse')) } }, $b;
    }
    while (@frontier) {
        my $current = pop @frontier;
        next if $visited{$current}++;
        for my $b (@{ $coarse_index{$current} || [] }) {
            for my $f (map { sval($_) } aitems(oget($b, 'fine'))) {
                $result{$f} = 1;
                push @frontier, $f;
            }
        }
    }
    return \%result;
}

# ALGORITHM B (amended Rule 7): 'consistent' | 'inconsistent' |
# 'indeterminate', ACROSS STRATA via bridged reachability.
# members: hashref from CRO id to CRO object for the mechanism entries;
# $bridges: arrayref of bridges (empty -> 1.0.0 literal reachability).
sub hierarchy_consistent {
    my ($parent, $members, $bridges) = @_;
    $bridges ||= [];
    my @mechanism = ohas($parent, 'mechanism')
        ? map { sval($_) } aitems(oget($parent, 'mechanism')) : ();
    return 'consistent' unless @mechanism;  # nothing claimed, nothing checked
    my %edges;  # node -> hashref set of successors
    for my $mid (@mechanism) {
        my $m = $members->{$mid};
        return 'indeterminate' unless defined $m;  # dangling; ignorance
        for my $c (map { sval($_) } aitems(oget($m, 'causes'))) {
            $edges{$c} ||= {};
            $edges{$c}{$_} = 1 for map { sval($_) } aitems(oget($m, 'effects'));
        }
    }
    my $path_exists = sub {
        my ($src, $dst) = @_;
        my (%seen, @stack);
        @stack = ($src);
        while (@stack) {
            my $node = pop @stack;
            return 1 if $node eq $dst;
            next if $seen{$node}++;
            push @stack, keys %{ $edges{$node} || {} };
        }
        return 0;
    };
    my @causes = map { sval($_) } aitems(oget($parent, 'causes'));
    my @effects = map { sval($_) } aitems(oget($parent, 'effects'));
    my %b_cause = map { $_ => bridge_closure($_, $bridges) } @causes;
    my %b_effect = map { $_ => bridge_closure($_, $bridges) } @effects;
    for my $c (@causes) {
        for my $e (@effects) {
            my $connected = 0;
          PAIR: for my $cp (keys %{ $b_cause{$c} }) {
                for my $ep (keys %{ $b_effect{$e} }) {
                    if ($path_exists->($cp, $ep)) { $connected = 1; last PAIR }
                }
            }
            return 'inconsistent' unless $connected;
        }
    }
    return 'consistent';
}

# the stratum id of an occurrent id via the occurrent map (undef when absent)
sub _stratum_of {
    my ($occ_map, $occ_id) = @_;
    my $o = $occ_map->{$occ_id};
    return undef unless defined $o && ohas($o, 'stratum');
    return sval(oget($o, 'stratum'));
}

# ALGORITHM C (Rule 15): 'intra_stratal' | 'adjacent_stratal' | 'skipping' |
# 'mixed' | 'unclassifiable' | 'scheme_mismatch'. Derived, never asserted.
sub classify_cro {
    my ($cro, $occ_map, $stratum_map) = @_;
    my @cause_strata = map { _stratum_of($occ_map, sval($_)) }
        aitems(oget($cro, 'causes'));
    my @effect_strata = map { _stratum_of($occ_map, sval($_)) }
        aitems(oget($cro, 'effects'));
    for my $s (@cause_strata, @effect_strata) {
        return 'unclassifiable' unless defined $s;
    }
    my %all = map { $_ => 1 } (@cause_strata, @effect_strata);
    my %schemes = map { sval(oget($stratum_map->{$_}, 'scheme')) => 1 }
        keys %all;
    return 'scheme_mismatch' if keys(%schemes) > 1;  # HARD
    my @c_ord = map { nval(oget($stratum_map->{$_}, 'ordinal')) } @cause_strata;
    my @e_ord = map { nval(oget($stratum_map->{$_}, 'ordinal')) } @effect_strata;
    if (max(@c_ord) == min(@c_ord)
            && min(@c_ord) == max(@e_ord) && max(@e_ord) == min(@e_ord)) {
        return 'intra_stratal';
    }
    my ($gap, $span);
    for my $i (@c_ord) {
        for my $j (@e_ord) {
            my $d = abs($i - $j);
            $gap = $d if !defined $gap || $d < $gap;
            $span = $d if !defined $span || $d > $span;
        }
    }
    return 'adjacent_stratal' if $span == 1;
    return 'skipping' if $gap > 1;
    return 'mixed';  # some pairs adjacent, some skipping
}

# True iff causes or effects span more than one distinct stratum (N12.3.2).
sub endpoints_mixed {
    my ($cro, $occ_map) = @_;
    my (%cs, $cs_none);
    for my $c (map { sval($_) } aitems(oget($cro, 'causes'))) {
        my $s = _stratum_of($occ_map, $c);
        if (defined $s) { $cs{$s} = 1 } else { $cs_none = 1 }
    }
    my (%es, $es_none);
    for my $e (map { sval($_) } aitems(oget($cro, 'effects'))) {
        my $s = _stratum_of($occ_map, $e);
        if (defined $s) { $es{$s} = 1 } else { $es_none = 1 }
    }
    return 0 if $cs_none || $es_none;
    return (keys(%cs) > 1 || keys(%es) > 1) ? 1 : 0;
}

# is a CRO field a truthy (present, non-empty) skips:true / mechanism?
sub _skips_true {
    my ($cro) = @_;
    return (ohas($cro, 'skips') && is_bool(oget($cro, 'skips'))
            && bval(oget($cro, 'skips'))) ? 1 : 0;
}

sub _has_mechanism {
    my ($cro) = @_;
    return (ohas($cro, 'mechanism') && is_arr(oget($cro, 'mechanism'))
            && scalar(aitems(oget($cro, 'mechanism'))) > 0) ? 1 : 0;
}

# ALGORITHM D (Rule 16): the gaps a CRO surfaces for the skip decision.
# THE ASYMMETRY (clause 3) is implemented exactly. Returns an arrayref.
sub skip_gaps {
    my ($cro, $classification) = @_;
    my @gaps;
    my $has_mech = _has_mechanism($cro);
    my $skips_true = _skips_true($cro);
    if ($skips_true && $has_mech) {
        return ['contradictory_skip'];           # HARD
    }
    if ($skips_true && $classification ne 'skipping'
            && $classification ne 'unclassifiable') {
        push @gaps, 'vacuous_skip';              # invitation
    }
    if ($classification eq 'skipping' && !$has_mech) {
        if ($skips_true) {
            # NOTHING: absence is a finding
        }
        else {
            push @gaps, 'incomplete_mechanism';  # invitation
        }
    }
    return \@gaps;
}

# ALGORITHM E helper: normalize a delay to seconds by the fixed table.
# 3.0.0: an ordinal ('ticks') unit is dimensionless and has NO wall-clock
# mapping - converting one to seconds is a category error and is refused.
sub to_seconds {
    my ($duration, $unit) = @_;
    die "'$unit' is an ordinal (dimensionless) unit and has no "
      . "wall-clock seconds mapping\n" if $ORDINAL_UNITS{$unit};
    return 0 if $unit eq 'instant';
    return $duration * $UNIT_SECONDS{$unit};
}

# ALGORITHM E (Rule 20): does an observed delay fall within a covering law's
# temporal window? Inclusive at both ends (N12.5.2). 3.0.0: an ordinal delay
# compares to an ordinal window by integer tick count; an ordinal delay and a
# wall-clock window (or vice versa) are different dimensions and never fall
# within one another.
sub delay_within_window {
    my ($actual_delay, $temporal) = @_;
    return 1 unless $actual_delay && $temporal;  # nothing to check
    my $du = sval(oget($actual_delay, 'unit'));
    my $tu = sval(oget($temporal, 'unit'));
    # dimension mismatch: a tick delay is not within a wall-clock window
    return 0 if _dimension($du) ne _dimension($tu);
    my $observed = _magnitude(nval(oget($actual_delay, 'duration')), $du);
    my $lo = _magnitude(nval(oget($temporal, 'minimum_delay')), $tu);
    my $hi = _magnitude(nval(oget($temporal, 'maximum_delay')), $tu);
    return ($lo <= $observed && $observed <= $hi) ? 1 : 0;
}

# Rule 14 / N3.2.1: Bridge well-formedness. (ok, reason).
sub bridge_wellformed {
    my ($bridge, $occ_map, $stratum_map) = @_;
    my $cs = _stratum_of($occ_map, sval(oget($bridge, 'coarse')));
    return (0, 'malformed_bridge: coarse has no stratum (a)')
        unless defined $cs;
    my @fine_strata = map { _stratum_of($occ_map, sval($_)) }
        aitems(oget($bridge, 'fine'));
    for my $s (@fine_strata) {
        return (0, 'malformed_bridge: a fine member has no stratum (b)')
            unless defined $s;
    }
    my %uniq = map { $_ => 1 } @fine_strata;
    return (0, 'malformed_bridge: fine members span >1 stratum (c)')
        unless keys(%uniq) == 1;
    my $fs = $fine_strata[0];
    if (sval(oget($stratum_map->{$cs}, 'scheme'))
            ne sval(oget($stratum_map->{$fs}, 'scheme'))) {
        return (0, 'malformed_bridge: coarse and fine differ in scheme (d)');
    }
    unless (nval(oget($stratum_map->{$cs}, 'ordinal'))
                > nval(oget($stratum_map->{$fs}, 'ordinal'))) {
        return (0, 'malformed_bridge: coarse ordinal not > fine ordinal (e)');
    }
    return (1, 'well-formed bridge');
}

# 3.0.0 Rule 22 / Algorithm F: Cross Stratal Seam well-formedness. (ok, reason).
# All of (a)-(g) must hold, else malformed_seam. A seam is a MANAGED jump across
# NON-ADJACENT strata; when it DRAWS a chain, the chain must be an
# adjacent-stratum path spanning the two endpoints' strata.
sub seam_wellformed {
    my ($seam, $occ_map, $stratum_map) = @_;
    my $src_s = _stratum_of($occ_map, sval(oget($seam, 'source')));
    my $tgt_s = _stratum_of($occ_map, sval(oget($seam, 'target')));
    return (0, 'malformed_seam: an endpoint has no stratum (a)')
        unless defined $src_s && defined $tgt_s;
    if (sval(oget($stratum_map->{$src_s}, 'scheme'))
            ne sval(oget($stratum_map->{$tgt_s}, 'scheme'))) {
        return (0, 'malformed_seam: endpoints differ in scheme (b)');
    }
    my $so = nval(oget($stratum_map->{$src_s}, 'ordinal'));
    my $to_ = nval(oget($stratum_map->{$tgt_s}, 'ordinal'));
    if (abs($so - $to_) <= 1) {
        return (0, 'malformed_seam: endpoints are adjacent or co-stratal; '
                 . 'a seam is for NON-adjacent strata (c)');
    }
    if (ohas($seam, 'chain')) {
        if (ohas($seam, 'mechanism_status')
                && sval(oget($seam, 'mechanism_status')) eq 'absent') {
            return (0, 'malformed_seam: a drawn chain contradicts '
                     . "mechanism_status 'absent' (d)");
        }
        my ($lo, $hi) = (min($so, $to_), max($so, $to_));
        my @ords;
        for my $oid (map { sval($_) } aitems(oget($seam, 'chain'))) {
            my $st = _stratum_of($occ_map, $oid);
            return (0, 'malformed_seam: a chain member has no stratum (e)')
                unless defined $st;
            if (sval(oget($stratum_map->{$st}, 'scheme'))
                    ne sval(oget($stratum_map->{$src_s}, 'scheme'))) {
                return (0, 'malformed_seam: a chain member differs in scheme (e)');
            }
            push @ords, nval(oget($stratum_map->{$st}, 'ordinal'));
        }
        for my $o (@ords) {
            unless ($lo < $o && $o < $hi) {
                return (0, 'malformed_seam: a chain member is not at an '
                     . 'INTERVENING stratum, strictly between the endpoints (f)');
            }
        }
        my @diffs = map { $ords[$_ + 1] - $ords[$_] } 0 .. ($#ords - 1);
        if (@diffs) {
            my $all_pos = !grep { $_ <= 0 } @diffs;
            my $all_neg = !grep { $_ >= 0 } @diffs;
            unless ($all_pos || $all_neg) {
                return (0, 'malformed_seam: chain is not strictly monotone from '
                         . 'one endpoint toward the other (g)');
            }
        }
    }
    return (1, 'well-formed cross_stratal_seam');
}

# THE HOME RULE (3.0.0): a Cross Stratal Seam belongs to the COARSEST stratum it
# touches - the endpoint of the greater ordinal. Returns that stratum's
# identifier (undef if an endpoint is unstratified).
sub seam_home {
    my ($seam, $occ_map, $stratum_map) = @_;
    my $src_s = _stratum_of($occ_map, sval(oget($seam, 'source')));
    my $tgt_s = _stratum_of($occ_map, sval(oget($seam, 'target')));
    return undef unless defined $src_s && defined $tgt_s;
    return (nval(oget($stratum_map->{$src_s}, 'ordinal'))
            >= nval(oget($stratum_map->{$tgt_s}, 'ordinal')))
        ? $src_s : $tgt_s;
}

# Rule 17 / N4.2.1-2: Conduit well-formedness. (ok, reason).
sub conduit_wellformed {
    my ($conduit, $port_map, $cro_map) = @_;
    $cro_map ||= {};
    my $frm = $port_map->{ sval(oget($conduit, 'from')) };
    my $to = $port_map->{ sval(oget($conduit, 'to')) };
    return (0, 'malformed_conduit: dangling port reference')
        unless defined $frm && defined $to;
    my $fdir = sval(oget($frm, 'direction'));
    return (0, 'malformed_conduit: from port is not out/bidirectional (a)')
        unless $fdir eq 'out' || $fdir eq 'bidirectional';
    my $tdir = sval(oget($to, 'direction'));
    return (0, 'malformed_conduit: to port is not in/bidirectional (b)')
        unless $tdir eq 'in' || $tdir eq 'bidirectional';
    my @carries = map { sval($_) } aitems(oget($conduit, 'carries'));
    my %frm_accepts = map { sval($_) => 1 } aitems(oget($frm, 'accepts'));
    for my $o (@carries) {
        return (0, 'malformed_conduit: carries not accepted by from (c)')
            unless $frm_accepts{$o};
    }
    my %to_accepts = map { sval($_) => 1 } aitems(oget($to, 'accepts'));
    my $transform = ohas($conduit, 'transform')
        ? sval(oget($conduit, 'transform')) : undef;
    if (!defined $transform) {
        for my $o (@carries) {
            return (0, 'malformed_conduit: carries not accepted by to (d)')
                unless $to_accepts{$o};
        }
    }
    else {
        my $law = $cro_map->{$transform};
        if (defined $law) {
            for my $o (map { sval($_) } aitems(oget($law, 'effects'))) {
                return (0, 'malformed_conduit: transform effects not '
                         . 'accepted by to (d, relaxed per N4.2.2)')
                    unless $to_accepts{$o};
            }
        }
    }
    return (1, 'well-formed conduit');
}

# Rule 19 / N5.3.1-2: State value type and unit coherence. Returns arrayref.
sub state_gaps {
    my ($state, $quality) = @_;
    my @gaps;
    my $dt = ohas($quality, 'datatype') ? sval(oget($quality, 'datatype')) : undef;
    my $v = ohas($state, 'value') ? oget($state, 'value') : undef;
    my $shape;
    if (defined $v && is_obj($v)) {
        $shape = ohas($v, 'quantity')    ? 'quantity'
               : ohas($v, 'categorical') ? 'categorical'
               : ohas($v, 'boolean')     ? 'boolean' : undef;
    }
    my $shape_eq_dt = (defined $shape && defined $dt && $shape eq $dt)
        || (!defined $shape && !defined $dt);
    if (!$shape_eq_dt) {
        push @gaps, 'value_type_mismatch';
    }
    elsif (defined $dt && $dt eq 'quantity') {
        my $vunit = (defined $v && ohas($v, 'unit'))
            ? sval(oget($v, 'unit')) : undef;
        my $qunit = ohas($quality, 'unit') ? sval(oget($quality, 'unit')) : undef;
        my $unit_eq = (defined $vunit && defined $qunit && $vunit eq $qunit)
            || (!defined $vunit && !defined $qunit);
        push @gaps, 'unit_mismatch' unless $unit_eq;
    }
    return \@gaps;
}

# Rule 20: covering-law coherence. True iff the token claim's cause/effect
# tokens do not instantiate the covering law's causes/effects.
sub covering_law_mismatch {
    my ($tcc, $token_map, $law) = @_;
    return 0 unless $law;
    my %law_causes = map { sval($_) => 1 } aitems(oget($law, 'causes'));
    my %law_effects = map { sval($_) => 1 } aitems(oget($law, 'effects'));
    for my $c (map { sval($_) } aitems(oget($tcc, 'causes'))) {
        my $inst = sval(oget($token_map->{$c}, 'instantiates'));
        return 1 unless $law_causes{$inst};
    }
    for my $e (map { sval($_) } aitems(oget($tcc, 'effects'))) {
        my $inst = sval(oget($token_map->{$e}, 'instantiates'));
        return 1 unless $law_effects{$inst};
    }
    return 0;
}

# 4.0.0 Rule 24: prediction-to-observation pairing. True iff the prediction
# error's observed token does not instantiate the occurrent its
# predicted_occurrence instantiates. An ABSENT observed is never a mismatch - it
# means the predicted occurrence was not fulfilled by any recorded occurrence.
sub prediction_pairing_mismatch {
    my ($error, $predicted, $observed) = @_;
    return 0 unless ohas($error, 'observed') && defined $observed;
    return (sval(oget($observed, 'instantiates'))
            ne sval(oget($predicted, 'instantiates'))) ? 1 : 0;
}

# Rule 21: temporal coherence of token causation. True iff any cause token
# starts after any effect token (HARD). RFC 3339 UTC 'Z' strings compare
# lexicographically.
sub retrocausal {
    my ($tcc, $token_map) = @_;
    for my $c (map { sval($_) } aitems(oget($tcc, 'causes'))) {
        my $cstart = sval(oget(oget($token_map->{$c}, 'interval'), 'start'));
        for my $e (map { sval($_) } aitems(oget($tcc, 'effects'))) {
            my $estart = sval(oget(oget($token_map->{$e}, 'interval'), 'start'));
            return 1 if $cstart gt $estart;
        }
    }
    return 0;
}

# Rules 4 / 6.1: generic acyclicity for the new graph relations. $edges is a
# hashref from node -> arrayref of successors. Returns 1/0.
sub has_cycle {
    my ($edges) = @_;
    my %state;  # 0 white, 1 grey, 2 black
    my $visit;
    $visit = sub {
        my ($node) = @_;
        $state{$node} = 1;
        for my $nxt (@{ $edges->{$node} || [] }) {
            my $s = $state{$nxt} || 0;
            return 1 if $s == 1;
            return 1 if $s == 0 && $visit->($nxt);
        }
        $state{$node} = 2;
        return 0;
    };
    for my $n (keys %$edges) {
        return 1 if ($state{$n} || 0) == 0 && $visit->($n);
    }
    return 0;
}

1;

# Causalontology::Store - an in-memory conformant store, mirroring the
# CURRENT bindings/python/causalontology/store.py.
#
# Implements the store side of the abstract operation set (spec/store.md):
# immutable content objects with idempotent put; signed, add-only provenance
# records; materialized enrichment views with contributors; retraction
# handling in default views; succession lineage; the resolve minimum; the
# deterministic cycle-breaking view rule; and the stigmergy gap read.
#
# Perl hashes are UNORDERED, so everywhere the Python reference iterates a
# dict in insertion order (objects, records, cycle-finder nodes, view
# buckets) this port keeps an explicit insertion-order array beside the hash.

package Causalontology::Store;

use strict;
use warnings;
use Causalontology::JSON qw(
    jstr jbool ohas oget oset oclone sval aitems is_str is_arr
);
use Causalontology::Canonical qw(identify infer_kind);
use Causalontology::Schema qw(validate_schema);
use Causalontology::Semantics qw(
    validate_semantics refinement_valid is_partial conflicts
);
use Causalontology::Signing qw(verify_record);
use Causalontology::JCS qw(jcs);

my %CONTENT_KINDS = map { $_ => 1 } qw(occurrent causal_relation_object
                                       continuant realizable);
my %RECORD_KINDS  = map { $_ => 1 } qw(assertion enrichment retraction
                                       succession);

# ---------------------------------------------------------------- exception
# An enforcing store refused a write, with the reason in ->message.
package Causalontology::RejectedWrite;

sub new {
    my ($class, $message) = @_;
    return bless { message => $message }, $class;
}

sub message { return $_[0]{message} }

sub throw {
    my ($class, $message) = @_;
    die $class->new($message);
}

package Causalontology::Store;

# --------------------------------------------------------------- construct
sub new {
    my ($class, %args) = @_;
    my $enforcing = exists $args{enforcing} ? $args{enforcing} : 1;
    return bless {
        enforcing     => $enforcing,
        objects       => {},  # id -> content object
        object_order  => [],  # ids in insertion order
        records       => {},  # id -> provenance record
        record_order  => [],  # ids in insertion order
        quarantine    => {},  # id -> record (unsigned / unverifiable)
    }, $class;
}

sub object_count { return scalar @{ $_[0]{object_order} } }

sub object_ids { return @{ $_[0]{object_order} } }

sub get_object { return $_[0]{objects}{ $_[1] } }

# ---------------------------------------------------------------------- put
# Write a content object; idempotent; returns the identifier.
sub put {
    my ($self, $obj, $kind) = @_;
    $kind ||= infer_kind($obj);
    die "put() takes content objects; use put_record()\n"
        unless $CONTENT_KINDS{$kind};
    $obj = oclone($obj);
    oset($obj, 'type', jstr($kind)) unless ohas($obj, 'type');
    oset($obj, 'id', jstr(identify($obj, $kind))) unless ohas($obj, 'id');
    my $id = sval(oget($obj, 'id'));
    # immutable: identical identity is a no-op
    return $id if exists $self->{objects}{$id};
    my ($ok, $why) = validate_schema($obj, $kind);
    Causalontology::RejectedWrite->throw(join '; ', @$why) unless $ok;
    ($ok, $why) = validate_semantics($obj, $kind);
    Causalontology::RejectedWrite->throw(join '; ', @$why) unless $ok;
    $self->{objects}{$id} = $obj;
    push @{ $self->{object_order} }, $id;
    return $id;
}

# Write a signed provenance record; returns the identifier.
sub put_record {
    my ($self, $record, $kind, $force) = @_;
    $kind ||= infer_kind($record);
    die "put_record() takes provenance records\n"
        unless $RECORD_KINDS{$kind};
    $record = oclone($record);
    oset($record, 'type', jstr($kind)) unless ohas($record, 'type');
    my $rid = ohas($record, 'id')
        ? sval(oget($record, 'id')) : identify($record, $kind);
    oset($record, 'id', jstr($rid));
    # add-only and idempotent
    return $rid if exists $self->{records}{$rid};
    unless (verify_record($record, $kind)) {
        $self->{quarantine}{$rid} = $record;
        Causalontology::RejectedWrite->throw(
            'unsigned or unverifiable record: quarantined');
    }
    my ($ok, $why) = validate_semantics($record, $kind);
    Causalontology::RejectedWrite->throw(join '; ', @$why) unless $ok;
    if ($kind eq 'retraction' && !$self->_retraction_source_ok($record)) {
        Causalontology::RejectedWrite->throw(
            "a retraction is valid only from the retracted record's "
          . 'source or its succession lineage');
    }
    if ($kind eq 'enrichment' && $self->{enforcing} && !$force) {
        my $field = sval(oget($record, 'field'));
        if (($field eq 'subsumes' || $field eq 'part_of')
                && $self->_would_cycle($record)) {
            Causalontology::RejectedWrite->throw(
                "would create a cycle in the materialized $field graph");
        }
    }
    $self->{records}{$rid} = $record;
    push @{ $self->{record_order} }, $rid;
    return $rid;
}

# Simulate a decentralized replica merge (no enforcement gate).
sub force_merge_record {
    my ($self, $record, $kind) = @_;
    return $self->put_record($record, $kind, 1);
}

# ------------------------------------------------------- record queries
# all records of one kind, in insertion order
sub _records_of {
    my ($self, $kind) = @_;
    return grep { sval(oget($_, 'type')) eq $kind }
           map { $self->{records}{$_} } @{ $self->{record_order} };
}

# the set of record ids named by any retraction
sub _retracted_ids {
    my ($self) = @_;
    my %out;
    for my $r ($self->_records_of('retraction')) {
        $out{ sval(oget($r, 'retracts')) } = 1;
    }
    return \%out;
}

# may this retraction's source retract its target?
sub _retraction_source_ok {
    my ($self, $retraction) = @_;
    my $target = $self->{records}{ sval(oget($retraction, 'retracts')) };
    return 1 unless defined $target;  # open world: target may arrive later
    my $lineage = $self->lineage(sval(oget($target, 'source')));
    return exists $lineage->{ sval(oget($retraction, 'source')) } ? 1 : 0;
}

# The succession chain closure containing key (includes key), as a hashref.
sub lineage {
    my ($self, $key) = @_;
    my (%succ, %pred);
    for my $s ($self->_records_of('succession')) {
        $succ{ sval(oget($s, 'predecessor')) } = sval(oget($s, 'successor'));
        $pred{ sval(oget($s, 'successor')) } = sval(oget($s, 'predecessor'));
    }
    my %chain = ($key => 1);
    my $cursor = $key;
    while (exists $pred{$cursor}) {
        $cursor = $pred{$cursor};
        $chain{$cursor} = 1;
    }
    $cursor = $key;
    while (exists $succ{$cursor}) {
        $cursor = $succ{$cursor};
        $chain{$cursor} = 1;
    }
    return \%chain;
}

# the assertions about one identifier (default view excludes retracted)
sub assertions_about {
    my ($self, $identifier, $include_retracted) = @_;
    my $retracted = $self->_retracted_ids();
    my @out;
    for my $r ($self->_records_of('assertion')) {
        next unless sval(oget($r, 'about')) eq $identifier;
        if (exists $retracted->{ sval(oget($r, 'id')) }) {
            if ($include_retracted) {
                # the history flavour carries an explicit retracted flag
                my $marked = oclone($r);
                oset($marked, 'retracted', jbool(1));
                push @out, $marked;
            }
            next;
        }
        push @out, $r;
    }
    return @out;
}

# the enrichments about one identifier (default view excludes retracted)
sub enrichments_about {
    my ($self, $identifier, $include_retracted) = @_;
    my $retracted = $self->_retracted_ids();
    my @out;
    for my $r ($self->_records_of('enrichment')) {
        next unless sval(oget($r, 'about')) eq $identifier;
        next if exists $retracted->{ sval(oget($r, 'id')) }
            && !$include_retracted;
        push @out, $r;
    }
    return @out;
}

# ------------------------------------------------- materialized views
# (\@edges, \@excluded) for subsumes/part_of after rule 13 cycle-breaking.
sub active_taxonomy_edges {
    my ($self, $field) = @_;
    my $retracted = $self->_retracted_ids();
    my @recs = grep {
        sval(oget($_, 'field')) eq $field
            && !exists $retracted->{ sval(oget($_, 'id')) }
    } $self->_records_of('enrichment');
    my @active = @recs;
    my @excluded;
    while (1) {
        my $cyc = _find_cycle_records(\@active);
        last unless @$cyc;
        # exclude the cycle-completing record with the LATEST timestamp,
        # ties broken by lexicographic record identifier (deterministic);
        # like Python's max(), keep the FIRST among equals
        my $loser = $cyc->[0];
        for my $r (@$cyc) {
            my $cmp = sval(oget($r, 'timestamp'))
                          cmp sval(oget($loser, 'timestamp'));
            $cmp = sval(oget($r, 'id')) cmp sval(oget($loser, 'id'))
                if $cmp == 0;
            $loser = $r if $cmp > 0;
        }
        my $loser_id = sval(oget($loser, 'id'));
        @active = grep { sval(oget($_, 'id')) ne $loser_id } @active;
        push @excluded, $loser;
    }
    return (\@active, \@excluded);
}

# the records forming the first cycle found in an enrichment edge set
sub _find_cycle_records {
    my ($recs) = @_;
    my (%edges, @node_order);
    for my $r (@$recs) {
        my $about = sval(oget($r, 'about'));
        push @node_order, $about unless exists $edges{$about};
        push @{ $edges{$about} }, [sval(oget($r, 'entry')), $r];
    }
    my %state;
    my @cycle;
    my $dfs;
    $dfs = sub {
        my ($node, $path_records) = @_;
        $state{$node} = 1;
        for my $pair (@{ $edges{$node} || [] }) {
            my ($nxt, $rec) = @$pair;
            if (($state{$nxt} || 0) == 1) {
                @cycle = (@$path_records, $rec);
                return 1;
            }
            if (($state{$nxt} || 0) == 0) {
                return 1 if $dfs->($nxt, [@$path_records, $rec]);
            }
        }
        $state{$node} = 2;
        return 0;
    };
    for my $start (@node_order) {
        if (($state{$start} || 0) == 0 && $dfs->($start, [])) {
            return \@cycle;
        }
    }
    return [];
}

# would accepting this enrichment complete a cycle in its field's graph?
sub _would_cycle {
    my ($self, $record) = @_;
    my $retracted = $self->_retracted_ids();
    my $field = sval(oget($record, 'field'));
    my @recs = grep {
        sval(oget($_, 'field')) eq $field
            && !exists $retracted->{ sval(oget($_, 'id')) }
    } $self->_records_of('enrichment');
    push @recs, $record;
    return @{ _find_cycle_records(\@recs) } ? 1 : 0;
}

# The object with its materialized enrichment sets and contributors.
sub get {
    my ($self, $identifier, $view) = @_;
    $view ||= 'default';
    my $obj = $self->{objects}{$identifier};
    return undef unless defined $obj;
    my $include_retracted = ($view eq 'history') ? 1 : 0;
    my %excluded_ids;
    for my $field ('subsumes', 'part_of') {
        my (undef, $excluded) = $self->active_taxonomy_edges($field);
        $excluded_ids{ sval(oget($_, 'id')) } = 1 for @$excluded;
    }
    my (%fields, @field_order);
    for my $rec ($self->enrichments_about($identifier, $include_retracted)) {
        next if exists $excluded_ids{ sval(oget($rec, 'id')) }
            && $view ne 'history';
        my $field = sval(oget($rec, 'field'));
        my $entry = oget($rec, 'entry');
        # the dedup key: canonical bytes make equal entries collide exactly
        my $entry_key = jcs($entry);
        unless (exists $fields{$field}) {
            $fields{$field} = { order => [], buckets => {} };
            push @field_order, $field;
        }
        my $slot = $fields{$field};
        unless (exists $slot->{buckets}{$entry_key}) {
            $slot->{buckets}{$entry_key} =
                { entry => $entry, contributors => [] };
            push @{ $slot->{order} }, $entry_key;
        }
        push @{ $slot->{buckets}{$entry_key}{contributors} },
            { source    => sval(oget($rec, 'source')),
              timestamp => sval(oget($rec, 'timestamp')) };
    }
    my %enrichments;
    for my $field (@field_order) {
        $enrichments{$field} = [
            map { $fields{$field}{buckets}{$_} } @{ $fields{$field}{order} }
        ];
    }
    return { object => $obj } if $view eq 'raw';
    return { object => $obj, enrichments => \%enrichments };
}

# -------------------------------------------------------------- resolve
# canonical-label form: lowercase, single underscores
sub _canon_label {
    my ($text) = @_;
    my @words = split ' ', lc $text;
    return join '_', @words;
}

# alias-normal form: single spaces, case-folded
sub _norm_alias {
    my ($text) = @_;
    my @words = split ' ', $text;
    return lc join ' ', @words;
}

# The conformance minimum: exact label, then alias, then nothing.
sub resolve {
    my ($self, $text, $lang) = @_;
    my (@label_hits, @alias_hits);
    my $wanted_label = _canon_label($text);
    my $wanted_alias = _norm_alias($text);
    my $retracted = $self->_retracted_ids();
    OBJECT: for my $oid (@{ $self->{object_order} }) {
        my $obj = $self->{objects}{$oid};
        my $type = sval(oget($obj, 'type'));
        next unless $type eq 'occurrent' || $type eq 'continuant';
        if (ohas($obj, 'label')
                && sval(oget($obj, 'label')) eq $wanted_label) {
            push @label_hits, $oid;
            next OBJECT;
        }
        for my $rec ($self->_records_of('enrichment')) {
            next unless sval(oget($rec, 'about')) eq $oid
                && sval(oget($rec, 'field')) eq 'aliases';
            next if exists $retracted->{ sval(oget($rec, 'id')) };
            my $entry = oget($rec, 'entry');
            if (defined $lang) {
                next unless ohas($entry, 'lang')
                    && sval(oget($entry, 'lang')) eq $lang;
            }
            my $entry_text = ohas($entry, 'text')
                ? sval(oget($entry, 'text')) : '';
            if (_norm_alias($entry_text) eq $wanted_alias) {
                push @alias_hits, $oid;
                last;
            }
        }
    }
    return (@label_hits, @alias_hits);
}

# ---------------------------------------------------------------- gaps
# The stigmergy read. Gap kinds per spec/store.md.
sub gaps {
    my ($self, $kind) = @_;
    my @out;
    my %refined;
    for my $oid (@{ $self->{object_order} }) {
        my $obj = $self->{objects}{$oid};
        next unless sval(oget($obj, 'type')) eq 'causal_relation_object';
        next unless ohas($obj, 'refines')
            && sval(oget($obj, 'refines')) ne '';
        my $parent = $self->{objects}{ sval(oget($obj, 'refines')) };
        next unless defined $parent;
        my ($ok, undef) = refinement_valid($obj, $parent);
        $refined{ sval(oget($parent, 'id')) } = 1 if $ok;
    }
    for my $oid (@{ $self->{object_order} }) {
        my $obj = $self->{objects}{$oid};
        next unless sval(oget($obj, 'type')) eq 'causal_relation_object';
        # missing_field: lacking the temporal window or the modality -
        # mechanism and context may legitimately stay unspecified forever
        # (empty_mechanism is its own kind; absent context = context-free).
        if ((!ohas($obj, 'temporal') || !ohas($obj, 'modality'))
                && !$refined{$oid}) {
            my (undef, $missing) = is_partial($obj);
            push @out, { id => $oid, kind => 'missing_field',
                         missing => $missing };
        }
        my $mech_empty = !ohas($obj, 'mechanism')
            || (is_arr(oget($obj, 'mechanism'))
                && !aitems(oget($obj, 'mechanism')));
        if ($mech_empty && !$refined{$oid}) {
            push @out, { id => $oid, kind => 'empty_mechanism' };
        }
    }
    for my $field ('subsumes', 'part_of') {
        my (undef, $excluded) = $self->active_taxonomy_edges($field);
        for my $rec (@$excluded) {
            push @out, { id => sval(oget($rec, 'id')),
                         kind => 'inconsistent_hierarchy',
                         note => 'excluded by the deterministic '
                               . 'cycle-breaking view rule' };
        }
    }
    # dangling_reference: a reference to an object absent from the store -
    # the red link that says "this page is wanted".
    for my $oid (@{ $self->{object_order} }) {
        my $obj = $self->{objects}{$oid};
        my $type = sval(oget($obj, 'type'));
        my @refs;
        if ($type eq 'causal_relation_object') {
            for my $field ('causes', 'effects', 'context', 'mechanism') {
                push @refs, map { sval($_) } aitems(oget($obj, $field))
                    if ohas($obj, $field);
            }
            push @refs, sval(oget($obj, 'refines'))
                if ohas($obj, 'refines') && sval(oget($obj, 'refines')) ne '';
        }
        elsif ($type eq 'realizable') {
            push @refs, ohas($obj, 'bearer')
                ? sval(oget($obj, 'bearer')) : undef;
        }
        for my $ref (@refs) {
            if (defined $ref && $ref ne ''
                    && !exists $self->{objects}{$ref}) {
                push @out, { id => $oid, kind => 'dangling_reference',
                             ref => $ref };
            }
        }
    }
    # conflict: pairs of claims satisfying the formal test (rule 6).
    my @cros = grep { sval(oget($_, 'type')) eq 'causal_relation_object' }
               map { $self->{objects}{$_} } @{ $self->{object_order} };
    for my $i (0 .. $#cros) {
        for my $j ($i + 1 .. $#cros) {
            if (conflicts($cros[$i], $cros[$j])) {
                push @out, { kind => 'conflict',
                             a => sval(oget($cros[$i], 'id')),
                             b => sval(oget($cros[$j], 'id')) };
            }
        }
    }
    if (defined $kind) {
        @out = grep { $_->{kind} eq $kind } @out;
    }
    return @out;
}

1;

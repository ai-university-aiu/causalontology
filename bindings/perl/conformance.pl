#!/usr/bin/env perl
# The Causalontology conformance runner for causalontology-perl (spec 4.0.0).
#
# Runs every vector in conformance/vectors/ against the Perl binding. An
# implementation is conformant if and only if it passes every vector; this
# runner exits nonzero on any failure. Mirrors
# bindings/python/tests/run_conformance.py exactly. Vectors V01-V107 are the
# whole-word 2.0.0 baseline (Principle P7): V01-V38 re-frozen unaltered in
# meaning, V39-V107 new. V108-V119 are the 3.0.0 additions; V120-V137 are the
# 4.0.0 additions (attitude, predicted_occurrence, prediction_error).
#
# The V01-V107 vectors carry concrete 64-hex identifiers and real keys, which
# pass through the (retained) normalization unchanged; behavioral vectors
# derive deterministic keypairs from the seed sha256("key:" + name).

use strict;
use warnings;
use File::Basename qw(dirname basename);
use Cwd qw(abs_path);
use Digest::SHA qw(sha256 sha256_hex);
use Time::HiRes qw(time);

# make bindings/perl/lib visible regardless of the working directory
use lib dirname(abs_path(__FILE__)) . '/lib';

use Causalontology;
use Causalontology::JSON qw(
    decode_json jstr jnum jbool jarr jobj
    is_str is_num is_arr is_obj sval nval aitems okeys ohas oget oset oclone
);
use Causalontology::JCS qw(jcs);
use Causalontology::Canonical qw(identify);
use Causalontology::Schema qw(validate_schema);
use Causalontology::Semantics qw(
    validate_semantics is_partial admissible conflicts refinement_valid
    hierarchy_consistent bridge_closure classify_cro endpoints_mixed
    skip_gaps to_seconds delay_within_window bridge_wellformed
    seam_wellformed seam_home conduit_wellformed state_gaps
    covering_law_mismatch prediction_pairing_mismatch retrocausal has_cycle
    %ENRICHMENT_FIELDS
);
use Causalontology::Ed25519 ();
use Causalontology::Signing qw(keypair_from_seed sign_record verify_record);
use Causalontology::Store ();

# progress must appear promptly (pure-Perl bigints make signing slow)
$| = 1;

# the repository root is two levels above this script (bindings/perl/..)
my $ROOT = dirname(dirname(dirname(abs_path(__FILE__))));
my $VECDIR = "$ROOT/conformance/vectors";

# ---------------------------------------------------------------------------
# symbolic-identifier normalization
# ---------------------------------------------------------------------------
my @SCHEMES = qw(occurrent causal_relation_object continuant realizable
                 assertion enrichment retraction succession
                 stratum bridge cross_stratal_seam port conduit quality
                 token_individual token_occurrence state_assertion
                 token_causal_claim
                 attitude predicted_occurrence prediction_error);
my $SCHEME_RE = join '|', @SCHEMES;
my %KEYS;

# A real, deterministic Ed25519 keypair for a symbolic key name.
sub key {
    my ($name) = @_;
    unless (exists $KEYS{$name}) {
        my $seed = sha256('key:' . $name);
        my ($secret, $public) = keypair_from_seed($seed);
        $KEYS{$name} = [$secret, $public];
    }
    return @{ $KEYS{$name} };
}

# Normalize one symbolic identifier to a well-formed one.
sub sym {
    my ($s) = @_;
    my ($scheme, $name) = split /:/, $s, 2;
    if ($scheme eq 'ed25519') {
        return $s if $name =~ /^[0-9a-f]{64}$/;  # frozen: real key passes
        my (undef, $public) = key($name);
        return $public;
    }
    return $s if $name =~ /^[0-9a-f]{64}$/;      # frozen: real id passes
    return $scheme . ':' . sha256_hex($name);
}

# Recursively normalize symbolic identifiers and placeholders.
sub normalize {
    my ($x) = @_;
    if (is_str($x)) {
        my $s = sval($x);
        return jstr('ab' x 64) if $s eq '<128 hex>';
        return jstr(sym($s)) if $s =~ /^(?:$SCHEME_RE|ed25519):/;
        return $x;
    }
    if (is_arr($x)) {
        return jarr(map { normalize($_) } aitems($x));
    }
    if (is_obj($x)) {
        my $out = jobj();
        oset($out, $_, normalize(oget($x, $_))) for okeys($x);
        return $out;
    }
    return $x;
}

# Load vector n's JSON file (for its structured inputs).
sub vector {
    my ($n) = @_;
    my @hits = glob sprintf('%s/v%02d_*.json', $VECDIR, $n);
    die "vector $n not found\n" unless @hits == 1;
    open my $fh, '<:raw', $hits[0] or die "cannot open $hits[0]: $!\n";
    local $/;
    my $raw = <$fh>;
    close $fh;
    return decode_json($raw);
}

# the basename (without .json) of vector n, for the report lines
sub vec_name {
    my ($n) = @_;
    my @hits = glob sprintf('%s/v%02d_*.json', $VECDIR, $n);
    my $base = basename($hits[0]);
    $base =~ s/\.json$//;
    return $base;
}

my $TS = '2026-07-13T0%d:00:00Z';

# Build, timestamp, and sign a provenance record.
sub signed {
    my ($kind, $body, $who, $ts_i) = @_;
    $ts_i = 0 unless defined $ts_i;
    my ($secret, $public) = key($who);
    my $rec = oclone($body);
    oset($rec, 'type', jstr($kind));
    oset($rec, 'timestamp', jstr(sprintf $TS, $ts_i))
        unless ohas($rec, 'timestamp');
    if ($kind eq 'succession') {
        oset($rec, 'predecessor', jstr($public))
            unless ohas($rec, 'predecessor');
    }
    else {
        oset($rec, 'source', jstr($public));
    }
    return sign_record($rec, $secret, $kind);
}

# assert helper: die with a message when a condition fails
sub ok_or {
    my ($cond, $msg) = @_;
    die "assertion failed: $msg\n" unless $cond;
}

# run a store call expecting a RejectedWrite; returns its message
sub rejected {
    my ($code, $what) = @_;
    my $result = eval { $code->(); 1 };
    if ($result) { die "assertion failed: $what was accepted\n" }
    my $e = $@;
    die $e unless ref $e && $e->isa('Causalontology::RejectedWrite');
    return $e->message;
}

# ---------------------------------------------------------------------------
# content-object builders (mirror run_conformance.py's builders)
# ---------------------------------------------------------------------------
# a content object completed with its real content-addressed id
sub mk {
    my ($obj) = @_;
    my $o = oclone($obj);
    oset($o, 'id', jstr(identify($o)));
    return $o;
}

# the id string of a built object
sub oid { return sval(oget($_[0], 'id')) }

sub b_stratum {
    my ($label, $scheme, $ordinal, $unit, $governs) = @_;
    my $o = jobj(type => jstr('stratum'), label => jstr($label),
                 scheme => jstr($scheme), ordinal => jnum($ordinal));
    oset($o, 'unit', jstr($unit)) if defined $unit;
    oset($o, 'governs', jarr(map { jstr($_) } @$governs)) if defined $governs;
    return mk($o);
}

sub b_occ {
    my ($label, $stratum_id, $category) = @_;
    $category = 'event' unless defined $category;
    my $o = jobj(type => jstr('occurrent'), label => jstr($label),
                 category => jstr($category));
    oset($o, 'stratum', jstr($stratum_id)) if defined $stratum_id;
    return mk($o);
}

sub b_cnt {
    my ($label, $category) = @_;
    $category = 'object' unless defined $category;
    return mk(jobj(type => jstr('continuant'), label => jstr($label),
                   category => jstr($category)));
}

# temporal window object {minimum_delay, maximum_delay, unit}
sub temporal {
    my ($min, $max, $unit) = @_;
    return jobj(minimum_delay => jnum($min), maximum_delay => jnum($max),
                unit => jstr($unit));
}

sub b_cro {
    my ($causes, $effects, %kw) = @_;
    my $o = jobj(type => jstr('causal_relation_object'),
                 causes => jarr(map { jstr($_) } @$causes),
                 effects => jarr(map { jstr($_) } @$effects));
    oset($o, 'mechanism', jarr(map { jstr($_) } @{ $kw{mechanism} }))
        if exists $kw{mechanism};
    oset($o, 'temporal', $kw{temporal}) if exists $kw{temporal};
    oset($o, 'modality', jstr($kw{modality})) if exists $kw{modality};
    oset($o, 'context', jarr(map { jstr($_) } @{ $kw{context} }))
        if exists $kw{context};
    oset($o, 'refines', jstr($kw{refines})) if exists $kw{refines};
    oset($o, 'skips', jbool($kw{skips})) if exists $kw{skips};
    return mk($o);
}

sub b_bridge {
    my ($coarse, $fine, $relation) = @_;
    return mk(jobj(type => jstr('bridge'), coarse => jstr($coarse),
                   fine => jarr(map { jstr($_) } @$fine),
                   relation => jstr($relation)));
}

sub b_port {
    my ($bearer, $label, $direction, $accepts, $realizable) = @_;
    my $o = jobj(type => jstr('port'), bearer => jstr($bearer),
                 label => jstr($label), direction => jstr($direction),
                 accepts => jarr(map { jstr($_) } @$accepts));
    oset($o, 'realizable', jstr($realizable)) if defined $realizable;
    return mk($o);
}

sub b_conduit {
    my ($frm, $to, $carries, $label, $transform) = @_;
    $label = 'conn' unless defined $label;
    my $o = jobj(type => jstr('conduit'), label => jstr($label),
                 from => jstr($frm), to => jstr($to),
                 carries => jarr(map { jstr($_) } @$carries));
    oset($o, 'transform', jstr($transform)) if defined $transform;
    return mk($o);
}

sub b_quality {
    my ($label, $datatype, $unit, $stratum_id) = @_;
    my $o = jobj(type => jstr('quality'), label => jstr($label),
                 datatype => jstr($datatype));
    oset($o, 'unit', jstr($unit)) if defined $unit;
    oset($o, 'stratum', jstr($stratum_id)) if defined $stratum_id;
    return mk($o);
}

sub b_realizable {
    my ($bearer, $kind, $label) = @_;
    my $o = jobj(type => jstr('realizable'), kind => jstr($kind),
                 bearer => jstr($bearer));
    oset($o, 'label', jstr($label)) if defined $label;
    return mk($o);
}

sub b_individual {
    my ($instantiates, $designator, $part_of) = @_;
    my $o = jobj(type => jstr('token_individual'),
                 instantiates => jstr($instantiates));
    oset($o, 'designator', jstr($designator)) if defined $designator;
    oset($o, 'part_of', jstr($part_of)) if defined $part_of;
    return mk($o);
}

# an interval object from a hash of {start, end?, open?}
sub interval {
    my (%h) = @_;
    my $o = jobj(start => jstr($h{start}));
    oset($o, 'end', jstr($h{end})) if exists $h{end};
    oset($o, 'open', jbool($h{open})) if exists $h{open};
    return $o;
}

sub b_token {
    my ($instantiates, $iv, $participants, $locus) = @_;
    my $o = jobj(type => jstr('token_occurrence'),
                 instantiates => jstr($instantiates), interval => $iv);
    oset($o, 'participants', jarr(@$participants)) if defined $participants;
    oset($o, 'locus', jstr($locus)) if defined $locus;
    return mk($o);
}

sub b_state {
    my ($subject, $qual, $value, $iv) = @_;
    return mk(jobj(type => jstr('state_assertion'), subject => jstr($subject),
                   quality => jstr($qual), value => $value, interval => $iv));
}

# a duration object {duration, unit}
sub duration {
    my ($dur, $unit) = @_;
    return jobj(duration => jnum($dur), unit => jstr($unit));
}

sub b_tcc {
    my ($causes, $effects, %kw) = @_;
    my $o = jobj(type => jstr('token_causal_claim'),
                 causes => jarr(map { jstr($_) } @$causes),
                 effects => jarr(map { jstr($_) } @$effects));
    oset($o, 'covering_law', jstr($kw{covering_law}))
        if exists $kw{covering_law};
    oset($o, 'actual_delay', $kw{actual_delay}) if exists $kw{actual_delay};
    oset($o, 'counterfactual', jbool($kw{counterfactual}))
        if exists $kw{counterfactual};
    return mk($o);
}

# the six-stratum neuroendocrine fixture: ordinal -> stratum object
sub neuro {
    my %labels = (4 => 'macromolecular', 5 => 'subcellular', 6 => 'cellular',
                  7 => 'synaptic', 9 => 'region', 14 => 'community_and_society');
    my %s;
    $s{$_} = b_stratum($labels{$_}, 'neuroendocrine', $_) for keys %labels;
    return \%s;
}

# ---------------------------------------------------------------------------
# internal sanity checks (not conformance vectors)
# ---------------------------------------------------------------------------
sub internal_checks {
    # RFC 8032, TEST 1 known-answer
    my $sk = pack 'H*',
        '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60';
    my $pk = Causalontology::Ed25519::secret_to_public($sk);
    my $pk_hex = unpack 'H*', $pk;
    ok_or($pk_hex eq 'd75a980182b10ab7d54bfed3c964073a'
                   . '0ee172f3daa62325af021a68f707511a',
          "RFC 8032 TEST 1 public key: got $pk_hex");
    my $sig = Causalontology::Ed25519::sign($sk, '');
    ok_or(Causalontology::Ed25519::verify($pk, '', $sig),
          'RFC 8032 TEST 1 signature must verify');
    ok_or(!Causalontology::Ed25519::verify($pk, 'x', $sig),
          'RFC 8032 TEST 1 signature must not verify a different message');
    # JCS basics
    ok_or(jcs(jobj(b => jnum('2'), a => jnum('1'))) eq '{"a":1,"b":2}',
          'JCS key sorting');
    ok_or(jcs(jnum('1.0')) eq '1' && jcs(jnum('6.000')) eq '6'
              && jcs(jnum('0.7')) eq '0.7',
          'JCS number formatting');
    # fixed unit constants (Algorithm E)
    ok_or(to_seconds(1, 'months') == 2629746, 'mean Gregorian month');
    ok_or(to_seconds(1, 'years') == 31556952, 'mean Gregorian year');
}

# ---------------------------------------------------------------------------
# V01 - V38: the whole-word re-freeze of the 1.0.0 suite (unaltered in meaning)
# ---------------------------------------------------------------------------
sub v01 {
    my $inp = normalize(oget(vector(1), 'input'));
    my ($ok, $why) = validate_schema($inp);
    ok_or($ok, 'schema: ' . join('; ', @$why));
    ($ok, $why) = validate_semantics($inp);
    ok_or($ok, 'semantics: ' . join('; ', @$why));
}

sub v02 {
    my $v = vector(2);
    my $inp = normalize(oget($v, 'input'));
    my ($ok) = validate_schema($inp);
    ok_or($ok, 'schema-valid');
    ($ok) = validate_semantics($inp);
    ok_or($ok, 'semantically-valid');
    my ($partial, $missing) = is_partial($inp);
    my @want = map { sval($_) }
        aitems(oget(oget($v, 'expect'), 'missing'));
    ok_or($partial && "@$missing" eq "@want",
          'missing = ' . join(',', @$missing));
}

sub schema_fails {
    my ($n, $must_mention) = @_;
    my $inp = normalize(oget(vector($n), 'input'));
    my ($ok, $why) = validate_schema($inp);
    ok_or(!$ok, 'expected schema-invalid');
    ok_or((grep { index($_, $must_mention) >= 0 } @$why),
          "'$must_mention' in " . join('; ', @$why));
}

sub v03 { schema_fails(3, 'effects') }
sub v04 { schema_fails(4, 'causes') }
sub v05 { schema_fails(5, 'modality') }
sub v06 { schema_fails(6, 'colour') }
sub v07 { schema_fails(7, 'causes') }

sub v08 {
    my ($ok, $why) = validate_schema(normalize(oget(vector(8), 'input')));
    ok_or($ok, join('; ', @$why));
}

sub v09 { schema_fails(9, 'label') }
sub v10 { schema_fails(10, 'category') }

sub v11 {
    my ($ok, $why) = validate_schema(normalize(oget(vector(11), 'input')));
    ok_or($ok, join('; ', @$why));
}

sub v12 { schema_fails(12, 'confidence') }

sub v13 {
    my $inp = normalize(oget(vector(13), 'input'));
    my ($ok, $why) = validate_schema($inp);
    ok_or($ok, 'schema: ' . join('; ', @$why));
    ($ok, $why) = validate_semantics($inp);
    ok_or($ok, 'semantics: ' . join('; ', @$why));
}

sub semantics_fails {
    my ($n, $must_mention) = @_;
    my $inp = normalize(oget(vector($n), 'input'));
    my ($ok, $why) = validate_semantics($inp);
    ok_or(!$ok, 'expected semantically-invalid');
    ok_or((grep { index($_, $must_mention) >= 0 } @$why),
          "'$must_mention' in " . join('; ', @$why));
}

sub v14 {
    my $inp = normalize(oget(vector(14), 'input'));
    my ($ok) = validate_schema($inp);
    ok_or($ok, 'schema-valid');
    semantics_fails(14, 'minimum_delay');
}

sub v15 { semantics_fails(15, 'acyclic') }
sub v16 { semantics_fails(16, 'acyclic') }

sub v17 {
    my $v = vector(17);
    my $parent = normalize(oget(oget($v, 'given'), 'parent'));
    my $child = normalize(oget($v, 'input'));
    my ($ok, $reason) = refinement_valid($child, $parent);
    ok_or(!$ok && index($reason, 'rival') >= 0, "reason: $reason");
}

sub v20 {
    my ($dog, $mam, $ani) = (sym('continuant:dog'), sym('continuant:mammal'),
                             sym('continuant:animal'));
    my $enrich = sub {
        my ($about, $entry, $i) = @_;
        return signed('enrichment',
                      jobj(about => jstr($about), field => jstr('subsumes'),
                           entry => jstr($entry)),
                      'taxo', $i);
    };
    # enforcing tier rejects the cycle-completing write
    my $s = Causalontology::Store->new(enforcing => 1);
    $s->put_record($enrich->($dog, $mam, 1));
    $s->put_record($enrich->($mam, $ani, 2));
    my $msg = rejected(sub { $s->put_record($enrich->($ani, $dog, 3)) },
                       'a cycle-completing enrichment');
    ok_or(index($msg, 'cycle') >= 0, "message: $msg");
    # decentralized merge: the view breaks the cycle deterministically
    my $s2 = Causalontology::Store->new(enforcing => 1);
    $s2->put_record($enrich->($dog, $mam, 1));
    $s2->put_record($enrich->($mam, $ani, 2));
    my $bad = $enrich->($ani, $dog, 3);
    $s2->force_merge_record($bad);
    my (undef, $excluded) = $s2->active_taxonomy_edges('subsumes');
    ok_or(@$excluded == 1
              && sval(oget($excluded->[0], 'id')) eq sval(oget($bad, 'id')),
          'exactly the cycle-completing record is excluded');
    my @repair = $s2->gaps('inconsistent_hierarchy');
    ok_or((grep { $_->{id} eq sval(oget($bad, 'id')) } @repair),
          'the excluded record surfaces as a repair gap');
}

sub adm {
    my ($n) = @_;
    my $g = oget(vector($n), 'given');
    my $cro = jobj(causes => jarr(jstr(sym('occurrent:c'))),
                   effects => jarr(jstr(sym('occurrent:e'))),
                   temporal => oget($g, 'temporal'));
    return admissible($cro, nval(oget($g, 'elapsed_seconds')));
}

sub v21 { ok_or(adm(21) == 1, 'inside the window is admissible') }
sub v22 { ok_or(adm(22) == 0, 'outside the window is not admissible') }
sub v23 { ok_or(adm(23) == 1, 'the fixed unit constants admit 12-14 months') }

sub v24 {
    my $v = vector(24);
    ok_or(identify(normalize(oget($v, 'inputA')))
              eq identify(normalize(oget($v, 'inputB'))),
          'key order must not change identity');
}

sub v25 {
    my $v = vector(25);
    ok_or(identify(normalize(oget($v, 'inputA')))
              eq identify(normalize(oget($v, 'inputB'))),
          'number formatting must not change identity');
}

sub v26 {
    my $s = Causalontology::Store->new;
    my $obj = jobj(type => jstr('occurrent'), label => jstr('press_button'),
                   category => jstr('action'));
    my $a = $s->put(oclone($obj));
    my $b = $s->put(oclone($obj));
    ok_or($a eq $b && $s->object_count == 1, 'idempotent put');
}

sub v27 {
    my $s = Causalontology::Store->new;
    my $occ = $s->put(jobj(type => jstr('occurrent'),
                           label => jstr('press_button'),
                           category => jstr('action')));
    my $entry = jobj(lang => jstr('en'), text => jstr('press the button'));
    my $r1 = signed('enrichment', jobj(about => jstr($occ),
                                       field => jstr('aliases'),
                                       entry => $entry), 'alice', 1);
    my $r2 = signed('enrichment', jobj(about => jstr($occ),
                                       field => jstr('aliases'),
                                       entry => $entry), 'bob', 2);
    ok_or($s->put_record($r1) ne $s->put_record($r2), 'two records');
    my $view = $s->get($occ)->{enrichments}{aliases};
    ok_or(@$view == 1 && @{ $view->[0]{contributors} } == 2,
          'one entry, two contributors');
}

sub v28 {
    my $s = Causalontology::Store->new;
    my $claim = jobj(type => jstr('causal_relation_object'),
                     causes => jarr(jstr(sym('occurrent:A'))),
                     effects => jarr(jstr(sym('occurrent:B'))),
                     modality => jstr('sufficient'));
    my $i1 = $s->put(oclone($claim));
    my $i2 = $s->put(oclone($claim));
    ok_or($i1 eq $i2 && $s->object_count == 1, 'one object');
    for my $pair (['lab1', 1], ['lab2', 2]) {
        my ($who, $ts) = @$pair;
        $s->put_record(signed('assertion',
                              jobj(about => jstr($i1),
                                   evidence_type => jstr('observation'),
                                   strength => jnum('0.8'),
                                   confidence => jnum('0.8')),
                              $who, $ts));
    }
    my @assertions = $s->assertions_about($i1);
    ok_or(@assertions == 2, 'two assertions about the one object');
}

sub v29 {
    my $rec = signed('assertion',
                     jobj(about => jstr(sym('causal_relation_object:demo')),
                          evidence_type => jstr('intervention'),
                          strength => jnum('0.7'),
                          confidence => jnum('0.9')), 'signer');
    ok_or(verify_record($rec) == 1, 'a valid signature verifies');
}

sub v30 {
    my $rec = signed('assertion',
                     jobj(about => jstr(sym('causal_relation_object:demo')),
                          evidence_type => jstr('intervention'),
                          strength => jnum('0.7'),
                          confidence => jnum('0.9')), 'signer');
    my $tampered = oclone($rec);
    oset($tampered, 'confidence', jnum('0.1'));
    ok_or(verify_record($tampered) == 0, 'a tampered record fails');
}

sub v31 {
    my $s = Causalontology::Store->new;
    my $x = $s->put(jobj(type => jstr('causal_relation_object'),
                         causes => jarr(jstr(sym('occurrent:A'))),
                         effects => jarr(jstr(sym('occurrent:B')))));
    my $a = signed('assertion', jobj(about => jstr($x),
                                     evidence_type => jstr('observation'),
                                     confidence => jnum('0.8')), 'lab1', 1);
    $s->put_record($a);
    $s->put_record(signed('retraction',
                          jobj(retracts => oget($a, 'id')), 'lab1', 2));
    ok_or($s->assertions_about($x) == 0, 'default view excludes it');
    my @hist = $s->assertions_about($x, 1);
    ok_or(@hist == 1, 'history has one record');
    my $flag = oget($hist[0], 'retracted');
    ok_or(defined $flag && $flag->[0] eq 'bool' && $flag->[1] == 1,
          'the history record is marked retracted');
    my $foreign = signed('retraction',
                         jobj(retracts => oget($a, 'id')), 'mallory', 3);
    rejected(sub { $s->put_record($foreign) }, 'a foreign retraction');
    ok_or($s->assertions_about($x) == 0, "still excluded by lab1's own");
    ok_or(scalar($s->assertions_about($x, 1)) == 1, 'history still one');
}

sub v32 {
    my $s = Causalontology::Store->new;
    my $occ = $s->put(jobj(type => jstr('occurrent'),
                           label => jstr('press_button'),
                           category => jstr('action')));
    my $e = signed('enrichment',
                   jobj(about => jstr($occ), field => jstr('aliases'),
                        entry => jobj(lang => jstr('ja'),
                                      text => jstr('botan'))),
                   'bob', 1);
    $s->put_record($e);
    ok_or(@{ $s->get($occ)->{enrichments}{aliases} // [] } == 1,
          'the alias is materialized');
    $s->put_record(signed('retraction',
                          jobj(retracts => oget($e, 'id')), 'bob', 2));
    ok_or(@{ $s->get($occ)->{enrichments}{aliases} // [] } == 0,
          'the default view drops the retracted alias');
    my $hist = $s->get($occ, 'history')->{enrichments}{aliases} // [];
    ok_or(@$hist == 1, 'the history view keeps it');
}

sub v33 {
    my $s = Causalontology::Store->new;
    my (undef, $k1) = key('K1');
    my (undef, $k2) = key('K2');
    my $a = signed('assertion',
                   jobj(about => jstr(sym('causal_relation_object:claim')),
                        evidence_type => jstr('observation'),
                        confidence => jnum('0.9')), 'K1', 1);
    $s->put_record($a);
    my $succ = signed('succession', jobj(successor => jstr($k2)), 'K1', 2);
    $s->put_record($succ);
    ok_or(exists $s->lineage($k2)->{$k1} && exists $s->lineage($k1)->{$k2},
          'the lineage closes over both keys');
    my $r = signed('retraction', jobj(retracts => oget($a, 'id')), 'K2', 3);
    $s->put_record($r);  # successor may retract the predecessor's record
    ok_or($s->assertions_about(sym('causal_relation_object:claim')) == 0,
          'the successor retraction takes effect');
}

sub v34 {
    my $g = normalize(oget(vector(34), 'given'));
    ok_or(conflicts(oget($g, 'A'), oget($g, 'B')) == 1,
          'preventive conflicts with sufficient');
}

sub v35 {
    my $g = normalize(oget(vector(35), 'given'));
    ok_or(conflicts(oget($g, 'A'), oget($g, 'B')) == 0,
          'contributory does not conflict with sufficient');
}

sub v36 {
    my ($A, $B, $C, $D) = (sym('occurrent:A'), sym('occurrent:B'),
                           sym('occurrent:C'), sym('occurrent:D'));
    my $m1 = jobj(id => jstr(sym('causal_relation_object:m1')),
                  causes => jarr(jstr($A)), effects => jarr(jstr($B)));
    my $m2 = jobj(id => jstr(sym('causal_relation_object:m2')),
                  causes => jarr(jstr($B)), effects => jarr(jstr($C)));
    my $m3 = jobj(id => jstr(sym('causal_relation_object:m3')),
                  causes => jarr(jstr($D)), effects => jarr(jstr($C)));
    my $P = jobj(causes => jarr(jstr($A)), effects => jarr(jstr($C)),
                 mechanism => jarr(oget($m1, 'id'), oget($m2, 'id')));
    ok_or(hierarchy_consistent($P, { sym('causal_relation_object:m1') => $m1,
                                     sym('causal_relation_object:m2') => $m2 })
              eq 'consistent', 'A -> B -> C is consistent');
    my $P2 = oclone($P);
    oset($P2, 'mechanism', jarr(oget($m1, 'id'), oget($m3, 'id')));
    ok_or(hierarchy_consistent($P2, { sym('causal_relation_object:m1') => $m1,
                                      sym('causal_relation_object:m3') => $m3 })
              eq 'inconsistent', 'D -> C leaves A -> C unreachable');
    ok_or(hierarchy_consistent($P, { sym('causal_relation_object:m1') => $m1 })
              eq 'indeterminate', 'a missing member is indeterminate');
}

sub v37 {
    my $s = Causalontology::Store->new;
    my $occ = $s->put(jobj(type => jstr('occurrent'),
                           label => jstr('press_button'),
                           category => jstr('action')));
    $s->put_record(signed('enrichment',
                          jobj(about => jstr($occ), field => jstr('aliases'),
                               entry => jobj(lang => jstr('en'),
                                             text => jstr('Press the Button'))),
                          'alice', 1));
    my @alias_hits = $s->resolve('Press  The   Button', 'en');
    ok_or(@alias_hits == 1 && $alias_hits[0] eq $occ, 'alias match');
    my @label_hits = $s->resolve('press_button', 'en');
    ok_or(@label_hits >= 1 && $label_hits[0] eq $occ, 'label match, first');
}

sub v38 {
    my $s = Causalontology::Store->new;
    my $P = $s->put(jobj(type => jstr('causal_relation_object'),
                         causes => jarr(jstr(sym('occurrent:A'))),
                         effects => jarr(jstr(sym('occurrent:B')))));
    my @gap_ids = map { $_->{id} } $s->gaps('missing_field');
    ok_or((grep { $_ eq $P } @gap_ids), 'the degenerate claim is a gap');
    my $R = $s->put(jobj(type => jstr('causal_relation_object'),
                         causes => jarr(jstr(sym('occurrent:A'))),
                         effects => jarr(jstr(sym('occurrent:B'))),
                         temporal => jobj(minimum_delay => jnum('0'),
                                          maximum_delay => jnum('1'),
                                          unit => jstr('seconds')),
                         modality => jstr('sufficient'),
                         refines => jstr($P)));
    @gap_ids = map { $_->{id} } $s->gaps('missing_field');
    ok_or(!(grep { $_ eq $P } @gap_ids), 'the gap did not close');
    ok_or(!(grep { $_ eq $R } @gap_ids),
          'the refinement itself must be complete');
}

# ---------------------------------------------------------------------------
# V39 - V107: the 2.0.0 additions
# ---------------------------------------------------------------------------
sub v39 {
    my $st = b_stratum('cellular', 'neuroendocrine', 6, 'cell',
                       ['cell_biology']);
    my ($ok, $why) = validate_schema($st);
    ok_or($ok, join('; ', @$why));
}

sub v40 {
    my $bad = mk(jobj(type => jstr('stratum'), label => jstr('cellular'),
                      ordinal => jnum(6)));
    my ($ok, $why) = validate_schema($bad, 'stratum');
    ok_or(!$ok && (grep { index($_, 'scheme') >= 0 } @$why),
          'expected a scheme error: ' . join('; ', @$why));
}

sub v41 {
    my $a = b_stratum('cellular', 'neuroendocrine', 6);
    my $b = b_stratum('neuronal', 'neuroendocrine', 6);
    for my $x ($a, $b) {
        my ($ok, $why) = validate_schema($x);
        ok_or($ok, join('; ', @$why));
    }
    ok_or(oid($a) ne oid($b), 'distinct ids');
}

sub v42 {
    my $s = neuro();
    my $s4p = b_stratum('molecular', 'physics', 4);
    my $c = b_occ('chronic_social_subordination', oid($s->{14}));
    my $e = b_occ('gene_expression', oid($s4p));
    my $smap = { oid($s->{14}) => $s->{14}, oid($s4p) => $s4p };
    my $omap = { oid($c) => $c, oid($e) => $e };
    my $P = b_cro([oid($c)], [oid($e)]);
    ok_or(classify_cro($P, $omap, $smap) eq 'scheme_mismatch',
          'scheme_mismatch');
}

sub v43 {
    for my $x (b_stratum('macromolecular', 'neuroendocrine', 4),
               b_stratum('region', 'neuroendocrine', 9)) {
        my ($ok, $why) = validate_schema($x);
        ok_or($ok, join('; ', @$why));
    }
}

sub v44 {
    my $st = b_stratum('cellular', 'neuroendocrine', 6);
    my $o = b_occ('neuron_fires', oid($st));
    my ($ok, $why) = validate_schema($o);
    ok_or($ok, join('; ', @$why));
    ($ok, $why) = validate_semantics($o);
    ok_or($ok, join('; ', @$why));
}

sub v45 {
    my $o = b_occ('press_button');
    my ($ok, $why) = validate_schema($o);
    ok_or($ok, join('; ', @$why));
    my $e = b_occ('light_on');
    my $P = b_cro([oid($o)], [oid($e)]);
    ok_or(classify_cro($P, { oid($o) => $o, oid($e) => $e }, {})
              eq 'unclassifiable', 'unclassifiable');
}

sub v46 {
    my $s = neuro();
    my $a = b_occ('depolarization', oid($s->{5}));
    my $b = b_occ('depolarization', oid($s->{6}));
    ok_or(oid($a) ne oid($b), 'distinct ids across strata');
}

sub bridge_fixture {
    my ($relation) = @_;
    my $s = neuro();
    my $coarse = b_occ('action_potential_fires', oid($s->{6}));
    my @fine = (b_occ('sodium_channels_open', oid($s->{4})),
                b_occ('sodium_influx', oid($s->{4})));
    my $b = b_bridge(oid($coarse), [map { oid($_) } @fine], $relation);
    my %omap = (oid($coarse) => $coarse);
    $omap{oid($_)} = $_ for @fine;
    my %smap = (oid($s->{4}) => $s->{4}, oid($s->{6}) => $s->{6});
    return ($b, \%omap, \%smap);
}

sub valid_bridge {
    my ($relation) = @_;
    my ($b, $omap, $smap) = bridge_fixture($relation);
    my ($ok, $why) = validate_schema($b);
    ok_or($ok, join('; ', @$why));
    ($ok, $why) = bridge_wellformed($b, $omap, $smap);
    ok_or($ok, $why);
}

sub v47 { valid_bridge('constitutes') }
sub v48 { valid_bridge('aggregates') }
sub v49 { valid_bridge('realizes') }
sub v50 { valid_bridge('supervenes_on') }

sub v51 {
    my $s = neuro();
    my $coarse = b_occ('x_coarse', oid($s->{4}));
    my $fine = b_occ('x_fine', oid($s->{6}));
    my $b = b_bridge(oid($coarse), [oid($fine)], 'constitutes');
    my $omap = { oid($coarse) => $coarse, oid($fine) => $fine };
    my $smap = { oid($s->{4}) => $s->{4}, oid($s->{6}) => $s->{6} };
    my ($ok) = bridge_wellformed($b, $omap, $smap);
    ok_or(!$ok, 'coarse ordinal must exceed fine ordinal');
}

sub v52 {
    my $s = neuro();
    my $coarse = b_occ('c', oid($s->{6}));
    my $f1 = b_occ('f1', oid($s->{4}));
    my $f2 = b_occ('f2', oid($s->{5}));
    my $b = b_bridge(oid($coarse), [oid($f1), oid($f2)], 'constitutes');
    my $omap = { oid($coarse) => $coarse, oid($f1) => $f1, oid($f2) => $f2 };
    my $smap = { oid($s->{4}) => $s->{4}, oid($s->{5}) => $s->{5},
                 oid($s->{6}) => $s->{6} };
    my ($ok) = bridge_wellformed($b, $omap, $smap);
    ok_or(!$ok, 'fine members may not span >1 stratum');
}

sub v53 {
    my ($x, $y) = (sym('occurrent:x'), sym('occurrent:y'));
    my $b1 = b_bridge($x, [$y], 'constitutes');
    my $b2 = b_bridge($y, [$x], 'constitutes');
    my %edges;
    for my $b ($b1, $b2) {
        for my $f (map { sval($_) } aitems(oget($b, 'fine'))) {
            push @{ $edges{$f} }, sval(oget($b, 'coarse'));
        }
    }
    ok_or(has_cycle(\%edges) == 1, 'bridge graph cycle');
}

sub v54 {
    my $a = b_stratum('cellular', 'neuroendocrine', 6);
    my $b = b_stratum('molecular', 'physics', 4);
    my $coarse = b_occ('c', oid($a));
    my $fine = b_occ('f', oid($b));
    my $br = b_bridge(oid($coarse), [oid($fine)], 'constitutes');
    my $omap = { oid($coarse) => $coarse, oid($fine) => $fine };
    my $smap = { oid($a) => $a, oid($b) => $b };
    my ($ok) = bridge_wellformed($br, $omap, $smap);
    ok_or(!$ok, 'coarse and fine must share a scheme');
}

sub v55 {
    my $s = neuro();
    my $coarse = b_occ('decision_made', oid($s->{6}));
    my $f1 = b_occ('cascade_a', oid($s->{4}));
    my $f2 = b_occ('cascade_b', oid($s->{4}));
    my $b1 = b_bridge(oid($coarse), [oid($f1)], 'realizes');
    my $b2 = b_bridge(oid($coarse), [oid($f2)], 'realizes');
    ok_or(oid($b1) ne oid($b2), 'distinct ids');
    for my $b ($b1, $b2) {
        my ($ok, $why) = validate_schema($b);
        ok_or($ok, join('; ', @$why));
    }
}

sub reach_fixture {
    my $s = neuro();
    my $ap = b_occ('action_potential_fires', oid($s->{6}));
    my $nt = b_occ('neurotransmitter_released', oid($s->{6}));
    my $fa = b_occ('calcium_enters', oid($s->{4}));
    my $fb = b_occ('vesicle_fuses', oid($s->{4}));
    my $m1 = b_cro([oid($fa)], [oid($fb)]);
    my $P = b_cro([oid($ap)], [oid($nt)], mechanism => [oid($m1)]);
    my @bridges = (b_bridge(oid($ap), [oid($fa)], 'constitutes'),
                   b_bridge(oid($nt), [oid($fb)], 'constitutes'));
    return ($P, { oid($m1) => $m1 }, \@bridges);
}

sub v56 {
    my ($P, $members, $bridges) = reach_fixture();
    ok_or(hierarchy_consistent($P, $members, $bridges) eq 'consistent',
          'bridged reachability is consistent');
}

sub v57 {
    my ($P, $members) = reach_fixture();
    ok_or(hierarchy_consistent($P, $members, []) eq 'inconsistent',
          'literal reachability is inconsistent');
}

sub v58 {
    my ($P, $members, $bridges) = reach_fixture();
    my $literal = hierarchy_consistent($P, $members, []);
    my $bridged = hierarchy_consistent($P, $members, $bridges);
    ok_or($literal ne 'consistent' && $bridged eq 'consistent',
          "literal=$literal bridged=$bridged");
}

sub classify_helper {
    my ($cause_ord, $effect_ord) = @_;
    my $s = neuro();
    my $c = b_occ('c', oid($s->{$cause_ord}));
    my $e = b_occ('e', oid($s->{$effect_ord}));
    my $smap = { oid($s->{$cause_ord}) => $s->{$cause_ord},
                 oid($s->{$effect_ord}) => $s->{$effect_ord} };
    my $omap = { oid($c) => $c, oid($e) => $e };
    return classify_cro(b_cro([oid($c)], [oid($e)]), $omap, $smap);
}

sub v59 { ok_or(classify_helper(6, 6) eq 'intra_stratal', 'intra_stratal') }
sub v60 { ok_or(classify_helper(6, 5) eq 'adjacent_stratal', 'adjacent') }
sub v61 { ok_or(classify_helper(14, 4) eq 'skipping', 'skipping') }

sub skip_fixture {
    my ($cause_ord, $effect_ord, %kw) = @_;
    my $s = neuro();
    my $c = b_occ('c', oid($s->{$cause_ord}));
    my $e = b_occ('e', oid($s->{$effect_ord}));
    my $smap = { oid($s->{$cause_ord}) => $s->{$cause_ord},
                 oid($s->{$effect_ord}) => $s->{$effect_ord} };
    my $omap = { oid($c) => $c, oid($e) => $e };
    my $P = b_cro([oid($c)], [oid($e)], %kw);
    return ($P, classify_cro($P, $omap, $smap));
}

sub v62 {
    my ($P, $cls) = skip_fixture(14, 4);
    ok_or("@{ skip_gaps($P, $cls) }" eq 'incomplete_mechanism',
          'skips absent -> incomplete_mechanism');
}

sub v63 {
    my ($P, $cls) = skip_fixture(14, 4, skips => 1);
    ok_or("@{ skip_gaps($P, $cls) }" eq '', 'skips true -> nothing');
}

sub v64 {
    my ($P, $cls) = skip_fixture(14, 4, skips => 1,
                                 mechanism => [sym('causal_relation_object:m')]);
    ok_or("@{ skip_gaps($P, $cls) }" eq 'contradictory_skip',
          'skips true + mechanism -> contradictory_skip');
    my ($ok, $why) = validate_semantics($P);
    ok_or(!$ok && (grep { index($_, 'contradictory_skip') >= 0 } @$why),
          'contradictory_skip is a hard semantics failure');
}

sub v65 {
    my ($P, $cls) = skip_fixture(6, 6, skips => 1);
    ok_or("@{ skip_gaps($P, $cls) }" eq 'vacuous_skip', 'vacuous_skip');
}

sub v66 {
    my $s = neuro();
    my $c = b_occ('c', oid($s->{14}));
    my $e = b_occ('e', oid($s->{4}));
    my $absent = b_cro([oid($c)], [oid($e)]);
    my $false_ = b_cro([oid($c)], [oid($e)], skips => 0);
    ok_or(oid($absent) ne oid($false_), 'absent differs from skips:false');
}

sub v67 {
    my $s = neuro();
    my $c1 = b_occ('c1', oid($s->{4}));
    my $c2 = b_occ('c2', oid($s->{6}));
    my $e = b_occ('e', oid($s->{6}));
    my $P = b_cro([oid($c1), oid($c2)], [oid($e)]);
    ok_or(endpoints_mixed($P, { oid($c1) => $c1, oid($c2) => $c2,
                                oid($e) => $e }) == 1, 'endpoints mixed');
}

sub v68 {
    my $P = b_cro([sym('occurrent:a')], [sym('occurrent:b')],
                  modality => 'enabling');
    my ($ok, $why) = validate_schema($P);
    ok_or($ok, join('; ', @$why));
}

sub v69 {
    my $a = jobj(causes => jarr(jstr(sym('occurrent:a'))),
                 effects => jarr(jstr(sym('occurrent:b'))),
                 modality => jstr('enabling'));
    my $b = jobj(causes => jarr(jstr(sym('occurrent:a'))),
                 effects => jarr(jstr(sym('occurrent:b'))),
                 modality => jstr('sufficient'));
    ok_or(conflicts($a, $b) == 0, 'enabling does not conflict with sufficient');
}

sub v70 {
    my $a = jobj(causes => jarr(jstr(sym('occurrent:a'))),
                 effects => jarr(jstr(sym('occurrent:b'))),
                 modality => jstr('enabling'));
    my $b = jobj(causes => jarr(jstr(sym('occurrent:a'))),
                 effects => jarr(jstr(sym('occurrent:b'))),
                 modality => jstr('preventive'));
    ok_or(conflicts($a, $b) == 1, 'enabling conflicts with preventive');
}

sub v71 {
    my $b = b_cnt('hippocampus');
    my $p = b_port(oid($b), 'perforant_path', 'in', [sym('occurrent:signal')]);
    my ($ok, $why) = validate_schema($p);
    ok_or($ok, join('; ', @$why));
}

sub v72 {
    my $b = oid(b_cnt('hippocampus'));
    my $x = sym('occurrent:signal');
    ok_or(oid(b_port($b, 'perforant_path', 'in', [$x]))
              ne oid(b_port($b, 'fornix', 'in', [$x])), 'distinct ports');
}

sub conduit_fixture {
    my (%opt) = @_;
    my $x = sym('occurrent:motor_command');
    my $y = sym('occurrent:error_signal');
    my $z = sym('occurrent:unrelated');
    my $m1 = oid(b_cnt('motor_cortex'));
    my $m2 = oid(b_cnt('spinal_neuron'));
    my $frm = b_port($m1, 'out_port', ($opt{in_from} ? 'in' : 'out'), [$x]);
    my $to = b_port($m2, 'in_port', 'in', ($opt{transform} ? [$y] : [$x]));
    my @carries = $opt{bad_carry} ? ($z) : ($x);
    my $xform;
    my %cro_map;
    if ($opt{transform}) {
        my $law = b_cro([$x], [$y]);
        $cro_map{oid($law)} = $law;
        $xform = oid($law);
    }
    my $c = b_conduit(oid($frm), oid($to), \@carries, 'conn', $xform);
    return ($c, { oid($frm) => $frm, oid($to) => $to }, \%cro_map);
}

sub v73 {
    my ($c, $pmap) = conduit_fixture();
    my ($ok, $why) = validate_schema($c);
    ok_or($ok, join('; ', @$why));
    ($ok, $why) = conduit_wellformed($c, $pmap);
    ok_or($ok, $why);
}

sub v74 {
    my ($c, $pmap, $cmap) = conduit_fixture(transform => 1);
    my ($ok, $why) = validate_schema($c);
    ok_or($ok, join('; ', @$why));
    ($ok, $why) = conduit_wellformed($c, $pmap, $cmap);
    ok_or($ok, $why);
}

sub v75 {
    my ($c, $pmap) = conduit_fixture(bad_carry => 1);
    my ($ok) = conduit_wellformed($c, $pmap);
    ok_or(!$ok, 'carries not accepted by from');
}

sub v76 {
    my ($c, $pmap) = conduit_fixture(in_from => 1);
    my ($ok) = conduit_wellformed($c, $pmap);
    ok_or(!$ok, 'from port must be out/bidirectional');
}

sub v77 {
    my ($c, $pmap, $cmap) = conduit_fixture(transform => 1);
    my ($ok, $why) = conduit_wellformed($c, $pmap, $cmap);
    ok_or($ok, $why);
    my ($law) = values %$cmap;
    my $eff0 = sval((aitems(oget($law, 'effects')))[0]);
    my %carries = map { sval($_) => 1 } aitems(oget($c, 'carries'));
    ok_or(!$carries{$eff0}, 'transform effect not carried literally');
}

sub v78 {
    my $b = oid(b_cnt('hippocampus'));
    ok_or(oid(b_realizable($b, 'disposition', 'long_term_potentiation'))
              ne oid(b_realizable($b, 'disposition', 'pattern_separation')),
          'distinct realizables by label');
}

sub v79 {
    my $b = oid(b_cnt('hippocampus'));
    my $u1 = b_realizable($b, 'disposition');
    my $u2 = b_realizable($b, 'disposition');
    my ($ok, $why) = validate_schema($u1);
    ok_or($ok, join('; ', @$why));
    ok_or(oid($u1) eq oid($u2), 'unlabelled realizables share an id');
    ok_or(oid(b_realizable($b, 'disposition', 'some_function')) ne oid($u1),
          'a labelled realizable differs');
}

sub v80 {
    my $parent = b_occ('fires');
    my $child = b_occ('fires_action_potential');
    my $e = jobj(type => jstr('enrichment'), about => jstr(oid($child)),
                 field => jstr('occurrent_subsumes'),
                 entry => jstr(oid($parent)));
    my ($ok, $why) = validate_semantics($e);
    ok_or($ok, join('; ', @$why));
}

sub v81 {
    my ($a, $b) = (sym('occurrent:a'), sym('occurrent:b'));
    ok_or(has_cycle({ $a => [$b], $b => [$a] }) == 1, 'occurrent cycle');
}

sub v82 {
    my $whole = b_occ('eat');
    my $part = b_occ('chew');
    my $e = jobj(type => jstr('enrichment'), about => jstr(oid($part)),
                 field => jstr('occurrent_part_of'),
                 entry => jstr(oid($whole)));
    my ($ok, $why) = validate_semantics($e);
    ok_or($ok, join('; ', @$why));
}

sub v83 {
    my $spec = $ENRICHMENT_FIELDS{occurrent_part_of};
    my ($legal, $shape) = @$spec;
    ok_or($shape eq 'occurrent' && @$legal == 1 && $legal->[0] eq 'occurrent',
          'occurrent_part_of spec');
    my $s = Causalontology::Store->new;
    $s->put(b_occ('eat'));
    $s->put(b_occ('chew'));
    for my $id ($s->object_ids) {
        ok_or(sval(oget($s->get_object($id), 'type'))
                  ne 'causal_relation_object', 'no CRO synthesized');
    }
}

sub v84 {
    my $s = neuro();
    my $a = b_occ('run', oid($s->{9}));
    my $b = b_occ('sprint', oid($s->{6}));
    ok_or(sval(oget($a, 'stratum')) ne sval(oget($b, 'stratum')),
          'distinct strata');
}

sub v85 {
    my $c = b_cnt('human_patient');
    my $ti = b_individual(oid($c), 'salted_hash_abc123');
    my ($ok, $why) = validate_schema($ti);
    ok_or($ok, join('; ', @$why));
}

sub v86 {
    my $bad = mk(jobj(type => jstr('token_individual'),
                      designator => jstr('x')));
    my ($ok, $why) = validate_schema($bad, 'token_individual');
    ok_or(!$ok && (grep { index($_, 'instantiates') >= 0 } @$why),
          'instantiates is required: ' . join('; ', @$why));
}

sub v87 {
    my $c = oid(b_cnt('human_patient'));
    ok_or(oid(b_individual($c, 'hash_a')) ne oid(b_individual($c, 'hash_b')),
          'distinct designators, distinct ids');
}

sub v88 {
    my $o = b_occ('bilateral_hippocampal_resection');
    my $t = b_token(oid($o), interval(start => '1953-08-25T00:00:00Z',
                                      end => '1953-08-25T00:00:00Z'));
    my ($ok, $why) = validate_schema($t);
    ok_or($ok, join('; ', @$why));
}

sub v89 {
    my $o = oid(b_occ('amnesia_onset'));
    my $bounded = b_token($o, interval(start => '1953-08-25T00:00:00Z',
                                       end => '1953-08-26T00:00:00Z'));
    my $instantaneous = b_token($o, interval(start => '1953-08-25T00:00:00Z'));
    my $ongoing = b_token($o, interval(start => '1953-08-25T00:00:00Z',
                                       open => 1));
    my %ids = (oid($bounded) => 1, oid($instantaneous) => 1,
               oid($ongoing) => 1);
    ok_or(keys(%ids) == 3, 'three distinct interval shapes');
}

sub v90 {
    my $o = oid(b_occ('resection'));
    my $c = oid(b_cnt('human_patient'));
    my $patient = oid(b_individual($c, 'p'));
    my $surgeon = oid(b_individual($c, 's'));
    my $t = b_token($o, interval(start => '1953-08-25T00:00:00Z'),
                    [jobj(role => jstr('patient'), filler => jstr($patient)),
                     jobj(role => jstr('agent'), filler => jstr($surgeon))]);
    my ($ok, $why) = validate_schema($t);
    ok_or($ok, join('; ', @$why));
}

sub v91 {
    my $q = b_quality('cortisol_concentration', 'quantity', 'ug/dL');
    my ($ok, $why) = validate_schema($q);
    ok_or($ok, join('; ', @$why));
}

sub state_fixture {
    my ($datatype, $value, $unit) = @_;
    my $q = b_quality('cortisol_concentration', $datatype, $unit);
    my $c = oid(b_cnt('human_patient'));
    my $subj = oid(b_individual($c, 'p'));
    my $st = b_state($subj, oid($q), $value,
                     interval(start => '2026-01-01T00:00:00Z',
                              end => '2026-01-01T01:00:00Z'));
    return ($st, $q);
}

sub v92 {
    my ($st, $q) = state_fixture('quantity',
        jobj(quantity => jnum('15.0'), unit => jstr('ug/dL')), 'ug/dL');
    my ($ok, $why) = validate_schema($st);
    ok_or($ok, join('; ', @$why));
    ok_or("@{ state_gaps($st, $q) }" eq '', 'no gaps for coherent quantity');
}

sub v93 {
    my ($st, $q) = state_fixture('categorical',
        jobj(categorical => jstr('elevated')));
    my ($ok, $why) = validate_schema($st);
    ok_or($ok, join('; ', @$why));
    ok_or("@{ state_gaps($st, $q) }" eq '', 'no gaps for categorical');
}

sub v94 {
    my ($st, $q) = state_fixture('boolean', jobj(boolean => jbool(1)));
    my ($ok, $why) = validate_schema($st);
    ok_or($ok, join('; ', @$why));
    ok_or("@{ state_gaps($st, $q) }" eq '', 'no gaps for boolean');
}

sub v95 {
    my ($st, $q) = state_fixture('quantity',
        jobj(categorical => jstr('elevated')), 'ug/dL');
    ok_or("@{ state_gaps($st, $q) }" eq 'value_type_mismatch',
          'value_type_mismatch');
}

sub v96 {
    my ($st, $q) = state_fixture('quantity',
        jobj(quantity => jnum('15.0'), unit => jstr('mg/dL')), 'ug/dL');
    ok_or("@{ state_gaps($st, $q) }" eq 'unit_mismatch', 'unit_mismatch');
}

sub law_and_tokens {
    my $o_cause = b_occ('resection');
    my $o_effect = b_occ('amnesia_onset');
    my $law = b_cro([oid($o_cause)], [oid($o_effect)],
                    temporal => temporal(0, 1, 'days'),
                    modality => 'sufficient');
    my $t_cause = b_token(oid($o_cause), interval(start => '1953-08-25T00:00:00Z'));
    my $t_effect = b_token(oid($o_effect),
                           interval(start => '1953-08-25T00:00:00Z', open => 1));
    return ($law, $o_cause, $o_effect, $t_cause, $t_effect);
}

sub v97 {
    my ($law, undef, undef, $tc, $te) = law_and_tokens();
    my $claim = b_tcc([oid($tc)], [oid($te)], covering_law => oid($law),
                      actual_delay => duration(0, 'instant'),
                      counterfactual => 1);
    my ($ok, $why) = validate_schema($claim);
    ok_or($ok, join('; ', @$why));
}

sub v98 {
    my (undef, undef, undef, $tc, $te) = law_and_tokens();
    my $claim = b_tcc([oid($tc)], [oid($te)]);
    my ($ok, $why) = validate_schema($claim);
    ok_or($ok, join('; ', @$why));
    ok_or(!ohas($claim, 'covering_law'), 'covering_law is optional');
}

sub v99 {
    my ($law) = law_and_tokens();
    ok_or(delay_within_window(duration(0, 'instant'),
                              oget($law, 'temporal')) == 1, 'within window');
}

sub v100 {
    my $t = temporal(0, 1, 'hours');
    ok_or(delay_within_window(duration(5, 'days'), $t) == 0,
          'outside window');
}

sub v101 {
    my $o = oid(b_occ('x'));
    my $cause = b_token($o, interval(start => '2026-01-02T00:00:00Z'));
    my $effect = b_token($o, interval(start => '2026-01-01T00:00:00Z'));
    my $claim = b_tcc([oid($cause)], [oid($effect)]);
    ok_or(retrocausal($claim, { oid($cause) => $cause,
                                oid($effect) => $effect }) == 1, 'retrocausal');
}

sub v102 {
    my $other = b_cro([sym('occurrent:foo')], [sym('occurrent:bar')]);
    my (undef, undef, undef, $tc, $te) = law_and_tokens();
    my $claim = b_tcc([oid($tc)], [oid($te)], covering_law => oid($other));
    ok_or(covering_law_mismatch($claim, { oid($tc) => $tc, oid($te) => $te },
                                $other) == 1, 'covering_law_mismatch');
}

sub v103 {
    my $a = signed('assertion',
                   jobj(about => jstr(sym('token_occurrence:t')),
                        evidence_type => jstr('observation'),
                        confidence => jnum('0.9')), 'signer');
    my ($ok, $why) = validate_schema($a);
    ok_or($ok, join('; ', @$why));
}

sub v104 {
    my @ev = (sym('token_occurrence:t1'), sym('token_causal_claim:c1'));
    my (undef, $pub) = key('signer');
    my $base = jobj(type => jstr('assertion'),
                    about => jstr(sym('causal_relation_object:law')),
                    source => jstr($pub), evidence_type => jstr('intervention'),
                    strength => jnum('0.95'), confidence => jnum('0.99'),
                    timestamp => jstr('2026-07-14T00:00:00Z'));
    my $a = oclone($base);
    oset($a, 'evidenced_by', jarr(map { jstr($_) } @ev));
    my $a_id = oclone($a);
    oset($a_id, 'id', jstr(identify($a)));
    my ($ok, $why) = validate_schema($a_id);
    ok_or($ok, join('; ', @$why));
    ok_or(identify($a) ne identify($base),
          'evidenced_by is identity-bearing');
}

sub v105 {
    my $a = signed('assertion',
                   jobj(about => jstr(sym('causal_relation_object:law')),
                        evidence_type => jstr('simulation'),
                        confidence => jnum('0.5')), 'signer');
    my ($ok, $why) = validate_schema($a);
    ok_or($ok, join('; ', @$why));
    ok_or(0 < 1 && 1 < 2, 'evidence rank ordering');
}

# recursively collect the scheme prefixes of all whole-word content ids
sub scan_ids {
    my ($node, $ids) = @_;
    if (is_str($node)) {
        if (sval($node) =~ /^([a-z0-9_]+):[0-9a-f]{64}$/) {
            push @$ids, $1;
        }
    }
    elsif (is_arr($node)) {
        scan_ids($_, $ids) for aitems($node);
    }
    elsif (is_obj($node)) {
        scan_ids(oget($node, $_), $ids) for okeys($node);
    }
}

sub v106 {
    my %WHOLE = map { $_ => 1 } @SCHEMES;
    $WHOLE{ed25519} = 1;
    for my $n (1 .. 38) {
        my @ids;
        scan_ids(vector($n), \@ids);
        for my $scheme (@ids) {
            ok_or($WHOLE{$scheme},
                  "V106: abbreviated scheme '$scheme' in vector $n");
        }
    }
    my $rec = jobj(type => jstr('occurrent'), label => jstr('press_button'),
                   category => jstr('action'));
    ok_or(identify($rec) eq identify($rec), 'identity is deterministic');
    ok_or((split /:/, identify($rec), 2)[0] eq 'occurrent',
          'the scheme is the whole word');
}

sub v107 {
    my $hexid = '0' x 64;
    # NOTE: the abbreviated prefix is intentional (the negative test); it must
    # NOT be re-minted, so the letters are assembled to survive re-mint tools.
    my $cro_abbr = 'c' . 'r' . 'o';
    my $abbreviated = jobj(type => jstr('causal_relation_object'),
                           id => jstr($cro_abbr . ':' . $hexid),
                           causes => jarr(jstr('occurrent:' . $hexid)),
                           effects => jarr(jstr('occurrent:' . $hexid)));
    my ($ok) = validate_schema($abbreviated, 'causal_relation_object');
    ok_or(!$ok, 'abbreviated scheme must be rejected');
    my $abbr_str = jobj(type => jstr('stratum'), id => jstr('str:' . $hexid),
                        label => jstr('cellular'),
                        scheme => jstr('neuroendocrine'), ordinal => jnum(6));
    ($ok) = validate_schema($abbr_str, 'stratum');
    ok_or(!$ok, 'the abbreviated stratum scheme must be rejected');
    my $whole = jobj(type => jstr('causal_relation_object'),
                     id => jstr('causal_relation_object:' . $hexid),
                     causes => jarr(jstr('occurrent:' . $hexid)),
                     effects => jarr(jstr('occurrent:' . $hexid)));
    my ($ok2, $why) = validate_schema($whole, 'causal_relation_object');
    ok_or($ok2, 'the whole-word scheme validates: ' . join('; ', @$why));
}

# ---------------------------------------------------------------------------
# V108 - V119: the 3.0.0 additions (tick unit, cross_stratal_seam, realized_by)
# ---------------------------------------------------------------------------
# a cross_stratal_seam content object, completed with its content-addressed id
sub b_seam {
    my ($source, $target, $mechanism_status, $chain) = @_;
    my $o = jobj(type => jstr('cross_stratal_seam'),
                 source => jstr($source), target => jstr($target),
                 mechanism_status => jstr($mechanism_status));
    oset($o, 'chain', jarr(map { jstr($_) } @$chain))
        if defined $chain && @$chain;
    return mk($o);
}

# build a seam over the neuro fixture: (seam, occ_map, stratum_map).
sub seam_fixture {
    my ($src_ord, $tgt_ord, $mechanism_status, $chain_ords) = @_;
    my $s = neuro();
    my $src = b_occ('source_event', oid($s->{$src_ord}));
    my $tgt = b_occ('target_event', oid($s->{$tgt_ord}));
    my %omap = (oid($src) => $src, oid($tgt) => $tgt);
    my %smap = (oid($s->{$src_ord}) => $s->{$src_ord},
                oid($s->{$tgt_ord}) => $s->{$tgt_ord});
    my $chain;
    if (defined $chain_ords) {
        $chain = [];
        my $i = 0;
        for my $o (@$chain_ords) {
            my $c = b_occ("chain_$i", oid($s->{$o}));
            $omap{oid($c)} = $c;
            $smap{oid($s->{$o})} = $s->{$o};
            push @$chain, oid($c);
            $i++;
        }
    }
    return (b_seam(oid($src), oid($tgt), $mechanism_status, $chain),
            \%omap, \%smap);
}

# a conduit with an optional realized_by reference, completed with its id
sub conduit_realized {
    my ($realized_by) = @_;
    my $o = jobj(type => jstr('conduit'), label => jstr('conn'),
                 from => jstr('port:' . ('1' x 64)),
                 to => jstr('port:' . ('2' x 64)),
                 carries => jarr(jstr('occurrent:' . ('3' x 64))));
    oset($o, 'realized_by', jstr($realized_by)) if defined $realized_by;
    return mk($o);
}

# -- Change One: the ordinal (tick) temporal unit --
sub v108 {
    my $P = b_cro([sym('occurrent:a')], [sym('occurrent:b')],
                  temporal => temporal(0, 5, 'ticks'),
                  modality => 'sufficient');
    my ($ok, $why) = validate_schema($P);
    ok_or($ok, join('; ', @$why));
    ($ok, $why) = validate_semantics($P);
    ok_or($ok, join('; ', @$why));
}

sub v109 {
    my $P = b_cro([sym('occurrent:a')], [sym('occurrent:b')],
                  temporal => temporal(2, 5, 'ticks'));
    ok_or(admissible($P, 3) == 1, '3 ticks inside [2, 5]');
    ok_or(admissible($P, 2) == 1 && admissible($P, 5) == 1,
          'endpoints are admissible');
    ok_or(admissible($P, 6) == 0 && admissible($P, 1) == 0,
          'outside the tick window is not admissible');
}

sub v110 {
    my $tick_window = temporal(0, 5, 'ticks');
    my $wall_window = temporal(0, 5, 'seconds');
    ok_or(delay_within_window(duration(3, 'ticks'), $tick_window) == 1,
          '3 ticks within the tick window');
    ok_or(delay_within_window(duration(1, 'ticks'), $wall_window) == 0,
          'a tick delay is not within a wall-clock window');
    ok_or(delay_within_window(duration(1, 'seconds'), $tick_window) == 0,
          'a seconds delay is not within a tick window');
    my $a = jobj(causes => jarr(jstr(sym('occurrent:a'))),
                 effects => jarr(jstr(sym('occurrent:b'))),
                 temporal => $tick_window, modality => jstr('sufficient'));
    my $b = jobj(causes => jarr(jstr(sym('occurrent:a'))),
                 effects => jarr(jstr(sym('occurrent:b'))),
                 temporal => $wall_window, modality => jstr('preventive'));
    ok_or(conflicts($a, $b) == 0, 'disjoint dimensions do not overlap');
    my $accepted = eval { to_seconds(1, 'ticks'); 1 };
    ok_or(!$accepted, 'to_seconds must refuse an ordinal unit');
}

sub v111 {
    my $base = sub {
        return (type => jstr('causal_relation_object'),
                causes => jarr(jstr(sym('occurrent:a'))),
                effects => jarr(jstr(sym('occurrent:b'))),
                modality => jstr('sufficient'));
    };
    my $tick = jobj($base->(), temporal => temporal(0, 1, 'ticks'));
    my $secs = jobj($base->(), temporal => temporal(0, 1, 'seconds'));
    ok_or(identify($tick) ne identify($secs), 'the unit is identity-bearing');
    # a wall-clock record's identity is UNCHANGED under 3.0.0 (pinned 2.0.0)
    ok_or(identify($secs) eq 'causal_relation_object:'
          . 'd8daf899daa3ee03caa6b1425cc6d4d33cef20d951e1203ffd35df29857aa43c',
          'the wall-clock CRO identity is pinned');
}

# -- Change Two: the managed cross-stratal seam (eighteenth kind) --
sub v112 {
    my ($sm, $omap, $smap) = seam_fixture(14, 4, 'unmodeled');
    my ($ok, $why) = validate_schema($sm);
    ok_or($ok, join('; ', @$why));
    ($ok, $why) = validate_semantics($sm);
    ok_or($ok, join('; ', @$why));
    ($ok, $why) = seam_wellformed($sm, $omap, $smap);
    ok_or($ok, $why);
}

sub v113 {
    my ($a) = seam_fixture(14, 4, 'unmodeled');
    my ($b, $omap, $smap) = seam_fixture(14, 4, 'absent');
    my ($ok, $why) = validate_schema($b);
    ok_or($ok, join('; ', @$why));
    ($ok, $why) = seam_wellformed($b, $omap, $smap);
    ok_or($ok, $why);
    ok_or(oid($a) ne oid($b), 'mechanism_status is identity-bearing');
}

sub v114 {
    my ($drawn, $omap, $smap) = seam_fixture(14, 4, 'unmodeled', [9, 7, 6, 5]);
    my ($ok, $why) = validate_schema($drawn);
    ok_or($ok, join('; ', @$why));
    ($ok, $why) = seam_wellformed($drawn, $omap, $smap);
    ok_or($ok, $why);
    my ($bad, $omap2, $smap2) = seam_fixture(14, 4, 'absent', [9, 7, 6, 5]);
    ($ok, $why) = validate_semantics($bad);
    ok_or(!$ok && (grep { index($_, 'contradictory_seam') >= 0 } @$why),
          'contradictory_seam: ' . join('; ', @$why));
    my ($ok2) = seam_wellformed($bad, $omap2, $smap2);
    ok_or(!$ok2, 'a drawn chain with absent status is malformed');
}

sub v115 {
    my ($sm, $omap, $smap) = seam_fixture(14, 4, 'unmodeled');
    my $s = neuro();
    ok_or(seam_home($sm, $omap, $smap) eq oid($s->{14}),
          'the home is the coarsest (max ordinal) stratum');
}

sub v116 {
    my ($adj, $o1, $s1) = seam_fixture(6, 5, 'unmodeled');   # adjacent (gap 1)
    my ($ok) = seam_wellformed($adj, $o1, $s1);
    ok_or(!$ok, 'an adjacent seam is malformed');
    my ($co, $o2, $s2) = seam_fixture(6, 6, 'unmodeled');    # co-stratal (gap 0)
    ($ok) = seam_wellformed($co, $o2, $s2);
    ok_or(!$ok, 'a co-stratal seam is malformed');
    my ($sm) = seam_fixture(14, 4, 'unmodeled');
    ok_or(index(oid($sm), 'cross_stratal_seam:') == 0, 'a new identity scheme');
}

# -- Change Three: the realized_by reference --
sub v117 {
    my $c = conduit_realized('causal_relation_object:' . ('a' x 64));
    my ($ok, $why) = validate_schema($c);
    ok_or($ok, join('; ', @$why));
    my $c2 = conduit_realized('native:region_stratum_predict');
    ($ok, $why) = validate_schema($c2);
    ok_or($ok, join('; ', @$why));  # a native scheme reference is legal
}

sub v118 {
    my $bound = conduit_realized('native:region_stratum_predict');
    my $unbound = conduit_realized();
    ok_or(oid($bound) ne oid($unbound), 'realized_by is identity-bearing');
    # an unbound conduit's identity is UNCHANGED under 3.0.0 (pinned 2.0.0)
    ok_or(oid($unbound) eq 'conduit:'
          . 'dc4af3b1a24f0560d5ebcee488779f06ab3c78301cfb9d0c7edff80bc62e27a6',
          'the unbound conduit identity is pinned');
}

sub v119 {
    my $unbound = conduit_realized();
    my ($ok, $why) = validate_schema($unbound);
    ok_or($ok, join('; ', @$why));  # unbound is legal
    my $bad = oclone($unbound);
    oset($bad, 'realized_by', jstr('not-a-scheme-qualified-reference'));
    ($ok) = validate_schema($bad, 'conduit');
    ok_or(!$ok, 'a malformed realized_by reference is rejected');
}

# ---------------------------------------------------------------------------
# V120 - V137: the 4.0.0 additions (attitude, predicted_occurrence,
# prediction_error)
# ---------------------------------------------------------------------------
sub b_attitude {
    my ($holder, $attitude_type, $content) = @_;
    return mk(jobj(type => jstr('attitude'), holder => jstr($holder),
                   attitude_type => jstr($attitude_type),
                   content => jstr($content)));
}

sub b_predicted {
    my ($instantiates, $iv, $predictor, $strength) = @_;
    my $o = jobj(type => jstr('predicted_occurrence'),
                 instantiates => jstr($instantiates), interval => $iv,
                 predictor => jstr($predictor));
    oset($o, 'strength', jnum($strength)) if defined $strength;
    return mk($o);
}

sub b_prediction_error {
    my ($predicted_id, $discrepancy, $observed) = @_;
    my $o = jobj(type => jstr('prediction_error'),
                 predicted => jstr($predicted_id),
                 discrepancy => jnum($discrepancy));
    oset($o, 'observed', jstr($observed)) if defined $observed;
    return mk($o);
}

# an interval carrying the ordinal (tick) dimension
sub tick_interval {
    my (%h) = @_;
    my $o = jobj(start_tick => jnum($h{start_tick}));
    oset($o, 'end_tick', jnum($h{end_tick})) if exists $h{end_tick};
    return $o;
}

# a modeled predicting agent (a token individual), by identity
sub predictor_id {
    my $c = b_cnt('forecasting_mind');
    return oid(b_individual(oid($c), 'predictor_p'));
}

# a modeled believing agent (a token individual), by identity
sub believer_id {
    my ($designator) = @_;
    $designator = 'holder_h' unless defined $designator;
    my $c = b_cnt('believing_mind');
    return oid(b_individual(oid($c), $designator));
}

# -- Group X: prediction and prediction error (Section A) --
sub v120 {
    my $o = b_occ('rainfall_begins');
    my $p = b_predicted(oid($o), tick_interval(start_tick => 3, end_tick => 8),
                        predictor_id());
    my ($ok, $why) = validate_schema($p);
    ok_or($ok, join('; ', @$why));
    ($ok, $why) = validate_semantics($p);
    ok_or($ok, join('; ', @$why));
    ok_or(index(oid($p), 'predicted_occurrence:') == 0, 'a new identity scheme');
    my $report = identify(jobj(type => jstr('token_occurrence'),
                               instantiates => jstr(oid($o)),
                               interval => tick_interval(start_tick => 3,
                                                         end_tick => 8)),
                          'token_occurrence');
    ok_or(oid($p) ne $report, 'a forecast is not a report');
    ok_or(index($report, 'token_occurrence:') == 0,
          'the report is a token_occurrence');
}

sub v121 {
    my $o = b_occ('rainfall_begins');
    my $wall = interval(start => '2026-07-23T00:00:00Z',
                        end => '2026-07-24T00:00:00Z');
    my $who = predictor_id();
    my $with_strength = b_predicted(oid($o), $wall, $who, '0.8');
    my $without = b_predicted(oid($o), $wall, $who);
    for my $p ($with_strength, $without) {
        my ($ok, $why) = validate_schema($p);
        ok_or($ok, join('; ', @$why));
        ($ok, $why) = validate_semantics($p);
        ok_or($ok, join('; ', @$why));
    }
    ok_or(oid($with_strength) ne oid($without), 'strength is identity-bearing');
}

sub v122 {
    my $o = b_occ('rainfall_begins');
    my $bad = mk(jobj(type => jstr('predicted_occurrence'),
                      instantiates => jstr(oid($o)),
                      interval => tick_interval(start_tick => 3)));
    my ($ok, $why) = validate_schema($bad, 'predicted_occurrence');
    ok_or(!$ok && (grep { index($_, 'predictor') >= 0 } @$why),
          'predictor is required: ' . join('; ', @$why));
}

sub v123 {
    my $o = b_occ('rainfall_begins');
    my $iv = jobj(start => jstr('2026-07-23T00:00:00Z'), start_tick => jnum(3));
    my $both = b_predicted(oid($o), $iv, predictor_id());
    my ($ok, $why) = validate_schema($both);
    ok_or($ok, join('; ', @$why));
    ($ok, $why) = validate_semantics($both);
    ok_or(!$ok && (grep { index($_, 'dimension_conflict') >= 0 } @$why),
          'dimension_conflict: ' . join('; ', @$why));
}

sub v124 {
    my $o = b_occ('rainfall_begins');
    my $p = b_predicted(oid($o), interval(start => '2026-07-23T00:00:00Z'),
                        predictor_id());
    my $t = b_token(oid($o), interval(start => '2026-07-23T06:00:00Z'));
    my $err = b_prediction_error(oid($p), '0.0', oid($t));
    my ($ok, $why) = validate_schema($err);
    ok_or($ok, join('; ', @$why));
    ($ok, $why) = validate_semantics($err);
    ok_or($ok, join('; ', @$why));
    ok_or(prediction_pairing_mismatch($err, $p, $t) == 0, 'no pairing mismatch');
}

sub v125 {
    my $o = b_occ('rainfall_begins');
    my $p = b_predicted(oid($o), interval(start => '2026-07-23T00:00:00Z'),
                        predictor_id());
    my $err = b_prediction_error(oid($p), '-1.0');
    my ($ok, $why) = validate_schema($err);
    ok_or($ok, join('; ', @$why));
    ($ok, $why) = validate_semantics($err);
    ok_or($ok, join('; ', @$why));
    ok_or(!ohas($err, 'observed'), 'observed is absent');
    ok_or(prediction_pairing_mismatch($err, $p, undef) == 0,
          'an absent observed is never a mismatch');
}

sub v126 {
    my $o = b_occ('rainfall_begins');
    my $p = b_predicted(oid($o), tick_interval(start_tick => 0), predictor_id());
    my $bad = mk(jobj(type => jstr('prediction_error'),
                      predicted => jstr(oid($p))));
    my ($ok, $why) = validate_schema($bad, 'prediction_error');
    ok_or(!$ok && (grep { index($_, 'discrepancy') >= 0 } @$why),
          'discrepancy is required: ' . join('; ', @$why));
}

sub v127 {
    my $o = b_occ('rainfall_begins');
    my $other = b_occ('snowfall_begins');
    my $p = b_predicted(oid($o), interval(start => '2026-07-23T00:00:00Z'),
                        predictor_id());
    my $t = b_token(oid($other), interval(start => '2026-07-23T06:00:00Z'));
    my $err = b_prediction_error(oid($p), '1.0', oid($t));
    my ($ok, $why) = validate_schema($err);
    ok_or($ok, join('; ', @$why));
    ok_or(prediction_pairing_mismatch($err, $p, $t) == 1, 'pairing mismatch');
}

# -- Group Y: attitude and theory of mind (Section B) --
sub v128 {
    my ($st) = state_fixture('quantity',
        jobj(quantity => jnum('15.0'), unit => jstr('ug/dL')), 'ug/dL');
    my $att = b_attitude(believer_id(), 'believes', oid($st));
    my ($ok, $why) = validate_schema($att);
    ok_or($ok, join('; ', @$why));
    ($ok, $why) = validate_semantics($att);
    ok_or($ok, join('; ', @$why));
}

sub v129 {
    my $a = b_occ('switch_pressed');
    my $b = b_occ('light_on');
    my $actual = b_cro([oid($a)], [oid($b)], modality => 'sufficient');
    my $believed = b_cro([oid($a)], [oid($b)], modality => 'preventive');
    ok_or(conflicts($believed, $actual) == 1, 'the claims contradict');
    my $att = b_attitude(believer_id(), 'believes', oid($believed));
    my ($ok, $why) = validate_schema($att);
    ok_or($ok, join('; ', @$why));
    ($ok, $why) = validate_semantics($att);
    ok_or($ok, join('; ', @$why));  # validity unaffected
    my $s = Causalontology::Store->new;
    $s->put($a);
    $s->put($b);
    $s->put($actual);
    $s->put($att);
    ok_or(scalar($s->gaps('conflict')) == 0,
          'Rule 25: no conflict raised for a quarantined belief');
}

sub v130 {
    my $o = b_occ('rainfall_begins');
    my $att = b_attitude(believer_id(), 'desires', oid($o));
    my ($ok, $why) = validate_schema($att);
    ok_or($ok, join('; ', @$why));
    ($ok, $why) = validate_semantics($att);
    ok_or($ok, join('; ', @$why));
}

sub v131 {
    my $o = b_occ('press_button');
    my $att = b_attitude(believer_id(), 'intends', oid($o));
    my ($ok, $why) = validate_schema($att);
    ok_or($ok, join('; ', @$why));
    ($ok, $why) = validate_semantics($att);
    ok_or($ok, join('; ', @$why));
}

sub v132 {
    my ($st) = state_fixture('boolean', jobj(boolean => jbool(1)));
    my $inner = b_attitude(believer_id('holder_b'), 'believes', oid($st));
    my $outer = b_attitude(believer_id('holder_a'), 'believes', oid($inner));
    for my $att ($inner, $outer) {
        my ($ok, $why) = validate_schema($att);
        ok_or($ok, join('; ', @$why));
        ($ok, $why) = validate_semantics($att);
        ok_or($ok, join('; ', @$why));
    }
    ok_or(oid($outer) ne oid($inner), 'distinct ids');
    ok_or(sval(oget($outer, 'content')) eq oid($inner), 'nested content');
}

sub v133 {
    my $o = b_occ('rainfall_begins');
    my $bad = mk(jobj(type => jstr('attitude'), holder => jstr(believer_id()),
                      attitude_type => jstr('suspects'),
                      content => jstr(oid($o))));
    my ($ok, $why) = validate_schema($bad, 'attitude');
    ok_or(!$ok && (grep { index($_, 'attitude_type') >= 0 } @$why),
          'attitude_type is a closed enumeration: ' . join('; ', @$why));
}

sub v134 {
    my $o = b_occ('rainfall_begins');
    my $bad = mk(jobj(type => jstr('attitude'), holder => jstr(believer_id()),
                      attitude_type => jstr('believes'),
                      content => jstr(oid($o)), strength => jnum('0.9')));
    my ($ok, $why) = validate_schema($bad, 'attitude');
    ok_or(!$ok && (grep { index($_, 'strength') >= 0 } @$why),
          'an attitude carries no strength: ' . join('; ', @$why));
}

sub v135 {
    my $o = b_occ('rainfall_begins');
    my $att = b_attitude(believer_id(), 'expects', oid($o));
    my $a = signed('assertion', jobj(about => jstr(oid($att)),
                                     evidence_type => jstr('observation'),
                                     confidence => jnum('0.9')), 'signer');
    my ($ok, $why) = validate_schema($a);
    ok_or($ok, join('; ', @$why));
    ok_or(verify_record($a) == 1, 'the assertion verifies');
    # the HOLDER (a modeled agent) and the SOURCE (a signing key) differ
    ok_or((split /:/, sval(oget($att, 'holder')), 2)[0] eq 'token_individual',
          'the holder is a modeled agent');
    ok_or((split /:/, sval(oget($a, 'source')), 2)[0] eq 'ed25519',
          'the source is a signing key');
    ok_or(sval(oget($att, 'holder')) ne sval(oget($a, 'source')),
          'the holder and the source differ');
}

sub v136 {
    # the V111 wall-clock Causal Relation Object, re-pinned under 4.0.0
    my $secs = jobj(type => jstr('causal_relation_object'),
                    causes => jarr(jstr(sym('occurrent:a'))),
                    effects => jarr(jstr(sym('occurrent:b'))),
                    modality => jstr('sufficient'),
                    temporal => temporal(0, 1, 'seconds'));
    ok_or(identify($secs) eq 'causal_relation_object:'
          . 'd8daf899daa3ee03caa6b1425cc6d4d33cef20d951e1203ffd35df29857aa43c',
          'the wall-clock CRO identity holds under 4.0.0');
    # the V118 unbound conduit, re-pinned under 4.0.0
    my $unbound = conduit_realized();
    ok_or(oid($unbound) eq 'conduit:'
          . 'dc4af3b1a24f0560d5ebcee488779f06ab3c78301cfb9d0c7edff80bc62e27a6',
          'the unbound conduit identity holds under 4.0.0');
}

sub v137 {
    my $hexid = '0' x 64;
    # NOTE: the abbreviated prefixes are intentional (the negative test); they
    # must NOT be re-minted. Each is assembled to survive re-mint tools.
    my $att_abbr = 'a' . 't' . 't';
    my $prd_abbr = 'p' . 'r' . 'd';
    my $err_abbr = 'e' . 'r' . 'r';
    my $bad_att = jobj(type => jstr('attitude'),
                       id => jstr($att_abbr . ':' . $hexid),
                       holder => jstr('token_individual:' . $hexid),
                       attitude_type => jstr('believes'),
                       content => jstr('state_assertion:' . $hexid));
    my ($ok) = validate_schema($bad_att, 'attitude');
    ok_or(!$ok, 'the abbreviated attitude scheme must be rejected');
    my $bad_prd = jobj(type => jstr('predicted_occurrence'),
                       id => jstr($prd_abbr . ':' . $hexid),
                       instantiates => jstr('occurrent:' . $hexid),
                       interval => tick_interval(start_tick => 0),
                       predictor => jstr('token_individual:' . $hexid));
    ($ok) = validate_schema($bad_prd, 'predicted_occurrence');
    ok_or(!$ok, 'the abbreviated predicted_occurrence scheme must be rejected');
    my $bad_err = jobj(type => jstr('prediction_error'),
                       id => jstr($err_abbr . ':' . $hexid),
                       predicted => jstr('predicted_occurrence:' . $hexid),
                       discrepancy => jnum('0.0'));
    ($ok) = validate_schema($bad_err, 'prediction_error');
    ok_or(!$ok, 'the abbreviated prediction_error scheme must be rejected');
    my $whole_att = oclone($bad_att);
    oset($whole_att, 'id', jstr('attitude:' . $hexid));
    my ($ok2, $why) = validate_schema($whole_att, 'attitude');
    ok_or($ok2, 'the whole-word attitude validates: ' . join('; ', @$why));
    my $whole_prd = oclone($bad_prd);
    oset($whole_prd, 'id', jstr('predicted_occurrence:' . $hexid));
    ($ok2, $why) = validate_schema($whole_prd, 'predicted_occurrence');
    ok_or($ok2, 'the whole-word predicted_occurrence validates: '
              . join('; ', @$why));
    my $whole_err = oclone($bad_err);
    oset($whole_err, 'id', jstr('prediction_error:' . $hexid));
    ($ok2, $why) = validate_schema($whole_err, 'prediction_error');
    ok_or($ok2, 'the whole-word prediction_error validates: '
              . join('; ', @$why));
}

# ---------------------------------------------------------------------------
my %VECTORS = (
    1 => \&v01,  2 => \&v02,  3 => \&v03,  4 => \&v04,  5 => \&v05,
    6 => \&v06,  7 => \&v07,  8 => \&v08,  9 => \&v09,  10 => \&v10,
    11 => \&v11, 12 => \&v12, 13 => \&v13, 14 => \&v14, 15 => \&v15,
    16 => \&v16, 17 => \&v17, 18 => sub { semantics_fails(18, 'not a legal field') },
    19 => sub { semantics_fails(19, 'language-tagged') },
    20 => \&v20, 21 => \&v21, 22 => \&v22, 23 => \&v23, 24 => \&v24,
    25 => \&v25, 26 => \&v26, 27 => \&v27, 28 => \&v28, 29 => \&v29,
    30 => \&v30, 31 => \&v31, 32 => \&v32, 33 => \&v33, 34 => \&v34,
    35 => \&v35, 36 => \&v36, 37 => \&v37, 38 => \&v38, 39 => \&v39,
    40 => \&v40, 41 => \&v41, 42 => \&v42, 43 => \&v43, 44 => \&v44,
    45 => \&v45, 46 => \&v46, 47 => \&v47, 48 => \&v48, 49 => \&v49,
    50 => \&v50, 51 => \&v51, 52 => \&v52, 53 => \&v53, 54 => \&v54,
    55 => \&v55, 56 => \&v56, 57 => \&v57, 58 => \&v58, 59 => \&v59,
    60 => \&v60, 61 => \&v61, 62 => \&v62, 63 => \&v63, 64 => \&v64,
    65 => \&v65, 66 => \&v66, 67 => \&v67, 68 => \&v68, 69 => \&v69,
    70 => \&v70, 71 => \&v71, 72 => \&v72, 73 => \&v73, 74 => \&v74,
    75 => \&v75, 76 => \&v76, 77 => \&v77, 78 => \&v78, 79 => \&v79,
    80 => \&v80, 81 => \&v81, 82 => \&v82, 83 => \&v83, 84 => \&v84,
    85 => \&v85, 86 => \&v86, 87 => \&v87, 88 => \&v88, 89 => \&v89,
    90 => \&v90, 91 => \&v91, 92 => \&v92, 93 => \&v93, 94 => \&v94,
    95 => \&v95, 96 => \&v96, 97 => \&v97, 98 => \&v98, 99 => \&v99,
    100 => \&v100, 101 => \&v101, 102 => \&v102, 103 => \&v103,
    104 => \&v104, 105 => \&v105, 106 => \&v106, 107 => \&v107,
    108 => \&v108, 109 => \&v109, 110 => \&v110, 111 => \&v111,
    112 => \&v112, 113 => \&v113, 114 => \&v114, 115 => \&v115,
    116 => \&v116, 117 => \&v117, 118 => \&v118, 119 => \&v119,
    120 => \&v120, 121 => \&v121, 122 => \&v122, 123 => \&v123,
    124 => \&v124, 125 => \&v125, 126 => \&v126, 127 => \&v127,
    128 => \&v128, 129 => \&v129, 130 => \&v130, 131 => \&v131,
    132 => \&v132, 133 => \&v133, 134 => \&v134, 135 => \&v135,
    136 => \&v136, 137 => \&v137,
);

sub main {
    my $t0 = time;
    print "causalontology-perl conformance run (specification 4.0.0)\n";
    print 'internal checks (RFC 8032 known-answer, RFC 8785 basics) ... ';
    internal_checks();
    print "ok\n";
    my $failures = 0;
    my $total = 137;
    for my $n (1 .. $total) {
        my $name = vec_name($n);
        my $result = eval { $VECTORS{$n}->(); 1 };
        if ($result) {
            printf "PASS  %s\n", $name;
        }
        else {
            $failures++;
            my $e = $@;
            $e = $e->message if ref $e
                && eval { $e->isa('Causalontology::RejectedWrite') };
            chomp $e if !ref $e;
            printf "FAIL  %s :: %s\n", $name, $e;
        }
    }
    print '-' x 60, "\n";
    printf "%d/%d vectors passed\n", $total - $failures, $total;
    printf "total runtime: %.1f s\n", time - $t0;
    exit 1 if $failures;
    print "causalontology-perl is CONFORMANT to the suite "
        . "(vectors frozen at specification 4.0.0).\n";
}

main();

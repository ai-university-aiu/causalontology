#!/usr/bin/env perl
# The Causalontology conformance runner for causalontology-perl.
#
# Runs every vector in conformance/vectors/ against the Perl binding. An
# implementation is conformant if and only if it passes every vector; this
# runner exits nonzero on any failure. Mirrors
# bindings/python/tests/run_conformance.py exactly.
#
# The vectors are frozen at specification 1.0.0: they carry concrete 64-hex
# identifiers and real keys, which pass through the (retained) normalization
# unchanged; behavioral vectors derive deterministic keypairs from the seed
# sha256("key:" + name).

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
    hierarchy_consistent
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
my @SCHEMES = qw(occ cro cnt rlz ast enr ret suc);
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
}

# ---------------------------------------------------------------------------
# the 38 vectors
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
my %VECTORS = (
    1 => \&v01,  2 => \&v02,  3 => \&v03,  4 => \&v04,  5 => \&v05,
    6 => \&v06,  7 => \&v07,  8 => \&v08,  9 => \&v09,  10 => \&v10,
    11 => \&v11, 12 => \&v12, 13 => \&v13, 14 => \&v14, 15 => \&v15,
    16 => \&v16, 17 => \&v17, 18 => sub { semantics_fails(18, 'not a legal field') },
    19 => sub { semantics_fails(19, 'language-tagged') },
    20 => \&v20, 21 => \&v21, 22 => \&v22, 23 => \&v23, 24 => \&v24,
    25 => \&v25, 26 => \&v26, 27 => \&v27, 28 => \&v28, 29 => \&v29,
    30 => \&v30, 31 => \&v31, 32 => \&v32, 33 => \&v33, 34 => \&v34,
    35 => \&v35, 36 => \&v36, 37 => \&v37, 38 => \&v38,
);

sub main {
    my $t0 = time;
    print "causalontology-perl conformance run\n";
    print 'internal checks (RFC 8032 known-answer, RFC 8785 basics) ... ';
    internal_checks();
    print "ok\n";
    my $failures = 0;
    for my $n (1 .. 38) {
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
    my $total = 38;
    print '-' x 60, "\n";
    printf "%d/%d vectors passed\n", $total - $failures, $total;
    printf "total runtime: %.1f s\n", time - $t0;
    exit 1 if $failures;
    print "causalontology-perl is CONFORMANT to the suite "
        . "(vectors frozen at specification 1.0.0).\n";
}

main();

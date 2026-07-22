# Causalontology - the Perl binding of the Causalontology standard.
#
# A faithful port of causalontology-py (bindings/python/causalontology/),
# core modules only (Digest::SHA, Math::BigInt, strict, warnings):
# conformant when it passes every vector in conformance/vectors/
# (run bindings/perl/conformance.pl).
#
# Causalontology is a verb-first noun-hosting ontology: reality is what
# happens, and things are its participants.

package Causalontology;

use strict;
use warnings;

# specification 4.0.0 (attitude, predicted_occurrence, prediction_error)
our $VERSION = '4.0.0';

use Causalontology::JSON ();
use Causalontology::JCS ();
use Causalontology::Canonical ();
use Causalontology::Schema ();
use Causalontology::Semantics ();
use Causalontology::Ed25519 ();
use Causalontology::Signing ();
use Causalontology::Store ();

1;

__END__

=head1 NAME

Causalontology - the Perl binding of the Causalontology standard

=head1 SYNOPSIS

    use Causalontology;
    use Causalontology::JSON qw(jobj jstr jarr);

    my $store = Causalontology::Store->new(enforcing => 1);
    my $press = $store->put(jobj(
        type => jstr('occurrent'), label => jstr('press_button'),
        category => jstr('action')));
    my $light = $store->put(jobj(
        type => jstr('occurrent'), label => jstr('light_on'),
        category => jstr('state_change')));
    my $claim = $store->put(jobj(
        type => jstr('causal_relation_object'),
        causes => jarr(jstr($press)), effects => jarr(jstr($light))));

    # the degenerate claim is a visible invitation
    my @gaps = $store->gaps('missing_field');

=head1 DESCRIPTION

Identity (RFC 8785 canonicalization + SHA-256), the twenty-one JSON
Schemas, the semantic rules, Ed25519 record signing (RFC 8032), and the
in-memory conformant store with materialized views, retraction,
succession lineage, resolve, and the stigmergy gap read.

=head1 LICENSE

The attribution always; no profit, no problem license. (Apache 2.0 text)

=cut

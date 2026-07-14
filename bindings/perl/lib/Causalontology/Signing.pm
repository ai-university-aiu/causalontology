# Causalontology::Signing - record-level signing and verification
# (spec/provenance.md), mirroring bindings/python/causalontology/signing.py.
#
# The signature is computed over the record's canonical identity-bearing
# bytes (the RFC 8785 form with id and signature removed - exactly the bytes
# that are hashed for the record's identifier), so verification needs
# nothing but the record itself. Ed25519 is deterministic (RFC 8032):
# re-signing the same record with the same key yields the same signature,
# so re-submission is idempotent.

package Causalontology::Signing;

use strict;
use warnings;
use Exporter 'import';
use Causalontology::Ed25519 ();
use Causalontology::Canonical qw(canonicalize identify infer_kind);
use Causalontology::JSON qw(jstr ohas oget oset odel oclone sval);

our @EXPORT_OK = qw(keypair_from_seed sign_record verify_record);

# (secret, 'ed25519:<hex>') from a 32-byte seed.
sub keypair_from_seed {
    my ($seed32) = @_;
    my $public = Causalontology::Ed25519::secret_to_public($seed32);
    return ($seed32, 'ed25519:' . unpack('H*', $public));
}

# Return the record completed with its id and Ed25519 signature.
sub sign_record {
    my ($record, $secret, $kind) = @_;
    $kind ||= infer_kind($record);
    my $body = oclone($record);
    odel($body, 'signature');
    my $message = canonicalize($body, $kind);
    my $signature = unpack 'H*',
        Causalontology::Ed25519::sign($secret, $message);
    my $out = oclone($body);
    oset($out, 'id', jstr(identify($body, $kind)));
    oset($out, 'signature', jstr($signature));
    return $out;
}

# the hex of the key field that must have signed a record of this kind
sub _signer_key_hex {
    my ($record, $kind) = @_;
    # a succession is signed by the predecessor key
    my $field = ($kind eq 'succession') ? 'predecessor' : 'source';
    my $value = ohas($record, $field) ? sval(oget($record, $field)) : '';
    return undef unless index($value, 'ed25519:') == 0;
    return (split /:/, $value, 2)[1];
}

# True iff the record's signature verifies against its own key field.
sub verify_record {
    my ($record, $kind) = @_;
    $kind ||= infer_kind($record);
    my $sig_hex = ohas($record, 'signature')
        ? sval(oget($record, 'signature')) : '';
    my $key_hex = _signer_key_hex($record, $kind);
    return 0 unless $sig_hex && defined $key_hex && $key_hex ne '';
    # hex decoding must be strict: reject odd lengths and non-hex bytes
    return 0 unless $key_hex =~ /^(?:[0-9a-fA-F]{2})+$/;
    return 0 unless $sig_hex =~ /^(?:[0-9a-fA-F]{2})+$/;
    my $public = pack 'H*', $key_hex;
    my $signature = pack 'H*', $sig_hex;
    my $body = oclone($record);
    odel($body, 'signature');
    my $message = canonicalize($body, $kind);
    return Causalontology::Ed25519::verify($public, $message, $signature);
}

1;

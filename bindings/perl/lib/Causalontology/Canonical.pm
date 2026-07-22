# Causalontology::Canonical - canonicalization and content-addressed identity.
#
# Implements the identity procedure of spec/identity.md, mirroring
# bindings/python/causalontology/canonical.py:
#   1. take the object as (tagged) JSON,
#   2. keep only the identity-bearing fields for its kind (with "type"
#      injected),
#   3. serialize with the JSON Canonicalization Scheme (RFC 8785),
#   4. hash with SHA-256,
#   5. identifier = scheme + ":" + lowercase hex digest.
#
# 3.0.0 adds the cross_stratal_seam and gives the conduit an optional
# realized_by; 4.0.0 adds the attitude, the predicted_occurrence, and the
# prediction_error - all additive and identity-preserving, so a record that
# omits a new field keeps its earlier identifier byte-for-byte, and the new
# kinds open new identity schemes that disturb no existing record.

package Causalontology::Canonical;

use strict;
use warnings;
use Exporter 'import';
use Digest::SHA qw(sha256_hex);
use Causalontology::JSON qw(jstr jobj ohas oget oset sval is_str);
use Causalontology::JCS qw(jcs);

our @EXPORT_OK = qw(
    identify canonicalize identity_bearing infer_kind
    %IDENTITY_FIELDS %PREFIX %KIND_OF_PREFIX
);

our %IDENTITY_FIELDS = (
    # ---- type tier ----
    occurrent  => ['label', 'category', 'stratum'],
    causal_relation_object => ['causes', 'effects', 'mechanism', 'temporal',
                               'modality', 'context', 'refines', 'skips'],
    continuant => ['label', 'category'],
    realizable => ['kind', 'bearer', 'label'],
    stratum    => ['label', 'scheme', 'ordinal', 'unit', 'governs'],
    bridge     => ['coarse', 'fine', 'relation'],
    cross_stratal_seam => ['source', 'target', 'mechanism_status', 'chain'],
    port       => ['bearer', 'label', 'direction', 'accepts', 'realizable'],
    conduit    => ['label', 'from', 'to', 'carries', 'transform',
                   'realized_by'],
    quality    => ['label', 'datatype', 'unit', 'stratum'],
    # ---- token tier ----
    token_individual   => ['instantiates', 'designator', 'part_of'],
    token_occurrence   => ['instantiates', 'interval', 'participants',
                           'locus', 'observer'],
    state_assertion    => ['subject', 'quality', 'value', 'interval'],
    token_causal_claim => ['causes', 'effects', 'covering_law',
                           'actual_delay', 'counterfactual'],
    attitude             => ['holder', 'attitude_type', 'content'],
    predicted_occurrence => ['instantiates', 'interval', 'predictor',
                             'strength'],
    prediction_error     => ['predicted', 'observed', 'discrepancy'],
    # ---- provenance tier ----
    assertion  => ['about', 'source', 'evidence_type', 'evidence', 'strength',
                   'confidence', 'timestamp', 'evidenced_by'],
    enrichment => ['about', 'field', 'entry', 'source', 'timestamp'],
    retraction => ['retracts', 'source', 'timestamp'],
    succession => ['predecessor', 'successor', 'timestamp'],
);

# Whole-word re-mint (P7): the scheme IS the type value for every kind.
our %PREFIX = map { $_ => $_ } keys %IDENTITY_FIELDS;

our %KIND_OF_PREFIX = reverse %PREFIX;

# Infer an object's kind from its type field, id prefix, or shape.
sub infer_kind {
    my ($obj) = @_;
    if (ohas($obj, 'type')) {
        return sval(oget($obj, 'type'));
    }
    if (ohas($obj, 'id') && is_str(oget($obj, 'id'))) {
        my $id = sval(oget($obj, 'id'));
        if (index($id, ':') >= 0) {
            my ($pre) = split /:/, $id, 2;
            return $KIND_OF_PREFIX{$pre} if exists $KIND_OF_PREFIX{$pre};
        }
    }
    return 'bridge'     if ohas($obj, 'coarse') && ohas($obj, 'fine');
    return 'causal_relation_object'        if ohas($obj, 'causes') && ohas($obj, 'effects');
    return 'retraction' if ohas($obj, 'retracts');
    return 'succession' if ohas($obj, 'predecessor') && ohas($obj, 'successor');
    return 'enrichment' if ohas($obj, 'field') && ohas($obj, 'entry');
    return 'assertion'  if ohas($obj, 'evidence_type')
                        || (ohas($obj, 'about') && ohas($obj, 'confidence'));
    return 'realizable' if ohas($obj, 'kind') && ohas($obj, 'bearer');
    die "cannot infer kind (occurrents and continuants share a shape); "
      . "pass kind explicitly\n";
}

# The identity-bearing subset of an object, with type always present.
sub identity_bearing {
    my ($obj, $kind) = @_;
    $kind ||= infer_kind($obj);
    die "unknown kind: '$kind'\n" unless exists $IDENTITY_FIELDS{$kind};
    my $out = jobj(type => jstr($kind));
    for my $field (@{ $IDENTITY_FIELDS{$kind} }) {
        oset($out, $field, oget($obj, $field)) if ohas($obj, $field);
    }
    return ($kind, $out);
}

# The RFC 8785 identity-bearing bytes of an object.
sub canonicalize {
    my ($obj, $kind) = @_;
    my (undef, $ib) = identity_bearing($obj, $kind);
    return jcs($ib);
}

# The content-addressed identifier: scheme + ':' + SHA-256 hex.
sub identify {
    my ($obj, $kind) = @_;
    (my $k, my $ib) = identity_bearing($obj, $kind);
    return $PREFIX{$k} . ':' . sha256_hex(jcs($ib));
}

1;

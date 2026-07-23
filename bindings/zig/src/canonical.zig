//! Canonicalization and content-addressed identity (spec/identity.md).
//!
//! The identity procedure, ported from bindings/python/causalontology/canonical.py:
//!   1. take the object as JSON,
//!   2. keep only the identity-bearing fields for its kind (with "type" injected),
//!   3. serialize with the JSON Canonicalization Scheme (RFC 8785),
//!   4. hash with SHA-256 (std.crypto.hash.sha2.Sha256),
//!   5. identifier = scheme + ":" + lowercase hex digest.

const std = @import("std");
const jcs = @import("jcs.zig");

const Value = jcs.Value;
const ObjectMap = jcs.ObjectMap;
const Allocator = jcs.Allocator;

/// One kind's identity recipe: its name, its identifier scheme prefix, and
/// the ordered list of identity-bearing fields.
pub const KindSpec = struct {
    kind: []const u8,
    prefix: []const u8,
    fields: []const []const u8,
};

/// The twenty-one kinds and their identity-bearing fields (IDENTITY_FIELDS +
/// PREFIX). Whole-word re-mint (P7): the scheme IS the type value for every
/// kind, so prefix == kind throughout. 3.0.0 adds the cross_stratal_seam and
/// the conduit's realized_by; 4.0.0 adds the attitude, the
/// predicted_occurrence, and the prediction_error - all additive and
/// identity-preserving: a record that omits a new field keeps its earlier
/// identifier byte-for-byte, and the new kinds open new identity schemes that
/// disturb no existing record.
pub const kind_specs = [_]KindSpec{
    // ---- type tier ----
    .{ .kind = "occurrent", .prefix = "occurrent", .fields = &.{ "label", "category", "stratum" } },
    .{ .kind = "causal_relation_object", .prefix = "causal_relation_object", .fields = &.{ "causes", "effects", "mechanism", "temporal", "modality", "context", "refines", "skips" } },
    .{ .kind = "continuant", .prefix = "continuant", .fields = &.{ "label", "category" } },
    .{ .kind = "realizable", .prefix = "realizable", .fields = &.{ "kind", "bearer", "label" } },
    .{ .kind = "stratum", .prefix = "stratum", .fields = &.{ "label", "scheme", "ordinal", "unit", "governs" } },
    .{ .kind = "bridge", .prefix = "bridge", .fields = &.{ "coarse", "fine", "relation" } },
    .{ .kind = "cross_stratal_seam", .prefix = "cross_stratal_seam", .fields = &.{ "source", "target", "mechanism_status", "chain" } },
    .{ .kind = "port", .prefix = "port", .fields = &.{ "bearer", "label", "direction", "accepts", "realizable" } },
    .{ .kind = "conduit", .prefix = "conduit", .fields = &.{ "label", "from", "to", "carries", "transform", "realized_by" } },
    .{ .kind = "quality", .prefix = "quality", .fields = &.{ "label", "datatype", "unit", "stratum" } },
    // ---- token tier ----
    .{ .kind = "token_individual", .prefix = "token_individual", .fields = &.{ "instantiates", "designator", "part_of" } },
    .{ .kind = "token_occurrence", .prefix = "token_occurrence", .fields = &.{ "instantiates", "interval", "participants", "locus", "observer" } },
    .{ .kind = "state_assertion", .prefix = "state_assertion", .fields = &.{ "subject", "quality", "value", "interval" } },
    .{ .kind = "token_causal_claim", .prefix = "token_causal_claim", .fields = &.{ "causes", "effects", "covering_law", "actual_delay", "counterfactual" } },
    .{ .kind = "attitude", .prefix = "attitude", .fields = &.{ "holder", "attitude_type", "content" } },
    .{ .kind = "predicted_occurrence", .prefix = "predicted_occurrence", .fields = &.{ "instantiates", "interval", "predictor", "strength" } },
    .{ .kind = "prediction_error", .prefix = "prediction_error", .fields = &.{ "predicted", "observed", "discrepancy" } },
    // ---- provenance tier ----
    .{ .kind = "assertion", .prefix = "assertion", .fields = &.{ "about", "source", "evidence_type", "evidence", "strength", "confidence", "timestamp", "evidenced_by" } },
    .{ .kind = "enrichment", .prefix = "enrichment", .fields = &.{ "about", "field", "entry", "source", "timestamp" } },
    .{ .kind = "retraction", .prefix = "retraction", .fields = &.{ "retracts", "source", "timestamp" } },
    .{ .kind = "succession", .prefix = "succession", .fields = &.{ "predecessor", "successor", "timestamp" } },
};

/// The spec for a kind name, or null if unknown.
pub fn specOfKind(kind: []const u8) ?*const KindSpec {
    for (&kind_specs) |*s| {
        if (std.mem.eql(u8, s.kind, kind)) return s;
    }
    return null;
}

/// The kind whose identifier scheme is `prefix` (KIND_OF_PREFIX), or null.
pub fn kindOfPrefix(prefix: []const u8) ?[]const u8 {
    for (&kind_specs) |*s| {
        if (std.mem.eql(u8, s.prefix, prefix)) return s.kind;
    }
    return null;
}

/// Infer an object's kind from its type field, id prefix, or shape.
pub fn inferKind(obj: ObjectMap) ![]const u8 {
    if (jcs.getString(obj, "type")) |t| return t;
    if (jcs.getString(obj, "id")) |id| {
        if (std.mem.indexOfScalar(u8, id, ':')) |i| {
            if (kindOfPrefix(id[0..i])) |k| return k;
        }
    }
    if (obj.contains("coarse") and obj.contains("fine")) return "bridge";
    if (obj.contains("causes") and obj.contains("effects")) return "causal_relation_object";
    if (obj.contains("retracts")) return "retraction";
    if (obj.contains("predecessor") and obj.contains("successor")) return "succession";
    if (obj.contains("field") and obj.contains("entry")) return "enrichment";
    if (obj.contains("evidence_type") or (obj.contains("about") and obj.contains("confidence"))) return "assertion";
    if (obj.contains("kind") and obj.contains("bearer")) return "realizable";
    // occurrents and continuants share a shape; the caller must pass kind.
    return error.CannotInferKind;
}

pub const IdentityBearing = struct {
    kind: []const u8,
    ib: ObjectMap,
};

/// The identity-bearing subset of an object, with type always present.
pub fn identityBearing(a: Allocator, obj: ObjectMap, kind_opt: ?[]const u8) !IdentityBearing {
    const kind = kind_opt orelse try inferKind(obj);
    const spec = specOfKind(kind) orelse return error.UnknownKind;
    var out = ObjectMap.init(a);
    try out.put("type", .{ .string = spec.kind });
    for (spec.fields) |field| {
        if (obj.get(field)) |v| try out.put(field, v);
    }
    return .{ .kind = spec.kind, .ib = out };
}

/// The RFC 8785 identity-bearing bytes of an object.
pub fn canonicalize(a: Allocator, obj: ObjectMap, kind_opt: ?[]const u8) ![]u8 {
    const r = try identityBearing(a, obj, kind_opt);
    return jcs.jcs(a, .{ .object = r.ib });
}

/// The content-addressed identifier: scheme + ":" + SHA-256 hex.
pub fn identify(a: Allocator, obj: ObjectMap, kind_opt: ?[]const u8) ![]u8 {
    const r = try identityBearing(a, obj, kind_opt);
    const bytes = try jcs.jcs(a, .{ .object = r.ib });
    const spec = specOfKind(r.kind).?;
    return std.fmt.allocPrint(a, "{s}:{s}", .{ spec.prefix, try sha256Hex(a, bytes) });
}

/// Lowercase-hex SHA-256 of a byte string.
pub fn sha256Hex(a: Allocator, data: []const u8) ![]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
    return jcs.hexLower(a, &digest);
}

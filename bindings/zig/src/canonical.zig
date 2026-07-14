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

/// The eight kinds and their identity-bearing fields (IDENTITY_FIELDS + PREFIX).
pub const kind_specs = [_]KindSpec{
    .{ .kind = "occurrent", .prefix = "occ", .fields = &.{ "label", "category" } },
    .{ .kind = "cro", .prefix = "cro", .fields = &.{ "causes", "effects", "mechanism", "temporal", "modality", "context", "refines" } },
    .{ .kind = "continuant", .prefix = "cnt", .fields = &.{ "label", "category" } },
    .{ .kind = "realizable", .prefix = "rlz", .fields = &.{ "kind", "bearer" } },
    .{ .kind = "assertion", .prefix = "ast", .fields = &.{ "about", "source", "evidence_type", "evidence", "strength", "confidence", "timestamp" } },
    .{ .kind = "enrichment", .prefix = "enr", .fields = &.{ "about", "field", "entry", "source", "timestamp" } },
    .{ .kind = "retraction", .prefix = "ret", .fields = &.{ "retracts", "source", "timestamp" } },
    .{ .kind = "succession", .prefix = "suc", .fields = &.{ "predecessor", "successor", "timestamp" } },
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
    if (obj.contains("causes") and obj.contains("effects")) return "cro";
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

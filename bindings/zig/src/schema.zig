//! Schema validation against spec/schema/*.schema.json.
//!
//! A deliberately small interpreter for exactly the JSON Schema keywords the
//! eight Causalontology schemas use: type, const, enum, pattern, required,
//! properties, additionalProperties, items, minItems, minLength, minimum,
//! maximum, oneOf, and local $ref (#/$defs/...). "format" is treated as an
//! annotation, as the 2020-12 draft does by default. Ported from
//! bindings/python/causalontology/schema.py.
//!
//! The schemas use exactly three anchored pattern families, so no regex
//! engine is needed - dedicated matchers cover them all:
//!   ^[0-9a-f]{128}$                    (a signature)
//!   ^(pre|fix|es):[0-9a-f]{64}$        (scheme-prefixed identifiers,
//!                                       one prefix or an alternation,
//!                                       including ed25519 keys)
//!   ^[a-z][a-z0-9_]*$                  (a canonical snake_case label)

const std = @import("std");
const jcs = @import("jcs.zig");
const canonical = @import("canonical.zig");

const Value = jcs.Value;
const Allocator = jcs.Allocator;
const Validation = jcs.Validation;

// Module-level schema location and cache (the harness is single-threaded,
// mirroring the Python module's _cache dict).
var spec_dir: ?[]const u8 = null;
var spec_alloc: ?Allocator = null;
var cache = [_]?Value{null} ** canonical.kind_specs.len;

/// Point the validator at the directory holding the eight *.schema.json files.
pub fn setSpecDir(a: Allocator, dir: []const u8) void {
    spec_alloc = a;
    spec_dir = dir;
    cache = [_]?Value{null} ** canonical.kind_specs.len;
}

/// Load (and cache) the parsed JSON Schema for a kind.
pub fn loadSchema(kind: []const u8) !Value {
    const a = spec_alloc orelse return error.SpecDirNotSet;
    const dir = spec_dir orelse return error.SpecDirNotSet;
    var index: ?usize = null;
    for (&canonical.kind_specs, 0..) |*s, i| {
        if (std.mem.eql(u8, s.kind, kind)) index = i;
    }
    const i = index orelse return error.UnknownKind;
    if (cache[i] == null) {
        // Every schema file is named <kind>.schema.json.
        const path = try std.fmt.allocPrint(a, "{s}{c}{s}.schema.json", .{ dir, std.fs.path.sep, kind });
        const bytes = try std.fs.cwd().readFileAlloc(a, path, 1 << 20);
        cache[i] = try std.json.parseFromSliceLeaky(Value, a, bytes, .{});
    }
    return cache[i].?;
}

/// (ok, reasons) - structural validity against the kind's JSON Schema.
pub fn validateSchema(a: Allocator, obj: Value, kind_opt: ?[]const u8) !Validation {
    const kind = kind_opt orelse try canonical.inferKind(obj.object);
    const root = try loadSchema(kind);
    var errors = std.ArrayList([]const u8).init(a);
    try check(a, obj, root, root, "$", &errors);
    return .{ .ok = errors.items.len == 0, .errors = errors.items };
}

/// Follow local $ref chains (#/$defs/...) to the referenced subschema.
fn resolveRef(schema_in: Value, root: Value) Value {
    var schema = schema_in;
    while (schema == .object) {
        const ref = schema.object.get("$ref") orelse break;
        // Only local references appear in the eight schemas.
        var node = root;
        var it = std.mem.splitScalar(u8, ref.string[2..], '/');
        while (it.next()) |part| {
            node = node.object.get(part).?;
        }
        schema = node;
    }
    return schema;
}

fn check(a: Allocator, value: Value, schema_in: Value, root: Value, path: []const u8, errors: *std.ArrayList([]const u8)) anyerror!void {
    const schema = resolveRef(schema_in, root);
    const so = schema.object;

    if (so.get("oneOf")) |branches| {
        var passing: usize = 0;
        for (branches.array.items) |sub| {
            var suberrs = std.ArrayList([]const u8).init(a);
            try check(a, value, sub, root, path, &suberrs);
            if (suberrs.items.len == 0) passing += 1;
        }
        if (passing != 1) {
            try errors.append(try std.fmt.allocPrint(a, "{s}: matches {d} of the oneOf branches (need exactly 1)", .{ path, passing }));
        }
        return;
    }

    if (so.get("type")) |tv| {
        const t = tv.string;
        const ok = if (std.mem.eql(u8, t, "object"))
            value == .object
        else if (std.mem.eql(u8, t, "array"))
            value == .array
        else if (std.mem.eql(u8, t, "string"))
            value == .string
        else if (std.mem.eql(u8, t, "boolean"))
            value == .bool
        else if (std.mem.eql(u8, t, "number"))
            // booleans are a distinct tag in std.json.Value, so the Python
            // bool-is-an-int exclusion is automatic here
            (value == .integer or value == .float)
        else
            false;
        if (!ok) {
            try errors.append(try std.fmt.allocPrint(a, "{s}: expected {s}", .{ path, t }));
            return;
        }
    }

    if (so.get("const")) |c| {
        if (!jcs.deepEqual(value, c)) {
            try errors.append(try std.fmt.allocPrint(a, "{s}: must equal {s}", .{ path, try jcs.jcs(a, c) }));
        }
    }
    if (so.get("enum")) |en| {
        var member = false;
        for (en.array.items) |cand| {
            if (jcs.deepEqual(value, cand)) {
                member = true;
                break;
            }
        }
        if (!member) {
            try errors.append(try std.fmt.allocPrint(a, "{s}: {s} not in enumeration", .{ path, try jcs.jcs(a, value) }));
        }
    }
    if (so.get("pattern")) |p| {
        if (value == .string and !matchesPattern(p.string, value.string)) {
            try errors.append(try std.fmt.allocPrint(a, "{s}: \"{s}\" does not match {s}", .{ path, value.string, p.string }));
        }
    }
    if (so.get("minLength")) |ml| {
        if (value == .string and @as(f64, @floatFromInt(value.string.len)) < jcs.numAsF64(ml).?) {
            try errors.append(try std.fmt.allocPrint(a, "{s}: shorter than minLength", .{path}));
        }
    }
    if (so.get("minimum")) |m| {
        if (jcs.numAsF64(value)) |f| {
            if (f < jcs.numAsF64(m).?) {
                try errors.append(try std.fmt.allocPrint(a, "{s}: below minimum {s}", .{ path, try jcs.jcs(a, m) }));
            }
        }
    }
    if (so.get("maximum")) |m| {
        if (jcs.numAsF64(value)) |f| {
            if (f > jcs.numAsF64(m).?) {
                try errors.append(try std.fmt.allocPrint(a, "{s}: above maximum {s}", .{ path, try jcs.jcs(a, m) }));
            }
        }
    }

    if (value == .array) {
        if (so.get("minItems")) |mi| {
            const want: usize = @intFromFloat(jcs.numAsF64(mi).?);
            if (value.array.items.len < want) {
                try errors.append(try std.fmt.allocPrint(a, "{s}: fewer than {d} items", .{ path, want }));
            }
        }
        if (so.get("items")) |items| {
            for (value.array.items, 0..) |item, i| {
                try check(a, item, items, root, try std.fmt.allocPrint(a, "{s}[{d}]", .{ path, i }), errors);
            }
        }
    }

    if (value == .object) {
        const props = so.get("properties");
        if (so.get("required")) |req| {
            for (req.array.items) |r| {
                if (!value.object.contains(r.string)) {
                    try errors.append(try std.fmt.allocPrint(a, "{s}: required property '{s}' missing", .{ path, r.string }));
                }
            }
        }
        if (so.get("additionalProperties")) |ap| {
            if (ap == .bool and !ap.bool) {
                for (value.object.keys()) |k| {
                    const in_props = if (props) |pv| pv.object.contains(k) else false;
                    if (!in_props) {
                        try errors.append(try std.fmt.allocPrint(a, "{s}: additional property '{s}'", .{ path, k }));
                    }
                }
            }
        }
        if (props) |pv| {
            var it = pv.object.iterator();
            while (it.next()) |e| {
                if (value.object.get(e.key_ptr.*)) |vv| {
                    try check(a, vv, e.value_ptr.*, root, try std.fmt.allocPrint(a, "{s}.{s}", .{ path, e.key_ptr.* }), errors);
                }
            }
        }
    }
}

/// Match a value against one of the three anchored pattern families the
/// schemas use. Unknown pattern shapes fail closed (never match), so a
/// future schema change surfaces as a loud vector failure, not a silent pass.
pub fn matchesPattern(pattern: []const u8, s: []const u8) bool {
    var body = pattern;
    if (std.mem.startsWith(u8, body, "^")) body = body[1..];
    if (std.mem.endsWith(u8, body, "$")) body = body[0 .. body.len - 1];

    if (std.mem.eql(u8, body, "[0-9a-f]{128}")) return jcs.isHex(s, 128);
    if (std.mem.eql(u8, body, "[a-z][a-z0-9_]*")) return isLabel(s);

    const hex_suffix = ":[0-9a-f]{64}";
    if (std.mem.endsWith(u8, body, hex_suffix)) {
        var prefixes = body[0 .. body.len - hex_suffix.len];
        if (std.mem.startsWith(u8, prefixes, "(") and std.mem.endsWith(u8, prefixes, ")")) {
            prefixes = prefixes[1 .. prefixes.len - 1];
        }
        const colon = std.mem.indexOfScalar(u8, s, ':') orelse return false;
        if (!jcs.isHex(s[colon + 1 ..], 64)) return false;
        var it = std.mem.splitScalar(u8, prefixes, '|');
        while (it.next()) |p| {
            if (std.mem.eql(u8, s[0..colon], p)) return true;
        }
        return false;
    }
    return false;
}

/// ^[a-z][a-z0-9_]*$ - a canonical lowercase snake_case label.
fn isLabel(s: []const u8) bool {
    if (s.len == 0) return false;
    switch (s[0]) {
        'a'...'z' => {},
        else => return false,
    }
    for (s[1..]) |c| {
        switch (c) {
            'a'...'z', '0'...'9', '_' => {},
            else => return false,
        }
    }
    return true;
}

//! RFC 8785 (JSON Canonicalization Scheme) serialization, plus the shared
//! JSON value helpers for causalontology-zig.
//!
//! Mirrors the `_jcs` / `_jcs_string` / `_jcs_number` trio of
//! bindings/python/causalontology/canonical.py. The universal value type is
//! std.json.Value: its ObjectMap is a StringArrayHashMap, so object key
//! insertion order is preserved exactly as Python dicts preserve it, and the
//! parser keeps the integer-versus-decimal source distinction (`1` parses to
//! .integer, `1.0` to .float) that RFC 8785 number canonicalization needs.

const std = @import("std");

pub const Value = std.json.Value;
pub const ObjectMap = std.json.ObjectMap;
pub const Array = std.json.Array;
pub const Allocator = std.mem.Allocator;

/// A (valid?, reasons) pair shared by the schema and semantics validators.
pub const Validation = struct {
    ok: bool,
    errors: []const []const u8,
};

/// Serialize a JSON value to its RFC 8785 canonical bytes.
pub fn jcs(a: Allocator, value: Value) anyerror![]u8 {
    var out = std.ArrayList(u8).init(a);
    try writeValue(a, &out, value);
    return out.items;
}

fn lessThanBytes(_: void, x: []const u8, y: []const u8) bool {
    // UTF-8 byte order equals Unicode code point order, which matches the
    // Python reference's sort key of [ord(c) for c in key].
    return std.mem.order(u8, x, y) == .lt;
}

fn writeValue(a: Allocator, out: *std.ArrayList(u8), value: Value) anyerror!void {
    switch (value) {
        .null => try out.appendSlice("null"),
        .bool => |b| try out.appendSlice(if (b) "true" else "false"),
        .integer => |i| try out.writer().print("{d}", .{i}),
        .float => |f| try out.appendSlice(try jcsNumber(a, f)),
        // number_string only appears for out-of-range literals, which the
        // 1.0.0 vectors never contain; pass the source literal through.
        .number_string => |s| try out.appendSlice(s),
        .string => |s| try writeString(out, s),
        .array => |arr| {
            try out.append('[');
            for (arr.items, 0..) |item, i| {
                if (i > 0) try out.append(',');
                try writeValue(a, out, item);
            }
            try out.append(']');
        },
        .object => |o| {
            // Sort a copy of the key list; never mutate the map's own order.
            const keys = try a.dupe([]const u8, o.keys());
            std.mem.sort([]const u8, keys, {}, lessThanBytes);
            try out.append('{');
            for (keys, 0..) |k, i| {
                if (i > 0) try out.append(',');
                try writeString(out, k);
                try out.append(':');
                try writeValue(a, out, o.get(k).?);
            }
            try out.append('}');
        },
    }
}

/// JCS string escaping: the two-character escapes for the JSON specials,
/// \u00xx for remaining control characters, everything else verbatim
/// (multi-byte UTF-8 sequences pass through untouched, byte for byte).
pub fn writeString(out: *std.ArrayList(u8), s: []const u8) !void {
    try out.append('"');
    for (s) |c| {
        switch (c) {
            '"' => try out.appendSlice("\\\""),
            '\\' => try out.appendSlice("\\\\"),
            0x08 => try out.appendSlice("\\b"),
            '\t' => try out.appendSlice("\\t"),
            '\n' => try out.appendSlice("\\n"),
            0x0c => try out.appendSlice("\\f"),
            '\r' => try out.appendSlice("\\r"),
            else => {
                if (c < 0x20) {
                    try out.writer().print("\\u{x:0>4}", .{c});
                } else {
                    try out.append(c);
                }
            },
        }
    }
    try out.append('"');
}

/// RFC 8785 number serialization for a float, mirroring Python's
/// _jcs_number: zero prints "0"; an integral value below 1e21 prints as the
/// exact integer (via i128, wide enough for every f64 below 1e21); everything
/// else prints as the shortest round-trip decimal. Zig 0.13's `{d}` float
/// formatting is shortest-round-trip and never produces exponent forms, so
/// there is no exponent notation to normalize; full ECMAScript exponent
/// formatting for extreme magnitudes is pinned out at the 1.0.0 freeze,
/// exactly as the Python reference notes.
pub fn jcsNumber(a: Allocator, f: f64) ![]u8 {
    if (!std.math.isFinite(f)) return error.NonFiniteNumber;
    if (f == 0) return a.dupe(u8, "0");
    if (@floor(f) == f and @abs(f) < 1e21) {
        return std.fmt.allocPrint(a, "{d}", .{@as(i128, @intFromFloat(f))});
    }
    return std.fmt.allocPrint(a, "{d}", .{f});
}

/// A numeric value (integer or float) widened to f64, else null.
pub fn numAsF64(v: Value) ?f64 {
    return switch (v) {
        .integer => |i| @floatFromInt(i),
        .float => |f| f,
        else => null,
    };
}

/// Deep structural equality with Python's cross-type numeric equality
/// (1 == 1.0). Objects compare order-insensitively, arrays element-wise.
pub fn deepEqual(x: Value, y: Value) bool {
    if (numAsF64(x) != null or numAsF64(y) != null) {
        const fx = numAsF64(x) orelse return false;
        const fy = numAsF64(y) orelse return false;
        return fx == fy;
    }
    switch (x) {
        .null => return y == .null,
        .bool => |b| return y == .bool and y.bool == b,
        .string => |s| return y == .string and std.mem.eql(u8, s, y.string),
        .number_string => |s| return y == .number_string and std.mem.eql(u8, s, y.number_string),
        .array => |arr| {
            if (y != .array or y.array.items.len != arr.items.len) return false;
            for (arr.items, y.array.items) |xi, yi| {
                if (!deepEqual(xi, yi)) return false;
            }
            return true;
        },
        .object => |o| {
            if (y != .object or y.object.count() != o.count()) return false;
            var it = o.iterator();
            while (it.next()) |e| {
                const yv = y.object.get(e.key_ptr.*) orelse return false;
                if (!deepEqual(e.value_ptr.*, yv)) return false;
            }
            return true;
        },
        else => return false,
    }
}

/// Shallow copy of an object map (the analogue of Python's dict(obj)):
/// a fresh insertion-ordered map sharing the key and value storage.
pub fn cloneObject(a: Allocator, o: ObjectMap) !ObjectMap {
    var out = ObjectMap.init(a);
    try out.ensureTotalCapacity(o.count());
    var it = o.iterator();
    while (it.next()) |e| {
        try out.put(e.key_ptr.*, e.value_ptr.*);
    }
    return out;
}

/// The string value of a field, or null if absent or not a string.
pub fn getString(o: ObjectMap, key: []const u8) ?[]const u8 {
    const v = o.get(key) orelse return null;
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

/// Lowercase hex encoding of a byte slice.
pub fn hexLower(a: Allocator, bytes: []const u8) ![]u8 {
    const charset = "0123456789abcdef";
    const out = try a.alloc(u8, bytes.len * 2);
    for (bytes, 0..) |b, i| {
        out[i * 2] = charset[b >> 4];
        out[i * 2 + 1] = charset[b & 0x0f];
    }
    return out;
}

/// True iff s is exactly n lowercase hex characters.
pub fn isHex(s: []const u8, n: usize) bool {
    if (s.len != n) return false;
    for (s) |c| {
        switch (c) {
            '0'...'9', 'a'...'f' => {},
            else => return false,
        }
    }
    return true;
}

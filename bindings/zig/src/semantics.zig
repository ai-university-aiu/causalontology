//! The semantic rules beyond the schemas (spec/semantics.md), ported from
//! bindings/python/causalontology/semantics.py.
//!
//! Local rules are checked here; store-context rules (materialized
//! acyclicity, retraction lineage) live in store.zig where the context exists.

const std = @import("std");
const jcs = @import("jcs.zig");
const canonical = @import("canonical.zig");

const Value = jcs.Value;
const ObjectMap = jcs.ObjectMap;
const Allocator = jcs.Allocator;
const Validation = jcs.Validation;

/// Rule 4: the fixed unit-conversion constants (average Gregorian values).
pub fn unitSeconds(unit: []const u8) ?f64 {
    const eq = std.mem.eql;
    if (eq(u8, unit, "instant")) return 0;
    if (eq(u8, unit, "seconds")) return 1;
    if (eq(u8, unit, "minutes")) return 60;
    if (eq(u8, unit, "hours")) return 3600;
    if (eq(u8, unit, "days")) return 86400;
    if (eq(u8, unit, "weeks")) return 604800;
    if (eq(u8, unit, "months")) return 2629746;
    if (eq(u8, unit, "years")) return 31556952;
    return null;
}

/// Rule 12: enrichment field-to-kind validity and entry shapes.
pub const EnrichmentFieldSpec = struct {
    field: []const u8,
    legal_kinds: []const []const u8,
    shape: []const u8, // "alias", or an identifier scheme prefix
};

pub const enrichment_fields = [_]EnrichmentFieldSpec{
    .{ .field = "aliases", .legal_kinds = &.{ "occurrent", "continuant" }, .shape = "alias" },
    .{ .field = "participants", .legal_kinds = &.{"occurrent"}, .shape = "cnt" },
    .{ .field = "subsumes", .legal_kinds = &.{"continuant"}, .shape = "cnt" },
    .{ .field = "part_of", .legal_kinds = &.{"continuant"}, .shape = "cnt" },
    .{ .field = "realized_in", .legal_kinds = &.{"realizable"}, .shape = "occ" },
};

pub const cro_optional_fields = [_][]const u8{ "mechanism", "temporal", "modality", "context" };

fn kindOfId(identifier: []const u8) ?[]const u8 {
    const i = std.mem.indexOfScalar(u8, identifier, ':') orelse return canonical.kindOfPrefix(identifier);
    return canonical.kindOfPrefix(identifier[0..i]);
}

/// (ok, reasons) - the locally checkable semantic rules.
pub fn validateSemantics(a: Allocator, obj_value: Value, kind_opt: ?[]const u8) !Validation {
    const obj = obj_value.object;
    const kind = kind_opt orelse try canonical.inferKind(obj);
    var errors = std.ArrayList([]const u8).init(a);

    if (std.mem.eql(u8, kind, "cro")) {
        if (obj.get("temporal")) |t| {
            if (t == .object) {
                const dmin = t.object.get("dmin");
                const dmax = t.object.get("dmax");
                if (dmin != null and dmax != null) {
                    const lo = jcs.numAsF64(dmin.?);
                    const hi = jcs.numAsF64(dmax.?);
                    if (lo != null and hi != null and lo.? > hi.?) {
                        try errors.append("dmin must be <= dmax");
                    }
                }
            }
        }
        if (jcs.getString(obj, "id")) |oid| {
            if (obj.get("mechanism")) |mech| {
                if (mech == .array) {
                    for (mech.array.items) |m| {
                        if (m == .string and std.mem.eql(u8, m.string, oid)) {
                            try errors.append("mechanism must be acyclic (a Causal Relation Object may not contain itself)");
                            break;
                        }
                    }
                }
            }
            if (jcs.getString(obj, "refines")) |r| {
                if (std.mem.eql(u8, r, oid)) {
                    try errors.append("refines must be acyclic");
                }
            }
        }
    }

    if (std.mem.eql(u8, kind, "enrichment")) {
        const field = jcs.getString(obj, "field") orelse "";
        const about = jcs.getString(obj, "about") orelse "";
        const entry = obj.get("entry");
        for (&enrichment_fields) |*spec| {
            if (!std.mem.eql(u8, spec.field, field)) continue;
            if (kindOfId(about)) |about_kind| {
                var legal = false;
                for (spec.legal_kinds) |lk| {
                    if (std.mem.eql(u8, lk, about_kind)) legal = true;
                }
                if (!legal) {
                    try errors.append(try std.fmt.allocPrint(a, "{s} is not a legal field for a {s} (rule 12)", .{ field, about_kind }));
                }
            }
            if (std.mem.eql(u8, spec.shape, "alias")) {
                const shaped = entry != null and entry.? == .object and
                    entry.?.object.contains("lang") and entry.?.object.contains("text");
                if (!shaped) {
                    try errors.append("an aliases entry must be a language-tagged text object");
                }
            } else {
                const prefix = try std.fmt.allocPrint(a, "{s}:", .{spec.shape});
                const shaped = entry != null and entry.? == .string and
                    std.mem.startsWith(u8, entry.?.string, prefix);
                if (!shaped) {
                    try errors.append(try std.fmt.allocPrint(a, "a {s} entry must be a {s}: identifier", .{ field, spec.shape }));
                }
            }
            break;
        }
    }

    return .{ .ok = errors.items.len == 0, .errors = errors.items };
}

pub const Partial = struct {
    partial: bool,
    missing: []const []const u8,
};

/// (partial, missing) - which optional CRO fields are unspecified.
pub fn isPartial(a: Allocator, cro: ObjectMap) !Partial {
    var missing = std.ArrayList([]const u8).init(a);
    for (cro_optional_fields) |f| {
        if (!cro.contains(f)) try missing.append(f);
    }
    return .{ .partial = missing.items.len > 0, .missing = missing.items };
}

/// Rule 4: temporal admissibility with the fixed constants.
pub fn admissible(cro: ObjectMap, elapsed_seconds: f64) bool {
    const t = cro.get("temporal") orelse return true; // no window, no constraint
    if (t != .object) return true;
    const unit = unitSeconds(jcs.getString(t.object, "unit") orelse "").?;
    const lo = jcs.numAsF64(t.object.get("dmin").?).? * unit;
    const hi = jcs.numAsF64(t.object.get("dmax").?).? * unit;
    return lo <= elapsed_seconds and elapsed_seconds <= hi;
}

/// True iff every string in xs appears in ys (as a set relation).
fn subsetOf(xs: []const Value, ys: []const Value) bool {
    outer: for (xs) |x| {
        for (ys) |y| {
            if (x == .string and y == .string and std.mem.eql(u8, x.string, y.string)) continue :outer;
        }
        return false;
    }
    return true;
}

fn setEq(xs: []const Value, ys: []const Value) bool {
    return subsetOf(xs, ys) and subsetOf(ys, xs);
}

fn windowOverlap(x: ObjectMap, y: ObjectMap) bool {
    const ta = x.get("temporal") orelse return true;
    const tb = y.get("temporal") orelse return true;
    if (ta != .object or tb != .object) return true; // either absent counts as overlapping
    const ua = unitSeconds(jcs.getString(ta.object, "unit") orelse "").?;
    const ub = unitSeconds(jcs.getString(tb.object, "unit") orelse "").?;
    const lo_a = jcs.numAsF64(ta.object.get("dmin").?).? * ua;
    const hi_a = jcs.numAsF64(ta.object.get("dmax").?).? * ua;
    const lo_b = jcs.numAsF64(tb.object.get("dmin").?).? * ub;
    const hi_b = jcs.numAsF64(tb.object.get("dmax").?).? * ub;
    return lo_a <= hi_b and lo_b <= hi_a;
}

fn contextsCompatible(x: ObjectMap, y: ObjectMap) bool {
    const ca = x.get("context");
    const cb = y.get("context");
    // Either absent (or empty) counts as compatible.
    if (ca == null or ca.? != .array or ca.?.array.items.len == 0) return true;
    if (cb == null or cb.? != .array or cb.?.array.items.len == 0) return true;
    const sa = ca.?.array.items;
    const sb = cb.?.array.items;
    return subsetOf(sa, sb) or subsetOf(sb, sa);
}

fn isPositiveModality(m: ?[]const u8) bool {
    const mm = m orelse return false;
    return std.mem.eql(u8, mm, "necessary") or std.mem.eql(u8, mm, "sufficient") or std.mem.eql(u8, mm, "contributory");
}

/// Rule 6: the formal conflict test.
pub fn conflicts(x: ObjectMap, y: ObjectMap) bool {
    if (!setEq(x.get("causes").?.array.items, y.get("causes").?.array.items)) return false;
    if (!setEq(x.get("effects").?.array.items, y.get("effects").?.array.items)) return false;
    if (!contextsCompatible(x, y)) return false;
    if (!windowOverlap(x, y)) return false;
    const ma = jcs.getString(x, "modality");
    const mb = jcs.getString(y, "modality");
    const a_prev = ma != null and std.mem.eql(u8, ma.?, "preventive");
    const b_prev = mb != null and std.mem.eql(u8, mb.?, "preventive");
    return (a_prev and isPositiveModality(mb)) or (b_prev and isPositiveModality(ma));
}

pub const Refinement = struct {
    ok: bool,
    reason: []const u8,
};

/// Rule 3: (ok, reason) - is child a valid refinement of parent?
pub fn refinementValid(child: ObjectMap, parent: ObjectMap) Refinement {
    const cr = child.get("refines");
    const pid = parent.get("id");
    const names_parent = if (cr == null and pid == null)
        true // both absent compare equal, as in Python None == None
    else if (cr != null and pid != null)
        jcs.deepEqual(cr.?, pid.?)
    else
        false;
    if (!names_parent) {
        return .{ .ok = false, .reason = "child does not name the parent in refines" };
    }
    if (!setEq(child.get("causes").?.array.items, parent.get("causes").?.array.items) or
        !setEq(child.get("effects").?.array.items, parent.get("effects").?.array.items))
    {
        return .{ .ok = false, .reason = "a refinement must keep the parent's causes and effects" };
    }
    var added: usize = 0;
    for (cro_optional_fields) |field| {
        if (parent.contains(field)) {
            const cv = child.get(field);
            if (cv == null or !jcs.deepEqual(cv.?, parent.get(field).?)) {
                return .{ .ok = false, .reason = "a refinement may not change a field the parent specified; this is a rival claim" };
            }
        } else if (child.contains(field)) {
            added += 1;
        }
    }
    if (added == 0) {
        return .{ .ok = false, .reason = "a refinement must add at least one unspecified field" };
    }
    return .{ .ok = true, .reason = "valid refinement" };
}

/// Rule 7: "consistent" | "inconsistent" | "indeterminate".
///
/// members: a map from CRO identifier to CRO object for the parent's
/// mechanism entries (the store's view of them).
pub fn hierarchyConsistent(a: Allocator, parent: ObjectMap, members: *const std.StringArrayHashMap(ObjectMap)) ![]const u8 {
    const mech = parent.get("mechanism");
    if (mech == null or mech.? != .array or mech.?.array.items.len == 0) {
        return "consistent"; // nothing claimed, nothing to check
    }
    // cause -> list of effects, built in record order (duplicates harmless).
    var edges = std.StringArrayHashMap(std.ArrayList([]const u8)).init(a);
    for (mech.?.array.items) |mid| {
        const m = members.get(mid.string) orelse return "indeterminate"; // dangling_reference gap, not a failure
        for (m.get("causes").?.array.items) |c| {
            const gop = try edges.getOrPut(c.string);
            if (!gop.found_existing) gop.value_ptr.* = std.ArrayList([]const u8).init(a);
            for (m.get("effects").?.array.items) |e| {
                try gop.value_ptr.append(e.string);
            }
        }
    }
    for (parent.get("causes").?.array.items) |c| {
        for (parent.get("effects").?.array.items) |e| {
            if (!try reachable(a, &edges, c.string, e.string)) return "inconsistent";
        }
    }
    return "consistent";
}

fn reachable(a: Allocator, edges: *const std.StringArrayHashMap(std.ArrayList([]const u8)), src: []const u8, dst: []const u8) !bool {
    var seen = std.StringArrayHashMap(void).init(a);
    var stack = std.ArrayList([]const u8).init(a);
    try stack.append(src);
    while (stack.items.len > 0) {
        const node = stack.pop();
        if (std.mem.eql(u8, node, dst)) return true;
        if (seen.contains(node)) continue;
        try seen.put(node, {});
        if (edges.get(node)) |nexts| {
            try stack.appendSlice(nexts.items);
        }
    }
    return false;
}

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
    .{ .field = "participants", .legal_kinds = &.{"occurrent"}, .shape = "continuant" },
    .{ .field = "subsumes", .legal_kinds = &.{"continuant"}, .shape = "continuant" },
    .{ .field = "part_of", .legal_kinds = &.{"continuant"}, .shape = "continuant" },
    .{ .field = "realized_in", .legal_kinds = &.{"realizable"}, .shape = "occurrent" },
    // Two occurrent forms added in 2.0.0 (rule 12, amended).
    .{ .field = "occurrent_subsumes", .legal_kinds = &.{"occurrent"}, .shape = "occurrent" },
    .{ .field = "occurrent_part_of", .legal_kinds = &.{"occurrent"}, .shape = "occurrent" },
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

    if (std.mem.eql(u8, kind, "causal_relation_object")) {
        if (obj.get("temporal")) |t| {
            if (t == .object) {
                const minimum_delay = t.object.get("minimum_delay");
                const maximum_delay = t.object.get("maximum_delay");
                if (minimum_delay != null and maximum_delay != null) {
                    const lo = jcs.numAsF64(minimum_delay.?);
                    const hi = jcs.numAsF64(maximum_delay.?);
                    if (lo != null and hi != null and lo.? > hi.?) {
                        try errors.append("minimum_delay must be <= maximum_delay");
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
        // Rule 16, clause 1 (contradictory_skip): a HARD, locally-decidable
        // contradiction between skips:true and a non-empty mechanism.
        const skips = obj.get("skips");
        const skips_true = skips != null and skips.? == .bool and skips.?.bool;
        const mech = obj.get("mechanism");
        const has_mech = mech != null and mech.? == .array and mech.?.array.items.len > 0;
        if (skips_true and has_mech) {
            try errors.append("contradictory_skip: skips is true but a mechanism is present");
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
    const lo = jcs.numAsF64(t.object.get("minimum_delay").?).? * unit;
    const hi = jcs.numAsF64(t.object.get("maximum_delay").?).? * unit;
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
    const lo_a = jcs.numAsF64(ta.object.get("minimum_delay").?).? * ua;
    const hi_a = jcs.numAsF64(ta.object.get("maximum_delay").?).? * ua;
    const lo_b = jcs.numAsF64(tb.object.get("minimum_delay").?).? * ub;
    const hi_b = jcs.numAsF64(tb.object.get("maximum_delay").?).? * ub;
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
    // Rule 6 (amended): necessary, sufficient, contributory, enabling are
    // mutually compatible; preventive opposes all four.
    const mm = m orelse return false;
    return std.mem.eql(u8, mm, "necessary") or std.mem.eql(u8, mm, "sufficient") or
        std.mem.eql(u8, mm, "contributory") or std.mem.eql(u8, mm, "enabling");
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

// ===========================================================================
// 2.0.0 NORMATIVE ALGORITHMS (Section 12)
// ===========================================================================

/// ALGORITHM A. Every finer occurrent an occurrent resolves to, following
/// Bridges downward, transitively. Includes the starting occurrent (N12.1.1).
/// `bridges` is any slice of bridge objects. The visited guard (N12.1.2)
/// prevents an infinite loop on malformed cyclic data. Returns a set (a
/// StringArrayHashMap(void)) of occurrent identifiers.
pub fn bridgeClosure(a: Allocator, occurrent_id: []const u8, bridges: []const ObjectMap) !std.StringArrayHashMap(void) {
    var coarse_index = std.StringArrayHashMap(std.ArrayList(ObjectMap)).init(a);
    for (bridges) |b| {
        const coarse = jcs.getString(b, "coarse") orelse continue;
        const gop = try coarse_index.getOrPut(coarse);
        if (!gop.found_existing) gop.value_ptr.* = std.ArrayList(ObjectMap).init(a);
        try gop.value_ptr.append(b);
    }
    var result = std.StringArrayHashMap(void).init(a);
    try result.put(occurrent_id, {});
    var visited = std.StringArrayHashMap(void).init(a);
    var frontier = std.ArrayList([]const u8).init(a);
    try frontier.append(occurrent_id);
    while (frontier.items.len > 0) {
        const current = frontier.pop();
        if (visited.contains(current)) continue;
        try visited.put(current, {});
        if (coarse_index.get(current)) |bs| {
            for (bs.items) |b| {
                if (b.get("fine")) |fine| {
                    if (fine == .array) {
                        for (fine.array.items) |f| {
                            if (f == .string) {
                                try result.put(f.string, {});
                                try frontier.append(f.string);
                            }
                        }
                    }
                }
            }
        }
    }
    return result;
}

/// ALGORITHM B (amended Rule 7): "consistent" | "inconsistent" |
/// "indeterminate", ACROSS STRATA via bridged reachability.
///
/// members: a map from CRO identifier to CRO object for the parent's
/// mechanism entries. bridges: the store's bridges (empty -> 1.0.0 literal
/// reachability, the degenerate case, N12.2.3).
pub fn hierarchyConsistent(a: Allocator, parent: ObjectMap, members: *const std.StringArrayHashMap(ObjectMap), bridges: []const ObjectMap) ![]const u8 {
    const mech = parent.get("mechanism");
    if (mech == null or mech.? != .array or mech.?.array.items.len == 0) {
        return "consistent"; // nothing claimed, nothing to check (N12.2.1)
    }
    // cause -> list of effects, built in record order (duplicates harmless).
    var edges = std.StringArrayHashMap(std.ArrayList([]const u8)).init(a);
    for (mech.?.array.items) |mid| {
        const m = members.get(mid.string) orelse return "indeterminate"; // dangling; ignorance, not refutation
        for (m.get("causes").?.array.items) |c| {
            const gop = try edges.getOrPut(c.string);
            if (!gop.found_existing) gop.value_ptr.* = std.ArrayList([]const u8).init(a);
            for (m.get("effects").?.array.items) |e| {
                try gop.value_ptr.append(e.string);
            }
        }
    }
    for (parent.get("causes").?.array.items) |c| {
        const b_cause = try bridgeClosure(a, c.string, bridges);
        for (parent.get("effects").?.array.items) |e| {
            const b_effect = try bridgeClosure(a, e.string, bridges);
            var connected = false;
            for (b_cause.keys()) |cp| {
                for (b_effect.keys()) |ep| {
                    if (try reachable(a, &edges, cp, ep)) {
                        connected = true;
                        break;
                    }
                }
                if (connected) break;
            }
            if (!connected) return "inconsistent";
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

/// A map from content identifier to the content object (occ_map, stratum_map,
/// port_map, token_map, members, cro_map).
pub const ObjMap = std.StringArrayHashMap(ObjectMap);

/// The stratum identifier an occurrent is pitched at, or null.
fn stratumOf(occ_map: *const ObjMap, occ_id: []const u8) ?[]const u8 {
    const o = occ_map.get(occ_id) orelse return null;
    return jcs.getString(o, "stratum");
}

fn ordinalOf(stratum_map: *const ObjMap, sid: []const u8) i64 {
    const s = stratum_map.get(sid).?;
    return @intFromFloat(jcs.numAsF64(s.get("ordinal").?).?);
}

/// ALGORITHM C (Rule 15): "intra_stratal" | "adjacent_stratal" | "skipping" |
/// "mixed" | "unclassifiable" | "scheme_mismatch". Derived, never asserted;
/// recompute on ingest (N12.3.1).
pub fn classifyCro(a: Allocator, cro: ObjectMap, occ_map: *const ObjMap, stratum_map: *const ObjMap) ![]const u8 {
    var cause_strata = std.ArrayList([]const u8).init(a);
    var effect_strata = std.ArrayList([]const u8).init(a);
    for (cro.get("causes").?.array.items) |c| {
        const s = stratumOf(occ_map, c.string) orelse return "unclassifiable";
        try cause_strata.append(s);
    }
    for (cro.get("effects").?.array.items) |e| {
        const s = stratumOf(occ_map, e.string) orelse return "unclassifiable";
        try effect_strata.append(s);
    }
    // schemes across the union of all strata; more than one is a HARD mismatch.
    var all = std.StringArrayHashMap(void).init(a);
    for (cause_strata.items) |s| try all.put(s, {});
    for (effect_strata.items) |s| try all.put(s, {});
    var schemes = std.StringArrayHashMap(void).init(a);
    for (all.keys()) |s| {
        const scheme = jcs.getString(stratum_map.get(s).?, "scheme").?;
        try schemes.put(scheme, {});
    }
    if (schemes.count() > 1) return "scheme_mismatch";
    var c_ord = std.ArrayList(i64).init(a);
    var e_ord = std.ArrayList(i64).init(a);
    for (cause_strata.items) |s| try c_ord.append(ordinalOf(stratum_map, s));
    for (effect_strata.items) |s| try e_ord.append(ordinalOf(stratum_map, s));
    const c_max = maxI64(c_ord.items);
    const c_min = minI64(c_ord.items);
    const e_max = maxI64(e_ord.items);
    const e_min = minI64(e_ord.items);
    if (c_max == c_min and c_min == e_max and e_max == e_min) return "intra_stratal";
    var gap: i64 = std.math.maxInt(i64);
    var span: i64 = 0;
    for (c_ord.items) |i| {
        for (e_ord.items) |j| {
            const d = if (i > j) i - j else j - i;
            if (d < gap) gap = d;
            if (d > span) span = d;
        }
    }
    if (span == 1) return "adjacent_stratal";
    if (gap > 1) return "skipping";
    return "mixed"; // some pairs adjacent, some skipping
}

fn maxI64(xs: []const i64) i64 {
    var m = xs[0];
    for (xs[1..]) |x| {
        if (x > m) m = x;
    }
    return m;
}

fn minI64(xs: []const i64) i64 {
    var m = xs[0];
    for (xs[1..]) |x| {
        if (x < m) m = x;
    }
    return m;
}

/// True iff causes or effects span more than one distinct stratum (surfaces
/// mixed_stratal_endpoints, an invitation; N12.3.2).
pub fn endpointsMixed(a: Allocator, cro: ObjectMap, occ_map: *const ObjMap) !bool {
    var cs = std.StringArrayHashMap(void).init(a);
    var es = std.StringArrayHashMap(void).init(a);
    for (cro.get("causes").?.array.items) |c| {
        const s = stratumOf(occ_map, c.string) orelse return false; // None in cs
        try cs.put(s, {});
    }
    for (cro.get("effects").?.array.items) |e| {
        const s = stratumOf(occ_map, e.string) orelse return false; // None in es
        try es.put(s, {});
    }
    return cs.count() > 1 or es.count() > 1;
}

/// ALGORITHM D (Rule 16): the gaps a Causal Relation Object surfaces for the
/// skip decision. THE ASYMMETRY (clause 3) is the whole point of the field.
pub fn skipGaps(a: Allocator, cro: ObjectMap, classification: []const u8) !std.ArrayList([]const u8) {
    var gaps = std.ArrayList([]const u8).init(a);
    const mech = cro.get("mechanism");
    const has_mech = mech != null and mech.? == .array and mech.?.array.items.len > 0;
    const skips = cro.get("skips");
    const skips_true = skips != null and skips.? == .bool and skips.?.bool;
    if (skips_true and has_mech) {
        try gaps.append("contradictory_skip"); // HARD
        return gaps;
    }
    const cls_skipping = std.mem.eql(u8, classification, "skipping");
    const cls_unclassifiable = std.mem.eql(u8, classification, "unclassifiable");
    if (skips_true and !(cls_skipping or cls_unclassifiable)) {
        try gaps.append("vacuous_skip"); // invitation
    }
    if (cls_skipping and !has_mech) {
        if (skips_true) {
            // NOTHING: absence is a finding
        } else {
            try gaps.append("incomplete_mechanism"); // invitation
        }
    }
    return gaps;
}

/// ALGORITHM E helper: normalize a delay to seconds by the fixed table.
pub fn toSeconds(duration: f64, unit: []const u8) f64 {
    if (std.mem.eql(u8, unit, "instant")) return 0;
    return duration * unitSeconds(unit).?;
}

/// ALGORITHM E (Rule 20): does an observed delay fall within a covering law's
/// temporal window? Inclusive at both ends (N12.5.2).
pub fn delayWithinWindow(actual_delay: ?ObjectMap, temporal: ?ObjectMap) bool {
    if (actual_delay == null or temporal == null) return true; // nothing to check
    const ad = actual_delay.?;
    const t = temporal.?;
    const observed = toSeconds(jcs.numAsF64(ad.get("duration").?).?, jcs.getString(ad, "unit").?);
    const lo = toSeconds(jcs.numAsF64(t.get("minimum_delay").?).?, jcs.getString(t, "unit").?);
    const hi = toSeconds(jcs.numAsF64(t.get("maximum_delay").?).?, jcs.getString(t, "unit").?);
    return lo <= observed and observed <= hi;
}

pub const OkReason = struct {
    ok: bool,
    reason: []const u8,
};

/// Rule 14 / N3.2.1: Bridge well-formedness. All of (a)-(e) must hold.
pub fn bridgeWellformed(bridge: ObjectMap, occ_map: *const ObjMap, stratum_map: *const ObjMap) OkReason {
    const coarse_id = jcs.getString(bridge, "coarse") orelse "";
    const cs = stratumOf(occ_map, coarse_id) orelse
        return .{ .ok = false, .reason = "malformed_bridge: coarse has no stratum (a)" };
    var fs: ?[]const u8 = null;
    for (bridge.get("fine").?.array.items) |f| {
        const s = stratumOf(occ_map, f.string) orelse
            return .{ .ok = false, .reason = "malformed_bridge: a fine member has no stratum (b)" };
        if (fs == null) {
            fs = s;
        } else if (!std.mem.eql(u8, fs.?, s)) {
            return .{ .ok = false, .reason = "malformed_bridge: fine members span >1 stratum (c)" };
        }
    }
    const cs_scheme = jcs.getString(stratum_map.get(cs).?, "scheme").?;
    const fs_scheme = jcs.getString(stratum_map.get(fs.?).?, "scheme").?;
    if (!std.mem.eql(u8, cs_scheme, fs_scheme)) {
        return .{ .ok = false, .reason = "malformed_bridge: coarse and fine differ in scheme (d)" };
    }
    if (!(ordinalOf(stratum_map, cs) > ordinalOf(stratum_map, fs.?))) {
        return .{ .ok = false, .reason = "malformed_bridge: coarse ordinal not > fine ordinal (e)" };
    }
    return .{ .ok = true, .reason = "well-formed bridge" };
}

fn allIn(needles: []const Value, haystack: []const Value) bool {
    for (needles) |n| {
        var found = false;
        for (haystack) |h| {
            if (n == .string and h == .string and std.mem.eql(u8, n.string, h.string)) found = true;
        }
        if (!found) return false;
    }
    return true;
}

fn directionOneOf(port: ObjectMap, opts: []const []const u8) bool {
    const d = jcs.getString(port, "direction") orelse return false;
    for (opts) |o| {
        if (std.mem.eql(u8, d, o)) return true;
    }
    return false;
}

/// Rule 17 / N4.2.1-2: Conduit well-formedness, with the transform exception.
pub fn conduitWellformed(conduit: ObjectMap, port_map: *const ObjMap, cro_map: ?*const ObjMap) OkReason {
    const frm = port_map.get(jcs.getString(conduit, "from") orelse "") orelse
        return .{ .ok = false, .reason = "malformed_conduit: dangling port reference" };
    const to = port_map.get(jcs.getString(conduit, "to") orelse "") orelse
        return .{ .ok = false, .reason = "malformed_conduit: dangling port reference" };
    if (!directionOneOf(frm, &.{ "out", "bidirectional" })) {
        return .{ .ok = false, .reason = "malformed_conduit: from port is not out/bidirectional (a)" };
    }
    if (!directionOneOf(to, &.{ "in", "bidirectional" })) {
        return .{ .ok = false, .reason = "malformed_conduit: to port is not in/bidirectional (b)" };
    }
    const carries = conduit.get("carries").?.array.items;
    if (!allIn(carries, frm.get("accepts").?.array.items)) {
        return .{ .ok = false, .reason = "malformed_conduit: carries not accepted by from (c)" };
    }
    const transform = jcs.getString(conduit, "transform");
    if (transform == null) {
        if (!allIn(carries, to.get("accepts").?.array.items)) {
            return .{ .ok = false, .reason = "malformed_conduit: carries not accepted by to (d)" };
        }
    } else {
        const law_opt = if (cro_map) |cm| cm.get(transform.?) else null;
        if (law_opt) |law| {
            if (!allIn(law.get("effects").?.array.items, to.get("accepts").?.array.items)) {
                return .{ .ok = false, .reason = "malformed_conduit: transform effects not accepted by to (d, relaxed per N4.2.2)" };
            }
        }
    }
    return .{ .ok = true, .reason = "well-formed conduit" };
}

/// Rule 19 / N5.3.1-2: the HARD gaps a state assertion surfaces against its
/// quality: value_type_mismatch and/or unit_mismatch.
pub fn stateGaps(a: Allocator, state: ObjectMap, quality: ObjectMap) !std.ArrayList([]const u8) {
    var gaps = std.ArrayList([]const u8).init(a);
    const dt = jcs.getString(quality, "datatype"); // may be null
    const v = state.get("value");
    const vo: ?ObjectMap = if (v != null and v.? == .object) v.?.object else null;
    var shape: ?[]const u8 = null;
    if (vo) |m| {
        if (m.contains("quantity")) {
            shape = "quantity";
        } else if (m.contains("categorical")) {
            shape = "categorical";
        } else if (m.contains("boolean")) {
            shape = "boolean";
        }
    }
    const shape_matches = (shape == null and dt == null) or
        (shape != null and dt != null and std.mem.eql(u8, shape.?, dt.?));
    if (!shape_matches) {
        try gaps.append("value_type_mismatch");
    } else if (dt != null and std.mem.eql(u8, dt.?, "quantity")) {
        const vunit = if (vo) |m| jcs.getString(m, "unit") else null;
        const qunit = jcs.getString(quality, "unit");
        const units_equal = (vunit == null and qunit == null) or
            (vunit != null and qunit != null and std.mem.eql(u8, vunit.?, qunit.?));
        if (!units_equal) try gaps.append("unit_mismatch");
    }
    return gaps;
}

/// Rule 20: True iff the token claim's cause/effect tokens do not instantiate
/// the covering law's causes/effects (surfaces covering_law_mismatch).
pub fn coveringLawMismatch(tcc: ObjectMap, token_map: *const ObjMap, law: ?ObjectMap) bool {
    const l = law orelse return false;
    const law_causes = l.get("causes").?.array.items;
    const law_effects = l.get("effects").?.array.items;
    for (tcc.get("causes").?.array.items) |c| {
        const inst = jcs.getString(token_map.get(c.string).?, "instantiates").?;
        if (!containsStr(law_causes, inst)) return true;
    }
    for (tcc.get("effects").?.array.items) |e| {
        const inst = jcs.getString(token_map.get(e.string).?, "instantiates").?;
        if (!containsStr(law_effects, inst)) return true;
    }
    return false;
}

fn containsStr(xs: []const Value, needle: []const u8) bool {
    for (xs) |x| {
        if (x == .string and std.mem.eql(u8, x.string, needle)) return true;
    }
    return false;
}

/// Rule 21: True iff any cause token starts after any effect token (HARD;
/// retrocausal_claim). RFC 3339 UTC 'Z' strings compare lexicographically.
pub fn retrocausal(tcc: ObjectMap, token_map: *const ObjMap) bool {
    for (tcc.get("causes").?.array.items) |c| {
        const cstart = jcs.getString(token_map.get(c.string).?.get("interval").?.object, "start").?;
        for (tcc.get("effects").?.array.items) |e| {
            const estart = jcs.getString(token_map.get(e.string).?.get("interval").?.object, "start").?;
            if (std.mem.order(u8, cstart, estart) == .gt) return true;
        }
    }
    return false;
}

const CYCLE_WHITE: u8 = 0;
const CYCLE_GREY: u8 = 1;
const CYCLE_BLACK: u8 = 2;

const CycleEdges = std.StringArrayHashMap(std.ArrayList([]const u8));

fn cycleVisit(edges: *const CycleEdges, state: *std.StringArrayHashMap(u8), node: []const u8) anyerror!bool {
    try state.put(node, CYCLE_GREY);
    if (edges.get(node)) |nexts| {
        for (nexts.items) |nxt| {
            const s = state.get(nxt) orelse CYCLE_WHITE;
            if (s == CYCLE_GREY) return true;
            if (s == CYCLE_WHITE and try cycleVisit(edges, state, nxt)) return true;
        }
    }
    try state.put(node, CYCLE_BLACK);
    return false;
}

/// Rules 4 / 6.1: True iff a directed graph (node -> successors) has a cycle.
/// Used for the bridge graph, occurrent_subsumes, occurrent_part_of, and token
/// mereology (part_of).
pub fn hasCycle(a: Allocator, edges: *const CycleEdges) !bool {
    var state = std.StringArrayHashMap(u8).init(a);
    for (edges.keys()) |n| {
        if ((state.get(n) orelse CYCLE_WHITE) == CYCLE_WHITE and try cycleVisit(edges, &state, n)) return true;
    }
    return false;
}

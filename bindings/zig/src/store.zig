//! An in-memory conformant store, ported from
//! bindings/python/causalontology/store.py (the CURRENT store rules).
//!
//! Implements the store side of the abstract operation set (spec/store.md):
//! immutable content objects with idempotent put; signed, add-only provenance
//! records with quarantine for the unverifiable; materialized enrichment
//! views with contributors; retraction handling in default views; succession
//! lineage; the resolve minimum (label before alias); the deterministic
//! cycle-breaking view rule; and the stigmergy gap read with its five gap
//! kinds.
//!
//! Where the Python reference iterates dicts, insertion order is normative.
//! Every map here is a StringArrayHashMap (objects, records, quarantine,
//! retracted-id sets, cycle-finder adjacency, view buckets), which iterates
//! in insertion order - never a StringHashMap, whose order is undefined.

const std = @import("std");
const jcs = @import("jcs.zig");
const canonical = @import("canonical.zig");
const schema = @import("schema.zig");
const semantics = @import("semantics.zig");
const signing = @import("signing.zig");

const Value = jcs.Value;
const ObjectMap = jcs.ObjectMap;
const Array = jcs.Array;
const Allocator = jcs.Allocator;

const content_kinds = [_][]const u8{ "occurrent", "causal_relation_object", "continuant", "realizable" };
const record_kinds = [_][]const u8{ "assertion", "enrichment", "retraction", "succession" };

fn inList(list: []const []const u8, s: []const u8) bool {
    for (list) |x| {
        if (std.mem.eql(u8, x, s)) return true;
    }
    return false;
}

fn eq(x: []const u8, y: []const u8) bool {
    return std.mem.eql(u8, x, y);
}

/// The active and excluded taxonomy records after rule 13 cycle-breaking.
pub const TaxonomyEdges = struct {
    active: std.ArrayList(ObjectMap),
    excluded: std.ArrayList(ObjectMap),
};

pub const Store = struct {
    a: Allocator,
    enforcing: bool,
    objects: std.StringArrayHashMap(ObjectMap), // id -> content object
    records: std.StringArrayHashMap(ObjectMap), // id -> provenance record
    quarantine: std.StringArrayHashMap(ObjectMap), // id -> record (unsigned / unverifiable)
    /// The reason for the last error.RejectedWrite (Zig errors carry no
    /// payload, so the analogue of Python's str(RejectedWrite) lives here).
    reject_reason: []const u8 = "",

    pub fn init(a: Allocator, enforcing: bool) Store {
        return .{
            .a = a,
            .enforcing = enforcing,
            .objects = std.StringArrayHashMap(ObjectMap).init(a),
            .records = std.StringArrayHashMap(ObjectMap).init(a),
            .quarantine = std.StringArrayHashMap(ObjectMap).init(a),
        };
    }

    /// Record the refusal reason and return the RejectedWrite error.
    fn rejectWrite(self: *Store, comptime fmt: []const u8, args: anytype) anyerror {
        self.reject_reason = std.fmt.allocPrint(self.a, fmt, args) catch return error.OutOfMemory;
        return error.RejectedWrite;
    }

    fn rejectJoined(self: *Store, reasons: []const []const u8) anyerror {
        const joined = std.mem.join(self.a, "; ", reasons) catch return error.OutOfMemory;
        return self.rejectWrite("{s}", .{joined});
    }

    // ------------------------------------------------------------------ put

    /// Write a content object; idempotent; returns the identifier.
    pub fn put(self: *Store, obj_in: ObjectMap, kind_opt: ?[]const u8) anyerror![]const u8 {
        const kind = kind_opt orelse try canonical.inferKind(obj_in);
        if (!inList(&content_kinds, kind)) return error.NotAContentObject; // use putRecord()
        var obj = try jcs.cloneObject(self.a, obj_in);
        if (!obj.contains("type")) try obj.put("type", .{ .string = kind });
        var id = jcs.getString(obj, "id");
        if (!obj.contains("id")) {
            id = try canonical.identify(self.a, obj, kind);
            try obj.put("id", .{ .string = id.? });
        }
        const oid = id orelse return error.MalformedIdentifier;
        if (self.objects.contains(oid)) {
            return oid; // immutable: identical identity is a no-op
        }
        const sr = try schema.validateSchema(self.a, .{ .object = obj }, kind);
        if (!sr.ok) return self.rejectJoined(sr.errors);
        const mr = try semantics.validateSemantics(self.a, .{ .object = obj }, kind);
        if (!mr.ok) return self.rejectJoined(mr.errors);
        try self.objects.put(oid, obj);
        return oid;
    }

    /// Write a signed provenance record; returns the identifier.
    /// force simulates a decentralized replica merge (no enforcement gate).
    pub fn putRecord(self: *Store, record_in: ObjectMap, kind_opt: ?[]const u8, force: bool) anyerror![]const u8 {
        const kind = kind_opt orelse try canonical.inferKind(record_in);
        if (!inList(&record_kinds, kind)) return error.NotAProvenanceRecord; // use put()
        var record = try jcs.cloneObject(self.a, record_in);
        if (!record.contains("type")) try record.put("type", .{ .string = kind });
        const rid = jcs.getString(record, "id") orelse try canonical.identify(self.a, record, kind);
        try record.put("id", .{ .string = rid });
        if (self.records.contains(rid)) {
            return rid; // add-only and idempotent
        }
        if (!signing.verifyRecord(self.a, record, kind)) {
            try self.quarantine.put(rid, record);
            return self.rejectWrite("unsigned or unverifiable record: quarantined", .{});
        }
        const mr = try semantics.validateSemantics(self.a, .{ .object = record }, kind);
        if (!mr.ok) return self.rejectJoined(mr.errors);
        if (eq(kind, "retraction") and !try self.retractionSourceOk(record)) {
            return self.rejectWrite("a retraction is valid only from the retracted record's source or its succession lineage", .{});
        }
        if (eq(kind, "enrichment") and self.enforcing and !force) {
            const field = jcs.getString(record, "field") orelse "";
            if ((eq(field, "subsumes") or eq(field, "part_of")) and try self.wouldCycle(record)) {
                return self.rejectWrite("would create a cycle in the materialized {s} graph", .{field});
            }
        }
        try self.records.put(rid, record);
        return rid;
    }

    /// Simulate a decentralized replica merge (no enforcement gate).
    pub fn forceMergeRecord(self: *Store, record: ObjectMap, kind_opt: ?[]const u8) anyerror![]const u8 {
        return self.putRecord(record, kind_opt, true);
    }

    // ------------------------------------------------------- record queries

    /// The records of one kind, in insertion order.
    fn recordsOf(self: *Store, kind: []const u8) !std.ArrayList(ObjectMap) {
        var out = std.ArrayList(ObjectMap).init(self.a);
        for (self.records.values()) |r| {
            if (jcs.getString(r, "type")) |t| {
                if (eq(t, kind)) try out.append(r);
            }
        }
        return out;
    }

    /// The set of record identifiers named by some retraction.
    fn retractedIds(self: *Store) !std.StringArrayHashMap(void) {
        var out = std.StringArrayHashMap(void).init(self.a);
        for ((try self.recordsOf("retraction")).items) |r| {
            try out.put(jcs.getString(r, "retracts").?, {});
        }
        return out;
    }

    fn retractionSourceOk(self: *Store, retraction: ObjectMap) !bool {
        const target = self.records.get(jcs.getString(retraction, "retracts") orelse "") orelse
            return true; // open world: the target may arrive later
        const lin = try self.lineage(jcs.getString(target, "source") orelse "");
        return lin.contains(jcs.getString(retraction, "source") orelse "");
    }

    /// The succession chain closure containing key (includes key).
    pub fn lineage(self: *Store, key: []const u8) !std.StringArrayHashMap(void) {
        var succ = std.StringArrayHashMap([]const u8).init(self.a);
        var pred = std.StringArrayHashMap([]const u8).init(self.a);
        for ((try self.recordsOf("succession")).items) |s| {
            try succ.put(jcs.getString(s, "predecessor").?, jcs.getString(s, "successor").?);
            try pred.put(jcs.getString(s, "successor").?, jcs.getString(s, "predecessor").?);
        }
        var chain = std.StringArrayHashMap(void).init(self.a);
        try chain.put(key, {});
        var cursor = key;
        while (pred.get(cursor)) |p| {
            if (chain.contains(p)) break; // guard against a malformed loop
            cursor = p;
            try chain.put(p, {});
        }
        cursor = key;
        while (succ.get(cursor)) |s| {
            if (chain.contains(s)) break;
            cursor = s;
            try chain.put(s, {});
        }
        return chain;
    }

    /// The assertions about an identifier, retracted ones excluded by
    /// default; with include_retracted they return marked retracted=true.
    pub fn assertionsAbout(self: *Store, identifier: []const u8, include_retracted: bool) !std.ArrayList(ObjectMap) {
        const retracted = try self.retractedIds();
        var out = std.ArrayList(ObjectMap).init(self.a);
        for ((try self.recordsOf("assertion")).items) |r| {
            if (!eq(jcs.getString(r, "about") orelse "", identifier)) continue;
            if (retracted.contains(jcs.getString(r, "id") orelse "")) {
                if (include_retracted) {
                    var marked = try jcs.cloneObject(self.a, r);
                    try marked.put("retracted", .{ .bool = true });
                    try out.append(marked);
                }
                continue;
            }
            try out.append(r);
        }
        return out;
    }

    pub fn enrichmentsAbout(self: *Store, identifier: []const u8, include_retracted: bool) !std.ArrayList(ObjectMap) {
        const retracted = try self.retractedIds();
        var out = std.ArrayList(ObjectMap).init(self.a);
        for ((try self.recordsOf("enrichment")).items) |r| {
            if (!eq(jcs.getString(r, "about") orelse "", identifier)) continue;
            if (retracted.contains(jcs.getString(r, "id") orelse "") and !include_retracted) continue;
            try out.append(r);
        }
        return out;
    }

    // ------------------------------------------------- materialized views

    /// (active, excluded) for subsumes/part_of after rule 13 cycle-breaking:
    /// while a cycle exists, exclude its cycle-completing record with the
    /// LATEST timestamp, ties broken by lexicographic record identifier.
    pub fn activeTaxonomyEdges(self: *Store, field: []const u8) !TaxonomyEdges {
        const retracted = try self.retractedIds();
        var active = std.ArrayList(ObjectMap).init(self.a);
        for ((try self.recordsOf("enrichment")).items) |r| {
            if (!eq(jcs.getString(r, "field") orelse "", field)) continue;
            if (retracted.contains(jcs.getString(r, "id") orelse "")) continue;
            try active.append(r);
        }
        var excluded = std.ArrayList(ObjectMap).init(self.a);
        while (true) {
            const cyc = try findCycleRecords(self.a, active.items);
            if (cyc.items.len == 0) break;
            var loser = cyc.items[0];
            for (cyc.items[1..]) |r| {
                if (laterThan(r, loser)) loser = r;
            }
            const loser_id = jcs.getString(loser, "id").?;
            for (active.items, 0..) |r, i| {
                if (eq(jcs.getString(r, "id").?, loser_id)) {
                    _ = active.orderedRemove(i);
                    break;
                }
            }
            try excluded.append(loser);
        }
        return .{ .active = active, .excluded = excluded };
    }

    /// Strictly greater by the (timestamp, id) key, so the earliest maximal
    /// record wins ties exactly as Python's max() does.
    fn laterThan(r: ObjectMap, cur: ObjectMap) bool {
        const rt = jcs.getString(r, "timestamp") orelse "";
        const ct = jcs.getString(cur, "timestamp") orelse "";
        switch (std.mem.order(u8, rt, ct)) {
            .gt => return true,
            .lt => return false,
            .eq => return std.mem.order(u8, jcs.getString(r, "id") orelse "", jcs.getString(cur, "id") orelse "") == .gt,
        }
    }

    const EdgeTo = struct {
        next: []const u8,
        rec: ObjectMap,
    };

    const CycleFinder = struct {
        edges: *std.StringArrayHashMap(std.ArrayList(EdgeTo)),
        state: std.StringArrayHashMap(u8), // 0 unvisited, 1 on path, 2 done
        path: std.ArrayList(ObjectMap),
        cycle: std.ArrayList(ObjectMap),

        fn dfs(self: *CycleFinder, node: []const u8) anyerror!bool {
            try self.state.put(node, 1);
            if (self.edges.get(node)) |list| {
                for (list.items) |e| {
                    const st = self.state.get(e.next) orelse 0;
                    if (st == 1) {
                        try self.cycle.appendSlice(self.path.items);
                        try self.cycle.append(e.rec);
                        return true;
                    }
                    if (st == 0) {
                        try self.path.append(e.rec);
                        if (try self.dfs(e.next)) return true;
                        _ = self.path.pop();
                    }
                }
            }
            try self.state.put(node, 2);
            return false;
        }
    };

    /// The records forming a cycle in the about -> entry graph, or empty.
    /// Adjacency and start nodes iterate in first-appearance order, matching
    /// the Python dict-based DFS exactly.
    fn findCycleRecords(a: Allocator, recs: []const ObjectMap) !std.ArrayList(ObjectMap) {
        var edges = std.StringArrayHashMap(std.ArrayList(EdgeTo)).init(a);
        for (recs) |r| {
            const about = jcs.getString(r, "about") orelse continue;
            const entry = jcs.getString(r, "entry") orelse continue;
            const gop = try edges.getOrPut(about);
            if (!gop.found_existing) gop.value_ptr.* = std.ArrayList(EdgeTo).init(a);
            try gop.value_ptr.append(.{ .next = entry, .rec = r });
        }
        var finder = CycleFinder{
            .edges = &edges,
            .state = std.StringArrayHashMap(u8).init(a),
            .path = std.ArrayList(ObjectMap).init(a),
            .cycle = std.ArrayList(ObjectMap).init(a),
        };
        for (edges.keys()) |start| {
            if ((finder.state.get(start) orelse 0) == 0) {
                if (try finder.dfs(start)) return finder.cycle;
            }
        }
        return finder.cycle; // empty
    }

    fn wouldCycle(self: *Store, record: ObjectMap) !bool {
        const retracted = try self.retractedIds();
        const field = jcs.getString(record, "field") orelse "";
        var recs = std.ArrayList(ObjectMap).init(self.a);
        for ((try self.recordsOf("enrichment")).items) |r| {
            if (!eq(jcs.getString(r, "field") orelse "", field)) continue;
            if (retracted.contains(jcs.getString(r, "id") orelse "")) continue;
            try recs.append(r);
        }
        try recs.append(record);
        return (try findCycleRecords(self.a, recs.items)).items.len != 0;
    }

    /// The object with its materialized enrichment sets and contributors.
    /// view is "default", "history", or "raw".
    pub fn get(self: *Store, identifier: []const u8, view: []const u8) !?Value {
        const obj = self.objects.get(identifier) orelse return null;
        const include_retracted = eq(view, "history");
        var excluded_ids = std.StringArrayHashMap(void).init(self.a);
        for ([_][]const u8{ "subsumes", "part_of" }) |field| {
            const te = try self.activeTaxonomyEdges(field);
            for (te.excluded.items) |r| {
                try excluded_ids.put(jcs.getString(r, "id").?, {});
            }
        }
        const Bucket = struct {
            entry: Value,
            contributors: std.ArrayList(Value),
        };
        // field -> canonical-entry-key -> bucket, all in insertion order,
        // so corroborating contributors accumulate on one entry.
        var fields = std.StringArrayHashMap(std.StringArrayHashMap(Bucket)).init(self.a);
        for ((try self.enrichmentsAbout(identifier, include_retracted)).items) |rec| {
            const rid = jcs.getString(rec, "id").?;
            if (excluded_ids.contains(rid) and !eq(view, "history")) continue;
            const field = jcs.getString(rec, "field").?;
            const entry = rec.get("entry").?;
            // The canonical (RFC 8785) form is the dedup key: an object entry
            // keys by its sorted items, exactly like the Python tuple key.
            const entry_key = try jcs.jcs(self.a, entry);
            const slot = try fields.getOrPut(field);
            if (!slot.found_existing) slot.value_ptr.* = std.StringArrayHashMap(Bucket).init(self.a);
            const bucket = try slot.value_ptr.getOrPut(entry_key);
            if (!bucket.found_existing) {
                bucket.value_ptr.* = .{ .entry = entry, .contributors = std.ArrayList(Value).init(self.a) };
            }
            var contributor = ObjectMap.init(self.a);
            try contributor.put("source", rec.get("source").?);
            try contributor.put("timestamp", rec.get("timestamp").?);
            try bucket.value_ptr.contributors.append(.{ .object = contributor });
        }
        var enrichments = ObjectMap.init(self.a);
        var fit = fields.iterator();
        while (fit.next()) |fe| {
            var arr = Array.init(self.a);
            var bit = fe.value_ptr.iterator();
            while (bit.next()) |be| {
                var bucket_obj = ObjectMap.init(self.a);
                try bucket_obj.put("entry", be.value_ptr.entry);
                var contribs = Array.init(self.a);
                try contribs.appendSlice(be.value_ptr.contributors.items);
                try bucket_obj.put("contributors", .{ .array = contribs });
                try arr.append(.{ .object = bucket_obj });
            }
            try enrichments.put(fe.key_ptr.*, .{ .array = arr });
        }
        var out = ObjectMap.init(self.a);
        try out.put("object", .{ .object = obj });
        if (!eq(view, "raw")) {
            try out.put("enrichments", .{ .object = enrichments });
        }
        return .{ .object = out };
    }

    // -------------------------------------------------------------- resolve

    /// Canonical-label form: lowercase, whitespace runs collapsed to "_".
    fn canonLabel(a: Allocator, text: []const u8) ![]const u8 {
        var out = std.ArrayList(u8).init(a);
        var it = std.mem.tokenizeAny(u8, text, " \t\r\n\x0b\x0c");
        var first = true;
        while (it.next()) |tok| {
            if (!first) try out.append('_');
            for (tok) |c| try out.append(std.ascii.toLower(c));
            first = false;
        }
        return out.items;
    }

    /// Alias-normal form: whitespace runs collapsed to one space, lowercased
    /// (the ASCII analogue of Python's casefold, sufficient for the suite).
    fn normAlias(a: Allocator, text: []const u8) ![]const u8 {
        var out = std.ArrayList(u8).init(a);
        var it = std.mem.tokenizeAny(u8, text, " \t\r\n\x0b\x0c");
        var first = true;
        while (it.next()) |tok| {
            if (!first) try out.append(' ');
            for (tok) |c| try out.append(std.ascii.toLower(c));
            first = false;
        }
        return out.items;
    }

    /// The conformance minimum: exact label, then alias, then nothing.
    pub fn resolve(self: *Store, text: []const u8, lang: ?[]const u8) !std.ArrayList([]const u8) {
        var label_hits = std.ArrayList([]const u8).init(self.a);
        var alias_hits = std.ArrayList([]const u8).init(self.a);
        const wanted_label = try canonLabel(self.a, text);
        const wanted_alias = try normAlias(self.a, text);
        const retracted = try self.retractedIds();
        const enrichment_records = try self.recordsOf("enrichment");
        var it = self.objects.iterator();
        outer: while (it.next()) |e| {
            const oid = e.key_ptr.*;
            const obj = e.value_ptr.*;
            const t = jcs.getString(obj, "type") orelse "";
            if (!eq(t, "occurrent") and !eq(t, "continuant")) continue;
            if (jcs.getString(obj, "label")) |label| {
                if (eq(label, wanted_label)) {
                    try label_hits.append(oid);
                    continue :outer;
                }
            }
            for (enrichment_records.items) |rec| {
                if (!eq(jcs.getString(rec, "about") orelse "", oid)) continue;
                if (!eq(jcs.getString(rec, "field") orelse "", "aliases")) continue;
                if (retracted.contains(jcs.getString(rec, "id") orelse "")) continue;
                const entry = rec.get("entry") orelse continue;
                if (entry != .object) continue;
                if (lang) |lg| {
                    const entry_lang = jcs.getString(entry.object, "lang") orelse "";
                    if (!eq(entry_lang, lg)) continue;
                }
                const entry_text = jcs.getString(entry.object, "text") orelse "";
                if (eq(try normAlias(self.a, entry_text), wanted_alias)) {
                    try alias_hits.append(oid);
                    break;
                }
            }
        }
        try label_hits.appendSlice(alias_hits.items);
        return label_hits;
    }

    // ---------------------------------------------------------------- gaps

    fn gapObject(self: *Store, pairs: []const struct { k: []const u8, v: Value }) !Value {
        var g = ObjectMap.init(self.a);
        for (pairs) |p| try g.put(p.k, p.v);
        return .{ .object = g };
    }

    /// The stigmergy read. Gap kinds per spec/store.md: missing_field,
    /// empty_mechanism, inconsistent_hierarchy, dangling_reference, conflict.
    pub fn gaps(self: *Store, kind_filter: ?[]const u8) !std.ArrayList(Value) {
        var out = std.ArrayList(Value).init(self.a);
        // The parents closed by a valid refinement leave the gap list: the
        // refined set holds every parent named by a valid refinement child.
        var refined = std.StringArrayHashMap(void).init(self.a);
        for (self.objects.values()) |obj| {
            if (!eq(jcs.getString(obj, "type") orelse "", "causal_relation_object")) continue;
            const refines = jcs.getString(obj, "refines") orelse continue;
            if (refines.len == 0) continue;
            const parent = self.objects.get(refines) orelse continue;
            if (semantics.refinementValid(obj, parent).ok) {
                try refined.put(jcs.getString(parent, "id").?, {});
            }
        }
        var it = self.objects.iterator();
        while (it.next()) |e| {
            const oid = e.key_ptr.*;
            const obj = e.value_ptr.*;
            if (!eq(jcs.getString(obj, "type") orelse "", "causal_relation_object")) continue;
            // missing_field: lacking the temporal window or the modality -
            // mechanism and context may legitimately stay unspecified forever
            // (empty_mechanism is its own kind; absent context = context-free).
            if ((!obj.contains("temporal") or !obj.contains("modality")) and !refined.contains(oid)) {
                const partial = try semantics.isPartial(self.a, obj);
                var missing = Array.init(self.a);
                for (partial.missing) |m| try missing.append(.{ .string = m });
                try out.append(try self.gapObject(&.{
                    .{ .k = "id", .v = .{ .string = oid } },
                    .{ .k = "kind", .v = .{ .string = "missing_field" } },
                    .{ .k = "missing", .v = .{ .array = missing } },
                }));
            }
            const mech = obj.get("mechanism");
            const mech_empty = mech == null or (mech.? == .array and mech.?.array.items.len == 0);
            if (mech_empty and !refined.contains(oid)) {
                try out.append(try self.gapObject(&.{
                    .{ .k = "id", .v = .{ .string = oid } },
                    .{ .k = "kind", .v = .{ .string = "empty_mechanism" } },
                }));
            }
        }
        for ([_][]const u8{ "subsumes", "part_of" }) |field| {
            const te = try self.activeTaxonomyEdges(field);
            for (te.excluded.items) |rec| {
                try out.append(try self.gapObject(&.{
                    .{ .k = "id", .v = .{ .string = jcs.getString(rec, "id").? } },
                    .{ .k = "kind", .v = .{ .string = "inconsistent_hierarchy" } },
                    .{ .k = "note", .v = .{ .string = "excluded by the deterministic cycle-breaking view rule" } },
                }));
            }
        }
        // dangling_reference: a reference to an object absent from the store -
        // the red link that says "this page is wanted".
        it = self.objects.iterator();
        while (it.next()) |e| {
            const oid = e.key_ptr.*;
            const obj = e.value_ptr.*;
            var refs = std.ArrayList([]const u8).init(self.a);
            const t = jcs.getString(obj, "type") orelse "";
            if (eq(t, "causal_relation_object")) {
                try appendStrings(&refs, obj.get("causes"));
                try appendStrings(&refs, obj.get("effects"));
                try appendStrings(&refs, obj.get("context"));
                try appendStrings(&refs, obj.get("mechanism"));
                if (jcs.getString(obj, "refines")) |r| {
                    if (r.len > 0) try refs.append(r);
                }
            } else if (eq(t, "realizable")) {
                if (jcs.getString(obj, "bearer")) |b| try refs.append(b);
            }
            for (refs.items) |ref| {
                if (ref.len > 0 and !self.objects.contains(ref)) {
                    try out.append(try self.gapObject(&.{
                        .{ .k = "id", .v = .{ .string = oid } },
                        .{ .k = "kind", .v = .{ .string = "dangling_reference" } },
                        .{ .k = "ref", .v = .{ .string = ref } },
                    }));
                }
            }
        }
        // conflict: pairs of claims satisfying the formal test (rule 6).
        var cros = std.ArrayList(ObjectMap).init(self.a);
        for (self.objects.values()) |obj| {
            if (eq(jcs.getString(obj, "type") orelse "", "causal_relation_object")) try cros.append(obj);
        }
        for (cros.items, 0..) |x, i| {
            for (cros.items[i + 1 ..]) |y| {
                if (semantics.conflicts(x, y)) {
                    try out.append(try self.gapObject(&.{
                        .{ .k = "kind", .v = .{ .string = "conflict" } },
                        .{ .k = "a", .v = .{ .string = jcs.getString(x, "id").? } },
                        .{ .k = "b", .v = .{ .string = jcs.getString(y, "id").? } },
                    }));
                }
            }
        }
        if (kind_filter) |kf| {
            var filtered = std.ArrayList(Value).init(self.a);
            for (out.items) |g| {
                if (eq(jcs.getString(g.object, "kind").?, kf)) try filtered.append(g);
            }
            return filtered;
        }
        return out;
    }

    fn appendStrings(refs: *std.ArrayList([]const u8), v: ?Value) !void {
        const arr = v orelse return;
        if (arr != .array) return;
        for (arr.array.items) |item| {
            if (item == .string) try refs.append(item.string);
        }
    }
};

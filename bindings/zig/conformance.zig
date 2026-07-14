//! The Causalontology conformance runner for causalontology-zig.
//!
//! Runs every vector in conformance/vectors/ against the Zig binding,
//! mirroring bindings/python/tests/run_conformance.py exactly. An
//! implementation is conformant if and only if it passes every vector; this
//! runner exits nonzero on any failure.
//!
//! The vectors are frozen at specification 1.0.0: they carry concrete 64-hex
//! identifiers, real Ed25519 keys, and a real verifying signature, which the
//! normalizer passes through unchanged. The remaining symbolic names used by
//! the behavioral vectors ("cnt:dog", key "alice") normalize
//! deterministically - object names become scheme:sha256(name), key names
//! become real Ed25519 keypairs seeded from sha256("key:" + name).

const std = @import("std");
const jcs = @import("src/jcs.zig");
const canonical = @import("src/canonical.zig");
const schema = @import("src/schema.zig");
const semantics = @import("src/semantics.zig");
const signing = @import("src/signing.zig");
const store_mod = @import("src/store.zig");

const Value = jcs.Value;
const ObjectMap = jcs.ObjectMap;
const Array = jcs.Array;
const Store = store_mod.Store;
const Ed25519 = signing.Ed25519;

// One arena for the whole run: this is a test harness, so nothing is freed
// along the way (leaks are deliberate and harmless) and the OS reclaims
// everything at exit.
var arena_state: std.heap.ArenaAllocator = undefined;
var A: std.mem.Allocator = undefined;
var vectors_dir: []const u8 = undefined;
var keys_cache: std.StringArrayHashMap(signing.NamedKeypair) = undefined;

pub fn main() !void {
    arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    A = arena_state.allocator();
    keys_cache = std.StringArrayHashMap(signing.NamedKeypair).init(A);

    const root = try findRoot();
    vectors_dir = try std.fs.path.join(A, &.{ root, "conformance", "vectors" });
    schema.setSpecDir(A, try std.fs.path.join(A, &.{ root, "spec", "schema" }));

    const stdout = std.io.getStdOut().writer();
    try stdout.print("causalontology-zig conformance run\n", .{});
    try stdout.print("internal checks (RFC 8032 known-answer, RFC 8785 basics) ... ", .{});
    try internalChecks();
    try stdout.print("ok\n", .{});

    const vector_fns = [_]*const fn () anyerror!void{
        v01, v02, v03, v04, v05, v06, v07, v08, v09, v10,
        v11, v12, v13, v14, v15, v16, v17, v18, v19, v20,
        v21, v22, v23, v24, v25, v26, v27, v28, v29, v30,
        v31, v32, v33, v34, v35, v36, v37, v38,
    };
    var failures: usize = 0;
    for (vector_fns, 1..) |f, n| {
        const name = vectorName(n) catch "unknown vector";
        if (f()) |_| {
            try stdout.print("PASS  {s}\n", .{name});
        } else |err| {
            failures += 1;
            try stdout.print("FAIL  {s} :: {s}\n", .{ name, @errorName(err) });
        }
    }
    try stdout.print("------------------------------------------------------------\n", .{});
    try stdout.print("{d}/{d} vectors passed\n", .{ vector_fns.len - failures, vector_fns.len });
    if (failures != 0) std.process.exit(1);
    try stdout.print("causalontology-zig is CONFORMANT to the suite (vectors frozen at specification 1.0.0).\n", .{});
}

/// The repository root: CAUSALONTOLOGY_ROOT when set, otherwise the nearest
/// ancestor of the working directory holding conformance/vectors.
fn findRoot() ![]const u8 {
    if (std.process.getEnvVarOwned(A, "CAUSALONTOLOGY_ROOT")) |r| {
        return r;
    } else |_| {}
    var dir: []const u8 = try std.fs.cwd().realpathAlloc(A, ".");
    while (true) {
        const probe = try std.fs.path.join(A, &.{ dir, "conformance", "vectors" });
        if (std.fs.accessAbsolute(probe, .{})) |_| {
            return dir;
        } else |_| {}
        dir = std.fs.path.dirname(dir) orelse return error.RepoRootNotFound;
    }
}

// ---------------------------------------------------------------------------
// vector loading and symbolic-identifier normalization
// ---------------------------------------------------------------------------

fn vectorFileName(n: usize) ![]const u8 {
    var dir = try std.fs.openDirAbsolute(vectors_dir, .{ .iterate = true });
    defer dir.close();
    var buf: [8]u8 = undefined;
    const prefix = try std.fmt.bufPrint(&buf, "v{d:0>2}_", .{n});
    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (std.mem.startsWith(u8, entry.name, prefix) and std.mem.endsWith(u8, entry.name, ".json")) {
            return A.dupe(u8, entry.name);
        }
    }
    return error.VectorNotFound;
}

fn vectorName(n: usize) ![]const u8 {
    const fname = try vectorFileName(n);
    return fname[0 .. fname.len - ".json".len]; // the stem
}

/// Load vector n's JSON file (for its structured inputs).
fn vec(n: usize) !Value {
    const path = try std.fs.path.join(A, &.{ vectors_dir, try vectorFileName(n) });
    const bytes = try std.fs.cwd().readFileAlloc(A, path, 1 << 20);
    return std.json.parseFromSliceLeaky(Value, A, bytes, .{});
}

/// A real, deterministic Ed25519 keypair for a symbolic key name.
fn key(name: []const u8) !signing.NamedKeypair {
    if (keys_cache.get(name)) |k| return k;
    var seed: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(try std.fmt.allocPrint(A, "key:{s}", .{name}), &seed, .{});
    const kp = try signing.keypairFromSeed(A, seed);
    try keys_cache.put(try A.dupe(u8, name), kp);
    return kp;
}

const schemes = [_][]const u8{ "occ", "cro", "cnt", "rlz", "ast", "enr", "ret", "suc" };

fn hasSymPrefix(s: []const u8) bool {
    for (schemes) |scheme| {
        if (s.len > scheme.len and s[scheme.len] == ':' and std.mem.startsWith(u8, s, scheme)) return true;
    }
    return std.mem.startsWith(u8, s, "ed25519:");
}

/// Normalize one symbolic identifier to a well-formed one; frozen concrete
/// identifiers (64 lowercase hex) pass through unchanged.
fn sym(s: []const u8) ![]const u8 {
    const i = std.mem.indexOfScalar(u8, s, ':').?;
    const scheme = s[0..i];
    const name = s[i + 1 ..];
    if (std.mem.eql(u8, scheme, "ed25519")) {
        if (jcs.isHex(name, 64)) return s; // frozen: a real key passes through
        return (try key(name)).public_id;
    }
    if (jcs.isHex(name, 64)) return s;
    return std.fmt.allocPrint(A, "{s}:{s}", .{ scheme, try canonical.sha256Hex(A, name) });
}

/// Recursively normalize symbolic identifiers and placeholders.
fn normalize(v: Value) anyerror!Value {
    switch (v) {
        .string => |s| {
            if (std.mem.eql(u8, s, "<128 hex>")) {
                const buf = try A.alloc(u8, 128);
                for (0..64) |i| {
                    buf[i * 2] = 'a';
                    buf[i * 2 + 1] = 'b';
                }
                return .{ .string = buf };
            }
            if (hasSymPrefix(s)) return .{ .string = try sym(s) };
            return v;
        },
        .array => |arr| {
            var out = Array.init(A);
            for (arr.items) |item| try out.append(try normalize(item));
            return .{ .array = out };
        },
        .object => |o| {
            var out = ObjectMap.init(A);
            var it = o.iterator();
            while (it.next()) |e| try out.put(e.key_ptr.*, try normalize(e.value_ptr.*));
            return .{ .object = out };
        },
        else => return v,
    }
}

/// Build, timestamp, and sign a provenance record.
fn signed(kind: []const u8, body: ObjectMap, who: []const u8, ts_i: usize) !ObjectMap {
    const k = try key(who);
    var rec = try jcs.cloneObject(A, body);
    try rec.put("type", .{ .string = kind });
    if (!rec.contains("timestamp")) {
        try rec.put("timestamp", .{ .string = try std.fmt.allocPrint(A, "2026-07-13T0{d}:00:00Z", .{ts_i}) });
    }
    if (std.mem.eql(u8, kind, "succession")) {
        // a succession is signed by the predecessor key
        if (!rec.contains("predecessor")) try rec.put("predecessor", .{ .string = k.public_id });
    } else {
        try rec.put("source", .{ .string = k.public_id });
    }
    return signing.signRecord(A, rec, k.kp, kind);
}

// ---------------------------------------------------------------------------
// small builders and expectations
// ---------------------------------------------------------------------------

fn str(s: []const u8) Value {
    return .{ .string = s };
}

fn flt(f: f64) Value {
    return .{ .float = f };
}

fn strArr(items: []const []const u8) !Value {
    var arr = Array.init(A);
    for (items) |s| try arr.append(str(s));
    return .{ .array = arr };
}

fn newObj() ObjectMap {
    return ObjectMap.init(A);
}

fn fld(v: Value, name: []const u8) Value {
    return v.object.get(name).?;
}

fn expect(cond: bool) !void {
    if (!cond) return error.ExpectationFailed;
}

fn expectContains(haystacks: []const []const u8, needle: []const u8) !void {
    for (haystacks) |h| {
        if (std.mem.indexOf(u8, h, needle) != null) return;
    }
    return error.ExpectedMessageMissing;
}

fn eq(x: []const u8, y: []const u8) bool {
    return std.mem.eql(u8, x, y);
}

// ---------------------------------------------------------------------------
// internal sanity checks (not conformance vectors)
// ---------------------------------------------------------------------------

fn internalChecks() !void {
    // RFC 8032, TEST 1 known-answer
    var seed: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&seed, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    const kp = try Ed25519.KeyPair.create(seed);
    const pk_bytes = kp.public_key.toBytes();
    try expect(eq(try jcs.hexLower(A, &pk_bytes), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"));
    const sig = try kp.sign("", null);
    sig.verify("", kp.public_key) catch return error.KnownAnswerVerifyFailed;
    if (sig.verify("x", kp.public_key)) |_| {
        return error.TamperedMessageVerified;
    } else |_| {}
    // JCS basics
    var o = newObj();
    try o.put("b", .{ .integer = 2 });
    try o.put("a", .{ .integer = 1 });
    try expect(eq(try jcs.jcs(A, .{ .object = o }), "{\"a\":1,\"b\":2}"));
    try expect(eq(try jcs.jcs(A, flt(1.0)), "1"));
    try expect(eq(try jcs.jcs(A, flt(6.000)), "6"));
    try expect(eq(try jcs.jcs(A, flt(0.7)), "0.7"));
}

// ---------------------------------------------------------------------------
// the 38 vectors
// ---------------------------------------------------------------------------

fn v01() !void {
    const inp = try normalize(fld(try vec(1), "input"));
    const sr = try schema.validateSchema(A, inp, null);
    try expect(sr.ok);
    const mr = try semantics.validateSemantics(A, inp, null);
    try expect(mr.ok);
}

fn v02() !void {
    const v = try vec(2);
    const inp = try normalize(fld(v, "input"));
    try expect((try schema.validateSchema(A, inp, null)).ok);
    try expect((try semantics.validateSemantics(A, inp, null)).ok);
    const partial = try semantics.isPartial(A, inp.object);
    try expect(partial.partial);
    const expected = fld(fld(v, "expect"), "missing").array.items;
    try expect(partial.missing.len == expected.len);
    for (partial.missing, expected) |m, x| try expect(eq(m, x.string));
}

fn schemaFails(n: usize, must_mention: []const u8) !void {
    const inp = try normalize(fld(try vec(n), "input"));
    const sr = try schema.validateSchema(A, inp, null);
    try expect(!sr.ok); // expected schema-invalid
    try expectContains(sr.errors, must_mention);
}

fn v03() !void {
    try schemaFails(3, "effects");
}
fn v04() !void {
    try schemaFails(4, "causes");
}
fn v05() !void {
    try schemaFails(5, "modality");
}
fn v06() !void {
    try schemaFails(6, "colour");
}
fn v07() !void {
    try schemaFails(7, "causes");
}

fn v08() !void {
    try expect((try schema.validateSchema(A, try normalize(fld(try vec(8), "input")), null)).ok);
}

fn v09() !void {
    try schemaFails(9, "label");
}
fn v10() !void {
    try schemaFails(10, "category");
}

fn v11() !void {
    try expect((try schema.validateSchema(A, try normalize(fld(try vec(11), "input")), null)).ok);
}

fn v12() !void {
    try schemaFails(12, "confidence");
}

fn v13() !void {
    const inp = try normalize(fld(try vec(13), "input"));
    try expect((try schema.validateSchema(A, inp, null)).ok);
    try expect((try semantics.validateSemantics(A, inp, null)).ok);
}

fn semanticsFails(n: usize, must_mention: []const u8) !void {
    const inp = try normalize(fld(try vec(n), "input"));
    const mr = try semantics.validateSemantics(A, inp, null);
    try expect(!mr.ok); // expected semantically-invalid
    try expectContains(mr.errors, must_mention);
}

fn v14() !void {
    const inp = try normalize(fld(try vec(14), "input"));
    try expect((try schema.validateSchema(A, inp, null)).ok);
    try semanticsFails(14, "dmin");
}

fn v15() !void {
    try semanticsFails(15, "acyclic");
}
fn v16() !void {
    try semanticsFails(16, "acyclic");
}

fn v17() !void {
    const v = try vec(17);
    const parent = try normalize(fld(fld(v, "given"), "parent"));
    const child = try normalize(fld(v, "input"));
    const r = semantics.refinementValid(child.object, parent.object);
    try expect(!r.ok);
    try expect(std.mem.indexOf(u8, r.reason, "rival") != null);
}

fn v18() !void {
    try semanticsFails(18, "not a legal field");
}
fn v19() !void {
    try semanticsFails(19, "language-tagged");
}

fn v20enrich(about: []const u8, entry: []const u8, i: usize) !ObjectMap {
    var body = newObj();
    try body.put("about", str(about));
    try body.put("field", str("subsumes"));
    try body.put("entry", str(entry));
    return signed("enrichment", body, "taxo", i);
}

fn v20() !void {
    const dog = try sym("cnt:dog");
    const mam = try sym("cnt:mammal");
    const ani = try sym("cnt:animal");
    // enforcing tier rejects the cycle-completing write
    var s = Store.init(A, true);
    _ = try s.putRecord(try v20enrich(dog, mam, 1), null, false);
    _ = try s.putRecord(try v20enrich(mam, ani, 2), null, false);
    if (s.putRecord(try v20enrich(ani, dog, 3), null, false)) |_| {
        return error.EnforcingStoreAcceptedCycle;
    } else |err| {
        try expect(err == error.RejectedWrite);
        try expect(std.mem.indexOf(u8, s.reject_reason, "cycle") != null);
    }
    // decentralized merge: the view breaks the cycle deterministically
    var s2 = Store.init(A, true);
    _ = try s2.putRecord(try v20enrich(dog, mam, 1), null, false);
    _ = try s2.putRecord(try v20enrich(mam, ani, 2), null, false);
    const bad = try v20enrich(ani, dog, 3);
    _ = try s2.forceMergeRecord(bad, null);
    const te = try s2.activeTaxonomyEdges("subsumes");
    const bad_id = jcs.getString(bad, "id").?;
    try expect(te.excluded.items.len == 1);
    try expect(eq(jcs.getString(te.excluded.items[0], "id").?, bad_id));
    var surfaced = false;
    for ((try s2.gaps("inconsistent_hierarchy")).items) |g| {
        if (eq(jcs.getString(g.object, "id").?, bad_id)) surfaced = true;
    }
    try expect(surfaced);
}

fn adm(n: usize) !bool {
    const given = fld(try vec(n), "given");
    var cro = newObj();
    try cro.put("causes", try strArr(&.{try sym("occ:c")}));
    try cro.put("effects", try strArr(&.{try sym("occ:e")}));
    try cro.put("temporal", fld(given, "temporal"));
    return semantics.admissible(cro, jcs.numAsF64(fld(given, "elapsed_seconds")).?);
}

fn v21() !void {
    try expect((try adm(21)) == true);
}
fn v22() !void {
    try expect((try adm(22)) == false);
}
fn v23() !void {
    try expect((try adm(23)) == true);
}

fn identityEqual(n: usize) !void {
    const v = try vec(n);
    const ia = try canonical.identify(A, (try normalize(fld(v, "inputA"))).object, null);
    const ib = try canonical.identify(A, (try normalize(fld(v, "inputB"))).object, null);
    try expect(eq(ia, ib));
}

fn v24() !void {
    try identityEqual(24);
}
fn v25() !void {
    try identityEqual(25);
}

fn pressButtonOccurrent() !ObjectMap {
    var o = newObj();
    try o.put("type", str("occurrent"));
    try o.put("label", str("press_button"));
    try o.put("category", str("action"));
    return o;
}

fn v26() !void {
    var s = Store.init(A, true);
    const first = try s.put(try pressButtonOccurrent(), null);
    const second = try s.put(try pressButtonOccurrent(), null);
    try expect(eq(first, second));
    try expect(s.objects.count() == 1);
}

fn v27() !void {
    var s = Store.init(A, true);
    const occ = try s.put(try pressButtonOccurrent(), null);
    var entry = newObj();
    try entry.put("lang", str("en"));
    try entry.put("text", str("press the button"));
    var body = newObj();
    try body.put("about", str(occ));
    try body.put("field", str("aliases"));
    try body.put("entry", .{ .object = entry });
    const r1 = try signed("enrichment", body, "alice", 1);
    const r2 = try signed("enrichment", body, "bob", 2);
    const id1 = try s.putRecord(r1, null, false);
    const id2 = try s.putRecord(r2, null, false);
    try expect(!eq(id1, id2)); // two records
    const view = (try s.get(occ, "default")).?;
    const aliases = fld(fld(view, "enrichments"), "aliases").array.items;
    try expect(aliases.len == 1);
    try expect(fld(aliases[0], "contributors").array.items.len == 2);
}

fn v28() !void {
    var s = Store.init(A, true);
    var claim = newObj();
    try claim.put("type", str("cro"));
    try claim.put("causes", try strArr(&.{try sym("occ:A")}));
    try claim.put("effects", try strArr(&.{try sym("occ:B")}));
    try claim.put("modality", str("sufficient"));
    const first = try s.put(claim, null);
    const second = try s.put(claim, null);
    try expect(eq(first, second));
    try expect(s.objects.count() == 1);
    const labs = [_]struct { who: []const u8, ts: usize }{
        .{ .who = "lab1", .ts = 1 },
        .{ .who = "lab2", .ts = 2 },
    };
    for (labs) |lab| {
        var body = newObj();
        try body.put("about", str(first));
        try body.put("evidence_type", str("observation"));
        try body.put("strength", flt(0.8));
        try body.put("confidence", flt(0.8));
        _ = try s.putRecord(try signed("assertion", body, lab.who, lab.ts), null, false);
    }
    try expect((try s.assertionsAbout(first, false)).items.len == 2);
}

fn signerDemoAssertion() !ObjectMap {
    var body = newObj();
    try body.put("about", str(try sym("cro:demo")));
    try body.put("evidence_type", str("intervention"));
    try body.put("strength", flt(0.7));
    try body.put("confidence", flt(0.9));
    return signed("assertion", body, "signer", 0);
}

fn v29() !void {
    try expect(signing.verifyRecord(A, try signerDemoAssertion(), null) == true);
}

fn v30() !void {
    var tampered = try jcs.cloneObject(A, try signerDemoAssertion());
    try tampered.put("confidence", flt(0.1));
    try expect(signing.verifyRecord(A, tampered, null) == false);
}

fn v31() !void {
    var s = Store.init(A, true);
    var claim = newObj();
    try claim.put("type", str("cro"));
    try claim.put("causes", try strArr(&.{try sym("occ:A")}));
    try claim.put("effects", try strArr(&.{try sym("occ:B")}));
    const x = try s.put(claim, null);
    var body = newObj();
    try body.put("about", str(x));
    try body.put("evidence_type", str("observation"));
    try body.put("confidence", flt(0.8));
    const assertion = try signed("assertion", body, "lab1", 1);
    _ = try s.putRecord(assertion, null, false);
    const aid = jcs.getString(assertion, "id").?;
    var retract_body = newObj();
    try retract_body.put("retracts", str(aid));
    _ = try s.putRecord(try signed("retraction", retract_body, "lab1", 2), null, false);
    try expect((try s.assertionsAbout(x, false)).items.len == 0);
    const hist = try s.assertionsAbout(x, true);
    try expect(hist.items.len == 1);
    try expect(hist.items[0].get("retracted").?.bool == true);
    var foreign_body = newObj();
    try foreign_body.put("retracts", str(aid));
    const foreign = try signed("retraction", foreign_body, "mallory", 3);
    if (s.putRecord(foreign, null, false)) |_| {
        return error.ForeignRetractionAccepted;
    } else |err| {
        try expect(err == error.RejectedWrite);
    }
    try expect((try s.assertionsAbout(x, false)).items.len == 0); // still excluded by lab1's own
    try expect((try s.assertionsAbout(x, true)).items.len == 1);
}

fn v32() !void {
    var s = Store.init(A, true);
    const occ = try s.put(try pressButtonOccurrent(), null);
    var entry = newObj();
    try entry.put("lang", str("ja"));
    try entry.put("text", str("botan"));
    var body = newObj();
    try body.put("about", str(occ));
    try body.put("field", str("aliases"));
    try body.put("entry", .{ .object = entry });
    const e = try signed("enrichment", body, "bob", 1);
    _ = try s.putRecord(e, null, false);
    const before = (try s.get(occ, "default")).?;
    try expect(fld(before, "enrichments").object.get("aliases").?.array.items.len == 1);
    var retract_body = newObj();
    try retract_body.put("retracts", str(jcs.getString(e, "id").?));
    _ = try s.putRecord(try signed("retraction", retract_body, "bob", 2), null, false);
    const after = (try s.get(occ, "default")).?;
    const after_aliases = fld(after, "enrichments").object.get("aliases");
    try expect(after_aliases == null or after_aliases.?.array.items.len == 0);
    const hist = (try s.get(occ, "history")).?;
    try expect(fld(hist, "enrichments").object.get("aliases").?.array.items.len == 1);
}

fn v33() !void {
    var s = Store.init(A, true);
    const k1 = (try key("K1")).public_id;
    const k2 = (try key("K2")).public_id;
    var body = newObj();
    try body.put("about", str(try sym("cro:claim")));
    try body.put("evidence_type", str("observation"));
    try body.put("confidence", flt(0.9));
    const assertion = try signed("assertion", body, "K1", 1);
    _ = try s.putRecord(assertion, null, false);
    var succ_body = newObj();
    try succ_body.put("successor", str(k2));
    _ = try s.putRecord(try signed("succession", succ_body, "K1", 2), null, false);
    try expect((try s.lineage(k2)).contains(k1));
    try expect((try s.lineage(k1)).contains(k2));
    var retract_body = newObj();
    try retract_body.put("retracts", str(jcs.getString(assertion, "id").?));
    // successor may retract the predecessor's record
    _ = try s.putRecord(try signed("retraction", retract_body, "K2", 3), null, false);
    try expect((try s.assertionsAbout(try sym("cro:claim"), false)).items.len == 0);
}

fn v34() !void {
    const given = try normalize(fld(try vec(34), "given"));
    try expect(semantics.conflicts(fld(given, "A").object, fld(given, "B").object) == true);
}

fn v35() !void {
    const given = try normalize(fld(try vec(35), "given"));
    try expect(semantics.conflicts(fld(given, "A").object, fld(given, "B").object) == false);
}

fn v36cro(id: []const u8, cause: []const u8, effect: []const u8) !ObjectMap {
    var o = newObj();
    try o.put("id", str(id));
    try o.put("causes", try strArr(&.{cause}));
    try o.put("effects", try strArr(&.{effect}));
    return o;
}

fn v36() !void {
    const oa = try sym("occ:A");
    const ob = try sym("occ:B");
    const oc = try sym("occ:C");
    const od = try sym("occ:D");
    const m1id = try sym("cro:m1");
    const m2id = try sym("cro:m2");
    const m3id = try sym("cro:m3");
    const m1 = try v36cro(m1id, oa, ob);
    const m2 = try v36cro(m2id, ob, oc);
    const m3 = try v36cro(m3id, od, oc);
    var parent = newObj();
    try parent.put("causes", try strArr(&.{oa}));
    try parent.put("effects", try strArr(&.{oc}));
    try parent.put("mechanism", try strArr(&.{ m1id, m2id }));
    var members = std.StringArrayHashMap(ObjectMap).init(A);
    try members.put(m1id, m1);
    try members.put(m2id, m2);
    try expect(eq(try semantics.hierarchyConsistent(A, parent, &members), "consistent"));
    var parent2 = try jcs.cloneObject(A, parent);
    try parent2.put("mechanism", try strArr(&.{ m1id, m3id }));
    var members2 = std.StringArrayHashMap(ObjectMap).init(A);
    try members2.put(m1id, m1);
    try members2.put(m3id, m3);
    try expect(eq(try semantics.hierarchyConsistent(A, parent2, &members2), "inconsistent"));
    var members3 = std.StringArrayHashMap(ObjectMap).init(A);
    try members3.put(m1id, m1);
    try expect(eq(try semantics.hierarchyConsistent(A, parent, &members3), "indeterminate"));
}

fn v37() !void {
    var s = Store.init(A, true);
    const occ = try s.put(try pressButtonOccurrent(), null);
    var entry = newObj();
    try entry.put("lang", str("en"));
    try entry.put("text", str("Press the Button"));
    var body = newObj();
    try body.put("about", str(occ));
    try body.put("field", str("aliases"));
    try body.put("entry", .{ .object = entry });
    _ = try s.putRecord(try signed("enrichment", body, "alice", 1), null, false);
    const by_alias = try s.resolve("Press  The   Button", "en"); // alias match
    try expect(by_alias.items.len == 1 and eq(by_alias.items[0], occ));
    const by_label = try s.resolve("press_button", "en"); // label, first
    try expect(by_label.items.len >= 1 and eq(by_label.items[0], occ));
}

fn v38() !void {
    var s = Store.init(A, true);
    var degenerate = newObj();
    try degenerate.put("type", str("cro"));
    try degenerate.put("causes", try strArr(&.{try sym("occ:A")}));
    try degenerate.put("effects", try strArr(&.{try sym("occ:B")}));
    const parent_id = try s.put(degenerate, null);
    var found = false;
    for ((try s.gaps("missing_field")).items) |g| {
        if (eq(jcs.getString(g.object, "id").?, parent_id)) found = true;
    }
    try expect(found);
    var temporal = newObj();
    try temporal.put("dmin", .{ .integer = 0 });
    try temporal.put("dmax", .{ .integer = 1 });
    try temporal.put("unit", str("seconds"));
    var refinement = newObj();
    try refinement.put("type", str("cro"));
    try refinement.put("causes", try strArr(&.{try sym("occ:A")}));
    try refinement.put("effects", try strArr(&.{try sym("occ:B")}));
    try refinement.put("temporal", .{ .object = temporal });
    try refinement.put("modality", str("sufficient"));
    try refinement.put("refines", str(parent_id));
    const refinement_id = try s.put(refinement, null);
    for ((try s.gaps("missing_field")).items) |g| {
        const gid = jcs.getString(g.object, "id").?;
        if (eq(gid, parent_id)) return error.GapDidNotClose;
        if (eq(gid, refinement_id)) return error.RefinementMustBeComplete;
    }
}

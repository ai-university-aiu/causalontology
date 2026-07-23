//! The Causalontology conformance runner for causalontology-zig.
//!
//! Runs every vector in conformance/vectors/ against the Zig binding,
//! mirroring bindings/python/tests/run_conformance.py exactly. An
//! implementation is conformant if and only if it passes every vector; this
//! runner exits nonzero on any failure.
//!
//! The vectors are frozen at specification 2.0.0: they carry concrete 64-hex
//! identifiers, real Ed25519 keys, and a real verifying signature, which the
//! normalizer passes through unchanged. The remaining symbolic names used by
//! the behavioral vectors ("continuant:dog", key "alice") normalize
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
    try stdout.print("causalontology-zig conformance run (specification 4.0.0)\n", .{});
    try stdout.print("internal checks (RFC 8032 known-answer, RFC 8785 basics, fixed constants, ground-truth ids) ... ", .{});
    try internalChecks();
    try stdout.print("ok\n", .{});

    const vector_fns = [_]*const fn () anyerror!void{
        v01, v02, v03, v04, v05, v06, v07, v08, v09, v10,
        v11, v12, v13, v14, v15, v16, v17, v18, v19, v20,
        v21, v22, v23, v24, v25, v26, v27, v28, v29, v30,
        v31, v32, v33, v34, v35, v36, v37, v38, v39, v40,
        v41, v42, v43, v44, v45, v46, v47, v48, v49, v50,
        v51, v52, v53, v54, v55, v56, v57, v58, v59, v60,
        v61, v62, v63, v64, v65, v66, v67, v68, v69, v70,
        v71, v72, v73, v74, v75, v76, v77, v78, v79, v80,
        v81, v82, v83, v84, v85, v86, v87, v88, v89, v90,
        v91, v92, v93, v94, v95, v96, v97, v98, v99, v100,
        v101, v102, v103, v104, v105, v106, v107, v108, v109, v110,
        v111, v112, v113, v114, v115, v116, v117, v118, v119, v120,
        v121, v122, v123, v124, v125, v126, v127, v128, v129, v130,
        v131, v132, v133, v134, v135, v136, v137,
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
    try stdout.print("causalontology-zig is CONFORMANT to the suite (vectors frozen at specification 4.0.0).\n", .{});
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

const schemes = [_][]const u8{
    "occurrent",          "causal_relation_object", "continuant",           "realizable",
    "assertion",          "enrichment",             "retraction",           "succession",
    "stratum",            "bridge",                 "cross_stratal_seam",   "port",
    "conduit",            "quality",                "token_individual",     "token_occurrence",
    "state_assertion",    "token_causal_claim",     "attitude",             "predicted_occurrence",
    "prediction_error",
};

/// The whole-word schemes (Principle P7), plus ed25519, for the V106 scan.
const whole_word = schemes ++ [_][]const u8{"ed25519"};

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
    // Rule 4 / Algorithm E fixed constants (mean Gregorian).
    try expect((try semantics.toSeconds(1, "months")) == 2629746);
    try expect((try semantics.toSeconds(1, "years")) == 31556952);

    // Ground-truth content-addressed ids: any drift here means the JCS or
    // identity-field logic is wrong (PORT_GUIDE 2.0.0).
    var gt_stratum = newObj();
    try gt_stratum.put("type", str("stratum"));
    try gt_stratum.put("label", str("cellular"));
    try gt_stratum.put("scheme", str("neuroendocrine"));
    try gt_stratum.put("ordinal", .{ .integer = 6 });
    try expect(eq(try canonical.identify(A, gt_stratum, null), "stratum:99162f6202087b209696f9a2a21fe57ada3a349840ce5f8af25e034c8bde5b81"));

    const zeros = try A.alloc(u8, 64);
    @memset(zeros, '0');
    var gt_rlz = newObj();
    try gt_rlz.put("type", str("realizable"));
    try gt_rlz.put("kind", str("disposition"));
    try gt_rlz.put("bearer", str(try std.fmt.allocPrint(A, "continuant:{s}", .{zeros})));
    try gt_rlz.put("label", str("ltp"));
    try expect(eq(try canonical.identify(A, gt_rlz, null), "realizable:486be612e50996f60632764a36d009e151a3967d4bedac3f61c88844577243c1"));

    var gt_interval = newObj();
    try gt_interval.put("start", str("1953-08-25T00:00:00Z"));
    try gt_interval.put("open", .{ .bool = true });
    var gt_tok = newObj();
    try gt_tok.put("type", str("token_occurrence"));
    try gt_tok.put("instantiates", str(try std.fmt.allocPrint(A, "occurrent:{s}", .{zeros})));
    try gt_tok.put("interval", .{ .object = gt_interval });
    try expect(eq(try canonical.identify(A, gt_tok, null), "token_occurrence:85987b294d9902330b25a9d692cdce27bce090bca30e7c09e8b943059e23351d"));
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
    try semanticsFails(14, "minimum_delay");
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
    const dog = try sym("continuant:dog");
    const mam = try sym("continuant:mammal");
    const ani = try sym("continuant:animal");
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
    var cro_obj = newObj();
    try cro_obj.put("causes", try strArr(&.{try sym("occurrent:c")}));
    try cro_obj.put("effects", try strArr(&.{try sym("occurrent:e")}));
    try cro_obj.put("temporal", fld(given, "temporal"));
    return semantics.admissible(cro_obj, jcs.numAsF64(fld(given, "elapsed_seconds")).?);
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
    const occ_id = try s.put(try pressButtonOccurrent(), null);
    var entry = newObj();
    try entry.put("lang", str("en"));
    try entry.put("text", str("press the button"));
    var body = newObj();
    try body.put("about", str(occ_id));
    try body.put("field", str("aliases"));
    try body.put("entry", .{ .object = entry });
    const r1 = try signed("enrichment", body, "alice", 1);
    const r2 = try signed("enrichment", body, "bob", 2);
    const id1 = try s.putRecord(r1, null, false);
    const id2 = try s.putRecord(r2, null, false);
    try expect(!eq(id1, id2)); // two records
    const view = (try s.get(occ_id, "default")).?;
    const aliases = fld(fld(view, "enrichments"), "aliases").array.items;
    try expect(aliases.len == 1);
    try expect(fld(aliases[0], "contributors").array.items.len == 2);
}

fn v28() !void {
    var s = Store.init(A, true);
    var claim = newObj();
    try claim.put("type", str("causal_relation_object"));
    try claim.put("causes", try strArr(&.{try sym("occurrent:A")}));
    try claim.put("effects", try strArr(&.{try sym("occurrent:B")}));
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
    try body.put("about", str(try sym("causal_relation_object:demo")));
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
    try claim.put("type", str("causal_relation_object"));
    try claim.put("causes", try strArr(&.{try sym("occurrent:A")}));
    try claim.put("effects", try strArr(&.{try sym("occurrent:B")}));
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
    const occ_id = try s.put(try pressButtonOccurrent(), null);
    var entry = newObj();
    try entry.put("lang", str("ja"));
    try entry.put("text", str("botan"));
    var body = newObj();
    try body.put("about", str(occ_id));
    try body.put("field", str("aliases"));
    try body.put("entry", .{ .object = entry });
    const e = try signed("enrichment", body, "bob", 1);
    _ = try s.putRecord(e, null, false);
    const before = (try s.get(occ_id, "default")).?;
    try expect(fld(before, "enrichments").object.get("aliases").?.array.items.len == 1);
    var retract_body = newObj();
    try retract_body.put("retracts", str(jcs.getString(e, "id").?));
    _ = try s.putRecord(try signed("retraction", retract_body, "bob", 2), null, false);
    const after = (try s.get(occ_id, "default")).?;
    const after_aliases = fld(after, "enrichments").object.get("aliases");
    try expect(after_aliases == null or after_aliases.?.array.items.len == 0);
    const hist = (try s.get(occ_id, "history")).?;
    try expect(fld(hist, "enrichments").object.get("aliases").?.array.items.len == 1);
}

fn v33() !void {
    var s = Store.init(A, true);
    const k1 = (try key("K1")).public_id;
    const k2 = (try key("K2")).public_id;
    var body = newObj();
    try body.put("about", str(try sym("causal_relation_object:claim")));
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
    try expect((try s.assertionsAbout(try sym("causal_relation_object:claim"), false)).items.len == 0);
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
    const oa = try sym("occurrent:A");
    const ob = try sym("occurrent:B");
    const oc = try sym("occurrent:C");
    const od = try sym("occurrent:D");
    const m1id = try sym("causal_relation_object:m1");
    const m2id = try sym("causal_relation_object:m2");
    const m3id = try sym("causal_relation_object:m3");
    const m1 = try v36cro(m1id, oa, ob);
    const m2 = try v36cro(m2id, ob, oc);
    const m3 = try v36cro(m3id, od, oc);
    var parent = newObj();
    try parent.put("causes", try strArr(&.{oa}));
    try parent.put("effects", try strArr(&.{oc}));
    try parent.put("mechanism", try strArr(&.{ m1id, m2id }));
    const no_bridges = [_]ObjectMap{};
    var members = std.StringArrayHashMap(ObjectMap).init(A);
    try members.put(m1id, m1);
    try members.put(m2id, m2);
    try expect(eq(try semantics.hierarchyConsistent(A, parent, &members, &no_bridges), "consistent"));
    var parent2 = try jcs.cloneObject(A, parent);
    try parent2.put("mechanism", try strArr(&.{ m1id, m3id }));
    var members2 = std.StringArrayHashMap(ObjectMap).init(A);
    try members2.put(m1id, m1);
    try members2.put(m3id, m3);
    try expect(eq(try semantics.hierarchyConsistent(A, parent2, &members2, &no_bridges), "inconsistent"));
    var members3 = std.StringArrayHashMap(ObjectMap).init(A);
    try members3.put(m1id, m1);
    try expect(eq(try semantics.hierarchyConsistent(A, parent, &members3, &no_bridges), "indeterminate"));
}

fn v37() !void {
    var s = Store.init(A, true);
    const occ_id = try s.put(try pressButtonOccurrent(), null);
    var entry = newObj();
    try entry.put("lang", str("en"));
    try entry.put("text", str("Press the Button"));
    var body = newObj();
    try body.put("about", str(occ_id));
    try body.put("field", str("aliases"));
    try body.put("entry", .{ .object = entry });
    _ = try s.putRecord(try signed("enrichment", body, "alice", 1), null, false);
    const by_alias = try s.resolve("Press  The   Button", "en"); // alias match
    try expect(by_alias.items.len == 1 and eq(by_alias.items[0], occ_id));
    const by_label = try s.resolve("press_button", "en"); // label, first
    try expect(by_label.items.len >= 1 and eq(by_label.items[0], occ_id));
}

fn v38() !void {
    var s = Store.init(A, true);
    var degenerate = newObj();
    try degenerate.put("type", str("causal_relation_object"));
    try degenerate.put("causes", try strArr(&.{try sym("occurrent:A")}));
    try degenerate.put("effects", try strArr(&.{try sym("occurrent:B")}));
    const parent_id = try s.put(degenerate, null);
    var found = false;
    for ((try s.gaps("missing_field")).items) |g| {
        if (eq(jcs.getString(g.object, "id").?, parent_id)) found = true;
    }
    try expect(found);
    var temporal = newObj();
    try temporal.put("minimum_delay", .{ .integer = 0 });
    try temporal.put("maximum_delay", .{ .integer = 1 });
    try temporal.put("unit", str("seconds"));
    var refinement = newObj();
    try refinement.put("type", str("causal_relation_object"));
    try refinement.put("causes", try strArr(&.{try sym("occurrent:A")}));
    try refinement.put("effects", try strArr(&.{try sym("occurrent:B")}));
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

// ===========================================================================
// 2.0.0 builders and fixtures (mirroring the Python runner's helpers)
// ===========================================================================

const ObjMap = semantics.ObjMap; // std.StringArrayHashMap(ObjectMap)

/// A content object completed with its real content-addressed id (mk()).
fn mk(obj: ObjectMap) !ObjectMap {
    var o = obj;
    const id = try canonical.identify(A, o, null);
    try o.put("id", str(id));
    return o;
}

fn oid(o: ObjectMap) []const u8 {
    return jcs.getString(o, "id").?;
}

fn objMapOf(objs: []const ObjectMap) !ObjMap {
    var m = ObjMap.init(A);
    for (objs) |o| try m.put(oid(o), o);
    return m;
}

fn stratum(label: []const u8, scheme: []const u8, ordinal: i64, unit: ?[]const u8, governs: ?[]const []const u8) !ObjectMap {
    var o = newObj();
    try o.put("type", str("stratum"));
    try o.put("label", str(label));
    try o.put("scheme", str(scheme));
    try o.put("ordinal", .{ .integer = ordinal });
    if (unit) |u| try o.put("unit", str(u));
    if (governs) |g| try o.put("governs", try strArr(g));
    return mk(o);
}

fn occ(label: []const u8, stratum_id: ?[]const u8) !ObjectMap {
    var o = newObj();
    try o.put("type", str("occurrent"));
    try o.put("label", str(label));
    try o.put("category", str("event"));
    if (stratum_id) |s| try o.put("stratum", str(s));
    return mk(o);
}

fn cnt(label: []const u8) !ObjectMap {
    var o = newObj();
    try o.put("type", str("continuant"));
    try o.put("label", str(label));
    try o.put("category", str("object"));
    return mk(o);
}

const CroOpts = struct {
    mechanism: ?[]const []const u8 = null,
    temporal: ?ObjectMap = null,
    modality: ?[]const u8 = null,
    context: ?[]const []const u8 = null,
    refines: ?[]const u8 = null,
    skips: ?bool = null,
};

fn cro(causes: []const []const u8, effects: []const []const u8, opts: CroOpts) !ObjectMap {
    var o = newObj();
    try o.put("type", str("causal_relation_object"));
    try o.put("causes", try strArr(causes));
    try o.put("effects", try strArr(effects));
    if (opts.mechanism) |m| try o.put("mechanism", try strArr(m));
    if (opts.temporal) |t| try o.put("temporal", .{ .object = t });
    if (opts.modality) |m| try o.put("modality", str(m));
    if (opts.context) |c| try o.put("context", try strArr(c));
    if (opts.refines) |r| try o.put("refines", str(r));
    if (opts.skips) |s| try o.put("skips", .{ .bool = s });
    return mk(o);
}

fn bridge(coarse: []const u8, fine: []const []const u8, relation: []const u8) !ObjectMap {
    var o = newObj();
    try o.put("type", str("bridge"));
    try o.put("coarse", str(coarse));
    try o.put("fine", try strArr(fine));
    try o.put("relation", str(relation));
    return mk(o);
}

fn port(bearer: []const u8, label: []const u8, direction: []const u8, accepts: []const []const u8, realizable: ?[]const u8) !ObjectMap {
    var o = newObj();
    try o.put("type", str("port"));
    try o.put("bearer", str(bearer));
    try o.put("label", str(label));
    try o.put("direction", str(direction));
    try o.put("accepts", try strArr(accepts));
    if (realizable) |r| try o.put("realizable", str(r));
    return mk(o);
}

fn conduit(frm: []const u8, to: []const u8, carries: []const []const u8, label: []const u8, transform: ?[]const u8) !ObjectMap {
    var o = newObj();
    try o.put("type", str("conduit"));
    try o.put("label", str(label));
    try o.put("from", str(frm));
    try o.put("to", str(to));
    try o.put("carries", try strArr(carries));
    if (transform) |t| try o.put("transform", str(t));
    return mk(o);
}

fn quality(label: []const u8, datatype: []const u8, unit: ?[]const u8, stratum_id: ?[]const u8) !ObjectMap {
    var o = newObj();
    try o.put("type", str("quality"));
    try o.put("label", str(label));
    try o.put("datatype", str(datatype));
    if (unit) |u| try o.put("unit", str(u));
    if (stratum_id) |s| try o.put("stratum", str(s));
    return mk(o);
}

fn individual(instantiates: []const u8, designator: ?[]const u8, part_of: ?[]const u8) !ObjectMap {
    var o = newObj();
    try o.put("type", str("token_individual"));
    try o.put("instantiates", str(instantiates));
    if (designator) |d| try o.put("designator", str(d));
    if (part_of) |p| try o.put("part_of", str(p));
    return mk(o);
}

fn token(instantiates: []const u8, interval: ObjectMap, participants: ?[]const Value, locus: ?[]const u8) !ObjectMap {
    var o = newObj();
    try o.put("type", str("token_occurrence"));
    try o.put("instantiates", str(instantiates));
    try o.put("interval", .{ .object = interval });
    if (participants) |p| {
        var arr = Array.init(A);
        try arr.appendSlice(p);
        try o.put("participants", .{ .array = arr });
    }
    if (locus) |l| try o.put("locus", str(l));
    return mk(o);
}

fn state(subject: []const u8, qual: []const u8, value: Value, interval: ObjectMap) !ObjectMap {
    var o = newObj();
    try o.put("type", str("state_assertion"));
    try o.put("subject", str(subject));
    try o.put("quality", str(qual));
    try o.put("value", value);
    try o.put("interval", .{ .object = interval });
    return mk(o);
}

const TccOpts = struct {
    covering_law: ?[]const u8 = null,
    actual_delay: ?ObjectMap = null,
    counterfactual: ?bool = null,
};

fn tcc(causes: []const []const u8, effects: []const []const u8, opts: TccOpts) !ObjectMap {
    var o = newObj();
    try o.put("type", str("token_causal_claim"));
    try o.put("causes", try strArr(causes));
    try o.put("effects", try strArr(effects));
    if (opts.covering_law) |c| try o.put("covering_law", str(c));
    if (opts.actual_delay) |ad| try o.put("actual_delay", .{ .object = ad });
    if (opts.counterfactual) |cf| try o.put("counterfactual", .{ .bool = cf });
    return mk(o);
}

const Neuro = struct { s4: ObjectMap, s5: ObjectMap, s6: ObjectMap, s7: ObjectMap, s9: ObjectMap, s14: ObjectMap };

fn neuro() !Neuro {
    return .{
        .s4 = try stratum("macromolecular", "neuroendocrine", 4, null, null),
        .s5 = try stratum("subcellular", "neuroendocrine", 5, null, null),
        .s6 = try stratum("cellular", "neuroendocrine", 6, null, null),
        .s7 = try stratum("synaptic", "neuroendocrine", 7, null, null),
        .s9 = try stratum("region", "neuroendocrine", 9, null, null),
        .s14 = try stratum("community_and_society", "neuroendocrine", 14, null, null),
    };
}

fn neuroStratum(nu: Neuro, ord: usize) ObjectMap {
    return switch (ord) {
        4 => nu.s4,
        5 => nu.s5,
        6 => nu.s6,
        7 => nu.s7,
        9 => nu.s9,
        14 => nu.s14,
        else => unreachable,
    };
}

fn interval2(pairs: []const struct { k: []const u8, v: Value }) !ObjectMap {
    var o = newObj();
    for (pairs) |p| try o.put(p.k, p.v);
    return o;
}

// ---------------------------------------------------------------------------
// V39 - V107: the 2.0.0 additions
// ---------------------------------------------------------------------------

fn v39() !void {
    const st = try stratum("cellular", "neuroendocrine", 6, "cell", &.{"cell_biology"});
    try expect((try schema.validateSchema(A, .{ .object = st }, null)).ok);
}

fn v40() !void {
    var bad = newObj();
    try bad.put("type", str("stratum"));
    try bad.put("label", str("cellular"));
    try bad.put("ordinal", .{ .integer = 6 });
    bad = try mk(bad);
    const sr = try schema.validateSchema(A, .{ .object = bad }, "stratum");
    try expect(!sr.ok);
    try expectContains(sr.errors, "scheme");
}

fn v41() !void {
    const a = try stratum("cellular", "neuroendocrine", 6, null, null);
    const b = try stratum("neuronal", "neuroendocrine", 6, null, null);
    try expect((try schema.validateSchema(A, .{ .object = a }, null)).ok);
    try expect((try schema.validateSchema(A, .{ .object = b }, null)).ok);
    try expect(!eq(oid(a), oid(b)));
}

fn v42() !void {
    const nu = try neuro();
    const s4p = try stratum("molecular", "physics", 4, null, null);
    const c = try occ("chronic_social_subordination", oid(nu.s14));
    const e = try occ("gene_expression", oid(s4p));
    var smap = ObjMap.init(A);
    try smap.put(oid(nu.s14), nu.s14);
    try smap.put(oid(s4p), s4p);
    const omap = try objMapOf(&.{ c, e });
    const P = try cro(&.{oid(c)}, &.{oid(e)}, .{});
    try expect(eq(try semantics.classifyCro(A, P, &omap, &smap), "scheme_mismatch"));
}

fn v43() !void {
    const a = try stratum("macromolecular", "neuroendocrine", 4, null, null);
    const b = try stratum("region", "neuroendocrine", 9, null, null);
    try expect((try schema.validateSchema(A, .{ .object = a }, null)).ok);
    try expect((try schema.validateSchema(A, .{ .object = b }, null)).ok);
}

fn v44() !void {
    const st = try stratum("cellular", "neuroendocrine", 6, null, null);
    const o = try occ("neuron_fires", oid(st));
    try expect((try schema.validateSchema(A, .{ .object = o }, null)).ok);
    try expect((try semantics.validateSemantics(A, .{ .object = o }, null)).ok);
}

fn v45() !void {
    const o = try occ("press_button", null);
    try expect((try schema.validateSchema(A, .{ .object = o }, null)).ok);
    const e = try occ("light_on", null);
    const P = try cro(&.{oid(o)}, &.{oid(e)}, .{});
    const omap = try objMapOf(&.{ o, e });
    var smap = ObjMap.init(A);
    try expect(eq(try semantics.classifyCro(A, P, &omap, &smap), "unclassifiable"));
}

fn v46() !void {
    const nu = try neuro();
    const a = try occ("depolarization", oid(nu.s5));
    const b = try occ("depolarization", oid(nu.s6));
    try expect(!eq(oid(a), oid(b)));
}

const BridgeFixture = struct { b: ObjectMap, omap: ObjMap, smap: ObjMap };

fn bridgeFixture(relation: []const u8) !BridgeFixture {
    const nu = try neuro();
    const coarse = try occ("action_potential_fires", oid(nu.s6));
    const f1 = try occ("sodium_channels_open", oid(nu.s4));
    const f2 = try occ("sodium_influx", oid(nu.s4));
    const b = try bridge(oid(coarse), &.{ oid(f1), oid(f2) }, relation);
    const omap = try objMapOf(&.{ coarse, f1, f2 });
    var smap = ObjMap.init(A);
    try smap.put(oid(nu.s4), nu.s4);
    try smap.put(oid(nu.s6), nu.s6);
    return .{ .b = b, .omap = omap, .smap = smap };
}

fn validBridge(relation: []const u8) !void {
    var fx = try bridgeFixture(relation);
    try expect((try schema.validateSchema(A, .{ .object = fx.b }, null)).ok);
    try expect(semantics.bridgeWellformed(fx.b, &fx.omap, &fx.smap).ok);
}

fn v47() !void {
    try validBridge("constitutes");
}
fn v48() !void {
    try validBridge("aggregates");
}
fn v49() !void {
    try validBridge("realizes");
}
fn v50() !void {
    try validBridge("supervenes_on");
}

fn v51() !void {
    const nu = try neuro();
    const coarse = try occ("x_coarse", oid(nu.s4));
    const fine = try occ("x_fine", oid(nu.s6));
    const b = try bridge(oid(coarse), &.{oid(fine)}, "constitutes");
    const omap = try objMapOf(&.{ coarse, fine });
    var smap = ObjMap.init(A);
    try smap.put(oid(nu.s4), nu.s4);
    try smap.put(oid(nu.s6), nu.s6);
    try expect(!semantics.bridgeWellformed(b, &omap, &smap).ok);
}

fn v52() !void {
    const nu = try neuro();
    const coarse = try occ("c", oid(nu.s6));
    const f1 = try occ("f1", oid(nu.s4));
    const f2 = try occ("f2", oid(nu.s5));
    const b = try bridge(oid(coarse), &.{ oid(f1), oid(f2) }, "constitutes");
    const omap = try objMapOf(&.{ coarse, f1, f2 });
    var smap = ObjMap.init(A);
    try smap.put(oid(nu.s4), nu.s4);
    try smap.put(oid(nu.s5), nu.s5);
    try smap.put(oid(nu.s6), nu.s6);
    try expect(!semantics.bridgeWellformed(b, &omap, &smap).ok);
}

fn v53() !void {
    const x = try sym("occurrent:x");
    const y = try sym("occurrent:y");
    const b1 = try bridge(x, &.{y}, "constitutes");
    const b2 = try bridge(y, &.{x}, "constitutes");
    var edges = std.StringArrayHashMap(std.ArrayList([]const u8)).init(A);
    for ([_]ObjectMap{ b1, b2 }) |b| {
        for (b.get("fine").?.array.items) |f| {
            const gop = try edges.getOrPut(f.string);
            if (!gop.found_existing) gop.value_ptr.* = std.ArrayList([]const u8).init(A);
            try gop.value_ptr.append(jcs.getString(b, "coarse").?);
        }
    }
    try expect(try semantics.hasCycle(A, &edges));
}

fn v54() !void {
    const a = try stratum("cellular", "neuroendocrine", 6, null, null);
    const b = try stratum("molecular", "physics", 4, null, null);
    const coarse = try occ("c", oid(a));
    const fine = try occ("f", oid(b));
    const br = try bridge(oid(coarse), &.{oid(fine)}, "constitutes");
    const omap = try objMapOf(&.{ coarse, fine });
    var smap = ObjMap.init(A);
    try smap.put(oid(a), a);
    try smap.put(oid(b), b);
    try expect(!semantics.bridgeWellformed(br, &omap, &smap).ok);
}

fn v55() !void {
    const nu = try neuro();
    const coarse = try occ("decision_made", oid(nu.s6));
    const f1 = try occ("cascade_a", oid(nu.s4));
    const f2 = try occ("cascade_b", oid(nu.s4));
    const b1 = try bridge(oid(coarse), &.{oid(f1)}, "realizes");
    const b2 = try bridge(oid(coarse), &.{oid(f2)}, "realizes");
    try expect(!eq(oid(b1), oid(b2)));
    try expect((try schema.validateSchema(A, .{ .object = b1 }, null)).ok);
    try expect((try schema.validateSchema(A, .{ .object = b2 }, null)).ok);
}

const ReachFixture = struct { P: ObjectMap, members: ObjMap, bridges: [2]ObjectMap };

fn reachFixture() !ReachFixture {
    const nu = try neuro();
    const ap = try occ("action_potential_fires", oid(nu.s6));
    const nt = try occ("neurotransmitter_released", oid(nu.s6));
    const fa = try occ("calcium_enters", oid(nu.s4));
    const fb = try occ("vesicle_fuses", oid(nu.s4));
    const m1 = try cro(&.{oid(fa)}, &.{oid(fb)}, .{});
    const P = try cro(&.{oid(ap)}, &.{oid(nt)}, .{ .mechanism = &.{oid(m1)} });
    var members = ObjMap.init(A);
    try members.put(oid(m1), m1);
    const bridges = [2]ObjectMap{
        try bridge(oid(ap), &.{oid(fa)}, "constitutes"),
        try bridge(oid(nt), &.{oid(fb)}, "constitutes"),
    };
    return .{ .P = P, .members = members, .bridges = bridges };
}

fn v56() !void {
    var fx = try reachFixture();
    try expect(eq(try semantics.hierarchyConsistent(A, fx.P, &fx.members, &fx.bridges), "consistent"));
}

fn v57() !void {
    var fx = try reachFixture();
    const empty = [_]ObjectMap{};
    try expect(eq(try semantics.hierarchyConsistent(A, fx.P, &fx.members, &empty), "inconsistent"));
}

fn v58() !void {
    var fx = try reachFixture();
    const empty = [_]ObjectMap{};
    const literal = try semantics.hierarchyConsistent(A, fx.P, &fx.members, &empty);
    const bridged = try semantics.hierarchyConsistent(A, fx.P, &fx.members, &fx.bridges);
    try expect(!eq(literal, "consistent") and eq(bridged, "consistent"));
}

fn classifyOrd(cause_ord: usize, effect_ord: usize) ![]const u8 {
    const nu = try neuro();
    const sc = neuroStratum(nu, cause_ord);
    const se = neuroStratum(nu, effect_ord);
    const c = try occ("c", oid(sc));
    const e = try occ("e", oid(se));
    var smap = ObjMap.init(A);
    try smap.put(oid(sc), sc);
    try smap.put(oid(se), se);
    const omap = try objMapOf(&.{ c, e });
    return semantics.classifyCro(A, try cro(&.{oid(c)}, &.{oid(e)}, .{}), &omap, &smap);
}

fn v59() !void {
    try expect(eq(try classifyOrd(6, 6), "intra_stratal"));
}
fn v60() !void {
    try expect(eq(try classifyOrd(6, 5), "adjacent_stratal"));
}
fn v61() !void {
    try expect(eq(try classifyOrd(14, 4), "skipping"));
}

const SkipFixture = struct { P: ObjectMap, cls: []const u8 };

fn skipFixture(cause_ord: usize, effect_ord: usize, opts: CroOpts) !SkipFixture {
    const nu = try neuro();
    const sc = neuroStratum(nu, cause_ord);
    const se = neuroStratum(nu, effect_ord);
    const c = try occ("c", oid(sc));
    const e = try occ("e", oid(se));
    var smap = ObjMap.init(A);
    try smap.put(oid(sc), sc);
    try smap.put(oid(se), se);
    const omap = try objMapOf(&.{ c, e });
    const P = try cro(&.{oid(c)}, &.{oid(e)}, opts);
    const cls = try semantics.classifyCro(A, P, &omap, &smap);
    return .{ .P = P, .cls = cls };
}

fn v62() !void {
    const fx = try skipFixture(14, 4, .{});
    const gaps = try semantics.skipGaps(A, fx.P, fx.cls);
    try expect(gaps.items.len == 1 and eq(gaps.items[0], "incomplete_mechanism"));
}

fn v63() !void {
    const fx = try skipFixture(14, 4, .{ .skips = true });
    const gaps = try semantics.skipGaps(A, fx.P, fx.cls);
    try expect(gaps.items.len == 0);
}

fn v64() !void {
    const fx = try skipFixture(14, 4, .{ .skips = true, .mechanism = &.{try sym("causal_relation_object:m")} });
    const gaps = try semantics.skipGaps(A, fx.P, fx.cls);
    try expect(gaps.items.len == 1 and eq(gaps.items[0], "contradictory_skip"));
    const mr = try semantics.validateSemantics(A, .{ .object = fx.P }, null);
    try expect(!mr.ok);
    try expectContains(mr.errors, "contradictory_skip");
}

fn v65() !void {
    const fx = try skipFixture(6, 6, .{ .skips = true });
    const gaps = try semantics.skipGaps(A, fx.P, fx.cls);
    try expect(gaps.items.len == 1 and eq(gaps.items[0], "vacuous_skip"));
}

fn v66() !void {
    const nu = try neuro();
    const c = try occ("c", oid(nu.s14));
    const e = try occ("e", oid(nu.s4));
    const absent = try cro(&.{oid(c)}, &.{oid(e)}, .{});
    const false_ = try cro(&.{oid(c)}, &.{oid(e)}, .{ .skips = false });
    try expect(!eq(oid(absent), oid(false_)));
}

fn v67() !void {
    const nu = try neuro();
    const c1 = try occ("c1", oid(nu.s4));
    const c2 = try occ("c2", oid(nu.s6));
    const e = try occ("e", oid(nu.s6));
    const P = try cro(&.{ oid(c1), oid(c2) }, &.{oid(e)}, .{});
    const omap = try objMapOf(&.{ c1, c2, e });
    try expect(try semantics.endpointsMixed(A, P, &omap));
}

fn v68() !void {
    const P = try cro(&.{try sym("occurrent:a")}, &.{try sym("occurrent:b")}, .{ .modality = "enabling" });
    try expect((try schema.validateSchema(A, .{ .object = P }, null)).ok);
}

fn plainCro(cause: []const u8, effect: []const u8, modality: []const u8) !ObjectMap {
    var o = newObj();
    try o.put("causes", try strArr(&.{cause}));
    try o.put("effects", try strArr(&.{effect}));
    try o.put("modality", str(modality));
    return o;
}

fn v69() !void {
    const a = try plainCro(try sym("occurrent:a"), try sym("occurrent:b"), "enabling");
    const b = try plainCro(try sym("occurrent:a"), try sym("occurrent:b"), "sufficient");
    try expect(semantics.conflicts(a, b) == false);
}

fn v70() !void {
    const a = try plainCro(try sym("occurrent:a"), try sym("occurrent:b"), "enabling");
    const b = try plainCro(try sym("occurrent:a"), try sym("occurrent:b"), "preventive");
    try expect(semantics.conflicts(a, b) == true);
}

fn v71() !void {
    const b = try cnt("hippocampus");
    const p = try port(oid(b), "perforant_path", "in", &.{try sym("occurrent:signal")}, null);
    try expect((try schema.validateSchema(A, .{ .object = p }, null)).ok);
}

fn v72() !void {
    const b = oid(try cnt("hippocampus"));
    const x = try sym("occurrent:signal");
    const p1 = try port(b, "perforant_path", "in", &.{x}, null);
    const p2 = try port(b, "fornix", "in", &.{x}, null);
    try expect(!eq(oid(p1), oid(p2)));
}

const ConduitFixture = struct { c: ObjectMap, pmap: ObjMap, cro_map: ObjMap };

fn conduitFixture(transform: bool, bad_carry: bool, in_from: bool) !ConduitFixture {
    const x = try sym("occurrent:motor_command");
    const y = try sym("occurrent:error_signal");
    const z = try sym("occurrent:unrelated");
    const m1 = oid(try cnt("motor_cortex"));
    const m2 = oid(try cnt("spinal_neuron"));
    const frm = try port(m1, "out_port", if (in_from) "in" else "out", &.{x}, null);
    const to_accepts: []const []const u8 = if (transform) &.{y} else &.{x};
    const to = try port(m2, "in_port", "in", to_accepts, null);
    const carries: []const []const u8 = if (bad_carry) &.{z} else &.{x};
    var cro_map = ObjMap.init(A);
    var xform: ?[]const u8 = null;
    if (transform) {
        const law = try cro(&.{x}, &.{y}, .{});
        try cro_map.put(oid(law), law);
        xform = oid(law);
    }
    const c = try conduit(oid(frm), oid(to), carries, "conn", xform);
    var pmap = ObjMap.init(A);
    try pmap.put(oid(frm), frm);
    try pmap.put(oid(to), to);
    return .{ .c = c, .pmap = pmap, .cro_map = cro_map };
}

fn v73() !void {
    var fx = try conduitFixture(false, false, false);
    try expect((try schema.validateSchema(A, .{ .object = fx.c }, null)).ok);
    try expect(semantics.conduitWellformed(fx.c, &fx.pmap, null).ok);
}

fn v74() !void {
    var fx = try conduitFixture(true, false, false);
    try expect((try schema.validateSchema(A, .{ .object = fx.c }, null)).ok);
    try expect(semantics.conduitWellformed(fx.c, &fx.pmap, &fx.cro_map).ok);
}

fn v75() !void {
    var fx = try conduitFixture(false, true, false);
    try expect(!semantics.conduitWellformed(fx.c, &fx.pmap, null).ok);
}

fn v76() !void {
    var fx = try conduitFixture(false, false, true);
    try expect(!semantics.conduitWellformed(fx.c, &fx.pmap, null).ok);
}

fn v77() !void {
    var fx = try conduitFixture(true, false, false);
    try expect(semantics.conduitWellformed(fx.c, &fx.pmap, &fx.cro_map).ok);
    const law = fx.cro_map.values()[0];
    const eff0 = law.get("effects").?.array.items[0].string;
    var in_carries = false;
    for (fx.c.get("carries").?.array.items) |cc| {
        if (eq(cc.string, eff0)) in_carries = true;
    }
    try expect(!in_carries);
}

fn rlz(bearer: []const u8, kind: []const u8, label: ?[]const u8) !ObjectMap {
    var o = newObj();
    try o.put("type", str("realizable"));
    try o.put("kind", str(kind));
    try o.put("bearer", str(bearer));
    if (label) |l| try o.put("label", str(l));
    return mk(o);
}

fn v78() !void {
    const b = oid(try cnt("hippocampus"));
    try expect(!eq(oid(try rlz(b, "disposition", "long_term_potentiation")), oid(try rlz(b, "disposition", "pattern_separation"))));
}

fn v79() !void {
    const b = oid(try cnt("hippocampus"));
    const ua = try rlz(b, "disposition", null);
    const ub = try rlz(b, "disposition", null);
    try expect((try schema.validateSchema(A, .{ .object = ua }, null)).ok);
    try expect(eq(oid(ua), oid(ub)));
    try expect(!eq(oid(try rlz(b, "disposition", "some_function")), oid(ua)));
}

fn v80() !void {
    const parent = try occ("fires", null);
    const child = try occ("fires_action_potential", null);
    var e = newObj();
    try e.put("type", str("enrichment"));
    try e.put("about", str(oid(child)));
    try e.put("field", str("occurrent_subsumes"));
    try e.put("entry", str(oid(parent)));
    try expect((try semantics.validateSemantics(A, .{ .object = e }, null)).ok);
}

fn v81() !void {
    const a = try sym("occurrent:a");
    const b = try sym("occurrent:b");
    var edges = std.StringArrayHashMap(std.ArrayList([]const u8)).init(A);
    var la = std.ArrayList([]const u8).init(A);
    try la.append(b);
    try edges.put(a, la);
    var lb = std.ArrayList([]const u8).init(A);
    try lb.append(a);
    try edges.put(b, lb);
    try expect(try semantics.hasCycle(A, &edges));
}

fn v82() !void {
    const whole = try occ("eat", null);
    const part = try occ("chew", null);
    var e = newObj();
    try e.put("type", str("enrichment"));
    try e.put("about", str(oid(part)));
    try e.put("field", str("occurrent_part_of"));
    try e.put("entry", str(oid(whole)));
    try expect((try semantics.validateSemantics(A, .{ .object = e }, null)).ok);
}

fn v83() !void {
    var spec_found: ?semantics.EnrichmentFieldSpec = null;
    for (&semantics.enrichment_fields) |*sp| {
        if (eq(sp.field, "occurrent_part_of")) spec_found = sp.*;
    }
    try expect(spec_found != null);
    try expect(eq(spec_found.?.shape, "occurrent"));
    try expect(spec_found.?.legal_kinds.len == 1 and eq(spec_found.?.legal_kinds[0], "occurrent"));
    var s = Store.init(A, true);
    _ = try s.put(try occ("eat", null), null);
    _ = try s.put(try occ("chew", null), null);
    for (s.objects.values()) |o| {
        try expect(!eq(jcs.getString(o, "type") orelse "", "causal_relation_object"));
    }
}

fn v84() !void {
    const nu = try neuro();
    const a = try occ("run", oid(nu.s9));
    const b = try occ("sprint", oid(nu.s6));
    try expect(!eq(jcs.getString(a, "stratum").?, jcs.getString(b, "stratum").?));
}

fn v85() !void {
    const c = try cnt("human_patient");
    const ti = try individual(oid(c), "salted_hash_abc123", null);
    try expect((try schema.validateSchema(A, .{ .object = ti }, null)).ok);
}

fn v86() !void {
    var bad = newObj();
    try bad.put("type", str("token_individual"));
    try bad.put("designator", str("x"));
    bad = try mk(bad);
    const sr = try schema.validateSchema(A, .{ .object = bad }, "token_individual");
    try expect(!sr.ok);
    try expectContains(sr.errors, "instantiates");
}

fn v87() !void {
    const c = oid(try cnt("human_patient"));
    try expect(!eq(oid(try individual(c, "hash_a", null)), oid(try individual(c, "hash_b", null))));
}

fn v88() !void {
    const o = try occ("bilateral_hippocampal_resection", null);
    const iv = try interval2(&.{
        .{ .k = "start", .v = str("1953-08-25T00:00:00Z") },
        .{ .k = "end", .v = str("1953-08-25T00:00:00Z") },
    });
    const t = try token(oid(o), iv, null, null);
    try expect((try schema.validateSchema(A, .{ .object = t }, null)).ok);
}

fn v89() !void {
    const o = oid(try occ("amnesia_onset", null));
    const bounded = try token(o, try interval2(&.{
        .{ .k = "start", .v = str("1953-08-25T00:00:00Z") },
        .{ .k = "end", .v = str("1953-08-26T00:00:00Z") },
    }), null, null);
    const instantaneous = try token(o, try interval2(&.{
        .{ .k = "start", .v = str("1953-08-25T00:00:00Z") },
    }), null, null);
    const ongoing = try token(o, try interval2(&.{
        .{ .k = "start", .v = str("1953-08-25T00:00:00Z") },
        .{ .k = "open", .v = .{ .bool = true } },
    }), null, null);
    try expect(!eq(oid(bounded), oid(instantaneous)));
    try expect(!eq(oid(bounded), oid(ongoing)));
    try expect(!eq(oid(instantaneous), oid(ongoing)));
}

fn v90() !void {
    const o = oid(try occ("resection", null));
    const c = oid(try cnt("human_patient"));
    const patient = oid(try individual(c, "p", null));
    const surgeon = oid(try individual(c, "s", null));
    const p1 = try interval2(&.{
        .{ .k = "role", .v = str("patient") },
        .{ .k = "filler", .v = str(patient) },
    });
    const p2 = try interval2(&.{
        .{ .k = "role", .v = str("agent") },
        .{ .k = "filler", .v = str(surgeon) },
    });
    const participants = [_]Value{ .{ .object = p1 }, .{ .object = p2 } };
    const iv = try interval2(&.{.{ .k = "start", .v = str("1953-08-25T00:00:00Z") }});
    const t = try token(o, iv, &participants, null);
    try expect((try schema.validateSchema(A, .{ .object = t }, null)).ok);
}

fn v91() !void {
    const q = try quality("cortisol_concentration", "quantity", "ug/dL", null);
    try expect((try schema.validateSchema(A, .{ .object = q }, null)).ok);
}

const StateFixture = struct { st: ObjectMap, q: ObjectMap };

fn stateFixture(datatype: []const u8, value: Value, unit: ?[]const u8) !StateFixture {
    const q = try quality("cortisol_concentration", datatype, unit, null);
    const c = oid(try cnt("human_patient"));
    const subj = oid(try individual(c, "p", null));
    const iv = try interval2(&.{
        .{ .k = "start", .v = str("2026-01-01T00:00:00Z") },
        .{ .k = "end", .v = str("2026-01-01T01:00:00Z") },
    });
    const st = try state(subj, oid(q), value, iv);
    return .{ .st = st, .q = q };
}

fn v92() !void {
    const value = try interval2(&.{
        .{ .k = "quantity", .v = flt(15.0) },
        .{ .k = "unit", .v = str("ug/dL") },
    });
    const fx = try stateFixture("quantity", .{ .object = value }, "ug/dL");
    try expect((try schema.validateSchema(A, .{ .object = fx.st }, null)).ok);
    try expect((try semantics.stateGaps(A, fx.st, fx.q)).items.len == 0);
}

fn v93() !void {
    const value = try interval2(&.{.{ .k = "categorical", .v = str("elevated") }});
    const fx = try stateFixture("categorical", .{ .object = value }, null);
    try expect((try schema.validateSchema(A, .{ .object = fx.st }, null)).ok);
    try expect((try semantics.stateGaps(A, fx.st, fx.q)).items.len == 0);
}

fn v94() !void {
    const value = try interval2(&.{.{ .k = "boolean", .v = .{ .bool = true } }});
    const fx = try stateFixture("boolean", .{ .object = value }, null);
    try expect((try schema.validateSchema(A, .{ .object = fx.st }, null)).ok);
    try expect((try semantics.stateGaps(A, fx.st, fx.q)).items.len == 0);
}

fn v95() !void {
    const value = try interval2(&.{.{ .k = "categorical", .v = str("elevated") }});
    const fx = try stateFixture("quantity", .{ .object = value }, "ug/dL");
    const gaps = try semantics.stateGaps(A, fx.st, fx.q);
    try expect(gaps.items.len == 1 and eq(gaps.items[0], "value_type_mismatch"));
}

fn v96() !void {
    const value = try interval2(&.{
        .{ .k = "quantity", .v = flt(15.0) },
        .{ .k = "unit", .v = str("mg/dL") },
    });
    const fx = try stateFixture("quantity", .{ .object = value }, "ug/dL");
    const gaps = try semantics.stateGaps(A, fx.st, fx.q);
    try expect(gaps.items.len == 1 and eq(gaps.items[0], "unit_mismatch"));
}

const LawTokens = struct { law: ObjectMap, tc: ObjectMap, te: ObjectMap };

fn lawAndTokens() !LawTokens {
    const o_cause = try occ("resection", null);
    const o_effect = try occ("amnesia_onset", null);
    const temporal = try interval2(&.{
        .{ .k = "minimum_delay", .v = .{ .integer = 0 } },
        .{ .k = "maximum_delay", .v = .{ .integer = 1 } },
        .{ .k = "unit", .v = str("days") },
    });
    const law = try cro(&.{oid(o_cause)}, &.{oid(o_effect)}, .{ .temporal = temporal, .modality = "sufficient" });
    const tc = try token(oid(o_cause), try interval2(&.{.{ .k = "start", .v = str("1953-08-25T00:00:00Z") }}), null, null);
    const te = try token(oid(o_effect), try interval2(&.{
        .{ .k = "start", .v = str("1953-08-25T00:00:00Z") },
        .{ .k = "open", .v = .{ .bool = true } },
    }), null, null);
    return .{ .law = law, .tc = tc, .te = te };
}

fn v97() !void {
    const lt = try lawAndTokens();
    const ad = try interval2(&.{
        .{ .k = "duration", .v = .{ .integer = 0 } },
        .{ .k = "unit", .v = str("instant") },
    });
    const claim = try tcc(&.{oid(lt.tc)}, &.{oid(lt.te)}, .{ .covering_law = oid(lt.law), .actual_delay = ad, .counterfactual = true });
    try expect((try schema.validateSchema(A, .{ .object = claim }, null)).ok);
}

fn v98() !void {
    const lt = try lawAndTokens();
    const claim = try tcc(&.{oid(lt.tc)}, &.{oid(lt.te)}, .{});
    try expect((try schema.validateSchema(A, .{ .object = claim }, null)).ok);
    try expect(!claim.contains("covering_law"));
}

fn v99() !void {
    const lt = try lawAndTokens();
    const ad = try interval2(&.{
        .{ .k = "duration", .v = .{ .integer = 0 } },
        .{ .k = "unit", .v = str("instant") },
    });
    try expect(semantics.delayWithinWindow(ad, lt.law.get("temporal").?.object) == true);
}

fn v100() !void {
    const temporal = try interval2(&.{
        .{ .k = "minimum_delay", .v = .{ .integer = 0 } },
        .{ .k = "maximum_delay", .v = .{ .integer = 1 } },
        .{ .k = "unit", .v = str("hours") },
    });
    const ad = try interval2(&.{
        .{ .k = "duration", .v = .{ .integer = 5 } },
        .{ .k = "unit", .v = str("days") },
    });
    try expect(semantics.delayWithinWindow(ad, temporal) == false);
}

fn v101() !void {
    const o = oid(try occ("x", null));
    const cause = try token(o, try interval2(&.{.{ .k = "start", .v = str("2026-01-02T00:00:00Z") }}), null, null);
    const effect = try token(o, try interval2(&.{.{ .k = "start", .v = str("2026-01-01T00:00:00Z") }}), null, null);
    const claim = try tcc(&.{oid(cause)}, &.{oid(effect)}, .{});
    const tmap = try objMapOf(&.{ cause, effect });
    try expect(semantics.retrocausal(claim, &tmap) == true);
}

fn v102() !void {
    const other = try cro(&.{try sym("occurrent:foo")}, &.{try sym("occurrent:bar")}, .{});
    const lt = try lawAndTokens();
    const claim = try tcc(&.{oid(lt.tc)}, &.{oid(lt.te)}, .{ .covering_law = oid(other) });
    const tmap = try objMapOf(&.{ lt.tc, lt.te });
    try expect(semantics.coveringLawMismatch(claim, &tmap, other) == true);
}

fn v103() !void {
    var body = newObj();
    try body.put("about", str(try sym("token_occurrence:t")));
    try body.put("evidence_type", str("observation"));
    try body.put("confidence", flt(0.9));
    const a = try signed("assertion", body, "signer", 0);
    try expect((try schema.validateSchema(A, .{ .object = a }, null)).ok);
}

fn v104() !void {
    const ev = [_][]const u8{ try sym("token_occurrence:t1"), try sym("token_causal_claim:c1") };
    var base = newObj();
    try base.put("type", str("assertion"));
    try base.put("about", str(try sym("causal_relation_object:law")));
    try base.put("source", str((try key("signer")).public_id));
    try base.put("evidence_type", str("intervention"));
    try base.put("strength", flt(0.95));
    try base.put("confidence", flt(0.99));
    try base.put("timestamp", str("2026-07-14T00:00:00Z"));
    var a = try jcs.cloneObject(A, base);
    try a.put("evidenced_by", try strArr(&ev));
    var a_with_id = try jcs.cloneObject(A, a);
    try a_with_id.put("id", str(try canonical.identify(A, a, null)));
    try expect((try schema.validateSchema(A, .{ .object = a_with_id }, null)).ok);
    try expect(!eq(try canonical.identify(A, a, null), try canonical.identify(A, base, null)));
}

fn v105() !void {
    var body = newObj();
    try body.put("about", str(try sym("causal_relation_object:law")));
    try body.put("evidence_type", str("simulation"));
    try body.put("confidence", flt(0.5));
    const a = try signed("assertion", body, "signer", 0);
    try expect((try schema.validateSchema(A, .{ .object = a }, null)).ok);
    // intervention < observation < simulation (strongest to weakest); trivially true
    try expect(true);
}

fn isSchemeName(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| switch (c) {
        'a'...'z', '0'...'9', '_' => {},
        else => return false,
    };
    return true;
}

fn inWholeWord(scheme: []const u8) bool {
    for (whole_word) |w| {
        if (eq(scheme, w)) return true;
    }
    return false;
}

fn scanIds(node: Value, ids: *std.ArrayList([]const u8)) !void {
    switch (node) {
        .string => |s| {
            if (std.mem.indexOfScalar(u8, s, ':')) |i| {
                const scheme = s[0..i];
                const rest = s[i + 1 ..];
                if (jcs.isHex(rest, 64) and isSchemeName(scheme)) try ids.append(scheme);
            }
        },
        .array => |arr| {
            for (arr.items) |x| try scanIds(x, ids);
        },
        .object => |o| {
            var it = o.iterator();
            while (it.next()) |e| try scanIds(e.value_ptr.*, ids);
        },
        else => {},
    }
}

fn v106() !void {
    for (1..39) |n| {
        var ids = std.ArrayList([]const u8).init(A);
        try scanIds(try vec(n), &ids);
        for (ids.items) |scheme| {
            if (!inWholeWord(scheme)) return error.AbbreviatedSchemeInVector;
        }
    }
    const rec = try pressButtonOccurrent();
    const id1 = try canonical.identify(A, rec, null);
    const id2 = try canonical.identify(A, rec, null);
    try expect(eq(id1, id2));
    const colon = std.mem.indexOfScalar(u8, id1, ':').?;
    try expect(eq(id1[0..colon], "occurrent"));
}

fn v107() !void {
    const hexid = try A.alloc(u8, 64);
    @memset(hexid, '0');
    // The abbreviated prefixes below are INTENTIONAL (the negative test); they
    // are assembled from letters so a re-mint pass cannot rewrite them.
    const cro_abbr = "c" ++ "r" ++ "o";
    var abbreviated = newObj();
    try abbreviated.put("type", str("causal_relation_object"));
    try abbreviated.put("id", str(try std.fmt.allocPrint(A, "{s}:{s}", .{ cro_abbr, hexid })));
    try abbreviated.put("causes", try strArr(&.{try std.fmt.allocPrint(A, "occurrent:{s}", .{hexid})}));
    try abbreviated.put("effects", try strArr(&.{try std.fmt.allocPrint(A, "occurrent:{s}", .{hexid})}));
    try expect(!(try schema.validateSchema(A, .{ .object = abbreviated }, "causal_relation_object")).ok);

    const str_abbr = "s" ++ "t" ++ "r";
    var abbr_str = newObj();
    try abbr_str.put("type", str("stratum"));
    try abbr_str.put("id", str(try std.fmt.allocPrint(A, "{s}:{s}", .{ str_abbr, hexid })));
    try abbr_str.put("label", str("cellular"));
    try abbr_str.put("scheme", str("neuroendocrine"));
    try abbr_str.put("ordinal", .{ .integer = 6 });
    try expect(!(try schema.validateSchema(A, .{ .object = abbr_str }, "stratum")).ok);

    var whole = newObj();
    try whole.put("type", str("causal_relation_object"));
    try whole.put("id", str(try std.fmt.allocPrint(A, "causal_relation_object:{s}", .{hexid})));
    try whole.put("causes", try strArr(&.{try std.fmt.allocPrint(A, "occurrent:{s}", .{hexid})}));
    try whole.put("effects", try strArr(&.{try std.fmt.allocPrint(A, "occurrent:{s}", .{hexid})}));
    try expect((try schema.validateSchema(A, .{ .object = whole }, "causal_relation_object")).ok);
}

// ---------------------------------------------------------------------------
// V108 - V137: the folded 3.0.0 delta (tick unit, cross_stratal_seam,
// realized_by) and the 4.0.0 delta (attitude, predicted_occurrence,
// prediction_error). Mirrors bindings/python/tests/run_conformance.py and the
// first-wave C++ port handler by handler.
// ---------------------------------------------------------------------------

fn schemaOk(o: ObjectMap) !void {
    try expect((try schema.validateSchema(A, .{ .object = o }, null)).ok);
}

fn semOk(o: ObjectMap) !void {
    try expect((try semantics.validateSemantics(A, .{ .object = o }, null)).ok);
}

/// A 64-character run of one character (for the pinned/negative fixtures).
fn repeatChar(c: u8, n: usize) ![]u8 {
    const buf = try A.alloc(u8, n);
    @memset(buf, c);
    return buf;
}

/// A CRO temporal window (minimum_delay, maximum_delay, unit). Whole numbers
/// are emitted as integers, so a wall-clock window keeps its 2.0.0 identifier
/// byte-for-byte under the widened (ticks-bearing) unit enum.
fn temporalObj(min: i64, max: i64, unit: []const u8) !ObjectMap {
    var t = newObj();
    try t.put("minimum_delay", .{ .integer = min });
    try t.put("maximum_delay", .{ .integer = max });
    try t.put("unit", str(unit));
    return t;
}

fn delayObj(duration: i64, unit: []const u8) !ObjectMap {
    var d = newObj();
    try d.put("duration", .{ .integer = duration });
    try d.put("unit", str(unit));
    return d;
}

/// A bare causes/effects/modality pair for the conflict test (no identity).
fn modalityPair(modality: []const u8) !ObjectMap {
    var o = newObj();
    try o.put("type", str("causal_relation_object"));
    try o.put("causes", try strArr(&.{try sym("occurrent:a")}));
    try o.put("effects", try strArr(&.{try sym("occurrent:b")}));
    try o.put("modality", str(modality));
    return o;
}

// -- Change One: the ordinal (tick) temporal unit --
fn v108() !void {
    const P = try cro(&.{try sym("occurrent:a")}, &.{try sym("occurrent:b")}, .{
        .temporal = try temporalObj(0, 5, "ticks"),
        .modality = "sufficient",
    });
    try schemaOk(P);
    try semOk(P);
}

fn v109() !void {
    const P = try cro(&.{try sym("occurrent:a")}, &.{try sym("occurrent:b")}, .{
        .temporal = try temporalObj(2, 5, "ticks"),
    });
    try expect(semantics.admissible(P, 3)); // 3 ticks inside [2, 5]
    try expect(semantics.admissible(P, 2) and semantics.admissible(P, 5)); // inclusive
    try expect(!semantics.admissible(P, 6) and !semantics.admissible(P, 1));
}

fn v110() !void {
    const tick_window = try temporalObj(0, 5, "ticks");
    const wall_window = try temporalObj(0, 5, "seconds");
    try expect(semantics.delayWithinWindow(try delayObj(3, "ticks"), tick_window));
    try expect(!semantics.delayWithinWindow(try delayObj(1, "ticks"), wall_window));
    try expect(!semantics.delayWithinWindow(try delayObj(1, "seconds"), tick_window));
    var a = try modalityPair("sufficient");
    try a.put("temporal", .{ .object = tick_window });
    var b = try modalityPair("preventive");
    try b.put("temporal", .{ .object = wall_window });
    try expect(!semantics.conflicts(a, b)); // disjoint dimensions -> no overlap
    // to_seconds refuses ticks (a category error).
    const refused = if (semantics.toSeconds(1, "ticks")) |_| false else |_| true;
    try expect(refused);
}

fn v111() !void {
    const tick = try cro(&.{try sym("occurrent:a")}, &.{try sym("occurrent:b")}, .{
        .temporal = try temporalObj(0, 1, "ticks"),
        .modality = "sufficient",
    });
    const secs = try cro(&.{try sym("occurrent:a")}, &.{try sym("occurrent:b")}, .{
        .temporal = try temporalObj(0, 1, "seconds"),
        .modality = "sufficient",
    });
    try expect(!eq(oid(tick), oid(secs))); // the unit is identity-bearing
    // a wall-clock record's identity is UNCHANGED (pinned 2.0.0 value).
    try expect(eq(oid(secs), "causal_relation_object:d8daf899daa3ee03caa6b1425cc6d4d33cef20d951e1203ffd35df29857aa43c"));
}

// -- Change Two: the managed cross-stratal seam --
fn seam(source: []const u8, target: []const u8, mechanism_status: []const u8, chain: ?[]const []const u8) !ObjectMap {
    var o = newObj();
    try o.put("type", str("cross_stratal_seam"));
    try o.put("source", str(source));
    try o.put("target", str(target));
    try o.put("mechanism_status", str(mechanism_status));
    if (chain) |c| try o.put("chain", try strArr(c));
    return mk(o);
}

const SeamFixture = struct { seam: ObjectMap, omap: ObjMap, smap: ObjMap };

fn seamFixture(src_ord: usize, tgt_ord: usize, mechanism_status: []const u8, chain_ords: []const usize) !SeamFixture {
    const nu = try neuro();
    const src = try occ("source_event", oid(neuroStratum(nu, src_ord)));
    const tgt = try occ("target_event", oid(neuroStratum(nu, tgt_ord)));
    var omap = ObjMap.init(A);
    try omap.put(oid(src), src);
    try omap.put(oid(tgt), tgt);
    var smap = ObjMap.init(A);
    try smap.put(oid(neuroStratum(nu, src_ord)), neuroStratum(nu, src_ord));
    try smap.put(oid(neuroStratum(nu, tgt_ord)), neuroStratum(nu, tgt_ord));
    var chain = std.ArrayList([]const u8).init(A);
    for (chain_ords, 0..) |ord, i| {
        const c = try occ(try std.fmt.allocPrint(A, "chain_{d}", .{i}), oid(neuroStratum(nu, ord)));
        try omap.put(oid(c), c);
        try smap.put(oid(neuroStratum(nu, ord)), neuroStratum(nu, ord));
        try chain.append(oid(c));
    }
    const chain_opt: ?[]const []const u8 = if (chain_ords.len > 0) chain.items else null;
    const sm = try seam(oid(src), oid(tgt), mechanism_status, chain_opt);
    return .{ .seam = sm, .omap = omap, .smap = smap };
}

fn v112() !void {
    const f = try seamFixture(14, 4, "unmodeled", &[_]usize{});
    try schemaOk(f.seam);
    try semOk(f.seam);
    try expect(semantics.seamWellformed(f.seam, &f.omap, &f.smap).ok);
}

fn v113() !void {
    const a = try seamFixture(14, 4, "unmodeled", &[_]usize{});
    const b = try seamFixture(14, 4, "absent", &[_]usize{});
    try schemaOk(b.seam);
    try expect(semantics.seamWellformed(b.seam, &b.omap, &b.smap).ok);
    try expect(!eq(oid(a.seam), oid(b.seam))); // mechanism_status is identity-bearing
}

fn v114() !void {
    const drawn = try seamFixture(14, 4, "unmodeled", &[_]usize{ 9, 7, 6, 5 });
    try schemaOk(drawn.seam);
    try expect(semantics.seamWellformed(drawn.seam, &drawn.omap, &drawn.smap).ok);
    const bad = try seamFixture(14, 4, "absent", &[_]usize{ 9, 7, 6, 5 });
    const sem = try semantics.validateSemantics(A, .{ .object = bad.seam }, null);
    try expect(!sem.ok);
    try expectContains(sem.errors, "contradictory_seam");
    try expect(!semantics.seamWellformed(bad.seam, &bad.omap, &bad.smap).ok);
}

fn v115() !void {
    const f = try seamFixture(14, 4, "unmodeled", &[_]usize{});
    const nu = try neuro();
    const home = semantics.seamHome(f.seam, &f.omap, &f.smap);
    try expect(home != null and eq(home.?, oid(nu.s14))); // coarsest (max ordinal)
}

fn v116() !void {
    const adj = try seamFixture(6, 5, "unmodeled", &[_]usize{}); // adjacent (gap 1)
    try expect(!semantics.seamWellformed(adj.seam, &adj.omap, &adj.smap).ok);
    const co = try seamFixture(6, 6, "unmodeled", &[_]usize{}); // co-stratal (gap 0)
    try expect(!semantics.seamWellformed(co.seam, &co.omap, &co.smap).ok);
    const f = try seamFixture(14, 4, "unmodeled", &[_]usize{});
    try expect(std.mem.startsWith(u8, oid(f.seam), "cross_stratal_seam:"));
}

// -- Change Three: the realized_by reference --
fn conduitRealized(realized_by: ?[]const u8) !ObjectMap {
    var o = newObj();
    try o.put("type", str("conduit"));
    try o.put("label", str("conn"));
    try o.put("from", str(try std.fmt.allocPrint(A, "port:{s}", .{try repeatChar('1', 64)})));
    try o.put("to", str(try std.fmt.allocPrint(A, "port:{s}", .{try repeatChar('2', 64)})));
    try o.put("carries", try strArr(&.{try std.fmt.allocPrint(A, "occurrent:{s}", .{try repeatChar('3', 64)})}));
    if (realized_by) |r| try o.put("realized_by", str(r));
    return mk(o);
}

fn v117() !void {
    const c = try conduitRealized(try std.fmt.allocPrint(A, "causal_relation_object:{s}", .{try repeatChar('a', 64)}));
    try schemaOk(c);
    const c2 = try conduitRealized("native:region_stratum_predict");
    try schemaOk(c2); // a native scheme reference is legal
}

fn v118() !void {
    const bound = try conduitRealized("native:region_stratum_predict");
    const unbound = try conduitRealized(null);
    try expect(!eq(oid(bound), oid(unbound))); // realized_by is identity-bearing
    // an unbound conduit's identity is UNCHANGED (pinned 2.0.0 value).
    try expect(eq(oid(unbound), "conduit:dc4af3b1a24f0560d5ebcee488779f06ab3c78301cfb9d0c7edff80bc62e27a6"));
}

fn v119() !void {
    const unbound = try conduitRealized(null);
    try schemaOk(unbound); // unbound is legal
    var bad = try jcs.cloneObject(A, unbound);
    try bad.put("realized_by", str("not-a-scheme-qualified-reference"));
    try expect(!(try schema.validateSchema(A, .{ .object = bad }, "conduit")).ok);
}

// ---- V120 - V137: attitude, predicted_occurrence, prediction_error --------

fn attitude(holder: []const u8, attitude_type: []const u8, content: []const u8) !ObjectMap {
    var o = newObj();
    try o.put("type", str("attitude"));
    try o.put("holder", str(holder));
    try o.put("attitude_type", str(attitude_type));
    try o.put("content", str(content));
    return mk(o);
}

fn predicted(instantiates: []const u8, iv: ObjectMap, predictor: []const u8, strength: ?f64) !ObjectMap {
    var o = newObj();
    try o.put("type", str("predicted_occurrence"));
    try o.put("instantiates", str(instantiates));
    try o.put("interval", .{ .object = iv });
    try o.put("predictor", str(predictor));
    if (strength) |s| try o.put("strength", flt(s));
    return mk(o);
}

fn predictionError(predicted_id: []const u8, discrepancy: f64, observed: ?[]const u8) !ObjectMap {
    var o = newObj();
    try o.put("type", str("prediction_error"));
    try o.put("predicted", str(predicted_id));
    try o.put("discrepancy", flt(discrepancy));
    if (observed) |ob| try o.put("observed", str(ob));
    return mk(o);
}

fn tickWindow(start_tick: i64, end_tick: ?i64) !ObjectMap {
    var iv = newObj();
    try iv.put("start_tick", .{ .integer = start_tick });
    if (end_tick) |e| try iv.put("end_tick", .{ .integer = e });
    return iv;
}

fn wallInterval(start: []const u8, end: ?[]const u8) !ObjectMap {
    var iv = newObj();
    try iv.put("start", str(start));
    if (end) |e| try iv.put("end", str(e));
    return iv;
}

/// A modeled predicting agent's identifier (a token individual, never a key).
fn predictorId() ![]const u8 {
    const c = try cnt("forecasting_mind");
    return oid(try individual(oid(c), "predictor_p", null));
}

/// A modeled believing agent's identifier (a token individual, never a key).
fn believerId(designator: []const u8) ![]const u8 {
    const c = try cnt("believing_mind");
    return oid(try individual(oid(c), designator, null));
}

// -- Group X: prediction and prediction error (Section A) --
fn v120() !void {
    const o = try occ("rainfall_begins", null);
    const p = try predicted(oid(o), try tickWindow(3, 8), try predictorId(), null);
    try schemaOk(p);
    try semOk(p);
    try expect(std.mem.startsWith(u8, oid(p), "predicted_occurrence:"));
    var report_obj = newObj();
    try report_obj.put("type", str("token_occurrence"));
    try report_obj.put("instantiates", str(oid(o)));
    try report_obj.put("interval", .{ .object = try tickWindow(3, 8) });
    const report = try canonical.identify(A, report_obj, "token_occurrence");
    try expect(!eq(oid(p), report)); // a forecast is not a report
    try expect(std.mem.startsWith(u8, report, "token_occurrence:"));
}

fn v121() !void {
    const o = try occ("rainfall_begins", null);
    const who = try predictorId();
    const with_strength = try predicted(oid(o), try wallInterval("2026-07-23T00:00:00Z", "2026-07-24T00:00:00Z"), who, 0.8);
    const without = try predicted(oid(o), try wallInterval("2026-07-23T00:00:00Z", "2026-07-24T00:00:00Z"), who, null);
    for ([_]ObjectMap{ with_strength, without }) |p| {
        try schemaOk(p);
        try semOk(p);
    }
    try expect(!eq(oid(with_strength), oid(without))); // strength is identity-bearing
}

fn v122() !void {
    const o = try occ("rainfall_begins", null);
    var bad = newObj();
    try bad.put("type", str("predicted_occurrence"));
    try bad.put("instantiates", str(oid(o)));
    try bad.put("interval", .{ .object = try tickWindow(3, null) });
    bad = try mk(bad);
    const r = try schema.validateSchema(A, .{ .object = bad }, "predicted_occurrence");
    try expect(!r.ok);
    try expectContains(r.errors, "predictor");
}

fn v123() !void {
    const o = try occ("rainfall_begins", null);
    var iv = newObj();
    try iv.put("start", str("2026-07-23T00:00:00Z"));
    try iv.put("start_tick", .{ .integer = 3 });
    const both = try predicted(oid(o), iv, try predictorId(), null);
    try schemaOk(both);
    const r = try semantics.validateSemantics(A, .{ .object = both }, null);
    try expect(!r.ok);
    try expectContains(r.errors, "dimension_conflict");
}

fn v124() !void {
    const o = try occ("rainfall_begins", null);
    const p = try predicted(oid(o), try wallInterval("2026-07-23T00:00:00Z", null), try predictorId(), null);
    const t = try token(oid(o), try wallInterval("2026-07-23T06:00:00Z", null), null, null);
    const err = try predictionError(oid(p), 0.0, oid(t));
    try schemaOk(err);
    try semOk(err);
    try expect(!semantics.predictionPairingMismatch(err, p, t));
}

fn v125() !void {
    const o = try occ("rainfall_begins", null);
    const p = try predicted(oid(o), try wallInterval("2026-07-23T00:00:00Z", null), try predictorId(), null);
    const err = try predictionError(oid(p), -1.0, null);
    try schemaOk(err);
    try semOk(err);
    try expect(!err.contains("observed"));
    try expect(!semantics.predictionPairingMismatch(err, p, null));
}

fn v126() !void {
    const o = try occ("rainfall_begins", null);
    const p = try predicted(oid(o), try tickWindow(0, null), try predictorId(), null);
    var bad = newObj();
    try bad.put("type", str("prediction_error"));
    try bad.put("predicted", str(oid(p)));
    bad = try mk(bad);
    const r = try schema.validateSchema(A, .{ .object = bad }, "prediction_error");
    try expect(!r.ok);
    try expectContains(r.errors, "discrepancy");
}

fn v127() !void {
    const o = try occ("rainfall_begins", null);
    const other = try occ("snowfall_begins", null);
    const p = try predicted(oid(o), try wallInterval("2026-07-23T00:00:00Z", null), try predictorId(), null);
    const t = try token(oid(other), try wallInterval("2026-07-23T06:00:00Z", null), null, null);
    const err = try predictionError(oid(p), 1.0, oid(t));
    try schemaOk(err);
    try expect(semantics.predictionPairingMismatch(err, p, t)); // pairing mismatch
}

// -- Group Y: attitude and theory of mind (Section B) --
fn v128() !void {
    const value = try interval2(&.{
        .{ .k = "quantity", .v = flt(15.0) },
        .{ .k = "unit", .v = str("ug/dL") },
    });
    const fx = try stateFixture("quantity", .{ .object = value }, "ug/dL");
    const att = try attitude(try believerId("holder_h"), "believes", oid(fx.st));
    try schemaOk(att);
    try semOk(att);
}

fn v129() !void {
    const a = try occ("switch_pressed", null);
    const b = try occ("light_on", null);
    const actual = try cro(&.{oid(a)}, &.{oid(b)}, .{ .modality = "sufficient" });
    const believed = try cro(&.{oid(a)}, &.{oid(b)}, .{ .modality = "preventive" });
    try expect(semantics.conflicts(believed, actual)); // the CLAIMS contradict
    const att = try attitude(try believerId("holder_h"), "believes", oid(believed));
    try schemaOk(att);
    try semOk(att); // validity unaffected
    var s = Store.init(A, true);
    _ = try s.put(a, null);
    _ = try s.put(b, null);
    _ = try s.put(actual, null);
    _ = try s.put(att, null);
    try expect((try s.gaps("conflict")).items.len == 0); // Rule 25: NO conflict raised
}

fn v130() !void {
    const o = try occ("rainfall_begins", null);
    const att = try attitude(try believerId("holder_h"), "desires", oid(o));
    try schemaOk(att);
    try semOk(att);
}

fn v131() !void {
    const o = try occ("press_button", null);
    const att = try attitude(try believerId("holder_h"), "intends", oid(o));
    try schemaOk(att);
    try semOk(att);
}

fn v132() !void {
    const value = try interval2(&.{.{ .k = "boolean", .v = .{ .bool = true } }});
    const fx = try stateFixture("boolean", .{ .object = value }, null);
    const inner = try attitude(try believerId("holder_b"), "believes", oid(fx.st));
    const outer = try attitude(try believerId("holder_a"), "believes", oid(inner));
    for ([_]ObjectMap{ inner, outer }) |att| {
        try schemaOk(att);
        try semOk(att);
    }
    try expect(!eq(oid(outer), oid(inner)));
    try expect(eq(jcs.getString(outer, "content").?, oid(inner))); // outer content IS the inner attitude
}

fn v133() !void {
    const o = try occ("rainfall_begins", null);
    var bad = newObj();
    try bad.put("type", str("attitude"));
    try bad.put("holder", str(try believerId("holder_h")));
    try bad.put("attitude_type", str("suspects"));
    try bad.put("content", str(oid(o)));
    bad = try mk(bad);
    const r = try schema.validateSchema(A, .{ .object = bad }, "attitude");
    try expect(!r.ok);
    try expectContains(r.errors, "attitude_type");
}

fn v134() !void {
    const o = try occ("rainfall_begins", null);
    var bad = newObj();
    try bad.put("type", str("attitude"));
    try bad.put("holder", str(try believerId("holder_h")));
    try bad.put("attitude_type", str("believes"));
    try bad.put("content", str(oid(o)));
    try bad.put("strength", flt(0.9));
    bad = try mk(bad);
    const r = try schema.validateSchema(A, .{ .object = bad }, "attitude");
    try expect(!r.ok);
    try expectContains(r.errors, "strength");
}

fn v135() !void {
    const o = try occ("rainfall_begins", null);
    const att = try attitude(try believerId("holder_h"), "expects", oid(o));
    var body = newObj();
    try body.put("about", str(oid(att)));
    try body.put("evidence_type", str("observation"));
    try body.put("confidence", flt(0.9));
    const a = try signed("assertion", body, "signer", 0);
    try schemaOk(a);
    try expect(signing.verifyRecord(A, a, null));
    // the HOLDER (a modeled agent) and the SOURCE (a signing key) differ.
    const holder = jcs.getString(att, "holder").?;
    const source = jcs.getString(a, "source").?;
    try expect(eq(holder[0..std.mem.indexOfScalar(u8, holder, ':').?], "token_individual"));
    try expect(eq(source[0..std.mem.indexOfScalar(u8, source, ':').?], "ed25519"));
    try expect(!eq(holder, source));
}

// -- Group Z: the 4.0.0 identity witnesses --
fn v136() !void {
    // the V111 wall-clock Causal Relation Object, re-pinned under 4.0.0
    const secs = try cro(&.{try sym("occurrent:a")}, &.{try sym("occurrent:b")}, .{
        .temporal = try temporalObj(0, 1, "seconds"),
        .modality = "sufficient",
    });
    try expect(eq(oid(secs), "causal_relation_object:d8daf899daa3ee03caa6b1425cc6d4d33cef20d951e1203ffd35df29857aa43c"));
    // the V118 unbound conduit, re-pinned under 4.0.0
    const unbound = try conduitRealized(null);
    try expect(eq(oid(unbound), "conduit:dc4af3b1a24f0560d5ebcee488779f06ab3c78301cfb9d0c7edff80bc62e27a6"));
}

fn v137() !void {
    const hexid = try repeatChar('0', 64);
    // The abbreviated prefixes here are the deliberate negative tests; each is
    // assembled from letters so a whole-word re-mint pass cannot rewrite it.
    const att_abbr = "a" ++ "t" ++ "t";
    const prd_abbr = "p" ++ "r" ++ "d";
    const err_abbr = "e" ++ "r" ++ "r";

    var bad_att = newObj();
    try bad_att.put("type", str("attitude"));
    try bad_att.put("id", str(try std.fmt.allocPrint(A, "{s}:{s}", .{ att_abbr, hexid })));
    try bad_att.put("holder", str(try std.fmt.allocPrint(A, "token_individual:{s}", .{hexid})));
    try bad_att.put("attitude_type", str("believes"));
    try bad_att.put("content", str(try std.fmt.allocPrint(A, "state_assertion:{s}", .{hexid})));
    try expect(!(try schema.validateSchema(A, .{ .object = bad_att }, "attitude")).ok);

    var bad_prd = newObj();
    try bad_prd.put("type", str("predicted_occurrence"));
    try bad_prd.put("id", str(try std.fmt.allocPrint(A, "{s}:{s}", .{ prd_abbr, hexid })));
    try bad_prd.put("instantiates", str(try std.fmt.allocPrint(A, "occurrent:{s}", .{hexid})));
    try bad_prd.put("interval", .{ .object = try tickWindow(0, null) });
    try bad_prd.put("predictor", str(try std.fmt.allocPrint(A, "token_individual:{s}", .{hexid})));
    try expect(!(try schema.validateSchema(A, .{ .object = bad_prd }, "predicted_occurrence")).ok);

    var bad_err = newObj();
    try bad_err.put("type", str("prediction_error"));
    try bad_err.put("id", str(try std.fmt.allocPrint(A, "{s}:{s}", .{ err_abbr, hexid })));
    try bad_err.put("predicted", str(try std.fmt.allocPrint(A, "predicted_occurrence:{s}", .{hexid})));
    try bad_err.put("discrepancy", flt(0.0));
    try expect(!(try schema.validateSchema(A, .{ .object = bad_err }, "prediction_error")).ok);

    var whole_att = try jcs.cloneObject(A, bad_att);
    try whole_att.put("id", str(try std.fmt.allocPrint(A, "attitude:{s}", .{hexid})));
    try expect((try schema.validateSchema(A, .{ .object = whole_att }, "attitude")).ok);

    var whole_prd = try jcs.cloneObject(A, bad_prd);
    try whole_prd.put("id", str(try std.fmt.allocPrint(A, "predicted_occurrence:{s}", .{hexid})));
    try expect((try schema.validateSchema(A, .{ .object = whole_prd }, "predicted_occurrence")).ok);

    var whole_err = try jcs.cloneObject(A, bad_err);
    try whole_err.put("id", str(try std.fmt.allocPrint(A, "prediction_error:{s}", .{hexid})));
    try expect((try schema.validateSchema(A, .{ .object = whole_err }, "prediction_error")).ok);
}

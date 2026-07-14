//! Record-level signing and verification (spec/provenance.md), ported from
//! bindings/python/causalontology/signing.py.
//!
//! The signature is computed over the record's canonical identity-bearing
//! bytes (the RFC 8785 form with id and signature removed - exactly the bytes
//! that are hashed for the record's identifier), so verification needs
//! nothing but the record itself. Ed25519 (std.crypto.sign.Ed25519 with a
//! null noise parameter) is deterministic per RFC 8032: re-signing the same
//! record with the same key yields the same signature, so re-submission is
//! idempotent. Key derivation from a 32-byte seed uses
//! Ed25519.KeyPair.create(seed), which is deterministic in Zig 0.13.0.

const std = @import("std");
const jcs = @import("jcs.zig");
const canonical = @import("canonical.zig");

const Value = jcs.Value;
const ObjectMap = jcs.ObjectMap;
const Allocator = jcs.Allocator;
pub const Ed25519 = std.crypto.sign.Ed25519;

/// A keypair with its public identifier ("ed25519:<hex>").
pub const NamedKeypair = struct {
    kp: Ed25519.KeyPair,
    public_id: []const u8,
};

/// (secret keypair, "ed25519:<hex>") from a 32-byte seed.
pub fn keypairFromSeed(a: Allocator, seed: [32]u8) !NamedKeypair {
    const kp = try Ed25519.KeyPair.create(seed);
    const pk_bytes = kp.public_key.toBytes();
    return .{
        .kp = kp,
        .public_id = try std.fmt.allocPrint(a, "ed25519:{s}", .{try jcs.hexLower(a, &pk_bytes)}),
    };
}

/// Return the record completed with its id and Ed25519 signature.
pub fn signRecord(a: Allocator, record: ObjectMap, kp: Ed25519.KeyPair, kind_opt: ?[]const u8) !ObjectMap {
    const kind = kind_opt orelse try canonical.inferKind(record);
    var body = try jcs.cloneObject(a, record);
    _ = body.orderedRemove("signature");
    const message = try canonical.canonicalize(a, body, kind);
    const sig = try kp.sign(message, null);
    const sig_bytes = sig.toBytes();
    var out = try jcs.cloneObject(a, body);
    try out.put("id", .{ .string = try canonical.identify(a, body, kind) });
    try out.put("signature", .{ .string = try jcs.hexLower(a, &sig_bytes) });
    return out;
}

/// The hex of the key a record must verify against: a succession is signed
/// by the predecessor key, every other record by its source.
fn signerKeyHex(record: ObjectMap, kind: []const u8) ?[]const u8 {
    const field = if (std.mem.eql(u8, kind, "succession")) "predecessor" else "source";
    const value = jcs.getString(record, field) orelse return null;
    if (!std.mem.startsWith(u8, value, "ed25519:")) return null;
    return value["ed25519:".len..];
}

/// True iff the record's signature verifies against its own key field.
pub fn verifyRecord(a: Allocator, record: ObjectMap, kind_opt: ?[]const u8) bool {
    const kind = kind_opt orelse (canonical.inferKind(record) catch return false);
    const sig_hex = jcs.getString(record, "signature") orelse return false;
    const key_hex = signerKeyHex(record, kind) orelse return false;
    if (sig_hex.len != 128 or key_hex.len != 64) return false;
    var pk_bytes: [32]u8 = undefined;
    var sig_bytes: [64]u8 = undefined;
    _ = std.fmt.hexToBytes(&pk_bytes, key_hex) catch return false;
    _ = std.fmt.hexToBytes(&sig_bytes, sig_hex) catch return false;
    var body = jcs.cloneObject(a, record) catch return false;
    _ = body.orderedRemove("signature");
    const message = canonical.canonicalize(a, body, kind) catch return false;
    const public_key = Ed25519.PublicKey.fromBytes(pk_bytes) catch return false;
    const signature = Ed25519.Signature.fromBytes(sig_bytes);
    signature.verify(message, public_key) catch return false;
    return true;
}

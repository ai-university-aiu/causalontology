// Signing.swift
//
// Record-level signing and verification (spec/provenance.md).
//
// The signature is computed over the record's canonical identity-bearing
// bytes (the RFC 8785 form with id and signature removed - exactly the bytes
// that are hashed for the record's identifier), so verification needs
// nothing but the record itself. Ed25519 signing on Linux (swift-crypto,
// BoringSSL) is deterministic per RFC 8032.

import Foundation
import Crypto

/// (secret key, "ed25519:<hex>") from a 32-byte seed. For Ed25519 the raw
/// private key IS the 32-byte seed (RFC 8032), and the raw public key is
/// the 32-byte compressed point.
public func keypairFromSeed(
    _ seed: Data
) throws -> (secret: Curve25519.Signing.PrivateKey, publicId: String) {
    let secret = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
    let publicHex = hexEncode(secret.publicKey.rawRepresentation)
    return (secret, "ed25519:" + publicHex)
}

/// Return the record completed with its id and Ed25519 signature.
public func signRecord(
    _ record: [String: JsonValue],
    secret: Curve25519.Signing.PrivateKey,
    kind: String? = nil
) throws -> [String: JsonValue] {
    let resolvedKind: String
    if let kind = kind {
        resolvedKind = kind
    } else {
        resolvedKind = try inferKind(record)
    }
    var body = record
    body.removeValue(forKey: "signature")
    let message = try canonicalize(body, kind: resolvedKind)
    let signature = try secret.signature(for: message)
    var out = body
    out["id"] = .string(try identify(body, kind: resolvedKind))
    out["signature"] = .string(hexEncode(signature))
    return out
}

/// The hex public key named by the record's own key field: "source" for
/// most records, "predecessor" for a succession (a succession is signed by
/// the predecessor key). Nil when absent or not an ed25519: identifier.
func signerKeyHex(_ record: [String: JsonValue], kind: String) -> String? {
    let field = (kind == "succession") ? "predecessor" : "source"
    guard let value = record[field]?.stringValue else { return nil }
    guard value.hasPrefix("ed25519:") else { return nil }
    return String(value.dropFirst("ed25519:".count))
}

/// True iff the record's signature verifies against its own key field.
public func verifyRecord(_ record: [String: JsonValue], kind: String? = nil) -> Bool {
    let resolvedKind: String
    if let kind = kind {
        resolvedKind = kind
    } else if let inferred = try? inferKind(record) {
        resolvedKind = inferred
    } else {
        return false
    }
    guard let signatureHex = record["signature"]?.stringValue, !signatureHex.isEmpty else {
        return false
    }
    guard let keyHex = signerKeyHex(record, kind: resolvedKind), !keyHex.isEmpty else {
        return false
    }
    guard let publicBytes = hexDecode(keyHex), publicBytes.count == 32 else {
        return false
    }
    guard let signatureBytes = hexDecode(signatureHex), signatureBytes.count == 64 else {
        return false
    }
    guard let publicKey = try? Curve25519.Signing.PublicKey(rawRepresentation: publicBytes) else {
        return false
    }
    var body = record
    body.removeValue(forKey: "signature")
    guard let message = try? canonicalize(body, kind: resolvedKind) else {
        return false
    }
    return publicKey.isValidSignature(signatureBytes, for: message)
}

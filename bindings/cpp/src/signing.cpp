// signing.cpp - sign_record / verify_record over canonical bytes.

#include "signing.hpp"

#include "canonical.hpp"
#include "ed25519.hpp"
#include "sha2.hpp"

namespace co {

std::pair<std::string, std::string> keypair_from_seed(
    const std::string& seed32) {
    std::string public_key = ed25519::secret_to_public(seed32);
    return {seed32, "ed25519:" + to_hex(public_key)};
}

JValue sign_record(const JValue& record, const std::string& secret,
                   const std::string& kind) {
    std::string k = kind.empty() ? infer_kind(record) : kind;
    JValue body = record;
    body.erase("signature");
    std::string message = canonicalize(body, k);
    std::string signature = to_hex(ed25519::sign(secret, message));
    JValue out = body;
    out.set("id", JValue::of(identify(body, k)));
    out.set("signature", JValue::of(signature));
    return out;
}

namespace {

// The hex of the signer's key: source, or predecessor for a succession.
std::string signerKeyHex(const JValue& record, const std::string& kind) {
    std::string field = (kind == "succession") ? "predecessor" : "source";
    std::string value = record.getString(field);
    const std::string scheme = "ed25519:";
    if (value.rfind(scheme, 0) != 0) return "";
    return value.substr(scheme.size());
}

}  // namespace

bool verify_record(const JValue& record, const std::string& kind) {
    std::string k = kind.empty() ? infer_kind(record) : kind;
    std::string sigHex = record.getString("signature");
    std::string keyHex = signerKeyHex(record, k);
    if (sigHex.empty() || keyHex.empty()) return false;
    std::string public_key, signature;
    if (!from_hex(keyHex, public_key) || !from_hex(sigHex, signature))
        return false;
    JValue body = record;
    body.erase("signature");
    std::string message = canonicalize(body, k);
    return ed25519::verify(public_key, message, signature);
}

}  // namespace co

//! Record-level Ed25519 signing and verification (spec/provenance.md),
//! over the canonical identity-bearing bytes - byte-compatible with every
//! other binding (Ed25519 signatures are deterministic per RFC 8032).

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{Map, Value};

use crate::canonical::{canonicalize, identify, infer_kind};

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn bytes_of_hex(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len()).step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

/// (signing key, "ed25519:<hex>") from a 32-byte seed.
pub fn keypair_from_seed(seed: &[u8; 32]) -> (SigningKey, String) {
    let key = SigningKey::from_bytes(seed);
    let public = key.verifying_key();
    (key.clone(), format!("ed25519:{}", hex_of(public.as_bytes())))
}

/// Return the record completed with its id and Ed25519 signature.
pub fn sign_record(record: &Map<String, Value>, secret: &SigningKey,
                   kind: Option<&str>) -> Result<Map<String, Value>, String> {
    let kind = match kind {
        Some(k) => k.to_string(),
        None => infer_kind(record)?,
    };
    let mut body = record.clone();
    body.remove("signature");
    let message = canonicalize(&body, Some(&kind))?;
    let signature = secret.sign(&message);
    let id = identify(&body, Some(&kind))?;
    let mut out = body;
    out.insert("id".to_string(), Value::String(id));
    out.insert("signature".to_string(),
               Value::String(hex_of(&signature.to_bytes())));
    Ok(out)
}

fn signer_key_hex(record: &Map<String, Value>, kind: &str) -> Option<String> {
    let field = if kind == "succession" { "predecessor" } else { "source" };
    let value = record.get(field)?.as_str()?;
    let rest = value.strip_prefix("ed25519:")?;
    Some(rest.to_string())
}

/// True iff the record's signature verifies against its own key field.
pub fn verify_record(record: &Map<String, Value>, kind: Option<&str>) -> bool {
    let kind = match kind {
        Some(k) => k.to_string(),
        None => match infer_kind(record) {
            Ok(k) => k,
            Err(_) => return false,
        },
    };
    let sig_hex = match record.get("signature").and_then(Value::as_str) {
        Some(s) => s,
        None => return false,
    };
    let key_hex = match signer_key_hex(record, &kind) {
        Some(k) => k,
        None => return false,
    };
    let public_bytes = match bytes_of_hex(&key_hex) {
        Some(b) if b.len() == 32 => b,
        _ => return false,
    };
    let sig_bytes = match bytes_of_hex(sig_hex) {
        Some(b) if b.len() == 64 => b,
        _ => return false,
    };
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&public_bytes);
    let public = match VerifyingKey::from_bytes(&pk) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig);
    let mut body = record.clone();
    body.remove("signature");
    let message = match canonicalize(&body, Some(&kind)) {
        Ok(m) => m,
        Err(_) => return false,
    };
    public.verify(&message, &signature).is_ok()
}

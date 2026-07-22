//! Canonicalization and content-addressed identity (spec/identity.md).
//! RFC 8785 serialization of the identity-bearing fields, SHA-256, and
//! the scheme-prefixed identifier.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// The identity-bearing fields of each of the twenty-one kinds (3.0.0 adds
/// the cross_stratal_seam; the conduit gains realized_by; 4.0.0 adds the
/// attitude, the predicted_occurrence, and the prediction_error - all
/// additive and identity-preserving - a record that omits a new field keeps
/// its earlier identifier byte-for-byte, and the new kinds open new identity
/// schemes that disturb no existing record). "type" is always injected, so it
/// is not listed here.
pub fn identity_fields(kind: &str) -> Option<&'static [&'static str]> {
    match kind {
        // ---- type tier ----
        "occurrent" => Some(&["label", "category", "stratum"]),
        "causal_relation_object" => Some(&["causes", "effects", "mechanism",
                        "temporal", "modality", "context", "refines", "skips"]),
        "continuant" => Some(&["label", "category"]),
        "realizable" => Some(&["kind", "bearer", "label"]),
        "stratum" => Some(&["label", "scheme", "ordinal", "unit", "governs"]),
        "bridge" => Some(&["coarse", "fine", "relation"]),
        "cross_stratal_seam" => Some(&["source", "target", "mechanism_status",
                                       "chain"]),
        "port" => Some(&["bearer", "label", "direction", "accepts",
                         "realizable"]),
        "conduit" => Some(&["label", "from", "to", "carries", "transform",
                            "realized_by"]),
        "quality" => Some(&["label", "datatype", "unit", "stratum"]),
        // ---- token tier ----
        "token_individual" => Some(&["instantiates", "designator", "part_of"]),
        "token_occurrence" => Some(&["instantiates", "interval", "participants",
                                     "locus", "observer"]),
        "state_assertion" => Some(&["subject", "quality", "value", "interval"]),
        "token_causal_claim" => Some(&["causes", "effects", "covering_law",
                                       "actual_delay", "counterfactual"]),
        "attitude" => Some(&["holder", "attitude_type", "content"]),
        "predicted_occurrence" => Some(&["instantiates", "interval",
                                         "predictor", "strength"]),
        "prediction_error" => Some(&["predicted", "observed", "discrepancy"]),
        // ---- provenance tier ----
        "assertion" => Some(&["about", "source", "evidence_type", "evidence",
                              "strength", "confidence", "timestamp",
                              "evidenced_by"]),
        "enrichment" => Some(&["about", "field", "entry", "source",
                               "timestamp"]),
        "retraction" => Some(&["retracts", "source", "timestamp"]),
        "succession" => Some(&["predecessor", "successor", "timestamp"]),
        _ => None,
    }
}

/// The twenty-one whole-word schemes. scheme == type value == id prefix.
pub const SCHEMES: [&str; 21] = [
    "occurrent", "causal_relation_object", "continuant", "realizable",
    "stratum", "bridge", "cross_stratal_seam", "port", "conduit", "quality",
    "token_individual", "token_occurrence", "state_assertion",
    "token_causal_claim", "attitude", "predicted_occurrence",
    "prediction_error", "assertion", "enrichment", "retraction",
    "succession",
];

/// Whole-word re-mint (P7): the scheme IS the type value for every kind.
pub fn prefix_of(kind: &str) -> Option<&'static str> {
    SCHEMES.iter().find(|k| **k == kind).copied()
}

pub fn kind_of_prefix(prefix: &str) -> Option<&'static str> {
    SCHEMES.iter().find(|k| **k == prefix).copied()
}

pub fn infer_kind(obj: &Map<String, Value>) -> Result<String, String> {
    if let Some(Value::String(t)) = obj.get("type") {
        return Ok(t.clone());
    }
    if let Some(Value::String(id)) = obj.get("id") {
        if let Some((pre, _)) = id.split_once(':') {
            if let Some(kind) = kind_of_prefix(pre) {
                return Ok(kind.to_string());
            }
        }
    }
    if obj.contains_key("coarse") && obj.contains_key("fine") {
        return Ok("bridge".to_string());
    }
    if obj.contains_key("causes") && obj.contains_key("effects") {
        return Ok("causal_relation_object".to_string());
    }
    if obj.contains_key("retracts") {
        return Ok("retraction".to_string());
    }
    if obj.contains_key("predecessor") && obj.contains_key("successor") {
        return Ok("succession".to_string());
    }
    if obj.contains_key("field") && obj.contains_key("entry") {
        return Ok("enrichment".to_string());
    }
    if obj.contains_key("evidence_type")
        || (obj.contains_key("about") && obj.contains_key("confidence")) {
        return Ok("assertion".to_string());
    }
    if obj.contains_key("kind") && obj.contains_key("bearer") {
        return Ok("realizable".to_string());
    }
    Err("cannot infer kind (occurrents and continuants share a shape); \
         pass kind explicitly".to_string())
}

pub fn identity_bearing(obj: &Map<String, Value>, kind: Option<&str>)
                        -> Result<(String, Map<String, Value>), String> {
    let kind = match kind {
        Some(k) => k.to_string(),
        None => infer_kind(obj)?,
    };
    let fields = identity_fields(&kind)
        .ok_or_else(|| format!("unknown kind: {}", kind))?;
    let mut out = Map::new();
    out.insert("type".to_string(), Value::String(kind.clone()));
    for field in fields {
        if let Some(v) = obj.get(*field) {
            out.insert((*field).to_string(), v.clone());
        }
    }
    Ok((kind, out))
}

// ---------------------------------------------------------------------
// RFC 8785 serialization
// ---------------------------------------------------------------------

fn jcs_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{000C}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn jcs_number(n: &serde_json::Number, out: &mut String) -> Result<(), String> {
    if let Some(i) = n.as_i64() {
        out.push_str(&i.to_string());
        return Ok(());
    }
    if let Some(u) = n.as_u64() {
        out.push_str(&u.to_string());
        return Ok(());
    }
    let f = n.as_f64().ok_or("unrepresentable number")?;
    if !f.is_finite() {
        return Err("NaN and Infinity are not permitted (RFC 8785)".into());
    }
    if f == 0.0 {
        out.push('0');
    } else if f.fract() == 0.0 && f.abs() < 1e21 {
        out.push_str(&format!("{}", f as i128));
    } else {
        // Rust's shortest round-trip Display; the ES6 exponent form for
        // extreme magnitudes is pinned at the 1.0.0 freeze (spec note).
        out.push_str(&format!("{}", f));
    }
    Ok(())
}

pub fn jcs(value: &Value) -> Result<String, String> {
    let mut out = String::new();
    jcs_into(value, &mut out)?;
    Ok(out)
}

fn jcs_into(value: &Value, out: &mut String) -> Result<(), String> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => jcs_number(n, out)?,
        Value::String(s) => jcs_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                jcs_into(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // sort keys by UTF-16 code units (== byte order for our keys)
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                jcs_string(key, out);
                out.push(':');
                jcs_into(map.get(*key).unwrap(), out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

pub fn canonicalize(obj: &Map<String, Value>, kind: Option<&str>)
                    -> Result<Vec<u8>, String> {
    let (_, ib) = identity_bearing(obj, kind)?;
    Ok(jcs(&Value::Object(ib))?.into_bytes())
}

pub fn identify(obj: &Map<String, Value>, kind: Option<&str>)
                -> Result<String, String> {
    let (kind, ib) = identity_bearing(obj, kind)?;
    let bytes = jcs(&Value::Object(ib))?.into_bytes();
    let digest = Sha256::digest(&bytes);
    let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
    Ok(format!("{}:{}", prefix_of(&kind).unwrap(), hex))
}

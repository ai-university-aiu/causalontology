//! Canonicalization and content-addressed identity (spec/identity.md).
//! RFC 8785 serialization of the identity-bearing fields, SHA-256, and
//! the scheme-prefixed identifier.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

pub fn identity_fields(kind: &str) -> Option<&'static [&'static str]> {
    match kind {
        "occurrent" => Some(&["label", "category"]),
        "cro" => Some(&["causes", "effects", "mechanism", "temporal",
                        "modality", "context", "refines"]),
        "continuant" => Some(&["label", "category"]),
        "realizable" => Some(&["kind", "bearer"]),
        "assertion" => Some(&["about", "source", "evidence_type", "evidence",
                              "strength", "confidence", "timestamp"]),
        "enrichment" => Some(&["about", "field", "entry", "source",
                               "timestamp"]),
        "retraction" => Some(&["retracts", "source", "timestamp"]),
        "succession" => Some(&["predecessor", "successor", "timestamp"]),
        _ => None,
    }
}

pub fn prefix_of(kind: &str) -> Option<&'static str> {
    match kind {
        "occurrent" => Some("occ"),
        "cro" => Some("cro"),
        "continuant" => Some("cnt"),
        "realizable" => Some("rlz"),
        "assertion" => Some("ast"),
        "enrichment" => Some("enr"),
        "retraction" => Some("ret"),
        "succession" => Some("suc"),
        _ => None,
    }
}

pub fn kind_of_prefix(prefix: &str) -> Option<&'static str> {
    match prefix {
        "occ" => Some("occurrent"),
        "cro" => Some("cro"),
        "cnt" => Some("continuant"),
        "rlz" => Some("realizable"),
        "ast" => Some("assertion"),
        "enr" => Some("enrichment"),
        "ret" => Some("retraction"),
        "suc" => Some("succession"),
        _ => None,
    }
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
    if obj.contains_key("causes") && obj.contains_key("effects") {
        return Ok("cro".to_string());
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

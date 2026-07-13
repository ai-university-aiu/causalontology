//! The WebAssembly ABI: a minimal C-callable surface over the pure core,
//! so one audited binary serves every host (browsers, edge workers, and
//! any language with a WASM runtime). Strings cross the boundary as
//! UTF-8 JSON; every output buffer is length-prefixed (4 bytes, little
//! endian) and owned by the caller (free with co_free, length + 4).

use serde_json::{Map, Value};
use std::alloc::{alloc, dealloc, Layout};

#[no_mangle]
pub extern "C" fn co_alloc(len: usize) -> *mut u8 {
    unsafe { alloc(Layout::from_size_align(len.max(1), 1).unwrap()) }
}

/// # Safety
/// ptr must have come from co_alloc with the same len.
#[no_mangle]
pub unsafe extern "C" fn co_free(ptr: *mut u8, len: usize) {
    dealloc(ptr, Layout::from_size_align(len.max(1), 1).unwrap());
}

fn out(payload: String) -> *mut u8 {
    let bytes = payload.into_bytes();
    let ptr = co_alloc(bytes.len() + 4);
    unsafe {
        let len32 = (bytes.len() as u32).to_le_bytes();
        std::ptr::copy_nonoverlapping(len32.as_ptr(), ptr, 4);
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr.add(4), bytes.len());
    }
    ptr
}

unsafe fn parse(ptr: *const u8, len: usize) -> Option<Map<String, Value>> {
    let text = std::str::from_utf8(
        std::slice::from_raw_parts(ptr, len)).ok()?;
    serde_json::from_str::<Value>(text).ok()?.as_object().cloned()
}

fn err(msg: &str) -> String {
    format!("{{\"error\":{}}}", Value::String(msg.to_string()))
}

/// {"id": "..."} - the content-addressed identifier of a JSON object.
/// # Safety
/// ptr/len must describe a valid UTF-8 buffer.
#[no_mangle]
pub unsafe extern "C" fn co_identify(ptr: *const u8, len: usize) -> *mut u8 {
    let object = match parse(ptr, len) {
        Some(o) => o,
        None => return out(err("invalid JSON object")),
    };
    out(match crate::canonical::identify(&object, None) {
        Ok(id) => format!("{{\"id\":{}}}", Value::String(id)),
        Err(e) => err(&e),
    })
}

/// {"jcs": "..."} - the RFC 8785 identity-bearing bytes, as a string.
/// # Safety
/// ptr/len must describe a valid UTF-8 buffer.
#[no_mangle]
pub unsafe extern "C" fn co_canonicalize(ptr: *const u8, len: usize)
                                         -> *mut u8 {
    let object = match parse(ptr, len) {
        Some(o) => o,
        None => return out(err("invalid JSON object")),
    };
    out(match crate::canonical::canonicalize(&object, None) {
        Ok(bytes) => format!(
            "{{\"jcs\":{}}}",
            Value::String(String::from_utf8_lossy(&bytes).to_string())),
        Err(e) => err(&e),
    })
}

/// {"schema_valid": bool, "semantically_valid": bool, "reasons": [...]}
/// # Safety
/// ptr/len must describe a valid UTF-8 buffer.
#[no_mangle]
pub unsafe extern "C" fn co_validate(ptr: *const u8, len: usize) -> *mut u8 {
    let object = match parse(ptr, len) {
        Some(o) => o,
        None => return out(err("invalid JSON object")),
    };
    let (schema_ok, mut reasons) =
        crate::schema::validate_schema(&object, None);
    let (semantics_ok, more) =
        crate::semantics::validate_semantics(&object, None);
    reasons.extend(more);
    out(serde_json::to_string(&serde_json::json!({
        "schema_valid": schema_ok,
        "semantically_valid": semantics_ok,
        "reasons": reasons,
    })).unwrap())
}

/// {"verified": bool} - Ed25519 verification of a signed record.
/// # Safety
/// ptr/len must describe a valid UTF-8 buffer.
#[no_mangle]
pub unsafe extern "C" fn co_verify_record(ptr: *const u8, len: usize)
                                          -> *mut u8 {
    let record = match parse(ptr, len) {
        Some(o) => o,
        None => return out(err("invalid JSON object")),
    };
    let verified = crate::signing::verify_record(&record, None);
    out(format!("{{\"verified\":{}}}", verified))
}

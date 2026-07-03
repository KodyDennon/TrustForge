//! TrustForge core surface compiled to wasm32 for in-process TS/JS adapters.
//!
//! This crate re-exports the security-critical functions from `tf-types`
//! through a wasm-bindgen surface so TS adapters can run TrustForge
//! decisions in-process (no HTTP round-trip, no daemon required).
//!
//! Build with `crates/tf-core-wasm/build.sh` (requires `wasm-pack`) or
//! directly via `cargo build -p tf-core-wasm --target wasm32-unknown-unknown
//! --release`.

use serde_wasm_bindgen::{from_value, to_value};
use wasm_bindgen::prelude::*;

/// Canonicalize a JSON value to canonical-JSON bytes (UTF-8). Surfaces
/// `tf_types::canonicalize` to JS.
#[wasm_bindgen]
pub fn canonicalize(value: JsValue) -> Result<String, JsValue> {
    let v: serde_json::Value = from_value(value).map_err(|e| JsValue::from_str(&e.to_string()))?;
    tf_types::canonicalize(&v).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Verify a TrustForge packet. Returns `{ok: bool, reason: string | null}`.
#[wasm_bindgen]
pub fn verify_packet(
    packet: JsValue,
    public_key_b64: String,
    now: String,
) -> Result<JsValue, JsValue> {
    let pk_bytes: Vec<u8> = tf_types::encoding::STANDARD
        .decode(&public_key_b64)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    if pk_bytes.len() != 32 {
        return Err(JsValue::from_str("public_key must be 32 bytes"));
    }
    let pk: [u8; 32] = pk_bytes.try_into().unwrap();
    let p: tf_types::packet::Packet =
        from_value(packet).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let r = tf_types::packet::verify_packet(&p, &pk, &now);
    let out = serde_json::json!({"ok": r.ok, "reason": r.reason});
    to_value(&out).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Evaluate a policy with the native engine.
#[wasm_bindgen]
pub fn evaluate_policy(manifest_json: String, query: JsValue) -> Result<JsValue, JsValue> {
    let manifest: tf_types::policy_engine::PolicyManifest =
        serde_json::from_str(&manifest_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let q: tf_types::policy_engine::PolicyQuery =
        from_value(query).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let engine = tf_types::policy_engine::NativePolicyEngine::new(manifest);
    let decision = engine.evaluate(&q);
    to_value(&decision).map_err(|e| JsValue::from_str(&e.to_string()))
}

/// Verify an ed25519 signature. Returns `bool`.
#[wasm_bindgen]
pub fn ed25519_verify(public_key_b64: String, message: Vec<u8>, signature_b64: String) -> bool {
    let pk = match tf_types::encoding::STANDARD.decode(&public_key_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig = match tf_types::encoding::STANDARD.decode(&signature_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };
    tf_types::crypto::ed25519_verify(&pk, &message, &sig).is_ok()
}

/// Verify a session migration's signature + replay protection.
#[wasm_bindgen]
pub fn verify_session_migration(
    migration_json: String,
    public_key_b64: String,
    last_generation: u64,
) -> Result<JsValue, JsValue> {
    let migration: tf_types::session_migration::SessionMigration =
        serde_json::from_str(&migration_json).map_err(|e| JsValue::from_str(&e.to_string()))?;
    let pk_bytes = tf_types::encoding::STANDARD
        .decode(&public_key_b64)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    if pk_bytes.len() != 32 {
        return Err(JsValue::from_str("pk must be 32 bytes"));
    }
    let pk: [u8; 32] = pk_bytes.try_into().unwrap();
    let r = tf_types::session_migration::verify_session_migration(
        &migration,
        &pk,
        Some(last_generation),
        None,
    );
    let out = serde_json::json!({"ok": r.ok, "reason": r.reason});
    to_value(&out).map_err(|e| JsValue::from_str(&e.to_string()))
}

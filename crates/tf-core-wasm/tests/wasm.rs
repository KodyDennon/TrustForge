//! Smoke tests for the wasm-bindgen surface.
//!
//! These tests are wasm32-only: the `JsValue` / `serde-wasm-bindgen` surface
//! panics on non-wasm targets ("cannot call wasm-bindgen imported functions
//! on non-wasm targets"), so we gate the bodies behind `cfg(target_arch =
//! "wasm32")`. The cross-language byte-for-byte parity test against the TS
//! canonicalize lives in `tools/tf-types-ts/tests/wasm-core.test.ts`.
//!
//! Run with:
//!   wasm-pack test --node crates/tf-core-wasm
//!
//! On host, this file simply compiles to a no-op test crate, which is
//! sufficient to prove the wasm-bindgen surface type-checks.

#![cfg(target_arch = "wasm32")]

use serde_wasm_bindgen::to_value;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::wasm_bindgen_test;

use tf_core_wasm::{canonicalize, ed25519_verify, evaluate_policy, verify_packet};

fn jv(v: serde_json::Value) -> JsValue {
    to_value(&v).expect("to_value")
}

#[wasm_bindgen_test]
fn canonicalize_roundtrip() {
    let input = jv(serde_json::json!({"z": 1, "a": 2}));
    let out = canonicalize(input).expect("canonicalize");
    assert_eq!(out, "{\"a\":2,\"z\":1}");
}

#[wasm_bindgen_test]
fn verify_packet_returns_decision_object() {
    // Construct a packet that will be rejected (bad signature) — we only
    // need to confirm the surface returns the expected `{ok, reason}`
    // shape, not that crypto succeeds.
    let packet = serde_json::json!({
        "packet_version": "1",
        "source": "tf:actor:agent:example.com/a",
        "destination": "tf:actor:agent:example.com/b",
        "kind": "test",
        "priority": "P3",
        "created_at": "2026-04-25T00:00:00Z",
        "signature": {
            "signer": "tf:actor:agent:example.com/a",
            "algorithm": "ed25519",
            "signature": "AAAA"
        }
    });
    let pk = tf_types::encoding::STANDARD.encode([0u8; 32]);
    let res =
        verify_packet(jv(packet), pk, "2026-04-25T00:00:00Z".to_string()).expect("verify_packet");
    let v: serde_json::Value = serde_wasm_bindgen::from_value(res).expect("from_value");
    assert!(v.get("ok").is_some(), "missing ok field");
    assert!(v.get("reason").is_some(), "missing reason field");
}

#[wasm_bindgen_test]
fn ed25519_verify_returns_false_on_garbage() {
    let pk = tf_types::encoding::STANDARD.encode([0u8; 32]);
    let sig = tf_types::encoding::STANDARD.encode([0u8; 64]);
    let ok = ed25519_verify(pk, b"hello".to_vec(), sig);
    assert!(!ok);
}

#[wasm_bindgen_test]
fn evaluate_policy_returns_decision() {
    let manifest = serde_json::json!({
        "policy_version": "1",
        "trust_domain": "tf:trust-domain:example.com",
        "rules": [{
            "id": "default-deny",
            "effect": "deny",
            "action": "*"
        }]
    })
    .to_string();
    let query = jv(serde_json::json!({
        "subject": "tf:actor:agent:example.com/a",
        "action": "fs.read"
    }));
    let res = evaluate_policy(manifest, query).expect("evaluate_policy");
    let v: serde_json::Value = serde_wasm_bindgen::from_value(res).expect("from_value");
    assert!(v.get("decision").is_some(), "missing decision field");
}

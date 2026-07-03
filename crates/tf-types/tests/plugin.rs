//! Rust PluginRegistry tests (native kind).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tf_types::encoding::STANDARD as B64;
use rand::rngs::OsRng;
use serde_json::{json, Value};
use tempfile::tempdir;
use tf_types::canonical::canonicalize;
use tf_types::crypto::{b64encode, Ed25519Signer};
use tf_types::plugin::{NativeHandler, PluginError, PluginRegistry};

fn write_manifest(path: &std::path::Path, manifest: &Value) {
    std::fs::write(path, serde_yaml::to_string(manifest).unwrap()).unwrap();
}

fn sign_manifest(manifest: Value, priv_key: &[u8; 32]) -> Value {
    let mut unsigned = manifest.clone();
    unsigned["signature"]["signature"] = Value::String(String::new());
    let canonical = canonicalize(&unsigned).expect("canonical");
    let signer = Ed25519Signer::from_bytes(priv_key);
    let sig = signer.sign(canonical.as_bytes());
    let mut signed = manifest;
    signed["signature"]["signature"] = Value::String(b64encode(&sig));
    signed
}

fn fresh_keypair() -> ([u8; 32], [u8; 32]) {
    use rand::RngCore;
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let signer = Ed25519Signer::from_bytes(&seed);
    (seed, signer.public_key_bytes())
}

fn base_manifest(pub_key: &[u8; 32]) -> Value {
    json!({
        "plugin_version": "1",
        "plugin_id": "com.example.native-rust",
        "actor_id": "tf:actor:plugin:example.com/native-rust",
        "kind": "native",
        "entry": "./native.rs",
        "identity_pub": b64encode(pub_key),
        "signature": {
            "algorithm": "ed25519",
            "signer": "tf:actor:plugin:example.com/native-rust",
            "signature": ""
        },
        "capabilities": [
            { "name": "file.read", "risk": "R0" }
        ]
    })
}

#[test]
fn load_native_plugin_and_invoke_handler() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("manifest.yaml");
    let (priv_k, pub_k) = fresh_keypair();
    let signed = sign_manifest(base_manifest(&pub_k), &priv_k);
    write_manifest(&path, &signed);

    let calls = Arc::new(Mutex::new(0u32));
    let calls_for_handler = calls.clone();
    let handler: NativeHandler = Arc::new(move |req: &Value| {
        *calls_for_handler.lock().unwrap() += 1;
        let path = req
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("(none)")
            .to_string();
        Ok(json!({ "path": path, "contents": format!("hello {}", path) }))
    });

    let mut handlers = HashMap::new();
    handlers.insert("file.read".to_string(), handler);

    let mut registry = PluginRegistry::new();
    let loaded = registry.load_native(&path, handlers).unwrap();
    assert_eq!(loaded.plugin_id, "com.example.native-rust");
    assert_eq!(loaded.capabilities, vec!["file.read"]);

    let result = registry
        .invoke(
            "com.example.native-rust",
            "file.read",
            &json!({ "path": "README.md" }),
        )
        .unwrap();
    assert_eq!(result["contents"], json!("hello README.md"));
    assert_eq!(*calls.lock().unwrap(), 1);
}

#[test]
fn tampered_signature_rejected() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("manifest.yaml");
    let (priv_k, pub_k) = fresh_keypair();
    let mut signed = sign_manifest(base_manifest(&pub_k), &priv_k);
    // Tamper: flip a character in the signature.
    let sig_str = signed["signature"]["signature"]
        .as_str()
        .unwrap()
        .to_string();
    let mut bytes = B64.decode(&sig_str).unwrap();
    bytes[0] ^= 0xff;
    signed["signature"]["signature"] = Value::String(B64.encode(&bytes));
    write_manifest(&path, &signed);

    let mut registry = PluginRegistry::new();
    let err = registry.load_native(&path, HashMap::new()).unwrap_err();
    assert!(matches!(err, PluginError::BadSignature(_)));
}

#[test]
fn unknown_kind_rejected() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("manifest.yaml");
    let (priv_k, pub_k) = fresh_keypair();
    let mut base = base_manifest(&pub_k);
    base["kind"] = Value::String("wasm".to_string());
    let signed = sign_manifest(base, &priv_k);
    write_manifest(&path, &signed);

    let mut registry = PluginRegistry::new();
    let err = registry.load_native(&path, HashMap::new()).unwrap_err();
    assert!(matches!(err, PluginError::UnknownKind(_)));
}

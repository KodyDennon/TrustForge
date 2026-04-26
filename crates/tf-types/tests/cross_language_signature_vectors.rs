//! Rust mirror of the cross-language signature vectors. Both runtimes
//! must canonicalize the listed payload to identical bytes and produce
//! identical (deterministic ed25519) signatures.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde_yaml::Value as YamlValue;
use sha2::{Digest, Sha256};
use std::fs;
use tf_types::canonical::canonicalize;

#[derive(serde::Deserialize)]
struct Vector {
    name: String,
    private_key_hex: String,
    public_key_hex: String,
    payload: serde_json::Value,
    canonical: String,
}

#[derive(serde::Deserialize)]
struct File {
    vectors: Vec<Vector>,
}

fn from_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn cross_language_signature_vectors_round_trip() {
    let path = format!(
        "{}/../../conformance/cross-language-signature-vectors.yaml",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path, e));
    // Parse via serde_yaml::Value first because the YAML uses non-string
    // keys via the JSON-flow style.
    let _yaml_check: YamlValue = serde_yaml::from_str(&raw).expect("yaml parse");
    let file: File = serde_yaml::from_str(&raw).expect("vectors parse");

    for v in &file.vectors {
        // 1. Canonicalize MUST match the listed bytes.
        let actual = canonicalize(&v.payload).expect("canonicalize");
        assert_eq!(actual, v.canonical, "{}: canonical mismatch", v.name);

        // 2. Derived public key from priv MUST match listed.
        let priv_bytes: [u8; 32] = from_hex(&v.private_key_hex).try_into().expect("32 bytes");
        let signing = SigningKey::from_bytes(&priv_bytes);
        let pub_bytes = signing.verifying_key().to_bytes();
        let expected_pub: [u8; 32] = from_hex(&v.public_key_hex).try_into().expect("32 bytes");
        assert_eq!(pub_bytes, expected_pub, "{}: public key mismatch", v.name);

        // 3. Sign + verify the canonical bytes (ed25519 deterministic).
        let digest = Sha256::digest(actual.as_bytes());
        let sig = signing.sign(&digest);
        let verifier = VerifyingKey::from_bytes(&expected_pub).expect("verify-key");
        verifier
            .verify_strict(&digest, &sig)
            .unwrap_or_else(|e| panic!("{}: verify: {}", v.name, e));

        // 4. Tampered digest MUST fail.
        let bad_digest = Sha256::digest((actual.clone() + "x").as_bytes());
        assert!(
            verifier.verify_strict(&bad_digest, &sig).is_err(),
            "{}: tampered digest accepted",
            v.name
        );
    }
}

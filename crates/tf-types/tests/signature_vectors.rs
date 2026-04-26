//! Rust side of the signature/hash parity suite.

use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

use tf_types::crypto::{
    blake3_hashref, ed25519_verify, hex as hex_encode, sha256_hashref, Ed25519Signer,
};

#[derive(Deserialize)]
struct VectorsFile {
    ed25519: Vec<Ed25519Vector>,
    sha256: Vec<HashVector>,
    blake3: Vec<HashVector>,
}

#[derive(Deserialize)]
struct Ed25519Vector {
    name: String,
    private_key: String,
    public_key: Option<String>,
    message: String,
    signature: Option<String>,
}

#[derive(Deserialize)]
struct HashVector {
    name: String,
    input_hex: String,
    output: String,
}

fn load_vectors() -> VectorsFile {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("conformance")
        .join("signature-vectors.yaml");
    let raw =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    serde_yaml::from_str(&raw).expect("parse signature-vectors.yaml")
}

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn ed25519_derives_and_signs() {
    let vectors = load_vectors();
    for v in &vectors.ed25519 {
        let seed: [u8; 32] = from_hex(&v.private_key).try_into().expect("32 bytes");
        let signer = Ed25519Signer::from_bytes(&seed);

        if let Some(expected_pk) = &v.public_key {
            let derived = signer.public_key_bytes();
            assert_eq!(
                hex_encode(&derived),
                expected_pk.to_lowercase(),
                "{} public key",
                v.name
            );
        }

        let msg = from_hex(&v.message);
        let signature = signer.sign(&msg);
        if let Some(expected_sig) = &v.signature {
            assert_eq!(
                hex_encode(&signature),
                expected_sig.to_lowercase(),
                "{} signature",
                v.name
            );
        }
        let pk = signer.public_key_bytes();
        ed25519_verify(&pk, &msg, &signature)
            .unwrap_or_else(|e| panic!("{} verify: {}", v.name, e));
    }
}

#[test]
fn ed25519_rejects_tampered_message() {
    let vectors = load_vectors();
    let v = &vectors.ed25519[1];
    let seed: [u8; 32] = from_hex(&v.private_key).try_into().unwrap();
    let signer = Ed25519Signer::from_bytes(&seed);
    let sig = signer.sign(&from_hex(&v.message));
    let tampered: [u8; 1] = [0xff];
    assert!(ed25519_verify(&signer.public_key_bytes(), &tampered, &sig).is_err());
}

#[test]
fn sha256_vectors_match() {
    let vectors = load_vectors();
    for v in &vectors.sha256 {
        assert_eq!(
            sha256_hashref(&from_hex(&v.input_hex)),
            v.output,
            "{}",
            v.name
        );
    }
}

#[test]
fn blake3_vectors_match() {
    let vectors = load_vectors();
    for v in &vectors.blake3 {
        assert_eq!(
            blake3_hashref(&from_hex(&v.input_hex)),
            v.output,
            "{}",
            v.name
        );
    }
}

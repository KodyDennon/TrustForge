//! Rust side of the session-primitive parity suite.

use std::fs;
use std::path::PathBuf;

use serde::Deserialize;

use tf_types::crypto::{
    chacha20poly1305_decrypt, chacha20poly1305_encrypt, hex as hex_encode, hkdf_sha256,
    x25519_diffie_hellman, x25519_from_bytes,
};

#[derive(Deserialize)]
struct VectorsFile {
    x25519: Vec<X25519Vec>,
    hkdf_sha256: Vec<HkdfVec>,
    chacha20poly1305: Vec<AeadVec>,
}

#[derive(Deserialize)]
struct X25519Vec {
    name: String,
    private_key: String,
    peer_public: String,
    shared: String,
}

#[derive(Deserialize)]
struct HkdfVec {
    name: String,
    ikm: String,
    salt: String,
    info: String,
    length: usize,
    output: String,
}

#[derive(Deserialize)]
struct AeadVec {
    name: String,
    key: String,
    nonce: String,
    aad: String,
    plaintext: String,
    ciphertext_with_tag: String,
}

fn load_vectors() -> VectorsFile {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("conformance")
        .join("session-vectors.yaml");
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    serde_yaml::from_str(&raw).expect("parse session-vectors.yaml")
}

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn x25519_vectors() {
    for v in &load_vectors().x25519 {
        let priv_bytes: [u8; 32] = from_hex(&v.private_key).try_into().expect("32 bytes");
        let peer_bytes: [u8; 32] = from_hex(&v.peer_public).try_into().expect("32 bytes");
        let shared = x25519_diffie_hellman(&priv_bytes, &peer_bytes);
        assert_eq!(hex_encode(&shared), v.shared.to_lowercase(), "{}", v.name);
    }
}

#[test]
fn x25519_dh_is_symmetric() {
    let a = x25519_from_bytes(&[1u8; 32]);
    let b = x25519_from_bytes(&[2u8; 32]);
    let ab = x25519_diffie_hellman(&a.private, &b.public);
    let ba = x25519_diffie_hellman(&b.private, &a.public);
    assert_eq!(hex_encode(&ab), hex_encode(&ba));
}

#[test]
fn hkdf_vectors() {
    for v in &load_vectors().hkdf_sha256 {
        let out = hkdf_sha256(&from_hex(&v.ikm), &from_hex(&v.salt), &from_hex(&v.info), v.length);
        assert_eq!(hex_encode(&out), v.output.to_lowercase(), "{}", v.name);
    }
}

#[test]
fn aead_vectors() {
    for v in &load_vectors().chacha20poly1305 {
        let key: [u8; 32] = from_hex(&v.key).try_into().unwrap();
        let nonce: [u8; 12] = from_hex(&v.nonce).try_into().unwrap();
        let aad = from_hex(&v.aad);
        let plaintext = from_hex(&v.plaintext);
        let ct = chacha20poly1305_encrypt(&key, &nonce, &aad, &plaintext);
        assert_eq!(hex_encode(&ct), v.ciphertext_with_tag.to_lowercase(), "{} encrypt", v.name);
        let pt = chacha20poly1305_decrypt(&key, &nonce, &aad, &from_hex(&v.ciphertext_with_tag))
            .unwrap_or_else(|e| panic!("{}: {}", v.name, e));
        assert_eq!(hex_encode(&pt), v.plaintext.to_lowercase(), "{} decrypt", v.name);
    }
}

#[test]
fn aead_rejects_tampered_ciphertext() {
    let vectors = load_vectors();
    let v = &vectors.chacha20poly1305[0];
    let key: [u8; 32] = from_hex(&v.key).try_into().unwrap();
    let nonce: [u8; 12] = from_hex(&v.nonce).try_into().unwrap();
    let aad = from_hex(&v.aad);
    let mut ct = from_hex(&v.ciphertext_with_tag);
    ct[0] ^= 0xff;
    assert!(chacha20poly1305_decrypt(&key, &nonce, &aad, &ct).is_err());
}

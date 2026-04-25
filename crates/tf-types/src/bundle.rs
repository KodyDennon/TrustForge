//! Encrypted .tfbundle (L4/L5) sealing + transparency anchoring — Rust
//! mirror of `tools/tf-types-ts/src/core/bundle.ts`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

use crate::canonicalize;

const HKDF_INFO: &[u8] = b"tfbundle/wrap";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EncryptedProofBundle {
    pub bundle_version: String,
    pub level: String,
    pub ciphertext: String,
    pub nonce: String,
    pub wrapped_keys: Vec<WrappedKey>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub transparency_anchor: Option<Value>,
    pub signature: SignatureEnvelope,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WrappedKey {
    pub recipient: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub recipient_key_id: Option<String>,
    pub ephemeral_public: String,
    pub wrapped: String,
    pub wrap_nonce: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureEnvelope {
    pub algorithm: String,
    pub signer: String,
    pub signature: String,
}

#[derive(Clone, Debug)]
pub struct BundleRecipient {
    pub actor: String,
    pub kem_public: [u8; 32],
    pub key_id: Option<String>,
}

pub fn seal_bundle(
    bundle: &Value,
    recipients: &[BundleRecipient],
    level: &str,
    signer_priv: &[u8; 32],
    signer: &str,
) -> EncryptedProofBundle {
    let mut rng = rand::thread_rng();
    let mut data_key = [0u8; 32];
    rng.fill_bytes(&mut data_key);
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let cipher = ChaCha20Poly1305::new(&data_key.into());
    let plaintext = canonicalize(bundle).unwrap_or_default();
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_bytes())
        .expect("seal");

    let mut wrapped_keys = Vec::with_capacity(recipients.len());
    for r in recipients {
        let mut eph_seed = [0u8; 32];
        rng.fill_bytes(&mut eph_seed);
        let eph = X25519Secret::from(eph_seed);
        let eph_pub = X25519Public::from(&eph);
        let recipient_pub = X25519Public::from(r.kem_public);
        let shared = eph.diffie_hellman(&recipient_pub);
        let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
        let mut wrap_key = [0u8; 32];
        hk.expand(HKDF_INFO, &mut wrap_key).expect("hkdf");
        let mut wrap_nonce = [0u8; 12];
        rng.fill_bytes(&mut wrap_nonce);
        let wrap_cipher = ChaCha20Poly1305::new(&wrap_key.into());
        let wrapped = wrap_cipher
            .encrypt(Nonce::from_slice(&wrap_nonce), data_key.as_ref())
            .expect("wrap");
        wrapped_keys.push(WrappedKey {
            recipient: r.actor.clone(),
            recipient_key_id: r.key_id.clone(),
            ephemeral_public: STANDARD.encode(eph_pub.as_bytes()),
            wrapped: STANDARD.encode(&wrapped),
            wrap_nonce: STANDARD.encode(wrap_nonce),
        });
    }

    let mut stub = EncryptedProofBundle {
        bundle_version: "1".into(),
        level: level.into(),
        ciphertext: STANDARD.encode(&ciphertext),
        nonce: STANDARD.encode(nonce_bytes),
        wrapped_keys,
        transparency_anchor: None,
        signature: SignatureEnvelope {
            algorithm: "ed25519".into(),
            signer: signer.into(),
            signature: String::new(),
        },
    };
    let digest = encrypted_signing_bytes(&stub);
    let signing = SigningKey::from_bytes(signer_priv);
    let sig: Signature = signing.sign(&digest);
    stub.signature.signature = STANDARD.encode(sig.to_bytes());
    stub
}

pub fn open_bundle(
    enc: &EncryptedProofBundle,
    recipient_priv: &[u8; 32],
    recipient_actor: &str,
    signer_pub: Option<&[u8; 32]>,
) -> Result<Value, String> {
    let wrap = enc
        .wrapped_keys
        .iter()
        .find(|w| w.recipient == recipient_actor)
        .ok_or_else(|| format!("no wrapped key for recipient {}", recipient_actor))?;
    let eph_pub_bytes = STANDARD
        .decode(&wrap.ephemeral_public)
        .map_err(|e| format!("ephemeral_public base64: {}", e))?;
    let mut eph_pub_arr = [0u8; 32];
    if eph_pub_bytes.len() != 32 {
        return Err("ephemeral_public not 32 bytes".into());
    }
    eph_pub_arr.copy_from_slice(&eph_pub_bytes);
    let recipient_secret = X25519Secret::from(*recipient_priv);
    let shared = recipient_secret.diffie_hellman(&X25519Public::from(eph_pub_arr));
    let hk = Hkdf::<Sha256>::new(None, shared.as_bytes());
    let mut wrap_key = [0u8; 32];
    hk.expand(HKDF_INFO, &mut wrap_key).map_err(|e| e.to_string())?;
    let wrapped = STANDARD
        .decode(&wrap.wrapped)
        .map_err(|e| format!("wrapped base64: {}", e))?;
    let wrap_nonce = STANDARD
        .decode(&wrap.wrap_nonce)
        .map_err(|e| format!("wrap_nonce base64: {}", e))?;
    let data_key_bytes = ChaCha20Poly1305::new(&wrap_key.into())
        .decrypt(Nonce::from_slice(&wrap_nonce), wrapped.as_ref())
        .map_err(|e| format!("unwrap: {}", e))?;
    let ciphertext = STANDARD
        .decode(&enc.ciphertext)
        .map_err(|e| format!("ciphertext base64: {}", e))?;
    let nonce = STANDARD
        .decode(&enc.nonce)
        .map_err(|e| format!("nonce base64: {}", e))?;
    let mut data_key_arr = [0u8; 32];
    if data_key_bytes.len() != 32 {
        return Err("data_key not 32 bytes".into());
    }
    data_key_arr.copy_from_slice(&data_key_bytes);
    let plaintext = ChaCha20Poly1305::new(&data_key_arr.into())
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|e| format!("decrypt: {}", e))?;

    if let Some(pk) = signer_pub {
        let digest = encrypted_signing_bytes(enc);
        let sig_bytes = STANDARD
            .decode(&enc.signature.signature)
            .map_err(|e| format!("signature base64: {}", e))?;
        let sig = Signature::from_slice(&sig_bytes).map_err(|e| format!("sig parse: {}", e))?;
        let vk = VerifyingKey::from_bytes(pk).map_err(|e| format!("verifying key: {}", e))?;
        if vk.verify(&digest, &sig).is_err() {
            return Err("encrypted bundle signature did not verify".into());
        }
    }

    let json: Value = serde_json::from_slice(&plaintext).map_err(|e| e.to_string())?;
    Ok(json)
}

pub fn encrypted_signing_bytes(enc: &EncryptedProofBundle) -> [u8; 32] {
    let mut value = serde_json::to_value(enc).unwrap_or(Value::Null);
    if let Value::Object(map) = &mut value {
        map.remove("signature");
    }
    let canonical = canonicalize(&value).unwrap_or_default();
    Sha256::digest(canonical.as_bytes()).into()
}

/// Build the DER-encoded TimeStampReq for SHA-256 over `data` (RFC 3161 §2.4.1).
pub fn build_rfc3161_request(data: &[u8]) -> Vec<u8> {
    let digest: [u8; 32] = Sha256::digest(data).into();
    let oid_sha256: [u8; 11] = [
        0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    ];
    let alg_id = der_sequence(&[oid_sha256.to_vec(), vec![0x05, 0x00]]);
    let hashed_message = der_octet_string(&digest);
    let message_imprint = der_sequence(&[alg_id, hashed_message]);
    let version = der_integer(&[0x01]);
    let cert_req = vec![0x01, 0x01, 0xff];
    der_sequence(&[version, message_imprint, cert_req])
}

fn der_sequence(parts: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = parts.iter().flat_map(|p| p.clone()).collect();
    let mut out = Vec::with_capacity(2 + body.len());
    out.push(0x30);
    out.extend_from_slice(&der_len(body.len()));
    out.extend_from_slice(&body);
    out
}

fn der_octet_string(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + bytes.len());
    out.push(0x04);
    out.extend_from_slice(&der_len(bytes.len()));
    out.extend_from_slice(bytes);
    out
}

fn der_integer(bytes: &[u8]) -> Vec<u8> {
    let mut start = 0usize;
    while start < bytes.len() - 1 && bytes[start] == 0 {
        start += 1;
    }
    let payload = &bytes[start..];
    let needs_pad = payload[0] & 0x80 != 0;
    let len = payload.len() + if needs_pad { 1 } else { 0 };
    let mut out = Vec::with_capacity(2 + len);
    out.push(0x02);
    out.extend_from_slice(&der_len(len));
    if needs_pad {
        out.push(0x00);
    }
    out.extend_from_slice(payload);
    out
}

fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let mut bytes = Vec::new();
    let mut v = n;
    while v > 0 {
        bytes.insert(0, (v & 0xff) as u8);
        v >>= 8;
    }
    let mut out = Vec::with_capacity(1 + bytes.len());
    out.push(0x80 | bytes.len() as u8);
    out.extend_from_slice(&bytes);
    out
}

/// In-memory transparency anchor for tests.
#[derive(Default)]
pub struct MemoryAnchor {
    entries: std::sync::Mutex<std::collections::HashMap<String, usize>>,
}

impl MemoryAnchor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn submit(&self, bundle_bytes: &[u8]) -> Value {
        let digest = Sha256::digest(bundle_bytes);
        let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
        let mut entries = self.entries.lock().unwrap();
        let seq = entries.len();
        entries.insert(hex.clone(), seq);
        serde_json::json!({ "kind": "memory", "digest": hex, "sequence_number": seq })
    }

    pub fn verify_inclusion(&self, bundle_bytes: &[u8], inclusion_proof: &Value) -> bool {
        let digest = Sha256::digest(bundle_bytes);
        let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
        if inclusion_proof.get("digest").and_then(|v| v.as_str()) != Some(&hex) {
            return false;
        }
        let seq = inclusion_proof
            .get("sequence_number")
            .and_then(|v| v.as_u64())
            .map(|n| n as usize);
        let entries = self.entries.lock().unwrap();
        seq == entries.get(&hex).copied()
    }
}

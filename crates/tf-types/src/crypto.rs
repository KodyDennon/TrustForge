//! Crypto primitives — thin wrappers over reviewed crates.
//!
//! Supported:
//!   - ed25519 signing / verifying (via `ed25519-dalek`).
//!   - SHA-256 and BLAKE3 hashing.
//!
//! Post-quantum ML-DSA is a Phase 3+ addition and is reserved in the
//! `SignatureEnvelope` schema today. No custom crypto is introduced in
//! this module — everything is a thin adapter.

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("invalid ed25519 private key: expected 32 raw bytes, got {0}")]
    PrivateKeyLength(usize),
    #[error("invalid ed25519 public key: expected 32 raw bytes, got {0}")]
    PublicKeyLength(usize),
    #[error("invalid ed25519 signature: expected 64 raw bytes, got {0}")]
    SignatureLength(usize),
    #[error("signature verification failed")]
    BadSignature,
    #[error("invalid public key encoding")]
    BadPublicKey,
    #[error("invalid base64: {0}")]
    BadBase64(String),
    #[error("unknown algorithm: {0}")]
    UnknownAlgorithm(String),
    #[error("{0}")]
    Generic(String),
}

/// ED25519 signing key.
pub struct Ed25519Signer {
    inner: SigningKey,
}

impl Ed25519Signer {
    pub fn from_bytes(seed: &[u8; 32]) -> Self {
        Ed25519Signer {
            inner: SigningKey::from_bytes(seed),
        }
    }

    pub fn generate<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> Self {
        Ed25519Signer {
            inner: SigningKey::generate(rng),
        }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.inner.verifying_key().to_bytes()
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.inner.sign(msg).to_bytes()
    }
}

/// Verify an ed25519 signature.
pub fn ed25519_verify(public_key: &[u8], msg: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    let pk_bytes: &[u8; 32] = public_key
        .try_into()
        .map_err(|_| CryptoError::PublicKeyLength(public_key.len()))?;
    let sig_bytes: &[u8; 64] = signature
        .try_into()
        .map_err(|_| CryptoError::SignatureLength(signature.len()))?;
    let vk = VerifyingKey::from_bytes(pk_bytes).map_err(|_| CryptoError::BadPublicKey)?;
    let sig = Signature::from_bytes(sig_bytes);
    vk.verify(msg, &sig).map_err(|_| CryptoError::BadSignature)
}

/// SHA-256 of the input, returned as `"sha256:<hex>"`.
pub fn sha256_hashref(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{}", hex(&digest))
}

/// BLAKE3 of the input, returned as `"blake3:<hex>"`.
pub fn blake3_hashref(bytes: &[u8]) -> String {
    let digest = blake3::hash(bytes);
    format!("blake3:{}", hex(digest.as_bytes()))
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// Parse `sha256:<hex>` back into raw bytes.
pub fn parse_hashref(s: &str) -> Result<(String, Vec<u8>), CryptoError> {
    let (algo, hex_part) = s
        .split_once(':')
        .ok_or_else(|| CryptoError::UnknownAlgorithm(s.to_owned()))?;
    let mut out = Vec::with_capacity(hex_part.len() / 2);
    let bytes = hex_part.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 >= bytes.len() {
            return Err(CryptoError::BadBase64("odd hex length".into()));
        }
        let hi = from_hex(bytes[i]).ok_or_else(|| CryptoError::BadBase64("non-hex char".into()))?;
        let lo = from_hex(bytes[i + 1]).ok_or_else(|| CryptoError::BadBase64("non-hex char".into()))?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok((algo.to_owned(), out))
}

fn from_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Base64 encode / decode helpers for signature payloads.
pub fn b64encode(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

pub fn b64decode(s: &str) -> Result<Vec<u8>, CryptoError> {
    B64.decode(s.as_bytes())
        .map_err(|e| CryptoError::BadBase64(e.to_string()))
}

// ---------- X25519 ----------

pub struct X25519KeyPair {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

pub fn x25519_generate<R: rand::RngCore + rand::CryptoRng>(rng: &mut R) -> X25519KeyPair {
    let secret = x25519_dalek::StaticSecret::random_from_rng(rng);
    let public = x25519_dalek::PublicKey::from(&secret);
    X25519KeyPair {
        private: secret.to_bytes(),
        public: public.to_bytes(),
    }
}

pub fn x25519_from_bytes(seed: &[u8; 32]) -> X25519KeyPair {
    let secret = x25519_dalek::StaticSecret::from(*seed);
    let public = x25519_dalek::PublicKey::from(&secret);
    X25519KeyPair {
        private: secret.to_bytes(),
        public: public.to_bytes(),
    }
}

pub fn x25519_diffie_hellman(private: &[u8; 32], peer_public: &[u8; 32]) -> [u8; 32] {
    let secret = x25519_dalek::StaticSecret::from(*private);
    let peer = x25519_dalek::PublicKey::from(*peer_public);
    secret.diffie_hellman(&peer).to_bytes()
}

// ---------- HKDF-SHA256 ----------

pub fn hkdf_sha256(input_key: &[u8], salt: &[u8], info: &[u8], output_len: usize) -> Vec<u8> {
    let hk = hkdf::Hkdf::<Sha256>::new(Some(salt), input_key);
    let mut out = vec![0u8; output_len];
    hk.expand(info, &mut out).expect("output_len <= 255*32");
    out
}

// ---------- ChaCha20-Poly1305-IETF ----------

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AeadError {
    #[error("aead key must be 32 bytes")]
    BadKey,
    #[error("aead nonce must be 12 bytes")]
    BadNonce,
    #[error("aead authentication failed")]
    AuthFailed,
}

pub fn chacha20poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Vec<u8> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::ChaCha20Poly1305;
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
    cipher
        .encrypt(
            chacha20poly1305::Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("encrypt")
}

pub fn chacha20poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::ChaCha20Poly1305;
    let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| AeadError::BadKey)?;
    cipher
        .decrypt(
            chacha20poly1305::Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| AeadError::AuthFailed)
}

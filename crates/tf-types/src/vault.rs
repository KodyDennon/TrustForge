//! File-backed passphrase vault. Mirrors
//! `tools/tf-types-ts/src/core/vault.ts`.
//!
//! On-disk layout is schemas/vault-file.schema.json. Wrap key = Argon2id
//! over the passphrase; each entry is sealed with ChaCha20-Poly1305 using
//! AAD = JSON([id, purpose, algorithm]).

use std::fs;
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json;

use crate::crypto::{chacha20poly1305_decrypt, chacha20poly1305_encrypt};

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("vault I/O error: {0}")]
    Io(String),
    #[error("vault parse error: {0}")]
    Parse(String),
    #[error("unsupported vault version: {0}")]
    UnsupportedVersion(String),
    #[error("unsupported vault algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("argon2 derivation failed: {0}")]
    Argon2(String),
    #[error("vault entry not found: {0}")]
    EntryNotFound(String),
    #[error("base64 decode failed: {0}")]
    Base64(String),
    #[error("aead decrypt failed")]
    Aead,
    #[error("invalid nonce length")]
    BadNonce,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct OnDiskEntry {
    id: String,
    purpose: String,
    algorithm: String,
    nonce: String,
    ciphertext: String,
    created_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct OnDiskKdf {
    algorithm: String,
    salt: String,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct OnDiskCipher {
    algorithm: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct OnDiskVault {
    vault_version: String,
    kdf: OnDiskKdf,
    cipher: OnDiskCipher,
    entries: Vec<OnDiskEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultEntryPlain {
    pub id: String,
    pub purpose: String,
    pub algorithm: String,
    pub key_bytes: Vec<u8>,
    pub created_at: String,
}

#[derive(Clone, Debug)]
pub struct VaultEntrySummary {
    pub id: String,
    pub purpose: String,
    pub algorithm: String,
    pub created_at: String,
}

#[derive(Clone, Debug)]
pub struct VaultCreateOptions {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt: Option<[u8; 16]>,
}

impl Default for VaultCreateOptions {
    fn default() -> Self {
        VaultCreateOptions {
            m_cost: 19456,
            t_cost: 2,
            p_cost: 1,
            salt: None,
        }
    }
}

pub struct Vault {
    path: PathBuf,
    wrap_key: [u8; 32],
    data: OnDiskVault,
}

impl Vault {
    pub fn create_at_path(
        path: &Path,
        passphrase: &str,
        opts: &VaultCreateOptions,
    ) -> Result<Self, VaultError> {
        let mut salt = [0u8; 16];
        match opts.salt {
            Some(s) => salt = s,
            None => rand::thread_rng().fill_bytes(&mut salt),
        }
        let wrap_key = derive_key(passphrase.as_bytes(), &salt, opts.m_cost, opts.t_cost, opts.p_cost)?;
        let data = OnDiskVault {
            vault_version: "1".to_string(),
            kdf: OnDiskKdf {
                algorithm: "argon2id".to_string(),
                salt: B64.encode(salt),
                m_cost: opts.m_cost,
                t_cost: opts.t_cost,
                p_cost: opts.p_cost,
            },
            cipher: OnDiskCipher {
                algorithm: "chacha20poly1305".to_string(),
            },
            entries: Vec::new(),
        };
        persist(path, &data)?;
        Ok(Vault {
            path: path.to_path_buf(),
            wrap_key,
            data,
        })
    }

    pub fn open_at_path(path: &Path, passphrase: &str) -> Result<Self, VaultError> {
        let raw = fs::read_to_string(path).map_err(|e| VaultError::Io(e.to_string()))?;
        let data: OnDiskVault = serde_json::from_str(&raw).map_err(|e| VaultError::Parse(e.to_string()))?;
        if data.vault_version != "1" {
            return Err(VaultError::UnsupportedVersion(data.vault_version));
        }
        if data.kdf.algorithm != "argon2id" || data.cipher.algorithm != "chacha20poly1305" {
            return Err(VaultError::UnsupportedAlgorithm(format!(
                "kdf={}, cipher={}",
                data.kdf.algorithm, data.cipher.algorithm
            )));
        }
        let salt_bytes = B64
            .decode(&data.kdf.salt)
            .map_err(|e| VaultError::Base64(e.to_string()))?;
        let mut salt = [0u8; 16];
        if salt_bytes.len() < 8 {
            return Err(VaultError::Parse(format!(
                "salt too short: {} bytes",
                salt_bytes.len()
            )));
        }
        let copy_len = salt_bytes.len().min(16);
        salt[..copy_len].copy_from_slice(&salt_bytes[..copy_len]);
        let wrap_key = derive_key(
            passphrase.as_bytes(),
            &salt_bytes,
            data.kdf.m_cost,
            data.kdf.t_cost,
            data.kdf.p_cost,
        )?;
        Ok(Vault {
            path: path.to_path_buf(),
            wrap_key,
            data,
        })
    }

    pub fn list(&self) -> Vec<VaultEntrySummary> {
        self.data
            .entries
            .iter()
            .map(|e| VaultEntrySummary {
                id: e.id.clone(),
                purpose: e.purpose.clone(),
                algorithm: e.algorithm.clone(),
                created_at: e.created_at.clone(),
            })
            .collect()
    }

    pub fn store(&mut self, entry: VaultEntryPlain) -> Result<(), VaultError> {
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let aad = aad_for(&entry.id, &entry.purpose, &entry.algorithm);
        let ciphertext = chacha20poly1305_encrypt(&self.wrap_key, &nonce, &aad, &entry.key_bytes);
        let disk_entry = OnDiskEntry {
            id: entry.id.clone(),
            purpose: entry.purpose.clone(),
            algorithm: entry.algorithm.clone(),
            nonce: B64.encode(nonce),
            ciphertext: B64.encode(&ciphertext),
            created_at: entry.created_at.clone(),
        };
        if let Some(existing) = self.data.entries.iter_mut().find(|e| e.id == entry.id) {
            *existing = disk_entry;
        } else {
            self.data.entries.push(disk_entry);
        }
        persist(&self.path, &self.data)?;
        Ok(())
    }

    pub fn read(&self, id: &str) -> Result<VaultEntryPlain, VaultError> {
        let entry = self
            .data
            .entries
            .iter()
            .find(|e| e.id == id)
            .ok_or_else(|| VaultError::EntryNotFound(id.to_string()))?;
        let nonce_bytes = B64
            .decode(&entry.nonce)
            .map_err(|e| VaultError::Base64(e.to_string()))?;
        if nonce_bytes.len() != 12 {
            return Err(VaultError::BadNonce);
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_bytes);
        let ct = B64
            .decode(&entry.ciphertext)
            .map_err(|e| VaultError::Base64(e.to_string()))?;
        let aad = aad_for(&entry.id, &entry.purpose, &entry.algorithm);
        let plaintext = chacha20poly1305_decrypt(&self.wrap_key, &nonce, &aad, &ct)
            .map_err(|_| VaultError::Aead)?;
        Ok(VaultEntryPlain {
            id: entry.id.clone(),
            purpose: entry.purpose.clone(),
            algorithm: entry.algorithm.clone(),
            key_bytes: plaintext,
            created_at: entry.created_at.clone(),
        })
    }

    pub fn remove(&mut self, id: &str) -> Result<bool, VaultError> {
        let before = self.data.entries.len();
        self.data.entries.retain(|e| e.id != id);
        let changed = self.data.entries.len() != before;
        if changed {
            persist(&self.path, &self.data)?;
        }
        Ok(changed)
    }
}

fn aad_for(id: &str, purpose: &str, algorithm: &str) -> Vec<u8> {
    serde_json::to_vec(&(id, purpose, algorithm)).expect("serialize aad triple")
}

fn derive_key(
    password: &[u8],
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<[u8; 32], VaultError> {
    let params =
        Params::new(m_cost, t_cost, p_cost, Some(32)).map_err(|e| VaultError::Argon2(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(|e| VaultError::Argon2(e.to_string()))?;
    Ok(out)
}

fn persist(path: &Path, data: &OnDiskVault) -> Result<(), VaultError> {
    let text = serde_json::to_string_pretty(data).map_err(|e| VaultError::Parse(e.to_string()))?;
    let final_text = format!("{}\n", text);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| VaultError::Io(e.to_string()))?;
        use std::io::Write;
        file.write_all(final_text.as_bytes())
            .map_err(|e| VaultError::Io(e.to_string()))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, final_text).map_err(|e| VaultError::Io(e.to_string()))?;
    }
    Ok(())
}

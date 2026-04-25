//! Rust Vault tests + cross-language parity.
//!
//! A parity test here writes a vault on the Rust side with fixed parameters,
//! then spawns `bun` to open it via a tiny TS helper script that reads a
//! known entry and prints it. A matching script does the reverse direction
//! (TS writes, Rust reads). If the argon2id + chacha20poly1305 byte
//! behaviour diverges, either side fails to decrypt.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use tempfile::tempdir;
use tf_types::vault::{Vault, VaultCreateOptions, VaultEntryPlain};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

const FAST: VaultCreateOptions = VaultCreateOptions {
    m_cost: 256,
    t_cost: 1,
    p_cost: 1,
    salt: Some(*b"0123456789abcdef"),
};

#[test]
fn create_store_read_remove() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.json");
    let mut vault = Vault::create_at_path(&path, "correct horse battery staple", &FAST).unwrap();
    let secret: Vec<u8> = (0..32u8).collect();
    vault
        .store(VaultEntryPlain {
            id: "agent-sign".into(),
            purpose: "signing".into(),
            algorithm: "ed25519".into(),
            key_bytes: secret.clone(),
            created_at: "2026-04-24T12:00:00Z".into(),
        })
        .unwrap();

    let read = vault.read("agent-sign").unwrap();
    assert_eq!(read.key_bytes, secret);
    assert_eq!(vault.list().len(), 1);
    assert!(vault.remove("agent-sign").unwrap());
    assert!(vault.list().is_empty());
}

#[test]
fn open_with_wrong_passphrase_fails() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.json");
    let mut vault = Vault::create_at_path(&path, "secret-one", &FAST).unwrap();
    vault
        .store(VaultEntryPlain {
            id: "k".into(),
            purpose: "signing".into(),
            algorithm: "ed25519".into(),
            key_bytes: vec![1, 2, 3],
            created_at: "2026-04-24T12:00:00Z".into(),
        })
        .unwrap();

    let reopened = Vault::open_at_path(&path, "secret-one").unwrap();
    assert_eq!(reopened.read("k").unwrap().key_bytes, vec![1, 2, 3]);

    let wrong = Vault::open_at_path(&path, "secret-two").unwrap();
    assert!(wrong.read("k").is_err());
}

#[test]
fn update_rewrites_entry_in_place() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.json");
    let mut vault = Vault::create_at_path(&path, "pw", &FAST).unwrap();
    vault
        .store(VaultEntryPlain {
            id: "k".into(),
            purpose: "signing".into(),
            algorithm: "ed25519".into(),
            key_bytes: vec![1, 1, 1],
            created_at: "2026-04-24T12:00:00Z".into(),
        })
        .unwrap();
    vault
        .store(VaultEntryPlain {
            id: "k".into(),
            purpose: "signing".into(),
            algorithm: "ed25519".into(),
            key_bytes: vec![9, 9, 9],
            created_at: "2026-04-24T12:00:00Z".into(),
        })
        .unwrap();
    assert_eq!(vault.list().len(), 1);
    assert_eq!(vault.read("k").unwrap().key_bytes, vec![9, 9, 9]);
}

/// Cross-language parity: Rust creates a vault, TS reads the entry.
/// Skipped gracefully if `bun` is not on PATH (so the test works both in
/// local dev and in CI).
#[test]
fn rust_written_vault_opens_in_ts() {
    if which::which("bun").is_err() {
        eprintln!("skip: bun not on PATH");
        return;
    }

    let dir = tempdir().unwrap();
    let path = dir.path().join("vault.json");
    let mut vault = Vault::create_at_path(&path, "parity-pw", &FAST).unwrap();
    let secret: Vec<u8> = (10..42u8).collect();
    vault
        .store(VaultEntryPlain {
            id: "parity-key".into(),
            purpose: "signing".into(),
            algorithm: "ed25519".into(),
            key_bytes: secret.clone(),
            created_at: "2026-04-24T12:00:00Z".into(),
        })
        .unwrap();

    let script = repo_root()
        .join("crates/tf-types/tests/vault-parity-reader.ts")
        .to_string_lossy()
        .to_string();
    let output = Command::new("bun")
        .arg("run")
        .arg(&script)
        .arg(path.to_string_lossy().to_string())
        .arg("parity-pw")
        .arg("parity-key")
        .output()
        .expect("spawn bun");
    assert!(
        output.status.success(),
        "bun failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // The helper prints the hex of the decrypted key bytes on one line.
    let expected: String = secret.iter().map(|b| format!("{:02x}", b)).collect();
    assert!(
        stdout.trim().contains(&expected),
        "expected hex {} not in: {}",
        expected,
        stdout
    );
    let _ = fs::remove_file(&path);
}

//! B7 vault tests — Rust mirror of TS b7-vault.test.ts.

use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;
use tf_types::vault::{Vault, VaultCreateOptions};

fn opts() -> VaultCreateOptions {
    VaultCreateOptions {
        m_cost: 256,
        t_cost: 1,
        p_cost: 1,
        salt: None,
    }
}

#[test]
fn create_at_path_refuses_to_overwrite_existing_file() {
    let dir = TempDir::new().unwrap();
    let path: PathBuf = dir.path().join("vault.json");
    fs::write(&path, b"preexisting").unwrap();
    let res = Vault::create_at_path(&path, "pw", &opts());
    assert!(res.is_err(), "create_at_path should refuse existing file");
    assert_eq!(fs::read_to_string(&path).unwrap(), "preexisting");
}

#[test]
fn create_at_path_succeeds_when_no_file_present() {
    let dir = TempDir::new().unwrap();
    let path: PathBuf = dir.path().join("vault.json");
    let v = Vault::create_at_path(&path, "pw", &opts()).expect("create");
    assert!(path.exists());
    assert_eq!(v.list().len(), 0);
}

#[test]
fn vault_canonical_aad_round_trip_with_non_ascii_id() {
    let dir = TempDir::new().unwrap();
    let path: PathBuf = dir.path().join("vault.json");
    let mut v = Vault::create_at_path(&path, "pw", &opts()).expect("create");
    let bytes = vec![0xa5u8; 32];
    v.store(tf_types::vault::VaultEntryPlain {
        id: "署名鍵".to_string(),
        purpose: "signing".to_string(),
        algorithm: "ed25519".to_string(),
        key_bytes: bytes.clone(),
        created_at: String::new(),
    })
    .expect("store");
    drop(v);
    let v2 = Vault::open_at_path(&path, "pw").expect("reopen");
    let got = v2.read("署名鍵").expect("read");
    assert_eq!(got.key_bytes, bytes);
}

#[test]
fn persist_leaves_no_temp_file_behind() {
    let dir = TempDir::new().unwrap();
    let path: PathBuf = dir.path().join("vault.json");
    let mut v = Vault::create_at_path(&path, "pw", &opts()).expect("create");
    for i in 0..5u8 {
        let bytes = vec![i; 32];
        v.store(tf_types::vault::VaultEntryPlain {
            id: format!("k{}", i),
            purpose: "signing".to_string(),
            algorithm: "ed25519".to_string(),
            key_bytes: bytes,
            created_at: String::new(),
        })
        .expect("store");
    }
    let leftover: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_str()
                .map(|n| n.contains(".tmp."))
                .unwrap_or(false)
        })
        .collect();
    assert!(
        leftover.is_empty(),
        "no leftover temp files: {:?}",
        leftover
    );
}

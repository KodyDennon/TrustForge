use std::sync::Arc;
use std::thread;

use serde_json::json;
use tf_store_file::{FileEvidenceArchive, FileProofLedger, FileRevocationCache, FileStore};
use tf_types::store::{EvidenceArchive, ProofLedger, RevocationCache};

fn fresh_dir(name: &str) -> std::path::PathBuf {
    let unique = format!(
        "trustforge-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let path = std::env::temp_dir().join(unique);
    std::fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn proof_ledger_roundtrip_and_reopen() {
    let path = fresh_dir("file-ledger");
    let ledger = FileProofLedger::open(&path).expect("open ledger");

    let event_a = json!({"kind": "approval", "id": "a", "n": 1});
    let event_b = json!({"kind": "approval", "id": "b", "n": 2});

    let h_a = ledger.append(&event_a).expect("append a");
    let h_b = ledger.append(&event_b).expect("append b");
    assert_ne!(h_a, h_b);
    assert!(h_a.starts_with("sha256:"));
    assert_eq!(ledger.lookup(&h_a).unwrap(), Some(event_a.clone()));

    let h_a2 = ledger.append(&event_a).expect("append duplicate");
    assert_eq!(h_a, h_a2);
    assert_eq!(
        ledger.tail(10).unwrap(),
        vec![event_a.clone(), event_b.clone()]
    );

    let reopened = FileProofLedger::open(&path).expect("reopen ledger");
    assert_eq!(reopened.lookup(&h_b).unwrap(), Some(event_b));
    assert_eq!(reopened.tail(10).unwrap().len(), 2);

    let _ = std::fs::remove_dir_all(path);
}

#[test]
fn proof_log_checksum_corruption_is_rejected() {
    let path = fresh_dir("file-ledger-corrupt");
    let ledger = FileProofLedger::open(&path).expect("open ledger");
    ledger
        .append(&json!({"kind": "approval", "id": "a"}))
        .expect("append");
    let log = path.join("proof.log");
    let mut text = std::fs::read_to_string(&log).unwrap();
    text = text.replacen("sha256:", "sha257:", 1);
    std::fs::write(&log, text).unwrap();

    let err = match FileProofLedger::open(&path) {
        Ok(_) => panic!("corrupt proof log should not open"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("checksum mismatch") || err.contains("hash mismatch"));

    let _ = std::fs::remove_dir_all(path);
}

#[test]
fn revocations_escape_and_reopen() {
    let path = fresh_dir("file-revocations");
    let cache = FileRevocationCache::open(&path).expect("open cache");
    cache
        .insert(
            "actor\tkind",
            "tf:actor:agent:example.com/x",
            "2026-04-25T00:00:00Z",
        )
        .unwrap();
    assert!(cache
        .is_revoked(
            "actor\tkind",
            "tf:actor:agent:example.com/x",
            "2026-04-26T00:00:00Z"
        )
        .unwrap());

    let reopened = FileRevocationCache::open(&path).expect("reopen cache");
    assert_eq!(
        reopened.list().unwrap(),
        vec![(
            "actor\tkind".to_string(),
            "tf:actor:agent:example.com/x".to_string(),
            "2026-04-25T00:00:00Z".to_string()
        )]
    );

    let _ = std::fs::remove_dir_all(path);
}

#[test]
fn evidence_archive_roundtrip_and_reopen() {
    let path = fresh_dir("file-evidence");
    let archive = FileEvidenceArchive::open(&path).expect("open archive");

    archive.put("bundle/one", b"hello").unwrap();
    archive.put("bundle:two", b"second").unwrap();
    assert_eq!(archive.get("bundle/one").unwrap().unwrap(), b"hello");
    assert_eq!(
        archive.list().unwrap(),
        vec!["bundle/one".to_string(), "bundle:two".to_string()]
    );

    let reopened = FileEvidenceArchive::open(&path).expect("reopen archive");
    assert_eq!(reopened.get("bundle:two").unwrap().unwrap(), b"second");

    let _ = std::fs::remove_dir_all(path);
}

#[test]
fn evidence_checksum_corruption_is_rejected() {
    let path = fresh_dir("file-evidence-corrupt");
    let archive = FileEvidenceArchive::open(&path).expect("open archive");
    archive.put("bundle-one", b"hello").unwrap();
    let evidence_file = path.join("evidence").join("62756e646c652d6f6e65");
    std::fs::write(evidence_file, b"tampered").unwrap();

    let err = archive.get("bundle-one").unwrap_err().to_string();
    assert!(err.contains("checksum mismatch"));

    let _ = std::fs::remove_dir_all(path);
}

#[test]
fn compact_rewrites_indexes_without_losing_data() {
    let path = fresh_dir("file-compact");
    let store = Arc::new(FileStore::open(&path).expect("open"));
    let ledger = FileProofLedger::from_store(store.clone());
    let a = json!({"kind": "compact", "i": 1});
    let b = json!({"kind": "compact", "i": 2});
    ledger.append(&a).unwrap();
    ledger.append(&b).unwrap();
    let before = std::fs::metadata(path.join("proof.log")).unwrap().len();

    store.compact().unwrap();

    let after = std::fs::metadata(path.join("proof.log")).unwrap().len();
    assert_eq!(before, after);
    let reopened = FileProofLedger::open(&path).unwrap();
    assert_eq!(reopened.tail(10).unwrap(), vec![a, b]);

    let _ = std::fs::remove_dir_all(path);
}

#[test]
fn concurrent_inserts_do_not_error() {
    let path = fresh_dir("file-concurrent");
    let store = Arc::new(FileStore::open(&path).expect("open"));
    let ledger = Arc::new(FileProofLedger::from_store(store));
    let mut handles = Vec::new();
    for i in 0..64u32 {
        let ledger = ledger.clone();
        handles.push(thread::spawn(move || {
            ledger
                .append(&json!({"kind": "concurrent", "i": i}))
                .unwrap()
        }));
    }
    let mut hashes = handles
        .into_iter()
        .map(|h| h.join().unwrap())
        .collect::<Vec<_>>();
    hashes.sort();
    hashes.dedup();
    assert_eq!(hashes.len(), 64);
    assert_eq!(ledger.tail(100).unwrap().len(), 64);

    let _ = std::fs::remove_dir_all(path);
}

//! End-to-end tests for the SQLite backend.
//!
//! Each test opens a fresh database file in a `tempfile::TempDir` to
//! guarantee isolation. The concurrent-insert test exercises the
//! Mutex-wrapped connection by spawning 100 threads.

use std::sync::Arc;
use std::thread;

use serde_json::json;
use tempfile::TempDir;

use tf_store_sqlite::{
    SqliteEvidenceArchive, SqliteProofLedger, SqliteRevocationCache, SqliteStore,
};
use tf_types::store::{EvidenceArchive, ProofLedger, RevocationCache};

fn fresh_db() -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("tf-store.sqlite");
    (dir, path)
}

#[test]
fn proof_ledger_roundtrip() {
    let (_dir, path) = fresh_db();
    let ledger = SqliteProofLedger::open(&path).expect("open ledger");

    let event_a = json!({"kind": "approval", "id": "a", "n": 1});
    let event_b = json!({"kind": "approval", "id": "b", "n": 2});

    let h_a = ledger.append(&event_a).expect("append a");
    let h_b = ledger.append(&event_b).expect("append b");
    assert_ne!(h_a, h_b, "different events must hash differently");

    let got_a = ledger.lookup(&h_a).expect("lookup a").expect("present a");
    assert_eq!(got_a, event_a);

    // Idempotent re-append returns the same hash and does not error.
    let h_a2 = ledger.append(&event_a).expect("idempotent append a");
    assert_eq!(h_a, h_a2);

    let tail = ledger.tail(10).expect("tail");
    assert_eq!(tail.len(), 2);
    assert_eq!(tail[0], event_a);
    assert_eq!(tail[1], event_b);

    assert!(ledger.lookup("does-not-exist").expect("lookup miss").is_none());
}

#[test]
fn revocation_cache_roundtrip() {
    let (_dir, path) = fresh_db();
    let cache = SqliteRevocationCache::open(&path).expect("open cache");

    cache
        .insert("actor", "tf:actor:agent:example.com/x", "2026-04-25T00:00:00Z")
        .expect("insert");

    assert!(cache
        .is_revoked("actor", "tf:actor:agent:example.com/x", "2026-04-25T00:00:00Z")
        .expect("is_revoked at boundary"));
    assert!(cache
        .is_revoked("actor", "tf:actor:agent:example.com/x", "2026-04-26T00:00:00Z")
        .expect("is_revoked after"));
    assert!(!cache
        .is_revoked("actor", "tf:actor:agent:example.com/x", "2026-04-24T00:00:00Z")
        .expect("not revoked before effective"));
    assert!(!cache
        .is_revoked("actor", "tf:actor:agent:example.com/y", "2099-01-01T00:00:00Z")
        .expect("unknown is not revoked"));

    let listed = cache.list().expect("list");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].0, "actor");
}

#[test]
fn evidence_archive_roundtrip() {
    let (_dir, path) = fresh_db();
    let archive = SqliteEvidenceArchive::open(&path).expect("open archive");

    let bundle = b"\x00\x01\x02hello-bundle\xff";
    archive.put("bundle-1", bundle).expect("put");
    let got = archive.get("bundle-1").expect("get").expect("present");
    assert_eq!(got, bundle);
    assert!(archive.get("missing").expect("get missing").is_none());

    archive.put("bundle-2", b"second").expect("put 2");
    let listed = archive.list().expect("list");
    assert_eq!(listed, vec!["bundle-1".to_string(), "bundle-2".to_string()]);

    // Overwrite is allowed.
    archive.put("bundle-1", b"replaced").expect("overwrite");
    assert_eq!(archive.get("bundle-1").unwrap().unwrap(), b"replaced");
}

#[test]
fn concurrent_inserts_do_not_error() {
    let (_dir, path) = fresh_db();
    let store = Arc::new(SqliteStore::open(&path).expect("open"));
    let ledger = Arc::new(SqliteProofLedger::from_store(store.clone()));

    let mut handles = Vec::with_capacity(100);
    for i in 0..100u32 {
        let l = ledger.clone();
        handles.push(thread::spawn(move || {
            let ev = json!({"kind": "concurrent", "i": i});
            l.append(&ev).expect("append in thread")
        }));
    }
    let hashes: Vec<String> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    // Every event has a distinct payload (`i` differs) so every hash is
    // distinct; if any thread had silently failed we would see a panic
    // inside the join above.
    let mut sorted = hashes.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), 100, "all 100 hashes should be unique");

    let tail = ledger.tail(200).expect("tail");
    assert_eq!(tail.len(), 100);
}

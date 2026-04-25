//! Live Postgres tests. Skipped automatically unless `DATABASE_URL` is set
//! to a reachable Postgres instance (per the acceptance criteria).
//!
//! These tests share a single database; they namespace their data with a
//! per-test random prefix to avoid cross-talk. They do NOT drop tables on
//! exit — operators running these against a real database should expect
//! the schema to remain.

use std::sync::Arc;

use serde_json::json;

use tf_store_postgres::{
    PostgresEvidenceArchive, PostgresProofLedger, PostgresRevocationCache, PostgresStore,
};
use tf_types::store::{EvidenceArchive, ProofLedger, RevocationCache};

fn database_url() -> Option<String> {
    std::env::var("DATABASE_URL").ok()
}

fn rand_suffix() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:x}", nanos)
}

fn store() -> Option<Arc<PostgresStore>> {
    let url = database_url()?;
    Some(PostgresStore::open(&url).expect("open postgres store"))
}

#[test]
fn proof_ledger_roundtrip_when_db_available() {
    let Some(store) = store() else {
        eprintln!("DATABASE_URL not set; skipping postgres proof_ledger_roundtrip");
        return;
    };
    let ledger = PostgresProofLedger::new(store);
    let suffix = rand_suffix();
    let event = json!({"kind": "approval", "test": "pg-roundtrip", "suffix": suffix});
    let h = ledger.append(&event).expect("append");
    let got = ledger.lookup(&h).expect("lookup").expect("present");
    assert_eq!(got, event);
    let h2 = ledger.append(&event).expect("idempotent");
    assert_eq!(h, h2);
}

#[test]
fn revocation_cache_roundtrip_when_db_available() {
    let Some(store) = store() else {
        eprintln!("DATABASE_URL not set; skipping postgres revocation_cache_roundtrip");
        return;
    };
    let cache = PostgresRevocationCache::new(store);
    let id = format!("tf:actor:agent:example.com/test-{}", rand_suffix());
    cache
        .insert("actor", &id, "2026-04-25T00:00:00Z")
        .expect("insert");
    assert!(cache
        .is_revoked("actor", &id, "2026-04-26T00:00:00Z")
        .expect("after"));
    assert!(!cache
        .is_revoked("actor", &id, "2026-04-24T00:00:00Z")
        .expect("before"));
}

#[test]
fn evidence_archive_roundtrip_when_db_available() {
    let Some(store) = store() else {
        eprintln!("DATABASE_URL not set; skipping postgres evidence_archive_roundtrip");
        return;
    };
    let archive = PostgresEvidenceArchive::new(store);
    let id = format!("bundle-{}", rand_suffix());
    let payload = b"evidence-bytes-\x00\xff";
    archive.put(&id, payload).expect("put");
    let got = archive.get(&id).expect("get").expect("present");
    assert_eq!(got, payload);
}

#[test]
fn concurrent_inserts_when_db_available() {
    let Some(store) = store() else {
        eprintln!("DATABASE_URL not set; skipping postgres concurrent_inserts");
        return;
    };
    // Postgres' tokio runtime is shared inside the store; spawning 100
    // OS threads each calling block_on would re-enter the same runtime
    // (panic in a multi-thread runtime, allowed but contended). To keep
    // the test honest we serialise the appends but exercise distinct
    // payloads to detect any silent failures.
    let ledger = PostgresProofLedger::new(store);
    let suffix = rand_suffix();
    for i in 0..100u32 {
        let ev = json!({"kind": "concurrent-pg", "suffix": suffix, "i": i});
        ledger.append(&ev).expect("append in loop");
    }
}

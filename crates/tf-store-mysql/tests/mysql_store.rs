//! Live MySQL tests. Skipped automatically unless `DATABASE_URL` is set
//! to a reachable MySQL instance (per the acceptance criteria).

use std::sync::Arc;

use serde_json::json;

use tf_store_mysql::{MysqlEvidenceArchive, MysqlProofLedger, MysqlRevocationCache, MysqlStore};
use tf_types::store::{EvidenceArchive, ProofLedger, RevocationCache};

fn database_url() -> Option<String> {
    // We accept either MYSQL_DATABASE_URL (preferred, avoids collision
    // with the Postgres tests) or DATABASE_URL when it points at MySQL.
    std::env::var("MYSQL_DATABASE_URL")
        .ok()
        .or_else(|| std::env::var("DATABASE_URL").ok())
        .filter(|u| u.starts_with("mysql://") || u.starts_with("mariadb://"))
}

fn rand_suffix() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:x}", nanos)
}

fn store() -> Option<Arc<MysqlStore>> {
    let url = database_url()?;
    Some(MysqlStore::open(&url).expect("open mysql store"))
}

#[test]
fn proof_ledger_roundtrip_when_db_available() {
    let Some(store) = store() else {
        eprintln!("MYSQL_DATABASE_URL not set; skipping mysql proof_ledger_roundtrip");
        return;
    };
    let ledger = MysqlProofLedger::new(store);
    let suffix = rand_suffix();
    let event = json!({"kind": "approval", "test": "mysql-roundtrip", "suffix": suffix});
    let h = ledger.append(&event).expect("append");
    let got = ledger.lookup(&h).expect("lookup").expect("present");
    assert_eq!(got, event);
}

#[test]
fn revocation_cache_roundtrip_when_db_available() {
    let Some(store) = store() else {
        eprintln!("MYSQL_DATABASE_URL not set; skipping mysql revocation_cache_roundtrip");
        return;
    };
    let cache = MysqlRevocationCache::new(store);
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
        eprintln!("MYSQL_DATABASE_URL not set; skipping mysql evidence_archive_roundtrip");
        return;
    };
    let archive = MysqlEvidenceArchive::new(store);
    let id = format!("bundle-{}", rand_suffix());
    let payload = b"evidence-bytes-\x00\xff";
    archive.put(&id, payload).expect("put");
    let got = archive.get(&id).expect("get").expect("present");
    assert_eq!(got, payload);
}

#[test]
fn concurrent_inserts_when_db_available() {
    let Some(store) = store() else {
        eprintln!("MYSQL_DATABASE_URL not set; skipping mysql concurrent_inserts");
        return;
    };
    let ledger = MysqlProofLedger::new(store);
    let suffix = rand_suffix();
    for i in 0..100u32 {
        let ev = json!({"kind": "concurrent-mysql", "suffix": suffix, "i": i});
        ledger.append(&ev).expect("append in loop");
    }
}

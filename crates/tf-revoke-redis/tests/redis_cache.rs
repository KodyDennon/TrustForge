//! Live Redis tests. Skipped automatically unless `REDIS_URL` is set.

use std::sync::Arc;
use std::thread;

use tf_revoke_redis::RedisRevocationCache;
use tf_types::store::RevocationCache;

fn redis_url() -> Option<String> {
    std::env::var("REDIS_URL").ok()
}

fn rand_suffix() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{:x}", nanos)
}

#[test]
fn revocation_roundtrip_when_redis_available() {
    let Some(url) = redis_url() else {
        eprintln!("REDIS_URL not set; skipping redis revocation_roundtrip");
        return;
    };
    let cache = RedisRevocationCache::open(&url).expect("open redis");
    let id = format!("tf:actor:agent:example.com/test-{}", rand_suffix());

    cache
        .insert("actor", &id, "2026-04-25T00:00:00Z")
        .expect("insert");
    assert!(cache
        .is_revoked("actor", &id, "2026-04-26T00:00:00Z")
        .expect("after"));
    assert!(cache
        .is_revoked("actor", &id, "2026-04-25T00:00:00Z")
        .expect("at boundary"));
    assert!(!cache
        .is_revoked("actor", &id, "2026-04-24T00:00:00Z")
        .expect("before"));
    assert!(!cache
        .is_revoked("actor", "missing", "2099-01-01T00:00:00Z")
        .expect("missing"));

    let listed = cache.list().expect("list");
    assert!(
        listed.iter().any(|(k, i, _)| k == "actor" && i == &id),
        "list should include the inserted id"
    );
}

#[test]
fn concurrent_inserts_when_redis_available() {
    let Some(url) = redis_url() else {
        eprintln!("REDIS_URL not set; skipping redis concurrent_inserts");
        return;
    };
    let cache = Arc::new(RedisRevocationCache::open(&url).expect("open redis"));
    let suffix = rand_suffix();

    let mut handles = Vec::with_capacity(100);
    for i in 0..100u32 {
        let c = cache.clone();
        let s = suffix.clone();
        handles.push(thread::spawn(move || {
            let id = format!("tf:actor:agent:example.com/conc-{}-{}", s, i);
            c.insert("actor", &id, "2026-04-25T00:00:00Z")
                .expect("insert in thread");
        }));
    }
    for h in handles {
        h.join().expect("thread");
    }

    // Spot-check 5 of the inserted entries.
    for i in [0u32, 17, 42, 88, 99] {
        let id = format!("tf:actor:agent:example.com/conc-{}-{}", suffix, i);
        assert!(cache
            .is_revoked("actor", &id, "2026-04-26T00:00:00Z")
            .expect("spot check"));
    }
}

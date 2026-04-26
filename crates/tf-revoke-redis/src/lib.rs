//! Redis-backed implementation of [`tf_types::store::RevocationCache`].
//!
//! Redis is the wrong shape for an append-only proof ledger (no native
//! durable ordered log; expensive to query historically), but it is an
//! excellent fast-path for revocation membership checks: keys are O(1)
//! and trivially shared across daemon instances.
//!
//! # Key layout
//!
//! ```text
//! tf:revoke:<target_kind>:<target_id>  -> effective_at (string)
//! ```
//!
//! `is_revoked(kind, id, at)` reads the value and compares lexicographically
//! against `at` (callers MUST pass ISO-8601 timestamps in a consistent
//! offset, the standard TrustForge convention being `Z`).
//!
//! `list()` uses `SCAN` rather than `KEYS` to avoid blocking the server;
//! it is intended for diagnostics, not the hot path.
//!
//! # What this crate does NOT provide
//!
//! No `ProofLedger` and no `EvidenceArchive`: those use one of the durable
//! SQL backends (`tf-store-sqlite`, `tf-store-postgres`, `tf-store-mysql`).
//! A typical deployment uses Postgres for durability and Redis as a
//! revocation fast-path fronting it.

use std::sync::Mutex;

use redis::{Commands, Connection};

use tf_types::store::{RevocationCache, StoreError};

const KEY_PREFIX: &str = "tf:revoke:";

fn map_err(e: redis::RedisError) -> StoreError {
    if e.is_connection_dropped() || e.is_io_error() || e.is_timeout() {
        StoreError::Unavailable(e.to_string())
    } else {
        StoreError::Other(e.to_string())
    }
}

fn key(kind: &str, id: &str) -> String {
    format!("{KEY_PREFIX}{kind}:{id}")
}

/// Redis revocation cache. The single underlying connection is wrapped in
/// a `Mutex` so the cache is `Send + Sync` from the trait's point of view;
/// throughput-sensitive deployments should layer multiple instances behind
/// a pool. (We do not pull in `r2d2-redis` here to keep the dependency
/// surface small.)
pub struct RedisRevocationCache {
    conn: Mutex<Connection>,
}

impl RedisRevocationCache {
    /// Open a connection to `url` (e.g. `redis://127.0.0.1:6379`).
    pub fn open(url: &str) -> Result<Self, StoreError> {
        let client = redis::Client::open(url)
            .map_err(|e| StoreError::Unavailable(format!("redis client: {e}")))?;
        let conn = client
            .get_connection()
            .map_err(|e| StoreError::Unavailable(format!("redis connect: {e}")))?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

impl RevocationCache for RedisRevocationCache {
    fn insert(
        &self,
        target_kind: &str,
        target_id: &str,
        effective_at: &str,
    ) -> Result<(), StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let _: () = conn
            .set(key(target_kind, target_id), effective_at)
            .map_err(map_err)?;
        Ok(())
    }

    fn is_revoked(&self, target_kind: &str, target_id: &str, at: &str) -> Result<bool, StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let val: Option<String> = conn.get(key(target_kind, target_id)).map_err(map_err)?;
        Ok(match val {
            Some(eff) => eff.as_str() <= at,
            None => false,
        })
    }

    fn list(&self) -> Result<Vec<(String, String, String)>, StoreError> {
        let mut conn = self.conn.lock().unwrap();
        let pattern = format!("{KEY_PREFIX}*");
        let iter: redis::Iter<'_, String> = conn.scan_match(&pattern).map_err(map_err)?;
        let keys: Vec<String> = iter.collect();

        // Now fetch each value. We don't reuse `iter` past collect because
        // the iterator borrows `conn` exclusively; subsequent commands need
        // a fresh borrow. (`conn` is already held by the Mutex guard.)
        let mut out = Vec::with_capacity(keys.len());
        for k in keys {
            // Strip prefix and split on the first ':' between kind and id.
            let rest = match k.strip_prefix(KEY_PREFIX) {
                Some(r) => r,
                None => continue,
            };
            let (kind, id) = match rest.split_once(':') {
                Some((kind, id)) => (kind.to_string(), id.to_string()),
                None => continue,
            };
            let val: Option<String> = conn.get(&k).map_err(map_err)?;
            if let Some(eff) = val {
                out.push((kind, id, eff));
            }
        }
        out.sort();
        Ok(out)
    }
}

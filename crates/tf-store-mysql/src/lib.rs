//! MySQL-backed implementations of the TrustForge persistence traits.
//!
//! Mirrors `tf-store-postgres`: sqlx + tokio internally, synchronous traits
//! externally, schema applied via `CREATE TABLE IF NOT EXISTS` at open.
//!
//! # Feature-flag note
//!
//! Uses `sqlx` with the `mysql` and `runtime-tokio-rustls` features. The
//! runtime feature must match every other sqlx-using crate in the
//! workspace (see `tf-store-postgres`).

use std::sync::Arc;

use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::mysql::{MySqlPool, MySqlPoolOptions};
use sqlx::Row;
use tokio::runtime::Runtime;

use tf_types::store::{EvidenceArchive, ProofLedger, RevocationCache, StoreError};

fn map_err(e: sqlx::Error) -> StoreError {
    use sqlx::Error::*;
    match e {
        RowNotFound => StoreError::NotFound,
        Database(db) if db.is_unique_violation() => StoreError::Conflict,
        Io(_) | PoolTimedOut | PoolClosed | WorkerCrashed => {
            StoreError::Unavailable(e.to_string())
        }
        other => StoreError::Other(other.to_string()),
    }
}

fn canonical_hash(event: &Value) -> Result<String, StoreError> {
    let canonical = serde_json::to_string(&sort_value(event))
        .map_err(|e| StoreError::Other(format!("canonical serialize: {e}")))?;
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

fn sort_value(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::with_capacity(m.len());
            for k in keys {
                out.insert(k.clone(), sort_value(&m[k]));
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(sort_value).collect()),
        other => other.clone(),
    }
}

pub struct MysqlStore {
    pool: MySqlPool,
    rt: Runtime,
}

impl MysqlStore {
    pub fn open(database_url: &str) -> Result<Arc<Self>, StoreError> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| StoreError::Unavailable(format!("tokio runtime: {e}")))?;
        let pool = rt
            .block_on(async {
                MySqlPoolOptions::new()
                    .max_connections(8)
                    .connect(database_url)
                    .await
            })
            .map_err(|e| StoreError::Unavailable(format!("connect: {e}")))?;
        rt.block_on(Self::migrate(&pool))?;
        Ok(Arc::new(Self { pool, rt }))
    }

    async fn migrate(pool: &MySqlPool) -> Result<(), StoreError> {
        // MySQL does not support multi-statement strings via the prepared
        // protocol that sqlx::raw_sql uses by default; split on `;`.
        let sql = include_str!("../migrations/0001_init.sql");
        for stmt in sql.split(';') {
            let trimmed = stmt.trim();
            if trimmed.is_empty() || trimmed.starts_with("--") {
                continue;
            }
            sqlx::query(trimmed)
                .execute(pool)
                .await
                .map_err(map_err)?;
        }
        Ok(())
    }
}

pub struct MysqlProofLedger {
    inner: Arc<MysqlStore>,
}
pub struct MysqlRevocationCache {
    inner: Arc<MysqlStore>,
}
pub struct MysqlEvidenceArchive {
    inner: Arc<MysqlStore>,
}

impl MysqlProofLedger {
    pub fn new(store: Arc<MysqlStore>) -> Self {
        Self { inner: store }
    }
}
impl MysqlRevocationCache {
    pub fn new(store: Arc<MysqlStore>) -> Self {
        Self { inner: store }
    }
}
impl MysqlEvidenceArchive {
    pub fn new(store: Arc<MysqlStore>) -> Self {
        Self { inner: store }
    }
}

impl ProofLedger for MysqlProofLedger {
    fn append(&self, event: &Value) -> Result<String, StoreError> {
        let hash = canonical_hash(event)?;
        let payload = serde_json::to_string(event)
            .map_err(|e| StoreError::Other(format!("serialize: {e}")))?;
        let pool = self.inner.pool.clone();
        let h = hash.clone();
        self.inner.rt.block_on(async move {
            // INSERT IGNORE for idempotent re-append by content hash.
            sqlx::query(
                "INSERT IGNORE INTO proof_events(event_hash, payload) VALUES (?, CAST(? AS JSON))",
            )
            .bind(&h)
            .bind(&payload)
            .execute(&pool)
            .await
            .map_err(map_err)?;
            Ok::<_, StoreError>(())
        })?;
        Ok(hash)
    }

    fn lookup(&self, event_hash: &str) -> Result<Option<Value>, StoreError> {
        let pool = self.inner.pool.clone();
        let h = event_hash.to_string();
        self.inner.rt.block_on(async move {
            let row = sqlx::query("SELECT payload FROM proof_events WHERE event_hash = ?")
                .bind(&h)
                .fetch_optional(&pool)
                .await
                .map_err(map_err)?;
            Ok::<_, StoreError>(match row {
                Some(r) => {
                    // sqlx returns mysql JSON as a String.
                    let s: String = r.get("payload");
                    let v: Value = serde_json::from_str(&s)
                        .map_err(|e| StoreError::Other(format!("decode payload: {e}")))?;
                    Some(v)
                }
                None => None,
            })
        })
    }

    fn tail(&self, limit: usize) -> Result<Vec<Value>, StoreError> {
        let pool = self.inner.pool.clone();
        self.inner.rt.block_on(async move {
            let rows = sqlx::query(
                "SELECT payload FROM (
                    SELECT payload, seq FROM proof_events ORDER BY seq DESC LIMIT ?
                 ) sub ORDER BY seq ASC",
            )
            .bind(limit as i64)
            .fetch_all(&pool)
            .await
            .map_err(map_err)?;
            let mut out = Vec::with_capacity(rows.len());
            for r in rows {
                let s: String = r.get("payload");
                let v: Value = serde_json::from_str(&s)
                    .map_err(|e| StoreError::Other(format!("decode payload: {e}")))?;
                out.push(v);
            }
            Ok::<_, StoreError>(out)
        })
    }
}

impl RevocationCache for MysqlRevocationCache {
    fn insert(
        &self,
        target_kind: &str,
        target_id: &str,
        effective_at: &str,
    ) -> Result<(), StoreError> {
        let pool = self.inner.pool.clone();
        let (k, i, e) = (
            target_kind.to_string(),
            target_id.to_string(),
            effective_at.to_string(),
        );
        self.inner.rt.block_on(async move {
            sqlx::query(
                "INSERT INTO revocations(target_kind, target_id, effective_at)
                 VALUES (?, ?, ?)
                 ON DUPLICATE KEY UPDATE effective_at = VALUES(effective_at)",
            )
            .bind(&k)
            .bind(&i)
            .bind(&e)
            .execute(&pool)
            .await
            .map_err(map_err)?;
            Ok::<_, StoreError>(())
        })
    }

    fn is_revoked(&self, target_kind: &str, target_id: &str, at: &str) -> Result<bool, StoreError> {
        let pool = self.inner.pool.clone();
        let (k, i, a) = (
            target_kind.to_string(),
            target_id.to_string(),
            at.to_string(),
        );
        self.inner.rt.block_on(async move {
            let row = sqlx::query(
                "SELECT effective_at FROM revocations WHERE target_kind = ? AND target_id = ?",
            )
            .bind(&k)
            .bind(&i)
            .fetch_optional(&pool)
            .await
            .map_err(map_err)?;
            Ok::<_, StoreError>(match row {
                Some(r) => {
                    let eff: String = r.get("effective_at");
                    eff.as_str() <= a.as_str()
                }
                None => false,
            })
        })
    }

    fn list(&self) -> Result<Vec<(String, String, String)>, StoreError> {
        let pool = self.inner.pool.clone();
        self.inner.rt.block_on(async move {
            let rows = sqlx::query(
                "SELECT target_kind, target_id, effective_at FROM revocations
                 ORDER BY target_kind, target_id",
            )
            .fetch_all(&pool)
            .await
            .map_err(map_err)?;
            Ok::<_, StoreError>(
                rows.into_iter()
                    .map(|r| {
                        (
                            r.get::<String, _>("target_kind"),
                            r.get::<String, _>("target_id"),
                            r.get::<String, _>("effective_at"),
                        )
                    })
                    .collect(),
            )
        })
    }
}

impl EvidenceArchive for MysqlEvidenceArchive {
    fn put(&self, bundle_id: &str, bytes: &[u8]) -> Result<(), StoreError> {
        let pool = self.inner.pool.clone();
        let id = bundle_id.to_string();
        let payload = bytes.to_vec();
        self.inner.rt.block_on(async move {
            sqlx::query(
                "INSERT INTO evidence_bundles(bundle_id, payload)
                 VALUES (?, ?)
                 ON DUPLICATE KEY UPDATE payload = VALUES(payload)",
            )
            .bind(&id)
            .bind(&payload)
            .execute(&pool)
            .await
            .map_err(map_err)?;
            Ok::<_, StoreError>(())
        })
    }

    fn get(&self, bundle_id: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let pool = self.inner.pool.clone();
        let id = bundle_id.to_string();
        self.inner.rt.block_on(async move {
            let row = sqlx::query("SELECT payload FROM evidence_bundles WHERE bundle_id = ?")
                .bind(&id)
                .fetch_optional(&pool)
                .await
                .map_err(map_err)?;
            Ok::<_, StoreError>(row.map(|r| r.get::<Vec<u8>, _>("payload")))
        })
    }

    fn list(&self) -> Result<Vec<String>, StoreError> {
        let pool = self.inner.pool.clone();
        self.inner.rt.block_on(async move {
            let rows = sqlx::query("SELECT bundle_id FROM evidence_bundles ORDER BY bundle_id")
                .fetch_all(&pool)
                .await
                .map_err(map_err)?;
            Ok::<_, StoreError>(rows.into_iter().map(|r| r.get::<String, _>("bundle_id")).collect())
        })
    }
}

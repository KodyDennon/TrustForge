//! SQLite-backed implementations of the TrustForge persistence traits.
//!
//! All three traits (`ProofLedger`, `RevocationCache`, `EvidenceArchive`)
//! are implemented against a single SQLite database file. Each store struct
//! owns a `rusqlite::Connection` wrapped in a `Mutex` so it can be shared
//! across threads (rusqlite connections are not `Sync`).
//!
//! Schema migrations are run on startup via `CREATE TABLE IF NOT EXISTS`
//! statements; opening an existing database is non-destructive.
//!
//! # Concurrency
//!
//! This crate is intended for single-process deployments (the home and
//! constrained profiles). The Mutex serialises writes through a single
//! connection. SQLite itself is configured in WAL mode for better
//! concurrent-reader behaviour.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection};
use serde_json::Value;
use sha2::{Digest, Sha256};

use tf_types::store::{EvidenceArchive, ProofLedger, RevocationCache, StoreError};

fn map_err(e: rusqlite::Error) -> StoreError {
    use rusqlite::Error::*;
    match e {
        SqliteFailure(err, _) if err.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE => {
            StoreError::Conflict
        }
        QueryReturnedNoRows => StoreError::NotFound,
        other => StoreError::Other(other.to_string()),
    }
}

fn open_with_schema(path: &Path) -> Result<Connection, StoreError> {
    let conn = Connection::open(path)
        .map_err(|e| StoreError::Unavailable(format!("open sqlite at {}: {e}", path.display())))?;
    // WAL gives better concurrent reads; busy_timeout avoids spurious
    // SQLITE_BUSY when multiple stores share the same file.
    conn.pragma_update(None, "journal_mode", "WAL").ok();
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .map_err(map_err)?;
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS proof_events (
            event_hash TEXT PRIMARY KEY,
            payload    TEXT NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
            seq        INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS proof_seq (
            id  INTEGER PRIMARY KEY CHECK (id = 1),
            val INTEGER NOT NULL
        );
        INSERT OR IGNORE INTO proof_seq(id, val) VALUES (1, 0);

        CREATE TABLE IF NOT EXISTS revocations (
            target_kind  TEXT NOT NULL,
            target_id    TEXT NOT NULL,
            effective_at TEXT NOT NULL,
            PRIMARY KEY (target_kind, target_id)
        );

        CREATE TABLE IF NOT EXISTS evidence_bundles (
            bundle_id TEXT PRIMARY KEY,
            payload   BLOB NOT NULL,
            created_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
        );
        ",
    )
    .map_err(map_err)?;
    Ok(conn)
}

fn canonical_hash(event: &Value) -> Result<String, StoreError> {
    // Serialise with sorted keys for deterministic hashing. We build a
    // BTreeMap-ordered serialization by round-tripping through
    // serde_json::to_value and re-serialising; serde_json itself does not
    // sort, so we walk the value.
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

/// Shared SQLite-backed store. Open once, then use any of the trait
/// adapters (`SqliteProofLedger` / `SqliteRevocationCache` /
/// `SqliteEvidenceArchive`) on top of the same connection.
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let conn = open_with_schema(path.as_ref())?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

/// `ProofLedger` adapter. Construct via `SqliteProofLedger::open(path)` for
/// a stand-alone ledger, or via `SqliteProofLedger::from_store(store)` to
/// share a connection with the other adapters.
pub struct SqliteProofLedger {
    inner: std::sync::Arc<SqliteStore>,
}

pub struct SqliteRevocationCache {
    inner: std::sync::Arc<SqliteStore>,
}

pub struct SqliteEvidenceArchive {
    inner: std::sync::Arc<SqliteStore>,
}

impl SqliteProofLedger {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Ok(Self {
            inner: std::sync::Arc::new(SqliteStore::open(path)?),
        })
    }
    pub fn from_store(store: std::sync::Arc<SqliteStore>) -> Self {
        Self { inner: store }
    }
}

impl SqliteRevocationCache {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Ok(Self {
            inner: std::sync::Arc::new(SqliteStore::open(path)?),
        })
    }
    pub fn from_store(store: std::sync::Arc<SqliteStore>) -> Self {
        Self { inner: store }
    }
}

impl SqliteEvidenceArchive {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Ok(Self {
            inner: std::sync::Arc::new(SqliteStore::open(path)?),
        })
    }
    pub fn from_store(store: std::sync::Arc<SqliteStore>) -> Self {
        Self { inner: store }
    }
}

impl ProofLedger for SqliteProofLedger {
    fn append(&self, event: &Value) -> Result<String, StoreError> {
        let hash = canonical_hash(event)?;
        let payload = serde_json::to_string(event)
            .map_err(|e| StoreError::Other(format!("serialize event: {e}")))?;
        let conn = self.inner.conn.lock().unwrap();
        let tx = conn
            .unchecked_transaction()
            .map_err(map_err)?;
        tx.execute(
            "UPDATE proof_seq SET val = val + 1 WHERE id = 1",
            [],
        )
        .map_err(map_err)?;
        let seq: i64 = tx
            .query_row("SELECT val FROM proof_seq WHERE id = 1", [], |r| r.get(0))
            .map_err(map_err)?;
        let inserted = tx.execute(
            "INSERT OR IGNORE INTO proof_events(event_hash, payload, seq) VALUES (?1, ?2, ?3)",
            params![&hash, &payload, seq],
        )
        .map_err(map_err)?;
        tx.commit().map_err(map_err)?;
        // `INSERT OR IGNORE` for a duplicate hash is a successful no-op;
        // the ledger is content-addressed, so a duplicate append is
        // idempotent and we still return the existing hash.
        let _ = inserted;
        Ok(hash)
    }

    fn lookup(&self, event_hash: &str) -> Result<Option<Value>, StoreError> {
        let conn = self.inner.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT payload FROM proof_events WHERE event_hash = ?1")
            .map_err(map_err)?;
        let mut rows = stmt.query(params![event_hash]).map_err(map_err)?;
        if let Some(row) = rows.next().map_err(map_err)? {
            let s: String = row.get(0).map_err(map_err)?;
            let v: Value = serde_json::from_str(&s)
                .map_err(|e| StoreError::Other(format!("deserialize event: {e}")))?;
            Ok(Some(v))
        } else {
            Ok(None)
        }
    }

    fn tail(&self, limit: usize) -> Result<Vec<Value>, StoreError> {
        let conn = self.inner.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT payload FROM (
                    SELECT payload, seq FROM proof_events ORDER BY seq DESC LIMIT ?1
                 ) ORDER BY seq ASC",
            )
            .map_err(map_err)?;
        let rows = stmt
            .query_map(params![limit as i64], |row| row.get::<_, String>(0))
            .map_err(map_err)?;
        let mut out = Vec::new();
        for r in rows {
            let s = r.map_err(map_err)?;
            let v: Value = serde_json::from_str(&s)
                .map_err(|e| StoreError::Other(format!("deserialize event: {e}")))?;
            out.push(v);
        }
        Ok(out)
    }
}

impl RevocationCache for SqliteRevocationCache {
    fn insert(
        &self,
        target_kind: &str,
        target_id: &str,
        effective_at: &str,
    ) -> Result<(), StoreError> {
        let conn = self.inner.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO revocations(target_kind, target_id, effective_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(target_kind, target_id) DO UPDATE SET effective_at = excluded.effective_at",
            params![target_kind, target_id, effective_at],
        )
        .map_err(map_err)?;
        Ok(())
    }

    fn is_revoked(&self, target_kind: &str, target_id: &str, at: &str) -> Result<bool, StoreError> {
        let conn = self.inner.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT effective_at FROM revocations
                 WHERE target_kind = ?1 AND target_id = ?2",
            )
            .map_err(map_err)?;
        let mut rows = stmt
            .query(params![target_kind, target_id])
            .map_err(map_err)?;
        if let Some(row) = rows.next().map_err(map_err)? {
            let eff: String = row.get(0).map_err(map_err)?;
            // Lexicographic compare works for ISO-8601 timestamps in the
            // same offset (typically `Z`); callers needing cross-offset
            // safety should normalise upstream.
            Ok(eff.as_str() <= at)
        } else {
            Ok(false)
        }
    }

    fn list(&self) -> Result<Vec<(String, String, String)>, StoreError> {
        let conn = self.inner.conn.lock().unwrap();
        let mut stmt = conn
            .prepare(
                "SELECT target_kind, target_id, effective_at FROM revocations
                 ORDER BY target_kind, target_id",
            )
            .map_err(map_err)?;
        let rows = stmt
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })
            .map_err(map_err)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(map_err)?);
        }
        Ok(out)
    }
}

impl EvidenceArchive for SqliteEvidenceArchive {
    fn put(&self, bundle_id: &str, bytes: &[u8]) -> Result<(), StoreError> {
        let conn = self.inner.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO evidence_bundles(bundle_id, payload)
             VALUES (?1, ?2)
             ON CONFLICT(bundle_id) DO UPDATE SET payload = excluded.payload",
            params![bundle_id, bytes],
        )
        .map_err(map_err)?;
        Ok(())
    }

    fn get(&self, bundle_id: &str) -> Result<Option<Vec<u8>>, StoreError> {
        let conn = self.inner.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT payload FROM evidence_bundles WHERE bundle_id = ?1")
            .map_err(map_err)?;
        let mut rows = stmt.query(params![bundle_id]).map_err(map_err)?;
        if let Some(row) = rows.next().map_err(map_err)? {
            let bytes: Vec<u8> = row.get(0).map_err(map_err)?;
            Ok(Some(bytes))
        } else {
            Ok(None)
        }
    }

    fn list(&self) -> Result<Vec<String>, StoreError> {
        let conn = self.inner.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT bundle_id FROM evidence_bundles ORDER BY bundle_id")
            .map_err(map_err)?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(map_err)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(map_err)?);
        }
        Ok(out)
    }
}

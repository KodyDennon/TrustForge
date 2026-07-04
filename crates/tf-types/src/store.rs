#![allow(clippy::doc_overindented_list_items)]
//! Persistence-backend traits for proof ledger, revocation cache, and
//! evidence archive. Implementations live in separate crates (tf-store-*).
//!
//! These traits let `tf-daemon` (and other components) treat their proof
//! ledger, revocation cache, and evidence archive as pluggable backends:
//! a deployment can run SQLite for a home profile, Postgres or MySQL for
//! enterprise, and Redis as a fast revocation cache fronting any of the
//! durable ledgers, all without touching daemon code.
//!
//! Implementations:
//! * `tf-store-file`       — first-party file-backed local store, all
//!                            three traits.
//! * `tf-store-sqlite`     — single-file embedded SQLite, all three traits.
//! * `tf-store-postgres`   — sqlx-backed Postgres, all three traits.
//! * `tf-store-mysql`      — sqlx-backed MySQL, all three traits.
//! * `tf-revoke-redis`     — Redis-backed `RevocationCache` only (Redis is
//!                            the wrong shape for an append-only ledger but
//!                            an excellent fast-path for revocation checks).

use serde_json::Value;

/// Errors returned by every persistence backend.
///
/// Backends MUST map their native error types onto these variants so the
/// daemon can treat them uniformly. `Unavailable` is reserved for transient
/// connectivity / pool exhaustion; `NotFound` for explicit absence;
/// `Conflict` for unique-constraint or optimistic-lock failures; `Other`
/// for everything else (with a human-readable message).
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("backend unavailable: {0}")]
    Unavailable(String),
    #[error("not found")]
    NotFound,
    #[error("conflict")]
    Conflict,
    #[error("backend error: {0}")]
    Other(String),
}

/// Append-only ledger of TrustForge proof events.
///
/// `append` returns the canonical event hash (implementation-defined; the
/// SQLite/Postgres/MySQL backends use SHA-256 over canonical JSON). Lookup
/// is by that hash; `tail` returns the most recent `limit` events in
/// insertion order (oldest first within the slice).
pub trait ProofLedger: Send + Sync {
    fn append(&self, event: &Value) -> Result<String, StoreError>;
    fn lookup(&self, event_hash: &str) -> Result<Option<Value>, StoreError>;
    fn tail(&self, limit: usize) -> Result<Vec<Value>, StoreError>;
}

/// Revocation set. Conceptually a `(target_kind, target_id) -> effective_at`
/// map; `is_revoked` answers "was this target revoked at or before `at`?"
///
/// The SQL backends store this as a regular table; Redis stores it as
/// `tf:revoke:<kind>:<id>` keys whose value is the effective_at timestamp.
pub trait RevocationCache: Send + Sync {
    fn insert(
        &self,
        target_kind: &str,
        target_id: &str,
        effective_at: &str,
    ) -> Result<(), StoreError>;
    fn is_revoked(&self, target_kind: &str, target_id: &str, at: &str) -> Result<bool, StoreError>;
    fn list(&self) -> Result<Vec<(String, String, String)>, StoreError>;
}

/// Opaque-byte evidence-bundle archive (e.g. compliance bundles per
/// TF-0012). Bundles are addressed by an external bundle id, not a content
/// hash, because callers may want to overwrite or version a bundle outside
/// the archive's responsibility.
pub trait EvidenceArchive: Send + Sync {
    fn put(&self, bundle_id: &str, bytes: &[u8]) -> Result<(), StoreError>;
    fn get(&self, bundle_id: &str) -> Result<Option<Vec<u8>>, StoreError>;
    fn list(&self) -> Result<Vec<String>, StoreError>;
}

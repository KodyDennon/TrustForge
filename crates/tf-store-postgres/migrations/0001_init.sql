-- Initial schema for the TrustForge Postgres backend.
-- Applied at startup by `PostgresStore::open`.

CREATE TABLE IF NOT EXISTS proof_events (
    event_hash TEXT PRIMARY KEY,
    payload    JSONB NOT NULL,
    seq        BIGSERIAL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS revocations (
    target_kind  TEXT NOT NULL,
    target_id    TEXT NOT NULL,
    effective_at TEXT NOT NULL,
    PRIMARY KEY (target_kind, target_id)
);

CREATE TABLE IF NOT EXISTS evidence_bundles (
    bundle_id  TEXT PRIMARY KEY,
    payload    BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

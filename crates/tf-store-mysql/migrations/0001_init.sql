-- Initial schema for the TrustForge MySQL backend.
-- Applied at startup by `MysqlStore::open`.

CREATE TABLE IF NOT EXISTS proof_events (
    event_hash VARCHAR(128) NOT NULL PRIMARY KEY,
    payload    JSON NOT NULL,
    seq        BIGINT NOT NULL AUTO_INCREMENT UNIQUE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS revocations (
    target_kind  VARCHAR(64)  NOT NULL,
    target_id    VARCHAR(512) NOT NULL,
    effective_at VARCHAR(64)  NOT NULL,
    PRIMARY KEY (target_kind, target_id)
);

CREATE TABLE IF NOT EXISTS evidence_bundles (
    bundle_id  VARCHAR(256) NOT NULL PRIMARY KEY,
    payload    LONGBLOB NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

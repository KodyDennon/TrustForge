# tf-store-file

First-party file-backed storage for TrustForge proof events,
revocations, and evidence bundles.

This crate is the dependency-minimal local store intended to replace
SQLite as the default embedded deployment target over time. It owns the
on-disk format directly: append-only proof log, revocation snapshot, and
evidence bundle files. It does not depend on SQLite, SQLx, Redis,
tempfile, hex, or a hashing crate.

Current boundary: the shared `tf_types::store` traits still accept
`serde_json::Value`, so this crate retains the workspace JSON boundary
until the planned `tf_types::json::Value` migration lands.

## Layout

- `proof.log` — tab-separated `hash<TAB>canonical-json` records.
- `proof.log` — tab-separated
  `hash<TAB>record-checksum<TAB>canonical-json` records.
- `revocations.tsv` — tab-separated `target_kind<TAB>target_id<TAB>effective_at`.
- `evidence/` — one file per bundle id, named by first-party hex
  encoding of the bundle id bytes, plus a `.sha256` sidecar.

Writes are serialized through an in-process mutex. Proof and evidence
writes are flushed with `sync_data`; revocation snapshot replacement is
atomic via write-temp, sync, rename, and parent-directory sync.

`FileStore::compact()` rewrites the proof log and revocation snapshot
from the rebuilt in-memory indexes. Opening the store verifies proof-log
record checksums and event hashes; reading evidence verifies the sidecar
checksum.

`FileStore::health_check()` re-reads durable files and evidence
sidecars from disk, returning proof/revocation/evidence counts only when
all checks pass. Opening a store also removes stale `.tmp` files left by
interrupted writes before rebuilding indexes.

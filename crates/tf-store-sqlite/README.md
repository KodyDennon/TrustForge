# tf-store-sqlite

TrustForge database backend for Sqlite. High-performance storage driver for the TrustForge proof ledger, revocation cache, and evidence archive.

Part of [TrustForge](https://github.com/KodyDennon/TrustForge) — the open-source trust fabric for
AI-native software, devices, and verifiable action. The Rust crates and
the TypeScript packages (`@trustforge-protocol/*`) are mirrored
reference implementations kept in lockstep by a cross-language
conformance suite.

## Install

```sh
cargo add tf-store-sqlite
```

## Overview

SQLite-backed implementations of the TrustForge persistence traits.

All three traits (`ProofLedger`, `RevocationCache`, `EvidenceArchive`)
are implemented against a single SQLite database file. Each store struct
owns a `rusqlite::Connection` wrapped in a `Mutex` so it can be shared
across threads (rusqlite connections are not `Sync`).

Schema migrations are run on startup via `CREATE TABLE IF NOT EXISTS`
statements; opening an existing database is non-destructive.

# Concurrency

This crate is intended for single-process deployments (the home and
constrained profiles). The Mutex serialises writes through a single
connection. SQLite itself is configured in WAL mode for better
concurrent-reader behaviour.

## Links

- API docs: [docs.rs/tf-store-sqlite](https://docs.rs/tf-store-sqlite)
- Source: [crates/tf-store-sqlite](https://github.com/KodyDennon/TrustForge/tree/main/crates/tf-store-sqlite)
- Specs & conformance vectors: [KodyDennon/TrustForge](https://github.com/KodyDennon/TrustForge)
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.

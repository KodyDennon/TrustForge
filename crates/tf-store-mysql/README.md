# tf-store-mysql

TrustForge database backend for Mysql. High-performance storage driver for the TrustForge proof ledger, revocation cache, and evidence archive.

Part of [TrustForge](https://github.com/KodyDennon/TrustForge) — the open-source trust fabric for
AI-native software, devices, and verifiable action. The Rust crates and
the TypeScript packages (`@trustforge-protocol/*`) are mirrored
reference implementations kept in lockstep by a cross-language
conformance suite.

## Install

```sh
cargo add tf-store-mysql
```

## Overview

MySQL-backed implementations of the TrustForge persistence traits.

Mirrors `tf-store-postgres`: sqlx + tokio internally, synchronous traits
externally, schema applied via `CREATE TABLE IF NOT EXISTS` at open.

# Feature-flag note

Uses `sqlx` with the `mysql` and `runtime-tokio-rustls` features. The
runtime feature must match every other sqlx-using crate in the
workspace (see `tf-store-postgres`).

## Links

- API docs: [docs.rs/tf-store-mysql](https://docs.rs/tf-store-mysql)
- Source: [crates/tf-store-mysql](https://github.com/KodyDennon/TrustForge/tree/main/crates/tf-store-mysql)
- Specs & conformance vectors: [KodyDennon/TrustForge](https://github.com/KodyDennon/TrustForge)
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.

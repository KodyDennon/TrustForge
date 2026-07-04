# tf-store-postgres

TrustForge database backend for Postgres. High-performance storage driver for the TrustForge proof ledger, revocation cache, and evidence archive.

Part of [TrustForge](https://github.com/KodyDennon/TrustForge) — the open-source trust fabric for
AI-native software, devices, and verifiable action. The Rust crates and
the TypeScript packages (`@trustforge-protocol/*`) are mirrored
reference implementations kept in lockstep by a cross-language
conformance suite.

## Install

```sh
cargo add tf-store-postgres
```

## Overview

Postgres-backed implementations of the TrustForge persistence traits.

Internally async (sqlx + tokio), but the public surface is the same
synchronous trait shape used by SQLite. Each call uses
`tokio::runtime::Handle::block_on` against a runtime owned by the store
so the daemon does not need to be async-aware to use this backend.

# Feature-flag note

`sqlx` is built with `runtime-tokio-rustls`. Because sqlx requires
exactly one runtime feature globally, every `tf-store-*` crate that
depends on sqlx in this workspace MUST agree on `runtime-tokio-rustls`.
Mixing in `runtime-async-std-*` would break the build.

## Links

- API docs: [docs.rs/tf-store-postgres](https://docs.rs/tf-store-postgres)
- Source: [crates/tf-store-postgres](https://github.com/KodyDennon/TrustForge/tree/main/crates/tf-store-postgres)
- Specs & conformance vectors: [KodyDennon/TrustForge](https://github.com/KodyDennon/TrustForge)
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.

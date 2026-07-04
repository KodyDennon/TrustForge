# tf-revoke-redis

TrustForge revocation cache backed by Redis. High-performance, distributed invalidation of capabilities and active sessions.

Part of [TrustForge](https://github.com/KodyDennon/TrustForge) — the open-source trust fabric for
AI-native software, devices, and verifiable action. The Rust crates and
the TypeScript packages (`@trustforge-protocol/*`) are mirrored
reference implementations kept in lockstep by a cross-language
conformance suite.

## Install

```sh
cargo add tf-revoke-redis
```

## Overview

Redis-backed implementation of [`tf_types::store::RevocationCache`].

Redis is the wrong shape for an append-only proof ledger (no native
durable ordered log; expensive to query historically), but it is an
excellent fast-path for revocation membership checks: keys are O(1)
and trivially shared across daemon instances.

# Key layout

```text
tf:revoke:<target_kind>:<target_id>  -> effective_at (string)
```

`is_revoked(kind, id, at)` reads the value and compares lexicographically
against `at` (callers MUST pass ISO-8601 timestamps in a consistent
offset, the standard TrustForge convention being `Z`).

`list()` uses `SCAN` rather than `KEYS` to avoid blocking the server;
it is intended for diagnostics, not the hot path.

# What this crate does NOT provide

No `ProofLedger` and no `EvidenceArchive`: those use one of the durable
SQL backends (`tf-store-sqlite`, `tf-store-postgres`, `tf-store-mysql`).
A typical deployment uses Postgres for durability and Redis as a
revocation fast-path fronting it.

## Links

- API docs: [docs.rs/tf-revoke-redis](https://docs.rs/tf-revoke-redis)
- Source: [crates/tf-revoke-redis](https://github.com/KodyDennon/TrustForge/tree/main/crates/tf-revoke-redis)
- Specs & conformance vectors: [KodyDennon/TrustForge](https://github.com/KodyDennon/TrustForge)
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.

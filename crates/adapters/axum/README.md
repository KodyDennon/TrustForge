# tf-axum

TrustForge middleware for Axum. Provides drop-in zero-trust request verification, capability delegation, and policy enforcement for Axum servers.

Part of [TrustForge](https://github.com/KodyDennon/TrustForge) — the open-source trust fabric for
AI-native software, devices, and verifiable action. The Rust crates and
the TypeScript packages (`@trustforge-protocol/*`) are mirrored
reference implementations kept in lockstep by a cross-language
conformance suite.

## Install

```sh
cargo add tf-axum
```

## Overview

tf-axum — axum/tower middleware that calls `tf-daemon`'s `/v1/decide`.

Drop [`TrustForgeLayer`] into any axum `Router` (or any `tower` stack) and
every inbound request will:

1. extract a host token (default: `Authorization: Bearer …`),
2. POST to `tf-daemon`'s `/v1/decide`,
3. on `allow`: attach `Extension<TfDecision>` and forward,
4. on `deny`: short-circuit with `403 Forbidden` and a JSON body,
5. on `approval` (or `approval_required`): short-circuit with `202 Accepted`.

The middleware is profile-agnostic and intentionally small: it only
enforces the live-mode authority gate; replay packets and per-route
capability mapping are handled by higher-level helpers.

## Links

- API docs: [docs.rs/tf-axum](https://docs.rs/tf-axum)
- Source: [crates/adapters/axum](https://github.com/KodyDennon/TrustForge/tree/main/crates/adapters/axum)
- Specs & conformance vectors: [KodyDennon/TrustForge](https://github.com/KodyDennon/TrustForge)
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.

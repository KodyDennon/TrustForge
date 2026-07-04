# tf-actix-web

TrustForge middleware for Actix web. Provides drop-in zero-trust request verification, capability delegation, and policy enforcement for Actix web servers.

Part of [TrustForge](https://github.com/KodyDennon/TrustForge) — the open-source trust fabric for
AI-native software, devices, and verifiable action. The Rust crates and
the TypeScript packages (`@trustforge-protocol/*`) are mirrored
reference implementations kept in lockstep by a cross-language
conformance suite.

## Install

```sh
cargo add tf-actix-web
```

## Overview

tf-actix-web — actix-web middleware that calls `tf-daemon`'s `/v1/decide`.

Use [`TrustForgeMiddleware`] as a transform on `App::wrap(...)`. On allow,
the [`TfDecision`] is attached to the request `extensions()` so handlers
can inspect it. On deny / approval the middleware short-circuits without
invoking the inner service.

## Links

- API docs: [docs.rs/tf-actix-web](https://docs.rs/tf-actix-web)
- Source: [crates/adapters/actix-web](https://github.com/KodyDennon/TrustForge/tree/main/crates/adapters/actix-web)
- Specs & conformance vectors: [KodyDennon/TrustForge](https://github.com/KodyDennon/TrustForge)
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.

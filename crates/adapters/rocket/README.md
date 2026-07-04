# tf-rocket

TrustForge middleware for Rocket. Provides drop-in zero-trust request verification, capability delegation, and policy enforcement for Rocket servers.

Part of [TrustForge](https://github.com/KodyDennon/TrustForge) — the open-source trust fabric for
AI-native software, devices, and verifiable action. The Rust crates and
the TypeScript packages (`@trustforge-protocol/*`) are mirrored
reference implementations kept in lockstep by a cross-language
conformance suite.

## Install

```sh
cargo add tf-rocket
```

## Overview

tf-rocket — Rocket fairing that calls `tf-daemon`'s `/v1/decide`.

Attach [`TrustForgeFairing`] with `rocket::build().attach(...)`. Every
incoming request is gated against the daemon. On allow, the [`TfDecision`]
is stashed in `request.local_cache` for handlers to inspect.
On deny / approval, the response is rewritten to 403 / 202 before the
handler runs.

## Links

- API docs: [docs.rs/tf-rocket](https://docs.rs/tf-rocket)
- Source: [crates/adapters/rocket](https://github.com/KodyDennon/TrustForge/tree/main/crates/adapters/rocket)
- Specs & conformance vectors: [KodyDennon/TrustForge](https://github.com/KodyDennon/TrustForge)
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.

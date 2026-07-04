# tf-tonic

TrustForge middleware for Tonic. Provides drop-in zero-trust request verification, capability delegation, and policy enforcement for Tonic servers.

Part of [TrustForge](https://github.com/KodyDennon/TrustForge) — the open-source trust fabric for
AI-native software, devices, and verifiable action. The Rust crates and
the TypeScript packages (`@trustforge-protocol/*`) are mirrored
reference implementations kept in lockstep by a cross-language
conformance suite.

## Install

```sh
cargo add tf-tonic
```

## Overview

tf-tonic — tonic gRPC interceptor that calls `tf-daemon`'s `/v1/decide`.

`tonic`'s `Interceptor` trait is synchronous; it inspects request metadata
and either returns the request or rejects it with a `Status`. Because our
decide call is async, this crate exposes two flavours:

 * [`TrustForgeInterceptor::check`] — async helper used by code that wants
   to pre-flight a `Request` before it hits the inner service.
 * [`tonic_interceptor`] — convenience that runs `check` on the current
   runtime via `tokio::runtime::Handle::current().block_on(...)`. This is
   the form that plugs into `tonic::service::interceptor`.

Both produce a `tonic::Status::permission_denied` on `deny`,
`failed_precondition` on `approval_required`, and `unavailable` on
transport error (unless `fail_open` is set).

## Links

- API docs: [docs.rs/tf-tonic](https://docs.rs/tf-tonic)
- Source: [crates/adapters/tonic](https://github.com/KodyDennon/TrustForge/tree/main/crates/adapters/tonic)
- Specs & conformance vectors: [KodyDennon/TrustForge](https://github.com/KodyDennon/TrustForge)
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.

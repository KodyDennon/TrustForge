# tf-otel

TrustForge OpenTelemetry integration. Standardized OTLP tracing, spans, and metrics for auditing the entire zero-trust lifecycle.

Part of [TrustForge](https://github.com/KodyDennon/TrustForge) — the open-source trust fabric for
AI-native software, devices, and verifiable action. The Rust crates and
the TypeScript packages (`@trustforge-protocol/*`) are mirrored
reference implementations kept in lockstep by a cross-language
conformance suite.

## Install

```sh
cargo add tf-otel
```

## Overview

tf-otel — TrustForge OpenTelemetry / OTLP wiring for Rust.

This crate is the Rust counterpart to `tools/tf-daemon/src/otel.ts`.
It owns three things:

1. **A single `init_otel(...)` entry point** that brings up a tracer
   provider, a meter provider, and a `tracing` -> OpenTelemetry bridge
   in one shot. Callers hand back a [`TfOtelHandle`] whose `Drop` impl
   flushes spans and metrics on shutdown so we never silently drop the
   tail of a workload.

2. **Canonical span and metric names** that match the TS daemon's wire
   spec. Every Rust component that participates in a TrustForge
   decision MUST use these constants — that is the contract that lets
   Grafana dashboards cover the whole stack with a single set of
   queries. The names are listed in [`spans`] and [`metrics`] modules.

3. **Convenience helpers** ([`record_decide`], [`record_proof_event`],
   etc.) that the proxy, axum/tonic adapters, and prom-exporter use to
   emit the standard observable events without each call site
   re-implementing the attribute keys.

## Wire-spec compatibility

The TS daemon emits one span per `/v1/decide` request named `tf.decide`
with attributes `tf.action`, `tf.target`, `tf.decision`,
`tf.actor_resolved`. The Rust side keeps `tf.daemon.decide` (the spec
name from `crates/tf-otel`) as the canonical span; the legacy
`tf.decide` short form is also available as
[`spans::DECIDE_LEGACY`] for cross-stack joins.

## Links

- API docs: [docs.rs/tf-otel](https://docs.rs/tf-otel)
- Source: [crates/tf-otel](https://github.com/KodyDennon/TrustForge/tree/main/crates/tf-otel)
- Specs & conformance vectors: [KodyDennon/TrustForge](https://github.com/KodyDennon/TrustForge)
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.

# Dependency Replacement Roadmap

Status: active replacement program, started July 2026.

This document is the execution plan for moving TrustForge-owned runtime
surface away from small third-party dependencies. It complements
`docs/dependency-audit.md`, which records the audit inventory and the
first completed replacement waves.

## Policy

- TrustForge-owned protocol behavior should be first-party: codecs,
  envelopes, canonicalization, schema validation, request framing, and
  local storage formats.
- Dependencies under roughly 50k lines of code are replacement
  candidates unless they are crypto primitives, database/server
  adapter targets, framework adapter targets, or audit-gated transport
  infrastructure.
- Breaking API changes are allowed when an API exposes a dependency
  type directly, such as `reqwest::Client` or `serde_json::Value`.
- First-party TLS, QUIC, and HTTP/3 must be real implementations, easy
  to opt into, and standards-tracked. They are not production defaults
  until external security review passes.

## Current implementation slice

The first implementation slice removes `reqwest` from
`tf-decide-client`, the shared Rust client used by framework adapters
to call `tf-daemon`'s `/v1/decide` endpoint, and from
`tf-prom-exporter`, which scrapes local daemon admin endpoints. Both
now use the shared first-party `tf-transport` HTTP/1.1 client.

- Scope: plain HTTP/1.1 to the local daemon, one request per
  connection, `Connection: close`, JSON body, optional bearer token,
  timeout, `Content-Length`, chunked responses, and close-framed
  responses.
- Intentional limit: no HTTPS in this local-daemon client. Production
  TLS termination belongs at the listener/proxy layer until the
  first-party transport track is audit-ready.
- Breaking API: `TfDecideClient::with_client(reqwest::Client)` is
  removed. Use `TfDecideClient::new(...).with_timeout(...)` for the
  only supported client customization in this crate.
- The exporter uses the same policy: plain HTTP/1.1 for local daemon
  scraping, no generic HTTPS client claim.
- Release hygiene: the Rust publish script includes regular native
  workspace crates outside `crates/`, currently `tf-prom-exporter`, so
  dependency-replacement work is visible on crates.io after release.
- Codegen hygiene: generated TS RPC and agent-contract helpers import
  the published `@trustforge-protocol/types` package, not the stale
  `tf-types` placeholder.

## Next phases

1. **HTTP client consolidation**
   - Move the local HTTP/1.1 code into a shared `tf-transport` crate.
   - Remove direct `reqwest` usage from cloud bridges and native tools.
   - Hide any temporary `rustls`/HTTPS backend behind owned TrustForge
     transport traits.
   - Current status: `tf-transport` owns the plain HTTP/1.1 client used
     by `tf-decide-client` and `tf-prom-exporter`; cloud bridge HTTPS
     still waits on the audit-gated TLS transport backend.

2. **First-party JSON runtime**
   - Add `tf_types::json::Value`, parser, serializer, canonical
     serializer, and JSON pointer/path helpers.
   - Regenerate Rust bindings so generated fields stop exposing
     `serde_json::Value`.
   - Migrate stores, RPC/session/packet code, policy engines, bridges,
     tests, and generated examples.

3. **No-dependency file store**
   - Add `tf-store-file` as the preferred dependency-minimal store.
   - Implement append-only proof ledger, revocation index, evidence
     bundle storage, crash recovery, checksums, compaction, and index
     rebuild.
   - Keep SQLite/Postgres/MySQL/Redis as optional adapter backends.
   - Current status: `tf-store-file` exists with an owned append-only
     proof log, revocation snapshot, evidence files, proof/evidence
     checksums, atomic evidence and revocation writes, compaction, and
     reopen/index rebuild tests.

4. **First-party TLS, QUIC, and HTTP/3**
   - Track TLS 1.3 RFC 8446, QUIC RFC 9000, QUIC/TLS RFC 9001,
     HTTP/3 RFC 9114, and QPACK RFC 9204.
   - Ship behind explicit experimental features first.
   - Promote to production default only after conformance tests,
     interop tests, fuzzing, and external audit.

## Acceptance gates

- Every replacement must remove the dependency from the published
  runtime dependency graph, not merely hide it in code.
- Tests must cover positive behavior, malformed input, timeout/error
  paths, and compatibility with existing TrustForge fixtures.
- Registry verification is part of release: crates.io/npm dependency
  pages must match the documented result after publish.

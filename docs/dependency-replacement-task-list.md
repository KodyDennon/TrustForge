# Dependency Replacement Task List

Status: active production implementation.

## Done in this slice

- [x] Add shared first-party `tf-transport` crate.
- [x] Move local HTTP/1.1 client behavior into `tf-transport`.
- [x] Remove `reqwest` from `tf-decide-client`.
- [x] Remove the public `TfDecideClient::with_client(reqwest::Client)` API.
- [x] Remove `reqwest` from `tf-prom-exporter`.
- [x] Add `tf-store-file` as a first-party file-backed store.
- [x] Add proof-log record checksums and event-hash verification.
- [x] Add evidence checksum sidecars and read-time verification.
- [x] Add file-store compaction and reopen/index rebuild coverage.
- [x] Fix generated TS RPC/agent-contract imports to use the published
      `@trustforge-protocol/types` package instead of nonexistent
      `tf-types`.
- [x] Harden `tf-transport` HTTP/1.1 parsing for ambiguous authorities,
      reserved request headers, duplicate/conflicting response framing,
      chunk framing errors, IPv6 bracket authorities, and query-only
      request targets.
- [x] Harden `tf-store-file` with stale-temp cleanup, parent-directory
      sync after atomic renames, serialized evidence writes, and
      `FileStore::health_check()` for startup/backup integrity probes.
- [x] Extend `scripts/publish-crates.sh` so native workspace crates
      such as `tf-prom-exporter` publish with the rest of the Rust
      release set.
- [x] Bump publishable Rust workspace crates to `0.1.9` for the next
      crates.io release.
- [x] Configure npm trusted publishing for all 36 npm packages and switch
      release publishing to npm OIDC provenance.
- [x] Configure crates.io trusted publishing for all 31 publishable Rust
      crates and switch Cargo release publishing to GitHub OIDC.
- [x] Document the policy, roadmap, implementation state, and audit gates.

## Next production slices

- [ ] Move remaining direct `reqwest` bridge users onto `tf-transport`
      once the HTTPS/TLS backend exists.
- [ ] Add `tf_types::json::Value`, parser, serializer, canonical
      serializer, and JSON pointer/path helpers.
- [ ] Regenerate Rust bindings to stop exposing `serde_json::Value`.
- [ ] Migrate stores, RPC/session/packet code, policy engines, bridges,
      and tests to the first-party JSON value.
- [ ] Add migration/export tooling from SQLite/Postgres/MySQL stores into
      `tf-store-file`.
- [ ] Add `tf-tls` experimental TLS 1.3 state machine and vectors.
- [ ] Add `tf-quic` experimental QUIC transport over UDP.
- [ ] Add `tf-http3` experimental HTTP/3 + QPACK layer.
- [ ] Add transport interop/fuzz targets and external audit gate docs.
- [ ] Verify crates.io and npm registry pages after the trusted-publishing
      release.

## Hard gates

- No first-party TLS/QUIC/HTTP3 backend becomes default production until
  conformance, interop, fuzzing, and external review are complete.
- No schema/codegen change ships without regenerating TS/Rust bindings
  and running conformance.
- Do not run blanket `cargo fmt`; format touched non-generated Rust
  files only, because generated Rust layout is codegen-diff checked.

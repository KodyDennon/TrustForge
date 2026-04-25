# TrustForge Full Implementation Plan

**Date:** 2026-04-25
**Goal:** Land every deferred item from v0.1.0 plus the full compatibility-layer surface — every popular runtime, every popular auth library, every popular operating system, embedded/no_std targets, kernel hooks, and network-equipment packaging — so TrustForge is the drop-in next-generation auth fabric described in the manifesto.

Scope is locked. No scaffolding, no stubs, no deferrals. Each line item lists files to create, tests to pass, and acceptance criteria.

---

## Conventions

- **TS packages**: `@trustforge/<name>` published from `tools/adapters/ts/<name>/`.
- **Rust crates**: `tf-<name>` published from `crates/adapters/<name>/`.
- **Other-language packages**: `tools/adapters/<lang>/<name>/`.
- **Native binaries / OS modules**: `tools/native/<target>/`.
- **Acceptance criterion (default)**: every adapter ships:
  1. unit tests proving the host's existing auth still works,
  2. integration tests proving TrustForge can deny an action the host's auth would have allowed (when profile = E3+),
  3. a "drop into a hello-world repo" example that proves zero host code change for observe-only mode,
  4. a `bridge.<adapter>.accepted` proof event on every successful authorization,
  5. parity vectors (where applicable) so the same decision-request bytes round-trip through the sidecar HTTP `/v1/decide` endpoint identically.

---

## Phase A — Close every v0.1 Rust parity deferral

### A1. Rust per-kind ProofRPC dispatchers (all 10 kinds)

**Files:**
- modify `crates/tf-types/src/rpc.rs` — extend `Handler` enum with 8 new variants:
  `Subscribe`, `ClientStream`, `Bidi`, `CommandChannel`, `BulkTransfer`, `Telemetry`, `RemoteShell`, `AgentSession`.
- add per-kind handler trait aliases: `SubscribeHandler`, `ClientStreamHandler`, `BidiHandler`, `CommandChannelHandler`, `BulkTransferHandler`, `TelemetryHandler`, `RemoteShellHandler`, `AgentSessionHandler`.
- add `RegisteredCall` inflight state map: `call_id → (kind, client_stream_tx, credit_tracker, rolling_sha256_state)`.
- add `dispatch_subscribe`, `dispatch_command_channel`, `dispatch_bulk_transfer`, `dispatch_telemetry`, `dispatch_remote_shell`, `dispatch_agent_session` private methods on `RpcServer`.
- add corresponding client helpers on `RpcClient`: `subscribe_raw`, `command_channel_raw`, `bulk_transfer_raw`, `telemetry_raw`, `remote_shell_raw`, `agent_session_raw`.
- modify `decode_rpc` to accept `RpcClientStream` frames and route them to inflight call.
- update `RpcContext` to carry `initial_chain` (agent-session) and `subscribe_topic`.

**Per-kind invariants the dispatcher MUST enforce:**
- `subscribe` — emit synthetic `seq=-1, more=true, ext.ack="subscribed"` on call accept; emit `seq=-1, more=false, ext.ack="unsubscribed"` on close.
- `command-channel` — emit initial credit grant `seq=-1, ext.credit=N` on call accept; track outstanding credit; refuse to forward server-side message when `credit <= 0`; decrement on send.
- `bulk-transfer` — require `rpc-call.ext.bulk.expected_hash`; accumulate SHA-256 over chunks via `sha2::Sha256::update`; on completion, compare and emit `bulk_hash_verified` in proof event.
- `telemetry` — emit closing `RpcResponse{status: ok, response: null, ext.streaming_priority}` on completion; surface priority in proof event.
- `remote-shell` — refuse server frames whose `ext.shell_stream` is missing or not in `{stdin, stdout, stderr}`; refuse client frames where shell_stream != stdin.
- `agent-session` — read `responsibility_chain` off every `RpcClientStream.ext.responsibility_chain`; emit `ext.responsibility_chain` on every server frame.

**Tests:** `crates/tf-types/tests/rpc_kinds.rs`
- 10 dispatcher tests, one per method kind, mirroring `tools/tf-types-ts/tests/rpc-kinds.test.ts`.
- 6 invariant tests: subscribe-ack-frame-shape, command-channel-credit-exhaustion-blocks-send, bulk-transfer-hash-mismatch-rejects, telemetry-priority-surfaces-in-proof-event, remote-shell-untagged-frame-rejected, agent-session-chain-preserved-end-to-end.
- 1 cross-language byte-parity test: load `conformance/proofrpc-method-kind-vectors.yaml`, encode each fixture in Rust, assert byte-identical to TS-encoded reference bytes.

### A2. Rust TLS extensions

**Files:**
- modify `crates/tf-types/src/bridge_tls.rs` — add `OcspCheck`, `CrlCheck`, `ExporterBinding`, `PostHandshakeReauth` modules.
- new dep: `x509-parser = "0.16"` for cert parsing, `rasn = "0.18"` for OCSP DER, `ureq` (sync) for OCSP HTTP fetch.
- `OcspCheck::query(cert, issuer, ocsp_url)` returns `Good | Revoked | Unknown`.
- `CrlCheck::load(crl_bytes)` parses RFC 5280 CRL; `is_revoked(serial)` is O(log n).
- `ExporterBinding::derive(transport_secret, label, context)` exposes RFC 5705 keying material.
- `PostHandshakeReauth::challenge()` + `verify_response()` for RFC 8446 §4.6.3 post-handshake.

**Tests:** `crates/tf-types/tests/bridge_tls_extensions.rs`
- OCSP good/revoked/unknown round-trip against rfc-2560 fixtures.
- CRL with 1k revoked entries; lookup latency < 1ms median.
- Exporter binding parity with TS via `conformance/tls-exporter-vectors.yaml`.
- Post-handshake reauth: challenge → response → accept; tampered response → reject.

### A3. Rust service-mesh extension

**Files:**
- modify `crates/tf-types/src/bridge_service_mesh.rs` — add real Envoy XFCC parser, Istio AuthN header parser, Linkerd `l5d-client-id` parser.
- delegate to `bridge_spiffe::parse_spiffe_uri` when a SAN URI is `spiffe://`.
- emit `bridge.service_mesh.<envoy|istio|linkerd>.accepted` proof event with the parsed SVID.

**Tests:**
- 12 parsing fixtures, four per mesh, covering happy-path and three malformed-input rejects each.

### A4. Real Cedar policy engine via wasmtime

**Files:**
- new crate `crates/tf-cedar/` — wraps the official `cedar-policy = "4.x"` crate.
- expose `CedarPolicyEngine::new(policy_src, entities)` and `evaluate(query: PolicyQuery) -> PolicyDecision`.
- update `crates/tf-types/src/policy_engine.rs` to delegate to the cedar crate when `engine_hint == "cedar"`.

**TS counterpart:** `tools/tf-types-ts/src/core/cedar-engine.ts` — uses the official `@cedar-policy/cedar-wasm` package.

**Tests:** 8 cedar policy vectors, byte-identical decisions on both sides.

### A5. Real Rego policy engine

**Files:**
- new crate `crates/tf-rego/` — uses `regorus = "0.2"` (pure-Rust Rego interpreter).
- expose `RegoPolicyEngine::new(rego_src)` and `evaluate(query)`.
- TS: `tools/tf-types-ts/src/core/rego-engine.ts` uses `@open-policy-agent/opa-wasm` package.

**Tests:** 6 Rego policy vectors, byte-identical decisions both sides.

### A6. `conformance/binary-format-vectors.yaml`

**Files:**
- new `conformance/binary-format-vectors.yaml` with 8 fixtures (4 `.tfbundle` + 4 `.tfpkt`).
- each fixture: input JSON, expected hex bytes, expected decoded shape.
- new runner in `tools/tf-conformance/src/runner.ts` — `runBinaryFormatVectors(root)`.
- new Rust test harness in `crates/tf-types/tests/binary_format_parity.rs`.
- enable deterministic CBOR encoding on both `cbor-x` (TS) and `ciborium` (Rust): use canonical-CBOR-of-canonical-JSON to guarantee byte parity.

### A7. `.tf/threat-model.yaml`

**Files:**
- new `.tf/threat-model.yaml` validating against `schemas/threat-model.schema.json`.
- enumerates: 9 trust boundaries, 24 threats, 18 mitigations, 6 residual risks.
- referenced from `.tf/agent-contract.yaml`.

### A8. Full `tf` CLI surface

**Files:**
- modify `tools/tf-cli/src/index.ts` — add subcommands:
  - `tf actor {create, list, inspect, revoke, key-rotate}`
  - `tf instance {list, inspect, terminate}`
  - `tf trust-domain {init, federate, verify-federation, list-roots}`
  - `tf bridge {list, install, configure, test}`
  - `tf bridge spiffe {import, federate}`
  - `tf bridge oauth {register-issuer, introspect}`
  - `tf bridge webauthn {register, assert-test}`
  - `tf packet {sign, verify, inspect, fragment, reassemble, simulate-lora}`
  - `tf session {inspect, migrate, rekey, kill}`
  - `tf approval {list, approve, deny, drain}`
  - `tf revoke {actor, instance, capability, key, list, import-orl, export-orl}`
  - `tf plugin {list, install, verify-manifest, sandbox-test}`
  - `tf rpc {call, list-methods, inspect-method}`
  - `tf evidence {assemble, verify, seal, open, anchor, replay, redact}`
  - `tf proof {sign, verify, inspect, derive-pubkey, log-tail}`
  - `tf policy {simulate, validate, lint, explain}`
  - `tf vault {init, unlock, lock, store, retrieve, list, rotate-passphrase}`
  - `tf conformance {run, label, list-categories}`
  - `tf generate {policy, mcp-tool-wrapper, audit-viewer, bridge, proofrpc-service, threat-model, agent-contract, dockerfile, k8s-manifest, terraform-module}`
  - `tf daemon {start, stop, status, reload-config, dump-config}`
  - `tf adapter {install, list, config, test}`
- every subcommand prints `--json` machine-readable output with `--quiet` flag.
- every subcommand has `tf <cmd> --help` long-form text from a generated YAML.

**Tests:** `tools/tf-cli/tests/subcommands.test.ts` — one test per subcommand, snapshot the `--help` and the `--json` empty-state output.

### A9. Kill `tf-cli` shell-out

**Files:**
- locate every `Bun.spawn` / `child_process.exec` call inside `tools/tf-cli/`.
- replace each with native imports of the corresponding library function.
- specifically: `tf packet` calls `signPacket` / `verifyPacket` directly (not shelling out to `tf-packet`); `tf evidence` calls `assembleEvidenceBundle` directly; `tf proof` calls into `tf-types-ts`'s evidence/chain modules directly.

### A10. Conformance failure-path tests

**Files:**
- new `tools/tf-conformance/tests/failure-paths.test.ts`:
  - `runSchemaVectors` rejects fixtures that violate AJV schema.
  - `runSignatureVectors` rejects forged signatures.
  - `runGuardVectors` rejects allow-decisions for forbidden actions.
  - `runBridgeVectors` rejects unsupported bridge kinds.
  - `runFuzzCorpus` rejects accepted-malformed inputs (inverse of normal pass).
  - `runProfileVectors` rejects profile mismatches.
  - `runSecurityRegressions` re-runs all 4 v0.1 regressions plus 8 new ones (vault tamper, ed25519 malleability, replay attack, AEAD tamper, glob-escape, regex-DoS, certificate-chain-bypass, time-skew).

---

## Phase B — Compatibility layer foundations

### B1. HTTP `/v1/decide` endpoint on `tf-daemon`

**Files:**
- modify `tools/tf-daemon/src/index.ts` — add a `Bun.serve` HTTP listener bound to loopback (default `127.0.0.1:8642`) AND a Unix socket (default `~/.trustforge/decide.sock`).
- `POST /v1/decide` accepts:
  ```json
  {
    "actor": "tf:actor:agent:example.com/x" | null,
    "host_token": "<base64 opaque host credential>" | null,
    "host_token_kind": "oauth-jwt" | "clerk-session" | "next-auth-jwt" | "better-auth-session" | "webauthn-assertion" | "mtls-cert-pem" | "spiffe-svid" | "session-cookie" | null,
    "action": "file.write",
    "target": "/etc/passwd",
    "context": { "ip": "1.2.3.4", "user_agent": "..." },
    "trace_id": "..."
  }
  ```
- response:
  ```json
  {
    "decision": "allow" | "deny" | "escalate" | "approval-required" | "log-only",
    "reason": "...",
    "approval_id": "..." | null,
    "proof_id": "...",
    "actor_resolved": "tf:actor:...",
    "trust_level": "T0..T7",
    "authority_mode": "layered" | "replace" | "co-equal",
    "danger_tags": [...]
  }
  ```
- when `host_token` present, daemon dispatches to the right bridge to resolve the actor before policy evaluation.
- requests authenticated via `Authorization: Bearer <admin_token>` from the daemon's vault, OR via Unix socket with `SO_PEERCRED` matching the daemon's owner UID.
- every decision emits a signed proof event with `decision_request` + `decision_result` fields.

**Tests:** `tools/tf-daemon/tests/decide-endpoint.test.ts`
- happy-path: oauth-jwt → allow.
- denied action returns 200 with `decision: "deny"`.
- malformed body → 400.
- missing admin token → 401.
- request with `target` matching forbidden pattern → 200 with `decision: "deny"`.
- batch endpoint `POST /v1/decide-batch` accepts an array, returns array.

### B2. HTTP `/v1/import-credential` endpoint with auto-detection

**Files:**
- modify `tools/tf-daemon/src/index.ts` — `POST /v1/import-credential`:
  ```json
  { "credential": "<base64-or-text>", "hint": "oauth-jwt" | null }
  ```
- new resolver `tools/tf-daemon/src/credential-resolver.ts`:
  - peek first byte: `eyJ...` → JWT → OAuth bridge.
  - `-----BEGIN CERTIFICATE-----` → PEM → TLS bridge.
  - starts with `MII...` → DER cert → TLS bridge.
  - JSON `{credentialId, response: {clientDataJSON, ...}}` → WebAuthn assertion → WebAuthn bridge.
  - JSON `{sub_ids, access_token: ...}` → GNAP → GNAP bridge.
  - `spiffe://...` → SPIFFE bridge.
  - URL `did:...` → DID bridge.
  - opaque session id with `sess_*` prefix → Clerk; `auth_*` → Better Auth; `__Secure-next-auth.session-token` cookie → NextAuth.
- response: `{actor, capabilities, trust_level, bridge_kind, expires_at}`.
- `.tf/bridges.yaml` registry can override auto-detection per `iss` or per `domain`.

**Tests:** 16 fixture-based detection tests, one per credential kind.

### B3. HTTP `/v1/proof/sign` and `/v1/proof/verify`

**Files:**
- `POST /v1/proof/sign` — body is a proof event draft, daemon signs with its identity key and returns `{event_hash, signature}`.
- `POST /v1/proof/verify` — body is a signed event, daemon verifies and returns `{ok, signer_actor, trust_level}`.

### B4. `.tf/bridges.yaml` registry

**Files:**
- new `schemas/bridges-registry.schema.json` — declares known bridges, per-issuer overrides, default profile.
- new `tools/tf-types-ts/src/core/bridges-registry.ts` — `BridgesRegistry.load(yamlPath)`.
- new `crates/tf-types/src/bridges_registry.rs` — Rust mirror.

### B5. `tf-proxy` reverse-proxy binary

**Files:**
- new crate `crates/tf-proxy/` — Rust binary using `hyper` + `tower` + `reqwest`.
- listens on `0.0.0.0:8080` (configurable), forwards to upstream `127.0.0.1:8081`.
- on every incoming request, extracts host token from `Authorization` header / cookies, calls `tf-daemon /v1/decide`.
- decision `allow` → forward to upstream.
- decision `deny` → return 403 with `WWW-Authenticate: TrustForge realm="..."` and reason JSON.
- decision `approval-required` → return 202 with `Location: /tf/approval/<id>`.
- emits proof events for every request.

**Tests:** `crates/tf-proxy/tests/proxy.rs`
- proxy + mock upstream + mock daemon, verify allow/deny/escalate paths.
- TLS termination: proxy serves HTTPS via rustls, forwards as cleartext to upstream.
- WebSocket upgrade: proxy preserves Connection: Upgrade across the decision check.

### B6. WASM-compiled `tf-core`

**Files:**
- new crate `crates/tf-core-wasm/` — re-exports the security-critical functions from `tf-types` (`canonicalize`, `verify_packet`, `evaluate_policy`, `verify_session_migration`, etc.) and compiles to `wasm32-unknown-unknown`.
- `wasm-bindgen` for JS interop.
- output: `dist/tf-core.wasm` + `dist/tf-core.js` glue.
- TS adapters can import this for in-process decisions without an HTTP round-trip.

**Tests:** `crates/tf-core-wasm/tests/wasm.rs` — Node + Bun harness verifying the same decision via wasm matches the native Rust path bit-for-bit.

### B7. Decision-protocol cross-language vectors

**Files:**
- new `conformance/decide-protocol-vectors.yaml` with 24 fixtures.
- runner: every adapter must produce identical bytes when sending the same decision request, and identical decoded structure when receiving the same response.

---

## Phase C — TS / JS framework adapters

Every TS adapter follows the same shape:
- exports a `tfMiddleware({daemonUrl, profile, mode})` factory.
- inspects request for any host token / session.
- calls `tf-daemon /v1/decide` (or in-process via `tf-core.wasm`).
- on `allow`, forwards request and attaches `req.tfActor`, `req.tfDecision`, `req.tfProofId`.
- on `deny`/`approval-required`, short-circuits with the appropriate HTTP response.
- documented per-package: drop-in snippet, observe-only mode flag, profile selection.

### C1. `@trustforge/sdk` core SDK
- in `tools/adapters/ts/sdk/`.
- public API: `class TrustForge { decide(req): Promise<Decision>; importCredential(cred): Promise<Actor>; signProof(event): Promise<SignedEvent> }`.
- transport: HTTP sidecar OR in-process via `tf-core.wasm`.
- tests: 24 — happy/sad path for every public method, both transports.

### C2. `@trustforge/express` Express middleware
- in `tools/adapters/ts/express/`.
- exposes `trustforgeMiddleware({...})` and `tfRequire('action.name')` route guard.
- tests: Express app integration test with supertest, 8 paths.

### C3. `@trustforge/fastify` Fastify plugin
- in `tools/adapters/ts/fastify/`.
- exposes a Fastify plugin that registers `preHandler` hooks.
- tests: Fastify integration, 8 paths.

### C4. `@trustforge/hono` Hono middleware
- in `tools/adapters/ts/hono/`.
- exposes `trustforge()` Hono middleware.

### C5. `@trustforge/bun-serve` Bun.serve adapter
- in `tools/adapters/ts/bun-serve/`.
- exposes `wrapHandler(handler)` returning a `Bun.serve`-compatible handler.

### C6. `@trustforge/koa` Koa middleware
- in `tools/adapters/ts/koa/`.
- exposes Koa middleware.

### C7. `@trustforge/next` Next.js middleware
- in `tools/adapters/ts/next/`.
- exposes a `middleware.ts` template + a route-handler decorator.
- supports both Pages Router and App Router.

### C8. `@trustforge/sveltekit` SvelteKit handle
- in `tools/adapters/ts/sveltekit/`.
- exposes a `handle` hook for `hooks.server.ts`.

### C9. `@trustforge/nestjs` NestJS guard
- in `tools/adapters/ts/nestjs/`.
- exposes `@TrustForgeGuard()` decorator + module.

### C10. `@trustforge/remix` Remix middleware
- in `tools/adapters/ts/remix/`.

### C11. `@trustforge/elysia` Elysia.js plugin
- in `tools/adapters/ts/elysia/`.

### C12. `@trustforge/h3` H3 (Nitro/Nuxt) middleware
- in `tools/adapters/ts/h3/`.

---

## Phase D — TS auth-library integrations

### D1. `@trustforge/better-auth`
- in `tools/adapters/ts/better-auth/`.
- exposes a Better Auth plugin: `betterAuth({ plugins: [trustforgePlugin({...})] })`.
- hooks into `session.fetch` and emits `bridge.better_auth.session_resolved` proof event with derived TF actor.
- tests: full Better Auth happy-path login + TF decision integration.

### D2. `@trustforge/next-auth` (Auth.js)
- in `tools/adapters/ts/next-auth/`.
- exposes a callbacks adapter:
  ```ts
  callbacks: trustforgeCallbacks({...})
  ```
- runs in `jwt`, `session`, `signIn`, `signOut` callbacks.

### D3. `@trustforge/clerk`
- in `tools/adapters/ts/clerk/`.
- exposes `clerkTrustForgeMiddleware()` for Next.js + Express.
- hooks Clerk's `auth()` helper to capture session id, project to TF actor.

### D4. `@trustforge/lucia`
- in `tools/adapters/ts/lucia/`.

### D5. `@trustforge/iron-session`
- in `tools/adapters/ts/iron-session/`.

### D6. `@trustforge/passport`
- in `tools/adapters/ts/passport/`.
- exposes a Passport strategy `TrustForgeStrategy`.

### D7. `@trustforge/firebase-auth`
- in `tools/adapters/ts/firebase-auth/`.

### D8. `@trustforge/supabase-auth`
- in `tools/adapters/ts/supabase-auth/`.

### D9. `@trustforge/workos`
- in `tools/adapters/ts/workos/`.

### D10. `@trustforge/auth0`
- in `tools/adapters/ts/auth0/`.

### D11. `@trustforge/stack-auth`
- in `tools/adapters/ts/stack-auth/`.

### D12. `@trustforge/kinde`
- in `tools/adapters/ts/kinde/`.

### D13. `@trustforge/logto`
- in `tools/adapters/ts/logto/`.

---

## Phase E — Rust framework adapters

### E1. `tf-axum` Tower middleware
- new crate `crates/adapters/axum/`.
- exposes `TrustForgeLayer::new(config)` Tower layer.
- intercepts requests, calls daemon `/v1/decide`, attaches `Extension<TfDecision>` on allow.

### E2. `tf-tonic` gRPC interceptor
- new crate `crates/adapters/tonic/`.
- exposes a Tonic interceptor implementing `tonic::service::Interceptor`.

### E3. `tf-actix-web` middleware
- new crate `crates/adapters/actix-web/`.

### E4. `tf-rocket` fairing
- new crate `crates/adapters/rocket/`.

### E5. `tf-warp` filter
- new crate `crates/adapters/warp/`.

### E6. `tf-poem` middleware
- new crate `crates/adapters/poem/`.

### E7. `tf-salvo` handler
- new crate `crates/adapters/salvo/`.

### E8. `tf-hyper` raw service
- new crate `crates/adapters/hyper/`.

---

## Phase F — Python adapters

Every Python adapter is a separate package under `tools/adapters/python/<name>/` published to PyPI.

### F1. `trustforge-fastapi`
- exposes `TrustForge(daemon_url=...)` instance + `Depends(trustforge.require("file.write"))` dependency.

### F2. `trustforge-django`
- exposes `TrustForgeMiddleware` + `@require_capability("action.name")` view decorator.

### F3. `trustforge-flask`
- exposes `TrustForge(app)` extension + `@trustforge.require_cap("action")` view decorator.

### F4. `trustforge-starlette`
- ASGI middleware.

### F5. `trustforge-pyramid`
- tween factory.

### F6. `trustforge-tornado`
- request handler decorator.

### F7. `trustforge-sanic`
- middleware.

### F8. `trustforge-litestar`
- guard.

### F9. `trustforge-bottle`
- decorator.

---

## Phase G — Go adapters

Every Go adapter under `tools/adapters/go/<name>/`.

### G1. `github.com/trustforge/tf-go-net-http`
- standard `http.Handler` middleware.

### G2. `github.com/trustforge/tf-go-chi`
- Chi-compatible middleware.

### G3. `github.com/trustforge/tf-go-gin`
- Gin middleware.

### G4. `github.com/trustforge/tf-go-echo`
- Echo middleware.

### G5. `github.com/trustforge/tf-go-fiber`
- Fiber middleware.

### G6. `github.com/trustforge/tf-go-iris`
- Iris middleware.

### G7. `github.com/trustforge/tf-go-buffalo`
- Buffalo middleware.

### G8. `github.com/trustforge/tf-go-grpc`
- Go gRPC interceptor.

---

## Phase H — JVM adapters

### H1. `tf-spring-boot` Java filter
- `tools/adapters/jvm/spring-boot/` Maven module.
- Spring Boot auto-configuration + `@TrustForgeRequire("action")` annotation.

### H2. `tf-micronaut`
- Micronaut filter.

### H3. `tf-quarkus`
- Quarkus extension.

### H4. `tf-vertx`
- Vert.x interceptor.

### H5. `tf-ktor` Kotlin
- Ktor plugin.

### H6. `tf-play` Scala
- Play action filter.

### H7. `tf-spark-java`
- SparkJava middleware.

### H8. `tf-helidon`
- Helidon SE middleware.

---

## Phase I — .NET adapters

### I1. `Trustforge.AspNetCore`
- ASP.NET Core middleware + `[TrustForgeRequire("action")]` action filter attribute.

### I2. `Trustforge.OWIN`
- OWIN middleware.

### I3. `Trustforge.MinimalApi`
- Minimal API extensions.

### I4. `Trustforge.SignalR`
- SignalR hub filter.

### I5. `Trustforge.Orleans`
- Orleans grain interceptor.

---

## Phase J — Other-language adapters

### J1. Ruby
- `trustforge` Rack middleware.
- `trustforge-rails` Rails engine.
- `trustforge-sinatra` extension.
- `trustforge-hanami` middleware.

### J2. PHP
- `trustforge/laravel` Laravel package.
- `trustforge/symfony` Symfony bundle.
- `trustforge/slim` middleware.
- `trustforge/wordpress` plugin.

### J3. Elixir
- `trustforge` Plug.
- `trustforge_phoenix` Phoenix integration.

### J4. Erlang
- `trustforge` cowboy middleware.

### J5. Swift
- `TrustForgeVapor` Vapor middleware.
- `TrustForgePerfect` Perfect HTTP middleware.

### J6. Crystal
- `trustforge` Kemal middleware.
- `trustforge` Lucky framework.

### J7. Zig
- `trustforge` zap middleware.

### J8. Haskell
- `trustforge-wai` WAI middleware.
- `trustforge-yesod` Yesod plugin.

### J9. OCaml
- `trustforge-dream` Dream middleware.
- `trustforge-opium` Opium middleware.

### J10. Nim
- `trustforge` Jester middleware.

### J11. Dart
- `trustforge` shelf middleware.

### J12. Lua
- `trustforge` OpenResty/lapis middleware.

### J13. Perl
- `Trustforge::Plack` Plack middleware.

---

## Phase K — Embedded / no_std

### K1. `tf-core-no-std`
- new crate `crates/tf-core-no-std/`.
- `#![no_std]` with optional `alloc` feature.
- exposes: `verify_packet`, `sign_packet`, `verify_relay_authority`, `OfflineRevocationListChecker`, `PacketReceiver` (using `heapless::FnvIndexMap` for the nonce cache when no alloc).
- crypto: `ed25519-compact` (no_std-compatible), `chacha20poly1305` (no_std-compatible), `sha2` (no_std-compatible).
- target: passes `cargo build --target thumbv7em-none-eabihf` and `cargo build --target riscv32imac-unknown-none-elf`.
- binary footprint goal: < 80 KB stripped, including ed25519 + ChaCha20-Poly1305 + SHA-256 + canonical-CBOR.

**Tests:** `cargo test --target thumbv7em-none-eabihf` via QEMU.

### K2. Cortex-M LoRa node example
- `examples/embedded/cortex-m-lora/` STM32WL55 sketch.
- BSP via `embassy-stm32`.
- proves: receive LoRa packet → tf-core-no-std verifies → enqueue ORL check → emit signed proof packet on TX queue.

### K3. ESP32 example
- `examples/embedded/esp32/` esp-idf integration.
- Wi-Fi-connected demo: signs a packet, calls remote tf-daemon over HTTP `/v1/decide`.

### K4. RP2040 example
- `examples/embedded/rp2040/` Pico W demo.

### K5. nRF52 BLE example
- `examples/embedded/nrf52-ble/` Nordic SDK integration.

### K6. RISC-V example
- `examples/embedded/riscv/` ESP32-C3 + bare-metal build.

### K7. AVR (ATmega328) example
- `examples/embedded/avr/` Arduino sketch using Rust-AVR.
- ed25519 verify only (constrained); demonstrates absolute minimum footprint.

### K8. Embedded HAL traits
- `crates/tf-embedded-hal/` — abstractions over radio TX/RX, secure storage (e.g. ATECC608 element), entropy source.
- LoRa HAL trait, BLE HAL trait, NFC HAL trait, secure-element HAL trait.

### K9. Bootloader integration
- `examples/embedded/bootloader/` demo of TrustForge-verified firmware updates: bootloader checks the firmware's `.tfpkt` signature against an actor's pinned key before flashing.

---

## Phase L — OS-level integration

### L1. Linux PAM module
- `tools/native/linux/pam_trustforge/` C module.
- conversational PAM that calls daemon over Unix socket.
- supports `auth`, `account`, `session`, `password` stacks.
- test: `pamtester` against the module + a mock daemon.

### L2. nsswitch module
- `tools/native/linux/libnss_trustforge/` C module.
- resolves `getpwnam` / `getgrnam` against TF actor URIs.

### L3. sudo plugin
- `tools/native/linux/sudo_trustforge/` C plugin.
- consults daemon before `sudo` allows the wrapped command.

### L4. polkit policy backend
- `tools/native/linux/polkit_trustforge/` agent.

### L5. macOS Authorization Plugin
- `tools/native/macos/AuthorizationPlugin/` Objective-C plugin bundle.
- registers in `/etc/authorization` for `system.privilege.taskport` etc.

### L6. macOS PluggableAuthenticationModule
- `tools/native/macos/PAM/` macOS PAM module.

### L7. Windows Credential Provider
- `tools/native/windows/CredentialProvider/` C++ DLL.
- registers as a logon credential provider.

### L8. Windows Authentication Package
- `tools/native/windows/AuthPackage/` LSA-loaded auth package DLL.

### L9. systemd integration
- `tools/native/linux/systemd-trustforge/` `unit-generator` + a `tf-daemon.service` template.

### L10. SELinux policy module
- `tools/native/linux/selinux/trustforge.te` policy source + compiled `.pp`.

### L11. AppArmor profile
- `tools/native/linux/apparmor/usr.bin.tf-daemon` profile.

### L12. macOS LaunchDaemon plist
- `tools/native/macos/com.trustforge.daemon.plist`.

### L13. Windows Service
- `tools/native/windows/TrustForgeService/` C++ service binary.

---

## Phase M — Kernel-grade integration

### M1. Linux LSM module
- `tools/native/linux/lsm_trustforge/` kernel module in C.
- hooks: `inode_permission`, `file_permission`, `socket_create`, `socket_connect`, `bprm_set_creds`.
- communicates with userspace daemon via netlink.
- builds against kernel >= 5.15.

### M2. eBPF program suite
- `tools/native/linux/ebpf/` BCC + libbpf programs.
- LSM hooks via `bpf_lsm_*` programs.
- userspace loader written in Go using `cilium/ebpf`.

### M3. eBPF socket-level decisions
- per-process, per-cgroup connection authorization.

### M4. eBPF filesystem-level
- `bpf_lsm_inode_permission` for read/write/exec gating.

### M5. FreeBSD MAC framework module
- `tools/native/freebsd/mac_trustforge/` C kernel module.

### M6. OpenBSD pledge integration
- `tools/native/openbsd/pledge-trustforge/` userspace shim.

### M7. illumos / Solaris integration
- `tools/native/illumos/` kernel module.

---

## Phase N — Network-equipment firmware

### N1. OpenWRT package
- `tools/native/openwrt/` — Makefile, init script, UCI config.
- `opkg install trustforge` works on a fresh OpenWRT build.
- LuCI web UI page.

### N2. pfSense package
- `tools/native/pfsense/` — pkg manifest + PHP UI integration.

### N3. OPNsense plugin
- `tools/native/opnsense/` — same shape as pfSense.

### N4. VyOS Salt formula
- `tools/native/vyos/`.

### N5. Cisco Guest Shell integration
- `tools/native/cisco/` — Python + IOX guestshell.

### N6. Juniper Junos jet integration
- `tools/native/junos/` — slax + jet apps.

### N7. MikroTik RouterOS package
- `tools/native/routeros/`.

### N8. Ubiquiti UniFi controller plugin
- `tools/native/unifi/`.

### N9. Pi-hole / AdGuard Home integration
- DNS-level authorization decisions.

### N10. Tailscale ACL adapter
- emits Tailscale ACLs from TrustForge policy.

---

## Phase O — Cloud / orchestration integration

### O1. Kubernetes admission webhook
- `tools/native/k8s/admission-webhook/` Go binary.
- `ValidatingAdmissionWebhook` that calls daemon for create/update verdicts.
- Helm chart.

### O2. Envoy filter
- `tools/native/envoy/` WASM filter built from `tf-core-wasm`.
- registered as `envoy.filters.http.wasm`.

### O3. Istio adapter
- `tools/native/istio/` AuthorizationPolicy generator + wasm extension.

### O4. Linkerd plugin
- `tools/native/linkerd/`.

### O5. Consul connect plugin
- intentions backend.

### O6. HashiCorp Vault auth method
- `tools/native/vault/auth-trustforge/` plugin.

### O7. Terraform provider
- `tools/native/terraform/provider-trustforge/`.

### O8. Pulumi provider
- `tools/native/pulumi/`.

### O9. AWS IAM identity provider
- SAML / OIDC bridge that surfaces TF actors as AWS principals.

### O10. GCP IAM identity provider
- Workload Identity Federation pool.

### O11. Azure AD identity provider
- federated credential setup.

### O12. CrowdStrike / SentinelOne EDR integration
- proof event subscription.

### O13. Datadog Cloud SIEM integration
- proof event sink.

---

## Phase P — Persistence backends

### P1. SQLite proof ledger
- `crates/tf-store-sqlite/`.

### P2. PostgreSQL proof ledger
- `crates/tf-store-postgres/`.

### P3. MySQL proof ledger
- `crates/tf-store-mysql/`.

### P4. Redis revocation cache
- `crates/tf-revoke-redis/`.

### P5. S3 evidence archive
- `crates/tf-evidence-s3/`.

### P6. Filesystem `.tflog` backend
- already exists; harden + add rotation, atomic append.

### P7. Sigstore Rekor integration
- `crates/tf-anchor-rekor/`.

### P8. Certificate Transparency log integration
- `crates/tf-anchor-ct/`.

### P9. RFC 3161 timestamp authority client
- `crates/tf-anchor-rfc3161/`.

### P10. Kafka proof event sink
- `crates/tf-sink-kafka/`.

---

## Phase Q — Observability

### Q1. tf-dashboard improvements
- live proof event stream via WebSocket from `tf-daemon`.
- decision histogram per route.
- approval queue UI.

### Q2. Prometheus exporter
- `tools/native/prometheus-exporter/` Rust binary; metrics: `tf_decisions_total{decision}`, `tf_approval_queue_depth`, `tf_revocations_active`, etc.

### Q3. OpenTelemetry tracing
- daemon emits OTel spans for every decision.

### Q4. Grafana dashboard JSON
- `tools/native/grafana/trustforge.json`.

### Q5. Datadog integration
- `dd-agent` config snippet + custom check.

### Q6. Splunk integration
- TA + dashboard XML.

---

## Phase R — Documentation + onboarding

Documentation is treated as a first-class deliverable on the same gate
as code: every adapter, every spec change, every bridge, every
backend ships its docs in the same PR as its implementation. No
adapter is considered done until its docs are written, reviewed, and
running in `docs/` with passing link-check + spell-check.

### R1. Per-language / per-framework quickstart guides
- `docs/integration/typescript/<adapter>.md` × 12 (every TS adapter from Phase C).
- `docs/integration/auth-libraries/<lib>.md` × 13 (every auth-lib integration from Phase D).
- `docs/integration/rust/<adapter>.md` × 8 (every Rust adapter from Phase E).
- `docs/integration/python/<adapter>.md` × 9 (every Python adapter from Phase F).
- `docs/integration/go/<adapter>.md` × 8 (every Go adapter from Phase G).
- `docs/integration/jvm/<adapter>.md` × 8 (every JVM adapter from Phase H).
- `docs/integration/dotnet/<adapter>.md` × 5 (every .NET adapter from Phase I).
- `docs/integration/other-languages/<lang>.md` × 13 (every adapter from Phase J).
- `docs/integration/embedded/<target>.md` × 7 (every embedded target from Phase K).
- `docs/integration/os-level/<target>.md` × 13 (every OS-level integration from Phase L).
- `docs/integration/kernel/<target>.md` × 7 (every kernel integration from Phase M).
- `docs/integration/network-equipment/<target>.md` × 10 (every network-equipment package from Phase N).
- `docs/integration/cloud/<target>.md` × 13 (every cloud integration from Phase O).
- Every quickstart MUST include: 5-minute setup, 30-minute deeper integration, common pitfalls, observability hooks, profile recommendations, security caveats.

### R2. Migration guides
- `docs/migration/from-auth0.md`
- `docs/migration/from-clerk.md`
- `docs/migration/from-next-auth.md`
- `docs/migration/from-better-auth.md`
- `docs/migration/from-spring-security.md`
- `docs/migration/from-django-auth.md`
- `docs/migration/from-passport.md`
- `docs/migration/from-firebase-auth.md`
- `docs/migration/from-supabase-auth.md`
- `docs/migration/from-pam.md`
- `docs/migration/from-okta.md`
- `docs/migration/from-keycloak.md`
- `docs/migration/from-aws-cognito.md`
- `docs/migration/from-azure-ad.md`
- `docs/migration/from-google-identity.md`
- `docs/migration/from-spiffe-spire.md`
- `docs/migration/from-istio-authn.md`
- `docs/migration/from-oauth2-proxy.md`
- `docs/migration/from-pomerium.md`
- `docs/migration/from-buzzfeed-sso.md`
- Every migration guide includes: side-by-side config diff, rollback plan, cut-over strategy, observability checklist, downtime estimate.

### R3. Conceptual guides ("Understanding TrustForge")
- `docs/concepts/actors-vs-instances.md`
- `docs/concepts/trust-domains.md`
- `docs/concepts/capabilities-and-negative-capabilities.md`
- `docs/concepts/policy-decisions.md`
- `docs/concepts/proof-events-and-ledgers.md`
- `docs/concepts/sessions-vs-packets.md`
- `docs/concepts/relays-as-actors.md`
- `docs/concepts/approval-ceremonies.md`
- `docs/concepts/profiles-and-enforcement-levels.md`
- `docs/concepts/trust-levels-t0-to-t7.md`
- `docs/concepts/risk-classes-r0-to-r5.md`
- `docs/concepts/proof-levels-l0-to-l5.md`
- `docs/concepts/enforcement-levels-e0-to-e5.md`
- `docs/concepts/hybrid-pq-cryptography.md`
- `docs/concepts/continuous-authorization.md`
- `docs/concepts/delegation-chains.md`
- `docs/concepts/federation-and-bridges.md`
- `docs/concepts/agent-contracts-for-ai.md`
- `docs/concepts/emergency-authority-and-break-glass.md`
- `docs/concepts/offline-revocation-lists.md`
- Every concept guide is 600-1200 words, has a "what problem this solves" section, a worked example, and a "common misconceptions" section.

### R4. API reference
- `docs/api/typescript/` — TypeDoc-generated reference for every published `@trustforge/*` package.
- `docs/api/rust/` — `cargo doc --all` output for every `tf-*` crate, hosted at `docs.rs/tf-types`.
- `docs/api/python/` — Sphinx-generated reference for every `trustforge-*` package.
- `docs/api/go/` — `pkg.go.dev` style reference for every `tf-go-*` module.
- `docs/api/jvm/` — Javadoc for every `tf-*` Maven artifact.
- `docs/api/dotnet/` — DocFX for every `Trustforge.*` package.
- `docs/api/http/` — OpenAPI 3.1 spec for `tf-daemon` HTTP endpoints, rendered via Redoc.
- `docs/api/proofrpc/` — generated reference for every `.tfrpc.yaml` ProofRPC service.
- `docs/api/cli/` — auto-generated `tf <subcommand> --help` reference for every CLI subcommand.
- `docs/api/wasm/` — JS/TS bindings reference for `tf-core.wasm`.

### R5. Tutorials (long-form, hands-on)
- `docs/tutorials/01-first-decision.md` — make TrustForge enforce one rule on one route.
- `docs/tutorials/02-bring-your-own-auth.md` — drop-in to a repo that has Clerk/NextAuth/Auth0 and observe-only mode.
- `docs/tutorials/03-flip-to-enforcement.md` — graduate observe-only → enforce, including profile change and rollback.
- `docs/tutorials/04-add-a-bridge.md` — write a custom bridge for a proprietary auth system.
- `docs/tutorials/05-write-a-policy.md` — write Cedar / Rego / native TrustForge policy.
- `docs/tutorials/06-emit-proof-events.md` — wire proof events into existing logging/SIEM.
- `docs/tutorials/07-quorum-approvals.md` — set up M-of-N approval ceremonies.
- `docs/tutorials/08-relay-and-mesh.md` — deploy a relay; route packets through it.
- `docs/tutorials/09-offline-mode.md` — air-gap a deployment with offline revocation lists.
- `docs/tutorials/10-embedded-lora-node.md` — flash `tf-core-no-std` to a Cortex-M and exchange packets.
- `docs/tutorials/11-kernel-lsm.md` — load the LSM module and gate sudo with TrustForge.
- `docs/tutorials/12-router-firmware.md` — install on OpenWRT and gate WAN traffic decisions.
- `docs/tutorials/13-kubernetes-admission.md` — deploy the admission webhook + Helm chart.
- `docs/tutorials/14-write-an-agent-contract.md` — make an AI-agent codebase TrustForge-compliant.
- `docs/tutorials/15-evidence-bundles-for-compliance.md` — produce SOC 2 / HIPAA / PCI evidence.
- `docs/tutorials/16-federate-two-trust-domains.md` — sign federation attestations and verify cross-domain identities.
- `docs/tutorials/17-rotate-keys-without-downtime.md` — vault key rotation walkthrough.
- `docs/tutorials/18-debugging-decisions.md` — `tf policy explain` walkthrough, `tf-dashboard` decision histograms.
- `docs/tutorials/19-build-a-custom-adapter.md` — port TrustForge to a language not yet covered.
- `docs/tutorials/20-zero-to-production-checklist.md` — end-to-end production readiness.

### R6. How-to recipes (short, focused)
- `docs/recipes/` × 60+ snippets, each ~200-400 words, answering one question:
  - "How do I deny all writes to /etc when an actor's trust_level < T2?"
  - "How do I require quorum approval for any action with risk_class >= R3?"
  - "How do I exclude a specific Clerk user from TrustForge enforcement?"
  - "How do I ship proof events to Splunk?"
  - "How do I rotate the daemon's signing key without breaking active sessions?"
  - "How do I expire a SPIFFE SVID early?"
  - "How do I sign a `.tfpkt` from a CI pipeline?"
  - "How do I verify an evidence bundle offline?"
  - … (60+ total, growing with the codebase).

### R7. Threat model document
- `docs/threat-model.md` — long-form 30-page document mirroring `.tf/threat-model.yaml`.
- per-component threat tables: session, packet, vault, relay, plugin, bridge, daemon admin, dashboard.
- attacker capabilities matrix (network on-path, host-compromised, kernel-compromised, supply-chain, insider).
- mitigation matrix with explicit "covered by what" per threat.

### R8. Security documentation
- `docs/security/security-review-checklist.md` — what an external reviewer must verify before production.
- `docs/security/cryptographic-primitives.md` — the exact set we use, and why nothing else.
- `docs/security/key-management.md` — how keys are generated, stored, rotated, retired, destroyed.
- `docs/security/supply-chain.md` — how we keep `cargo-deny`, `npm audit`, etc. green; SBOM generation.
- `docs/security/responsible-disclosure.md` — already in `SECURITY.md`, expanded with severity rubric and CVE-issuance plan.
- `docs/security/post-quantum-roadmap.md` — when classical-only suites get deprecated, exact migration plan.

### R9. Specifications (TF-XXXX series)
- All existing `docs/specs/TF-0000` through `TF-0012`.
- New specs landed alongside the implementation:
  - `TF-0013-decision-protocol.md` — the HTTP `/v1/decide` contract.
  - `TF-0014-bridge-registry.md` — the `.tf/bridges.yaml` schema and resolver.
  - `TF-0015-tf-core-no-std.md` — embedded subset of TrustForge.
  - `TF-0016-os-credential-providers.md` — PAM, macOS Authorization, Windows Credential Provider integration shape.
  - `TF-0017-kernel-hooks.md` — Linux LSM + eBPF integration model.
  - `TF-0018-network-equipment-profile.md` — router-firmware-specific constraints.
  - `TF-0019-cloud-orchestration-profile.md` — K8s admission, Envoy filter, mesh adapter shape.
  - `TF-0020-persistent-ledger-backends.md` — pluggable proof-ledger storage.

### R10. Compatibility matrix
- `docs/compatibility-matrix.md` — multi-axis table:
  - language × framework × auth-library × profile × OS × kernel
  - marked `✅ tested in CI`, `🟡 alpha`, `🔴 known broken`, `❌ not supported`.
  - regenerated automatically from CI test outcomes; never hand-maintained.

### R11. Architecture documentation
- `docs/architecture/overview.md` — system overview with mermaid C4 diagrams.
- `docs/architecture/sequence-diagrams.md` — every wire flow rendered as mermaid sequence diagrams (handshake, decision, approval, revocation, federation, packet round-trip, agent-session).
- `docs/architecture/data-flow.md` — what data lives where, retention, encryption-at-rest.
- `docs/architecture/component-boundaries.md` — what tf-types owns vs. tf-daemon vs. tf-cli vs. adapters.
- `docs/architecture/extension-points.md` — every plugin / hook / bridge slot with its contract.

### R12. Reference deployment topologies
- `docs/topologies/single-host.md` — laptop / personal server.
- `docs/topologies/sidecar-per-service.md` — microservice with a per-pod tf-daemon.
- `docs/topologies/centralized-daemon.md` — one shared daemon, many adapters.
- `docs/topologies/mesh-of-relays.md` — multi-region mesh with relay actors.
- `docs/topologies/federated-trust-domains.md` — multi-org federation.
- `docs/topologies/multi-tenant-saas.md` — TrustForge as a multi-tenant control plane.
- `docs/topologies/edge-mesh-lora.md` — LoRa mesh + sometimes-online gateway.
- `docs/topologies/air-gapped.md` — fully offline deployment with sneakernet.
- `docs/topologies/compliance-evidence.md` — compliance-evidence-compatible production layout.

### R13. Operations runbook
- `docs/ops/install.md` — every supported install path (cargo, npm, brew, apt, dnf, docker, helm, terraform, openwrt opkg, pfsense pkg, …).
- `docs/ops/upgrade.md` — version-to-version upgrade procedures with rollback steps.
- `docs/ops/backup-and-restore.md` — vault, ledger, evidence bundles.
- `docs/ops/disaster-recovery.md` — daemon dies, vault corrupted, ledger lost; recovery procedures per scenario.
- `docs/ops/scaling.md` — when to add a daemon, when to shard the ledger, when to add a relay.
- `docs/ops/monitoring.md` — Prometheus/OTel/Grafana setup, alert rules, SLO definitions.
- `docs/ops/incident-response.md` — when a key is compromised, when a bridge issuer gets pwned, when a plugin sandbox escapes.
- `docs/ops/troubleshooting.md` — symptom → diagnosis → fix table for the 50 most common issues.

### R14. CLI reference
- `docs/cli/` — one page per `tf <subcommand>` (~25 pages from Phase A8).
- each page: synopsis, options, examples, exit codes, side effects.
- man pages auto-generated for every subcommand and shipped with the OS packages.

### R15. Schema reference
- `docs/schemas/` — one page per JSON Schema in `schemas/`.
- each page: purpose, every field's meaning, validation rules, valid + invalid example, cross-references.
- generated from JSON Schema annotations, never hand-edited.

### R16. Glossary
- `docs/glossary.md` — every term used in TrustForge with a one-paragraph definition.
- includes: actor, actor instance, trust domain, capability, negative capability, policy decision, approval ceremony, proof event, proof bundle, evidence bundle, transparency anchor, federation attestation, agent contract, threat model, plugin manifest, bridge, profile, conformance label, etc.

### R17. FAQ
- `docs/faq.md` — top 50 questions answered honestly.
- includes: "Why not OAuth?", "Why not OIDC?", "Why not OPA?", "Why not Envoy ext_authz?", "Is this production-ready?", "Why Rust + TS?", "How does this compare to SPIFFE?", "Can I use this without an AI agent?", etc.

### R18. Roadmap
- `ROADMAP.md` already exists; expand with the full phase A-S map and a public Trello-equivalent board (or a markdown table) showing in-progress / done / planned per phase.

### R19. Examples gallery
- `examples/` already exists; add complete runnable examples for every adapter:
  - `examples/express-clerk-trustforge/` — Express + Clerk + TrustForge in observe-only mode.
  - `examples/fastapi-supabase-trustforge/` — FastAPI + Supabase + TrustForge enforcing.
  - `examples/axum-spiffe-trustforge/` — Axum + SPIFFE + TrustForge in mesh.
  - `examples/openwrt-router-trustforge/` — OpenWRT + tf-daemon enforcing WAN policy.
  - `examples/lora-node-tf-core-no-std/` — Cortex-M LoRa node end-to-end.
  - `examples/k8s-admission-trustforge/` — K8s admission webhook + Helm chart.
  - … one per adapter (~50 examples).

### R20. Video / live walkthroughs
- `docs/walkthroughs/` — embedded loom-style screen recordings (linked, hosted externally) of every quickstart.
- transcripts written into the docs page so the docs are usable without watching.

### R21. CHANGELOG (continuous)
- every phase ships a CHANGELOG entry with file paths + tests + breaking-change notes.
- `docs/breaking-changes-by-version.md` — long-form per-major-version breakage table.

### R22. Internationalization
- `docs/i18n/` — translation infrastructure (gettext-style key catalog).
- launch with English; structure ready for community translations.
- all docs marked with `lang: en` frontmatter so a translation system can match them.

### R23. Accessibility
- every doc page passes `pa11y` accessibility checks.
- diagrams have alt-text and equivalent prose descriptions.
- terminal sessions in tutorials are also presented as plain-text transcripts.

### R24. Documentation site
- `docs/.docusaurus/` (or equivalent — Astro Starlight, mdBook, VuePress, …) — one chosen, locked.
- searchable, versioned (one site per major version), with a working dark mode and RSS feed.
- deployed from CI on every merge to `main`; preview deploys per PR.

### R25. Documentation tests
- `tools/docs-test/` — extracts every code block from every doc page and runs it through the relevant linter / type-checker / compiler.
- `npm run docs:test` must be green before any release tag.

---

## Phase S — Test, conformance, hardening

### S1. CLI subcommand integration tests
- one test per `tf <subcommand>` from Phase A8.

### S2. Conformance failure-path tests
- already in Phase A10.

### S3. Cross-adapter round-trip vectors
- `conformance/cross-adapter-vectors.yaml` — request originated from `@trustforge/express` flows through `tf-daemon` to `tf-axum` upstream; decision is identical.

### S4. Fuzz harness for `/v1/decide`
- `tools/tf-conformance/src/fuzz-decide.ts` — 1M random requests, no panics, no 5xx.

### S5. Soak test
- 24-hour continuous flow at 1k decisions/sec; memory ceiling, no leaks.

### S6. Chaos test
- daemon restart mid-decision, relay drops, network partitions, vault re-keying.

### S7. Cross-platform CI matrix
- Linux x86_64 / aarch64, macOS arm64, Windows x86_64, FreeBSD, plus thumbv7em / riscv32imac for `tf-core-no-std`.

### S8. Supply-chain audits
- `cargo-deny`, `npm audit` (already), `pip-audit`, `go mod audit`, `mvn dependency-check`, `bundler-audit`.

### S9. Reproducible builds
- every binary builds reproducibly from the source tree given a pinned toolchain.

### S10. Public security audit
- engage an external auditor; track findings in `docs/audit/`.

---

## Acceptance gate for "TrustForge v1.0 candidate"

All of the above ships and:
- Every adapter passes its drop-in test.
- Cross-adapter round-trip vectors are byte-identical across every language.
- `tf-core-no-std` builds for every embedded target listed.
- Linux LSM + eBPF programs load on a stock kernel and survive 24h soak.
- OpenWRT + pfSense + Junos packages install via their native package managers.
- Public security audit completed; all critical+high findings remediated.
- Every popular auth library adapter has a working migration guide that's been validated by spinning up a real example app from each.

---

## Parallelism and integration contract

Most of this work is parallelisable. To make that safe:

### Shared contracts every parallel agent MUST honour

1. **Decision-protocol wire format** — defined by `conformance/decide-protocol-vectors.yaml` (Phase B7). Every adapter, every language, every transport produces and consumes the same bytes for the same logical request. Any deviation fails the parity test.
2. **Public adapter API shape** — defined per-language in the adapter's quickstart doc (Phase R1). Every TS adapter exposes `tfMiddleware({daemonUrl, profile, mode})`. Every Rust adapter exposes `TrustForgeLayer::new(config)`. Every Python adapter exposes `TrustForge(daemon_url=...).require("action")`. Etc. New language adapters mirror the shape from the same-language style guide.
3. **Proof event format** — every adapter emits `bridge.<adapter_name>.<verb>` events conforming to `schemas/proof-event.schema.json`. The verbs are: `accepted`, `rejected`, `escalated`, `deferred`. Free-form annotations go under `metadata`.
4. **Schema source of truth** — every type lives in `schemas/*.schema.json` first; codegen produces TS / Rust / Python / Go / etc. bindings. Hand-written types in any adapter that diverge from the schema are bugs.
5. **`@trustforge/sdk` (TS) / `tf-types` (Rust)** — every same-language adapter depends on the shared SDK rather than re-implementing the protocol. Other languages depend on the HTTP `/v1/decide` endpoint (Phase B1) instead of porting the protocol.

### File-conflict avoidance

Tasks are scoped so files belong to exactly one parallel agent:

- `crates/tf-types/src/rpc.rs` — Phase A1 only (single agent).
- `crates/tf-types/src/policy_engine.rs` — Phases A4 + A5 (serial, A4 → A5).
- `tools/tf-daemon/src/index.ts` — Phase B1 + B2 + B3 add new route files; index.ts gets short additions in a serial sequence (B1 → B2 → B3).
- `tools/adapters/<lang>/<package>/` — single agent per package, fully independent.
- `crates/adapters/<crate>/` — single agent per crate, fully independent.
- `tools/native/<target>/` — single agent per target, fully independent.
- `docs/integration/<lang>/<adapter>.md` — single agent per page, fully independent.
- `examples/<scenario>/` — single agent per scenario, fully independent.

### Integration verification

After any parallel batch lands, the integration-verification gate runs:

1. `bun test` — full TS test suite (every adapter's unit tests).
2. `cargo test --workspace` — full Rust suite.
3. `tools/tf-conformance/src/cli.ts run --decide-protocol` — replays cross-adapter parity vectors; one byte off and the gate fails.
4. `examples/*/test.sh` — every example app spins up, accepts a known-good request, rejects a known-bad one.
5. `pa11y` + link-check on `docs/`.
6. `cargo deny check`, `npm audit`, `pip-audit`, `go mod audit` — supply-chain green.

If a parallel agent misses any of these gates, its task is reverted on the integration branch and the agent is dispatched again with the failing test linked.

### Recommended parallelism per phase

| Phase | Max parallel agents | Notes |
|---|---|---|
| A1 | 1 | rpc.rs single owner |
| A2 | 1 | bridge_tls.rs single owner |
| A3 | 1 | bridge_service_mesh.rs single owner |
| A4-A5 | 2 (A4 then A5) | policy_engine.rs serial dependency |
| A6-A10 | 5 in parallel | independent files |
| B1-B7 | 4 in parallel after B1 lands | B1 is the foundation; B2/B3/B4/B5/B6/B7 then parallel |
| C1-C12 | 12 in parallel | one agent per TS adapter |
| D1-D13 | 13 in parallel | one agent per auth-lib integration |
| E1-E8 | 8 in parallel | one agent per Rust adapter crate |
| F1-F9 | 9 in parallel | one agent per Python adapter |
| G1-G8 | 8 in parallel | one agent per Go adapter |
| H1-H8 | 8 in parallel | one agent per JVM adapter |
| I1-I5 | 5 in parallel | one agent per .NET adapter |
| J | 13 in parallel | one agent per other-language adapter |
| K1 | 1 | tf-core-no-std single agent |
| K2-K9 | 8 in parallel after K1 | one agent per embedded target |
| L1-L13 | 13 in parallel after B1 | one agent per OS-level integration |
| M1-M7 | 7 in parallel after L lands | one agent per kernel target |
| N1-N10 | 10 in parallel after L lands | one agent per network device |
| O1-O13 | 13 in parallel after B lands | one agent per cloud platform |
| P1-P10 | 10 in parallel | one agent per persistence backend |
| Q1-Q6 | 6 in parallel | one agent per observability target |
| R | continuous; 1-2 per doc per phase as code lands |
| S | continuous; gates the merges |

Maximum theoretical concurrency: ~150 simultaneous agents during the adapter explosion (Phases C-J + K2-K9 + L + N + O + P + Q). The practical ceiling is set by review bandwidth, not by the work itself.

## Execution order

Strict dependency order; nothing skips ahead until its prerequisites land:

1. Phase A (close v0.1 deferrals) — must be 100% green before B starts.
2. Phase B (compatibility-layer foundations: HTTP decide, bridge auto-detect, tf-proxy, wasm core).
3. Phases C, D, E, F, G in parallel (TS / Rust / Python / Go adapters).
4. Phase K (no_std) in parallel with phases C-G.
5. Phases H, I, J (JVM / .NET / other languages) after C completes.
6. Phase L (OS-level) after B + Phase K.
7. Phase M (kernel-grade) after L.
8. Phase N (network-equipment) after L.
9. Phase O (cloud) in parallel with N.
10. Phase P (persistence) in parallel with B.
11. Phase Q (observability) in parallel with the adapter phases.
12. Phase R (docs) tracks every phase as it lands.
13. Phase S (tests/conformance/audit) is a continuous gate — every PR adds the relevant tests; the soak/chaos/audit lands at the end.

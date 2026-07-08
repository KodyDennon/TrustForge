# Changelog

All notable changes to TrustForge are recorded here. Versions follow
[Semantic Versioning](https://semver.org/) once we hit 1.0; before then
the API is explicitly experimental.

Current source metadata is on a patch line: TrustForge npm workspace
packages are at 0.1.6 and publishable Rust workspace crates are at
0.1.9. The sections below track the first public cut plus unreleased
hardening work.

## 0.1.6 / Rust 0.1.9 — Unreleased

### Changed

* Clarified the daemon/local decision contract: TCP `/v1/*` endpoints
  remain bearer-token protected, while the Unix-domain decision socket
  is the local trust boundary for `/v1/decide` and `/v1/decide-batch`.
  Privileged import, proof-signing, admin, and mutation routes remain
  bearer-gated.
* Native Linux integration defaults now point at
  `/run/trustforge/decide.sock`, with per-user sockets treated as test
  or explicit override paths.
* Documentation now separates working references, mock-tested native
  shims, hardware-untested packages, docs-only surfaces, and planned
  release artifacts.

### Fixed

* `tf-schema` fuzzing now marks fixtureless schemas as intentionally
  skipped instead of reporting zero accepted/rejected cases against a
  non-zero iteration count.
* `@trustforge/fastify` now stops request flow after terminal deny,
  approval-required, unknown-decision, or daemon-unreachable replies.
* `tf-daemon run --config <path> --dry-run` and `--print-config` provide
  config preflight and redacted effective-config output without booting
  listeners.

## 0.1.0 — 2026-04-25

First public experimental cut of TrustForge. Core schemas, generated
types, conformance vectors, the Bun daemon, CLI surfaces, and selected
TS/Rust protocol paths are working references. The broader profile,
bridge, native OS, network-device, and release-packaging surface is not
uniformly implemented or production-reviewed.

### Added

#### Specifications and decisions
* `TF-0000` through `TF-0013` published as Draft. `TF-0013` defines the
  site-to-site binary path (length-delimited TCP/TLS framing plus the
  `http-bridge` ProofRPC method kind).
* `DECISIONS.md` records the long-form rationale for early architecture
  choices.
* `GOVERNANCE.md` records the spec process.
* Profiles `tf-home-compatible`, `tf-enterprise-compatible`,
  `tf-constrained-compatible`, `tf-compliance-evidence-compatible`
  flagged out as full normative MUST/SHOULD/MUST_NOT documents.

#### Schemas + types
* 36 domain JSON Schemas plus `_common.schema.json` under `schemas/`
  covering every machine-readable artifact (manifests + runtime
  objects).
* Valid and invalid fixtures for every schema, with `expected-error`
  files describing the failure surface.
* `profile-spec.schema.json` + `conformance-vector.schema.json` formalise
  the conformance gate.
* TypeScript bindings (`tools/tf-types-ts/src/generated/`) and Rust
  bindings (`crates/tf-types/src/generated/`) generated from the same
  source.
* Cross-language parity manifest (`conformance/parity.yaml`) and
  canonical-JSON parity (`conformance/canonical-vectors.yaml`).

#### Cryptography
* ed25519 (RFC 8032) signing/verification with byte-parity vectors.
* X25519 + HKDF-SHA256 + ChaCha20-Poly1305 + ed25519 session protocol.
* SHA-256 / BLAKE3 hashing, hash-chained events, Merkle roots,
  `.tflog` / `.tfproof` framing.
* Argon2id-protected file vault.
* Hybrid post-quantum mode using ml-dsa-44 / -65 / -87 (FIPS 204) for
  signatures.
* RFC 3161 anchoring + RFC 6962 (Certificate Transparency) anchoring
  for evidence bundles.
* RFC 5705 / RFC 8446 exporter keying for transport-binding.

#### Runtime + tooling
* `tools/tf-schema` — validate / lint / bundle / codegen / fuzz / parity
  / agent-contract-check.
* `tools/tf-proof` — keygen / sign / verify / inspect / derive-pubkey.
* `tools/tf-session` — WebSocket session carrier with full handshake +
  in-band rekey.
* `tools/tf-daemon` — Bun.serve daemon with WebSocket session listener,
  admin HTTP endpoint (sessions / approvals / plugins / proofs /
  revocations), AgentGuard enforcement, ApprovalQueue, signed plugin
  manifests, and Worker-isolated native plugin sandbox.
* `tools/tf-packet` — sign / verify / inspect / fragment / reassemble /
  simulate-lora.
* `tools/tf-evidence` — assemble / verify / seal / open / anchor /
  replay / redact.
* `tools/tf-cli` — unified `tf` command: `policy simulate`,
  `actor {create,inspect}`, `trust-domain {init,federate,verify-federation}`,
  `bridge spiffe import`, `packet inspect`, `session inspect`,
  `approval list`, `approve`, `deny`, `revoke`, `plugin list`,
  `rpc call`, `evidence assemble`, `conformance run`,
  `generate <policy|mcp-tool-wrapper|audit-viewer|bridge|proofrpc-service>`.
* `tools/tf-dashboard` — viewer-only HTML dashboard reading the daemon
  admin endpoint.
* `tools/tf-conformance` — runs every conformance category (schema,
  signature, guard, trust-overlay, bridge, interop, fuzz, profile,
  security regression, AI-implementation, compatibility-label) in one
  shot.

#### Compatibility bridges
* WebAuthn (FIDO2 attestation, packed/none/anonca formats, FIDO MDS).
* SPIFFE workload identity (SPIFFE ID ↔ TrustForge actor URI, federated
  bundles, Envoy XFCC, Istio AuthN, Linkerd l5d-client-id).
* OAuth (RFC 6749/6750) and GNAP (RFC 9635) + DPoP (RFC 9449).
* MCP / A2A tool-name normalisation and capability mapping.
* TLS / mTLS with RFC 5705 / RFC 8446 exporter keying.
* DID (W3C DID Core 1.0) with multibase base58btc.
* Matrix events ↔ ProofEvent.
* Webhook bridge with HMAC-SHA256, HMAC-SHA1, ed25519 signature
  schemes.
* gRPC bridge through the service-mesh adapters.

#### Tests
* 553 TypeScript tests across 59 files (Bun test).
* 280+ Rust tests across `tf-types` + `tf-code-helper-example`.
* 120+ parity vectors covering canonical JSON, signature, hashing,
  chain, framing, session, bridge, relay, trust-overlay, guard,
  negative-capability.

#### ProofRPC method kinds (B13)
* All 10 `Method.kind` enum values exercised distinctly: unary,
  server-streaming, client-streaming, bidi-streaming, subscribe (with
  explicit `subscribed` / `unsubscribed` ack frames), command-channel
  (credit-based backpressure), bulk-transfer (SHA-256 hash-verified),
  telemetry (priority-classed), remote-shell (stdin/stdout/stderr
  tagged frames), agent-session (delegation-chain propagation).
* `RpcProofEventStub` carries `method_kind`, `streaming_priority`,
  `bulk_hash_verified` for daemon-side per-kind policy decisions.
* Rust mirror ships wire-format parity (`RpcFrameExt`,
  `RpcClientStream`, `RpcMethodKind` enum); per-kind handler-type
  ergonomics are TS-only for v0.1.0.

#### Constrained mode (B14)
* `PacketReceiver` sliding-window nonce cache with LRU eviction +
  expired-packet rejection.
* `OfflineRevocationListRuntime` — sealed-list verifier; refuses
  expired or unsigned lists.
* `signDeliveryReceipt` / `verifyDeliveryReceipt` for one-way bearers.
* `signProofOfForwarding` / `verifyProofOfForwarding` so a relay can
  attest carriage without seeing plaintext.
* Rust LoRa channel simulation with deterministic xorshift64* RNG.

#### Binary container formats (B15)
* `.tfbundle` — magic + u32 BE length + CBOR-encoded body + optional
  signature trailer; carries `ProofBundle` or `ProofBundleEncrypted`.
* `.tfpkt` — magic + u32 BE length + CBOR-encoded `Packet`.
* Both formats round-trip in TS (`cbor-x`) and Rust (`ciborium`).

### Known limitations
* Drafts are explicitly experimental. Spec line items may change while
  the implementation tracks them.
* No production posture: the threat model in `SECURITY.md` is honest
  about what 0.1.0 does and does not promise.
* No public infrastructure dependency. The daemon's RFC 6962 anchor and
  RFC 3161 anchor stubs run against in-memory test logs unless
  configured against external services.
* Per-kind ProofRPC handler ergonomics are TS-only for v0.1.0; Rust
  ships the wire format and the proof-event surface but reuses the
  generic streaming dispatcher for new kinds (`subscribe`,
  `command-channel`, `bulk-transfer`, `telemetry`, `remote-shell`,
  `agent-session`). Full handler-type parity is a v0.2 concern.
* CBOR byte-level parity between TS (`cbor-x`) and Rust (`ciborium`)
  is round-trip stable but not guaranteed byte-identical without
  deterministic-encoding flags. Cross-language *decode-anything-the-
  other-side-encoded* is the v0.1.0 contract.
* `OfflineRevocationListRuntime`, `PacketReceiver`, delivery receipts,
  and proof-of-forwarding ship in TypeScript only for v0.1.0; Rust
  mirrors of these constrained-mode runtimes are deferred.

# TrustForge Roadmap

## Status snapshot (v0.1.0 candidate)

The phases below describe the design programme. The current codebase
implements substantial portions of phases 0 through 10:

- **Phase 0–4** (seed, types, proofs, sessions, RPC) — implemented in
  both `tools/tf-types-ts/` and `crates/tf-types/`. ProofRPC has all
  10 distinct method kinds with per-kind dispatch on TS and wire-format
  parity on Rust.
- **Phase 5** (agent contract) — schema + validator shipped; `.tf/`
  conventions in use repo-internally.
- **Phase 6** (daemon + CLI) — `tools/tf-daemon` and `tools/tf-cli`
  reach the home-profile feature set; production deployment still
  requires v0.2 hardening.
- **Phase 7** (plugins) — child-process sandbox (sandbox-exec on macOS,
  seccomp on Linux) plus `wasmtime` host integration on Rust.
- **Phase 8** (bridges) — WebAuthn, SPIFFE, OAuth/GNAP, MCP/A2A, TLS
  all shipped on both sides; service-mesh and matrix bridges TS-only.
- **Phase 9** (constrained/offline) — packets, fragmentation,
  PacketReceiver nonce cache, OfflineRevocationListRuntime, delivery
  receipts, proof-of-forwarding, LoRa simulation.
- **Phase 10** (conformance) — 11 runner categories, schema vectors,
  signature vectors, AI-implementation suite, compatibility-label
  runner, CI gate, cargo-deny supply-chain audit.

Anything not listed above is still a v0.2+ concern. This file remains
authoritative for the design programme; the README and CHANGELOG track
shipped state.

## Phase 0: Repository seed

- Write manifesto
- Write decision log
- Define repo structure
- Define RFC-style spec index
- Define initial schemas
- Define AI Agent Contract draft
- Define threat model draft

## Phase 1: Core type system

- Actor IDs
- Actor instance IDs
- Trust domains
- Capabilities
- Negative capabilities
- Risk classes
- Proof levels
- Policy decisions
- Delegation chains
- Revocation objects

## Phase 2: Proof format

- Proof event schema
- Local proof log
- Proof bundle
- Hash-chain verification
- CLI proof inspect/verify

## Phase 3: Session protocol prototype

- Binary framing
- Handshake skeleton
- Mutual authentication
- Session metadata
- Rekey hooks
- WebSocket carried mode

## Phase 4: ProofRPC prototype

- Schema format
- Unary request/response
- Streaming model
- Rust codegen
- TypeScript codegen
- Capability-bound methods

## Phase 5: Agent Contract

- `.tf/agent-contract.yaml`
- validator
- codegen hooks
- AI integration guide
- dangerous action schemas

## Phase 6: Daemon and CLI

- tf-daemon
- key vault abstraction
- approval request handling
- session inspect
- proof inspect
- policy simulate
- actor management

## Phase 7: Plugins

- plugin manifest
- plugin actor identity
- WASM plugin proof of concept
- native Rust plugin proof of concept
- permission sandbox model

## Phase 8: Bridges

- WebAuthn bridge
- SPIFFE bridge
- OAuth/GNAP bridge
- MCP/A2A bridge
- TLS/mTLS bridge

## Phase 9: Constrained and offline profile

- packet mode
- offline command packet
- fragmentation
- LoRa-style simulation
- priority classes
- emergency packets

## Phase 10: Conformance

- test vectors
- protocol traces
- fuzzing
- interoperability tests
- compatibility labels

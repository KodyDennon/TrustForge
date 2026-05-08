# TrustForge Roadmap

## Status snapshot (v0.1.0 experimental, v0.2 hardening in progress)

The phases below describe the design programme. The current codebase
implements substantial portions of phases 0 through 10, but the
implementation is not uniform across every language, bridge, native OS,
or package target:

- **Phase 0–4** (seed, types, proofs, sessions, RPC) — implemented in
  both `tools/tf-types-ts/` and `crates/tf-types/`. ProofRPC has all
  10 distinct method kinds with per-kind dispatch on TS and wire-format
  parity on Rust.
- **Phase 5** (agent contract) — schema + validator shipped; `.tf/`
  conventions in use repo-internally.
- **Phase 6** (daemon + CLI) — `tools/tf-daemon` and `tools/tf-cli`
  are working references. v0.2 hardening is focused on installability,
  local socket contracts, and truthful release artifacts.
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

Anything not listed above is still a v0.2+ concern. The native status
source is [`docs/native-support-matrix.md`](docs/native-support-matrix.md);
the README and CHANGELOG track shipped state.

## v0.2 hardening priorities

- Keep the full local gate green: Bun tests, workspace typecheck,
  conformance runner, Cargo tests, and Cargo all-target checks.
- Lock the local auth contract: TCP `/v1/*` uses bearer auth; Unix
  `/run/trustforge/decide.sock` uses filesystem/group/peer trust for
  local decision callers; privileged mutation endpoints stay bearer
  gated.
- Prefer Linux source + systemd install first, then container and
  Kubernetes wiring, then binary tarballs and deb/rpm-style packages.
- Keep native integration docs honest: every surface must state status,
  tested environment, daemon dependency, install method, rollback, and
  known gaps.

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

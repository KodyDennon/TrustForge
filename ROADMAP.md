# TrustForge Roadmap

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

# TrustForge — Complete Initial Decisions

This document captures the major architecture, product, protocol, and governance decisions from the initial TrustForge brainstorming session.

## Core identity of the project

TrustForge is not merely an authentication library.

TrustForge is intended to become an open-source trust fabric for the next era of software: humans, AI agents, services, sites, devices, organizations, relays, plugins, tools, processes, models, and sessions all operating through verifiable identity, authenticated communication, explicit authority, policy, and proof.

The central thesis:

> The next era of security is not just login. The next era is verifiable action by cryptographic actors over authenticated channels.

## Scope decision

TrustForge should be broad by design.

It should support:

- human authentication
- AI-agent authentication
- AI-to-site authentication
- site-to-site authentication
- service-to-service secure communication
- device authentication
- secure live communication
- secure RPC
- authenticated streaming
- offline proof packets
- mesh and relay routing
- LoRa/constrained radio profiles
- remote admin/control channels
- enterprise policy
- home/self-hosted deployments
- compliance/legal evidence
- local-first and offline-capable trust
- AI-readable implementation contracts
- plugins and extensibility
- formal conformance

The project should avoid becoming “just another login system.”

## Communication modes

TrustForge supports both Live Mode and Packet Mode.

### Live Mode

Live Mode is for real-time authenticated sessions, streaming, RPC, event channels, remote admin, AI tool sessions, telemetry, service-to-service communication, and bidirectional communication.

### Packet Mode

Packet Mode is for standalone signed/encrypted packets that can be transported over unreliable, delayed, offline, constrained, air-gapped, or mesh networks.

Packet Mode supports:

- offline command packets
- delayed messages
- store-and-forward
- USB/file transfer
- QR-code transfer
- radio packets
- LoRa-style communication
- serial links
- air-gapped approval/proof transfer
- emergency packets
- proof bundles

## Session migration

Session migration is core.

An TrustForge trust relationship should be able to move between transports while preserving session lineage and trust continuity.

Examples:

- local IPC to WebSocket
- WebSocket to QUIC
- TCP to offline packet mode
- BLE to internet relay
- radio packet to resumed live session
- WebSocket to ProofWire native transport
- internal service channel to high-performance ProofRPC stream

Migration should preserve or explicitly update:

- actor identity
- actor instance identity
- peer identity
- authority grants
- proof chain
- session lineage
- transport binding
- cryptographic keys
- sequence state or resumed sequence state
- risk state
- policy state

## Relay and mesh forwarding

Untrusted relay and mesh forwarding are core.

A relay may transport TrustForge packets, but only endpoints may decrypt, authorize, approve, or execute them.

Relays should be able to forward packets without gaining access to payload contents.

TrustForge should support:

- relay-routed live sessions
- relay-routed packet delivery
- mesh forwarding
- store-and-forward relays
- emergency relays
- public relays
- organization relays
- device relays
- marine/vehicle/field relays
- LoRa gateways
- offline drop relays

## Relay identity

Relays are first-class actors.

Relays have:

- actor identity
- actor instance identity when applicable
- trust level
- policy constraints
- forwarding permissions
- reputation
- revocation state
- proof obligations
- route constraints

Relays cannot authorize application actions unless separately granted authority. Forwarding authority and action authority are separate.

## LoRa and constrained network support

LoRa and similar constrained networks are in scope, but TrustForge should not become pigeonholed as a LoRa-only system.

LoRa is one constrained profile among many.

The constrained transport profile should support:

- tiny packets
- fragmentation and reassembly
- high latency
- lossy delivery
- low bandwidth
- battery-aware behavior
- short emergency packets
- compact binary encoding
- optional compression
- packet priority
- offline routing
- store-and-forward
- delayed proof sync

Other constrained targets include:

- serial
- BLE
- radio
- marine telemetry
- field sensors
- embedded devices
- no_std Rust devices
- low-power devices
- disaster networks

## Packet priority

Policy-controlled packet priority is core.

TrustForge should define priority classes such as:

- P0 emergency / distress / safety-critical
- P1 identity, revocation, approval, and security control
- P2 live command/control
- P3 normal messages/events
- P4 telemetry/background sync
- P5 bulk transfer/proof log backfill

Priority must be policy-controlled to prevent abuse.

Actors may need explicit permission to send high-priority packets.

Relays may rate-limit or restrict priority classes.

False emergency use should be logged and may trigger revocation or downgrade.

## Emergency / break-glass authority

Emergency authority is core.

Emergency authority must be:

- explicit
- scoped
- time-limited
- heavily logged
- reviewable
- revocable
- policy-controlled
- visible in proof logs
- optionally subject to post-event quorum review

Emergency use cases include:

- vessel distress
- medical systems
- remote IT recovery
- lost connectivity
- disaster response
- critical infrastructure recovery
- AI safety intervention
- account recovery
- emergency device access
- incident response

## Actor URI

TrustForge requires a universal actor URI format from day one.

The actor URI should support:

- human actors
- AI agent actors
- AI agent instances
- devices
- services
- sites
- organizations
- relays
- plugins
- processes
- tools
- model-serving systems
- local-only actors
- domain-scoped actors
- federated actors
- global portable actors
- temporary/session actors

Example shapes:

```text
tf:actor:human:example.com/kody
tf:actor:agent:local/code-helper
tf:actor:device:honesttechservices.com/backup-box-01
tf:actor:service:spiffe/example.org/ns/prod/sa/api
tf:actor:model-provider:openai/gpt-service
tf:actor:relay:public/relay-8841
tf:actor:org:honesttechservices.com
tf:actor:process:local/pid-4812
tf:actor:plugin:tf-spiffe-bridge
```

## Actor versus actor instance

Actor identity and actor instance identity are separate core concepts.

An actor is the named entity.

An actor instance is a concrete running or active instance of that entity.

Example:

```text
actor: tf:actor:agent:example.com/code-helper
instance: tf:instance:agent:example.com/code-helper/macbook/session-9912
```

This distinction matters for:

- AI agents
- processes
- containers
- browser sessions
- device sessions
- service replicas
- local model runtimes
- plugins
- remote support sessions

## Model identity

Model identity is optional provenance metadata by default.

A model usually does not directly hold authority. The agent/runtime/service using the model is the authority-bearing actor.

However, TrustForge should be able to record model provenance:

```text
human -> agent instance -> model used -> tool -> action
```

A model-serving system may be an authority-bearing service actor.

The model itself is normally recorded as provenance, not as the responsible actor.

## AI-readable implementation manifests

AI-readable implementation manifests are core from day one.

TrustForge should provide machine-readable files such as:

- tf-spec.yaml
- tf-protocol.schema.json
- tf-threat-model.md or .yaml
- tf-rust-rules.md
- tf-conformance-tests.json
- tf-codegen-manifest.toml
- tf-agent-contract.schema.json
- tf-policy-decision.schema.json

Purpose:

- allow AI coding agents to implement TrustForge correctly
- support code generation
- support conformance testing
- prevent AI-generated protocol drift
- make codebases security-legible to AI systems

## Code generation

Spec-driven code generation is core from day one.

TrustForge should support generators such as:

```bash
tf generate rust-server
tf generate rust-client
tf generate typescript-client
tf generate policy
tf generate mcp-tool-wrapper
tf generate audit-viewer
tf generate bridge spiffe
tf generate bridge webauthn
tf generate proofrpc-service
tf generate agent-contract
```

Code generation should be based on schemas, manifests, and conformance tests.

## Agent Contract

Agent Contract files are core from day one.

Every TrustForge-enabled project should be able to expose a machine-readable file such as:

```text
.tf/agent-contract.yaml
```

The Agent Contract tells AI agents:

- available actions
- required permissions
- dangerous operations
- approval requirements
- proof requirements
- safe integration points
- forbidden areas
- test commands
- security boundaries
- allowed codegen targets
- policy hooks
- escalation rules

This is a key differentiator.

TrustForge should make codebases legible and safely interactable by AI agents.

## Dynamic permission negotiation

Dynamic permission negotiation is core.

AI agents and other actors may request exactly the permissions they need during task execution.

Example flow:

```text
agent requests broad file edit permission
policy denies broad permission
agent requests narrow permission for /src/auth.rs for 10 minutes
human approves
permission is granted
agent performs action
proof event is recorded
permission expires
```

Negotiation is controlled by policy.

## Proof logs and proof storage

Proof logs support all of the following:

- local append-only logs
- organization proof servers
- federated proof exchange
- public transparency logs
- timestamp authorities
- optional blockchain anchoring
- offline proof bundles

TrustForge should not force one proof storage model.

## Blockchain-like properties

TrustForge may use blockchain-like cryptographic properties where useful.

In scope:

- signed events
- append-only event chains
- hash-linked proof logs
- Merkle roots
- distributed verification
- public/federated transparency logs
- optional timestamp anchoring
- optional blockchain anchoring

Out of scope as core requirements:

- coins
- tokens
- mining
- proof-of-work
- speculative financial systems
- global consensus for every action
- requiring a public blockchain to use TrustForge

TrustForge should be described as using cryptographic proof chains and optional transparency anchoring, not as a blockchain project.

## Native proof ledger and bundle formats

Native TrustForge proof ledger/bundle formats are core.

Examples:

- `.tfproof`
- `.tflog`
- `.tfbundle`

These formats should contain:

- signed events
- hash chains
- timestamps
- approvals
- actor IDs
- actor instance IDs
- session references
- policy decisions
- proof levels
- payload commitments
- verification metadata
- optional external anchors

## Compliance and legal evidence

Compliance/legal-evidence awareness is core.

TrustForge should not claim automatic compliance.

TrustForge should produce verifiable records useful for:

- audit
- legal review
- compliance programs
- MSP operations
- medical systems
- finance
- government
- maritime
- enterprise AI
- remote access
- device firmware control
- customer support sessions

TrustForge should be able to record:

- who approved remote access
- who accessed sensitive records
- what AI agent touched client data
- who authorized firmware updates
- what technician ran which commands
- what device sent emergency data
- which policy allowed or denied an action

## Tiered proof levels

Tiered proof levels are core.

Initial example:

- L0: no proof
- L1: session proof only
- L2: action proof
- L3: payload hash proof
- L4: encrypted evidence bundle
- L5: compliance-grade notarized proof

Proof level should be policy-controlled by action, actor, domain, risk, environment, and profile.

## Trust levels

TrustForge defines base trust levels with custom policy overlays.

Initial example:

- T0: Unknown
- T1: Self-claimed
- T2: Locally trusted
- T3: Organization-issued
- T4: Hardware-backed
- T5: Multi-party verified
- T6: Publicly attestable
- T7: Regulated/compliance verified

Organizations can customize overlays, but the base levels provide interoperability.

## Composable and contextual trust

Trust is composable and context-aware.

Trust is not a single static score.

Trust may depend on:

- actor identity
- actor instance identity
- hardware-backed key
- human approval
- passkey/YubiKey proof
- device posture
- network path
- relay path
- session age
- rekey state
- policy decision
- revocation status
- risk class
- transport type
- emergency mode
- compliance profile
- recent behavior
- proof level

## Compatibility bridge specs

Formal compatibility bridge specs are first-class parts of TrustForge.

Bridge specs should include:

- TrustForge-WebAuthn Bridge
- TrustForge-SPIFFE Bridge
- TrustForge-OAuth Bridge
- TrustForge-GNAP Bridge
- TrustForge-MCP Bridge
- TrustForge-A2A Bridge
- TrustForge-Matrix Bridge
- TrustForge-TLS Bridge
- TrustForge-DID Bridge
- TrustForge-Webhook Bridge
- TrustForge-gRPC Bridge
- TrustForge-Service-Mesh Bridge

TrustForge should integrate with existing systems instead of pretending they do not exist.

## RFC-style specification series

TrustForge should be written as an RFC-style specification series from day one.

Initial RFC-style documents:

- TF-0000: Manifesto
- TF-0001: Core Architecture
- TF-0002: Actor Identity
- TF-0003: ProofWire Transport
- TF-0004: Capabilities and Policy
- TF-0005: Proof Events and Ledgers
- TF-0006: AI Agent Contract
- TF-0007: ProofRPC
- TF-0008: Plugins and Extensions
- TF-0009: Compatibility Bridges
- TF-0010: Conformance and Governance
- TF-0011: Constrained / LoRa / Offline Profile
- TF-0012: Compliance Evidence Profile

## Conformance and certification

Formal conformance and compatibility profiles are core from day one.

Example labels:

- TrustForge-Core Compatible
- TrustForge-Secure-Session Compatible
- TrustForge-Proof-Compatible
- TrustForge-Agent-Compatible
- TrustForge-Device-Compatible
- TrustForge-Bridge-Compatible
- TrustForge-Constrained-Compatible
- TrustForge-Compliance-Evidence-Compatible
- TrustForge-ProofRPC-Compatible

Conformance should include:

- test vectors
- protocol traces
- fuzzing corpus
- interoperability tests
- profile-specific tests
- security checks
- AI implementation checks

## Policy model

TrustForge defines the policy model, decision format, proof requirements, and policy hooks.

TrustForge supports:

- OPA/Rego
- Cedar
- custom policy backends
- plugin policy engines
- future TrustForge-native policy profile/language

TrustForge should not overcommit to a native policy language too early, but it must define the canonical decision model.

## Human approval ceremonies

Human approval ceremonies are core protocol concepts.

Supported ceremony types may include:

- click approval
- passkey approval
- YubiKey tap
- mobile push
- multi-party approval
- time-delay approval
- emergency override
- physical presence proof
- customer-present approval
- biometric-backed platform approval where appropriate
- hardware-token approval
- signed offline approval packet

Approval records must be proof events.

## Quorum approval

Quorum/multi-party approval is core, but policy-controlled.

It can be turned on/off by:

- action type
- actor type
- risk class
- organization rule
- environment
- trust domain
- compliance profile
- emergency mode

Example policies:

- firmware update requires 2 of 3 maintainers
- emergency override requires captain + engineer
- production deployment requires owner + security approver
- AI high-risk action requires user + organization policy service
- remote support requires technician + customer presence

## Delegation chains

Delegation chains are core.

TrustForge must track:

- who delegated authority
- what authority was delegated
- who received it
- whether it can be re-delegated
- how long it lasts
- what policy allowed it
- what proof supports it
- when it expires
- whether it was revoked

Example:

```text
human:kody
-> delegates limited authority to agent:code-helper
-> agent delegates one file-read task to subagent:scanner
-> subagent calls tool:repo-indexer
-> tool accesses file:/src/auth.rs
```

## Negative capabilities

Negative capabilities / explicit denials are core.

Explicit denials can override broad grants.

Example:

```text
agent can edit /src
BUT cannot edit /src/auth/
BUT cannot delete files
BUT cannot push to main
BUT cannot access secrets
```

This is critical for AI-agent safety.

## Risk classes

Risk classes are core protocol concepts with custom overlays.

Initial example:

- R0: harmless/read-only/public
- R1: low-risk normal action
- R2: sensitive read or limited write
- R3: privileged operation
- R4: destructive/financial/security-impacting
- R5: emergency/life-safety/irreversible

Policies may use risk class to require proof, approval, reauthentication, quorum, emergency review, or blocking.

## Revocation

Revocation is core and high-priority across live, packet, mesh, relay, and offline modes.

Revocation applies to:

- actor identity
- actor instance
- device key
- session
- delegation grant
- capability
- approval
- relay trust
- emergency authority
- plugin
- proof anchor
- bridge
- compromised AI agent instance

Revocation should support:

- priority packets
- revocation receipts
- offline-safe expiration limits
- proof events
- propagation across relays
- continuous authorization updates

## Expiration

Expiration is mandatory/default for authority-bearing objects.

Applies to:

- sessions
- delegations
- capabilities
- approvals
- offline commands
- emergency authority
- relay forwarding grants
- AI permissions
- proof requests

Permanent authority should be exceptional and explicitly justified.

## Continuous authorization

Continuous authorization is core.

A session is not merely authorized at login.

TrustForge may re-check trust based on:

- actor behavior
- device posture
- session age
- transport migration
- route/relay change
- risk level increase
- new requested capability
- revocation events
- human presence expiration
- emergency mode
- plugin changes
- proof failure

## Rekeying and ratcheting

Session rekeying and cryptographic ratcheting are core.

Rekeying may occur:

- every N minutes
- every N messages
- after transport migration
- after privilege escalation
- after relay/path change
- after emergency mode starts
- after policy change
- after plugin/bridge change
- after risk increase

## Post-quantum and hybrid readiness

Post-quantum/hybrid readiness is core from day one.

TrustForge should be crypto-agile.

It should support negotiation of:

- classical key exchange/signatures
- post-quantum key exchange/signatures
- hybrid classical + post-quantum modes
- hardware-backed signing
- constrained-device lightweight profiles
- future algorithms

The first implementation may start with practical modern classical suites, but the spec must be designed for PQ/hybrid migration immediately.

## Plugin system

A formal plugin/extension system is core.

Plugins may support:

- transports
- identity bridges
- policy engines
- proof backends
- approval ceremonies
- crypto suites
- storage layers
- AI-agent integrations
- device profiles
- hardware keys
- constrained networks
- dashboards
- code generation
- compliance exports

## Plugin identity

Plugins are first-class actors.

Plugins have:

- actor identity
- trust level
- permissions
- proof obligations
- revocation state
- conformance profile
- declared capabilities
- declared risk surface

## Plugin sandboxing

Plugin sandboxing and least-privilege permissions are core.

A plugin should declare:

- what it does
- what permissions it needs
- what trust level it can assert
- what proof events it emits
- what data it can see
- what actions it can perform
- what risks it introduces
- which TrustForge profile it conforms to

## WASM plugins

WASM is a supported portable plugin runtime alongside native Rust plugins.

WASM is preferred for portable, sandboxed, cross-language, AI-generated, and lower-risk plugins.

Native Rust plugins remain necessary for:

- high-performance transport
- hardware keys
- crypto
- OS-level integration
- embedded systems
- low-level networking

## Threat-model files

Formal machine-readable threat-model files are core from day one.

Example:

```text
.tf/threat-model.yaml
```

They should define:

- protected assets
- trusted actors
- untrusted actors
- allowed transports
- dangerous actions
- approval requirements
- replay risks
- offline packet risks
- relay/mesh risks
- AI-agent risks
- plugin risks
- compliance requirements
- failure modes
- enforcement level

## Simulation and testing

Simulation/testing modes are core.

TrustForge should simulate:

- AI agent permission requests
- compromised relays
- expired offline packet replay
- emergency break-glass
- transport migration
- revocation propagation
- quorum approval failure
- LoRa packet loss
- plugin failure
- policy denial
- proof log corruption
- delegated authority misuse

## Shadow mode

Digital twin / shadow mode is core.

TrustForge should be able to run beside an existing app and:

- observe auth decisions
- simulate policy enforcement
- generate proof logs
- warn about unsafe actions
- avoid blocking production behavior
- help teams migrate safely

## Progressive enforcement

Progressive enforcement levels are core.

Example:

- E0: observe only
- E1: warn only
- E2: require proof logging
- E3: require policy approval
- E4: block unauthorized action
- E5: fail-closed / high-security mode

This allows gradual adoption.

## Standard action schemas

Standard action schemas are core.

Common actions should have shared semantics across systems.

Examples:

- file.read
- file.write
- file.delete
- shell.exec
- network.connect
- email.send
- database.query
- record.view
- record.modify
- payment.initiate
- device.config.update
- firmware.install
- model.invoke
- agent.delegate
- relay.forward
- proof.anchor
- session.migrate
- approval.request
- emergency.invoke

Applications may define custom actions, but TrustForge should standardize common and dangerous actions.

## ProofRPC

ProofRPC is a first-class TrustForge profile from day one.

ProofRPC is for:

- AI-to-site authentication
- AI agent to SaaS/tool communication
- website-to-website authenticated communication
- service-to-service secure RPC
- internal backend RPC
- device-to-cloud telemetry
- browser/client to backend live sessions
- backend-to-backend proof-aware message bus
- fast authenticated binary communication

ProofRPC should be a possible “RPC killer” where identity, permission, encryption, replay protection, proof, and policy are built into the session instead of bolted onto headers.

## ProofRPC schema-first design

ProofRPC is schema-first.

A service schema should define:

- methods/actions
- input/output types
- required capabilities
- risk class
- proof level
- approval rules
- streaming type
- policy hooks
- conformance tests
- code generation targets

## ProofRPC method types

ProofRPC supports:

- unary request/response
- server streaming
- client streaming
- bidirectional streaming
- event subscription
- command channels
- bulk transfer
- telemetry streams
- remote shell streams
- agent/tool session streams

## Home and enterprise through profiles

TrustForge supports simple home/self-hosted mode and enterprise/federated mode from the same architecture.

Profiles control complexity.

Examples:

- Home profile
- Small business/MSP profile
- Enterprise profile
- Public/federated profile
- Embedded profile
- Constrained/offline profile
- Compliance evidence profile
- AI-agent profile
- Critical infrastructure profile

## Dashboard

A local/admin trust dashboard is a core reference app.

It should show:

- active actors
- active AI agents
- active sessions
- approved devices
- pending permission requests
- recent proof events
- emergency events
- revoked actors
- installed plugins
- relay status
- proof ledger health
- policy decisions
- approval requests
- trust domain status

## CLI

The CLI is first-class from day one.

Example commands:

```bash
tf actor list
tf session inspect
tf approve request-123
tf revoke actor device:backup-box-01
tf proof verify event.tfproof
tf policy simulate agent:code-helper file.delete
tf bridge spiffe import
tf rpc call service.method
tf plugin list
tf trust-domain init
tf packet inspect packet.tfpkt
```

The CLI is essential for:

- developers
- sysadmins
- AI coding agents
- conformance testing
- home deployments
- emergency recovery
- debugging
- automation

## TrustForge daemon

A local TrustForge daemon / agent service is core.

The daemon may handle:

- local actor identity
- key storage
- hardware key access
- session management
- approval prompts
- policy decisions
- proof logging
- plugin loading
- Agent Contract enforcement
- local RPC
- device/service discovery
- dashboard backend
- trust domain operations
- relay operations

## Secure local key vault

TrustForge includes a secure local key vault abstraction from day one.

It should integrate with:

- software key vault
- OS keychain
- TPM
- Secure Enclave
- Android/iOS hardware-backed keys
- YubiKey
- passkeys/WebAuthn
- smart cards
- HSMs
- recovery keys
- device enrollment keys
- agent instance keys
- emergency authority keys

## Hardware-backed identity and approval

Hardware-backed identity and approval are first-class.

Supported categories:

- YubiKey
- passkeys/WebAuthn authenticators
- TPM
- Secure Enclave
- Android/iOS hardware-backed keys
- smart cards
- HSMs
- manufacturer device certificates
- hardware security modules

## Identity model

TrustForge uses a hybrid identity model.

It supports:

- domain-scoped identity
- global portable identity
- local-only identity
- federated identity
- temporary/session identity

TrustForge always records the trust context being used.

## Authority model

TrustForge uses a multi-root / policy-rooted authority model.

Authority may come from:

- owner
- organization
- manufacturer
- hardware key
- federation
- government/compliance issuer
- local emergency authority
- public transparency anchor
- trust domain
- policy engine

Policy decides which roots matter for each action.

## Spec and implementation relationship

TrustForge is spec-and-reference together.

The spec defines the contract.

The Rust reference implementation proves it works.

Neither should drift from the other.

## Default design rule

When deciding whether TrustForge should support a serious capability, the default is yes if it can be:

- modular
- profile-based
- policy-controlled
- plugin-safe
- conformance-testable
- not forced on lightweight deployments

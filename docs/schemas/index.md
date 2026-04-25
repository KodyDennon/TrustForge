# TrustForge Schemas

This directory is generated from `schemas/*.schema.json` by
`tf-schema codegen --target docs`. Do not edit by hand.

| Schema | Spec | Description |
| --- | --- | --- |
| [_common](./_common.md) | underlies every other schema | Shared $defs referenced by every other TrustForge schema |
| [actions](./actions.md) | TF-0006 | Catalog of action definitions referenced by TF-0006 agent contracts. |
| [actor-identity](./actor-identity.md) | TF-0002 | Identity document that binds an actor URI to public keys, authority roots, and validity (TF-0002). |
| [agent-contract](./agent-contract.md) | TF-0006 | Declarative contract that makes a TrustForge-enabled codebase legible and safe for AI agents |
| [approval-ceremony](./approval-ceremony.md) | — | Discriminated record describing how an approval was (or must be) collected |
| [approval-request](./approval-request.md) | — | A pending approval request raised by the daemon when a guarded action requires explicit human approval. |
| [approval-response](./approval-response.md) | — | A signed response to an ApprovalRequest. |
| [bridge-descriptor](./bridge-descriptor.md) | — | Declarative descriptor for a TrustForge compatibility bridge |
| [capability-token](./capability-token.md) | TF-0004 | Serialized capability grant carried across actors (TF-0004). |
| [conformance](./conformance.md) | TF-0010 | Manifest describing which TrustForge profiles a deployment claims to implement (TF-0010) |
| [conformance-vector](./conformance-vector.md) | — | A single conformance vector consumed by tf-conformance runners |
| [daemon-config](./daemon-config.md) | — | Configuration file for a running tf-daemon instance (.tf/daemon.yaml). |
| [dangerous-actions](./dangerous-actions.md) | — | Canonical catalog of action names with their danger tags and default enforcement |
| [evidence-bundle](./evidence-bundle.md) | — | Compliance / legal evidence bundle (TF-0012) |
| [federation-attestation](./federation-attestation.md) | — | Cross-trust-domain attestation: domain A signs a statement asserting that domain B's identity (or a specific actor in B) is recognized within A's trust fabric, optionally bounded by capability scope and time |
| [offline-revocation-list](./offline-revocation-list.md) | — | Bounded-validity revocation list distributed for offline / constrained deployments (TF-0011 "offline revocation limits") |
| [packet](./packet.md) | — | Standalone signed/encrypted object that may be delivered offline, relayed, stored, or transferred and verified later |
| [packet-bundle](./packet-bundle.md) | — | A group of related packets (e.g |
| [packet-fragment](./packet-fragment.md) | — | Fragmentation header attached to a Packet when its payload is too large for the underlying transport (LoRa MTU, BLE characteristic size, etc.) |
| [permission-grant](./permission-grant.md) | — | Daemon-signed reply to a PermissionRequest |
| [permission-request](./permission-request.md) | — | An AI agent's typed request to acquire authority for a specific action, target, and duration |
| [plugin-manifest](./plugin-manifest.md) | — | Declarative manifest describing a TrustForge plugin |
| [policy](./policy.md) | TF-0004 | Declarative policy definition referenced by TF-0004 |
| [policy-decision](./policy-decision.md) | — | Structured result emitted by a TrustForge PolicyEngine |
| [profile-spec](./profile-spec.md) | — | Declarative profile specification (TF-0010 conformance label + TF-0001 'profiles control complexity') |
| [proof-bundle](./proof-bundle.md) | TF-0005 | JSON representation of a .tfproof bundle (TF-0005) |
| [proof-bundle-encrypted](./proof-bundle-encrypted.md) | — | Encrypted variant of .tfbundle (proof level L4) |
| [proof-event](./proof-event.md) | TF-0005 | Signed record of an important event (TF-0005) |
| [proof-profile](./proof-profile.md) | TF-0005 | Declarative profile describing which proof events to emit and how (TF-0005). |
| [proofrpc](./proofrpc.md) | — | Declarative RPC service definition consumed by tf-schema codegen --target rpc-ts|rpc-rust |
| [relay-authority](./relay-authority.md) | — | Encodes the distinction between forwarding authority and action authority |
| [revocation](./revocation.md) | TF-0004 | Revocation record that invalidates a capability, actor, delegation, or instance (TF-0004). |
| [session-migration](./session-migration.md) | — | Signed record describing a TrustForge session being moved between transports while preserving session_id, generation, and trust continuity (TF-0003 "session migration"). |
| [threat-model](./threat-model.md) | TF-0006 | Declarative threat-model manifest referenced by TF-0006 and by agent-contract.references.threat_model. |
| [transport-binding](./transport-binding.md) | — | Describes the underlying transport a TrustForge session is currently bound to |
| [vault-file](./vault-file.md) | — | Passphrase-encrypted key vault on disk |

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
| [daemon-config](./daemon-config.md) | — | Configuration file for a running tf-daemon instance (.tf/daemon.yaml). |
| [dangerous-actions](./dangerous-actions.md) | — | Canonical catalog of action names with their danger tags and default enforcement |
| [plugin-manifest](./plugin-manifest.md) | — | Declarative manifest describing a TrustForge plugin |
| [policy](./policy.md) | TF-0004 | Declarative policy definition referenced by TF-0004 |
| [policy-decision](./policy-decision.md) | — | Structured result emitted by a TrustForge PolicyEngine |
| [proof-bundle](./proof-bundle.md) | TF-0005 | JSON representation of a .tfproof bundle (TF-0005) |
| [proof-event](./proof-event.md) | TF-0005 | Signed record of an important event (TF-0005) |
| [proof-profile](./proof-profile.md) | TF-0005 | Declarative profile describing which proof events to emit and how (TF-0005). |
| [proofrpc](./proofrpc.md) | — | Declarative RPC service definition consumed by tf-schema codegen --target rpc-ts|rpc-rust |
| [revocation](./revocation.md) | TF-0004 | Revocation record that invalidates a capability, actor, delegation, or instance (TF-0004). |
| [threat-model](./threat-model.md) | TF-0006 | Declarative threat-model manifest referenced by TF-0006 and by agent-contract.references.threat_model. |
| [vault-file](./vault-file.md) | — | Passphrase-encrypted key vault on disk |

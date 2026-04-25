# TrustForge Schemas

This directory is generated from `schemas/*.schema.json` by
`tf-schema codegen --target docs`. Do not edit by hand.

| Schema | Spec | Description |
| --- | --- | --- |
| [_common](./_common.md) | underlies every other schema | Shared $defs referenced by every other TrustForge schema |
| [actions](./actions.md) | TF-0006 | Catalog of action definitions referenced by TF-0006 agent contracts. |
| [actor-identity](./actor-identity.md) | TF-0002 | Identity document that binds an actor URI to public keys, authority roots, and validity (TF-0002). |
| [agent-contract](./agent-contract.md) | TF-0006 | Declarative contract that makes a TrustForge-enabled codebase legible and safe for AI agents |
| [capability-token](./capability-token.md) | TF-0004 | Serialized capability grant carried across actors (TF-0004). |
| [conformance](./conformance.md) | TF-0010 | Manifest describing which TrustForge profiles a deployment claims to implement (TF-0010) |
| [dangerous-actions](./dangerous-actions.md) | — | Canonical catalog of action names with their danger tags and default enforcement |
| [policy](./policy.md) | TF-0004 | Declarative policy definition referenced by TF-0004 |
| [proof-bundle](./proof-bundle.md) | TF-0005 | JSON representation of a .tfproof bundle (TF-0005) |
| [proof-event](./proof-event.md) | TF-0005 | Signed record of an important event (TF-0005) |
| [proof-profile](./proof-profile.md) | TF-0005 | Declarative profile describing which proof events to emit and how (TF-0005). |
| [proofrpc](./proofrpc.md) | — | Declarative RPC service definition consumed by tf-schema codegen --target rpc-ts|rpc-rust |
| [revocation](./revocation.md) | TF-0004 | Revocation record that invalidates a capability, actor, delegation, or instance (TF-0004). |
| [threat-model](./threat-model.md) | TF-0006 | Declarative threat-model manifest referenced by TF-0006 and by agent-contract.references.threat_model. |

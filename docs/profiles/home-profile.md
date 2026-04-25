# Home Profile

## Status

Draft.

## Purpose

The `tf-home-compatible` profile targets single-operator deployments — home automation, personal devices, family mesh networks, hobbyist labs. It optimises for ease of bootstrap, not multi-tenant audit. There is one human, the daemon runs locally, the vault is on the same machine, and the proof log is the operator's own audit trail.

## MUST features

| Feature id | Spec |
|---|---|
| `agent-contract` | TF-0006 |
| `proof-log` | TF-0005 |
| `ed25519` | SECURITY.md |
| `vault` | TF-0001 |

## SHOULD features

| Feature id | Spec |
|---|---|
| `webauthn` | TF-0009 |
| `shadow-mode` | DECISIONS.md |

## Enforcement floor

`min_enforcement_level: E3` — escalations are required to surface to the operator UI; lower levels (E0, E1, E2) reduce to log-only and would not be appropriate for a profile that has only one operator to consult.

## Proof level floor

`min_proof_level: L1` — every action emits a signed event, but transparency anchoring is not required.

## What this profile does NOT promise

- No quorum approvals (single-operator profile).
- No federated trust; cross-domain identities are not recognised.
- No transparency-log anchoring; the local `.tflog` is the only audit trail.

## Migration to enterprise

Switching to `tf-enterprise-compatible` requires adding policy-engine, quorum-collector, continuous-reauth, transparency anchoring, and federation. A home daemon CAN add WebAuthn and stay within this profile.

## Related specs

- [TF-0001 — Core Architecture](../specs/TF-0001-core-architecture.md)
- [TF-0010 — Conformance and Governance](../specs/TF-0010-conformance-governance.md)

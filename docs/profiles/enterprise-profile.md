# Enterprise Profile

## Status

Draft.

## Purpose

The `tf-enterprise-compatible` profile targets multi-tenant enterprise deployments: business-unit isolation, federated trust between subsidiaries / partners, policy engines that block dangerous actions, quorum approvals for high-risk operations, and external transparency anchoring so audits cannot rewrite history.

## MUST features

| Feature id | Spec |
|---|---|
| `policy-engine` | TF-0004 |
| `quorum-collector` | TF-0004 |
| `continuous-reauth` | TF-0004 |
| `transparency-anchor.any` | TF-0005 |
| `federation` | TF-0002 |
| `webauthn` | TF-0009 |
| `agent-contract` | TF-0006 |

## SHOULD features

| Feature id | Spec |
|---|---|
| `shadow-mode` | DECISIONS.md |
| `hybrid-pq` | TF-0003 |

## Required bridges

`webauthn`, `oauth`, `spiffe`. Enterprise deployments routinely need passkey-style human auth (WebAuthn), workforce SSO (OAuth/GNAP), and workload identity (SPIFFE).

## Required anchors

`rfc6962` — at least one Certificate Transparency log so high-risk decisions land in an externally observable audit trail.

## Enforcement floor

`min_enforcement_level: E4` — block unauthorized actions. Enterprise deployments do not run in shadow mode; every guard decision is enforced.

## Proof level floor

`min_proof_level: L2` — every action emits a signed event with a hash chain back to the previous event.

## Quorum

Quorum approvals are required for any action whose `risk_class` is R4 or R5 OR whose `danger_tags` include `irreversible` / `legal-exposure` / `financial`. The default quorum is 2-of-3 (operator + manager + auditor).

## What this profile does NOT promise

- It does not by itself satisfy `tf-compliance-evidence-compatible` — compliance adds L4 encrypted bundles, L5 RFC 3161 anchoring, and signed log events.
- It does not require packet mode; choose `tf-constrained-compatible` if your deployment is offline / LoRa.

## Related specs

- [TF-0001](../specs/TF-0001-core-architecture.md), [TF-0002](../specs/TF-0002-actor-identity.md), [TF-0004](../specs/TF-0004-capabilities-policy.md), [TF-0005](../specs/TF-0005-proof-events-ledgers.md), [TF-0010](../specs/TF-0010-conformance-governance.md)

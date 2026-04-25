# Compliance Evidence Profile

## Status

Draft.

## Purpose

The compliance-evidence profile (TF-0012) describes a TrustForge deployment whose primary goal is producing tamper-evident, replayable, legally meaningful records of every privileged action. It is the profile MSPs, healthcare operators, finance/treasury teams, government agencies, maritime fleets, critical-infrastructure operators, remote-support vendors, enterprise AI platforms, device-management programs, and firmware-control programs select when they need to be able to answer, after the fact:

- **Who acted** (`actor_id`, `instance_id`, full provenance chain)
- **What authority** (capability tokens, delegation chain, negative capabilities considered)
- **What policy decided** (`policy_decision.schema.json` with `policy_manifest_hash`)
- **What approval was given** (`approval_response.schema.json` + `approval_ceremony.schema.json`, including ceremony kind)
- **Whether quorum was met** (`quorum_outcomes` with N-of-M signers)
- **What system executed** (the daemon's signed log events)
- **What proof was generated** (proof level L0–L5, hash-chained `.tflog`)
- **When it happened** (`evaluated_at`, `signed_at`, `created_at`, `migrated_at`)
- **Whether the chain is tamper-evident** (verifiable hash chain + transparency anchor)

## MUST features

A daemon claiming `tf-compliance-evidence-compatible` MUST:

1. Run with EnforcementLevel ≥ E2 (proof logging required) at minimum, E4 (block unauthorized) for production.
2. Sign every log event before append using the daemon's identity key (`appendSignedEventLine`).
3. Capture and persist a `PolicyDecision` for every evaluated action; the decision MUST carry `policy_manifest_hash` so an auditor can replay the decision against the exact policy manifest active at the time.
4. Capture a `ApprovalCeremony` record alongside every `ApprovalResponse`. `kind: click` is acceptable for low-risk actions; `kind: passkey` / `yubikey` / `mobile-push` / `quorum` / `physical-presence` / `offline-signed-packet` / `biometric` are required at higher risk.
5. Resolve quorum-bound approvals through `QuorumApprovalCollector` and persist the resulting `quorum_outcomes` entry.
6. Emit `evidence-bundle.schema.json` documents on demand via `tf-evidence assemble`. Each bundle MUST include the full `events`, `policy_decisions`, `approvals`, `ceremonies`, and `quorum_outcomes` for the incident window.
7. Support L4 (encrypted evidence bundle) sealing per recipient via X25519+HKDF+ChaCha20-Poly1305.
8. Support L5 (notarized) anchoring via at least one of: RFC 6962 Certificate Transparency log, sigstore Rekor, RFC 3161 Time-Stamping Authority.

## SHOULD features

1. Anchor every L4+ bundle to at least two independent backends.
2. Apply field-level redaction (`tf-evidence redact`) before sharing bundles externally; secrets and PII redacted by `hash` or `drop`.
3. Maintain an offline `proof_log_path` mirror so the local hash-chain is recoverable even if the primary store is compromised.
4. Run continuous reauthorization (`triggers: [revocation, session_rekey, time]`) on long-lived RpcServer connections so revoked credentials terminate in-flight operations.

## Conformance tests

A deployment claiming this profile MUST pass these conformance vectors:

- `conformance/proof-bundle-vectors.yaml` (signature + chain integrity)
- `conformance/canonical-vectors.yaml` (canonical JSON byte-exact)
- `conformance/policy-vectors.yaml` (engine determinism)
- The evidence-pipeline integration test: assemble → seal → anchor → open → verify.

`tf conformance run --profile tf-compliance-evidence-compatible` exercises the full set.

## Proof level expectations

| Action class | Minimum level | Anchor required |
|---|---|---|
| `file.read` / `record.view` | L1 | no |
| `file.write` / `record.modify` | L2 | no |
| `shell.exec` / `key.sign` / `payment.*` | L3 | yes (any) |
| `firmware.install` / `device.reset` / `account.delete` | L4 | yes (≥ 1) |
| `emergency.invoke` | L5 | yes (≥ 2) |

## Security expectations

- **Crypto**: ed25519 (RFC 8032) classical; ml-dsa-65 hybrid available behind suite negotiation; ChaCha20-Poly1305 for AEAD; SHA-256 for chain hashing; HKDF-SHA256 for key derivation; X25519 for key wrapping. No custom primitives.
- **Key custody**: daemon signing keys MUST live in the encrypted vault (Argon2id KDF). Hardware-backed keys (YubiKey, Secure Enclave, TPM) SHOULD be used where available; `T4` is the floor trust level for human approvers operating under this profile.
- **Time discipline**: all timestamps are RFC 3339 UTC `Z`-suffixed. Clocks MUST be synchronized; replay protection on session frames requires monotonic clocks.
- **Recovery**: emergency / break-glass authority is allowed but every invocation MUST produce a follow-up post-event quorum review packet within `T_review` (default 24h) or the bundle is flagged as incomplete.

## What this profile does NOT promise

- Per [`SECURITY.md`](../../SECURITY.md), TrustForge cannot make any organization automatically compliant. The profile produces verifiable records; the organization remains responsible for treating those records as part of its compliance program.
- Anchoring backends are external; the profile assumes the operator chooses backends with appropriate audit history (e.g. a CT log they trust, a TSA they have a contract with).

## Related specs

- [TF-0005 — Proof Events and Ledgers](../specs/TF-0005-proof-events-ledgers.md)
- [TF-0012 — Compliance Evidence Profile](../specs/TF-0012-compliance-evidence-profile.md)
- [DECISIONS.md "Compliance and legal evidence"](../../DECISIONS.md)

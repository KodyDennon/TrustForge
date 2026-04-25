---
name: TrustForge v0.1.0 spec-vs-impl audit (2026-04-24)
description: Snapshot of the major gap categories found while auditing the codebase against the full spec corpus on 2026-04-24, in support of the v0.1.0 release
type: project
---

The user (Kody) is preparing TrustForge v0.1.0 and wants every specced behavior implemented before cutting the release. Phases 0–8 of ROADMAP.md were declared "done" by the user, but the audit found that the spec corpus (TF-0000…TF-0012, DECISIONS.md, profiles, bridges, ai-implementation.md) demands a substantial superset of what ROADMAP.md enumerates.

**Why:** ROADMAP.md is a build plan; DECISIONS.md and the TF-XXXX series are the normative contract. The user explicitly asked me to surface drift, even on items not in ROADMAP.

**How to apply:** When estimating remaining work for v0.1.0, treat ROADMAP.md as a (very rough) lower bound. The full-spec gap surface includes: packet mode, transparency-anchor submission, policy engine binding (cedar/rego), TLS post-handshake auth, DID + Matrix bridges, GNAP semantics beyond JWT, conformance compatibility-label tooling, profiles wired into code, EnforcementLevel applied anywhere, hybrid PQ signatures actually exercised, session migration, relay-as-actor with separate forwarding/action authority, dashboard, and CLI completeness (`tf revoke`, `tf approve`, `tf packet`, `tf rpc`, `tf trust-domain`, `tf bridge`, `tf plugin`, `tf conformance`).

Confirmed in code on 2026-04-24:
- All packages and crates remain at version `0.0.0`.
- No CHANGELOG.md, no CONTRIBUTING.md.
- README.md says "Phases 0–7 done" — stale (Phase 8 has shipped).
- Rust crate `tf-types` does not include `bridge_mcp.rs` or `bridge_webauthn.rs` (TS has both); `BridgeKind` enum lists Mcp + Webauthn but no concrete bridge types/tests.
- ProofRPC schema only allows `unary | server-streaming` — TF-0007 mandates 10 method kinds.
- ApprovalQueue has only "approve"/"deny" — no ceremony types (passkey, YubiKey, mobile push, time-delay, multi-party, physical-presence, customer-present, biometric, offline signed approval packet).
- `tf policy simulate` calls `AgentGuard.fromContract`, NOT a policy engine over policy.schema.json. The policy schema exists but has no interpreter.
- `EnforcementLevel` enum exists in `_common.schema.json`/generated types but is not referenced by any other schema or runtime path.
- No packet schema (`.tfpkt` / packet envelope / fragmentation / priority class / emergency packet).
- No `.tfbundle` writer/reader (only `.tflog` and `.tfproof`).
- No transparency-log submitter or inclusion-proof verifier — schema field exists, no code.
- No DID bridge, no Matrix bridge, no Webhook bridge, no gRPC bridge, no Service-Mesh bridge.
- TLS bridge does basic chain validation but not post-handshake auth, OCSP/CRL, exporter-keying, or session-migration to TrustForge native session.
- OAuth bridge is JWT verification only — no GNAP continuous grant, no DPoP, no token introspection, and a placeholder `public_key: "AA=="` is hardwired.
- No revocation propagation, no offline revocation list, no revocation receipts, no priority delivery.
- No session migration, no continuous reauth wiring, no transport binding object.
- Profiles (home/enterprise/constrained/compliance) are 1-paragraph stubs in `docs/profiles/` and have no runtime selection / feature gating.
- `tf-cli` has only `policy simulate`, `actor create`, `actor inspect`. Missing every other CLI command listed in DECISIONS.md ("CLI" section).
- Conformance suite has 7 vectors files but no compatibility-label runner, no published format spec, no protocol traces, no fuzzing corpus, no interop suite, no profile-test directories.
- No dashboard.
- Hybrid PQ: SignatureEnvelope schema has `alt_algorithm`/`alt_signature` fields, but no signing or verification path uses them — `KNOWN_ALGORITHMS` lists ml-dsa-* but they are never invoked.

This memory is a 2026-04-24 snapshot; verify each item against the current tree before relying on it.

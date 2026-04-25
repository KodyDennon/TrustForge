# TrustForge Phase 8 — Compatibility Bridges Design

**Date:** 2026-04-24
**Status:** Draft, approved for implementation planning
**Scope:** Roadmap Phase 8 — compatibility bridges to existing standards. This phase lands the common bridge framework and three concrete bridges: SPIFFE, WebAuthn, and MCP. OAuth/GNAP and TLS/mTLS bridges are deliberately deferred to a follow-up phase.

## 1. Purpose

Make TrustForge interoperable with existing identity/capability/tooling standards instead of replacing them:

- A SPIFFE SVID should resolve to a TrustForge actor URI with no data loss.
- A WebAuthn-attested credential should produce a valid actor-identity document that downstream TrustForge code can consume.
- An MCP server's declared tools should be projectable as TrustForge agent-contract actions (and vice versa) so an AI agent discovering an MCP endpoint gets the same contract guarantees as one discovering `.tf/agent-contract.yaml`.

## 2. Non-goals

- **No OAuth/GNAP bridge in this phase.** Real OAuth token verification requires JWKS fetch + caching + clock skew handling; we'll ship it when we land a daemon HTTP client.
- **No TLS/mTLS bridge in this phase.** Real certificate-chain verification needs a trust store + OCSP/CRL; Phase 9 has time.
- **No real WebAuthn attestation chain verification.** The bridge parses an already-extracted credential (public key bytes + user handle + RP ID) and builds an actor-identity. Chain verification against AAGUIDs + FIDO metadata is out of scope for the prototype.
- **No MCP server hosting.** The bridge translates between MCP tool descriptors and agent-contract actions, and offers a `callMcpTool(rpc, toolName, args)` helper that assumes the MCP transport is already wired by the caller — it does not implement the MCP JSON-RPC server itself.

## 3. Schema

New `schemas/bridge-descriptor.schema.json` — a bridge registration manifest (`.tf/bridge.yaml`):

```yaml
bridge_version: "1"
bridge_id: tf-webauthn-bridge        # kebab-case
kind: webauthn | spiffe | mcp | oauth | tls
trust_domain: example.com             # TrustForge trust domain accepting input
description: "Accepts WebAuthn credentials, produces actor-identity documents."
config:
  # kind-specific structured config, validated per-kind at runtime.
  type: object
  additionalProperties: true
```

3 fixtures per schema (valid + 2 invalid).

## 4. Common bridge framework

New `tools/tf-types-ts/src/core/bridges.ts` and `crates/tf-types/src/bridges.rs`:

- `BridgeRegistry.register(bridge: Bridge)` — bridges implement a minimal trait/interface.
- `BridgeRegistry.get(kind): Bridge | undefined`.
- Standard error type: `BridgeError { code: "unsupported"|"invalid-input"|"rejected"|"internal"; message }`.
- Each concrete bridge exports a `project*` / `accept*` function per its contract (see below).

## 5. SPIFFE bridge

Input: a SPIFFE ID string, e.g. `spiffe://example.org/ns/prod/sa/api`.

Output: a TrustForge ActorId `tf:actor:service:example.org/ns/prod/sa/api`.

Reverse projection: given `tf:actor:service:<trust-domain>/<path>`, produce `spiffe://<trust-domain>/<path>`. Non-service actor types produce a `BridgeError { code: "unsupported" }`.

TS + Rust implementations. `conformance/bridge-vectors.yaml` pins inputs and expected outputs so both languages agree byte-for-byte.

## 6. WebAuthn bridge

Input: a structured `WebAuthnCredential` (already extracted from the browser's `PublicKeyCredential`):

```ts
type WebAuthnCredential = {
  credential_id: string;       // base64url
  public_key: string;          // base64, raw COSE/ECDSA or ed25519 public key bytes
  algorithm: "ed25519" | "p256" | "rsa-pss-sha256";
  rp_id: string;               // e.g. "example.com"
  user_handle: string;         // base64 (opaque user ID from RP)
  aaguid?: string;             // authenticator identifier, optional
  attestation_format?: "none" | "packed" | "fido-u2f" | "tpm";
};
```

Output: a valid `ActorIdentity` document (`schemas/actor-identity.schema.json`) where:
- `actor_id = tf:actor:human:<rp_id>/<base64url(user_handle)>`
- `actor_type = human`
- `public_keys = [{ key_id, algorithm, public_key, purpose: "signing" }]`
- `trust_levels = ["T4"]` (hardware-backed, per TF-0002)
- `authority_roots = [{ kind: "hardware-key", id: aaguid ?? "(unknown)" }]`

Reverse: given an ActorIdentity and an expected `rp_id`, extract the (public_key, algorithm, user_handle) triple needed to re-register the credential. Rejects identities whose authority_root isn't `hardware-key`.

TS only for this phase; Rust is a mechanical mirror that can ship with a Phase 9 caller.

## 7. MCP bridge

The Model Context Protocol ([spec](https://modelcontextprotocol.io/)) describes tools as `{ name, description, inputSchema }`. A TrustForge agent-contract describes actions as `{ name, risk, approval, parameters?, danger_tags?, ... }`.

Two projections:

- **Import (MCP → contract)**: given an MCP `tools/list` response + a default risk class + an optional danger-tag map, produce a `contract.actions[]` entry per tool. Caller-supplied defaults fill in risk and approval. Schema validity is enforced.
- **Export (contract → MCP)**: given a contract, emit an MCP-shaped tool list. Each action becomes `{ name, description, inputSchema: action.parameters ?? {type:"object"} }`. Actions with `danger_tags` get a conservative `description` prefix ("⚠️ destructive").

Bonus helper: `callMcpTool(rpc, toolName, args)` issues the matching TrustForge RPC call through an existing `RpcClient` — the MCP wire encoding (JSON-RPC) is handled by the caller's transport; the bridge just provides the typed mapping.

TS only for this phase.

## 8. Repository additions

```
schemas/
  bridge-descriptor.schema.json
  fixtures/bridge-descriptor/valid/*.yaml
  fixtures/bridge-descriptor/invalid/*.yaml

tools/tf-types-ts/src/core/
  bridges.ts            # BridgeRegistry + shared types
  bridge-spiffe.ts      # TS SPIFFE
  bridge-webauthn.ts    # TS WebAuthn
  bridge-mcp.ts         # TS MCP

crates/tf-types/src/
  bridges.rs            # Bridge + BridgeRegistry + BridgeError
  bridge_spiffe.rs      # Rust SPIFFE (only kind with a Rust mirror this phase)

conformance/
  bridge-vectors.yaml   # SPIFFE ↔ ActorId byte-exact pairs, both runtimes

tools/tf-types-ts/tests/
  bridges.test.ts       # SPIFFE, WebAuthn, MCP
crates/tf-types/tests/
  bridges.rs            # SPIFFE parity against the shared vectors
```

## 9. Phases

1. **B1** — `bridge-descriptor.schema.json` + fixtures + codegen; validate-all + lint + parity green.
2. **B2** — common framework: `BridgeRegistry`, `BridgeError`, the `Bridge` trait/interface.
3. **B3** — SPIFFE bridge in both languages + `conformance/bridge-vectors.yaml` byte-exact parity.
4. **B4** — WebAuthn bridge in TS; tests cover ed25519 + p256 + rsa-pss-sha256 credentials, RP-ID round-trip, reverse projection.
5. **B5** — MCP bridge in TS; tests cover MCP→contract, contract→MCP, round-trip, and the `callMcpTool` helper.
6. **B6** — CI: wire new tests into the workflow, add the new codegen target paths, final sweep.

## 10. Done criteria

- 23 JSON schemas (adds `bridge-descriptor`), all valid-all / lint / parity green.
- SPIFFE bridge produces byte-identical mappings in TS and Rust against pinned vectors.
- WebAuthn bridge accepts a credential and produces a schema-valid ActorIdentity.
- MCP bridge round-trips a tool list ↔ contract projection.
- `bun test` stays at ≥200 tests passing; Rust workspace stays 0 warnings.
- Full-stack e2e continues to pass unchanged.

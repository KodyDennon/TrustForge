# TrustForge

**TrustForge** is an open-source trust fabric for AI-native software, secure devices, authenticated live systems, site-to-site communication, service-to-service communication, and verifiable action.

> Who or what is acting, under what authority, through what session, with what permissions, under what policy, across what transport, and with what verifiable proof?

TrustForge's core thesis: the next era of security is not login; it is **verifiable action by cryptographic actors over authenticated channels**.

The project is split into a **spec series** (see [`docs/specs/`](docs/specs/)) and a reference implementation in TypeScript (Bun) and Rust. Both are alive, tested, and cross-checked against each other.

This is the **0.1.0** release. Every documented profile, bridge, and protocol surface has a working reference implementation in both languages, gated behind a conformance suite. Nothing is production-ready — this is a 0.1.0 cut intended for spec review, interop experiments, and contributors.

---

## What ships in 0.1.0

| Sprint | Surface |
|---|---|
| Phase 0 — Schemas + types | 36 JSON Schemas with valid/invalid fixtures, TS + Rust codegen, schema linter, fuzz harness, cross-language parity |
| Phase 2 — Proof format | ed25519 (RFC 8032), SHA-256 / BLAKE3, hash-chained events, Merkle roots, `.tflog` + `.tfproof` framing |
| Phase 3 — Session protocol | X25519 + HKDF-SHA256 + ChaCha20-Poly1305 + ed25519, AEAD frames, in-band rekey, WebSocket carrier |
| Phase 4 — ProofRPC | Unary + server-streaming + client-streaming + bidi RPC, `.tfrpc.yaml` codegen for TS + Rust |
| Phase 5 — Agent Contract | `.tf/agent-contract.yaml`, dangerous-actions catalog, AgentGuard (TS + Rust), AI integration workflow |
| Phase 6 — Daemon + CLI | Argon2id + ChaCha20-Poly1305 vault, ApprovalQueue, runnable daemon, unified `tf` command, signed plugin manifests, sandboxed plugin host |
| Phase 7 — Plugins | Native (Worker-isolated) + WASM plugin runtime, capability-bound dispatch, revocation index |
| Sprint 4 (this release) — Constrained + offline | Packet-mode signing, fragmentation, reassembly, LoRa simulator, offline revocation list, emergency authority |
| Sprint 4 (this release) — Compliance evidence | L4 encrypted bundle (multi-recipient ChaCha20-Poly1305 + X25519 wrap), L5 RFC 3161 anchoring, redaction, replay timeline |
| Sprint 5 (this release) — Bridges | WebAuthn, SPIFFE, OAuth/GNAP + DPoP, MCP, TLS, DID, Matrix, Webhook (HMAC + ed25519), gRPC + service mesh (Envoy XFCC, Istio, Linkerd) |
| Sprint 6 (this release) — Profile gating + admin | profile-spec + four built-in profiles, admin HTTP endpoint, full `tf` CLI, viewer-only dashboard |
| Sprint 7 (this release) — Conformance gate | Vector format spec, [`tf-conformance`](tools/tf-conformance/) runner, profile + interop + fuzz + security + AI-implementation suites, compatibility-label runner |

## Repository layout

```
docs/
  specs/                    TF-0000 through TF-0012 RFC-style specs
  bridges/                  WebAuthn / SPIFFE / OAuth-GNAP / MCP / TLS / DID / Matrix bridge specs
  profiles/                 home / enterprise / constrained / compliance-evidence
  ai-integration.md         How an AI agent should consume the contract
  schemas/                  Generated per-schema Markdown reference

schemas/
  *.schema.json             36 JSON Schemas
  fixtures/<name>/{valid,invalid,composite}/

conformance/
  parity.yaml               schema verdict cross-language parity
  canonical-vectors.yaml    canonical-JSON parity (post-B2)
  cross-language-signature-vectors.yaml  TS↔Rust sign+verify parity
  signature-vectors.yaml    ed25519 / hash parity
  chain-vectors.yaml        event-hash / merkle / chain-hash parity
  framing-vectors.yaml      .tflog / .tfproof byte parity
  session-vectors.yaml      X25519 / HKDF / ChaCha20-Poly1305 parity
  guard-vectors.yaml        AgentGuard decision parity
  bridge-vectors.yaml       SPIFFE / MCP / OAuth bridge parity
  trust-overlay-vectors.yaml posture composition parity
  relay-forwarding-vectors.yaml relay authority parity
  negative-capability-vectors.yaml deny-overrides parity

examples/
  agent-contracts/          full.yaml, minimal.yaml
  dangerous-actions/        tf-dangerous-std.yaml
  proofrpc/                 code-helper.tfrpc.yaml

tools/
  tf-schema/                validate / lint / bundle / codegen / fuzz / parity / agent-contract-check
  tf-types-ts/              TypeScript type bindings + hand-written core
  tf-proof/                 keygen / sign / verify / inspect / derive-pubkey
  tf-session/               WebSocket carrier for the session protocol
  tf-daemon/                Runnable daemon (with admin HTTP endpoint)
  tf-packet/                Packet sign/verify/fragment/reassemble + LoRa simulator
  tf-evidence/              Evidence assemble/verify/seal/open/anchor/replay/redact
  tf-cli/                   Unified `tf` command
  tf-dashboard/             Viewer-only dashboard for an active daemon
  tf-conformance/           Runs every conformance category in one shot

crates/
  tf-types/                 Rust type bindings + hand-written core
  tf-code-helper-example/   Downstream crate that compiles rpc-rust output
```

## Quick start

```bash
bun install
bun run --filter '*' typecheck
bun test
bun run tools/tf-conformance/src/cli.ts run

cargo test --workspace
```

Today this passes with:

- **510 TS tests** across 66 files
- **232 Rust tests** across `tf-types` + `tf-code-helper-example`
- **36 schemas** with valid + invalid fixtures, **0 lint issues**, **120+ parity vectors**
- **`tf-conformance run`** green across schema / signature / guard / trust-overlay / bridge / interop / fuzz / profile / security / AI-implementation / label

### Run the daemon

```bash
# 1. Mint a daemon identity into a vault.
TF_VAULT_PASS=dev-pw bun run tools/tf-cli/src/cli.ts actor create \
  --type service --name tf-daemon --domain example.com

# 2. Boot the daemon with admin HTTP enabled.
TF_VAULT_PASS=dev-pw TF_ADMIN_TOKEN=$(openssl rand -hex 16) \
  bun run tools/tf-daemon/src/cli.ts run --config .tf/daemon.yaml

# 3. Browse the dashboard (read-only).
TF_ADMIN_TOKEN=$TF_ADMIN_TOKEN \
  bun run tools/tf-dashboard/src/cli.ts --daemon http://127.0.0.1:8787

# 4. Inspect, approve, revoke from the CLI.
tf session inspect
tf approval list
tf approve <id>
tf revoke actor tf:actor:agent:example.com/bad
```

## Profiles

TrustForge ships four conformance labels:

| Profile | Floor | When to use |
|---|---|---|
| `tf-home-compatible` | E3 / L1 | Single-operator deployments — home automation, personal mesh |
| `tf-enterprise-compatible` | E4 / L2 + RFC 6962 | Multi-tenant, federation, transparency anchoring, quorum |
| `tf-constrained-compatible` | E3 / L1 | LoRa, BLE, serial, sneakernet, store-and-forward |
| `tf-compliance-evidence-compatible` | E4 / L3 + RFC 3161 + RFC 6962 | Legal / compliance evidence with offline reproducibility |

The daemon refuses to boot if its claimed profile's MUST features aren't satisfied; see [`docs/profiles/`](docs/profiles/) for the normative definitions.

## Spec status

Every spec in `docs/specs/` is **Draft**. The reference implementation tracks the spec one-for-one — when a spec changes, the implementation moves with it. See [`GOVERNANCE.md`](GOVERNANCE.md) for the spec process.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for development setup, conformance expectations, and the rules around new crypto primitives, new protocol surfaces, and AI-implementability.

## License

Apache-2.0. See [LICENSE](LICENSE).

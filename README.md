# TrustForge

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue?logo=typescript)](https://www.typescriptlang.org/)
[![Rust](https://img.shields.io/badge/Rust-Ready-orange?logo=rust)](https://www.rust-lang.org/)
[![NPM Core](https://img.shields.io/npm/v/@trustforge-protocol/core.svg)](https://www.npmjs.com/package/@trustforge-protocol/core)
[![Crates.io Types](https://img.shields.io/crates/v/tf-types.svg)](https://crates.io/crates/tf-types)

**TrustForge** is an open-source trust fabric for AI-native software, secure devices, authenticated live systems, site-to-site communication, service-to-service communication, and verifiable action.

> Who or what is acting, under what authority, through what session, with what permissions, under what policy, across what transport, and with what verifiable proof?

TrustForge's core thesis: the next era of security is not login; it is **verifiable action by cryptographic actors over authenticated channels**.

The project is split into a **spec series** (see [`docs/specs/`](docs/specs/)) and a reference implementation in TypeScript (Bun) and Rust. Both are active, but coverage is uneven across the broad native and bridge surface.

This is the **0.1.1 experimental** line with v0.2 hardening underway. Core schemas, type bindings, conformance vectors, the Bun daemon, the CLI, and several adapters are working references. Many native integrations are mock-tested, hardware-untested, docs-only, or planned. Nothing is production-ready; use this repo for spec review, local interop experiments, and contributor development.

---

## What ships in 0.1.1

| Surface | Status |
|---|---|
| Schemas + generated types | Working reference with fixtures, linting, fuzzing, TS/Rust generated bindings, and parity checks. |
| Proof/session/RPC core | Working reference for the implemented TS/Rust paths; some advanced parity remains v0.2 work. |
| Agent Contract + policy guard | Working reference in TS/Rust for core allow/deny/approval behavior. |
| `tf-daemon` + `tf-cli` | Working reference. TCP `/v1/*` remains bearer-protected; Unix `/run/trustforge/decide.sock` is the local decision socket. |
| Web adapters | Several working reference adapters; each adapter README is the source for its tested surface. |
| Native OS/network integrations | Mixed status. See [`docs/native-support-matrix.md`](docs/native-support-matrix.md) before assuming anything is installable. |
| Release artifacts | Source install path exists. Container/Kubernetes and binary/package distribution are v0.2+ hardening work. |

## Repository layout

```
docs/
  specs/                    TF-0000 through TF-0013 RFC-style specs (TF-0013 defines the site-to-site binary path)
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

The required local gates for this line are `bun test`, `bun run --filter '*' typecheck`, `bun run tools/tf-conformance/src/cli.ts run`, `cargo test --workspace`, and `cargo check --workspace --all-targets`.

### Run the daemon

```bash
# 1. Mint a daemon identity into a vault.
TF_VAULT_PASS=dev-pw bun run tools/tf-cli/src/cli.ts actor create \
  --type service --name tf-daemon --domain example.com

# 2. Boot the daemon with admin HTTP enabled.
TF_VAULT_PASS=dev-pw TF_ADMIN_TOKEN=$(openssl rand -hex 16) \
  bun run tools/tf-daemon/src/cli.ts run --config .tf/daemon.yaml

# Optional preflight without booting listeners.
bun run tools/tf-daemon/src/cli.ts run --config .tf/daemon.yaml --dry-run

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

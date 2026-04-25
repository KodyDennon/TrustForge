# TrustForge

**TrustForge** is an open-source trust fabric for AI-native software, secure devices, authenticated live systems, site-to-site communication, service-to-service communication, and verifiable action.

> Who or what is acting, under what authority, through what session, with what permissions, under what policy, across what transport, and with what verifiable proof?

TrustForge's core thesis: the next era of security is not login; it is **verifiable action by cryptographic actors over authenticated channels**.

The project is split into a **spec series** (see [`docs/specs/`](docs/specs/)) and a reference implementation in TypeScript (Bun) and Rust. Both are alive, tested, and cross-checked against each other. Nothing here is production-ready yet — everything is drafts, prototypes, and working POCs.

---

## What ships today

Phases 0 through 7 of [`ROADMAP.md`](ROADMAP.md) are implemented end-to-end:

### Phase 0 — Repository seed + foundation

20 JSON Schemas covering every machine-readable artifact (manifests + runtime objects), a validator / linter / bundler / fuzzer / codegen in [`tools/tf-schema`](tools/tf-schema/), and matched TypeScript + Rust type bindings with hand-written semantic cores in [`tools/tf-types-ts`](tools/tf-types-ts/) and [`crates/tf-types`](crates/tf-types/).

### Phase 2 — Proof format

Ed25519 signing and verification, SHA-256 / BLAKE3 hashing, hash-chained proof events, Merkle roots, chain hashes, and the `.tflog` + `.tfproof` binary framing. Driven by the [`tf-proof`](tools/tf-proof/) CLI: `keygen`, `sign`, `verify`, `inspect`, `derive-pubkey`. All primitives match RFC 7748 / RFC 5869 / RFC 8439 / RFC 8032 test vectors byte-for-byte in both languages.

### Phase 3 — Session protocol

X25519 + HKDF-SHA256 + ChaCha20-Poly1305 + ed25519 in a 3-message mutually-authenticated handshake. AEAD frames with sequence numbers, in-band rekey, WebSocket carrier in [`tools/tf-session`](tools/tf-session/). Live loopback test: real Bun WebSocket server + client completing the handshake and exchanging encrypted frames.

### Phase 4 — ProofRPC

A typed RPC layer with unary + server-streaming methods, capability-bound dispatch, and [`rpc-ts`](tools/tf-schema/src/codegen/rpc-ts.ts) + [`rpc-rust`](tools/tf-schema/src/codegen/rpc-rust.ts) codegen from `.tfrpc.yaml` descriptors. Live end-to-end: TS RPC client over a real WebSocket calls a TS server through the generated CodeHelper stubs; the generated Rust bindings compile and round-trip via [`crates/tf-code-helper-example`](crates/tf-code-helper-example/).

### Phase 5 — Agent Contract

Extended `.tf/agent-contract.yaml` with `danger_tags`, `parameters`, `reversible`, and `pre_conditions`. A standalone [dangerous-actions catalog](schemas/dangerous-actions.schema.json) + deep validator (`tf-schema agent-contract-check`) that enforces conflict, target-set, reversibility, and catalog-mandatory-tag rules. [`AgentGuard`](tools/tf-types-ts/src/core/guard.ts) + [Rust mirror](crates/tf-types/src/guard.rs) — the runtime interpreter for the contract, with cross-language parity on 9 vectors. Codegen emits typed guard builders. The [AI integration guide](docs/ai-integration.md) is the concrete 5-step workflow an AI agent must follow before touching a TrustForge repo.

### Phase 6 — Daemon + CLI

An Argon2id + ChaCha20-Poly1305 file-backed key [Vault](tools/tf-types-ts/src/core/vault.ts) (TS + Rust, cross-language parity tested), a promise-based [ApprovalQueue](tools/tf-types-ts/src/core/approval.ts) (TS + Rust), and a runnable daemon in [`tools/tf-daemon`](tools/tf-daemon/) that:

- loads a YAML config,
- opens the passphrase-encrypted vault,
- binds a WebSocket listener,
- runs the Phase 3 handshake per connection,
- exposes the AgentGuard as the RpcServer's CapabilityEnforcer,
- queues escalate / approval-required decisions for human UIs,
- writes every call + guard event to a `.tflog`.

Plus a unified [`tf`](tools/tf-cli/) CLI with `policy simulate`, `actor create`, and `actor inspect`.

### Phase 7 — Plugins

A [plugin-manifest schema](schemas/plugin-manifest.schema.json) with ed25519-signed manifests, a [`PluginRegistry`](tools/tf-types-ts/src/core/plugin.ts) (TS) that loads and verifies native and WASM plugins, and a matched [Rust native registry](crates/tf-types/src/plugin.rs). The WASM prototype demonstrates permission-gated imports: a plugin whose manifest omits an import it needs fails at instantiation.

---

## Repository layout

```
docs/
  specs/                    TF-0000 through TF-0012 RFC-style specs
  ai-integration.md         How an AI agent should consume the contract
  schemas/                  Generated per-schema Markdown reference
  superpowers/              Design specs + implementation plans

schemas/                    20 JSON Schemas + fixtures
  fixtures/<name>/{valid,invalid,composite}/
  *.schema.json

examples/
  agent-contracts/          full.yaml, minimal.yaml
  dangerous-actions/        tf-dangerous-std.yaml
  proofrpc/                 code-helper.tfrpc.yaml

conformance/
  parity.yaml               cross-language schema verdicts
  canonical-vectors.yaml    canonical-JSON parity
  signature-vectors.yaml    ed25519 / sha256 / blake3 parity
  chain-vectors.yaml        event-hash / merkle / chain-hash parity
  framing-vectors.yaml      .tflog / .tfproof byte parity
  session-vectors.yaml      X25519 / HKDF / ChaCha20-Poly1305 parity
  guard-vectors.yaml        AgentGuard decision parity

tools/
  tf-schema/                CLI: validate / lint / bundle / codegen / fuzz
                            / parity / agent-contract-check
  tf-types-ts/              TypeScript type bindings + hand-written core
  tf-proof/                 keygen / sign / verify / inspect / derive-pubkey
  tf-session/               WebSocket carrier for the session protocol
  tf-daemon/                Runnable daemon
  tf-cli/                   Unified tf command

crates/
  tf-types/                 Rust type bindings + hand-written core
  tf-code-helper-example/   Downstream crate that compiles rpc-rust output
```

## Running the test suite

```bash
bun install
bun run --filter '*' typecheck
bun test
bun run tools/tf-schema/src/cli.ts validate-all
bun run tools/tf-schema/src/cli.ts lint
bun run tools/tf-schema/src/cli.ts parity

cargo check --workspace
cargo test --workspace
```

Today these pass with:

- **200 TS tests** (409 `expect()` calls)
- **92 Rust tests** across `tf-types` + `tf-code-helper-example`
- **20 schemas** × 20+ valid / 50+ invalid fixtures, **0 lint issues**, **73+ parity vectors**
- A real Bun.serve WebSocket daemon that completes a mutually-authenticated handshake, runs an agent-contract-guarded RPC, and appends to a `.tflog`.

## What's next

The roadmap has three more phases:

- **Phase 8** — Compatibility bridges (WebAuthn, SPIFFE, OAuth/GNAP, MCP/A2A, TLS/mTLS).
- **Phase 9** — Constrained + offline profile (packet mode, fragmentation, LoRa-style simulation, emergency packets).
- **Phase 10** — Conformance suite (cross-implementation test vectors, protocol traces, fuzzing, interoperability tests).

## Spec status

All specs in `docs/specs/` are **Draft**. No TrustForge component is production-ready. Everything is being built on purpose, in the open, with spec and implementation moving together.

## License

Apache-2.0. See [LICENSE](LICENSE).

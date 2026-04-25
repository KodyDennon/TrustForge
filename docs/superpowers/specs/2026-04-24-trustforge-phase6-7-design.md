# TrustForge Phase 6 + 7 Design Spec

**Date:** 2026-04-24
**Status:** Draft, approved for implementation planning
**Scope:** Roadmap Phases 6 (tf-daemon, key vault, approval requests, tf CLI, session/proof/policy inspect, actor management) and 7 (plugin manifest, plugin actor identity, native + WASM plugin POCs, permission sandbox).

## 1. Purpose

Turn the typed, signed, session-carrying, RPC-speaking, contract-guarded foundation into a runnable **daemon** with a unified **CLI**, and extend it with a **plugin** system so third-party code can register capability-bound RPC methods under its own actor identity.

## 2. Non-goals

- **No OS keychain integration.** Vault is file-backed; passphrase-derived key encrypts on disk.
- **No multi-tenant daemon.** One config file, one actor identity, one vault per `tf-daemon` instance.
- **No signing HSM.** The vault is a software KDF + AEAD store; hardware-backed keys are a future hook.
- **No full WASM sandboxing.** The WASM POC demonstrates manifest-gated imports and a host-supplied permission surface, not Wasmtime-grade isolation.
- **No plugin auto-discovery / installer.** Plugins are loaded from paths in the daemon config.
- **No cross-daemon federation.** One daemon, one session, one vault.

## 3. Phase 6 — Daemon + CLI

### 3.1 Schemas

- `schemas/daemon-config.schema.json` — `.tf/daemon.yaml`:
  - `daemon_version`, `self_actor`, `listen: { kind: "websocket", port, bind }`, `vault: { path }`, `contract_path`, `proof_log_path`, `approval_queue: { max_pending, default_timeout_seconds }`.
- `schemas/vault-file.schema.json` — on-disk vault format:
  - `vault_version`, `kdf: { algorithm: "argon2id", salt, m_cost, t_cost, p_cost }`, `cipher: { algorithm: "chacha20poly1305" }`, `entries[]: { id, purpose, algorithm, nonce, ciphertext, created_at }`.
- `schemas/approval-request.schema.json` — pending approval shape:
  - `request_version`, `id`, `actor`, `action`, `target?`, `danger_tags`, `reason`, `created_at`, `expires_at`.
- `schemas/approval-response.schema.json` — human's response:
  - `response_version`, `request_id`, `decision: "approve" | "deny"`, `responder: ActorId`, `note?`, `signed_at`, `signature: SignatureEnvelope`.

All schemas + 3 invalid fixtures each.

### 3.2 Vault library (TS + Rust)

- `Vault.createAtPath(path, passphrase)` — writes a fresh empty vault; derives the encryption key via Argon2id.
- `Vault.openAtPath(path, passphrase)` — reads + decrypts.
- `vault.store(id, purpose, keyBytes)` / `vault.read(id)`, `vault.list()`, `vault.remove(id)`.
- Canonical JSON round-trip of vault content (for test parity vectors).
- Argon2id via `@noble/hashes` (TS) and `argon2` crate (Rust).
- ChaCha20-Poly1305 already landed in Phase 3.

### 3.3 Approval queue (TS)

- In-memory FIFO of `ApprovalRequest` objects with an async-iterable interface for UIs / tooling.
- `queue.push(req)` → returns a promise that resolves with `ApprovalResponse` (or times out with a `deny`).
- `queue.approve(request_id, responder, signature)` / `queue.deny(...)` for external approvers.
- Emits a `proof-event` stub on every resolution.

### 3.4 `tf-daemon` package

New workspace package `tools/tf-daemon`:

- `tf-daemon run --config <path>`:
  - Loads daemon config + contract + vault (prompts for passphrase via env var `TF_VAULT_PASS`).
  - Spins up Bun WebSocket server running the Phase-3 session protocol.
  - Accepts incoming sessions → runs the `RpcServer` with a `CapabilityEnforcer` backed by `AgentGuard`.
  - When the guard returns `approval-required` or `escalate`, emits an `ApprovalRequest` to the queue and awaits the response.
  - Writes every RPC call + guard event into a rolling `.tflog`.
- `tf-daemon status` — dump running state (caller sessions, pending approvals).

### 3.5 Unified `tf` CLI

New workspace package `tools/tf-cli`:

Commands map to existing packages:
- `tf schema ...` → `tf-schema`
- `tf proof ...` → `tf-proof`
- `tf daemon ...` → `tf-daemon`
- `tf session inspect` — connect to daemon, list sessions.
- `tf policy simulate <contract> <action> [--target <t>]` — runs `AgentGuard.check` locally, prints the decision.
- `tf actor create --type agent --name <name>` — generates an ed25519 key pair, writes an actor-identity document.
- `tf actor inspect <identity-file>` — prints the document.
- `tf approval list` / `tf approval approve <id>` / `tf approval deny <id>` — operate against a running daemon.

### 3.6 Phase 6 tasks

- **V1**: daemon/vault/approval schemas + fixtures.
- **V2**: TS vault library + parity vectors in both languages.
- **V3**: approval queue (TS).
- **V4**: `tf-daemon` server implementation.
- **V5**: unified `tf` CLI.
- **V6**: e2e test: start daemon → connect session → RPC calls through guard → write tflog → approval flow.

## 4. Phase 7 — Plugins

### 4.1 Schema

- `schemas/plugin-manifest.schema.json` — `.tf/plugin.yaml`:
  - `plugin_version`, `plugin_id` (reverse-DNS-style), `actor_id` (ActorId the plugin operates as), `kind: "native" | "wasm"`, `entry`, `identity_pub`, `signature: SignatureEnvelope`, `capabilities: Capability[]`, `imports?: string[]` (list of host functions the plugin is allowed to call, enforced by the sandbox), `proof_profile?: ProofLevel`, `description`.

### 4.2 Plugin registry (TS + Rust)

- `PluginRegistry.load(manifestPath)`:
  - Schema-validate the manifest.
  - Verify `signature` over canonical JSON of the manifest with the signature field cleared.
  - Record the plugin actor identity.
- `PluginRegistry.register(plugin)` — register a loaded plugin with a running RpcServer under the plugin's actor.
- Enforcement: plugin's declared `capabilities` are the only capabilities its handlers can claim; guards use the plugin's actor ID as the caller.

### 4.3 Plugin kinds

- **Native** (TS + Rust): a plugin is a module exporting a conventional entry function `tfPluginEntry(host)` that registers ProofRPC handlers.
- **WASM** (TS only for this POC): a plugin is a `.wasm` module. The plugin receives an imports object limited to what the manifest's `imports` field declares (host-provided log / RPC-call helpers). A minimal demo: a WASM module that imports `tf.log` and exports `tf_plugin_init()`; the registry loads it and invokes the export; the plugin calls `tf.log("hello from wasm")` via the permission-gated import.

### 4.4 Phase 7 tasks

- **G1**: plugin-manifest schema + fixtures + example manifest.
- **G2**: PluginRegistry TS (load, verify, register).
- **G3**: Native plugin POC — a tiny plugin module that registers a CodeHelper method implementation.
- **G4**: WASM plugin POC — a bundled `.wasm` (built from a few lines of `.wat`) that exports one function, imports `tf.log`, runs under a permission-gated host surface.
- **G5**: PluginRegistry Rust mirror.
- **G6**: CI + final sweep.

## 5. Done criteria

- All new schemas + fixtures validate; 0 lint issues; parity vectors green.
- `tf-daemon run` spins up, accepts a tf-session WebSocket client, serves ProofRPC through an `AgentGuard` enforcer, writes a `.tflog` on disk, and routes escalate decisions through the approval queue.
- `tf policy simulate`, `tf actor create`, `tf actor inspect`, `tf session inspect`, `tf approval list/approve/deny` all run end-to-end against the live daemon.
- `PluginRegistry.load` + `.register` accept a signed native plugin and expose its method through the RpcServer. A signed WASM plugin loads, executes its init, and is rejected if its manifest omits an import it tries to use.
- CI green across both languages.

# AGENTS.md

This file provides shared context for AI coding agents and automation tools working within the TrustForge repository. It serves as an orientation guide and operational runbook.

## What is TrustForge?

TrustForge is an open-source trust fabric for AI-native software, secure devices, authenticated live systems, and verifiable action. It provides cryptographic proof of who or what is acting, under what authority, and with what permissions.

## Repository Architecture

This is a polyglot monorepo containing:
1. **JSON Schemas** (`schemas/`) acting as the single source of truth for the domain model.
2. **TypeScript/Bun Tooling** (`tools/`) implementing the daemon, CLI, SDKs, adapters, and the schema generator.
3. **Rust Crates** (`crates/`) implementing the native/Wasm logic.
4. **Conformance Vectors** (`conformance/`) verifying parity between TS and Rust.

## Core Rules for Agents

When implementing features, fixing bugs, or resolving CI issues, you MUST adhere to the following rules:

### 1. Codegen & Schema Drift

The `tools/tf-schema` tool generates TypeScript and Rust bindings from the JSON schemas. 
- If you modify any schema, you **must** re-run the codegen scripts:
  ```bash
  bun run tools/tf-schema/src/cli.ts codegen --target ts
  bun run tools/tf-schema/src/cli.ts codegen --target rust
  bun run tools/tf-schema/src/cli.ts codegen --target rpc-ts --spec examples/proofrpc/code-helper.tfrpc.yaml
  bun run tools/tf-schema/src/cli.ts codegen --target rpc-rust --spec examples/proofrpc/code-helper.tfrpc.yaml --out crates/tf-code-helper-example/src/generated
  bun run tools/tf-schema/src/cli.ts codegen --target agent-contract-ts --spec examples/agent-contracts/full.yaml
  bun run tools/tf-schema/src/cli.ts codegen --target agent-contract-rust --spec examples/agent-contracts/full.yaml
  ```
- **CRITICAL:** Do NOT run `cargo fmt` on the `crates/tf-types/src/generated/` folder. It will alter the layout, causing the `rust codegen-diff` CI check to fail. If you accidentally format it, simply re-run the codegen.

### 2. Rust Lints (Clippy)

TrustForge enforces a strict zero-warning policy on Rust code. CI uses `cargo clippy -D warnings`.
- When making Rust changes, always verify with:
  ```bash
  cargo clippy --workspace --all-targets -- -D warnings
  ```
- If you encounter overly complex async closures or legacy testing patterns that trigger `clippy::result_large_err`, `clippy::type_complexity`, or `clippy::cloned_ref_to_slice_refs`, prefer inserting highly scoped `#[allow(...)]` attributes over disruptive refactors, especially in test suites (`tests/`).

### 3. Supply Chain Security (Cargo Deny)

CI runs `cargo deny check` to ensure licenses, advisories, and bans are respected.
- If a vulnerability is flagged (e.g., via `RUSTSEC`), attempt to resolve it via `cargo update -p <crate>`.
- If no safe upgrade is available or the update requires a major breaking change, document and add the `RUSTSEC` ID to the `ignore` array in `deny.toml`. Do NOT disable `cargo deny` entirely.

### 4. Testing

Ensure full-stack tests pass before committing:
- **TypeScript:** `bun test` and `bun run --filter '*' typecheck`
- **Rust:** `cargo test --workspace`
- **Conformance:** `bun run tools/tf-conformance/src/cli.ts run`

### 5. TypeScript/Bun Types

- When exporting types in TypeScript (especially inside index files like `tools/tf-types-ts/src/index.ts`), strictly separate type exports using `export type {...}`. Mixing type and value exports will cause `SyntaxError` crashes when Bun strips types at runtime.

### 6. Commit Patterns

- Avoid pushing incomplete or failing builds to remote branches. Test thoroughly and squash commits where possible to maintain a clean history.

## Integration & Implementation

If you are an agent implementing TrustForge in a downstream application (not contributing to this repo directly), refer to `docs/ai-implementation.md` and `docs/ai-integration.md` for guidance on consuming `.tf/agent-contract.yaml` files, generating verifiable proofs, and routing requests securely.

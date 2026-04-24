# TrustForge Foundation — Design Spec

**Date:** 2026-04-24
**Status:** Draft, approved for implementation planning
**Scope:** Roadmap Phases 0 (repository seed, schemas) and 1 (core type system), end-to-end.

## 1. Purpose

Turn the TrustForge specification series into a working foundation that downstream phases (proof format, session protocol, ProofRPC, daemon, plugins, bridges) can build on without renegotiating shapes. Concretely:

- Publish JSON Schemas for every machine-readable artifact defined in the specs through TF-0012.
- Ship a `tf-schema` CLI that validates, lints, fuzzes, and generates code/docs from those schemas.
- Ship `tf-types` as a TypeScript package and a Rust crate, produced by codegen plus a hand-written semantic core.
- Guarantee cross-language parity with a conformance suite that feeds identical fixtures to both runtimes.

## 2. Non-goals

- **No cryptography.** Signature envelopes carry opaque bytes only. Signing, verification, hash-chain, Merkle, transparency anchoring are Phase 2+.
- **No binary framing.** `proof-bundle.schema.json` defines the JSON representation of `.tfproof`. The binary envelope format is Phase 2.
- **No session or packet protocol.** Phases 3+.
- **No daemon, plugins, bridges, or ProofRPC runtime.** Phases 4+.
- **No new specs.** This is foundation work against the existing TF-0000–TF-0012 specs; if a spec is ambiguous, the implementation defers the ambiguity and flags it in a follow-up ADR — it does not invent behavior.

## 3. Source-of-truth rule

JSON Schema is the normative source for every wire/config object. TypeScript types and Rust types are **generated** from it. Hand-written code in each language is only the semantic layer that JSON Schema cannot express (URI parsing, canonical JSON serialization, delegation-chain traversal, revocation-index queries, equality rules).

If a concept is representable in JSON Schema, it lives there — not duplicated in hand-written types.

## 4. Schemas

### 4.1 Shared primitives — `schemas/_common.schema.json`

Defines `$defs` referenced by every other schema. No top-level object of its own.

- `ActorId` — pattern-validated URI: `tf:actor:<type>:<path>` where `<type>` is one of the 14 actor types from TF-0002 (`human`, `agent`, `device`, `service`, `site`, `organization`, `relay`, `plugin`, `process`, `tool`, `model-provider`, `policy-engine`, `proof-anchor`, `emergency-authority`).
- `InstanceId` — `tf:instance:<type>:<path>/<instance-path>`.
- `TrustDomain` — DNS-like identifier with extension syntax for federation and local domains.
- `RiskClass` — enum `R0`–`R5` (TF-0004).
- `TrustLevel` — enum `T0`–`T7` (TF-0002).
- `ProofLevel` — enum `L0`–`L5` (TF-0005).
- `EnforcementLevel` — enum `E0`–`E5` (from DECISIONS.md).
- `Timestamp` — RFC 3339 with required timezone suffix (`Z` or `±HH:MM`).
- `HashRef` — `<algo>:<hex>` (e.g. `sha256:…`, `blake3:…`). Hex length validated per algorithm.
- `AlgorithmId` — registered algorithm identifier strings; open-ended enum with a validator-warn-on-unknown policy.
- `SignatureEnvelope` — `{algorithm, signer, signature, optional: alt_algorithm, alt_signature, hash_alg}`. Supports hybrid post-quantum signing. Bytes are opaque in this phase.
- `Capability` — `{name, constraints, risk, proof_required, approval, target_actor, expires_at, single_use, delegable, revocable}`.
- `NegativeCapability` — same shape as `Capability` minus grant-only fields, semantically an override.
- `Constraint` — discriminated union over time, target, quantity, rate, session, approval, quorum, device-binding.
- `DelegationLink` — one step: `{delegator, delegate, capabilities, constraints, expires_at, redelegation, proof_ref}`.

### 4.2 Manifests (repo-committed `.tf/` files)

Each manifest schema is YAML-authored, JSON-validated, `additionalProperties: false`, and every property has a `description`.

- `agent-contract.schema.json` — already exists; refactor to `$ref` `_common` for `RiskClass`, `ProofLevel`, `ApprovalRequirement`.
- `policy.schema.json` — TF-0004. Describes allow/deny rules, risk/proof/approval requirements per action pattern, target sets, quorum rules, continuous-reevaluation triggers. Backend-agnostic (Cedar, Rego, custom, native, none).
- `threat-model.schema.json` — TF-0006. Assets, adversaries, attack classes referenced, mitigations, residual risks.
- `actions.schema.json` — TF-0006. Catalog of action definitions with default risk class, parameters schema, default proof level.
- `proof-profile.schema.json` — TF-0005. Which proof events to emit, at which level, where to log/anchor them.
- `conformance.schema.json` — TF-0010. Which profiles a deployment claims (`tf-home`, `tf-enterprise`, `tf-constrained`, `tf-compliance-evidence`), with optional extension matrix. (Distinct from the repo's `conformance/` test-harness directory — same word, different artifact. See §9.)

### 4.3 Runtime objects (wire/storage JSON shape)

- `actor-identity.schema.json` — TF-0002. Actor identity document: `{actor_id, actor_type, public_keys[], trust_levels[], authority_roots[], attestations[], valid_from, valid_until, revocation_ref}`. Keys are opaque byte blobs + algorithm IDs; no crypto performed on them here.
- `capability-token.schema.json` — TF-0004. Serialized capability grant: `{id, issuer, subject, capability, constraints, chain[], issued_at, expires_at, proof_ref, signature}`. `signature` is a `SignatureEnvelope`; not verified in this phase.
- `revocation.schema.json` — TF-0004. Revocation object: `{id, target_id, target_kind: capability|actor|delegation|instance, effective_at, reason, issuer, signature}`.
- `proof-event.schema.json` — TF-0005. Signed event record: `{id, type, actor_id, instance_id, session_id?, timestamp, level, subject_ref?, payload_hash?, parent_hash?, signature}`. `parent_hash` enables hash-chain linking without performing the verification here.
- `proof-bundle.schema.json` — TF-0005. JSON representation of `.tfproof`: `{version, events[], merkle_root?, transparency_anchor?, signature}`. Matches what the future binary framing will carry.

### 4.4 Schema organization rules

- `$id` pattern: `https://trustforge.io/schemas/v0/<name>.schema.json`. The existing `agent-contract.schema.json` currently uses `https://trustforge.io/schemas/agent-contract.schema.json` (no `v0/`); P0 moves it under `v0/` so every schema uses the same convention. This is a breaking URL change — acceptable pre-1.0 and before any consumer exists.
- `v0` denotes pre-1.0 flux; bumping the path segment is the breaking-change signal.
- Every schema sets `$schema: https://json-schema.org/draft/2020-12/schema`.
- Every schema sets `additionalProperties: false` at the top level and at every nested object.
- Every property has a non-empty `description` — feeds docs codegen.
- Cross-schema references use `$ref: "_common.schema.json#/$defs/<Name>"` relative paths; the CLI bundles references at codegen/validate time.

### 4.5 Fixtures

Layout: `schemas/fixtures/<schema-name>/{valid,invalid,composite}/`.

- `valid/*.yaml` — each file is a complete, validating example. Representative, not exhaustive.
- `invalid/*.yaml` — each file is paired with `<same-name>.expected-error.yaml` listing `{path, keyword}` of expected violations. The CLI asserts the validator produces exactly those errors.
- `composite/*.yaml` — cross-schema examples (e.g., a `policy` fixture that references capabilities defined in an `actions` fixture); asserts that `$ref` chains resolve and cross-schema constraints hold.
- Fixtures are committed and live forever; fuzz-discovered regressions land in the appropriate `valid/` or `invalid/` bucket depending on what broke.

## 5. `tf-schema` CLI

Lives in `tools/tf-schema`. Existing scaffolding stays; new commands layer on.

```
tf-schema validate <file> [--schema <name>]
tf-schema validate-all
tf-schema lint [<dir>]
tf-schema codegen --target ts   [--out tools/tf-types-ts/src/generated]
tf-schema codegen --target rust [--out crates/tf-types/src/generated]
tf-schema codegen --target docs [--out docs/schemas]
tf-schema fuzz <schema> [--iterations N] [--seed S]
tf-schema bundle <schema> [--out -]        # resolve $refs, emit self-contained schema for consumers
```

### 5.1 `validate` / `validate-all`

- Infers schema from the document's `$schema` field, or falls back to top-level `kind`/filename convention; `--schema` overrides.
- Accepts YAML or JSON; emits structured error output (`{path, keyword, message, expected}`).
- `validate-all` walks `schemas/fixtures/` and enforces the valid/invalid matrix. Exits non-zero on any mismatch.

### 5.2 `lint`

Beyond schema validity:

- Every property has `description`.
- No inline enum that duplicates an existing `$def` in `_common`.
- `$ref` targets resolve.
- `additionalProperties: false` is present on every object.
- `$id` matches filename and the `v0` convention.
- No unused `$def`.

### 5.3 `codegen`

- **TS target**: emits `.ts` files under `tools/tf-types-ts/src/generated/` with one file per schema plus an `index.ts` barrel. Uses a deterministic generator driven by the bundled schema; stable output so diffs are minimal.
- **Rust target**: emits `.rs` files under `crates/tf-types/src/generated/` with serde derives. Integer/string/enum handling is canonical; discriminated unions use serde `tag`. Generator must produce code that compiles with no hand edits.
- **Docs target**: emits one Markdown file per schema under `docs/schemas/` with title, description, fields table (type, required, constraints, description, examples), and cross-links.

### 5.4 `fuzz`

- Schema-aware generator produces well-typed-but-pathological inputs (boundary integers, max-depth recursion, unicode, large arrays).
- Also mutates valid fixtures (bit-flips, truncation, extra fields) to verify graceful rejection.
- Asserts: the validator terminates within a bound, never panics, never throws an uncaught exception, and always returns a structured error for invalid inputs.
- Failing seeds are printed and can be pinned as regression fixtures.

### 5.5 `bundle`

Resolves all `$ref`s into a single self-contained JSON Schema. Used by external consumers and by the Rust codegen step (which prefers bundled input).

## 6. `tools/tf-types-ts` (TypeScript package)

New workspace package.

- `src/generated/` — codegen output, checked in so the package ships without build-time codegen.
- `src/core/`:
  - `actor-id.ts` — `parseActorId`, `formatActorId`, type-guards per actor type, equality per RFC 3986 rules.
  - `instance-id.ts` — same for instance URIs, plus actor-to-instance relation helpers.
  - `trust-domain.ts` — parsing + equality.
  - `capability.ts` — `isCapability`, `constraintsSatisfied(cap, context)`, `intersectConstraints(a, b)`.
  - `delegation.ts` — `DelegationChain.walk(chain, {at: Timestamp})` returning validity + effective constraints.
  - `revocation.ts` — `RevocationIndex` builder + `isRevoked(target, at)`.
  - `envelope.ts` — envelope shape validation only; no crypto.
  - `canonical.ts` — deterministic JSON serialization (sorted keys, NFC unicode, stable number formatting). Used later for signing.
- `src/index.ts` — re-exports.
- Tests: unit tests for each core module + fixture-driven tests that load every `schemas/fixtures/*/valid/*.yaml`, parse through the typed API, and assert round-trip equality.

## 7. `crates/tf-types` (Rust crate)

First Rust crate in the repo. Establishes the Cargo workspace.

- `Cargo.toml` features: `default = ["serde", "std"]`, optional `proptest` for fuzz impls.
- `src/generated/` — codegen output, checked in.
- `src/` modules mirror the TS core: `actor_id.rs`, `instance_id.rs`, `trust_domain.rs`, `capability.rs`, `delegation.rs`, `revocation.rs`, `envelope.rs`, `canonical.rs`.
- All generated and hand-written types implement `serde::Serialize`, `serde::Deserialize`, `PartialEq`, `Eq`, `Clone`, `Debug`.
- Parse errors are typed (`ActorIdParseError`, etc.), not stringly.
- Canonical JSON serialization matches the TS `canonical.ts` byte-for-byte; this is tested.
- No `unsafe`. No panics in parsing — all errors returned.

### 7.1 Cargo workspace

Top-level `Cargo.toml` declares `members = ["crates/tf-types"]`. Adding a crate is a simple member append — no restructuring needed for Phase 2.

## 8. Docs output

`docs/schemas/` is generated; no hand edits. Each page:

- H1: schema title.
- Intro: schema description.
- `$id`, `$schema`, and spec cross-reference (e.g., "Defined by TF-0004").
- Fields table: name · type · required · constraints (pattern, enum, min/max) · description · example.
- Cross-references: link every `$ref` to the target schema's page.

Regeneration is part of CI; the output is committed so GitHub renders it without a build step.

## 9. Cross-language parity

`conformance/parity.yaml` enumerates every fixture and its expected verdict (`valid | invalid` with expected error shape). Both runtimes run it:

- TS runner lives in `tools/tf-types-ts/tests/parity.test.ts`.
- Rust runner lives in `crates/tf-types/tests/parity.rs`.

Verdicts must match. If they disagree, the fixture is pinned as a failing regression until resolved. This is how we keep the two codegen targets aligned over time.

## 10. CI

- `bun run validate:all` — schema and fixture validation.
- `bun run typecheck` — TS.
- `cargo check --workspace` + `cargo test --workspace` — Rust.
- `bun run test` — full TS test suite.
- `bun run fuzz --iterations 1000` — bounded smoke-test (longer runs happen nightly).
- Codegen output is checked in; CI asserts that `tf-schema codegen --target {ts,rust,docs}` produces no diff against the repo. This forces generator changes to be reviewed alongside their output.

## 11. Build order (phases for the implementation plan)

Each phase delivers something usable.

1. **P0** — `_common.schema.json`; refactor `agent-contract.schema.json` to `$ref` `_common`; add the first `valid/invalid` fixtures for `agent-contract`.
2. **P1** — Manifest schemas: `policy`, `threat-model`, `actions`, `proof-profile`, `conformance`. Fixtures for each.
3. **P2** — Runtime object schemas: `actor-identity`, `capability-token`, `revocation`, `proof-event`, `proof-bundle`. Fixtures for each, including composite fixtures that cross-reference manifests.
4. **P3** — `tf-schema` CLI commands: `validate`, `validate-all`, `lint`, `bundle`. Expected-error matching for invalid fixtures. Lint rules enforced on all existing schemas.
5. **P4** — TS codegen target; `tools/tf-types-ts` package with generated types and the hand-written core (`actor-id`, `instance-id`, `trust-domain`, `capability`, `delegation`, `revocation`, `envelope`, `canonical`). Tests.
6. **P5** — Rust codegen target; `crates/tf-types` crate with matching surface. Cargo workspace. Tests.
7. **P6** — Docs codegen; regenerate `docs/schemas/` and commit.
8. **P7** — Fuzz harness; parity conformance suite (`conformance/parity.yaml`, TS and Rust runners).
9. **P8** — CI wiring: schema/validate/typecheck/test/fuzz/codegen-diff steps. Document how to add a new schema.

## 12. Risks and open questions

- **Rust codegen tooling across `$ref` files.** `typify`/`schemars`-family tools handle intra-file `$ref` well; cross-file is rougher. Mitigation: `tf-schema bundle` is a required pre-step for Rust codegen; the bundler lives in the CLI and is testable.
- **Canonical JSON cross-language match.** TS and Rust must agree on unicode normalization, number serialization (no `1.0` vs `1`), and key ordering. Mitigation: a shared fixture file lists input objects and their canonical byte output; both sides test against it. This test exists before P4 and P5 are declared complete.
- **"No custom crypto" boundary.** The envelope schema names algorithms (`ed25519`, `ml-dsa-65`, etc.) but does not implement them. We only validate shape and size. Any future move that would add crypto needs its own ADR.
- **Spec ambiguity.** Several specs describe fields in prose without exhaustive enums (e.g., constraint types). The schemas will encode what the specs enumerate explicitly; anything under-specified is a TODO in the schema with a comment pointing to the spec line. Each TODO is a follow-up ADR candidate.
- **Schema versioning within `v0`.** Pre-1.0, we don't promise stability. A `schema_version` field inside each object (not the URL) lets consumers detect revisions without changing `$id`. Bump only on semantic change.

## 13. Done criteria

Foundation work is complete when:

- Every schema listed in §4 exists, passes its own lint rules, and has at least one valid and three invalid fixtures.
- `bun run validate:all` passes.
- `tools/tf-types-ts` is published within the workspace, imports generated types, exposes the core API in §6, and passes its test suite.
- `crates/tf-types` compiles, passes `cargo test --workspace`, and exposes the core API in §7.
- `docs/schemas/` contains a generated Markdown page for every schema and is byte-identical to what codegen produces.
- `conformance/parity.yaml` is non-empty and both runtimes pass it.
- CI runs the full gauntlet on every PR, including the codegen-diff check.

At that point Phase 2 (proof format, hash-chaining, binary `.tfproof` framing) has a typed foundation to build on without rewriting wire shapes.

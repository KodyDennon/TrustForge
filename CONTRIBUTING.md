# Contributing to TrustForge

Thanks for your interest in TrustForge. This document is the short
version — for the long-form rationale, read [`DECISIONS.md`](DECISIONS.md)
and the spec series under [`docs/specs/`](docs/specs/).

## Required stance

TrustForge is **specification + reference implementation moving together**.
A change to one without the other will be rejected. If you change a TF-XXXX
spec, update the schemas, type bindings, runners, tests, and parity
vectors. If you change the implementation, update the spec.

## Hard rules

* **No custom cryptography.** Compose reviewed primitives. New crypto is
  a red flag and will be pushed back. See `SECURITY.md`.
* **Post-quantum readiness from day one.** The protocol is crypto-agile
  even where the first implementation uses classical suites.
* **Profiles control complexity.** Don't force a feature onto a profile
  that doesn't need it. New capabilities must be modular,
  profile-based, policy-controlled, plugin-safe, conformance-testable,
  and not forced on lightweight deployments.
* **Drafts only.** Nothing here is production-ready. Don't let a PR
  description claim otherwise.

## Local setup

Requires Bun ≥ 1.3 and Rust ≥ 1.78.

```bash
bun install
bun run --filter '*' typecheck
bun test

cargo check --workspace
cargo check --workspace --all-targets
cargo test --workspace
```

A passing PR must keep these green. CI also runs schema validation,
schema linting, codegen-diff, conformance, cargo-deny, and advisory
Rust fmt/clippy checks.

## Conformance gate

Before opening a PR, run:

```bash
bun run tools/tf-conformance/src/cli.ts run
```

This runs **schema, signature, guard, trust-overlay, bridge, interop,
fuzz, profile, security regression, AI-implementation, and
compatibility-label** suites. Anything failing must be addressed in the
PR. Adding a new capability? Add a vector to the relevant
`conformance/*-vectors.yaml` first.

## Adding a new schema

1. Add `schemas/<name>.schema.json` — strict types, `additionalProperties:
   false`, every keyword annotated.
2. Add at least one `valid/` and one `invalid/` fixture. Invalid fixtures
   pair with `<name>.expected-error.yaml` describing the expected
   AJV-style error.
3. Run `bun run tools/tf-schema/src/cli.ts codegen --target ts`,
   `--target rust`, and `--target docs`. Commit the regenerated
   bindings and schema reference docs.
4. Add the parity entry to `conformance/parity.yaml` (the schema CLI
   has a `parity` subcommand that re-derives this).
5. Add `docs/schemas/<name>.md` (the lint suite enforces this).

## Adding a new bridge

1. Write `docs/bridges/TF-XXXX-<bridge>.md` first.
2. Implement the bridge in `tools/tf-types-ts/src/core/bridge-<x>.ts`
   and `crates/tf-types/src/bridge_<x>.rs`. Both languages must produce
   byte-identical canonical outputs.
3. Add cross-language parity vectors to
   `conformance/bridge-vectors.yaml`.
4. Wire the bridge into the relevant profile's MUST/SHOULD list if it
   is normative for that profile.

## Adding a new capability

1. State which profile(s) it belongs to.
2. Declare its `risk_class`.
3. Decide its conformance posture: MUST, SHOULD, MUST_NOT.
4. If it touches the daemon's runtime FeatureGate, surface it in
   `tools/tf-types-ts/src/core/profile.ts`'s feature inventory and
   the matching `crates/tf-types/src/profile.rs`.
5. Add a vector to `conformance/<category>-vectors.yaml`.

## AI-implementability

TrustForge is designed to be implemented by AI coding agents
**correctly and safely**. When proposing a change:

* If it adds a new manifest, schema, or runtime object, the AI agent
  must be able to discover it through `.tf/agent-contract.yaml`.
* If it adds a dangerous action, add the `danger_tags` and the
  `dangerous-actions` catalog entry.
* Don't design flows that assume inherited authority. AI agents
  negotiate authority dynamically.

## Commit conventions

Use imperative present tense ("Add WebAuthn bridge", not "Added"). For
multi-area sprints, scope the commit by sprint:

```
Sprint N: <one-line summary>

<bulleted body>

bun test: ...
cargo test --workspace: ...
```

## Releasing

1. Update `CHANGELOG.md` under a new `## X.Y.Z — YYYY-MM-DD` heading.
2. Bump the version in every `tools/*/package.json`,
   `crates/*/Cargo.toml`, and the root `package.json`.
3. Confirm `tf-conformance run` is green.
4. Tag `vX.Y.Z`.

## Security disclosures

See [`SECURITY.md`](SECURITY.md). Please don't open public GitHub issues
for vulnerabilities — email the address listed in that file.

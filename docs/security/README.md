# TrustForge security

This directory is the security-focused documentation for TrustForge:
threat model, cryptography choices, key handling, and disclosure
process.

The normative threat model is the machine-readable
[`../../.tf/threat-model.yaml`](../../.tf/threat-model.yaml). The
top-level [`../../SECURITY.md`](../../SECURITY.md) is the public-facing
security policy. Everything in this directory is the long-form prose
that complements both.

## What lives here

| Document | Audience | Use when |
|---|---|---|
| [`threat-model.md`](threat-model.md) | Security reviewer, architect, auditor | You need a narrative reading of the nine trust boundaries and twenty-four threats with mitigations and residual risks. |
| [`cryptography.md`](cryptography.md) | Cryptographer, packager, security reviewer | You need the per-primitive list of crates, versions, justifications, and PQ readiness. |
| [`key-handling.md`](key-handling.md) | Operator, embedded engineer | You are deploying TrustForge and need to know how keys are minted, stored, rotated, revoked, and bound to hardware. |
| [`disclosure.md`](disclosure.md) | Security researcher, downstream operator | You found a vulnerability or you need to know our response timeline. |

## How to read this directory

1. Start with [`threat-model.md`](threat-model.md) to see what
   TrustForge defends against and what it explicitly does not.
2. If you are reviewing crypto choices, read
   [`cryptography.md`](cryptography.md) next. It lists every primitive,
   the source crate, the version, and a one-paragraph justification.
3. Operators should read [`key-handling.md`](key-handling.md) before
   running a daemon in any environment that matters.
4. Researchers reporting a vulnerability should jump straight to
   [`disclosure.md`](disclosure.md).

## Companion documents

- [`../architecture/threat-boundaries.md`](../architecture/threat-boundaries.md)
  — boundary-focused diagrams of the same threat model.
- [`../specs/TF-0002-actor-identity.md`](../specs/TF-0002-actor-identity.md)
  — normative actor identity, key derivation, and rotation rules.
- [`../specs/TF-0005-proof-events-ledgers.md`](../specs/TF-0005-proof-events-ledgers.md)
  — normative proof event format and signature scheme.
- [`../profiles/`](../profiles/) — what each profile requires from the
  security stack (E0–E5 enforcement, L0–L5 proof).
- [`../../.tf/threat-model.yaml`](../../.tf/threat-model.yaml) —
  machine-readable threat model.
- [`../../SECURITY.md`](../../SECURITY.md) — public-facing policy and
  disclosure entry point.

## Status of every page in this directory

Like the rest of 0.1.0, **draft**. The cryptography page is accurate
to the dependencies declared in
[`../../crates/tf-types/Cargo.toml`](../../crates/tf-types/Cargo.toml)
and [`../../tools/tf-types-ts/package.json`](../../tools/tf-types-ts/package.json)
at the time of writing; check those files for the source of truth.

## Hard rules (recap)

These are repeated from `CLAUDE.md` and `SECURITY.md` because they
inform every page below:

- **No custom cryptography.** Compose reviewed primitives. New
  primitives require an ADR and external review.
- **Post-quantum / hybrid readiness from day one.** Every signed
  object carries an algorithm identifier; FIPS-204 ml-dsa-44/65/87 is
  available alongside ed25519.
- **Nothing is production-ready.** 0.1.0 is for spec review and
  interop experiments.
- **Spec and implementation must not drift.** Crypto and key handling
  changes require updates to spec, code, schemas, and these docs in
  one PR.

## Vulnerability reporting at a glance

For full details, see [`disclosure.md`](disclosure.md). Short version:

- Email **security@trustforge.dev** (PGP-encrypted preferred; key in
  `disclosure.md`).
- Do not open public issues for security reports.
- Expect an acknowledgement within 72 hours.
- Coordinated disclosure window is 90 days unless extended by mutual
  agreement.

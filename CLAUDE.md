# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository status

This is the **TrustForge** project. The short form used in identifiers, URIs, CLI, crate names, and file extensions is `tf` (e.g. `tf:actor:…`, `.tf/`, `.tfproof`, `tf-core`, `TF-0001`).

The repo is currently in the **0.1.x experimental line with v0.2 hardening underway**. A significant amount of the reference implementation exists in Rust (`crates/`) and TypeScript (`tools/`), but coverage is uneven across bridges, native integrations, constrained devices, and packaging targets.

- `crates/tf-types/` — core protocol types, handshake state machines, and compatibility bridges.
- `crates/tf-session/` — Rust carrier driver for session handshakes (TCP/duplex).
- `tools/tf-session/` — TS carrier driver for session handshakes (WebSocket/TCP).
- `tools/tf-daemon/` — the core enforcement daemon. Functional site-to-site binary path (TCP/TLS) + HTTP-over-binary bridge.
- `schemas/` — JSON Schema definitions for all protocol objects.
- `conformance/` — cross-language parity vectors.

The project has a functional site-to-site prototype surface. Do not claim code doesn't exist; instead, verify its status in the `crates/`, `tools/`, `docs/native-support-matrix.md`, and per-adapter README files.

## How the specification is organized

TrustForge is written as an **RFC-style spec series together with TypeScript and Rust reference implementations**. The two must not drift — spec changes and implementation must move together.

- `docs/specs/TF-XXXX-*.md` — numbered specs, `TF-0000` (manifesto) through `TF-0013` (site-to-site binary path). Read these before answering architecture questions. `TF-0001-core-architecture.md` defines the 12 core layers and canonical object vocabulary.
- `docs/bridges/` — compatibility bridge specs (WebAuthn, SPIFFE, OAuth/GNAP, MCP/A2A, TLS/DID/Matrix). TrustForge integrates with existing standards rather than replacing them; new protocol work should check for a relevant bridge first.
- `docs/profiles/` — deployment profiles (home, enterprise, constrained, compliance-evidence). Profiles are how complexity is controlled; the same architecture serves home and enterprise by selecting a profile.
- `docs/adr/` — architecture decision records.
- `DECISIONS.md` — the long-form "source of truth" for early design decisions. When a spec is ambiguous, `DECISIONS.md` usually has the authoritative rationale.

## Core concepts to respect

These distinctions recur everywhere; violating them produces wrong designs:

- **Actor vs. Actor Instance** — an actor is the named entity (`tf:actor:agent:example.com/code-helper`); an instance is a specific running process/session/replica (`tf:instance:agent:example.com/code-helper/macbook/session-9912`). Authority, revocation, and proof events must track both.
- **Live Mode vs. Packet Mode** — TrustForge supports both real-time authenticated sessions *and* standalone signed/encrypted packets for offline / mesh / LoRa / air-gapped / delayed delivery. Designs that assume only one mode are incomplete.
- **Relays are first-class actors** — but forwarding authority and action authority are separate. A relay can carry a packet without being able to decrypt, authorize, or execute it.
- **Capabilities + Negative Capabilities** — explicit denials override grants. Critical for AI-agent safety.
- **Trust levels (T0–T7), Risk classes (R0–R5), Proof levels (L0–L5), Enforcement levels (E0–E5)** — these tiered scales are referenced across specs; keep them consistent. See `DECISIONS.md` for canonical definitions.
- **Profiles control complexity** — don't force features onto lightweight deployments. The default design rule: support a serious capability only if it can be modular, profile-based, policy-controlled, plugin-safe, conformance-testable, and not forced on lightweight deployments.

## AI-implementability is a first-class requirement

TrustForge is designed to be implemented by AI coding agents correctly and safely. This shapes the spec:

- Machine-readable manifests are core from day one: `.tf/agent-contract.yaml`, `.tf/threat-model.yaml`, `.tf/policy.yaml`, `.tf/actions.yaml`, `tf-spec.yaml`, `tf-protocol.schema.json`, etc. (see `docs/ai-implementation.md` and the "AI-readable implementation manifests" section of `DECISIONS.md`).
- When adding a new concept to a spec, consider what schema, conformance test, and Agent Contract entries it needs.
- AI agents are expected to **negotiate authority dynamically** rather than silently inherit broad user power. Don't design flows that assume inherited authority.

## Hard rules

- **No custom cryptography.** Per `SECURITY.md` and the manifesto: compose reviewed primitives and existing standards. If a design requires new crypto, treat it as a red flag and push back.
- **Post-quantum / hybrid readiness from day one.** The protocol must be crypto-agile even if the first implementation uses classical suites.
- **Nothing is production-ready.** Drafts and any future reference code are experimental until reviewed.
- **Spec and implementation must not drift.** If you change one, plan the matching change to the other.

## When writing new specs

- Use the numbered `TF-XXXX` RFC style and keep the "Status" line honest (Draft until reviewed).
- Cross-reference rather than duplicate: `DECISIONS.md` holds the rationale; specs hold the normative contract; ADRs hold decision provenance.
- For any new capability, state which profile(s) it belongs to, its risk class, and its conformance implications.

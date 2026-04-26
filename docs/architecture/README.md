# TrustForge Architecture

This directory is the contributor- and operator-facing tour of how
TrustForge fits together. The normative source of truth is the spec
series in [`../specs/`](../specs/); these documents are commentary,
diagrams, and orientation. When the spec and these notes disagree, the
spec wins.

## What lives here

| Document | Audience | Use when |
|---|---|---|
| [`system-overview.md`](system-overview.md) | New contributor, architect | You want a single picture of the 12 layers and how Live Mode and Packet Mode flow through them. |
| [`data-flows.md`](data-flows.md) | Implementer of a daemon, adapter, or bridge | You need to know which fields are signed, which messages cross the wire, and which proof events are emitted for each major operation. |
| [`threat-boundaries.md`](threat-boundaries.md) | Security reviewer, red team | You need a readable rendering of the nine trust boundaries and twenty-four threats from `.tf/threat-model.yaml`. |
| [`dependency-graph.md`](dependency-graph.md) | Maintainer, packager | You are touching crate or workspace boundaries and need to see what depends on what. |

## How to read this directory

1. Start with [`system-overview.md`](system-overview.md). It anchors
   every other diagram — every later flow refers back to the layer
   numbers (1 through 12) defined there and inherited from
   [`../specs/TF-0001-core-architecture.md`](../specs/TF-0001-core-architecture.md).
2. Next, read [`data-flows.md`](data-flows.md). The flows are presented
   in dependency order: actor minting first, then sessions, then
   policy decisions, then proof, then federation, then evidence.
3. Once the data flows make sense, read
   [`threat-boundaries.md`](threat-boundaries.md). It maps each flow
   to the trust boundary it crosses and the threats that boundary
   defends against. The boundary list is the same one in
   `.tf/threat-model.yaml`.
4. Finally, [`dependency-graph.md`](dependency-graph.md) tells you
   which crate or tool owns the code that implements each flow.

## Naming conventions used in every diagram

These conventions are used throughout this directory and the rest of
the docs. They reflect the conventions in
[`../specs/TF-0001-core-architecture.md`](../specs/TF-0001-core-architecture.md)
and [`../specs/TF-0002-actor-identity.md`](../specs/TF-0002-actor-identity.md).

- **Actor URIs** look like `tf:actor:<kind>:<domain>/<name>`, e.g.
  `tf:actor:agent:example.com/code-helper`.
- **Actor instance URIs** add a host and session segment, e.g.
  `tf:instance:agent:example.com/code-helper/macbook/session-9912`.
- **Trust domain URIs** look like `tf:domain:<dns-label>`, e.g.
  `tf:domain:example.com`.
- **Capability tokens** are abbreviated `cap-tok` in diagrams.
- **Proof events** are abbreviated `pe`, with a kind suffix
  (`pe.session.opened`, `pe.action.allowed`, etc.).
- **Mode** is shaded into diagrams as `[live]` for active session and
  `[packet]` for offline / packet-mode delivery. A flow that supports
  both is marked `[live | packet]`.

## Cross-cutting documents

A few docs sit outside this directory but are required reading for
architecture work:

- [`../security/threat-model.md`](../security/threat-model.md) — long-form
  prose of the nine trust boundaries and twenty-four threats.
- [`../security/cryptography.md`](../security/cryptography.md) — every
  primitive used and why.
- [`../specs/TF-0001-core-architecture.md`](../specs/TF-0001-core-architecture.md)
  — normative definitions of the 12 layers and the canonical object
  vocabulary.
- [`../specs/TF-0003-proofwire-transport.md`](../specs/TF-0003-proofwire-transport.md)
  — Live Mode and Packet Mode transport.
- [`../specs/TF-0013-site-to-site-binary-path.md`](../specs/TF-0013-site-to-site-binary-path.md)
  — site-to-site framing and the `http-bridge` ProofRPC method kind.
- [`../../DECISIONS.md`](../../DECISIONS.md) — long-form rationale for
  early architecture decisions; consult this when something looks
  arbitrary.

## What this directory is not

- It is not a quickstart. New users should start with
  [`../tutorials/01-getting-started.md`](../tutorials/01-getting-started.md).
- It is not deployment documentation. Operators should read
  [`../ops/`](../ops/) and [`../topologies/`](../topologies/).
- It is not the public spec. The public, normative contract lives in
  [`../specs/`](../specs/). These pages will lag the specs by design;
  if a discrepancy appears, file an issue and update both together
  (per the "Spec and implementation must not drift" rule in
  `CLAUDE.md`).

## Status

Like everything else in 0.1.0: **draft**. Diagrams are accurate to the
0.1.0 reference implementation in [`../../crates/`](../../crates/) and
[`../../tools/`](../../tools/) but will move with the spec.

# Governance

## Status

TrustForge is at v0.1.0. Governance is intentionally lightweight at
this stage; the model below describes how decisions are made *today*
and how the project intends to evolve as it stabilises.

## Mission

TrustForge exists to ship a unified trust fabric for AI agents,
humans, services, and devices that:

- **Composes existing standards** (WebAuthn, SPIFFE, OAuth/GNAP, MCP,
  A2A, TLS, DID, Matrix) instead of replacing them.
- **Stays AI-implementable** — every concept ships with a machine-
  readable schema, conformance vectors, and an Agent Contract entry.
- **Stays profile-controlled** — home, enterprise, constrained, and
  compliance-evidence profiles select feature surfaces from the same
  spec rather than forking the architecture.
- **Tracks its specification 1:1 with its reference implementation.**

Any proposal that would compromise these four properties needs an
explicit ADR before it lands.

## Roles

At v0.1.0 there are two roles. Both expand over time as the project
attracts contributors.

- **Maintainer** — has merge authority on `main`, can publish releases,
  and represents the project in security disclosures. The current
  maintainer set is captured in `CODEOWNERS` (to be added in a
  follow-up release).
- **Contributor** — anyone who opens an issue or PR. Contributions
  follow the normal GitHub flow; CI must be green before merge.

Trust levels for contributors will eventually map to a tiered review
requirement (T1 reviews need one maintainer ack, T2 reviews need two,
spec-touching changes always require two), but at v0.1.0 every change
ships through a single maintainer review plus a passing CI run.

## Decision-making

| Change kind                                  | Mechanism             |
| -------------------------------------------- | --------------------- |
| Editorial fixes, doc changes, test additions | Single maintainer PR  |
| Code changes that don't touch wire format    | Single maintainer PR  |
| Wire-format changes, schema additions        | ADR + 7-day comment   |
| Cryptographic changes                        | ADR + security review |
| New profile, new bridge, new spec            | RFC-style TF-XXXX     |
| Removing a feature                           | ADR + 14-day notice   |

ADRs live in `docs/adr/`. Numbered TrustForge specs (TF-0000 onwards)
live in `docs/specs/`. Both are append-only — superseded decisions
remain in the tree with a "Superseded by" link rather than being
deleted.

## Spec process

1. A change starts as a proposal (issue or short doc).
2. If the proposal is non-trivial, the proposer drafts a numbered
   `TF-XXXX-*.md` document and opens a PR. The "Status" line begins
   `Draft`.
3. Discussion happens on the PR. The proposer revises until two
   maintainers ACK.
4. On merge, the spec is "Draft, accepted". It moves to `Stable` only
   after a v1.0 review pass.
5. Implementation lands in the same release window the spec is
   accepted for. Spec and implementation must not drift across a
   release boundary.

## Reference implementation

Rust (`crates/tf-types/`) is the flagship reference implementation;
TypeScript (`tools/tf-types-ts/`) is the parallel reference. Other
implementations are encouraged and conformance-validated through
`tools/tf-conformance/`.

A change that lands in only one of the two reference implementations
must include an explicit "deferred to v0.X" note in the CHANGELOG so
parity gaps are honest.

## Path to a foundation

The long-term direction is a vendor-neutral foundation that owns the
trademark, the spec process, and the conformance gate. The interim
arrangement is:

- maintainership held by the original author and contributors;
- license + trademark policy permissive enough that a foundation can
  adopt the project later without re-licensing;
- governance changes to support a foundation tracked as their own
  ADRs.

## Code of conduct

A Code of Conduct will be added before community contributions are
actively solicited. Until then, the operating norm is:

- Be technically rigorous and kind.
- Reject ad-hominem and political attacks.
- Treat security reports with confidentiality and urgency.
- Credit contributors visibly.

## Changing this document

GOVERNANCE.md changes follow the "wire-format change" review path:
ADR + 7-day comment + two maintainer ACKs. The intent is that the
governance model itself does not drift silently.

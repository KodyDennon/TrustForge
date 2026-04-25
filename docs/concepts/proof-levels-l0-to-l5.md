# Proof Levels L0–L5

> A six-step ladder for how strong the cryptographic record of an
> action is. The right level is policy-driven; "always L5" is wrong.

## What problem this solves

Cryptographic proof costs CPU, key material, storage, and
sometimes external services (TSA, transparency log). Forcing every
event through the strongest level burns money and makes the
ledger unreadable. Forcing every event through the weakest level
makes audit useless. You need a graduated scale where policy can
demand stronger proof for the actions that need it and skip the
overhead for the ones that don't.

TrustForge defines six levels (L0–L5) so policies can name the
strength they require. Bridges and adapters use the level to
decide which proof artefacts to generate. Auditors use the level
to decide what verification they can do.

## The ladder

From `TF-0005-proof-events-ledgers.md` and `DECISIONS.md`:

| Level | Name                          | What is generated                                       |
|-------|-------------------------------|---------------------------------------------------------|
| L0    | No proof                      | Nothing recorded.                                       |
| L1    | Session proof                 | The action is recorded as part of session metadata only. |
| L2    | Action proof                  | A signed, hash-chained `action.executed` event.         |
| L3    | Payload-hash proof            | L2 plus a payload commitment (BLAKE3 / SHA-256 of the affected bytes). |
| L4    | Encrypted evidence bundle    | L3 plus an encrypted bundle to a recipient set, including signed inputs and outputs. |
| L5    | Compliance-grade notarized   | L4 plus an external timestamp anchor (RFC 3161) and inclusion in a transparency log (RFC 6962). |

Each level adds artefacts; nothing in a higher level *replaces*
the lower levels. An L5 event also carries an L4 bundle, an L3
commitment, an L2 signed event, and an L1 session reference.

## What each level buys you

- **L0** — No record. Useful for "decision was allow, action was
  trivial, we don't care." Some constrained profiles use L0 for
  background telemetry.
- **L1** — Lightweight session metadata. Useful for high-volume
  read paths where *which session* did *something* is enough.
- **L2** — Verifiable that *this actor instance* did *this action
  on this target* at *this time*. Cross-language signature parity
  (`conformance/signature-vectors.yaml`) covers this.
- **L3** — Same as L2 plus *what payload was involved* via hash
  commitment. Verifier can later compare the payload against the
  commitment without trusting the daemon. Required for write
  actions in compliance-aware deployments.
- **L4** — Full encrypted evidence bundle. Includes inputs,
  outputs, intermediate state, and configuration. Sealed to a
  recipient set so only authorised auditors can open it.
  Implementation in `tools/tf-evidence/` (TS reference).
- **L5** — L4 plus external anchoring. RFC 3161 timestamp tying the
  bundle's hash to a trusted clock; RFC 6962 transparency-log
  inclusion proof tying it to an append-only public log. Required
  for legal-evidence and regulated-industry deployments.

## How levels are demanded

Policies attach a `proof_required` field to decisions:

```yaml
- id: "escalate.git-push"
  effect: "escalate"
  action: "git.push"
  approval: "required"
  proof_required: "L2"
```

The daemon ensures the matching artefact is generated before the
action completes. If the deployment cannot produce the demanded
level (e.g., L5 demanded but no TSA configured), the action is
denied — not silently downgraded.

The conformance profile sets a *floor*. The compliance-evidence
profile mandates L3 or higher for any write; the home profile
floors at L1.

## Worked example: the same `fs.write` at four levels

The same action against four different policies:

- Demo project: `proof_required: L0`. Action runs; nothing logged.
- Personal repo: `proof_required: L1`. Daemon emits a session
  metadata note "session X performed N writes between 14:00 and
  14:10".
- Production codebase with audit: `proof_required: L3`. Daemon
  emits a signed `action.executed` event including a BLAKE3
  commitment of the file's new contents. Verifier can later
  re-hash the file and confirm.
- Healthcare records system: `proof_required: L5`. Daemon emits
  the L3 event, packages an L4 evidence bundle (encrypted to the
  audit team's keys), submits the bundle's hash to an RFC 3161
  TSA, and submits the result to an RFC 6962 transparency log.
  Auditor receives a verifiable inclusion proof.

The action is the same `fs.write`. The artefacts produced grow
with the level.

## Common misconceptions

**"L5 is always best."** L5 is most expensive — RFC 3161 calls
out, RFC 6962 inclusion proofs, encrypted bundles. Use it when
you need the legal property; otherwise lower levels are
appropriate. The cost of L5 across a high-frequency action stream
can be prohibitive.

**"L0 means insecure."** L0 means *no proof artefact recorded*.
The action still went through policy decision and capability
checks; those *do* leave records. L0 just declines to add an
action-level event. For some R0 read paths this is correct.

**"Can I demand a level higher than my profile supports?"** No —
the profile floor is also a ceiling for what the deployment can
*produce*. If you need L5 events, your deployment must be
configured for L5 (TSA, transparency log).

**"L4 bundles compromise privacy because they include payloads."**
Bundles are encrypted to a recipient set. Only key holders can
decrypt. The hash of the bundle in the ledger reveals nothing
about its contents.

**"The level a policy demands is also what the auditor will see."**
The auditor sees the event(s) that the level produced. They may
not have access to the encrypted bundle (they need a key in the
recipient set). The level controls *what is generated*; *who can
read it* is a separate authorisation question.

**"Proof levels and trust levels are the same scale."** They are
not. Trust levels are about identity; proof levels are about
evidence. A high-trust actor (T7) doing a destructive action (R4)
still has to produce L3 or L4 proof — the policy is a function of
all three plus enforcement level.

## Where to look next

- `docs/concepts/proof-events-and-ledgers.md` — the underlying
  data model.
- `docs/concepts/risk-classes-r0-to-r5.md` — what triggers higher
  levels.
- `docs/concepts/trust-levels-t0-to-t7.md` — paired with risk in
  policy gates.
- `docs/concepts/enforcement-levels-e0-to-e5.md` — observe-mode
  also produces proof.
- `TF-0005-proof-events-ledgers.md` — normative spec.
- `tools/tf-evidence/` — L4 / L5 reference implementation.

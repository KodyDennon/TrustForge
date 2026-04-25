# Trust Levels T0–T7

> A coarse, eight-step ladder of how confident TrustForge is that an
> identity is who it claims to be. Policies *use* this scale to gate
> action; they do not *replace* it.

## What problem this solves

Authorization decisions need a way to ask: "is this identity
strong enough?" without re-deriving the answer from raw evidence
every time. The raw evidence is endless — does the actor have a
hardware-backed key, did they pass WebAuthn, is their device
healthy, are they org-issued, are they regulated, was a quorum
involved? Pushing all of that into every policy rule produces
unreadable policies that drift across deployments.

TrustForge distils the evidence into a small, well-defined ladder
— **trust levels T0–T7** — that policies can compare against. The
ladder is normative (the same labels mean the same things across
deployments), but the *mapping* from evidence to level can be
overlaid by an organization.

This is part of the same family as risk classes (R0–R5), proof
levels (L0–L5), and enforcement levels (E0–E5). Policy rules
typically reason about all four together: "if action is R3 and
actor is at T4, require L3 proof".

## The ladder

From `TF-0002-actor-identity.md` and `DECISIONS.md`:

| Level | Name                       | What it means                           |
|-------|----------------------------|-----------------------------------------|
| T0    | Unknown                    | No useful identity assertion at all.   |
| T1    | Self-claimed               | Identity claim with no out-of-band check. |
| T2    | Locally trusted            | Recognised by the local trust domain (e.g. enrolled by the operator). |
| T3    | Organization-issued        | Issued by an organization's authority root (CA, SSO, …). |
| T4    | Hardware-backed            | Identity bound to a hardware key (TPM, Secure Enclave, YubiKey, …). |
| T5    | Multi-party verified       | Multiple independent parties attest to the identity. |
| T6    | Publicly attestable        | Backed by a public anchor (transparency log, public CA chain). |
| T7    | Regulated / compliance-verified | Backed by a recognised regulator, license, or compliance authority. |

A higher number is not "better" in the abstract — it is more
*expensive* and more *contextual*. T7 is meaningful only inside a
domain that recognises the relevant regulator. T4 is meaningful
only when the verifier trusts the hardware path. Policies use the
ladder to express requirements; deployments configure the mapping.

## How a level is assigned

The level is assigned by the daemon during identity assertion.
Inputs include:

- which authority root signed the actor's credential;
- whether the credential is hardware-backed (per the WebAuthn,
  TPM, or Secure-Enclave bridge);
- whether multiple verifiers independently signed (federation);
- whether the credential is anchored in a public transparency log;
- whether a recognised regulator issued the credential.

The daemon emits a `trust.level.assigned` proof event when an
actor's level changes. Levels can change *down* as well as up
(e.g., a session that started at T4 with hardware presence
demotes to T2 when the user removes the YubiKey).

## Worked example

`acme.corp` configures the following overlay:

```yaml
trust_overlay:
  rules:
    - if: { issuer: webauthn, attestation: packed }
      assign: T4
    - if: { issuer: spiffe.acme.corp, hardware_attested: true }
      assign: T4
    - if: { issuer: spiffe.acme.corp, hardware_attested: false }
      assign: T3
    - if: { issuer: federated.partner.com, partner_state: active }
      assign: T3
    - if: { local_enrolment: true }
      assign: T2
    - default: T1
```

Policy rules then reason in terms of the ladder:

```yaml
- id: "deny.below-T2-on-write"
  effect: "deny"
  action: "fs.write"
  condition:
    actor_trust_level_below: T2
- id: "require-T4-for-prod-deploy"
  effect: "escalate"
  action: "ci.deploy"
  target_pattern: "env:prod/*"
  condition:
    actor_trust_level_below: T4
  approval:
    kind: required
```

A self-claimed agent (T1) cannot write at all. An org-issued
service (T3) can write but cannot deploy to prod without
hardware-backed identity (T4). A regulator-issued auditor (T7)
can deploy to prod *and* request compliance evidence bundles.

## Common misconceptions

**"T7 is the goal; everyone should aim for it."** No — T7 is
appropriate when a regulator says so. Most actors live at T2–T4
permanently. Striving for T7 in a home deployment is meaningless
(there is no relevant regulator).

**"Trust level replaces authorization."** It does not. Trust level
is one *input* to authorization. An actor at T4 with no
capabilities can still do nothing. An actor at T7 with negative
capabilities is still bound by the negative capabilities. Trust
level is a *gate condition*, not a grant.

**"Trust level is the same across all trust domains."** The
ladder labels are the same; the *mapping* is per-domain. T4 in
one domain might require a TPM; T4 in another might require a
YubiKey. Federation attestations carry the asserted level *and*
the issuing domain so the importing domain can re-evaluate.

**"Once assigned, trust level is fixed."** It can change
mid-session. Triggers include: hardware-presence loss, posture
change (the device fell out of compliance), federated peer
revocation, or deliberate operator action. The continuous
authorization loop (see `docs/concepts/continuous-authorization.md`)
re-checks gates whenever level changes.

**"Trust level is the same as a confidence score."** It is not a
floating-point score. It is a discrete ladder so policies are
deterministic and explainable. Mixing it with a continuous score
defeats the auditability of decisions. If a deployment needs a
score, that score should be reduced to a trust-level rung before
hitting policy.

**"Self-claimed (T1) is useless."** It is not useless — it is
useful for low-risk read-only flows where the cost of higher
identity is unjustified. T1 means "we believe this is who they
say they are, but we have no out-of-band check"; that is fine for
public read access in many systems.

## Where to look next

- `docs/concepts/risk-classes-r0-to-r5.md` — the action-side ladder
  policies pair this with.
- `docs/concepts/proof-levels-l0-to-l5.md` — the evidence-side
  ladder.
- `docs/concepts/enforcement-levels-e0-to-e5.md` — the posture
  ladder.
- `docs/concepts/federation-and-bridges.md` — how federated
  identities receive a trust level.
- `TF-0002-actor-identity.md` — normative ladder.
- `conformance/trust-overlay-vectors.yaml` — parity vectors for
  trust-overlay composition.

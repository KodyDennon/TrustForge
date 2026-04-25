# Approval Ceremonies

> Sometimes "yes" needs a human, a tap, or a quorum. Approval
> ceremonies are how TrustForge encodes that need into the protocol
> rather than bolting it on top.

## What problem this solves

Many high-risk actions cannot be auto-approved by policy: they need
a human in the loop, a hardware-token tap, a customer's presence,
or two officers to agree. Most systems handle this with bespoke
UIs that gate the action *outside* the policy engine. The result:

- The audit log shows "user clicked approve" but cannot prove
  *which* user, *with which device*, *under which session*, *under
  which authority root*.
- An attacker who controls the UI can stage a fake approval
  prompt; the protocol cannot tell the difference.
- "Two-of-three approval" is implemented per app, slightly
  differently each time, and rarely with a verifiable record.
- Cross-domain approvals (a vendor signs off on a customer's
  request) require ad-hoc out-of-band paperwork.

TrustForge promotes approvals to a protocol-level **ceremony**:
a structured, signed sequence of events, recorded as proof, that
turns a deferred decision into an authoritative grant. Approvals
are themselves proof events bound to the request they answer.

## Ceremony types

`TF-0004-capabilities-policy.md` and `DECISIONS.md` enumerate the
core ceremony types. They share a common shape: each emits a
signed approval event referencing a `request_id`, an actor (or
actors), a method, and the resulting decision.

- **Click approval** — single-tap acknowledgement from a
  human-in-control. Lowest friction; lowest assurance. Useful
  for R1–R2.
- **Passkey approval** — WebAuthn assertion bound to a fresh
  challenge, origin, and RPID. The bridge in
  `docs/bridges/webauthn-bridge.md` defines the mapping.
- **YubiKey tap** — user-present hardware-token signature.
- **Mobile push** — out-of-band notification + tap on a paired
  device.
- **Multi-party / quorum** — M-of-N approvers must each emit a
  signed approval. Quorum is policy-controlled (see "Quorum
  approval" in `DECISIONS.md`).
- **Time-delay approval** — auto-approve after T minutes unless a
  watcher cancels. Useful for "I'm leaving the office; if I don't
  cancel by 18:00, run the deployment" patterns.
- **Emergency override** — break-glass authority with mandatory
  post-event review (see `docs/concepts/emergency-authority-and-
  break-glass.md`).
- **Physical-presence proof** — biometric, card, or sensor.
- **Customer-present approval** — the customer is on the phone
  with the technician, both sign.
- **Signed offline approval packet** — Packet Mode approval
  carried via sneakernet, USB, or LoRa. Allows asynchronous
  approval from disconnected approvers.

## The ceremony lifecycle

1. **Trigger.** A policy decision yields verdict `escalate` with
   an approval block (see `docs/concepts/policy-decisions.md`).
2. **Ceremony record created.** A `approval.requested` proof event
   is emitted with a fresh `ceremony_id`, the request shape, the
   set of valid approvers, the policy that demanded the approval,
   and an `expires_at`.
3. **Approver(s) presented.** The `tf-daemon` displays the
   ceremony to each approver via the configured UI (CLI, dashboard,
   mobile push, hardware-token prompt).
4. **Each approver responds.** Each response is a signed
   `approval.granted` or `approval.rejected` event referencing the
   `ceremony_id`. The signature is the approver's instance key —
   not a shared service key — so each individual approval is
   independently verifiable.
5. **Threshold check.** When the policy's threshold is met
   (1-of-1, M-of-N, customer-AND-staff, …) the daemon emits
   `approval.completed` with verdict `granted`. If the threshold
   cannot be met before expiry, `approval.expired` fires and the
   underlying decision becomes `deny`.
6. **Capability issued.** A capability token bound to the
   `ceremony_id` is minted and delivered to the requesting actor
   instance. The token is single-use or short-lived, depending on
   policy.
7. **Action executed.** When the action runs, its `action.executed`
   proof event references the approval ceremony.

The ceremony record is permanent in the ledger. Replays of
denied/expired ceremonies do not auto-grant — the response is
bound to the ceremony id, which appears once.

## Worked example: M-of-N for a production deploy

Policy:

```yaml
- id: "escalate.deploy-prod"
  effect: "escalate"
  action: "ci.deploy"
  target_pattern: "env:prod/*"
  approval:
    kind: "quorum"
    quorum:
      threshold: 2
      approvers:
        - tf:actor:human:acme.corp/release-captain
        - tf:actor:human:acme.corp/security-officer
        - tf:actor:human:acme.corp/owner
    expires_in: "PT15M"
  proof_required: "L3"
```

The CI agent submits an action `ci.deploy env:prod/web`. The daemon
emits `approval.requested` with `ceremony_id = ap-2026-04-25-0099`
and pushes notifications to the three approvers. The release
captain and the security officer both tap a YubiKey within the
window; each emits a signed `approval.granted`. The threshold is
met; the daemon issues a capability token bound to that ceremony
id, with a 5-minute expiry. CI runs the deploy under the issued
token. The `action.executed` event references the ceremony, which
references both individual approvals, which reference the original
policy rule and bundle hash. An auditor walking the chain six
months later can prove exactly who agreed to that deploy.

If only one of the three approves before expiry, the ceremony fails;
the policy decision falls through to `deny`, and CI does not
deploy. The CI agent receives a denial referencing the failed
ceremony id, so it can present a meaningful error.

## Common misconceptions

**"An approval is just a click on a button."** A click can be the
*input* to an approval, but the protocol-level approval is a signed
event bound to the ceremony id. Without the signature, an attacker
who can render a UI can spoof an approval. WebAuthn / YubiKey / TPM
keys raise the bar so the *signature* requires the approver's
present hardware.

**"Quorum is hard to implement, so I'll fake it with a comment in
the audit log."** The schema and reference engines support quorum
out of the box (`approval.kind: "quorum"`). Use it. Faking quorum
in audit logs leaves no protocol-level guarantee; real quorum is
enforced by the daemon refusing to mint a capability until the
signed approvals arrive.

**"Time-delay approvals are dangerous."** They are when used
carelessly, but they have legitimate use (overnight deploys
gated on absence of cancellation). The mitigation is to combine
them with watchers: anyone in the cancel set can stop the
ceremony, and cancellation is itself a signed proof event.

**"If a user has admin role, they shouldn't need to be in an
approval ceremony."** They do, when policy says so. Admin grants
the *capability* to be an approver; it does not bypass approval.
This is what stops a single compromised admin account from
taking the whole system.

**"Emergency overrides bypass approval."** They bypass the
*specific* policy gate, not the *recording* of the override. An
emergency override is a special ceremony type with mandatory
post-event review and quorum-required revert if abused. See
`docs/concepts/emergency-authority-and-break-glass.md`.

**"Customer-present approval is just a checkbox."** No — it is a
signed event from the customer's actor instance. The customer's
key signs an approval whose target is the technician's pending
action. If the customer is not actually present (and so the
customer's key is not actually used), the approval cannot be
forged.

## Where to look next

- `docs/concepts/policy-decisions.md` — the verdict shape that
  triggers ceremonies.
- `docs/concepts/proof-events-and-ledgers.md` — how ceremonies are
  recorded.
- `docs/concepts/emergency-authority-and-break-glass.md` — the
  override path.
- `docs/tutorials/07-quorum-approvals.md` — set up M-of-N.
- `TF-0004-capabilities-policy.md` — normative spec.
- `schemas/approval-request.schema.json`,
  `schemas/approval-grant.schema.json` — wire formats.

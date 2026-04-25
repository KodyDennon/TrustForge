# Enforcement Levels E0–E5

> A six-step ladder of *how strictly the daemon applies policy right
> now*. The same architecture serves "watch silently" and
> "fail-closed".

## What problem this solves

Migrating an existing system to TrustForge is risky if the only two
modes are "off" and "blocking everything that doesn't have a
policy". Most teams need to spend time *watching* what the system
would do, *warning* on borderline cases, and *gradually*
introducing enforcement.

Enforcement levels make this graduation a first-class concept.
The same policy bundle, the same engine, and the same identity
infrastructure can run at any level, so flipping is a flag-flip
rather than a redeploy.

## The ladder

From `DECISIONS.md` "Progressive enforcement" and the conformance
spec:

| Level | Name                          | What happens on a deny verdict                            |
|-------|-------------------------------|------------------------------------------------------------|
| E0    | Observe only                  | Action proceeds; deny is recorded as `deny_observe`.       |
| E1    | Warn only                     | Action proceeds; warning is logged and emitted to operator.|
| E2    | Require proof logging         | Action proceeds; a proof event is mandatory before the action completes. |
| E3    | Require policy approval       | Action escalates if approval is required; otherwise allows. Operator must close the loop. |
| E4    | Block unauthorized action     | Real deny; action does not run.                            |
| E5    | Fail-closed / high-security  | Real deny; ambiguous evaluations also deny; daemon refuses to run if policy bundle is unhealthy. |

Higher levels are stricter. Lower levels are useful for migration
and for non-production environments. The level is per-policy or
per-action — a deployment can run E4 in production and E0 in
staging while pointing at the same daemon and identity stack.

## How the level is set

The level is configured in the daemon config or per-policy file:

```yaml
# .tf/daemon.yaml
enforcement:
  default: E3
  per_action:
    "ci.deploy": E4
    "fs.read": E1
  per_actor_pattern:
    "tf:actor:agent:example.com/code-helper": E4
    "tf:actor:human:example.com/staff": E3
```

Changes to enforcement level are themselves proof events
(`enforcement.changed`) so the history of "we ran at E0 from
2026-04-25 to 2026-05-01, then E1 to 2026-05-15, then E4" is
auditable.

The *profile* sets a floor: the compliance-evidence profile
forbids running below E4 (you cannot be "compliance-evidence
compatible" if you do not actually enforce). See
`docs/concepts/profiles-and-enforcement-levels.md`.

## Worked example: a safe migration

Day 0: a service team wants to add TrustForge to their service
without breaking it.

1. **Day 0 — E0 (observe).** Drop the adapter in. Every request
   produces a decision; every deny becomes `deny_observe`. Nothing
   is blocked. The team reads the dashboard, finds rules that
   would have denied legitimate traffic, fixes them.
2. **Day 7 — E1 (warn).** Same behaviour, but warnings now emit
   to the on-call channel. False positives surface noisily but
   don't cause outages. The team tunes policies.
3. **Day 14 — E2 (proof-logged).** Every action is now in the
   ledger with full L2 proof events. Still no enforcement, but
   audit-grade evidence is being collected.
4. **Day 21 — E3 (escalation).** Actions that policy says should
   escalate now actually open approval ceremonies. Approvers see
   the prompts; allow/deny decisions get made; the loop closes.
   Auto-allowed actions still proceed.
5. **Day 30 — E4 (block).** Real enforcement. Denies actually
   deny. The team has a 30-day base of evidence showing the
   policies are tuned. Roll-back available if a critical false
   positive surfaces.
6. **Day 60 — E5 (fail-closed) for security-critical paths.**
   Highest sensitivity actions run at E5: ambiguous evaluations
   (e.g., policy bundle stale, vault locked) deny rather than
   default-allow.

This sequence is captured in
`docs/tutorials/03-flip-to-enforcement.md`.

## Decision verdicts at each level

The verdict shape (see `docs/concepts/policy-decisions.md`) varies:

| Engine output       | At E0          | At E1          | At E2          | At E3          | At E4–E5     |
|---------------------|----------------|----------------|----------------|----------------|--------------|
| `allow`             | `allow_observe`| `allow`        | `allow`        | `allow`        | `allow`      |
| `escalate`          | `allow_observe`| `allow` + warn | `allow` + warn | `escalate`     | `escalate`   |
| `deny`              | `deny_observe` | `allow` + warn | `allow` + warn (with proof) | `escalate` (if recoverable) | `deny` |
| Ambiguous (E5 only) | `allow_observe`| `allow`        | `allow`        | `allow`        | `deny` (E5)  |

The shapes preserve verbatim policy outputs; the level controls
the *side effects*.

## Common misconceptions

**"Observe mode is just dry-run."** It is more than that —
observe-mode emits real proof events with `_observe` verdicts.
You can later replay the ledger at E4 and see exactly which
denies would have fired. Dry-run typically does not produce
durable artefacts; observe mode does.

**"E5 is the goal; everyone should run there."** E5 is appropriate
for security-critical systems and high-stakes workflows. For
day-to-day code editing or low-risk automation, E3 or E4 is
plenty. The cost of E5 is that any operational hiccup (vault
locked, policy bundle invalid) becomes an outage. That is sometimes
exactly what you want; often it is not.

**"Enforcement levels are the same as profile."** They are not.
The profile is a label about what features exist; enforcement is
a posture about how strictly we apply them. See
`docs/concepts/profiles-and-enforcement-levels.md`.

**"Once at E4, you can't go back."** You can — but the
`enforcement.changed` proof event records every transition. In
audited deployments, dropping enforcement is itself a privileged
action requiring quorum.

**"E0 doesn't need a daemon."** It does. The daemon is what
*evaluates* the policies; without it, you have no observe-mode
data. E0 is "daemon running, but verdict downgrades to observe".

**"I can run E4 globally and skip the migration phases."** You
can if you have full confidence in the policies and the system
is small. For most non-trivial deployments, the migration phases
catch policy bugs that would otherwise become outages. The cost
of running observe-mode for a few weeks is much smaller than the
cost of a broken production deploy.

## Where to look next

- `docs/concepts/policy-decisions.md` — verdict shape across
  levels.
- `docs/concepts/profiles-and-enforcement-levels.md` — how
  profiles set the floor.
- `docs/tutorials/03-flip-to-enforcement.md` — graduate
  observe → enforce.
- `docs/tutorials/02-bring-your-own-auth.md` — drop in at E0
  alongside an existing system.
- `TF-0010-conformance-governance.md` — how labels constrain
  enforcement.

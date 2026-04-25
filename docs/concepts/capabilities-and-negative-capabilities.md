# Capabilities and Negative Capabilities

> Allow rules describe what an actor *may* do. **Negative
> capabilities** describe what they *may not* do, and they always
> win.

## What problem this solves

Most authorization systems are additive: you grant role A, role B,
role C, and the union is what the principal can do. This breaks
two ways at once:

1. **Roles drift wider than intended.** A role originally meant for
   "deploy the docs site" gets extended over time to also include
   "edit the secrets file" because someone needed it once. The
   role's name no longer matches its grants. Re-auditing every
   role is expensive, so it does not happen.
2. **Override is impossible without restructuring.** When you need
   to say "Alice has the admin role, *except* she may not write to
   `production/secrets/`", you usually have to invent a new role
   that mirrors admin minus those permissions, then move Alice off
   admin. This is the "Spiderman pointing at Spiderman" problem of
   role explosion.

Worse, in the AI-agent era, you have a more pressing safety
problem: a sufficiently clever (or sufficiently prompt-injected)
agent can chain together a sequence of innocuous-looking grants to
reach a dangerous outcome. You need a way to say "no matter what
positive grants you accumulate, you will *never* be able to do
this" and have that guarantee hold against creative composition.

TrustForge's answer: **deny-overrides at the protocol layer**, with
explicit denials elevated to first-class objects (negative
capabilities) that ride alongside grants and always take precedence.

## The model

A **capability** is a permission to perform an action under
constraints. A capability is fully described by, at minimum:

- subject (actor or actor instance URI)
- action (e.g. `fs.write`, `git.push`)
- target pattern (e.g. `docs/**/*.md`)
- constraints (time window, session binding, hardware-presence,
  approval-gate, single-use, …)
- expiry (mandatory by default per `DECISIONS.md` "Expiration")

A **negative capability** has the same shape, but its semantic is
"deny". Critically:

- **Negative capabilities override grants regardless of order.**
  This is the `negative-capability-precedence` mitigation in
  `.tf/threat-model.yaml`.
- They are evaluated *first* by the policy engine.
- A grant cannot exempt itself from a denial.
- An agent cannot prompt-inject its way around a denial — the denial
  is enforced at the daemon, not in the agent's own context.

See `TF-0004-capabilities-policy.md` for the normative spec, and
`.tf/policy.yaml` in this repo for a worked policy that mixes
allows, escalations, and `negative_capabilities`.

## Worked example

Here is the policy this repo uses on itself
(`.tf/policy.yaml`, abridged):

```yaml
rules:
  - id: "allow.fs-write"
    effect: "allow"
    action: "fs.write"
    reason: "General file writes auto-approved within the tree."

  - id: "escalate.fs-write-protected"
    effect: "escalate"
    action: "fs.write"
    target_patterns:
      - ".github/workflows/*"
      - "SECURITY.md"
      - "CHANGELOG.md"
    approval: "required"

negative_capabilities:
  - name: "secrets.read"
    reason: "Repository contains no production secrets."
  - name: "fs.delete_tree"
    target: "**"
    reason: "Recursive delete reserved for the operator."
```

When AgentGuard sees an action, it evaluates in this order:

1. **Negative capabilities first.** Action `fs.delete_tree` against
   any path? Denied. End of story. No grant can override this.
2. **Specific escalations next.** `fs.write` against
   `.github/workflows/ci.yml` triggers human approval.
3. **General grants last.** `fs.write` against `src/foo.rs` is
   auto-allowed.

A maliciously prompt-injected agent that tries to compose
`fs.write` + glob expansion to wipe the tree fails at step 1: there
is no positive capability for `fs.delete_tree` because the action
class itself is denied. Even if the agent obtains `fs.write`
authority for `**`, the explicit denial of `fs.delete_tree` is a
**different action** that no `fs.write` grant can synthesise.

The `glob-escape-on-action-targets` mitigation provides the
matching-time half: target patterns are matched with glob escape
applied to caller-supplied input, so an attacker cannot inject `**`
metacharacters into a narrow grant to widen it.

## Constraint composition

Capabilities can stack constraints. For example:

```yaml
- subject: tf:instance:agent:example.com/code-helper/laptop/session-A
  action: fs.write
  target_pattern: "docs/**/*.md"
  constraints:
    expires_at: 2026-04-25T18:00:00Z
    requires_approval_id: ap-2026-04-25-0042
    requires_session: sess-9912
    single_use: false
    requires_proof_level: L2
```

Every constraint must be satisfied for the capability to apply. If
the session ends, the capability is no longer usable — the binding
to `sess-9912` fails. This is how TrustForge implements
"continuous authorization" (see
`docs/concepts/continuous-authorization.md`): capabilities are not
just checked at issuance, they are re-checked at use, and the
checks include facts about the world *now*.

## Common misconceptions

**"Can I grant a permission and then carve out exceptions inline?"**
You can, but the carve-outs become *negative capabilities*, not
extra fields on the grant. `target_patterns` accepts both `allow`
and `deny` forms because the precedence is uniform: deny first,
allow second. This is enforced uniformly across Cedar, Rego, and
the native engine.

**"Negative capabilities are just policy rules with `effect:
deny`."** At the wire level, yes — they share the same schema. The
distinction is that *negative capabilities are protocol-level
guarantees*, written as their own block in policy and surfaced
distinctly in proof events (`capability_denied` with a pointer to
the denying rule). When auditing, you can grep proof events for
denials caused by negative capabilities specifically; you cannot do
that as cleanly if denial is buried inside an opaque rule.

**"If a grant says ALLOW and a negative capability says DENY, surely
the more specific one wins?"** No. The negative capability **always**
wins, regardless of specificity. This is intentional: in safety-
critical systems, the deny side must be inviolate. If specificity
governed precedence, an attacker who could engineer a more-specific
allow could bypass any denial.

**"Negative capabilities are only for AI safety."** They are
load-bearing for AI safety, but they exist for human operators too.
A typical use: "Alice is org-admin, *except* she may not approve her
own promotion request." A capability of type `negative` against
`approval.self` enforces this without making Alice a less-than-
admin role.

**"Can I delete a negative capability?"** Yes, but it is itself a
high-risk action governed by policy. Removing a negative capability
is logged as a `negative_capability_removed` proof event with
attribution. In compliance profiles, removing one is itself a
quorum-required operation.

## Where to look next

- `docs/concepts/policy-decisions.md` — the structured decision
  format that grants and denials produce.
- `docs/concepts/agent-contracts-for-ai.md` — how `forbidden`
  blocks in an agent contract become negative capabilities.
- `docs/tutorials/05-write-a-policy.md` — write your first policy.
- `TF-0004-capabilities-policy.md` — normative spec.
- `.tf/policy.yaml` and `.tf/agent-contract.yaml` — repo dogfood.
- `schemas/capability-token.schema.json` — wire format.

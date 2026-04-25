# Risk Classes R0–R5

> A coarse six-step ladder of how dangerous an action is. Combined
> with trust levels and proof levels, it tells policy what to demand.

## What problem this solves

Authorization is fundamentally a question of "is the strength of
the identity, the strictness of the policy, and the verifiability
of the proof *sufficient* for the danger of the action?" Without a
shared scale for danger, every policy author invents one, and the
results don't compose.

Risk classes give a normative six-step ladder so policies can say
"this action is R3" and deployments can apply consistent treatment
across actor types, transports, and deployments. Bridges (WebAuthn,
SPIFFE, MCP, …) carry the action's risk class through, so a tool
call originating in MCP arrives at the daemon with R3 already
computed and the daemon can demand the appropriate proof.

## The ladder

From `TF-0004-capabilities-policy.md` and `DECISIONS.md`:

| Class | Name                                          |
|-------|-----------------------------------------------|
| R0    | Harmless / read-only / public                |
| R1    | Low-risk normal action                       |
| R2    | Sensitive read or limited write              |
| R3    | Privileged operation                         |
| R4    | Destructive / financial / security-impacting |
| R5    | Emergency / life-safety / irreversible       |

The ladder is intentionally short. A finer-grained scale would
not survive consistent application across deployments; a binary
"safe / dangerous" is too coarse for policy gating to be useful.

The dangerous-actions catalog (`examples/dangerous-actions/tf-
dangerous-std.yaml`) ships a starting taxonomy: standard actions
like `file.read` (R0), `file.write` (R1), `git.push` (R3),
`firmware.install` (R4), and `emergency.invoke` (R5).

## How risk classes are assigned

Risk class is intrinsic to the *action*, not to the *actor*. It
is assigned by:

- a standard action schema (TrustForge ships defaults — see
  `examples/dangerous-actions/`);
- the agent contract (`.tf/agent-contract.yaml` — every action
  declares a `risk` field);
- the calling bridge's mapping (e.g., the SPIFFE bridge maps
  certain mTLS-signed RPCs to R2 by default).

A deployment can override risk classes via overlay if its context
calls for it. For example, `git.push` is R3 by default, but in a
codebase that does post-merge auto-deploy, `git.push` to `main` is
effectively R4 because pushing implies deploying. The overlay
records why the risk class was raised.

## Worked example

The repo's dogfood agent contract (`.tf/agent-contract.yaml`)
shows the pattern:

```yaml
actions:
  - name: "fs.read"
    risk: "R0"
    approval: "none"
  - name: "fs.write"
    risk: "R1"
    approval: "conditional"
  - name: "git.commit"
    risk: "R1"
    approval: "conditional"
  - name: "git.push"
    risk: "R3"
    approval: "required"
    danger_tags: ["irreversible", "external-network"]
  - name: "shell.exec"
    risk: "R2"
    approval: "conditional"
    danger_tags: ["destructive"]
```

Policies in `.tf/policy.yaml` then map class to treatment:

- R0 actions auto-allow.
- R1 actions auto-allow with proof at L1.
- R2 actions escalate if running against unfamiliar targets.
- R3 actions always escalate, require L2 proof.
- R4+ actions require quorum and L3+ proof.

A composed policy can be expressed concisely:

```yaml
- id: "global.risk-tier-defaults"
  effect: "tier"
  conditions:
    R0: { allow: true, proof: L0 }
    R1: { allow: true, proof: L1 }
    R2: { escalate_unless: known_target, proof: L1 }
    R3: { escalate: required, proof: L2 }
    R4: { quorum: 2, proof: L3 }
    R5: { quorum: 3, proof: L4, anchor: required }
```

Specific rules layer on top: "for `git.force_push`, deny outright,
overriding tier defaults."

## Worked example: AI agent demanding broader authority

An AI coding agent attempts `fs.write` to a path outside its
configured allow-list. The action class is R1, but the *target*
makes the situation R2-equivalent because the path is a security-
sensitive file (`SECURITY.md`). The policy elevates the effective
class:

```yaml
- id: "elevate.security-files"
  effect: "elevate-risk"
  action: "fs.write"
  target_pattern: "SECURITY.md"
  to_class: "R2"
  reason: "Security-sensitive content."
```

After elevation the action escalates rather than auto-allowing.
The decision records both the original and the elevated class so
auditors can see why the path was different from a normal write.

## Common misconceptions

**"Risk class and trust level are the same thing."** They are
not — they form a matrix. Trust level is about *who*; risk class
is about *what*. A T7 actor doing R5 still needs the same approval
gates as anyone else doing R5; trust level just controls whether
they are *eligible* to attempt it.

**"R5 means impossible."** R5 means emergency-grade. R5 actions
are achievable; they cost a serious ceremony (multi-party
approval, hardware presence, post-event review).

**"I can just give every action R0 to make life easier."** You
can — and your policy will mostly be irrelevant after that. The
point of the ladder is to be honest about danger so policy can
respond appropriately. Misclassifying R3 as R0 is exactly how
auth bypasses get shipped.

**"Risk class doesn't apply to read-only actions."** R0 *is* the
read-only class — and within reads, some are R2 (sensitive) and
some are R0 (public). "Read everything in `/customer-data/`" is
not R0.

**"Risk class is fixed forever."** It can be elevated by overlay
or by context. A normally-R1 action against a sensitive target
can become R2; a normally-R3 action during emergency mode can
become R5. Each elevation is recorded.

**"R5 is only for life-safety."** R5 is for emergency, life-safety,
or *irreversible* actions. Wiping production data permanently is
R5 even if no one is in danger.

## Where to look next

- `docs/concepts/trust-levels-t0-to-t7.md` — the *who* axis.
- `docs/concepts/proof-levels-l0-to-l5.md` — the *evidence* axis.
- `docs/concepts/enforcement-levels-e0-to-e5.md` — the *posture*
  axis.
- `docs/concepts/capabilities-and-negative-capabilities.md` — what
  policies grant.
- `TF-0004-capabilities-policy.md` — normative spec.
- `examples/dangerous-actions/tf-dangerous-std.yaml` — standard
  catalog.

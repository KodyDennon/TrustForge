# Policy Decisions

> A policy decision is the *answer*, signed and explainable, to "may
> this action proceed, and on what terms?"

## What problem this solves

Most policy engines return a boolean: allow or deny. That is not
enough for systems where decisions need to be explained later,
re-played from a ledger for audit, gated on human approval, or
escalated under quorum rules. A boolean cannot say:

- "Allow, but only if you also produce an L4 evidence bundle."
- "Allow, but only with two-of-three approval from the on-call list."
- "Deny, because rule `escalate.fs-write-protected` matched and the
  approval queue rejected the request at 14:31."
- "Allow in observe mode, but in enforce mode this would have been
  denied — useful, please log a warning."

TrustForge's policy decision is a structured object with an explicit
*verdict*, *constraints*, *obligations*, and *justification*, signed
by the policy engine and emitted as a proof event. Every decision is
auditable, replayable, and machine-readable by AI agents that need
to react to denials by negotiating narrower permission.

## The decision shape

Every policy evaluation produces an object conforming to
`schemas/policy-decision.schema.json`. The fields that matter:

- **verdict** — one of:
  - `allow` — proceed.
  - `deny` — do not proceed.
  - `escalate` — defer to an approval ceremony before deciding.
  - `allow_observe` — observe-only mode; would have allowed.
  - `deny_observe` — observe-only mode; would have denied.
- **subject** — the actor / actor instance the decision is about.
- **action** — the action class (e.g. `fs.write`, `git.push`).
- **target** — the resource (file path, URL, record ID).
- **matched_rule** — pointer into the policy bundle (rule id +
  version hash).
- **proof_required** — proof level (`L0`–`L5`) that the action must
  emit on completion.
- **approval** — `none` / `conditional` / `required` / `quorum`
  with details.
- **constraints** — extra conditions (time-bounds, session-binding,
  hardware-presence).
- **reason** — human-readable text from the matching rule.
- **expires_at** — when this decision stops being valid (decisions
  themselves expire, even allows).
- **engine** — which engine produced this (`cedar`, `rego`,
  `native`, `plugin:foo`).
- **engine_version** — pinned version of the engine.
- **policy_bundle_hash** — content hash of the policy bundle that
  produced the decision, so the exact ruleset can be reconstructed.

The decision is signed by the policy engine and emitted as a proof
event of type `policy.decision` (see `TF-0005-proof-events-
ledgers.md`). The signed decision is what AgentGuard hands to the
caller, and it is what shows up in `tf policy explain`.

## Worked example

Suppose an AI agent attempts `fs.write` to `.github/workflows/ci.yml`
in this repo. The applicable rule from `.tf/policy.yaml` is:

```yaml
- id: "escalate.fs-write-protected"
  effect: "escalate"
  action: "fs.write"
  target_patterns:
    - ".github/workflows/*"
    - "SECURITY.md"
    - "CHANGELOG.md"
  approval: "required"
  reason: "Workflow files and release artefacts must be human-
    reviewed."
```

The decision object emitted is, conceptually:

```json
{
  "decision_id": "dec-2026-04-25-018f...",
  "verdict": "escalate",
  "subject": "tf:instance:agent:example.com/code-helper/laptop/sess-A",
  "action": "fs.write",
  "target": ".github/workflows/ci.yml",
  "matched_rule": {
    "id": "escalate.fs-write-protected",
    "policy_bundle_hash": "blake3:9a3f..."
  },
  "approval": {
    "kind": "required",
    "ceremony_id": "ap-2026-04-25-0042"
  },
  "proof_required": "L2",
  "constraints": {
    "expires_at": "2026-04-25T18:00:00Z"
  },
  "reason": "Workflow files and release artefacts must be human-
    reviewed.",
  "engine": "native",
  "engine_version": "tf-cedar:0.1.0",
  "signature": {
    "key_thumbprint": "sha256:1aef...",
    "alg": "ed25519",
    "sig": "0x..."
  }
}
```

The agent receives this, knows the action is **escalated**, displays
the prompt to the human, and waits for `approval.granted` or
`approval.rejected` referencing `ap-2026-04-25-0042`. A second
decision is then emitted at the moment of completion.

Two related concepts ride on this:

- The decision is **deterministic** — given the same inputs, same
  policy bundle hash, and same engine version, the same verdict
  must come out. Cross-language parity vectors enforce this
  (see `conformance/guard-vectors.yaml`).
- The decision is **explainable** — `tf policy explain
  dec-2026-04-25-018f...` reproduces the rule chain, the inputs
  evaluated, and (for escalations) what would have changed the
  outcome.

## Decision modes per enforcement level

The same policy can produce different decision *kinds* depending on
the active enforcement level (see `docs/concepts/enforcement-levels-
e0-to-e5.md`). At E0 (observe), every decision is `allow_observe` or
`deny_observe`, never `deny` proper — useful when shadowing an
existing app to learn its access patterns without breaking
production. At E4+, decisions are real and the daemon refuses to
boot if they cannot be enforced.

## Common misconceptions

**"A decision is just allow/deny plus a reason string."** No — the
constraints and obligations are part of the decision. An "allow"
that also requires L4 proof is a different decision from an "allow"
that requires only L1, and downstream consumers must honour the
constraints to be conformant.

**"The policy engine is the source of truth."** The policy *bundle*
is. The engine is a function from (request, bundle) to decision.
Pinning the engine version and the bundle hash is what makes
decisions reproducible — important for audit and for federated
deployments where two domains run different engines but share the
same bundle.

**"Decisions can live forever."** They cannot — they expire.
Decisions over R0/R1 actions might be cached for the session;
decisions over R3+ actions typically expire on the order of seconds
to minutes. The `expires_at` field is mandatory.

**"Observe-mode decisions are just warnings."** They are full proof
events. The point of observe mode is to gather evidence with
production fidelity *without* enforcement. When you flip to enforce,
you do not need to re-derive the decisions; you flip a flag and the
*same* engine starts emitting `deny` instead of `deny_observe`. See
`docs/tutorials/03-flip-to-enforcement.md`.

**"Cedar / Rego don't model this."** TrustForge wraps Cedar and Rego
to produce a TrustForge-conformant decision. The engine emits its
native verdict; the wrapper attaches subject, action, target, and
constraint fields, signs the result, and turns it into a proof
event. See `crates/tf-cedar/` and `crates/tf-rego/`.

## Where to look next

- `docs/concepts/capabilities-and-negative-capabilities.md` — what
  the engine evaluates against.
- `docs/concepts/proof-events-and-ledgers.md` — where the signed
  decision is recorded.
- `docs/concepts/approval-ceremonies.md` — what happens between an
  `escalate` and the final outcome.
- `TF-0004-capabilities-policy.md` — normative model.
- `schemas/policy-decision.schema.json` — wire format.
- `conformance/guard-vectors.yaml` — cross-language parity vectors.

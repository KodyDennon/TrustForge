# 04 — Policy authoring (Cedar + Rego)

Goal: write a non-trivial Cedar policy and an equivalent Rego
(OPA) policy. Evaluate both against a set of test cases. About
30 minutes.

By the end you will have:

- A Cedar policy with positive grants, negative capabilities,
  attribute-based decisions, and approval ceremonies.
- The same policy in Rego.
- A test harness using `tf policy simulate` that confirms both
  produce the same decisions for the same inputs.

This tutorial assumes you have completed
[01 Getting started](01-getting-started.md). It does not require
tutorials 02 or 03 — you can author and evaluate policies
without an HTTP-facing application.

## Pick an engine

The two engines are interchangeable from TrustForge's point of
view: both produce the same `Decision` shape. Pick by
preference:

| Cedar | Rego (OPA) |
|---|---|
| Strongly typed, schema first. | Dynamically typed, but rules can be more expressive. |
| Smaller surface, easier to reason about. | Familiar to operators with OPA experience. |
| `crates/tf-cedar/` | `crates/tf-rego/` |

The TrustForge `Decision` shape is the same in both; the engine
choice is internal to the daemon.

## The example domain

We will model a small file-sharing service:

- Actors: humans and AI agents.
- Actions: `doc.read`, `doc.write`, `doc.share`.
- Targets: `doc:<id>` URIs.
- Attributes: each actor has a `trust_level` (T0–T7); each
  document has a `classification` (`public`, `internal`,
  `confidential`, `restricted`).

We want:

1. Anyone may `doc.read` a `public` doc.
2. Trust level >= 3 may `doc.read` an `internal` doc.
3. Trust level >= 5 may `doc.read` a `confidential` doc.
4. Trust level >= 6 may `doc.read` a `restricted` doc, **but**
   only with a fresh approval.
5. AI agents may not `doc.share` regardless of trust level
   (negative capability — prompt-injection defense).
6. The doc `doc:executive-comp` is forbidden to everyone except
   actors with explicit role `board` (regardless of trust level).

## Step 1 — Cedar policy

Create `.tf/policy.yaml` (Cedar engine):

```yaml
engine: cedar
schema: |
  entity Action;
  entity Actor in [Group] {
    trust_level: Long,
    kind: String,           // "human" | "agent"
    roles: Set<String>,
  };
  entity Target {
    classification: String, // "public" | "internal" | "confidential" | "restricted"
    id: String,
  };
  entity Group;

rules: |
  // Rule 1 — anyone reads public.
  permit (principal, action == Action::"doc.read", resource)
  when { resource.classification == "public" };

  // Rule 2 — internal needs trust_level >= 3.
  permit (principal, action == Action::"doc.read", resource)
  when {
    resource.classification == "internal" &&
    principal.trust_level >= 3
  };

  // Rule 3 — confidential needs trust_level >= 5.
  permit (principal, action == Action::"doc.read", resource)
  when {
    resource.classification == "confidential" &&
    principal.trust_level >= 5
  };

  // Rule 4 — restricted needs trust_level >= 6 AND an approval.
  permit (principal, action == Action::"doc.read", resource)
  when {
    resource.classification == "restricted" &&
    principal.trust_level >= 6 &&
    context.approval == true
  };

  // Rule 5 — AI agents may not share.
  forbid (principal, action == Action::"doc.share", resource)
  when { principal.kind == "agent" };

  // Rule 6 — only board may touch executive-comp.
  forbid (principal, action, resource == Target::"doc:executive-comp")
  unless { principal.roles.contains("board") };
```

Reload:

```bash
curl -X POST http://127.0.0.1:8787/v1/policy/reload \
    -H "Authorization: Bearer $TF_ADMIN_TOKEN"
```

## Step 2 — Define some actors

```bash
TF_VAULT_PASS=dev-pw bun run tools/tf-cli/src/cli.ts actor create \
    --type human --name alice --domain example.com \
    --attribute trust_level=3 --attribute kind=human \
    --attribute roles=staff

TF_VAULT_PASS=dev-pw bun run tools/tf-cli/src/cli.ts actor create \
    --type human --name carol --domain example.com \
    --attribute trust_level=6 --attribute kind=human \
    --attribute roles=board

TF_VAULT_PASS=dev-pw bun run tools/tf-cli/src/cli.ts actor create \
    --type agent --name code-helper --domain example.com \
    --attribute trust_level=5 --attribute kind=agent \
    --attribute roles=tools
```

## Step 3 — Simulate decisions

```bash
# Alice reads public doc → allow
tf policy simulate \
    --actor tf:actor:human:example.com/alice \
    --action doc.read \
    --target doc:welcome \
    --target-attribute classification=public

# Alice reads confidential doc → deny (needs trust >= 5)
tf policy simulate \
    --actor tf:actor:human:example.com/alice \
    --action doc.read \
    --target doc:plans-q3 \
    --target-attribute classification=confidential

# Carol reads restricted doc with approval → allow
tf policy simulate \
    --actor tf:actor:human:example.com/carol \
    --action doc.read \
    --target doc:legal-memo \
    --target-attribute classification=restricted \
    --context approval=true

# Code-helper tries to share → deny (negative capability)
tf policy simulate \
    --actor tf:actor:agent:example.com/code-helper \
    --action doc.share \
    --target doc:plans-q3

# Carol touches executive-comp → allow (board role)
tf policy simulate \
    --actor tf:actor:human:example.com/carol \
    --action doc.read \
    --target doc:executive-comp \
    --target-attribute classification=confidential

# Alice touches executive-comp → deny (no board role)
tf policy simulate \
    --actor tf:actor:human:example.com/alice \
    --action doc.read \
    --target doc:executive-comp \
    --target-attribute classification=internal
```

Each simulate command prints the decision plus the rule(s) that
fired. `tf policy simulate` does not write proof events; use
`/v1/decide` for evaluations you want recorded.

## Step 4 — Equivalent Rego

Switch the engine and rewrite:

```yaml
engine: rego
bundle: |
  package trustforge.policy

  default decision := {"effect": "deny", "reasons": ["no matching grant"]}

  decision := {"effect": "allow", "reasons": ["public doc"]} {
    input.action == "doc.read"
    input.target.classification == "public"
  }

  decision := {"effect": "allow", "reasons": ["internal+trust3"]} {
    input.action == "doc.read"
    input.target.classification == "internal"
    input.actor.trust_level >= 3
  }

  decision := {"effect": "allow", "reasons": ["confidential+trust5"]} {
    input.action == "doc.read"
    input.target.classification == "confidential"
    input.actor.trust_level >= 5
  }

  decision := {"effect": "allow", "reasons": ["restricted+trust6+approval"]} {
    input.action == "doc.read"
    input.target.classification == "restricted"
    input.actor.trust_level >= 6
    input.context.approval == true
  }

  # Negative capabilities first; "deny" wins.
  decision := {"effect": "deny", "reasons": ["agent cannot share"]} {
    input.action == "doc.share"
    input.actor.kind == "agent"
  }

  decision := {"effect": "deny", "reasons": ["executive-comp restricted"]} {
    input.target.id == "doc:executive-comp"
    not contains(input.actor.roles, "board")
  }
```

Rego evaluates all rules; the daemon merges them into a single
TrustForge decision with deny precedence (negative-capability
precedence). The result of every simulate command above must
match the Cedar version exactly.

## Step 5 — Cross-engine parity test

A useful exercise: write each test case as a YAML vector and
have the daemon assert parity:

```yaml
# tests/policy-parity.yaml
cases:
  - name: alice reads public
    actor: tf:actor:human:example.com/alice
    action: doc.read
    target: doc:welcome
    target_attributes: { classification: public }
    expect: allow

  - name: code-helper tries to share
    actor: tf:actor:agent:example.com/code-helper
    action: doc.share
    target: doc:plans-q3
    expect: deny
```

Run:

```bash
tf policy simulate --vectors tests/policy-parity.yaml --engine cedar
tf policy simulate --vectors tests/policy-parity.yaml --engine rego
```

Both must return identical decisions. If they diverge, the
divergence is a bug in your policy translation; fix it before
committing.

## Step 6 — Approval ceremony in detail

Rule 4 requires `context.approval == true`. When the adapter
calls `/v1/decide` without that context, the daemon returns
`escalate` with the approval id, queues the approval, and waits.

```bash
# Trigger the escalation — daemon returns escalate with id.
tf policy simulate \
    --actor tf:actor:human:example.com/carol \
    --action doc.read \
    --target doc:legal-memo \
    --target-attribute classification=restricted

# Operator-side: list and approve.
tf approval list
tf approve <approval-id>

# Re-decide; now context.approval == true → allow.
tf policy simulate \
    --actor tf:actor:human:example.com/carol \
    --action doc.read \
    --target doc:legal-memo \
    --target-attribute classification=restricted \
    --context approval=true
```

Production adapters poll the daemon (with `onEscalate: "wait"`)
or subscribe to approval events. See
[`../concepts/approval-ceremonies.md`](../concepts/approval-ceremonies.md).

## What you have learned

- Cedar and Rego are interchangeable surfaces for the same
  decision shape.
- Negative capabilities are first-class. `forbid` (Cedar) /
  early-deny (Rego) overrides every positive grant.
- Approvals are a third decision class alongside allow and deny.
- Cross-engine parity is testable. Use `--vectors` to lock in
  expectations.

## What to read next

- [05 Federation](05-federation.md) — share policies and
  identities across two trust domains.
- [`../specs/TF-0004-capabilities-policy.md`](../specs/TF-0004-capabilities-policy.md)
  — normative capability and policy contract.
- [`../concepts/capabilities-and-negative-capabilities.md`](../concepts/capabilities-and-negative-capabilities.md)
  — narrative on positive and negative capabilities.

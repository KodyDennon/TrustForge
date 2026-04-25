# TrustForge AI Integration Guide

This document tells AI coding agents and AI-driven runtimes how to interact with a TrustForge-enabled repository *safely*. Every step is enforceable: violating it either fails validation (before the agent runs) or fails a live guard check (during the agent run).

TrustForge is built with the assumption that the people operating the agent want to say yes to the agent often, but only after the agent has proven it understood the rules. This guide is the contract between the agent and the repository.

## 1. Discover the contract

When an AI agent opens a TrustForge-enabled repository, it SHOULD look for:

- `.tf/agent-contract.yaml` — the project's declarative rules.
- `.tf/threat-model.yaml` — optional companion.
- `.tf/policy.yaml` — optional companion.
- `.tf/proof-profile.yaml` — optional companion.

Absent a contract, the agent is operating outside TrustForge and should fall back to its host platform's permission model.

## 2. Validate the contract before use

Run:

```bash
bun run tools/tf-schema/src/cli.ts agent-contract-check .tf/agent-contract.yaml \
  --catalog examples/dangerous-actions/tf-dangerous-std.yaml
```

A non-zero exit means the contract is malformed or internally inconsistent — treat the repository as unsafe until the contract is fixed. Library authors should wire this check into CI as a non-optional gate.

## 3. Generate typed bindings

Agents that run TypeScript or Rust code get type-level guarantees by generating bindings:

```bash
bun run tools/tf-schema/src/cli.ts codegen --target agent-contract-ts \
  --spec .tf/agent-contract.yaml

bun run tools/tf-schema/src/cli.ts codegen --target agent-contract-rust \
  --spec .tf/agent-contract.yaml
```

The TypeScript output exposes `Action` as a literal union of declared action names; any reference to an action not in the contract fails at compile time. The Rust output exposes per-action `ACTION_*` constants and an `Action` enum for the same reason.

## 4. Consult the guard before *every* action

At runtime, the agent MUST call `AgentGuard.check(...)` before executing any TrustForge-declared action:

```ts
import { createAgentGuard, checkAction } from "./generated/agent-contract/exampleappfullcontract";

const guard = createAgentGuard({ onEvent: (ev) => myProofLog.append(ev) });

function runFileWrite(path: string, contents: string): void {
  const decision = checkAction(guard, "file.write", path, /* actor */ "tf:actor:agent:acme.com/coder");
  switch (decision.kind) {
    case "allow":
      return performWrite(path, contents);
    case "approval-required":
      return requestHumanApproval(decision, () => performWrite(path, contents));
    case "escalate":
      // danger_tags triggered this — do NOT proceed without explicit human
      // confirmation even if approval_required would have been "conditional".
      return requestHumanApprovalWithExplainer(decision);
    case "deny":
      throw new Error(`action denied by agent-contract: ${decision.reason}`);
  }
}
```

The Rust equivalent:

```rust
use generated::example_app_full::{create_agent_guard, check_action};
use tf_types::guard::GuardDecision;

let guard = create_agent_guard();
let decision = check_action(&guard, "file.write", Some(path.to_string()), Some(actor.clone()));
match decision {
    GuardDecision::Allow { .. } => perform_write(path, contents),
    GuardDecision::ApprovalRequired { .. } => request_human(decision),
    GuardDecision::Escalate { .. } => request_human(decision),
    GuardDecision::Deny { reason, .. } => panic!("agent-contract denied: {reason}"),
}
```

## 5. Escalate on dangerous tags — always

The contract's `danger_tags` field is the agent's hard backstop. If `AgentGuard` returns `escalate` for any of:

- `destructive`
- `irreversible`
- `financial`
- `security-sensitive`
- `legal-exposure`

the agent MUST obtain explicit human confirmation for *this specific invocation* before proceeding, even if:

- the declared `approval` is `none` or `conditional`,
- the caller claims a valid capability,
- the action worked without escalation in a previous session.

Escalation bypass is a protocol violation.

## 6. Emit proof events

Every completed action — allowed, denied, or escalated — SHOULD be written to a `.tflog`:

```ts
import { eventHash, writeTfproof, RpcProofEventStub } from "tf-types";

function recordGuardEvent(ev: GuardEventStub): void {
  myTflog.append({
    event_version: "1",
    id: randomId(),
    type: `guard.${ev.decision}`,
    actor_id: ev.actor,
    timestamp: new Date().toISOString(),
    level: "L1",
    subject_ref: ev.action,
    context: { target: ev.target, danger_tags: ev.danger_tags },
    signature: /* ed25519 signature over the canonical payload */,
  });
}
```

The `AgentGuard` surfaces guard events via its `onEvent` callback; the `RpcServer` surfaces `rpc.call` events via its `onProofEvent` callback. Both write into the same log via the `.tflog` format.

## 7. When in doubt, deny and ask

Every enforcement hook in TrustForge fails closed. If the agent cannot unambiguously confirm an action is allowed:

- the guard returns `deny`,
- the RPC server returns `permission_denied`,
- the session rejects out-of-order frames,
- the `.tfproof` binary refuses to open on bad magic.

An agent that encounters any of these should NOT retry blindly. Surface the failure to the human, include the reason, and wait.

## 8. Cross-reference

| Concept | Spec | Schema |
| --- | --- | --- |
| Actor identity | TF-0002 | `actor-identity.schema.json` |
| Capability + policy | TF-0004 | `policy.schema.json`, `capability-token.schema.json` |
| Proof events | TF-0005 | `proof-event.schema.json`, `proof-bundle.schema.json` |
| Agent contract | TF-0006 | `agent-contract.schema.json` |
| Dangerous-actions catalog | TF-0006 | `dangerous-actions.schema.json` |
| ProofRPC | TF-0007 | `proofrpc.schema.json` |

Canonical example contract: [`examples/agent-contracts/full.yaml`](../examples/agent-contracts/full.yaml).
Canonical dangerous-actions catalog: [`examples/dangerous-actions/tf-dangerous-std.yaml`](../examples/dangerous-actions/tf-dangerous-std.yaml).

## 9. What this guide does NOT cover

- Key management / vault semantics (Phase 6).
- Quorum approval ceremonies (Phase 6).
- Federated trust domains and cross-domain delegation (Phase 7+).
- Post-quantum hybrid signing (Phase 6+; envelope already carries the fields).

If your integration reaches those frontiers, escalate to the human and fall back to the host platform's permission model until TrustForge publishes the corresponding spec.

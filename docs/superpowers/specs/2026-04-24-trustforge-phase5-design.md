# TrustForge Phase 5 — Agent Contract Design

**Date:** 2026-04-24
**Status:** Draft, approved for implementation planning
**Scope:** Roadmap Phase 5 — extend `.tf/agent-contract.yaml` with dangerous-action semantics, implement a deep contract validator, land codegen hooks that emit typed guard runtimes, write the AI integration guide, and publish the canonical dangerous-actions catalog.

## 1. Purpose

The agent-contract is how a TrustForge-enabled codebase tells AI agents: *here is what you can do, under which risk and approval rules, with which targets allowed or forbidden.* Phase 5 goes beyond JSON Schema validation to:

- Cross-validate references (every declared action resolves; no action appears in both `actions[]` and `forbidden[]`; no orphan target set).
- Let deployments tag dangerous actions with structured danger categories (financial, destructive, irreversible, security-sensitive, privacy, external-network) and optional pre-conditions.
- Generate typed `AgentGuard` runtimes (TS + Rust) that answer *is this action allowed against this target for this caller* with a structured decision.
- Provide a canonical `dangerous-actions.schema.json` catalog so multiple contracts can share a common danger taxonomy.
- Publish `docs/ai-integration.md` — the concrete guide an AI agent reads before touching a TrustForge repository.

## 2. Non-goals

- **No runtime capability token resolution.** Phase 6 (daemon + vault) will turn a name into a signed token; Phase 5 only consults the contract declaratively.
- **No policy engine.** Cedar/Rego integration is Phase 6+; Phase 5's guard is a straight interpreter of the declarative contract.
- **No UI for approval ceremonies.** The contract says "approval required"; who asks the user is Phase 6.
- **No proof-event emission on every decision yet.** The guard exposes a proof-event *stub* callback (same shape as ProofRPC's stub) ready to write into a .tflog once Phase 6 wires the log.
- **No dynamic contract reload.** A guard is bound to the contract it was built from.

## 3. Schema extensions

Add optional fields to `schemas/agent-contract.schema.json` under `$defs.Action`:

- `parameters` — inline JSON Schema fragment describing the action's argument shape.
- `reversible` — boolean hint.
- `danger_tags` — array of strings from a closed enum (below).
- `pre_conditions` — array of human-readable gate strings (e.g. `"tests-pass"`, `"no-uncommitted-secrets"`).

New `$def DangerTag`:

```yaml
enum: [financial, destructive, irreversible, security-sensitive, privacy, external-network, legal-exposure, high-compute]
```

And a brand-new schema `schemas/dangerous-actions.schema.json`:

```yaml
dangerous_actions_version: "1"
catalog_id: tf-dangerous-std          # dotted id pattern
actions:
  - name: file.delete
    danger_tags: [destructive, irreversible]
    default_risk: R4
    default_approval: required
    default_reversible: false
    description: "Remove a file from the working tree. Irreversible without VCS recovery."
  - name: shell.exec
    danger_tags: [destructive, external-network, security-sensitive]
    default_risk: R4
    default_approval: required
    default_reversible: false
    description: "Execute an arbitrary shell command."
  - name: secret.read
    danger_tags: [privacy, security-sensitive]
    default_risk: R3
    default_approval: required
    default_reversible: true
    description: "Read a secret from a secret store. Leaves an audit trail."
```

Fixtures: valid + 3 invalid for each new schema. The existing agent-contract fixtures stay valid because the new fields are all optional.

## 4. Deep validator

New command: `tf-schema agent-contract-check <path.yaml>`.

Checks, in order:

1. **JSON-Schema validation** of the contract (reuses `validate`).
2. **Conflict check**: no action appears in both `actions[]` and `forbidden[]`.
3. **Target-set references**: every `allow_targets[*]` / `deny_targets[*]` entry that starts with `@` must name a `target_sets` key that exists.
4. **Action-library resolution** (optional): if `references.actions_library` is set AND a local library YAML is passed with `--library <path>`, every `actions[*].name` must exist in that library.
5. **Danger-tag validity**: if any action has `danger_tags`, and `--catalog <path-to-dangerous-actions.yaml>` is passed, cross-reference each tag against the catalog's declared tags per action; flag actions that omit tags the catalog declares mandatory.
6. **Reversibility vs danger**: if an action is tagged `irreversible` it MUST set `reversible: false`. If tagged `destructive` it MUST set either `reversible: false` or declare a `reversal_note` pre-condition — flag otherwise.

Output is a structured `AgentContractReport` with `findings: [{ severity, code, message, pointer }]`. Non-empty `error`-severity findings → exit 1.

## 5. AgentGuard runtime (TS + Rust)

New `guard.ts` / `guard.rs` in tf-types:

- `AgentGuard.fromContract(contractObject)` — builds internal indexes:
  - `actionByName: Map<ActionName, Action>`
  - `forbiddenByName: Set<ActionName>`
  - `targetSets: Record<string, string[]>`
- `guard.check({actor, action, target?, context?})` → `GuardDecision`:
  - `{ kind: "allow" }`
  - `{ kind: "approval-required", approval, reason }`
  - `{ kind: "deny", reason }`
  - `{ kind: "escalate", proof_required: ProofLevel, approval: ApprovalRequirement }`
- Matches targets against `allow_targets` and `deny_targets` with a minimal glob (reusing the matcher from Phase 0 `capability` module).
- Honours the forbidden list strictly (deny always wins).
- Emits `onGuardEvent(event)` callback per check for future proof-log ingestion.
- Optional `loadDangerCatalog(catalog)` so the guard can check whether the action is in the danger catalog; decisions for dangerous actions carry a `danger_tags[]` array in the result for UI hooks.

## 6. Codegen

New CLI target: `tf-schema codegen --target agent-contract-ts|agent-contract-rust --spec <path.yaml>`.

Produces a file with:

- `Action` enum listing every declared action name from the contract.
- `DangerTag` enum.
- Typed helper `const CONTRACT: LoadedContract = { ... }` (the contract's data structurally parsed, with enums narrowed to the `Action` type).
- `export function createGuard(options?: { dangerCatalog?: DangerCatalog }): AgentGuard` pre-wired.
- Per-danger-tagged action, generated constants exposing their full metadata for UIs (`export const SHELL_EXEC_META = { action: "shell.exec", danger_tags: [...], approval: "required" } as const`).

## 7. AI integration guide

New doc `docs/ai-integration.md`. Structured:

- How to discover a contract (look for `.tf/agent-contract.yaml` at repo root).
- The *minimum* checks an AI agent should run before taking any action:
  1. Load + validate the contract.
  2. Resolve the target action by name.
  3. Respect the forbidden list.
  4. If `danger_tags` intersects `[destructive, irreversible, financial, security-sensitive]`, escalate to the human even if the contract says `approval: conditional`.
  5. Emit a proof-event stub before and after execution.
- Snippets for using `AgentGuard` in both TS and Rust.
- Pointer to `dangerous-actions.schema.json` for the canonical danger taxonomy.
- Pointer to the ProofRPC integration: the server's `CapabilityEnforcer` can delegate to the `AgentGuard`.

## 8. Repository additions

```
schemas/
  dangerous-actions.schema.json                   # new
  fixtures/dangerous-actions/valid/basic.yaml
  fixtures/dangerous-actions/invalid/*.yaml       # bad tag, bad risk, missing actions

examples/
  agent-contracts/full.yaml                       # uses all new fields
  dangerous-actions/tf-dangerous-std.yaml

tools/tf-schema/src/
  agent_contract.ts                               # deep validator
  codegen/agent-contract-ts.ts
  codegen/agent-contract-rust.ts

tools/tf-types-ts/src/core/
  guard.ts                                        # AgentGuard

crates/tf-types/src/
  guard.rs

tools/tf-types-ts/src/generated/agent-contract/
  code-helper-example.ts                          # generated by codegen

crates/tf-types/src/generated/agent-contract/
  code-helper-example.rs                          # generated, not mod'd

docs/
  ai-integration.md                               # the guide
  schemas/ (regenerated)
```

## 9. Phases

1. **T1** — schema extensions (agent-contract.$defs.Action + DangerTag) + dangerous-actions.schema.json + fixtures. validate-all passes.
2. **T2** — `tf-schema agent-contract-check` deep validator with conflict / target / danger-tag / reversibility rules. Negative + positive test.
3. **T3** — AgentGuard runtime in TS + Rust with shared `conformance/guard-vectors.yaml` pinning a set of `(contract + query) → decision` cases. Both runtimes agree.
4. **T4** — codegen for agent-contract → TS + Rust typed guard builders.
5. **T5** — AI integration guide (`docs/ai-integration.md`) + regenerated docs.
6. **T6** — CI additions: new schema in validate-all, new codegen-diff rows, agent-contract-check in the workflow, AgentGuard vector tests, guide linked from README if present. Final sweep.

## 10. Done criteria

- New schemas + fixtures committed; validate-all + lint + parity all green.
- `tf-schema agent-contract-check examples/agent-contracts/full.yaml` reports no errors.
- AgentGuard produces identical decisions in TS and Rust against the pinned vector file.
- Generated agent-contract code compiles (TS via tsc, Rust via cargo check on a downstream harness).
- `docs/ai-integration.md` is committed and covers the five-step AI workflow.
- Full test matrix passes on both runtimes.

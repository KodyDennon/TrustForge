# TrustForge Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land every JSON Schema for TrustForge machine-readable artifacts (manifests + runtime objects), a hardened `tf-schema` CLI, TypeScript + Rust type packages generated from those schemas, docs codegen, a fuzz harness, and a cross-language parity conformance suite.

**Architecture:** JSON Schema is the normative source. A hand-written TS CLI (`tools/tf-schema`) validates, lints, bundles, and generates code + docs. Types are regenerated into `tools/tf-types-ts` and `crates/tf-types`; each language package wraps the generated types in a small hand-written semantic core (URI parsing, canonical JSON, delegation walks, revocation index). A conformance file drives both runtimes against the same fixtures.

**Tech Stack:** Bun 1.3+, TypeScript (strict, ES2022), AJV 8 (Draft 2020-12), YAML, fast-check (TS fuzz), Rust 1.95+ (edition 2021), serde, serde_json, proptest. No external codegen tools — generators are hand-written in ~300 LoC each.

**Design spec:** `docs/superpowers/specs/2026-04-24-trustforge-foundation-design.md`

**Git conventions:** All commits use `git -c commit.gpgsign=false commit` (per repo memory). Commit after every green task.

---

## File structure (locked in up front)

```
schemas/
  _common.schema.json               # shared $defs, no top-level object
  agent-contract.schema.json        # exists; refactored to $ref _common and $id v0/
  policy.schema.json                # new
  threat-model.schema.json          # new
  actions.schema.json               # new
  proof-profile.schema.json         # new
  conformance.schema.json           # new
  actor-identity.schema.json        # new
  capability-token.schema.json      # new
  revocation.schema.json            # new
  proof-event.schema.json           # new
  proof-bundle.schema.json          # new
  fixtures/
    <schema-name>/
      valid/*.yaml
      invalid/*.yaml                # paired with <same-name>.expected-error.yaml
      composite/*.yaml              # cross-schema examples

tools/tf-schema/
  src/
    cli.ts                          # entry point, command dispatch (exists, extend)
    loader.ts                       # YAML/JSON loader with cached schema compile
    validate.ts                     # validate / validate-all
    lint.ts                         # style rules across schema files
    bundle.ts                       # resolve $refs into a single document
    fuzz.ts                         # schema-aware input generator + safety asserts
    codegen/
      model.ts                      # shared IR walked by emitters
      ts.ts                         # JSON Schema -> TS
      rust.ts                       # JSON Schema -> Rust
      docs.ts                       # JSON Schema -> Markdown
    parity.ts                       # run TS side of conformance/parity.yaml
    util.ts                         # small helpers (relative paths, sorted JSON stringify)
  tests/
    validate.test.ts                # exists as cli.test.ts; rename + expand
    lint.test.ts
    bundle.test.ts
    codegen-ts.test.ts
    codegen-rust.test.ts
    codegen-docs.test.ts
    fuzz.test.ts
    parity.test.ts

tools/tf-types-ts/
  package.json
  tsconfig.json
  src/
    generated/
      index.ts                      # barrel
      _common.ts
      agent-contract.ts
      policy.ts
      threat-model.ts
      actions.ts
      proof-profile.ts
      conformance.ts
      actor-identity.ts
      capability-token.ts
      revocation.ts
      proof-event.ts
      proof-bundle.ts
    core/
      actor-id.ts                   # parseActorId, formatActorId, type guards
      instance-id.ts
      trust-domain.ts
      capability.ts                 # isCapability, constraintsSatisfied, intersectConstraints
      delegation.ts                 # DelegationChain.walk
      revocation.ts                 # RevocationIndex
      envelope.ts                   # shape validators for SignatureEnvelope
      canonical.ts                  # deterministic JSON serialization
    index.ts                        # re-exports generated + core
  tests/
    actor-id.test.ts
    instance-id.test.ts
    trust-domain.test.ts
    capability.test.ts
    delegation.test.ts
    revocation.test.ts
    canonical.test.ts
    round-trip.test.ts              # fixture-driven

Cargo.toml                          # new: workspace root
crates/tf-types/
  Cargo.toml
  src/
    lib.rs                          # re-exports
    generated/
      mod.rs
      common.rs
      agent_contract.rs
      policy.rs
      threat_model.rs
      actions.rs
      proof_profile.rs
      conformance.rs
      actor_identity.rs
      capability_token.rs
      revocation.rs
      proof_event.rs
      proof_bundle.rs
    actor_id.rs
    instance_id.rs
    trust_domain.rs
    capability.rs
    delegation.rs
    revocation.rs
    envelope.rs
    canonical.rs
  tests/
    fixture_round_trip.rs
    canonical_cross_language.rs
    parity.rs

docs/schemas/                       # generated, committed
  <schema>.md

conformance/
  parity.yaml                       # enumerates fixtures + expected verdicts

canonical-vectors.yaml              # at repo root: input/output pairs for canonical JSON; both runtimes test against it
.github/workflows/ci.yml            # CI gauntlet
```

---

## Phase P0 — Shared primitives + agent-contract refactor

### Task P0.1: Write `_common.schema.json`

**Files:**
- Create: `schemas/_common.schema.json`

- [ ] **Step 1: Create the common schema with all shared `$defs`**

Write `schemas/_common.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://trustforge.io/schemas/v0/_common.schema.json",
  "title": "TrustForge Common Definitions",
  "description": "Shared $defs referenced by every other TrustForge schema. Has no top-level instance.",
  "$defs": {
    "ActorType": {
      "enum": [
        "human", "agent", "device", "service", "site", "organization",
        "relay", "plugin", "process", "tool", "model-provider",
        "policy-engine", "proof-anchor", "emergency-authority"
      ],
      "description": "Canonical actor types from TF-0002."
    },
    "ActorId": {
      "type": "string",
      "pattern": "^tf:actor:(human|agent|device|service|site|organization|relay|plugin|process|tool|model-provider|policy-engine|proof-anchor|emergency-authority):[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]+$",
      "description": "Universal actor URI: tf:actor:<type>:<path>. See TF-0002."
    },
    "InstanceId": {
      "type": "string",
      "pattern": "^tf:instance:(human|agent|device|service|site|organization|relay|plugin|process|tool|model-provider|policy-engine|proof-anchor|emergency-authority):[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]+$",
      "description": "Actor instance URI: tf:instance:<type>:<path>/<instance-path>."
    },
    "TrustDomain": {
      "type": "string",
      "minLength": 1,
      "pattern": "^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$",
      "description": "Trust-domain identifier (DNS-like; local domains use `local/<name>`)."
    },
    "RiskClass": {
      "enum": ["R0", "R1", "R2", "R3", "R4", "R5"],
      "description": "Risk classes from TF-0004."
    },
    "TrustLevel": {
      "enum": ["T0", "T1", "T2", "T3", "T4", "T5", "T6", "T7"],
      "description": "Trust levels from TF-0002."
    },
    "ProofLevel": {
      "enum": ["L0", "L1", "L2", "L3", "L4", "L5"],
      "description": "Proof levels from TF-0005."
    },
    "EnforcementLevel": {
      "enum": ["E0", "E1", "E2", "E3", "E4", "E5"],
      "description": "Enforcement levels (see DECISIONS.md)."
    },
    "ApprovalRequirement": {
      "enum": ["none", "conditional", "required", "quorum"],
      "description": "Default approval requirement modes."
    },
    "Timestamp": {
      "type": "string",
      "pattern": "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:Z|[+-]\\d{2}:\\d{2})$",
      "description": "RFC 3339 timestamp with required timezone."
    },
    "HashRef": {
      "type": "string",
      "pattern": "^(sha256|sha384|sha512|blake3):[0-9a-f]+$",
      "description": "Algorithm-prefixed lowercase-hex hash."
    },
    "AlgorithmId": {
      "type": "string",
      "minLength": 1,
      "description": "Signature or KEM algorithm identifier, e.g. ed25519, ml-dsa-65, p256."
    },
    "SignatureEnvelope": {
      "type": "object",
      "required": ["algorithm", "signer", "signature"],
      "additionalProperties": false,
      "properties": {
        "algorithm":     { "$ref": "#/$defs/AlgorithmId" },
        "signer":        { "$ref": "#/$defs/ActorId" },
        "signature":     { "type": "string", "contentEncoding": "base64", "minLength": 1, "description": "Base64 signature bytes." },
        "hash_alg":      { "type": "string", "description": "Optional hash used before signing, e.g. sha256." },
        "alt_algorithm": { "$ref": "#/$defs/AlgorithmId" },
        "alt_signature": { "type": "string", "contentEncoding": "base64", "minLength": 1, "description": "Optional second signature for hybrid PQ." }
      },
      "description": "Opaque signature envelope. No crypto performed in foundation phase."
    },
    "ActionName": {
      "type": "string",
      "pattern": "^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+$",
      "description": "Dotted lowercase action identifier, e.g. file.write, shell.exec."
    },
    "Constraint": {
      "oneOf": [
        { "type": "object", "required": ["kind", "until"], "additionalProperties": false,
          "properties": {
            "kind": { "const": "time_window" },
            "from": { "$ref": "#/$defs/Timestamp" },
            "until": { "$ref": "#/$defs/Timestamp" }
          }
        },
        { "type": "object", "required": ["kind", "patterns"], "additionalProperties": false,
          "properties": {
            "kind": { "const": "target" },
            "patterns": { "type": "array", "items": { "type": "string", "minLength": 1 }, "minItems": 1 }
          }
        },
        { "type": "object", "required": ["kind", "max"], "additionalProperties": false,
          "properties": {
            "kind": { "const": "quantity" },
            "max":  { "type": "integer", "minimum": 1 },
            "unit": { "type": "string" }
          }
        },
        { "type": "object", "required": ["kind", "max_per_window", "window_seconds"], "additionalProperties": false,
          "properties": {
            "kind": { "const": "rate" },
            "max_per_window": { "type": "integer", "minimum": 1 },
            "window_seconds": { "type": "integer", "minimum": 1 }
          }
        },
        { "type": "object", "required": ["kind", "session_id"], "additionalProperties": false,
          "properties": {
            "kind": { "const": "session" },
            "session_id": { "type": "string", "minLength": 1 }
          }
        },
        { "type": "object", "required": ["kind", "approval"], "additionalProperties": false,
          "properties": {
            "kind": { "const": "approval" },
            "approval": { "$ref": "#/$defs/ApprovalRequirement" }
          }
        },
        { "type": "object", "required": ["kind", "quorum"], "additionalProperties": false,
          "properties": {
            "kind": { "const": "quorum" },
            "quorum": { "type": "integer", "minimum": 2 },
            "of":     { "type": "array", "items": { "$ref": "#/$defs/ActorId" }, "minItems": 2 }
          }
        },
        { "type": "object", "required": ["kind", "device_actor"], "additionalProperties": false,
          "properties": {
            "kind": { "const": "device_binding" },
            "device_actor": { "$ref": "#/$defs/ActorId" }
          }
        }
      ],
      "description": "Capability/grant constraint, discriminated by `kind`."
    },
    "Capability": {
      "type": "object",
      "required": ["name", "risk"],
      "additionalProperties": false,
      "properties": {
        "name":           { "$ref": "#/$defs/ActionName" },
        "risk":           { "$ref": "#/$defs/RiskClass" },
        "proof_required": { "$ref": "#/$defs/ProofLevel" },
        "approval":       { "$ref": "#/$defs/ApprovalRequirement" },
        "constraints":    { "type": "array", "items": { "$ref": "#/$defs/Constraint" } },
        "single_use":     { "type": "boolean" },
        "delegable":      { "type": "boolean" },
        "revocable":      { "type": "boolean" },
        "offline_valid":  { "type": "boolean" },
        "expires_at":     { "$ref": "#/$defs/Timestamp" }
      },
      "description": "Capability grant shape (TF-0004)."
    },
    "NegativeCapability": {
      "type": "object",
      "required": ["name"],
      "additionalProperties": false,
      "properties": {
        "name":        { "$ref": "#/$defs/ActionName" },
        "target":      { "type": "string", "description": "Optional target pattern the denial applies to." },
        "reason":      { "type": "string", "minLength": 1 },
        "overrides":   { "type": "array", "items": { "type": "string" }, "description": "Grant IDs this negative capability explicitly overrides." }
      },
      "description": "Explicit denial; overrides overlapping grants."
    },
    "DelegationLink": {
      "type": "object",
      "required": ["delegator", "delegate", "capabilities"],
      "additionalProperties": false,
      "properties": {
        "delegator":    { "$ref": "#/$defs/ActorId" },
        "delegate":     { "$ref": "#/$defs/ActorId" },
        "capabilities": { "type": "array", "items": { "$ref": "#/$defs/Capability" }, "minItems": 1 },
        "constraints":  { "type": "array", "items": { "$ref": "#/$defs/Constraint" } },
        "expires_at":   { "$ref": "#/$defs/Timestamp" },
        "redelegation": {
          "type": "object",
          "required": ["allowed"],
          "additionalProperties": false,
          "properties": {
            "allowed":    { "type": "boolean" },
            "max_depth":  { "type": "integer", "minimum": 0 }
          }
        },
        "proof_ref":    { "$ref": "#/$defs/HashRef" }
      }
    }
  }
}
```

- [ ] **Step 2: Verify the file parses as JSON**

Run: `bun -e "JSON.parse(require('fs').readFileSync('schemas/_common.schema.json','utf8'))"`
Expected: no output, exit 0.

- [ ] **Step 3: Verify AJV compiles it**

Run: `bun -e "const A=await import('ajv/dist/2020.js'); const f=await import('ajv-formats'); const a=new A.default({strict:true,allErrors:true}); f.default(a); a.compile(JSON.parse(require('fs').readFileSync('schemas/_common.schema.json','utf8'))); console.log('ok')"`
Expected: `ok`.

- [ ] **Step 4: Commit**

```bash
git add schemas/_common.schema.json
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
Add _common.schema.json with shared $defs

Defines the primitives every other schema references: ActorType,
ActorId, InstanceId, TrustDomain, RiskClass, TrustLevel, ProofLevel,
EnforcementLevel, Timestamp, HashRef, AlgorithmId, SignatureEnvelope,
ActionName, Constraint, Capability, NegativeCapability, DelegationLink.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

### Task P0.2: Refactor `agent-contract.schema.json` to use `_common`

**Files:**
- Modify: `schemas/agent-contract.schema.json`

- [ ] **Step 1: Write the failing test**

Add to `tools/tf-schema/src/cli.test.ts` (keep existing tests; append new ones):

```ts
test("agent-contract uses v0 $id", () => {
  const schema = JSON.parse(readFileSync(SCHEMA_PATH, "utf8")) as { $id: string };
  expect(schema.$id).toBe("https://trustforge.io/schemas/v0/agent-contract.schema.json");
});

test("agent-contract $refs _common for RiskClass", () => {
  const schema = JSON.parse(readFileSync(SCHEMA_PATH, "utf8"));
  const text = JSON.stringify(schema);
  expect(text).toContain("_common.schema.json#/$defs/RiskClass");
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `bun test tools/tf-schema/src/cli.test.ts`
Expected: FAIL on the two new tests.

- [ ] **Step 3: Update the schema**

Replace `schemas/agent-contract.schema.json` with the refactored version. Key changes:
- `$id`: `https://trustforge.io/schemas/v0/agent-contract.schema.json`
- Replace inline `RiskClass`, `ProofLevel`, `ApprovalRequirement`, `ActionName` `$defs` with `$ref` to `_common.schema.json#/$defs/<Name>`.
- Keep local `$defs` only for `Action` and `Forbidden` (specific to this schema).
- Add `description` to any property that lacks one.

Full replacement file:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://trustforge.io/schemas/v0/agent-contract.schema.json",
  "title": "TrustForge Agent Contract",
  "description": "Declarative contract that makes a TrustForge-enabled codebase legible and safe for AI agents. See TF-0006.",
  "type": "object",
  "required": ["contract_version", "spec_version", "project"],
  "additionalProperties": false,
  "properties": {
    "contract_version": {
      "description": "Version of the agent-contract schema itself.",
      "enum": ["1"]
    },
    "spec_version": {
      "type": "string",
      "description": "TrustForge spec revision this contract conforms to.",
      "pattern": "^TF-\\d{4}(-draft|-v\\d+)?$"
    },
    "project": {
      "type": "string",
      "description": "Project identifier used in logs and contract references.",
      "minLength": 1
    },
    "trust_domain": {
      "description": "The TrustForge trust domain this project belongs to.",
      "$ref": "_common.schema.json#/$defs/TrustDomain"
    },
    "references": {
      "type": "object",
      "description": "Pointers to companion manifests.",
      "additionalProperties": false,
      "properties": {
        "threat_model": { "type": "string", "minLength": 1, "description": "Path to the project's threat-model manifest." },
        "policy_engine": {
          "type": "object",
          "description": "Policy backend in use by this project.",
          "required": ["kind"],
          "additionalProperties": false,
          "properties": {
            "kind": { "enum": ["cedar", "rego", "custom", "none"], "description": "Policy backend kind." },
            "path": { "type": "string", "minLength": 1, "description": "Path to the policy file when applicable." }
          }
        },
        "actions_library": {
          "type": "string",
          "description": "Standard actions library identifier, e.g. tf-actions-std@1.",
          "pattern": "^[a-z][a-z0-9-]*@\\d+$"
        }
      }
    },
    "target_sets": {
      "type": "object",
      "description": "Named glob lists, reusable in action rules.",
      "propertyNames": { "pattern": "^[a-z][a-z0-9_]*$" },
      "additionalProperties": {
        "type": "array",
        "items": { "type": "string", "minLength": 1 },
        "minItems": 1
      }
    },
    "actions": {
      "type": "array",
      "description": "Declared actions this project allows agents to perform.",
      "items": { "$ref": "#/$defs/Action" }
    },
    "forbidden": {
      "type": "array",
      "description": "Actions this project forbids outright.",
      "items": { "$ref": "#/$defs/Forbidden" }
    },
    "integrations": {
      "type": "object",
      "description": "Connections to MCP tools, ProofRPC services, and test commands.",
      "additionalProperties": false,
      "properties": {
        "mcp_tools":        { "type": "array", "items": { "type": "object" } },
        "proofrpc_services":{ "type": "array", "items": { "type": "object" } },
        "test_commands":    { "type": "array", "items": { "type": "string", "minLength": 1 } }
      }
    },
    "conformance": {
      "type": "object",
      "description": "Profiles this project claims.",
      "additionalProperties": false,
      "properties": {
        "profiles": {
          "type": "array",
          "items": { "type": "string", "pattern": "^tf-[a-z0-9-]+$" },
          "minItems": 1
        }
      }
    }
  },
  "$defs": {
    "Action": {
      "type": "object",
      "description": "Single action declaration.",
      "required": ["name", "risk"],
      "additionalProperties": false,
      "properties": {
        "name":          { "$ref": "_common.schema.json#/$defs/ActionName" },
        "risk":          { "$ref": "_common.schema.json#/$defs/RiskClass" },
        "proof":         { "$ref": "_common.schema.json#/$defs/ProofLevel" },
        "approval":      { "$ref": "_common.schema.json#/$defs/ApprovalRequirement" },
        "description":   { "type": "string", "description": "Human-readable purpose." },
        "allow_targets": { "type": "array", "items": { "type": "string", "minLength": 1 } },
        "deny_targets":  { "type": "array", "items": { "type": "string", "minLength": 1 } }
      }
    },
    "Forbidden": {
      "type": "object",
      "description": "Forbidden action entry.",
      "required": ["action"],
      "additionalProperties": false,
      "properties": {
        "action": { "$ref": "_common.schema.json#/$defs/ActionName" },
        "reason": { "type": "string", "minLength": 1 }
      }
    }
  }
}
```

- [ ] **Step 4: Update the test loader to resolve `_common` references**

The existing test in `tools/tf-schema/src/cli.test.ts` compiles the schema alone. After this change AJV will fail with "can't resolve reference _common.schema.json#/…" — update the validator creation to also load `_common`. Replace the `makeValidator()` helper with:

```ts
function makeValidator() {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  const common = JSON.parse(readFileSync(join(REPO_ROOT, "schemas", "_common.schema.json"), "utf8"));
  ajv.addSchema(common, "_common.schema.json");
  const schema = JSON.parse(readFileSync(SCHEMA_PATH, "utf8"));
  return ajv.compile(schema);
}
```

- [ ] **Step 5: Run tests**

Run: `bun test tools/tf-schema/src/cli.test.ts`
Expected: all pass, including the two new ones and all existing ones.

- [ ] **Step 6: Commit**

```bash
git add schemas/agent-contract.schema.json tools/tf-schema/src/cli.test.ts
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
Refactor agent-contract.schema.json to use _common $defs

Moves $id under /schemas/v0/. Replaces inline RiskClass, ProofLevel,
ApprovalRequirement, and ActionName $defs with $refs to
_common.schema.json. Updates the test harness to register _common
so AJV can resolve the external references.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

### Task P0.3: Seed fixtures directory with agent-contract fixtures

**Files:**
- Create: `schemas/fixtures/agent-contract/valid/minimal.yaml` (copy of existing `examples/agent-contracts/minimal.yaml`)
- Create: `schemas/fixtures/agent-contract/invalid/missing-project.yaml`
- Create: `schemas/fixtures/agent-contract/invalid/missing-project.expected-error.yaml`
- Create: `schemas/fixtures/agent-contract/invalid/bad-risk.yaml`
- Create: `schemas/fixtures/agent-contract/invalid/bad-risk.expected-error.yaml`
- Create: `schemas/fixtures/agent-contract/invalid/bad-action-name.yaml`
- Create: `schemas/fixtures/agent-contract/invalid/bad-action-name.expected-error.yaml`

- [ ] **Step 1: Create `valid/minimal.yaml`**

Copy the current example verbatim:

```bash
mkdir -p schemas/fixtures/agent-contract/valid
cp examples/agent-contracts/minimal.yaml schemas/fixtures/agent-contract/valid/minimal.yaml
```

- [ ] **Step 2: Create `invalid/missing-project.yaml`** (same as minimal but `project` key deleted)

```yaml
contract_version: "1"
spec_version: TF-0006-draft
trust_domain: example.com
actions:
  - name: file.read
    risk: R0
```

- [ ] **Step 3: Create `invalid/missing-project.expected-error.yaml`**

```yaml
errors:
  - path: ""
    keyword: required
    params_missing: project
```

- [ ] **Step 4: Create `invalid/bad-risk.yaml`**

```yaml
contract_version: "1"
spec_version: TF-0006-draft
project: example
trust_domain: example.com
actions:
  - name: file.read
    risk: R9
```

- [ ] **Step 5: Create `invalid/bad-risk.expected-error.yaml`**

```yaml
errors:
  - path: "/actions/0/risk"
    keyword: enum
```

- [ ] **Step 6: Create `invalid/bad-action-name.yaml`**

```yaml
contract_version: "1"
spec_version: TF-0006-draft
project: example
trust_domain: example.com
actions:
  - name: FileWrite
    risk: R2
```

- [ ] **Step 7: Create `invalid/bad-action-name.expected-error.yaml`**

```yaml
errors:
  - path: "/actions/0/name"
    keyword: pattern
```

- [ ] **Step 8: Commit**

```bash
git add schemas/fixtures/agent-contract
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
Seed agent-contract fixtures with valid + invalid examples

Adds the fixture layout schemas/fixtures/<name>/{valid,invalid}/ and
the expected-error.yaml pairing for each invalid case. Used by the
validator matrix in later tasks.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

### Task P0.4: Extend `tf-schema` validator to enforce the fixture matrix

**Files:**
- Create: `tools/tf-schema/src/loader.ts`
- Create: `tools/tf-schema/src/validate.ts`
- Modify: `tools/tf-schema/src/cli.ts`
- Create: `tools/tf-schema/tests/validate-matrix.test.ts`

- [ ] **Step 1: Write the failing test**

Create `tools/tf-schema/tests/validate-matrix.test.ts`:

```ts
import { describe, expect, test } from "bun:test";
import { runValidateAll } from "../src/validate";

describe("validate-all with fixtures", () => {
  test("agent-contract fixtures: all valid pass, all invalid fail with expected errors", async () => {
    const result = await runValidateAll({ schema: "agent-contract" });
    expect(result.ok).toBe(true);
    expect(result.summary.validPassed).toBeGreaterThan(0);
    expect(result.summary.invalidMatched).toBeGreaterThan(0);
    expect(result.summary.mismatches).toEqual([]);
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `bun test tools/tf-schema/tests/validate-matrix.test.ts`
Expected: FAIL (module not found).

- [ ] **Step 3: Implement `tools/tf-schema/src/loader.ts`**

```ts
import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { extname, join, resolve } from "node:path";
import Ajv2020, { type ValidateFunction } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { parse as parseYAML } from "yaml";

export const REPO_ROOT = resolve(import.meta.dir, "..", "..", "..");
export const SCHEMAS_DIR = join(REPO_ROOT, "schemas");
export const FIXTURES_DIR = join(SCHEMAS_DIR, "fixtures");

export function loadFile(path: string): unknown {
  const raw = readFileSync(path, "utf8");
  const ext = extname(path).toLowerCase();
  if (ext === ".json") return JSON.parse(raw);
  if (ext === ".yaml" || ext === ".yml") return parseYAML(raw);
  throw new Error(`unsupported extension: ${ext}`);
}

export function listSchemas(): { name: string; path: string }[] {
  const entries = readdirSync(SCHEMAS_DIR)
    .filter((f) => f.endsWith(".schema.json"))
    .map((f) => ({ name: f.replace(/\.schema\.json$/, ""), path: join(SCHEMAS_DIR, f) }));
  return entries;
}

export function buildAjv(): Ajv2020 {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  for (const { name, path } of listSchemas()) {
    ajv.addSchema(loadFile(path) as object, `${name}.schema.json`);
  }
  return ajv;
}

export function getValidator(ajv: Ajv2020, schemaName: string): ValidateFunction {
  const key = `${schemaName}.schema.json`;
  const v = ajv.getSchema(key);
  if (!v) throw new Error(`schema not registered: ${key}`);
  return v as ValidateFunction;
}

export function walkFiles(dir: string, exts: Set<string>): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry);
    const s = statSync(p);
    if (s.isDirectory()) out.push(...walkFiles(p, exts));
    else if (exts.has(extname(p).toLowerCase())) out.push(p);
  }
  return out;
}

export const YAML_JSON = new Set([".yaml", ".yml", ".json"]);
```

- [ ] **Step 4: Implement `tools/tf-schema/src/validate.ts`**

```ts
import { basename, dirname, join, relative } from "node:path";
import { type ErrorObject } from "ajv/dist/2020.js";
import {
  FIXTURES_DIR, REPO_ROOT, YAML_JSON,
  buildAjv, getValidator, listSchemas, loadFile, walkFiles,
} from "./loader";

export type Mismatch = {
  file: string;
  kind: "valid-failed" | "invalid-passed" | "invalid-wrong-error";
  got?: ErrorObject[];
  expected?: ExpectedError[];
};

export type ExpectedError = { path: string; keyword: string; params_missing?: string };

export type ValidateAllResult = {
  ok: boolean;
  summary: { validPassed: number; invalidMatched: number; mismatches: Mismatch[] };
};

export async function runValidateAll(opts?: { schema?: string }): Promise<ValidateAllResult> {
  const ajv = buildAjv();
  const schemas = listSchemas().filter((s) => !opts?.schema || s.name === opts.schema);
  const mismatches: Mismatch[] = [];
  let validPassed = 0;
  let invalidMatched = 0;

  for (const { name } of schemas) {
    if (name === "_common") continue;
    const validDir = join(FIXTURES_DIR, name, "valid");
    const invalidDir = join(FIXTURES_DIR, name, "invalid");
    const validator = getValidator(ajv, name);

    for (const f of walkFiles(validDir, YAML_JSON)) {
      const doc = loadFile(f);
      if (validator(doc)) validPassed++;
      else mismatches.push({ file: relative(REPO_ROOT, f), kind: "valid-failed", got: validator.errors ?? [] });
    }

    for (const f of walkFiles(invalidDir, YAML_JSON)) {
      if (f.endsWith(".expected-error.yaml")) continue;
      const doc = loadFile(f);
      const passed = validator(doc);
      const expectPath = f.replace(/\.(yaml|yml|json)$/, ".expected-error.yaml");
      const expected = (loadFile(expectPath) as { errors: ExpectedError[] }).errors;

      if (passed) {
        mismatches.push({ file: relative(REPO_ROOT, f), kind: "invalid-passed", expected });
        continue;
      }
      if (matchesExpected(validator.errors ?? [], expected)) {
        invalidMatched++;
      } else {
        mismatches.push({
          file: relative(REPO_ROOT, f),
          kind: "invalid-wrong-error",
          got: validator.errors ?? [],
          expected,
        });
      }
    }
  }

  return { ok: mismatches.length === 0, summary: { validPassed, invalidMatched, mismatches } };
}

function matchesExpected(got: ErrorObject[], expected: ExpectedError[]): boolean {
  return expected.every((e) =>
    got.some((g) => {
      if (g.keyword !== e.keyword) return false;
      if (g.instancePath !== e.path) return false;
      if (e.params_missing && e.keyword === "required") {
        return (g.params as { missingProperty?: string }).missingProperty === e.params_missing;
      }
      return true;
    }),
  );
}

export function formatResult(result: ValidateAllResult): string {
  const { validPassed, invalidMatched, mismatches } = result.summary;
  const lines = [`valid: ${validPassed} ok`, `invalid: ${invalidMatched} matched`];
  for (const m of mismatches) lines.push(`FAIL ${m.kind} ${m.file}`);
  return lines.join("\n");
}
```

- [ ] **Step 5: Wire the new command into `cli.ts`**

Replace the body of `cli.ts` to dispatch `validate-all` to `runValidateAll` (keep the single-file `validate` command for direct use). Full replacement:

```ts
#!/usr/bin/env bun
import { resolve, relative } from "node:path";
import { REPO_ROOT, buildAjv, loadFile } from "./loader";
import { runValidateAll, formatResult } from "./validate";

function cmdValidate(args: string[]): number {
  const [schemaName, instance] = args;
  if (!schemaName || !instance) {
    console.error("usage: tf-schema validate <schema-name> <instance.(yaml|json)>");
    return 2;
  }
  const ajv = buildAjv();
  const key = `${schemaName}.schema.json`;
  const validator = ajv.getSchema(key);
  if (!validator) {
    console.error(`unknown schema: ${schemaName}`);
    return 2;
  }
  const doc = loadFile(resolve(instance));
  if (validator(doc)) {
    console.log(`OK ${relative(REPO_ROOT, resolve(instance))}`);
    return 0;
  }
  console.error(`FAIL ${relative(REPO_ROOT, resolve(instance))}`);
  for (const e of validator.errors ?? []) console.error(`  ${e.instancePath || "/"} ${e.keyword} ${e.message ?? ""}`);
  return 1;
}

async function cmdValidateAll(args: string[]): Promise<number> {
  const schema = args[0];
  const result = await runValidateAll(schema ? { schema } : undefined);
  console.log(formatResult(result));
  return result.ok ? 0 : 1;
}

const [cmd, ...rest] = process.argv.slice(2);
const exit =
  cmd === "validate" ? cmdValidate(rest)
  : cmd === "validate-all" ? await cmdValidateAll(rest)
  : (console.error("usage: tf-schema <validate|validate-all> [args]"), 2);
process.exit(exit);
```

- [ ] **Step 6: Update `package.json` scripts**

Modify `tools/tf-schema/package.json`:

```json
{
  "name": "tf-schema",
  "version": "0.0.0",
  "private": true,
  "type": "module",
  "description": "TrustForge JSON Schema validator, linter, and codegen.",
  "scripts": {
    "validate": "bun run src/cli.ts validate",
    "validate:all": "bun run src/cli.ts validate-all",
    "typecheck": "bun x tsc -p tsconfig.json --noEmit",
    "test": "bun test"
  },
  "dependencies": {
    "ajv": "^8.17.1",
    "ajv-formats": "^3.0.1",
    "yaml": "^2.6.0"
  },
  "devDependencies": {
    "@types/bun": "^1.3.9",
    "typescript": "^5.6.3"
  }
}
```

- [ ] **Step 7: Run the new test**

Run: `bun test tools/tf-schema/tests/validate-matrix.test.ts`
Expected: PASS.

- [ ] **Step 8: Run the full test suite**

Run: `bun test`
Expected: all pass (old `cli.test.ts` and new `validate-matrix.test.ts`).

- [ ] **Step 9: Run the CLI against fixtures manually**

Run: `bun run --filter tf-schema validate:all`
Expected: `valid: 1 ok\ninvalid: 3 matched` and exit 0.

- [ ] **Step 10: Commit**

```bash
git add tools/tf-schema
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
Extend tf-schema with fixture-matrix validator

Adds tools/tf-schema/src/{loader,validate}.ts and wires validate-all
into cli.ts to enforce the valid/invalid fixture matrix, including
expected-error matching for invalid inputs. AJV now loads every
schema under schemas/ so cross-schema $refs resolve.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Phase P1 — Manifest schemas

Each task below follows the same pattern as P0 tasks:
1. Write the schema JSON at `schemas/<name>.schema.json` with `$id: https://trustforge.io/schemas/v0/<name>.schema.json`, all `additionalProperties: false`, all properties described, `$ref`ing `_common` where possible.
2. Write `schemas/fixtures/<name>/valid/basic.yaml` — one minimal valid example.
3. Write at least three `schemas/fixtures/<name>/invalid/*.yaml` with paired `.expected-error.yaml` files.
4. Run `bun run --filter tf-schema validate:all` and confirm `valid: N ok / invalid: M matched / 0 mismatches`.
5. Commit under the message: `Add <name>.schema.json with fixtures`.

The schema bodies must match these shapes:

### Task P1.1: `policy.schema.json` (TF-0004)

**Top-level object.** Required: `policy_version` (enum `"1"`), `trust_domain` ($ref TrustDomain), `rules` (array, minItems 1). Optional: `negative_capabilities` (array of NegativeCapability), `quorum_defaults` (object with `min_approvers` int ≥ 2, `of` array of ActorId), `continuous_reevaluation` (object with `triggers` array of string enum `["time", "delegation_change", "revocation", "session_rekey", "explicit_reauth"]`), `engine_hint` (enum `["cedar", "rego", "custom", "native", "none"]`).

Each `Rule`: required `id` (string, pattern `^[a-z][a-z0-9._-]*$`), `effect` (enum `["allow", "deny", "escalate", "log_only"]`), `action` ($ref ActionName) or `action_pattern` (regex string). Optional: `subject_pattern`, `target_patterns` (string[]), `risk_at_most` (RiskClass), `proof_required` (ProofLevel), `approval` (ApprovalRequirement), `constraints` (Constraint[]), `reason` (string).

**Valid fixture:** one `allow` rule + one `deny` rule on `shell.exec` with `approval: required`.

**Invalid fixtures:**
- `missing-rules.yaml` — omit `rules`; expected `{path:"", keyword:"required", params_missing:"rules"}`.
- `bad-effect.yaml` — `effect: "approve"`; expected `{path:"/rules/0/effect", keyword:"enum"}`.
- `rule-id-pattern.yaml` — `id: "Bad ID!"`; expected `{path:"/rules/0/id", keyword:"pattern"}`.

### Task P1.2: `threat-model.schema.json` (TF-0006)

Required: `threat_model_version` (enum `"1"`), `project` (string), `assets` (array of `{id, description, criticality: RiskClass}`), `adversaries` (array of `{id, description, capability_levels: array of enum ["opportunistic","targeted","insider","nation-state","ai-assisted"]}`), `attack_classes` (array of string ids referencing a taxonomy — open strings here), `mitigations` (array of `{id, applies_to: string[], description, status: enum ["planned","implemented","not-applicable"]}`), `residual_risks` (array of `{description, accepted_by: ActorId, accepted_at: Timestamp}`).

**Invalid fixtures:** missing `assets`; `criticality: "R9"`; non-ISO `accepted_at`.

### Task P1.3: `actions.schema.json` (TF-0006)

Top-level: `actions_library_version` (enum `"1"`), `library_id` (string, pattern `^[a-z][a-z0-9-]*$`), `actions` (array of ActionDef).

`ActionDef`: required `name` (ActionName), `default_risk` (RiskClass), `default_proof` (ProofLevel), `description`. Optional: `parameters` (JSON Schema sub-object — represented here as `type: object`), `approval_default` (ApprovalRequirement), `dangerous` (bool), `reversible` (bool).

**Invalid fixtures:** duplicate `name` within array (use `uniqueItemProperties`-style check: JSON Schema doesn't express this directly, so instead check that `name` is required and invalid fixtures target that); missing `default_risk`; malformed `library_id`.

### Task P1.4: `proof-profile.schema.json` (TF-0005)

Required: `profile_version` (enum `"1"`), `trust_domain` (TrustDomain), `emit` (array of `{event_type: string, level: ProofLevel, anchor: enum ["local","org","federated","transparency","none"], retention_days?: integer ≥ 0}`). Optional: `default_level` (ProofLevel), `redaction_rules` (array of `{field, policy: enum ["keep","hash","drop"]}`).

**Invalid fixtures:** missing `emit`; invalid `anchor`; negative `retention_days`.

### Task P1.5: `conformance.schema.json` (TF-0010)

Top-level: `conformance_version` (enum `"1"`), `claimed_profiles` (array minItems 1 of string pattern `^tf-[a-z0-9-]+$`). Optional: `extensions` (object, additionalProperties array of string), `claimant` (ActorId), `as_of` (Timestamp), `notes` (string).

**Invalid fixtures:** empty `claimed_profiles`; bad profile pattern `"TF-HOME"`; bad `as_of`.

### Task P1.6: Add `proof_level` coercion smoke test

Optional hardening. Skip if short on time — the validator matrix already exercises this.

### Task P1.7: Run full matrix after every manifest added

After each of P1.1–P1.5 is committed, run `bun run --filter tf-schema validate:all` and confirm zero mismatches.

---

## Phase P2 — Runtime object schemas

Same pattern as P1. Shapes:

### Task P2.1: `actor-identity.schema.json` (TF-0002)

Required: `identity_version` (enum `"1"`), `actor_id` (ActorId), `actor_type` (ActorType), `public_keys` (array minItems 1 of `{key_id: string, algorithm: AlgorithmId, public_key: base64 string, purpose: enum ["signing","kem","attestation"], valid_from?: Timestamp, valid_until?: Timestamp}`), `trust_levels` (array of TrustLevel), `authority_roots` (array of `{kind: enum ["owner","organization","manufacturer","hardware-key","federation","compliance-issuer","local-emergency","transparency-anchor","trust-domain"], id: string}`), `valid_from` (Timestamp), `valid_until` (Timestamp). Optional: `attestations` (array), `instance_id` (InstanceId), `revocation_ref` (HashRef), `signature` (SignatureEnvelope).

**Invalid fixtures:** missing `public_keys`; `actor_id` with unknown type; `public_keys.0.purpose: "encrypt"`.

### Task P2.2: `capability-token.schema.json` (TF-0004)

Required: `token_version` (enum `"1"`), `id` (string), `issuer` (ActorId), `subject` (ActorId), `capability` (Capability), `issued_at` (Timestamp), `signature` (SignatureEnvelope). Optional: `constraints` (Constraint[]), `chain` (DelegationLink[]), `expires_at` (Timestamp), `proof_ref` (HashRef).

**Invalid fixtures:** missing `signature`; `issued_at` without timezone; unknown actor type in `subject`.

### Task P2.3: `revocation.schema.json` (TF-0004)

Required: `revocation_version` (enum `"1"`), `id` (string), `target_id` (string), `target_kind` (enum `["capability","actor","delegation","instance"]`), `effective_at` (Timestamp), `issuer` (ActorId), `signature` (SignatureEnvelope). Optional: `reason` (string), `reinstatement_possible` (bool).

**Invalid fixtures:** missing `target_kind`; `target_kind: "session"` (not in enum); malformed `effective_at`.

### Task P2.4: `proof-event.schema.json` (TF-0005)

Required: `event_version` (enum `"1"`), `id` (string), `type` (string, pattern `^[a-z][a-z0-9._-]*$`), `actor_id` (ActorId), `timestamp` (Timestamp), `level` (ProofLevel), `signature` (SignatureEnvelope). Optional: `instance_id` (InstanceId), `session_id` (string), `subject_ref` (string), `payload_hash` (HashRef), `parent_hash` (HashRef), `context` (object, additionalProperties true).

**Invalid fixtures:** missing `type`; `level: "L9"`; `type: "ActorConnected"` (bad pattern).

### Task P2.5: `proof-bundle.schema.json` (TF-0005)

JSON representation of `.tfproof`. Required: `bundle_version` (enum `"1"`), `events` (array minItems 1 of ProofEvent — use `$ref` to `proof-event.schema.json`), `signature` (SignatureEnvelope). Optional: `merkle_root` (HashRef), `transparency_anchor` (object with `kind: enum ["rfc6962","sigstore","custom"]`, `url: string`, `inclusion_proof?: object`), `chain_hash` (HashRef).

**Invalid fixtures:** empty `events`; missing `signature`; `transparency_anchor.kind: "gnap"`.

### Task P2.6: Composite fixture example

Create `schemas/fixtures/capability-token/composite/delegation-chain.yaml` — a capability token whose `chain` references capability names defined in `schemas/fixtures/actions/valid/basic.yaml`. Validate it with the existing matrix; this just proves cross-schema reference works end-to-end even though JSON Schema can't enforce the cross-file constraint by itself.

### Task P2.7: Run full matrix

Run `bun run --filter tf-schema validate:all`. Expected: `valid: ≥11 / invalid: ≥33 matched / 0 mismatches`.

---

## Phase P3 — CLI hardening: lint, bundle, improved validate

### Task P3.1: Implement `tf-schema lint`

**Files:**
- Create: `tools/tf-schema/src/lint.ts`
- Create: `tools/tf-schema/tests/lint.test.ts`
- Modify: `tools/tf-schema/src/cli.ts`

- [ ] **Step 1: Write failing test**

Create `tools/tf-schema/tests/lint.test.ts`:

```ts
import { describe, expect, test } from "bun:test";
import { lintSchemas } from "../src/lint";

describe("lint", () => {
  test("passes on current schemas", async () => {
    const result = await lintSchemas();
    expect(result.issues).toEqual([]);
  });
});
```

- [ ] **Step 2: Run — expect module-not-found FAIL**

Run: `bun test tools/tf-schema/tests/lint.test.ts`

- [ ] **Step 3: Implement `lint.ts`**

```ts
import { listSchemas, loadFile } from "./loader";

export type LintIssue = { file: string; path: string; rule: string; message: string };
export type LintResult = { issues: LintIssue[] };

type JSONValue = string | number | boolean | null | JSONValue[] | { [k: string]: JSONValue };

export async function lintSchemas(): Promise<LintResult> {
  const issues: LintIssue[] = [];
  for (const { name, path } of listSchemas()) {
    const schema = loadFile(path) as Record<string, JSONValue>;
    lintOne(name, schema, "", issues);
    const expectedId = `https://trustforge.io/schemas/v0/${name}.schema.json`;
    if (schema["$id"] !== expectedId) {
      issues.push({ file: `${name}.schema.json`, path: "/$id", rule: "id-matches-filename", message: `expected ${expectedId}` });
    }
  }
  return { issues };
}

function lintOne(file: string, node: JSONValue, path: string, issues: LintIssue[]): void {
  if (!node || typeof node !== "object" || Array.isArray(node)) return;
  const obj = node as Record<string, JSONValue>;

  if (obj["type"] === "object") {
    if (obj["additionalProperties"] !== false && !(obj["$ref"])) {
      issues.push({ file: `${file}.schema.json`, path: path || "/", rule: "no-extra-props", message: "object without additionalProperties:false" });
    }
    const props = obj["properties"];
    if (props && typeof props === "object" && !Array.isArray(props)) {
      for (const [k, v] of Object.entries(props as Record<string, JSONValue>)) {
        const sub = v as Record<string, JSONValue>;
        if (!sub["description"] && !sub["$ref"]) {
          issues.push({ file: `${file}.schema.json`, path: `${path}/properties/${k}`, rule: "description-required", message: `property '${k}' has no description` });
        }
        lintOne(file, v, `${path}/properties/${k}`, issues);
      }
    }
  }

  for (const [k, v] of Object.entries(obj)) {
    if (k === "properties") continue;
    lintOne(file, v, `${path}/${k}`, issues);
  }
}
```

- [ ] **Step 4: Wire into `cli.ts`**

Add case:

```ts
: cmd === "lint" ? await (async () => {
    const r = await (await import("./lint")).lintSchemas();
    for (const i of r.issues) console.error(`${i.file}${i.path} [${i.rule}] ${i.message}`);
    return r.issues.length === 0 ? 0 : 1;
  })()
```

- [ ] **Step 5: Run test**

Run: `bun test tools/tf-schema/tests/lint.test.ts`
Expected: PASS (if any existing schema fails, fix the schema — add missing descriptions; don't relax the rule).

- [ ] **Step 6: Commit**

```bash
git add tools/tf-schema
git -c commit.gpgsign=false commit -m "$(cat <<'EOF'
Add tf-schema lint with description + additionalProperties rules

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

### Task P3.2: Implement `tf-schema bundle`

**Files:**
- Create: `tools/tf-schema/src/bundle.ts`
- Create: `tools/tf-schema/tests/bundle.test.ts`
- Modify: `tools/tf-schema/src/cli.ts`

- [ ] **Step 1: Write failing test**

```ts
import { describe, expect, test } from "bun:test";
import { bundleSchema } from "../src/bundle";

describe("bundle", () => {
  test("inlines _common refs", async () => {
    const bundled = await bundleSchema("agent-contract");
    const text = JSON.stringify(bundled);
    expect(text).not.toContain("_common.schema.json");
    expect(text).toContain('"R0"');
  });
});
```

- [ ] **Step 2: Run — FAIL**

- [ ] **Step 3: Implement `bundle.ts`**

```ts
import { listSchemas, loadFile, SCHEMAS_DIR } from "./loader";
import { join } from "node:path";

type Obj = Record<string, unknown>;

export async function bundleSchema(name: string): Promise<Obj> {
  const path = join(SCHEMAS_DIR, `${name}.schema.json`);
  const root = loadFile(path) as Obj;
  const registry: Record<string, Obj> = {};
  for (const { name, path } of listSchemas()) registry[name] = loadFile(path) as Obj;

  const seen = new Set<string>();
  function resolve(node: unknown): unknown {
    if (Array.isArray(node)) return node.map(resolve);
    if (!node || typeof node !== "object") return node;
    const obj = node as Obj;
    const ref = obj["$ref"];
    if (typeof ref === "string" && ref.includes("_common.schema.json#/$defs/")) {
      const defName = ref.split("/$defs/")[1]!;
      if (seen.has(defName)) return { $ref: `#/$defs/${defName}` };
      seen.add(defName);
      const defs = (registry["_common"]!["$defs"] as Obj)[defName] as Obj;
      return resolve(defs);
    }
    if (typeof ref === "string" && !ref.startsWith("#")) {
      const [fileRef, fragment] = ref.split("#");
      const schemaName = fileRef!.replace(/\.schema\.json$/, "");
      const target = registry[schemaName];
      if (!target) throw new Error(`unknown $ref target: ${ref}`);
      return resolve(pointerGet(target, fragment ?? ""));
    }
    const out: Obj = {};
    for (const [k, v] of Object.entries(obj)) out[k] = resolve(v);
    return out;
  }

  const bundled = resolve(root) as Obj;
  return bundled;
}

function pointerGet(doc: Obj, fragment: string): unknown {
  if (!fragment || fragment === "/") return doc;
  const parts = fragment.replace(/^#?\//, "").split("/");
  let cur: unknown = doc;
  for (const p of parts) {
    if (cur && typeof cur === "object") cur = (cur as Obj)[decodeURIComponent(p)];
    else return undefined;
  }
  return cur;
}
```

- [ ] **Step 4: Wire into `cli.ts`**

```ts
: cmd === "bundle" ? await (async () => {
    const [name] = rest;
    if (!name) { console.error("usage: tf-schema bundle <schema-name>"); return 2; }
    const b = await (await import("./bundle")).bundleSchema(name);
    console.log(JSON.stringify(b, null, 2));
    return 0;
  })()
```

- [ ] **Step 5: Run test**

Run: `bun test tools/tf-schema/tests/bundle.test.ts`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add tools/tf-schema
git -c commit.gpgsign=false commit -m "Add tf-schema bundle to inline \$refs for codegen input

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Phase P4 — TypeScript codegen + `tools/tf-types-ts` package

### Task P4.1: Scaffold `tools/tf-types-ts` package

**Files:**
- Create: `tools/tf-types-ts/package.json`
- Create: `tools/tf-types-ts/tsconfig.json`
- Create: `tools/tf-types-ts/src/index.ts` (stub)

- [ ] **Step 1: Write `package.json`**

```json
{
  "name": "tf-types",
  "version": "0.0.0",
  "private": true,
  "type": "module",
  "description": "TrustForge typed schema bindings and semantic core.",
  "main": "./src/index.ts",
  "exports": { ".": "./src/index.ts" },
  "scripts": {
    "typecheck": "bun x tsc -p tsconfig.json --noEmit",
    "test": "bun test"
  },
  "devDependencies": {
    "@types/bun": "^1.3.9",
    "typescript": "^5.6.3",
    "fast-check": "^3.22.0"
  }
}
```

- [ ] **Step 2: Write `tsconfig.json`**

```json
{
  "extends": "../../tsconfig.json",
  "compilerOptions": { "types": ["bun"] },
  "include": ["src/**/*.ts", "tests/**/*.ts"]
}
```

- [ ] **Step 3: Write `src/index.ts` stub**

```ts
export {};
```

- [ ] **Step 4: Install**

Run: `bun install`
Expected: `fast-check` added to lockfile.

- [ ] **Step 5: Commit**

```bash
git add tools/tf-types-ts package.json bun.lock
git -c commit.gpgsign=false commit -m "Scaffold tools/tf-types-ts workspace package

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

### Task P4.2: Implement JSON-Schema → TS codegen

**Files:**
- Create: `tools/tf-schema/src/codegen/model.ts`
- Create: `tools/tf-schema/src/codegen/ts.ts`
- Create: `tools/tf-schema/tests/codegen-ts.test.ts`
- Modify: `tools/tf-schema/src/cli.ts`

- [ ] **Step 1: Write failing test**

```ts
import { describe, expect, test } from "bun:test";
import { generateTs } from "../src/codegen/ts";

describe("TS codegen", () => {
  test("emits RiskClass as a string-literal union", async () => {
    const out = await generateTs();
    expect(out["_common.ts"]).toContain('export type RiskClass = "R0" | "R1" | "R2" | "R3" | "R4" | "R5"');
  });

  test("emits AgentContract interface with required project", async () => {
    const out = await generateTs();
    expect(out["agent-contract.ts"]).toContain("export interface AgentContract");
    expect(out["agent-contract.ts"]).toContain("project: string");
  });

  test("produces a deterministic barrel index", async () => {
    const out = await generateTs();
    expect(out["index.ts"]).toContain('export * from "./_common.js"');
    expect(out["index.ts"]).toContain('export * from "./agent-contract.js"');
  });
});
```

- [ ] **Step 2: Run — FAIL (module not found)**

- [ ] **Step 3: Implement shared IR in `codegen/model.ts`**

```ts
import { listSchemas, loadFile } from "../loader";

export type Prop = {
  name: string;
  tsType: string;
  rustType: string;
  required: boolean;
  description?: string;
};

export type TypeDecl = {
  name: string;
  kind: "struct" | "alias" | "enum" | "tagged-union";
  description?: string;
  props?: Prop[];
  aliasTs?: string;
  aliasRust?: string;
  enumValues?: string[];
  variants?: { name: string; tag: string; props: Prop[] }[];
};

export type SchemaModel = { schemaName: string; decls: TypeDecl[]; rootName?: string };

const IDENT = (s: string) => s.replace(/(^|[-_])(\w)/g, (_, __, c) => c.toUpperCase());

export function buildModel(schemaName: string): SchemaModel {
  const path = `schemas/${schemaName}.schema.json`;
  void path;
  const schema = loadFile(`${process.cwd().replace(/\/?$/, "/")}schemas/${schemaName}.schema.json`) as any;
  const decls: TypeDecl[] = [];
  if (schema.$defs) for (const [name, def] of Object.entries<any>(schema.$defs)) decls.push(declForNamed(name, def));
  if (schema.type === "object") decls.push(declForNamed(IDENT(schemaName), schema));
  return { schemaName, decls, rootName: schema.type === "object" ? IDENT(schemaName) : undefined };
}

function declForNamed(name: string, node: any): TypeDecl {
  if (node.enum) {
    if (node.enum.every((v: any) => typeof v === "string")) {
      return { name, kind: "enum", enumValues: node.enum, description: node.description };
    }
  }
  if (node.type === "string") return { name, kind: "alias", aliasTs: "string", aliasRust: "String", description: node.description };
  if (node.type === "object" && node.properties) {
    const required = new Set<string>(node.required ?? []);
    const props: Prop[] = Object.entries<any>(node.properties).map(([k, v]) => ({
      name: k,
      required: required.has(k),
      description: v.description,
      tsType: tsType(v),
      rustType: rustType(v),
    }));
    return { name, kind: "struct", props, description: node.description };
  }
  if (node.oneOf) {
    const variants = node.oneOf.map((v: any, i: number) => {
      const tag = v.properties?.kind?.const ?? `variant_${i}`;
      const required = new Set<string>(v.required ?? []);
      const props: Prop[] = Object.entries<any>(v.properties ?? {}).filter(([k]) => k !== "kind").map(([k, vv]) => ({
        name: k, required: required.has(k), description: vv.description, tsType: tsType(vv), rustType: rustType(vv),
      }));
      return { name: IDENT(tag), tag, props };
    });
    return { name, kind: "tagged-union", variants, description: node.description };
  }
  return { name, kind: "alias", aliasTs: "unknown", aliasRust: "serde_json::Value" };
}

function refName(ref: string): string {
  const [, fragment] = ref.split("#");
  const parts = fragment?.split("/") ?? [];
  return IDENT(parts[parts.length - 1] ?? "unknown");
}

export function tsType(node: any): string {
  if (!node) return "unknown";
  if (node.$ref) return refName(node.$ref);
  if (node.enum && node.enum.every((v: any) => typeof v === "string")) return node.enum.map((v: string) => JSON.stringify(v)).join(" | ");
  if (node.type === "string") return "string";
  if (node.type === "integer" || node.type === "number") return "number";
  if (node.type === "boolean") return "boolean";
  if (node.type === "array") return `${tsType(node.items)}[]`;
  if (node.type === "object") {
    if (node.additionalProperties && typeof node.additionalProperties === "object") return `Record<string, ${tsType(node.additionalProperties)}>`;
    return "Record<string, unknown>";
  }
  if (node.oneOf) return node.oneOf.map((v: any) => tsType(v)).join(" | ");
  return "unknown";
}

export function rustType(node: any): string {
  if (!node) return "serde_json::Value";
  if (node.$ref) return refName(node.$ref);
  if (node.enum && node.enum.every((v: any) => typeof v === "string")) return refName(`#/${node.enum.join("_")}`);
  if (node.type === "string") return "String";
  if (node.type === "integer") return "i64";
  if (node.type === "number") return "f64";
  if (node.type === "boolean") return "bool";
  if (node.type === "array") return `Vec<${rustType(node.items)}>`;
  if (node.type === "object") return "serde_json::Value";
  return "serde_json::Value";
}

export function allModels(): SchemaModel[] {
  return listSchemas().map(s => buildModel(s.name));
}

/** typeName → schemaName that owns it. Used by emitters to write cross-file imports. */
export function buildSymbolRegistry(models: SchemaModel[]): Map<string, string> {
  const reg = new Map<string, string>();
  for (const m of models) for (const d of m.decls) reg.set(d.name, m.schemaName);
  return reg;
}
```

Note: this generator is intentionally minimal. It handles the schema shapes our repo actually uses. Do not generalize beyond what the fixtures exercise.

- [ ] **Step 4: Implement TS emitter in `codegen/ts.ts`**

```ts
import { allModels, buildSymbolRegistry, type SchemaModel, type Prop } from "./model";

const HEADER = "// GENERATED by `tf-schema codegen --target ts` — DO NOT EDIT BY HAND.\n\n";

function collectReferencedTypes(src: string): string[] {
  // matches bare PascalCase identifiers used as types (not the best parser, but good enough for our controlled output)
  const hits = new Set<string>();
  const re = /\b([A-Z][A-Za-z0-9]*)\b/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(src))) hits.add(m[1]!);
  return [...hits];
}

export async function generateTs(): Promise<Record<string, string>> {
  const files: Record<string, string> = {};
  const models = allModels().sort((a, b) => a.schemaName.localeCompare(b.schemaName));
  const registry = buildSymbolRegistry(models);

  for (const m of models) {
    const body = emitModel(m);
    const localNames = new Set(m.decls.map(d => d.name));
    const referenced = collectReferencedTypes(body).filter(n => registry.has(n) && !localNames.has(n));
    const byFile = new Map<string, Set<string>>();
    for (const n of referenced) {
      const owner = registry.get(n)!;
      if (owner === m.schemaName) continue;
      if (!byFile.has(owner)) byFile.set(owner, new Set());
      byFile.get(owner)!.add(n);
    }
    const imports = [...byFile.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([file, names]) => `import type { ${[...names].sort().join(", ")} } from "./${file}.js";`)
      .join("\n");
    files[`${m.schemaName}.ts`] = HEADER + (imports ? imports + "\n\n" : "") + body;
  }
  const barrelLines = models.map(m => `export * from "./${m.schemaName}.js";`);
  files["index.ts"] = HEADER + barrelLines.join("\n") + "\n";
  return files;
}

function emitModel(m: SchemaModel): string {
  const parts: string[] = [];
  const sorted = [...m.decls].sort((a, b) => a.name.localeCompare(b.name));
  for (const d of sorted) parts.push(emitDecl(d));
  return parts.join("\n\n") + "\n";
}

function emitDecl(d: { name: string; kind: string; description?: string; props?: Prop[]; aliasTs?: string; enumValues?: string[]; variants?: any[] }): string {
  const doc = d.description ? `/** ${d.description} */\n` : "";
  if (d.kind === "enum") return `${doc}export type ${d.name} = ${d.enumValues!.map(v => JSON.stringify(v)).join(" | ")};`;
  if (d.kind === "alias") return `${doc}export type ${d.name} = ${d.aliasTs};`;
  if (d.kind === "struct") {
    const lines = d.props!.map(p => `  ${JSON.stringify(p.name)}${p.required ? "" : "?"}: ${p.tsType};`);
    return `${doc}export interface ${d.name} {\n${lines.join("\n")}\n}`;
  }
  if (d.kind === "tagged-union") {
    const variants = d.variants!.map(v => {
      const fields = v.props.map((p: Prop) => `  ${JSON.stringify(p.name)}${p.required ? "" : "?"}: ${p.tsType};`);
      return `{\n  kind: ${JSON.stringify(v.tag)};\n${fields.join("\n")}\n}`;
    });
    return `${doc}export type ${d.name} =\n  | ${variants.join("\n  | ")};`;
  }
  return "";
}

export async function writeTsOutput(outDir: string): Promise<string[]> {
  const { writeFileSync, mkdirSync } = await import("node:fs");
  mkdirSync(outDir, { recursive: true });
  const files = await generateTs();
  for (const [name, content] of Object.entries(files)) writeFileSync(`${outDir}/${name}`, content);
  return Object.keys(files);
}
```

- [ ] **Step 5: Wire into `cli.ts`**

Add dispatch for `codegen --target ts [--out <dir>]`:

```ts
: cmd === "codegen" ? await (async () => {
    const target = argValue(rest, "--target");
    const out = argValue(rest, "--out");
    if (target === "ts") {
      const dest = out ?? "tools/tf-types-ts/src/generated";
      const names = await (await import("./codegen/ts")).writeTsOutput(dest);
      console.log(`wrote ${names.length} files to ${dest}`);
      return 0;
    }
    console.error("unknown codegen target: " + target);
    return 2;
  })()
```

Add helper:

```ts
function argValue(args: string[], flag: string): string | undefined {
  const idx = args.indexOf(flag);
  return idx >= 0 ? args[idx + 1] : undefined;
}
```

- [ ] **Step 6: Run codegen and regenerate TS types**

Run: `bun run tools/tf-schema/src/cli.ts codegen --target ts`
Expected: `wrote 13 files to tools/tf-types-ts/src/generated` (12 schemas + 1 barrel — will be more as P1/P2 schemas land).

- [ ] **Step 7: Run codegen test**

Run: `bun test tools/tf-schema/tests/codegen-ts.test.ts`
Expected: PASS.

- [ ] **Step 8: Typecheck the generated output**

Run: `bun run --filter tf-types typecheck`
Expected: no errors.

- [ ] **Step 9: Commit**

```bash
git add tools/tf-schema tools/tf-types-ts/src/generated
git -c commit.gpgsign=false commit -m "Add TS codegen; generate tf-types-ts/src/generated/

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

### Task P4.3: Hand-written core modules

For each of the following, follow this micro-pattern:
1. Write a test file at `tools/tf-types-ts/tests/<module>.test.ts` covering happy path + 3 error cases.
2. Run — expect FAIL.
3. Write the implementation at `tools/tf-types-ts/src/core/<module>.ts`.
4. Run — expect PASS.
5. Add a re-export to `src/index.ts`.
6. Commit.

Core modules and their surfaces:

**`actor-id.ts`** —
```ts
export type ActorType = "human" | "agent" | ... // 14 types
export interface ParsedActorId { type: ActorType; path: string; raw: string }
export function parseActorId(s: string): ParsedActorId // throws ActorIdParseError
export function formatActorId(p: { type: ActorType; path: string }): string
export class ActorIdParseError extends Error {}
```

**`instance-id.ts`** — same pattern, parsing `tf:instance:<type>:<actor-path>/<instance-path>`; expose `toActorId(instanceId)` returning the actor URI without the instance suffix.

**`trust-domain.ts`** — `parseTrustDomain(s): { kind: "dns" | "local"; value: string }` + `equals(a, b)`.

**`capability.ts`** —
```ts
export function isCapability(x: unknown): x is Capability
export function constraintsSatisfied(constraints: Constraint[], ctx: EvalContext): boolean
export function intersectConstraints(a: Constraint[], b: Constraint[]): Constraint[]
```

`EvalContext = { now: string; session_id?: string; target?: string; approver_count?: number; device_actor?: string }`. Tests: time window (not started, active, expired), rate (under/over), target pattern match, quorum, device binding.

**`delegation.ts`** —
```ts
export interface WalkResult { valid: boolean; effective: Constraint[]; expired_at?: string; broken_step?: number }
export function walkChain(chain: DelegationLink[], now: string): WalkResult
```

Tests: single link valid; expired link breaks chain; redelegation exceeded; last link's constraints intersected with earlier links.

**`revocation.ts`** —
```ts
export class RevocationIndex {
  static from(revs: Revocation[]): RevocationIndex
  isRevoked(target: { id: string; kind: Revocation["target_kind"] }, at: string): boolean
}
```

Tests: exact match, effective_at in future → not yet revoked, wrong kind → not revoked.

**`envelope.ts`** — `validateEnvelopeShape(e): ValidationResult` — checks base64 lengths, known-algorithm warning. No crypto.

**`canonical.ts`** —
```ts
export function canonicalize(value: unknown): string   // deterministic JSON
```

Rules: sorted object keys (NFC-normalized), integers without `.0`, no trailing zeros on floats but preserve representation, strings NFC-normalized, reject `undefined`/functions. Tests: nested objects sort; unicode NFC; numbers; reject reserved.

- [ ] **Steps per module** (repeat for each of the 8): write test, run-fail, implement, run-pass, export, commit.

Estimated commits: 8.

### Task P4.4: Round-trip test over all valid fixtures

**Files:**
- Create: `tools/tf-types-ts/tests/round-trip.test.ts`

- [ ] **Step 1: Write the test**

```ts
import { describe, expect, test } from "bun:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { parse as parseYAML } from "yaml";
import { canonicalize } from "../src/core/canonical";

const FIXTURES = join(import.meta.dir, "..", "..", "..", "schemas", "fixtures");

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const f of readdirSync(dir)) {
    const p = join(dir, f);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if (p.endsWith(".yaml") && !p.endsWith(".expected-error.yaml")) out.push(p);
  }
  return out;
}

describe("round-trip", () => {
  for (const f of walk(FIXTURES).filter(p => p.includes("/valid/"))) {
    test(`canonicalize is stable for ${f.split("/schemas/")[1]}`, () => {
      const doc = parseYAML(readFileSync(f, "utf8"));
      const a = canonicalize(doc);
      const b = canonicalize(JSON.parse(a));
      expect(a).toBe(b);
    });
  }
});
```

- [ ] **Step 2: Run**

Run: `bun test tools/tf-types-ts/tests/round-trip.test.ts`
Expected: PASS for every valid fixture.

- [ ] **Step 3: Commit**

```bash
git add tools/tf-types-ts/tests/round-trip.test.ts
git -c commit.gpgsign=false commit -m "Add canonical-JSON round-trip test over all valid fixtures

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Phase P5 — Rust codegen + `crates/tf-types`

### Task P5.1: Set up Cargo workspace and `crates/tf-types`

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `crates/tf-types/Cargo.toml`
- Create: `crates/tf-types/src/lib.rs`
- Modify: `.gitignore` to add `target/`

- [ ] **Step 1: Write workspace root `Cargo.toml`**

```toml
[workspace]
resolver = "2"
members = ["crates/tf-types"]

[workspace.package]
edition = "2021"
license = "Apache-2.0"
repository = "https://github.com/NuGit-Tech/TrustForge"

[workspace.dependencies]
serde = { version = "1", features = ["derive"] }
serde_json = "1"
proptest = "1"
```

- [ ] **Step 2: Write `crates/tf-types/Cargo.toml`**

```toml
[package]
name = "tf-types"
version = "0.0.0"
edition.workspace = true
license.workspace = true
repository.workspace = true

[features]
default = ["serde"]
serde = ["dep:serde", "dep:serde_json"]
fuzz = ["dep:proptest"]

[dependencies]
serde = { workspace = true, optional = true }
serde_json = { workspace = true, optional = true }
proptest = { workspace = true, optional = true }

[dev-dependencies]
serde_json = { workspace = true }
```

- [ ] **Step 3: Write minimal `src/lib.rs`**

```rust
//! TrustForge type bindings and semantic core.
//!
//! Generated wire types live under `generated/`; hand-written semantic
//! helpers live as sibling modules.

#![deny(unsafe_code)]
```

- [ ] **Step 4: Update `.gitignore`**

Ensure it contains `target/` and `Cargo.lock` is committed (apps) — for library-only workspaces we still commit `Cargo.lock` in CI-first repos. Leave `Cargo.lock` tracked.

- [ ] **Step 5: Verify build**

Run: `cargo check --workspace`
Expected: compiles clean.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock crates/tf-types .gitignore
git -c commit.gpgsign=false commit -m "Scaffold Cargo workspace with crates/tf-types

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

### Task P5.2: Implement Rust codegen

**Files:**
- Create: `tools/tf-schema/src/codegen/rust.ts`
- Create: `tools/tf-schema/tests/codegen-rust.test.ts`
- Modify: `tools/tf-schema/src/cli.ts`

- [ ] **Step 1: Write failing test**

```ts
import { describe, expect, test } from "bun:test";
import { generateRust } from "../src/codegen/rust";

describe("Rust codegen", () => {
  test("emits RiskClass enum", async () => {
    const out = await generateRust();
    expect(out["common.rs"]).toContain("pub enum RiskClass");
    expect(out["common.rs"]).toContain("R0,");
  });

  test("derives Serialize + Deserialize on every struct", async () => {
    const out = await generateRust();
    for (const [file, text] of Object.entries(out)) {
      if (file === "mod.rs") continue;
      const structCount = (text.match(/pub struct /g) ?? []).length;
      const deriveCount = (text.match(/#\[derive\([^)]*Serialize[^)]*Deserialize[^)]*\)\]/g) ?? []).length;
      expect(deriveCount).toBeGreaterThanOrEqual(structCount);
    }
  });
});
```

- [ ] **Step 2: Run — FAIL**

- [ ] **Step 3: Implement `codegen/rust.ts`**

```ts
import { allModels, type Prop, type TypeDecl } from "./model";

const HEADER = `// GENERATED by \`tf-schema codegen --target rust\` — DO NOT EDIT BY HAND.

#![allow(unused_imports, non_camel_case_types, clippy::all)]

use serde::{Deserialize, Serialize};
`;

const SNAKE = (s: string) => s.replace(/[-.]/g, "_").replace(/([a-z])([A-Z])/g, "$1_$2").toLowerCase();

export async function generateRust(): Promise<Record<string, string>> {
  const files: Record<string, string> = {};
  const models = allModels().sort((a, b) => a.schemaName.localeCompare(b.schemaName));

  for (const m of models) {
    const file = `${SNAKE(m.schemaName.replace(/^_/, ""))}.rs`;
    files[file] = HEADER + m.decls.sort((a, b) => a.name.localeCompare(b.name)).map(emit).join("\n\n") + "\n";
  }
  const modLines = models.map(m => `pub mod ${SNAKE(m.schemaName.replace(/^_/, ""))};`);
  files["mod.rs"] = HEADER + modLines.join("\n") + "\n";
  return files;
}

function emit(d: TypeDecl): string {
  if (d.kind === "enum") {
    const variants = d.enumValues!.map(v => `    #[serde(rename = ${JSON.stringify(v)})]\n    ${safeVariant(v)},`);
    return doc(d.description) + `#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]\npub enum ${d.name} {\n${variants.join("\n")}\n}`;
  }
  if (d.kind === "alias") {
    return doc(d.description) + `pub type ${d.name} = ${d.aliasRust};`;
  }
  if (d.kind === "struct") {
    const fields = d.props!.map((p: Prop) => {
      const rust = p.required ? p.rustType : `Option<${p.rustType}>`;
      const rename = p.name !== SNAKE(p.name) ? `    #[serde(rename = ${JSON.stringify(p.name)})]\n` : "";
      const skip = p.required ? "" : `    #[serde(skip_serializing_if = "Option::is_none", default)]\n`;
      return `${rename}${skip}    pub ${SNAKE(p.name)}: ${rust},`;
    });
    return doc(d.description) + `#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]\npub struct ${d.name} {\n${fields.join("\n")}\n}`;
  }
  if (d.kind === "tagged-union") {
    const variants = d.variants!.map(v => {
      const fields = v.props.map((p: Prop) => {
        const rust = p.required ? p.rustType : `Option<${p.rustType}>`;
        return `        ${SNAKE(p.name)}: ${rust},`;
      });
      return `    #[serde(rename = ${JSON.stringify(v.tag)})]\n    ${safeVariant(v.name)} {\n${fields.join("\n")}\n    },`;
    });
    return doc(d.description) + `#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]\n#[serde(tag = "kind")]\npub enum ${d.name} {\n${variants.join("\n")}\n}`;
  }
  return "";
}

function doc(s?: string): string { return s ? `/// ${s}\n` : ""; }
function safeVariant(s: string): string {
  const cleaned = s.replace(/[^A-Za-z0-9_]/g, "_");
  return /^[0-9]/.test(cleaned) ? `V${cleaned}` : cleaned.replace(/^([a-z])/, (_, c) => c.toUpperCase());
}

export async function writeRustOutput(outDir: string): Promise<string[]> {
  const { writeFileSync, mkdirSync } = await import("node:fs");
  mkdirSync(outDir, { recursive: true });
  const files = await generateRust();
  for (const [name, content] of Object.entries(files)) writeFileSync(`${outDir}/${name}`, content);
  return Object.keys(files);
}
```

- [ ] **Step 4: Wire into `cli.ts`**

Add in the `codegen` dispatch branch:

```ts
if (target === "rust") {
  const dest = out ?? "crates/tf-types/src/generated";
  const names = await (await import("./codegen/rust")).writeRustOutput(dest);
  console.log(`wrote ${names.length} files to ${dest}`);
  return 0;
}
```

- [ ] **Step 5: Run codegen**

Run: `bun run tools/tf-schema/src/cli.ts codegen --target rust`
Expected: `wrote N files to crates/tf-types/src/generated`.

- [ ] **Step 6: Add `mod generated;` to `lib.rs`**

Change `src/lib.rs` to:

```rust
#![deny(unsafe_code)]
pub mod generated;
```

- [ ] **Step 7: Compile**

Run: `cargo check --workspace`
Expected: clean build. If identifiers collide, adjust `safeVariant` / `SNAKE` in `rust.ts` and re-run codegen.

- [ ] **Step 8: Run codegen test**

Run: `bun test tools/tf-schema/tests/codegen-rust.test.ts`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add tools/tf-schema crates/tf-types/src
git -c commit.gpgsign=false commit -m "Add Rust codegen; generate crates/tf-types/src/generated/

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

### Task P5.3: Hand-written Rust core modules

Mirror each TS core module, using the same pattern (unit-test first). Key parity points:

- `canonical.rs`: byte-exact match with TS output. Add `tests/canonical_cross_language.rs` that reads `canonical-vectors.yaml` (input + expected output) and asserts equality for each.
- `actor_id.rs`, `instance_id.rs`, `trust_domain.rs`, `capability.rs`, `delegation.rs`, `revocation.rs`, `envelope.rs`: same API surface as TS, typed error variants.

Estimated: 8 commits.

### Task P5.4: Canonical-JSON parity

**Files:**
- Create: `canonical-vectors.yaml` (repo root)
- Create: `tools/tf-types-ts/tests/canonical-vectors.test.ts`
- Create: `crates/tf-types/tests/canonical_cross_language.rs`

- [ ] **Step 1: Write `canonical-vectors.yaml`**

```yaml
vectors:
  - name: simple-object
    input: { b: 1, a: 2 }
    output: '{"a":2,"b":1}'
  - name: nested
    input: { a: { y: 2, x: 1 } }
    output: '{"a":{"x":1,"y":2}}'
  - name: unicode-nfc
    input: { s: "é" }          # combining-acute input ≠ output after NFC
    output: '{"s":"é"}'
  - name: integer-no-float
    input: { n: 42 }
    output: '{"n":42}'
  - name: nested-arrays
    input: { xs: [2, 1, 3] }
    output: '{"xs":[2,1,3]}'
```

- [ ] **Step 2: Write TS test** (load the YAML, call `canonicalize`, assert equality)
- [ ] **Step 3: Write Rust test** (same)
- [ ] **Step 4: Run both; fix whichever implementation diverges**
- [ ] **Step 5: Commit**

---

## Phase P6 — Docs codegen

### Task P6.1: Implement `codegen/docs.ts`

**Files:**
- Create: `tools/tf-schema/src/codegen/docs.ts`
- Create: `tools/tf-schema/tests/codegen-docs.test.ts`
- Modify: `tools/tf-schema/src/cli.ts`

- [ ] **Step 1: Write failing test**

```ts
import { describe, expect, test } from "bun:test";
import { generateDocs } from "../src/codegen/docs";

describe("docs codegen", () => {
  test("agent-contract page has fields table", async () => {
    const out = await generateDocs();
    expect(out["agent-contract.md"]).toContain("# TrustForge Agent Contract");
    expect(out["agent-contract.md"]).toContain("| Field | Type | Required |");
    expect(out["agent-contract.md"]).toContain("project");
  });
});
```

- [ ] **Step 2: Run — FAIL**

- [ ] **Step 3: Implement** — emit Markdown per schema with title, description, $id, fields table, cross-links to other schemas' `.md` pages for `$ref` targets. Fields table columns: Field, Type (rendered as code), Required (✓/·), Constraints, Description.

- [ ] **Step 4: Wire into CLI** — `--target docs` writes to `docs/schemas/`.

- [ ] **Step 5: Run; regenerate; commit generated output**.

### Task P6.2: Regenerate and commit docs

Run: `bun run tools/tf-schema/src/cli.ts codegen --target docs`
Commit: `docs/schemas/*`.

---

## Phase P7 — Fuzz harness + parity conformance suite

### Task P7.1: Implement `tf-schema fuzz`

**Files:**
- Create: `tools/tf-schema/src/fuzz.ts`
- Create: `tools/tf-schema/tests/fuzz.test.ts`
- Modify: `tools/tf-schema/src/cli.ts`

- [ ] **Step 1: Write test** — `fuzzSchema("agent-contract", { iterations: 50 })` must return `{panics: 0, hangs: 0}` and at least one `rejected` case.

- [ ] **Step 2: Implement** — schema-aware generator using `fast-check`:
  - For each `type: "object"` property, recursively generate well-typed values using `fc.record`.
  - For each `enum`, `fc.constantFrom(...enum)`.
  - For `pattern`, use `fc.string({ minLength, maxLength })` filtered by regex.
  - Mutation harness: take the valid result, randomly delete required fields, inject extra properties, corrupt types. Feed both through the validator.
  - Wrap each call in `Promise.race` with a 1s timeout (detects hang). Catch all errors (detect panic).

- [ ] **Step 3: Wire into CLI**: `tf-schema fuzz <schema> [--iterations N] [--seed S]`.

- [ ] **Step 4: Run; commit.**

### Task P7.2: Write `conformance/parity.yaml` + runners

**Files:**
- Create: `conformance/parity.yaml`
- Create: `tools/tf-schema/src/parity.ts` + CLI entry `tf-schema parity`
- Create: `crates/tf-types/tests/parity.rs`

- [ ] **Step 1: Generate `parity.yaml`** — script walks `schemas/fixtures/` and emits one entry per fixture: `{schema, path, expect: valid|invalid, errors?: [...] }`.

- [ ] **Step 2: TS runner** — reads `parity.yaml`, for each entry loads via `tf-types-ts`, validates via `tf-schema` AJV validator, asserts verdict matches.

- [ ] **Step 3: Rust runner** — same thing. Reads `parity.yaml` via `serde_yaml`, uses `jsonschema` crate to validate. Add:

```toml
# crates/tf-types/Cargo.toml [dev-dependencies]
serde_yaml = "0.9"
jsonschema = "0.18"
```

- [ ] **Step 4: Run both runners**

```bash
bun run tools/tf-schema/src/cli.ts parity
cargo test --workspace parity
```

Both must pass with identical counts. If not, the fixture is added to the "known parity divergences" list and fixed before the phase is closed.

- [ ] **Step 5: Commit.**

---

## Phase P8 — CI wiring

### Task P8.1: Write `.github/workflows/ci.yml`

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Write the workflow**

```yaml
name: ci
on:
  push:
    branches: [main]
  pull_request:

jobs:
  ts:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: oven-sh/setup-bun@v2
        with: { bun-version: "1.3" }
      - run: bun install --frozen-lockfile
      - run: bun run --filter '*' typecheck
      - run: bun test
      - run: bun run validate:all
      - run: bun run tools/tf-schema/src/cli.ts lint
      - name: codegen-diff
        run: |
          bun run tools/tf-schema/src/cli.ts codegen --target ts
          bun run tools/tf-schema/src/cli.ts codegen --target rust
          bun run tools/tf-schema/src/cli.ts codegen --target docs
          git diff --exit-code
      - run: bun run tools/tf-schema/src/cli.ts fuzz agent-contract --iterations 200
      - run: bun run tools/tf-schema/src/cli.ts parity

  rust:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo check --workspace
      - run: cargo test --workspace
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/ci.yml
git -c commit.gpgsign=false commit -m "Wire CI: typecheck, test, validate, lint, codegen-diff, fuzz, parity

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

### Task P8.2: Document how to add a new schema

**Files:**
- Create: `docs/schemas/_adding-a-schema.md` (or extend the existing `schemas/README.md`)

- [ ] **Step 1: Write a 10-step checklist** — file placement, `$id`, lint rules, fixtures layout, regenerate codegen, regenerate docs, add to `parity.yaml`, run CI locally.

- [ ] **Step 2: Commit.**

---

## Self-review checklist (run after all phases)

- [ ] Every schema in `schemas/` has an entry in `docs/schemas/`.
- [ ] `bun run validate:all` passes with ≥11 valid and ≥33 invalid fixtures, zero mismatches.
- [ ] `bun run tools/tf-schema/src/cli.ts lint` passes with zero issues.
- [ ] `bun run --filter '*' typecheck` passes.
- [ ] `bun test` passes across all workspaces.
- [ ] `cargo check --workspace && cargo test --workspace` passes.
- [ ] Both parity runners pass identical counts.
- [ ] CI green on a PR containing the full series.

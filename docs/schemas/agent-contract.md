# TrustForge Agent Contract

> Defined by TF-0006.
> `$id`: `https://trustforge.io/schemas/v0/agent-contract.schema.json`

Declarative contract that makes a TrustForge-enabled codebase legible and safe for AI agents. See TF-0006.

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `contract_version` | `"1"` | ✓ | Version of the agent-contract schema itself. |
| `spec_version` | string (pattern: `^TF-\d{4}(-draft|-v\d+)?$`) | ✓ | TrustForge spec revision this contract conforms to. |
| `project` | string (minLength: 1) | ✓ | Project identifier used in logs and contract references. |
| `trust_domain` | [`TrustDomain`](./_common.md#trustdomain) | · | The TrustForge trust domain this project belongs to. |
| `references` | object | · | Pointers to companion manifests. |
| `target_sets` | object | · | Named glob lists, reusable in action rules. |
| `actions` | array of `Action` | · | Declared actions this project allows agents to perform. |
| `forbidden` | array of `Forbidden` | · | Actions this project forbids outright. |
| `integrations` | object | · | Connections to MCP tools, ProofRPC services, and test commands. |
| `conformance` | object | · | Profiles this project claims. |

## `$defs`

### `Action`

Single action declaration.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | [`ActionName`](./_common.md#actionname) | ✓ |  |
| `risk` | [`RiskClass`](./_common.md#riskclass) | ✓ |  |
| `proof` | [`ProofLevel`](./_common.md#prooflevel) | · |  |
| `approval` | [`ApprovalRequirement`](./_common.md#approvalrequirement) | · |  |
| `description` | string | · | Human-readable purpose of the action. |
| `allow_targets` | array of string (minLength: 1) | · | Glob patterns the action may target. |
| `deny_targets` | array of string (minLength: 1) | · | Glob patterns the action must not target. |

### `Forbidden`

Forbidden action entry.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `action` | [`ActionName`](./_common.md#actionname) | ✓ |  |
| `reason` | string (minLength: 1) | · | Why this action is forbidden. |

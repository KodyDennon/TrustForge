# TrustForge Actions Library

> Defined by TF-0006.
> `$id`: `https://trustforge.io/schemas/v0/actions.schema.json`

Catalog of action definitions referenced by TF-0006 agent contracts.

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `actions_library_version` | `"1"` | ✓ | Version of the actions-library manifest schema itself. |
| `library_id` | string (pattern: `^[a-z][a-z0-9-]*$`) | ✓ | Library identifier, e.g. tf-actions-std. |
| `actions` | array of `ActionDef` (minItems: 1) | ✓ | Action definitions this library publishes. |

## `$defs`

### `ActionDef`

Definition of a single named action.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | [`ActionName`](./_common.md#actionname) | ✓ | Dotted action name this library defines. |
| `default_risk` | [`RiskClass`](./_common.md#riskclass) | ✓ | Default risk class when no policy overrides it. |
| `default_proof` | [`ProofLevel`](./_common.md#prooflevel) | ✓ | Default proof level when no policy overrides it. |
| `approval_default` | [`ApprovalRequirement`](./_common.md#approvalrequirement) | · | Default approval requirement when no policy overrides it. |
| `description` | string (minLength: 1) | ✓ | Human-readable description of what the action does. |
| `parameters` | object | · | Parameters schema for the action (opaque JSON Schema fragment). |
| `dangerous` | boolean | · | Flagged as dangerous; policies SHOULD require explicit approval. |
| `reversible` | boolean | · | Whether the action can be undone by its inverse. |

# TrustForge Dangerous Actions Catalog

> `$id`: `https://trustforge.io/schemas/v0/dangerous-actions.schema.json`

Canonical catalog of action names with their danger tags and default enforcement. Consumed by the agent-contract deep validator and AI integration guide.

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `dangerous_actions_version` | `"1"` | ✓ | Version of the dangerous-actions catalog schema itself. |
| `catalog_id` | string (pattern: `^[a-z][a-z0-9-]*$`) | ✓ | Stable catalog identifier, e.g. tf-dangerous-std. |
| `description` | string | · | Human-readable description of this catalog. |
| `actions` | array of `CatalogEntry` (minItems: 1) | ✓ | Known-dangerous action entries. Contracts should cross-reference this catalog when declaring danger_tags. |

## `$defs`

### `CatalogEntry`

Catalog entry for one dangerous action.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | [`ActionName`](./_common.md#actionname) | ✓ | Dotted action name, e.g. file.delete. |
| `danger_tags` | array of [`DangerTag`](./_common.md#dangertag) (minItems: 1) | ✓ | Danger categories assigned to this action. |
| `default_risk` | [`RiskClass`](./_common.md#riskclass) | ✓ | Risk class the catalog recommends. |
| `default_approval` | [`ApprovalRequirement`](./_common.md#approvalrequirement) | ✓ | Approval requirement the catalog recommends. |
| `default_reversible` | boolean | · | Whether this action is intrinsically reversible. |
| `mandatory_tags` | array of [`DangerTag`](./_common.md#dangertag) | · | Tags that any contract using this action MUST also declare. Used by the deep validator. |
| `description` | string (minLength: 1) | ✓ | Human-readable description of why this action is dangerous. |

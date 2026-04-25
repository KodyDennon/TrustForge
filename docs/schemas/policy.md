# TrustForge Policy Manifest

> Defined by TF-0004.
> `$id`: `https://trustforge.io/schemas/v0/policy.schema.json`

Declarative policy definition referenced by TF-0004. Backend-agnostic (Cedar, Rego, custom, native, none).

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `policy_version` | `"1"` | ✓ | Version of the policy manifest schema itself. |
| `trust_domain` | [`TrustDomain`](./_common.md#trustdomain) | ✓ | Trust domain this policy applies within. |
| `engine_hint` | `"cedar"` \| `"rego"` \| `"custom"` \| `"native"` \| `"none"` | · | Policy engine that interprets this manifest. |
| `rules` | array of `Rule` (minItems: 1) | ✓ | Policy rules evaluated top-to-bottom until a match yields a decision. |
| `negative_capabilities` | array of [`NegativeCapability`](./_common.md#negativecapability) | · | Explicit denials that override grants regardless of rule order. |
| `quorum_defaults` | object | · | Default quorum settings when a rule requests quorum approval without specifying one. |
| `continuous_reevaluation` | object | · | When live sessions must re-check this policy during execution. |

## `$defs`

### `Rule`

A single policy rule.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `id` | string (pattern: `^[a-z][a-z0-9._-]*$`) | ✓ | Rule identifier, used in proofs and audit logs. |
| `effect` | `"allow"` \| `"deny"` \| `"escalate"` \| `"log_only"` | ✓ | Decision produced when the rule matches. |
| `action` | [`ActionName`](./_common.md#actionname) | · | Exact action this rule applies to. |
| `action_pattern` | string | · | Regex (ECMAScript) matched against action names when an exact action is not set. |
| `subject_pattern` | string | · | Regex matched against the subject actor URI. |
| `target_patterns` | array of string (minLength: 1) | · | Glob patterns matched against the action target. |
| `risk_at_most` | [`RiskClass`](./_common.md#riskclass) | · | Rule applies only to actions whose risk is at or below this class. |
| `proof_required` | [`ProofLevel`](./_common.md#prooflevel) | · | Minimum proof level demanded when this rule applies. |
| `approval` | [`ApprovalRequirement`](./_common.md#approvalrequirement) | · | Approval requirement demanded when this rule applies. |
| `constraints` | array of [`Constraint`](./_common.md#constraint) | · | Additional constraints attached by this rule. |
| `reason` | string | · | Human-readable reason emitted in the decision. |

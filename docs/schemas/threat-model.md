# TrustForge Threat Model

> Defined by TF-0006.
> `$id`: `https://trustforge.io/schemas/v0/threat-model.schema.json`

Declarative threat-model manifest referenced by TF-0006 and by agent-contract.references.threat_model.

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `threat_model_version` | `"1"` | ✓ | Version of the threat-model manifest schema itself. |
| `project` | string (minLength: 1) | ✓ | Project identifier this threat model applies to. |
| `assets` | array of `Asset` (minItems: 1) | ✓ | Assets whose protection this threat model addresses. |
| `adversaries` | array of `Adversary` (minItems: 1) | ✓ | Adversary profiles this threat model considers. |
| `attack_classes` | array of string (minLength: 1) (minItems: 1) | ✓ | Attack-class identifiers relevant to this project (open-ended taxonomy). |
| `mitigations` | array of `Mitigation` | ✓ | Mitigations implemented, planned, or deliberately not applicable. |
| `residual_risks` | array of `ResidualRisk` | · | Risks explicitly accepted after mitigations. |

## `$defs`

### `Adversary`

Adversary profile.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `id` | string (pattern: `^[a-z][a-z0-9._-]*$`) | ✓ | Stable adversary identifier. |
| `description` | string (minLength: 1) | ✓ | Who this adversary is and what they want. |
| `capability_levels` | array of `"opportunistic"` \| `"targeted"` \| `"insider"` \| `"nation-state"` \| `"ai-assisted"` (minItems: 1) | ✓ | Capabilities attributed to this adversary. |

### `Asset`

Asset under threat analysis.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `id` | string (pattern: `^[a-z][a-z0-9._-]*$`) | ✓ | Stable asset identifier. |
| `description` | string (minLength: 1) | ✓ | What this asset is and why it matters. |
| `criticality` | [`RiskClass`](./_common.md#riskclass) | ✓ | Risk class describing asset-loss impact. |

### `Mitigation`

Mitigation applied to one or more assets or attack classes.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `id` | string (pattern: `^[a-z][a-z0-9._-]*$`) | ✓ | Stable mitigation identifier. |
| `applies_to` | array of string (minLength: 1) (minItems: 1) | ✓ | Asset or attack-class identifiers this mitigation covers. |
| `description` | string (minLength: 1) | ✓ | What the mitigation does. |
| `status` | `"planned"` \| `"implemented"` \| `"not-applicable"` | ✓ | Implementation status. |

### `ResidualRisk`

Risk accepted after mitigations.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `description` | string (minLength: 1) | ✓ | Nature of the residual risk. |
| `accepted_by` | [`ActorId`](./_common.md#actorid) | ✓ | Actor who accepted this risk. |
| `accepted_at` | [`Timestamp`](./_common.md#timestamp) | ✓ | When the acceptance was recorded. |

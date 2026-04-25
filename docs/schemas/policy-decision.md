# TrustForge Policy Decision

> `$id`: `https://trustforge.io/schemas/v0/policy-decision.schema.json`

Structured result emitted by a TrustForge PolicyEngine. Captures the decision, the rule that produced it, the constraints attached, and enough provenance to be replayed in audits and verified after the fact (TF-0004, DECISIONS.md "AI-readable manifests").

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `decision_version` | `"1"` | ✓ | Version of the policy-decision schema itself. |
| `policy_engine` | `"cedar"` \| `"rego"` \| `"custom"` \| `"native"` \| `"none"` | ✓ | Which engine produced this decision. |
| `engine_version` | string | · | Free-form version label so audits can replay the same engine build. |
| `trust_domain` | [`TrustDomain`](./_common.md#trustdomain) | ✓ |  |
| `subject` | [`ActorId`](./_common.md#actorid) | ✓ | Actor URI the policy was evaluated against. |
| `instance` | [`InstanceId`](./_common.md#instanceid) | · | Optional actor instance URI captured in the decision. |
| `action` | [`ActionName`](./_common.md#actionname) | ✓ | Action name being authorized. |
| `target` | string | · | Target the action operates on (file path, record id, URL, ...). |
| `decision` | `"allow"` \| `"deny"` \| `"escalate"` \| `"approval-required"` \| `"log-only"` | ✓ | Effect produced by the policy engine. |
| `rule_id` | string (pattern: `^[a-z][a-z0-9._-]*$`) | · | Identifier of the rule that produced the decision. |
| `reason` | string | · | Human-readable explanation of the decision. |
| `approval` | [`ApprovalRequirement`](./_common.md#approvalrequirement) | · |  |
| `proof_required` | [`ProofLevel`](./_common.md#prooflevel) | · |  |
| `constraints_applied` | array of [`Constraint`](./_common.md#constraint) | · | Constraints the rule attached to this decision. |
| `negative_capabilities_consulted` | array of [`NegativeCapability`](./_common.md#negativecapability) | · | Negative capabilities considered while reaching the decision (for audit). |
| `enforcement_level` | [`EnforcementLevel`](./_common.md#enforcementlevel) | · |  |
| `evaluated_at` | [`Timestamp`](./_common.md#timestamp) | ✓ |  |
| `policy_manifest_hash` | [`HashRef`](./_common.md#hashref) | · | Hash of the policy manifest that was evaluated. Lets auditors replay the decision against the exact manifest. |
| `context` | object | · | Free-form evaluation-time context (session id, posture flags, quorum approver count, etc.). |

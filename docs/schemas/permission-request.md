# TrustForge Permission Request

> `$id`: `https://trustforge.io/schemas/v0/permission-request.schema.json`

An AI agent's typed request to acquire authority for a specific action, target, and duration. The daemon validates the request, runs the policy engine, optionally collects approvals, and replies with a PermissionGrant or a denial. See TF-0006 "dynamic permission negotiation".

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `request_version` | `"1"` | ✓ | Version of the permission-request schema itself. |
| `id` | string (minLength: 1) | ✓ | Stable identifier for this request; copied into the matching PermissionGrant. |
| `agent` | [`ActorId`](./_common.md#actorid) | ✓ | Agent actor making the request. |
| `instance` | [`InstanceId`](./_common.md#instanceid) | · | Specific running instance of the agent. |
| `human` | [`ActorId`](./_common.md#actorid) | · | Human principal the agent is acting on behalf of. |
| `model` | string (minLength: 1) | · | Provider-prefixed model identifier (e.g. anthropic:claude-opus-4-7). |
| `tool` | string (minLength: 1) | · | Tool the agent intends to invoke once the permission is granted. |
| `action` | [`ActionName`](./_common.md#actionname) | ✓ | Dotted action name being requested. |
| `target` | string (minLength: 1) | · | Target the action will operate on (file path, record id, URL, ...). |
| `risk` | [`RiskClass`](./_common.md#riskclass) | · | Agent's self-declared risk class for the action. |
| `danger_tags` | array of [`DangerTag`](./_common.md#dangertag) | · | Danger tags the agent already knows apply. |
| `duration_seconds` | integer (≥ 1) | · | Maximum lifetime the agent is asking for; the daemon may cap it. |
| `reason` | string (minLength: 1) | ✓ | Human-readable rationale visible to approvers. |
| `proof_level_offered` | [`ProofLevel`](./_common.md#prooflevel) | · | Highest proof level the agent can produce if challenged. |
| `requested_at` | [`Timestamp`](./_common.md#timestamp) | ✓ | When the request was created. |
| `context` | object | · | Free-form context the daemon and approvers can use. |

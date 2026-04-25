# TrustForge Permission Grant

> `$id`: `https://trustforge.io/schemas/v0/permission-grant.schema.json`

Daemon-signed reply to a PermissionRequest. When granted, the bearer can present this to the RpcServer to authorize the requested action within the listed constraints; when denied, audits still see the reason and the policy decision the engine produced.

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `grant_version` | `"1"` | ✓ | Version of the permission-grant schema itself. |
| `request_id` | string (minLength: 1) | ✓ | Identifier of the PermissionRequest this grant resolves. |
| `decision` | `"allow"` \| `"deny"` \| `"approval-required"` | ✓ | Outcome of the request. |
| `capability` | [`Capability`](./_common.md#capability) | · | Capability the bearer may exercise. Present only when decision=allow. |
| `constraints` | array of [`Constraint`](./_common.md#constraint) | · | Constraints attached to the grant (time window, target glob, quorum, ...). |
| `policy_decision` | [`policy-decision`](./policy-decision.md) | · | PolicyDecision the engine produced while evaluating the request. |
| `ceremony_id` | string | · | Approval ceremony that resolved the request, if any. |
| `denial_reason` | string | · | Free-text denial reason (decision=deny / approval-required). |
| `valid_from` | [`Timestamp`](./_common.md#timestamp) | · |  |
| `valid_until` | [`Timestamp`](./_common.md#timestamp) | · |  |
| `issued_at` | [`Timestamp`](./_common.md#timestamp) | ✓ |  |
| `issuer` | [`ActorId`](./_common.md#actorid) | ✓ | Daemon actor that signed this grant. |
| `signature` | [`SignatureEnvelope`](./_common.md#signatureenvelope) | ✓ | Ed25519 signature over the canonical form of this grant. |

# TrustForge Revocation Object

> Defined by TF-0004.
> `$id`: `https://trustforge.io/schemas/v0/revocation.schema.json`

Revocation record that invalidates a capability, actor, delegation, or instance (TF-0004).

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `revocation_version` | `"1"` | ✓ | Version of the revocation schema itself. |
| `id` | string (minLength: 1) | ✓ | Stable identifier for this revocation. |
| `target_id` | string (minLength: 1) | ✓ | Identifier of the object being revoked (depends on target_kind). |
| `target_kind` | `"capability"` \| `"actor"` \| `"delegation"` \| `"instance"` | ✓ | Kind of object being revoked. |
| `effective_at` | [`Timestamp`](./_common.md#timestamp) | ✓ | When the revocation becomes effective. |
| `reason` | string | · | Human-readable reason for the revocation. |
| `reinstatement_possible` | boolean | · | Whether a future identity or grant could reuse this target_id. |
| `issuer` | [`ActorId`](./_common.md#actorid) | ✓ | Actor issuing this revocation. |
| `signature` | [`SignatureEnvelope`](./_common.md#signatureenvelope) | ✓ | Signature envelope over the canonical form of this revocation (not verified in the foundation phase). |

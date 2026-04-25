# TrustForge Session Migration

> `$id`: `https://trustforge.io/schemas/v0/session-migration.schema.json`

Signed record describing a TrustForge session being moved between transports while preserving session_id, generation, and trust continuity (TF-0003 "session migration").

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `migration_version` | `"1"` | ✓ | Version of the session-migration schema itself. |
| `session_id` | string (minLength: 1) | ✓ | The session id that survives the migration. Must equal the pre-migration session id. |
| `generation` | integer (≥ 0) | ✓ | Migration counter. Increases by 1 per migration; lets receivers detect replays. |
| `from_binding` | [`transport-binding`](./transport-binding.md) | ✓ |  |
| `to_binding` | [`transport-binding`](./transport-binding.md) | ✓ |  |
| `preserved_capabilities` | array of [`Capability`](./_common.md#capability) | · | Capabilities the migration explicitly preserves. |
| `rotated_keys` | boolean | · | Whether the session keys were rotated as part of the migration. |
| `migrated_at` | [`Timestamp`](./_common.md#timestamp) | ✓ |  |
| `reason` | string | · | Human-readable reason (transport upgrade, network change, peer reconnect, ...). |
| `signer` | [`ActorId`](./_common.md#actorid) | ✓ |  |
| `signature` | [`SignatureEnvelope`](./_common.md#signatureenvelope) | ✓ |  |

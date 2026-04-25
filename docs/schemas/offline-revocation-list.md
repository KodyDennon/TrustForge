# TrustForge Offline Revocation List

> `$id`: `https://trustforge.io/schemas/v0/offline-revocation-list.schema.json`

Bounded-validity revocation list distributed for offline / constrained deployments (TF-0011 "offline revocation limits"). Verifiers refuse to honour packets whose authority appears in this list, but the list itself expires so a stale list cannot be used forever.

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `list_version` | `"1"` | ✓ | Version of the offline-revocation-list schema. |
| `trust_domain` | [`TrustDomain`](./_common.md#trustdomain) | ✓ |  |
| `issued_at` | [`Timestamp`](./_common.md#timestamp) | ✓ |  |
| `valid_until` | [`Timestamp`](./_common.md#timestamp) | ✓ |  |
| `issuer` | [`ActorId`](./_common.md#actorid) | ✓ |  |
| `revoked` | array of `RevokedEntry` | ✓ | Entries listed in this offline revocation list. |
| `signature` | [`SignatureEnvelope`](./_common.md#signatureenvelope) | ✓ |  |

## `$defs`

### `RevokedEntry`


| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `kind` | `"actor"` \| `"instance"` \| `"capability"` \| `"delegation"` \| `"key"` | ✓ | What is being revoked. |
| `id` | string (minLength: 1) | ✓ | Stable identifier of the revoked object. |
| `reason` | string | · | Free-text reason. |
| `revoked_at` | [`Timestamp`](./_common.md#timestamp) | · |  |

# TrustForge Actor Identity Document

> Defined by TF-0002.
> `$id`: `https://trustforge.io/schemas/v0/actor-identity.schema.json`

Identity document that binds an actor URI to public keys, authority roots, and validity (TF-0002).

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `identity_version` | `"1"` | ✓ | Version of the actor-identity document schema itself. |
| `actor_id` | [`ActorId`](./_common.md#actorid) | ✓ | Canonical actor URI this document identifies. |
| `actor_type` | [`ActorType`](./_common.md#actortype) | ✓ | Actor-type discriminator; must match the type embedded in actor_id. |
| `instance_id` | [`InstanceId`](./_common.md#instanceid) | · | Optional instance URI when this document binds to a specific instance. |
| `public_keys` | array of `PublicKey` (minItems: 1) | ✓ | Public keys associated with this actor. |
| `trust_levels` | array of [`TrustLevel`](./_common.md#trustlevel) (minItems: 1) | ✓ | Trust levels currently attributed to this actor. |
| `authority_roots` | array of `AuthorityRoot` (minItems: 1) | ✓ | Authority roots that vouch for this identity. |
| `attestations` | array of object | · | Opaque third-party attestations strengthening this identity. |
| `valid_from` | [`Timestamp`](./_common.md#timestamp) | ✓ | When this identity document becomes valid. |
| `valid_until` | [`Timestamp`](./_common.md#timestamp) | · | When this identity document stops being valid. |
| `revocation_ref` | [`HashRef`](./_common.md#hashref) | · | Hash reference to a revocation object, if this identity is revoked. |
| `signature` | [`SignatureEnvelope`](./_common.md#signatureenvelope) | · | Signature envelope over the canonical form of this document (not verified in the foundation phase). |

## `$defs`

### `AuthorityRoot`

Root of authority that vouches for this identity.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `kind` | `"owner"` \| `"organization"` \| `"manufacturer"` \| `"hardware-key"` \| `"federation"` \| `"compliance-issuer"` \| `"local-emergency"` \| `"transparency-anchor"` \| `"trust-domain"` | ✓ | Category of authority root. |
| `id` | string (minLength: 1) | ✓ | Identifier for this authority root. |

### `PublicKey`

A public-key entry for this actor.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `key_id` | string (minLength: 1) | ✓ | Stable identifier for this key within the actor. |
| `algorithm` | [`AlgorithmId`](./_common.md#algorithmid) | ✓ | Algorithm this key is used with. |
| `public_key` | string (minLength: 1) | ✓ | Base64-encoded public-key bytes. |
| `purpose` | `"signing"` \| `"kem"` \| `"attestation"` | ✓ | What this key is used for. |
| `valid_from` | [`Timestamp`](./_common.md#timestamp) | · | When this key becomes valid. |
| `valid_until` | [`Timestamp`](./_common.md#timestamp) | · | When this key stops being valid. |

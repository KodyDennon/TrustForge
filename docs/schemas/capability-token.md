# TrustForge Capability Token

> Defined by TF-0004.
> `$id`: `https://trustforge.io/schemas/v0/capability-token.schema.json`

Serialized capability grant carried across actors (TF-0004).

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `token_version` | `"1"` | ✓ | Version of the capability-token schema itself. |
| `id` | string (minLength: 1) | ✓ | Stable token identifier, usable by revocations. |
| `issuer` | [`ActorId`](./_common.md#actorid) | ✓ | Actor that issued the grant. |
| `subject` | [`ActorId`](./_common.md#actorid) | ✓ | Actor the grant is issued to. |
| `capability` | [`Capability`](./_common.md#capability) | ✓ | Granted capability. |
| `constraints` | array of [`Constraint`](./_common.md#constraint) | · | Additional constraints attached on top of those inside `capability`. |
| `chain` | array of [`DelegationLink`](./_common.md#delegationlink) | · | Delegation chain leading to this grant, root at index 0. |
| `issued_at` | [`Timestamp`](./_common.md#timestamp) | ✓ | When the token was issued. |
| `expires_at` | [`Timestamp`](./_common.md#timestamp) | · | When the token expires. |
| `proof_ref` | [`HashRef`](./_common.md#hashref) | · | Optional hash reference to a proof event recording issuance. |
| `signature` | [`SignatureEnvelope`](./_common.md#signatureenvelope) | ✓ | Signature envelope over the canonical form of this token (not verified in the foundation phase). |

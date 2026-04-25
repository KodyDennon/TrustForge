# TrustForge Federation Attestation

> `$id`: `https://trustforge.io/schemas/v0/federation-attestation.schema.json`

Cross-trust-domain attestation: domain A signs a statement asserting that domain B's identity (or a specific actor in B) is recognized within A's trust fabric, optionally bounded by capability scope and time. Used by SPIFFE federated trust bundles, business-partner trust links, and sovereignty federations (TF-0002 "federated" identity mode).

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `attestation_version` | `"1"` | ✓ | Version of the federation-attestation schema. |
| `attestation_id` | string (minLength: 1) | ✓ | Stable identifier for this attestation; used for revocation lookups. |
| `issuer_domain` | [`TrustDomain`](./_common.md#trustdomain) | ✓ | Domain making the assertion. |
| `subject_domain` | [`TrustDomain`](./_common.md#trustdomain) | ✓ | Domain being recognized. |
| `subject_actor` | [`ActorId`](./_common.md#actorid) | · | Optional specific actor inside subject_domain. When omitted the attestation covers the whole domain. |
| `scope` | array of [`ActionName`](./_common.md#actionname) | · | Optional list of action names this attestation permits cross-domain. Empty means "recognize identity only" (no implicit authority). |
| `trust_levels_granted` | array of [`TrustLevel`](./_common.md#trustlevel) | · | Maximum TrustLevel the issuer is willing to extend to subjects under this attestation. |
| `trust_bundle` | array of object (minItems: 1) | ✓ | SPIFFE-style trust bundle: the public keys / certificates of subject_domain that issuer_domain accepts. Each entry is either an X.509 PEM, a SPIFFE JWT-SVID JWK, or an opaque ed25519 public key. |
| `constraints` | array of [`Constraint`](./_common.md#constraint) | · | Optional constraints attached to the federation grant (rate limits, target globs, time windows). |
| `issued_at` | [`Timestamp`](./_common.md#timestamp) | ✓ |  |
| `valid_until` | [`Timestamp`](./_common.md#timestamp) | ✓ |  |
| `issuer` | [`ActorId`](./_common.md#actorid) | ✓ | Authority within issuer_domain that signed this attestation. |
| `signature` | [`SignatureEnvelope`](./_common.md#signatureenvelope) | ✓ |  |

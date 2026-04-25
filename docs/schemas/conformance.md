# TrustForge Conformance Claim

> Defined by TF-0010.
> `$id`: `https://trustforge.io/schemas/v0/conformance.schema.json`

Manifest describing which TrustForge profiles a deployment claims to implement (TF-0010). Distinct from the repo's conformance/ test-harness directory.

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `conformance_version` | `"1"` | ✓ | Version of the conformance manifest schema itself. |
| `claimed_profiles` | array of string (pattern: `^tf-[a-z0-9-]+$`) (minItems: 1) | ✓ | Profile identifiers this deployment claims to conform to. |
| `extensions` | object | · | Optional profile-specific extensions this deployment supports. |
| `claimant` | [`ActorId`](./_common.md#actorid) | · | Actor publishing this conformance claim. |
| `as_of` | [`Timestamp`](./_common.md#timestamp) | · | When this claim is made. |
| `notes` | string | · | Free-form notes qualifying the claim. |

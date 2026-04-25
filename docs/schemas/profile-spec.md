# TrustForge Profile Specification

> `$id`: `https://trustforge.io/schemas/v0/profile-spec.schema.json`

Declarative profile specification (TF-0010 conformance label + TF-0001 'profiles control complexity'). A profile lists the MUST and SHOULD features a deployment claiming the label has to satisfy. The runtime FeatureGate consults this so daemons can refuse to start when a claimed profile demands a feature that isn't enabled.

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `profile_version` | `"1"` | ✓ | Version of the profile-spec schema. |
| `profile_id` | string (pattern: `^tf-[a-z][a-z0-9-]*-compatible$`) | ✓ | Conformance-label identifier, e.g. tf-home-compatible. |
| `label` | string (minLength: 1) | ✓ | Human-readable profile label. |
| `description` | string | · | Free-text description of when this profile applies. |
| `must` | array of `Feature` (minItems: 1) | ✓ | Mandatory features. A daemon claiming this profile MUST satisfy every entry. |
| `should` | array of `Feature` | ✓ | Recommended features. |
| `must_not` | array of `Feature` | · | Features the profile forbids (e.g. constrained profile MUST NOT enable WebSocket-only listener). |
| `min_enforcement_level` | `"E0"` \| `"E1"` \| `"E2"` \| `"E3"` \| `"E4"` \| `"E5"` | · | Minimum EnforcementLevel the daemon must run at when claiming this profile. |
| `min_proof_level` | [`ProofLevel`](./_common.md#prooflevel) | · | Minimum proof level for actions emitted under this profile. |
| `required_bridges` | array of string (minLength: 1) | · | Bridge kinds the profile requires (e.g. ['spiffe', 'webauthn']). |
| `required_anchors` | array of `"rfc6962"` \| `"sigstore"` \| `"rfc3161"` \| `"memory"` \| `"custom"` | · | Transparency anchor kinds the profile requires. |

## `$defs`

### `Feature`


| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `id` | string (pattern: `^[a-z][a-z0-9.-]*$`) | ✓ | Stable feature identifier the FeatureGate exposes (e.g. policy-engine, transparency-anchor.rfc6962). |
| `description` | string | · | Human-readable description. |
| `spec_ref` | string | · | TF-XXXX or DECISIONS.md reference. |

# TrustForge Evidence Bundle

> `$id`: `https://trustforge.io/schemas/v0/evidence-bundle.schema.json`

Compliance / legal evidence bundle (TF-0012). Captures who acted, what authority they had, what policy allowed/denied the action, what approval was given, whether quorum was met, what proof was generated, when it happened, and whether the event chain is tamper-evident.

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `evidence_version` | `"1"` | ✓ | Version of the evidence-bundle schema. |
| `bundle_id` | string (minLength: 1) | ✓ | Stable identifier for this evidence bundle. |
| `trust_domain` | [`TrustDomain`](./_common.md#trustdomain) | ✓ |  |
| `incident` | object | ✓ | Incident the bundle is collecting evidence for. |
| `actors` | array of [`ActorId`](./_common.md#actorid) | · | Distinct actors involved in this incident. |
| `events` | array of [`proof-event`](./proof-event.md) (minItems: 1) | ✓ | Proof events that constitute the audit trail. Order is the original hash-chain order. |
| `policy_decisions` | array of [`policy-decision`](./policy-decision.md) | ✓ | Policy decisions consulted while the incident unfolded. |
| `approvals` | array of [`approval-response`](./approval-response.md) | ✓ | Approval responses captured during the incident. |
| `ceremonies` | array of [`approval-ceremony`](./approval-ceremony.md) | · | Ceremony records for each approval (so audits can see how each approval was collected). |
| `quorum_outcomes` | array of object | · | Quorum outcomes for any quorum-bound approval that resolved during the incident. |
| `anchors` | array of object | · | Transparency-log / RFC 3161 anchors that strengthen this evidence. |
| `encrypted_payload` | [`proof-bundle-encrypted`](./proof-bundle-encrypted.md) | · | Optional L4 sealed evidence — the events array may be empty if the payload is sealed. |
| `level` | `"L0"` \| `"L1"` \| `"L2"` \| `"L3"` \| `"L4"` \| `"L5"` | · | Highest proof level any single event in this bundle was emitted at. |
| `issued_at` | [`Timestamp`](./_common.md#timestamp) | ✓ |  |
| `issuer` | [`ActorId`](./_common.md#actorid) | ✓ |  |
| `signature` | [`SignatureEnvelope`](./_common.md#signatureenvelope) | ✓ |  |

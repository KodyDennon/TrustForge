# TrustForge Approval Response

> `$id`: `https://trustforge.io/schemas/v0/approval-response.schema.json`

A signed response to an ApprovalRequest.

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `response_version` | `"1"` | ✓ | Version of the approval-response schema itself. |
| `request_id` | string (minLength: 1) | ✓ | Identifier of the ApprovalRequest this responds to. |
| `decision` | `"approve"` \| `"deny"` | ✓ | The human's decision. |
| `responder` | [`ActorId`](./_common.md#actorid) | ✓ | Actor that signed this response. |
| `note` | string | · | Optional free-text note from the responder. |
| `signed_at` | [`Timestamp`](./_common.md#timestamp) | ✓ | When the response was signed. |
| `signature` | [`SignatureEnvelope`](./_common.md#signatureenvelope) | ✓ | Signature envelope over the canonical form of this response with signature.signature cleared. |

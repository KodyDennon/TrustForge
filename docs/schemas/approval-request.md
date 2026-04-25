# TrustForge Approval Request

> `$id`: `https://trustforge.io/schemas/v0/approval-request.schema.json`

A pending approval request raised by the daemon when a guarded action requires explicit human approval.

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `request_version` | `"1"` | ✓ | Version of the approval-request schema itself. |
| `id` | string (minLength: 1) | ✓ | Stable identifier for this pending request. |
| `actor` | [`ActorId`](./_common.md#actorid) | ✓ | Actor requesting the action. |
| `action` | [`ActionName`](./_common.md#actionname) | ✓ | Action name the actor is attempting. |
| `target` | string | · | Optional target (path, URL, etc.) the action would affect. |
| `danger_tags` | array of [`DangerTag`](./_common.md#dangertag) | · | Danger categories the guard surfaced for this request. |
| `reason` | string (minLength: 1) | ✓ | Human-readable explanation of why approval is needed. |
| `created_at` | [`Timestamp`](./_common.md#timestamp) | ✓ | When the request was enqueued. |
| `expires_at` | [`Timestamp`](./_common.md#timestamp) | · | When the request will be auto-denied. |

# TrustForge Proof Event

> Defined by TF-0005.
> `$id`: `https://trustforge.io/schemas/v0/proof-event.schema.json`

Signed record of an important event (TF-0005). Hash-chain verification lives in Phase 2.

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `event_version` | `"1"` | ✓ | Version of the proof-event schema itself. |
| `id` | string (minLength: 1) | ✓ | Stable event identifier. |
| `type` | string (pattern: `^[a-z][a-z0-9._-]*$`) | ✓ | Dotted event-type identifier, e.g. session.established, action.approved. |
| `actor_id` | [`ActorId`](./_common.md#actorid) | ✓ | Actor that produced the event. |
| `instance_id` | [`InstanceId`](./_common.md#instanceid) | · | Specific actor instance that produced the event. |
| `session_id` | string (minLength: 1) | · | Session identifier this event belongs to. |
| `timestamp` | [`Timestamp`](./_common.md#timestamp) | ✓ | When the event occurred. |
| `level` | [`ProofLevel`](./_common.md#prooflevel) | ✓ | Proof level at which this event was emitted. |
| `subject_ref` | string (minLength: 1) | · | Reference to the object this event is about (capability ID, file hash, etc.). |
| `payload_hash` | [`HashRef`](./_common.md#hashref) | · | Hash of the event's associated payload. |
| `parent_hash` | [`HashRef`](./_common.md#hashref) | · | Hash of the immediately preceding event in the hash-chain. |
| `context` | object | · | Free-form context object carried with the event. |
| `provenance` | object | · | Chain of responsibility for this event: who/what authorised, requested, and executed the action. TF-0006 "chain of responsibility". |
| `signature` | [`SignatureEnvelope`](./_common.md#signatureenvelope) | ✓ | Signature envelope over the canonical form of this event (not verified in the foundation phase). |

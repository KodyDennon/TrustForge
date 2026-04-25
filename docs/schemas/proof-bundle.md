# TrustForge Proof Bundle

> Defined by TF-0005.
> `$id`: `https://trustforge.io/schemas/v0/proof-bundle.schema.json`

JSON representation of a .tfproof bundle (TF-0005). Binary framing is defined in Phase 2.

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `bundle_version` | `"1"` | ✓ | Version of the proof-bundle schema itself. |
| `events` | array of [`proof-event`](./proof-event.md) (minItems: 1) | ✓ | Proof events carried by this bundle, in their hash-chain order. |
| `merkle_root` | [`HashRef`](./_common.md#hashref) | · | Merkle root over the events, if computed. |
| `chain_hash` | [`HashRef`](./_common.md#hashref) | · | Hash over the event sequence as a linear hash-chain. |
| `transparency_anchor` | object | · | Anchoring metadata if this bundle was submitted to a transparency log. |
| `signature` | [`SignatureEnvelope`](./_common.md#signatureenvelope) | ✓ | Signature envelope over the canonical form of this bundle (not verified in the foundation phase). |

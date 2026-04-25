# TrustForge Packet Bundle

> `$id`: `https://trustforge.io/schemas/v0/packet-bundle.schema.json`

A group of related packets (e.g. emergency packet + post-event quorum review) shipped together as a unit, for store-and-forward / air-gap workflows.

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `bundle_version` | `"1"` | ✓ | Version of the packet-bundle schema itself. |
| `bundle_id` | string (minLength: 1) | ✓ | Stable bundle identifier. |
| `label` | string | · | Human-readable bundle label. |
| `packets` | array of [`packet`](./packet.md) (minItems: 1) | ✓ | Packets carried by this bundle. |
| `transport_hint` | `"usb"` \| `"qr-code"` \| `"serial"` \| `"lora"` \| `"file-drop"` \| `"manual"` | · | How the bundle is being moved. |
| `created_at` | [`Timestamp`](./_common.md#timestamp) | · |  |
| `signature` | [`SignatureEnvelope`](./_common.md#signatureenvelope) | ✓ |  |

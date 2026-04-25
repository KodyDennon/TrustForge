# TrustForge Packet Fragment

> `$id`: `https://trustforge.io/schemas/v0/packet-fragment.schema.json`

Fragmentation header attached to a Packet when its payload is too large for the underlying transport (LoRa MTU, BLE characteristic size, etc.). Fragments are reassembled by their destination using `fragment_id` + `index` + `count`.

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `fragment_id` | string (minLength: 1) | ✓ | Stable identifier shared by every fragment that belongs to the same logical packet. |
| `index` | integer (≥ 0) | ✓ | Zero-based index of this fragment within the sequence. |
| `count` | integer (≥ 1) | ✓ | Total number of fragments in the sequence. |
| `total_payload_bytes` | integer (≥ 1) | ✓ | Size of the reassembled payload in bytes; reassembly fails if the assembled output differs. |
| `payload_digest` | [`HashRef`](./_common.md#hashref) | ✓ | Hash of the reassembled canonical payload; consumers MUST verify this after reassembly. |

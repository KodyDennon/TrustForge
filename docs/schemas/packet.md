# TrustForge Packet

> `$id`: `https://trustforge.io/schemas/v0/packet.schema.json`

Standalone signed/encrypted object that may be delivered offline, relayed, stored, or transferred and verified later. Implements TF-0011 packet mode: packet priority, expiration, route constraints, fragmentation, emergency packets.

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `packet_version` | `"1"` | ✓ | Version of the packet schema itself. |
| `packet_id` | string (minLength: 1) | ✓ | Stable packet identifier; used for de-duplication, fragmentation reassembly, and audit lookup. |
| `source` | [`ActorId`](./_common.md#actorid) | ✓ | Originating actor. |
| `destination` | [`ActorId`](./_common.md#actorid) | ✓ | Final destination actor. |
| `priority` | `"P0"` \| `"P1"` \| `"P2"` \| `"P3"` \| `"P4"` \| `"P5"` | ✓ | Packet priority class. P0 is reserved for emergency / break-glass and is policy-controlled. |
| `emergency` | boolean | · | When true, the packet is invoking break-glass emergency authority. Must be scoped, logged, and reviewable per TF-0011. |
| `created_at` | [`Timestamp`](./_common.md#timestamp) | ✓ |  |
| `expires_at` | [`Timestamp`](./_common.md#timestamp) | · |  |
| `ttl_hops` | integer (≥ 0) | · | Maximum number of relay hops the packet may traverse. |
| `route_constraints` | array of string (minLength: 1) | · | Optional ordered/unordered hints ("only-trusted-relays", "avoid:internet", ...). |
| `encoding` | `"json"` \| `"cbor"` | · | Wire encoding of the payload bytes. |
| `compression` | `"none"` \| `"deflate"` | · | Optional payload compression. |
| `payload` | string (minLength: 1) | ✓ | Base64-encoded canonical payload bytes (the body the source signed). |
| `session_ref` | string | · | Optional session identifier this packet relates to. |
| `fragment` | [`packet-fragment`](./packet-fragment.md) | · | Set when the packet is itself a fragment of a larger packet. |
| `signature` | [`SignatureEnvelope`](./_common.md#signatureenvelope) | ✓ |  |

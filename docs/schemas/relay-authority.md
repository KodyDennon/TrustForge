# TrustForge Relay Authority

> `$id`: `https://trustforge.io/schemas/v0/relay-authority.schema.json`

Encodes the distinction between forwarding authority and action authority. A relay can carry signed/encrypted TrustForge packets without ever being able to decrypt, authorize, or execute them. The authority record is what the daemon checks before letting a relay forward packets on its behalf, and the proof event a relay emits when it forwards is bound to this record.

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `relay_authority_version` | `"1"` | ✓ | Version of the relay-authority schema itself. |
| `relay` | [`ActorId`](./_common.md#actorid) | ✓ | Relay actor URI (must be of type `relay`). |
| `trust_domain` | [`TrustDomain`](./_common.md#trustdomain) | ✓ |  |
| `kinds` | array of `"forward-only"` \| `"store-and-forward"` \| `"fragment-reassemble"` \| `"priority-queue"` \| `"emergency-route"` \| `"lora-relay"` \| `"matrix-relay"` \| `"internet-relay"` (minItems: 1) | ✓ | What kinds of relaying this authority permits. Forwarding authority does NOT include action authority — relays can never decrypt or execute the packets they carry. |
| `max_hop_count` | integer (≥ 1) | · | Maximum number of hops a packet can traverse via this relay. |
| `rate_limit_per_minute` | integer (≥ 1) | · | Caller-observed rate limit; relays exceeding this lose authority. |
| `valid_from` | [`Timestamp`](./_common.md#timestamp) | ✓ |  |
| `valid_until` | [`Timestamp`](./_common.md#timestamp) | · |  |
| `issuer` | [`ActorId`](./_common.md#actorid) | ✓ | Trust-domain authority that issued this relay grant. |
| `constraints` | array of [`Constraint`](./_common.md#constraint) | · | Additional constraints (time window, target glob, ...). |
| `signature` | [`SignatureEnvelope`](./_common.md#signatureenvelope) | ✓ |  |

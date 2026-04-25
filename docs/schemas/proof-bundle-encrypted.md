# TrustForge Encrypted Proof Bundle

> `$id`: `https://trustforge.io/schemas/v0/proof-bundle-encrypted.schema.json`

Encrypted variant of .tfbundle (proof level L4). The plaintext is a canonical proof-bundle.schema.json document; the ciphertext is sealed with a per-bundle ChaCha20-Poly1305 data key and the data key is wrapped to one or more recipient ed25519 keys via X25519+HKDF-SHA256.

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `bundle_version` | `"1"` | ✓ | Version of the encrypted-bundle schema itself. |
| `level` | `"L4"` \| `"L5"` | ✓ | Proof level this bundle was sealed at. |
| `ciphertext` | string (minLength: 1) | ✓ | Base64-encoded ChaCha20-Poly1305 ciphertext + tag over the canonical proof bundle. |
| `nonce` | string (minLength: 1) | ✓ | Base64-encoded 12-byte AEAD nonce used to seal the ciphertext. |
| `wrapped_keys` | array of `WrappedKey` (minItems: 1) | ✓ | Per-recipient wrapped data keys. Each entry binds the bundle to one verifier. |
| `transparency_anchor` | object | · | Optional transparency-log anchor for the ciphertext. |
| `signature` | [`SignatureEnvelope`](./_common.md#signatureenvelope) | ✓ | Ed25519 signature over the canonical encrypted bundle (sans `signature` field). |

## `$defs`

### `WrappedKey`


| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `recipient` | [`ActorId`](./_common.md#actorid) | ✓ | Recipient actor URI. |
| `recipient_key_id` | string | · | Optional key-id of the recipient key used for wrapping. |
| `ephemeral_public` | string (minLength: 1) | ✓ | Base64-encoded X25519 ephemeral public key the sender used. |
| `wrapped` | string (minLength: 1) | ✓ | Base64-encoded ChaCha20-Poly1305 ciphertext + tag wrapping the data key. |
| `wrap_nonce` | string (minLength: 1) | · | Base64-encoded 12-byte nonce used for wrap_key encryption. |

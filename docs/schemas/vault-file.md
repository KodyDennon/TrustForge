# TrustForge Vault File

> `$id`: `https://trustforge.io/schemas/v0/vault-file.schema.json`

Passphrase-encrypted key vault on disk. KDF = Argon2id, cipher = ChaCha20-Poly1305.

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `vault_version` | `"1"` | ✓ | Version of the vault file schema itself. |
| `kdf` | object | ✓ | Key-derivation parameters used to turn the passphrase into the 32-byte wrap key. |
| `cipher` | object | ✓ | AEAD cipher used to seal each entry. |
| `entries` | array of `VaultEntry` | ✓ | Encrypted entries. Each entry's ciphertext decrypts under the wrap key to raw key bytes. |

## `$defs`

### `VaultEntry`

One encrypted entry.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `id` | string (minLength: 1) | ✓ | Stable identifier for this entry within the vault. |
| `purpose` | `"signing"` \| `"kem"` \| `"attestation"` \| `"raw"` | ✓ | What the key is used for. |
| `algorithm` | [`AlgorithmId`](./_common.md#algorithmid) | ✓ | Algorithm this key targets, e.g. ed25519. |
| `nonce` | string (minLength: 1) | ✓ | Base64-encoded 12-byte AEAD nonce. |
| `ciphertext` | string (minLength: 1) | ✓ | Base64-encoded AEAD ciphertext (includes 16-byte tag). |
| `created_at` | [`Timestamp`](./_common.md#timestamp) | ✓ | When this entry was written. |

# TrustForge Plugin Manifest

> `$id`: `https://trustforge.io/schemas/v0/plugin-manifest.schema.json`

Declarative manifest describing a TrustForge plugin. See TF-0008.

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `plugin_version` | `"1"` | ✓ | Version of the plugin-manifest schema itself. |
| `plugin_id` | string (pattern: `^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$`) | ✓ | Reverse-DNS-style plugin identifier, e.g. com.example.my-plugin. |
| `actor_id` | [`ActorId`](./_common.md#actorid) | ✓ | Actor URI the plugin operates as once loaded. Use tf:actor:plugin:... |
| `kind` | `"native"` \| `"wasm"` | ✓ | Plugin runtime kind. |
| `entry` | string (minLength: 1) | ✓ | Path (relative to the manifest) to the plugin entry point — a .js/.ts/.mjs module for native, or a .wasm file for WASM. |
| `identity_pub` | string (minLength: 1) | ✓ | Base64-encoded ed25519 public key that signs this manifest. |
| `signature` | [`SignatureEnvelope`](./_common.md#signatureenvelope) | ✓ | Signature envelope over the canonical form of this manifest with signature.signature cleared. |
| `capabilities` | array of [`Capability`](./_common.md#capability) (minItems: 1) | ✓ | Capabilities the plugin declares it needs. Enforced by the registry + guard. |
| `imports` | array of string (minLength: 1) | · | WASM-only: host functions the plugin is allowed to import. The registry enforces that only these imports are supplied. |
| `proof_profile` | [`ProofLevel`](./_common.md#prooflevel) | · | Optional proof level at which this plugin's actions should be emitted. |
| `description` | string | · | Human-readable description. |

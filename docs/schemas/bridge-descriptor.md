# TrustForge Compatibility Bridge Descriptor

> `$id`: `https://trustforge.io/schemas/v0/bridge-descriptor.schema.json`

Declarative descriptor for a TrustForge compatibility bridge. Concrete bridges implement the TS Bridge interface or the Rust Bridge trait and are registered by BridgeRegistry.

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `bridge_version` | `"1"` | ✓ | Version of the bridge-descriptor schema itself. |
| `bridge_id` | string (pattern: `^[a-z][a-z0-9-]*$`) | ✓ | Stable kebab-case bridge identifier. |
| `kind` | `"spiffe"` \| `"webauthn"` \| `"mcp"` \| `"oauth"` \| `"tls"` | ✓ | Which foreign standard this bridge wires into TrustForge. |
| `trust_domain` | [`TrustDomain`](./_common.md#trustdomain) | ✓ | TrustForge trust domain that accepts input from this bridge. |
| `description` | string | · | Human-readable description of what the bridge accepts and what it emits. |
| `config` | object | · | Kind-specific configuration. Each bridge validates its own config shape at runtime. |
| `capabilities` | array of [`Capability`](./_common.md#capability) | · | Optional capabilities this bridge may claim or issue on behalf of the foreign protocol. |

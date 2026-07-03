# TrustForge Bridges Registry

> `$id`: `https://trustforge.io/schemas/v0/bridges-registry.schema.json`

Per-deployment registry that overrides the default credential-resolver mapping. The daemon reads `.tf/bridges.yaml` once at startup, validates against this schema, and uses `resolveByIssuer` to map an incoming credential's issuer / iss claim / SPIFFE trust domain to a TrustForge bridge entry. When no entry matches, the resolver falls back to the built-in defaults declared in `tools/tf-daemon/src/credential-resolver.ts` (B2).

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `registry_version` | `"1"` | ✓ | Version of the bridges-registry schema itself. |
| `default_profile` | string (pattern: `^tf-[a-z][a-z0-9-]*-compatible$`) | · | Optional conformance profile name applied when an entry omits its own. Purely informational at this layer; the FeatureGate is the authoritative gate. |
| `bridges` | array of `BridgeEntry` | ✓ | Per-issuer bridge entries. The first entry whose `issuer_match` / `iss_pattern` matches an incoming credential wins. |

## `$defs`

### `BridgeEntry`


| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `kind` | `"oauth"` \| `"clerk"` \| `"next-auth"` \| `"better-auth"` \| `"webauthn"` \| `"tls"` \| `"spiffe"` \| `"did"` \| `"gnap"` \| `"mcp"` \| `"matrix"` \| `"webhook"` \| `"grpc"` \| `"service-mesh"` \| `"a2a"` \| `"session-cookie"` \| `"aws"` \| `"gcp"` \| `"azure"` \| `"vault"` \| `"doppler"` | ✓ | Which TrustForge bridge module handles this credential format. |
| `issuer_match` | string (minLength: 1) | · | Exact match against the credential's `iss` claim (OAuth/JWT) or trust-domain authority. Use `iss_pattern` for prefix/suffix matching. |
| `iss_pattern` | string (minLength: 1) | · | Substring match against the credential's `iss` claim. `clerk.dev` matches both `https://api.clerk.dev/...` and `clerk.dev`. |
| `trust_domain` | [`TrustDomain`](./_common.md#trustdomain) | · | Trust domain the resolved actor belongs to. |
| `trust_level` | [`TrustLevel`](./_common.md#trustlevel) | · | Initial TrustForge trust level assigned to actors resolved through this bridge entry. |
| `capability_map` | object | · | Mapping from the credential's native scope/permission to a TrustForge action name. Keys are the native scope (e.g. OAuth `email`); values are TrustForge action names matching the dotted ActionName pattern. |
| `profile` | string (pattern: `^tf-[a-z][a-z0-9-]*-compatible$`) | · | Per-entry conformance profile override. |

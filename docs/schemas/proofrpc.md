# TrustForge ProofRPC Service Descriptor

> `$id`: `https://trustforge.io/schemas/v0/proofrpc.schema.json`

Declarative RPC service definition consumed by tf-schema codegen --target rpc-ts|rpc-rust. See TF-0007.

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `rpc_version` | `"1"` | ✓ | Version of the proofrpc service descriptor schema. |
| `service_id` | string (pattern: `^[A-Z][A-Za-z0-9]*$`) | ✓ | PascalCase service identifier used by generated client and server types. |
| `description` | string | · | Human-readable description of the service. |
| `methods` | array of `Method` (minItems: 1) | ✓ | Methods exposed by this service. |

## `$defs`

### `Method`

One RPC method.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string (pattern: `^[a-z][A-Za-z0-9_]*$`) | ✓ | Method name, camelCase or snake_case, starts with a lowercase letter. |
| `kind` | `"unary"` \| `"server-streaming"` | ✓ | Streaming mode. Unary is one request, one response. Server-streaming is one request, zero or more responses. |
| `description` | string | · | What this method does. |
| `request` | object | ✓ | Inline JSON Schema describing the request body. Must be type:object with properties. |
| `response` | object | ✓ | Inline JSON Schema describing the response body (or stream element for server-streaming). |
| `capability` | [`ActionName`](./_common.md#actionname) | ✓ | Name of the TrustForge capability required to invoke. |
| `risk` | [`RiskClass`](./_common.md#riskclass) | ✓ | Risk class assigned to this method. |
| `proof` | [`ProofLevel`](./_common.md#prooflevel) | · | Proof level at which successful calls are emitted. |
| `approval` | [`ApprovalRequirement`](./_common.md#approvalrequirement) | · | Approval requirement for invocations; defaults to none. |

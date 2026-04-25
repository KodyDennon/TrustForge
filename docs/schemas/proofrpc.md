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
| `kind` | `"unary"` \| `"server-streaming"` \| `"client-streaming"` \| `"bidi-streaming"` \| `"subscribe"` \| `"command-channel"` \| `"bulk-transfer"` \| `"telemetry"` \| `"remote-shell"` \| `"agent-session"` | ✓ | Streaming mode. unary: one request → one response. server-streaming: one request → many. client-streaming: many → one. bidi-streaming: many ↔ many. subscribe: one subscribe → many events with optional ack. command-channel: long-lived control with backpressure. bulk-transfer: chunked binary with content-hashing. telemetry: push-only with priority class. remote-shell: stdin/stdout stream. agent-session: bidi stream that carries the chain of responsibility. |
| `description` | string | · | What this method does. |
| `request` | object | ✓ | Inline JSON Schema describing the request body. Must be type:object with properties. |
| `response` | object | ✓ | Inline JSON Schema describing the response body (or stream element for server-streaming). |
| `capability` | [`ActionName`](./_common.md#actionname) | ✓ | Name of the TrustForge capability required to invoke. |
| `risk` | [`RiskClass`](./_common.md#riskclass) | ✓ | Risk class assigned to this method. |
| `proof` | [`ProofLevel`](./_common.md#prooflevel) | · | Proof level at which successful calls are emitted. |
| `approval` | [`ApprovalRequirement`](./_common.md#approvalrequirement) | · | Approval requirement for invocations; defaults to none. |
| `policy_hooks` | array of string (minLength: 1) | · | Names of policy hooks the daemon must consult before this method runs. |
| `denial` | string | · | Optional human-readable denial reason if the method is forbidden in this trust domain. |
| `streaming_priority` | `"P0"` \| `"P1"` \| `"P2"` \| `"P3"` \| `"P4"` \| `"P5"` | · | Priority class for streaming methods (TF-0011). |
| `conformance_tests` | array of string (minLength: 1) | · | Conformance vector files this method participates in. |

# TrustForge Proof Profile

> Defined by TF-0005.
> `$id`: `https://trustforge.io/schemas/v0/proof-profile.schema.json`

Declarative profile describing which proof events to emit and how (TF-0005).

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `profile_version` | `"1"` | ✓ | Version of the proof-profile manifest schema itself. |
| `trust_domain` | [`TrustDomain`](./_common.md#trustdomain) | ✓ | Trust domain this profile applies to. |
| `default_level` | [`ProofLevel`](./_common.md#prooflevel) | · | Default proof level when an event has none explicitly set. |
| `emit` | array of `EmitRule` (minItems: 1) | ✓ | Event-emission rules, evaluated per emitted event. |
| `redaction_rules` | array of `RedactionRule` | · | Field-level redaction applied before anchoring. |

## `$defs`

### `EmitRule`

Rule describing how a given event type is recorded.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `event_type` | string (minLength: 1) | ✓ | Event type identifier this rule applies to, e.g. session.established. |
| `level` | [`ProofLevel`](./_common.md#prooflevel) | ✓ | Proof level at which this event must be emitted. |
| `anchor` | `"local"` \| `"org"` \| `"federated"` \| `"transparency"` \| `"none"` | ✓ | Where the event is anchored. |
| `retention_days` | integer (≥ 0) | · | Retention period in days (0 = indefinite). |

### `RedactionRule`

Redaction applied to a field before anchoring.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `field` | string (minLength: 1) | ✓ | JSON Pointer into the event payload. |
| `policy` | `"keep"` \| `"hash"` \| `"drop"` | ✓ | How the field is treated. |

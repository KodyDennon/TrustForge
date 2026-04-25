# TrustForge Common Definitions

> Defined by underlies every other schema.
> `$id`: `https://trustforge.io/schemas/v0/_common.schema.json`

Shared $defs referenced by every other TrustForge schema. Has no top-level instance.

## `$defs`

### `ActionName`

Dotted lowercase action identifier, e.g. file.write, shell.exec.

Type: string (pattern: `^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

### `ActorId`

Universal actor URI: tf:actor:<type>:<path>. See TF-0002.

Type: string (pattern: `^tf:actor:(human|agent|device|service|site|organization|relay|plugin|process|tool|model-provider|policy-engine|proof-anchor|emergency-authority):[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]+$`)

### `ActorType`

Canonical actor types from TF-0002.

Enum: `human`, `agent`, `device`, `service`, `site`, `organization`, `relay`, `plugin`, `process`, `tool`, `model-provider`, `policy-engine`, `proof-anchor`, `emergency-authority`

### `AlgorithmId`

Signature or KEM algorithm identifier, e.g. ed25519, ml-dsa-65, p256.

Type: string (minLength: 1)

### `ApprovalRequirement`

Default approval requirement modes.

Enum: `none`, `conditional`, `required`, `quorum`

### `Capability`

Capability grant shape (TF-0004).

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | `ActionName` | ✓ |  |
| `risk` | `RiskClass` | ✓ |  |
| `proof_required` | `ProofLevel` | · |  |
| `approval` | `ApprovalRequirement` | · |  |
| `constraints` | array of `Constraint` | · | Constraints that must all hold for the capability to apply. |
| `single_use` | boolean | · | If true, consumed after one invocation. |
| `delegable` | boolean | · | If true, subject may delegate this capability. |
| `revocable` | boolean | · | If false, revocation is ineffective. |
| `offline_valid` | boolean | · | If true, usable without live authority checks. |
| `expires_at` | `Timestamp` | · |  |

### `Constraint`

Capability/grant constraint, discriminated by `kind`.

Discriminated union:

- `kind: "time_window"`
  - `from`: `Timestamp`
  - `until` *(required)*: `Timestamp`
- `kind: "target"`
  - `patterns` *(required)*: array of string (minLength: 1) (minItems: 1)
- `kind: "quantity"`
  - `max` *(required)*: integer (≥ 1)
  - `unit`: string
- `kind: "rate"`
  - `max_per_window` *(required)*: integer (≥ 1)
  - `window_seconds` *(required)*: integer (≥ 1)
- `kind: "session"`
  - `session_id` *(required)*: string (minLength: 1)
- `kind: "approval"`
  - `approval` *(required)*: `ApprovalRequirement`
- `kind: "quorum"`
  - `quorum` *(required)*: integer (≥ 2)
  - `of` *(required)*: array of `ActorId` (minItems: 2)
- `kind: "device_binding"`
  - `device_actor` *(required)*: `ActorId`

### `DangerTag`

Structured danger categories used by agent-contract and dangerous-actions. AI agents must escalate on destructive / irreversible / financial / security-sensitive tags regardless of the declared approval mode.

Enum: `financial`, `destructive`, `irreversible`, `security-sensitive`, `privacy`, `external-network`, `legal-exposure`, `high-compute`

### `DelegationLink`

One step in a delegation chain (TF-0004).

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `delegator` | `ActorId` | ✓ |  |
| `delegate` | `ActorId` | ✓ |  |
| `capabilities` | array of `Capability` (minItems: 1) | ✓ | Capabilities being delegated at this step. |
| `constraints` | array of `Constraint` | · | Additional constraints imposed at this step. |
| `expires_at` | `Timestamp` | · |  |
| `redelegation` | object | · | Redelegation rules for this step. |
| `proof_ref` | `HashRef` | · |  |

### `EnforcementLevel`

Enforcement levels (see DECISIONS.md).

Enum: `E0`, `E1`, `E2`, `E3`, `E4`, `E5`

### `HashRef`

Algorithm-prefixed lowercase-hex hash.

Type: string (pattern: `^(sha256|sha384|sha512|blake3):[0-9a-f]+$`)

### `InstanceId`

Actor instance URI: tf:instance:<type>:<path>/<instance-path>.

Type: string (pattern: `^tf:instance:(human|agent|device|service|site|organization|relay|plugin|process|tool|model-provider|policy-engine|proof-anchor|emergency-authority):[A-Za-z0-9._~:/?#@!$&'()*+,;=%-]+$`)

### `NegativeCapability`

Explicit denial; overrides overlapping grants.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | `ActionName` | ✓ |  |
| `target` | string | · | Optional target pattern the denial applies to. |
| `reason` | string (minLength: 1) | · | Human-readable denial reason. |
| `overrides` | array of string | · | Grant IDs this negative capability explicitly overrides. |

### `ProofLevel`

Proof levels from TF-0005.

Enum: `L0`, `L1`, `L2`, `L3`, `L4`, `L5`

### `RiskClass`

Risk classes from TF-0004.

Enum: `R0`, `R1`, `R2`, `R3`, `R4`, `R5`

### `SignatureEnvelope`

Opaque signature envelope. No crypto performed in the foundation phase.

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `algorithm` | `AlgorithmId` | ✓ |  |
| `signer` | `ActorId` | ✓ |  |
| `signature` | string (minLength: 1) | ✓ | Base64-encoded signature bytes. Not verified in the foundation phase. |
| `hash_alg` | string | · | Optional hash used before signing, e.g. sha256. |
| `alt_algorithm` | `AlgorithmId` | · |  |
| `alt_signature` | string (minLength: 1) | · | Optional second signature for hybrid post-quantum signing. |

### `Timestamp`

RFC 3339 timestamp with required timezone.

Type: string (pattern: `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$`)

### `TrustDomain`

Trust-domain identifier. DNS-like (e.g. example.com), or local-scoped (e.g. local/home).

Type: string (pattern: `^[A-Za-z0-9](?:[A-Za-z0-9._/-]*[A-Za-z0-9])?$`, minLength: 1)

### `TrustLevel`

Trust levels from TF-0002.

Enum: `T0`, `T1`, `T2`, `T3`, `T4`, `T5`, `T6`, `T7`

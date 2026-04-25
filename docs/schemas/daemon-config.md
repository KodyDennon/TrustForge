# TrustForge Daemon Config

> `$id`: `https://trustforge.io/schemas/v0/daemon-config.schema.json`

Configuration file for a running tf-daemon instance (.tf/daemon.yaml).

## Fields

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `daemon_version` | `"1"` | ✓ | Version of the daemon-config schema itself. |
| `self_actor` | [`ActorId`](./_common.md#actorid) | ✓ | Actor URI the daemon presents during the session handshake. |
| `listen` | object | ✓ | Transport bind settings for the daemon. |
| `vault` | object | ✓ | On-disk vault location. |
| `contract_path` | string (minLength: 1) | ✓ | Path to the agent-contract YAML this daemon enforces. |
| `proof_log_path` | string (minLength: 1) | ✓ | Path to the .tflog file the daemon appends to. |
| `approval_queue` | object | · | Approval-queue tuning. |
| `profile` | string (pattern: `^tf-[a-z][a-z0-9-]*-compatible$`) | · | Conformance profile this daemon claims at startup. The runtime FeatureGate refuses to boot when the profile's MUST entries are not all satisfied. |
| `enforcement_level` | [`EnforcementLevel`](./_common.md#enforcementlevel) | · | Default EnforcementLevel for the daemon's AgentGuard. See DECISIONS.md "Progressive enforcement". |

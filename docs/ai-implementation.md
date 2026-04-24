# AI Implementation Guidance

## Purpose

TrustForge must be AI-implementable by design.

This means AI coding agents should be able to read machine-readable TrustForge manifests, understand what is safe, generate integrations, run tests, and avoid violating security boundaries.

## Required machine-readable files

Recommended files:

```text
.tf/agent-contract.yaml
.tf/threat-model.yaml
.tf/policy.yaml
.tf/actions.yaml
.tf/proof-profile.yaml
.tf/codegen.toml
.tf/conformance.json
```

## AI safety rule

AI agents should request authority explicitly.

They should not silently inherit broad user power.

## Dynamic permission request example

```yaml
request:
  actor: "tf:actor:agent:local/code-helper"
  action: "file.write"
  target: "/src/auth.rs"
  duration: "10m"
  reason: "Implement TrustForge verification hook"
  proof_level: "L2"
```

## Generated code must be conformance-tested

```bash
tf conformance run
tf policy simulate
tf proof verify
tf agent-contract validate
```

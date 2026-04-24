# TF-0006: AI Agent Contract

## Status

Draft.

## Purpose

The Agent Contract is a machine-readable file that makes an TrustForge-enabled codebase legible and safe for AI agents.

## Default path

```text
.tf/agent-contract.yaml
```

## Contract contents

An Agent Contract may define available actions, action schemas, required capabilities, risk classes, proof levels, approval requirements, dangerous operations, forbidden operations, safe integration points, test commands, security boundaries, policy hooks, code generation targets, service endpoints, plugin requirements, threat model references, and conformance requirements.

## Why it exists

AI agents should not have to guess what they are allowed to touch, where dangerous boundaries are, what approval they need, how to generate proof, what tests validate safety, or how to integrate TrustForge correctly.

## Dynamic permission negotiation

Agents may request permissions dynamically.

Requests are evaluated by policy and may be allowed, denied, narrowed, escalated, approval-gated, time-limited, proof-required, delegated, or revoked.

## Chain of responsibility

TrustForge should support proof chains such as:

```text
human -> agent -> agent instance -> model provenance -> tool -> action
```

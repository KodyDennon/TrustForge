# ADR-0001: Initial Architecture Direction

## Status

Accepted as initial direction.

## Context

The project is intended to define a new open-source trust fabric for authentication, secure communication, AI agents, service-to-service RPC, devices, proof logs, and policy-controlled authority.

## Decision

TrustForge will be broad, modular, profile-based, and RFC-style.

It will support hybrid identity, multi-root authority, live and packet modes, ProofWire, ProofRPC, Agent Contracts, proof ledgers, compatibility bridges, plugins, and conformance.

## Consequences

The project is ambitious and must be carefully modularized.

The specification must avoid vague “do everything” language by defining profiles, conformance levels, and clear protocol boundaries.

The reference implementation must not drift from the spec.

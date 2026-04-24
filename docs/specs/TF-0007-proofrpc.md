# TF-0007: ProofRPC

## Status

Draft.

## Purpose

ProofRPC is a first-class TrustForge profile for authenticated, capability-scoped, proof-aware RPC and streaming communication.

## Scope

ProofRPC supports AI-to-site authentication, AI agent to SaaS/tool communication, site-to-site authenticated communication, service-to-service secure RPC, internal backend RPC, device-to-cloud telemetry, browser/client to backend live sessions, backend-to-backend proof-aware message bus, and fast authenticated binary communication.

## Design

ProofRPC is schema-first.

A ProofRPC schema defines service, methods/actions, input types, output types, streaming type, required capabilities, explicit denials, risk class, proof level, approval requirements, policy hooks, generated code targets, and conformance tests.

## Method types

ProofRPC supports unary request/response, server streaming, client streaming, bidirectional streaming, event subscription, command channel, bulk transfer, telemetry stream, remote shell stream, and agent/tool session stream.

## Goal

ProofRPC should make identity, permission, encryption, replay protection, policy, and proof part of RPC itself instead of bolted onto headers.

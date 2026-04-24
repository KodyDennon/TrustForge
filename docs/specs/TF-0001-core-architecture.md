# TF-0001: Core Architecture

## Status

Draft.

## Purpose

This document defines the initial architecture of TrustForge.

## Core layers

1. Actor Identity
2. Actor Instance Identity
3. Trust Domain and Authority Roots
4. Session Protocol
5. Packet Protocol
6. Capability and Denial Model
7. Policy Decision Model
8. Approval Ceremonies
9. Proof Events and Ledgers
10. Compatibility Bridges
11. Plugins and Extension System
12. Conformance Profiles

## Core objects

### Actor

An actor is any entity capable of participating in TrustForge.

Examples: human, AI agent, service, device, relay, plugin, organization, process, tool, model-serving system, policy engine, proof anchor.

### Actor Instance

An actor instance is a concrete active instance of an actor.

Examples: a specific running AI agent process, service replica, browser session, device session, plugin instance, or containerized workload.

### Trust Domain

A trust domain is a context in which authority is interpreted.

Examples: a home, company, vessel, device fleet, federation, or public TrustForge network.

### Session

A live trust relationship between actors.

Sessions support authentication, rekeying, ratcheting, continuous authorization, migration, transport binding, and proof emission.

### Packet

A standalone signed/encrypted object that may be delivered offline, relayed, stored, transferred, or verified later.

### Capability

A permission to perform an action under constraints.

### Negative Capability

An explicit denial that overrides grants.

### Policy Decision

A structured result determining whether an action is allowed, denied, escalated, approved, logged, or constrained.

### Proof Event

A signed record of an important event.

## Major architecture decisions

TrustForge uses hybrid identity, multi-root authority, composable trust, live and packet communication, first-class AI integration, first-class proof logs, formal compatibility bridges, and formal conformance profiles.

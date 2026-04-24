# TF-0003: ProofWire Transport

## Status

Draft.

## Purpose

ProofWire is the TrustForge-native communication mode.

It supports authenticated live sessions, offline packets, relay/mesh forwarding, constrained transport, and session migration.

## Modes

### Carried Mode

TrustForge frames carried over existing transports: WebSocket, QUIC, TCP, Unix socket, local IPC, WebTransport, BLE, serial, LoRa/radio, MCP transport, and message queues.

### Native Mode

ProofWire-native binary transport.

### Packet Mode

Standalone TrustForge packets for offline and delayed delivery.

## Core requirements

ProofWire supports binary frames, mutual actor authentication, session lineage, transport binding, session migration, rekeying, ratcheting, priority classes, relay/mesh forwarding, offline proof packets, fragmentation/reassembly, constrained profiles, proof event transmission, end-to-end encryption, endpoint signatures, anti-replay protections, packet expiration, delivery receipts, and optional proof-of-forwarding.

## Relay model

Relays are first-class actors.

Relays may forward traffic but cannot decrypt payloads or authorize actions unless separately authorized.

## Priority classes

Initial priority classes:

- P0 emergency / distress / safety-critical
- P1 identity, revocation, approval, security control
- P2 live command/control
- P3 normal messages/events
- P4 telemetry/background sync
- P5 bulk transfer/proof log backfill

## Session migration

Sessions may migrate across transports.

Migration must preserve session lineage and update transport binding.

## Constrained profile

The constrained profile supports LoRa, serial, BLE, field radio, embedded devices, and low-bandwidth networks.

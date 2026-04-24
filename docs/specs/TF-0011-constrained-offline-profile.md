# TF-0011: Constrained / LoRa / Offline Profile

## Status

Draft.

## Targets

- LoRa
- serial
- BLE
- field radio
- marine telemetry
- embedded devices
- no_std devices
- low-power sensors
- disaster networks
- offline relays
- air-gapped transfer

## Requirements

The constrained profile supports tiny packet mode, fragmentation/reassembly, compact binary encoding, optional compression, store-and-forward, packet expiration, replay protection, route constraints, packet priority, emergency packets, delayed proof sync, offline revocation limits, and proof bundles.

## Priority

Packet priority is core and policy-controlled.

## Emergency

Emergency packets may use P0 priority and break-glass authority, but must be scoped, logged, and reviewable.

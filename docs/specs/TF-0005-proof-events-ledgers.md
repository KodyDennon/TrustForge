# TF-0005: Proof Events and Ledgers

## Status

Draft.

## Proof event

A proof event is a signed record of an important event.

Potential proof events include actor connected, session established, capability granted, capability denied, AI proposed action, human approved action, quorum approved action, policy denied action, tool executed action, message delivered, file changed, command run, device config updated, firmware update accepted, emergency authority invoked, revocation issued, and proof anchored.

## Proof levels

Initial proof levels:

- L0 no proof
- L1 session proof
- L2 action proof
- L3 payload hash proof
- L4 encrypted evidence bundle
- L5 compliance-grade notarized proof

## Native formats

Native formats:

- `.tfproof`
- `.tflog`
- `.tfbundle`

## Ledger modes

TrustForge supports local append-only logs, organization proof servers, federated proof exchange, public transparency logs, timestamp authority anchoring, optional blockchain anchoring, and offline proof bundles.

## Blockchain-like properties

TrustForge uses useful proof-chain properties without requiring blockchain infrastructure.

Useful properties include signed events, hash-linked logs, Merkle roots, transparency anchoring, and distributed verification.

Not required: coins, mining, proof-of-work, or global consensus for every action.

## Compliance evidence

TrustForge is compliance/legal-evidence aware but does not claim automatic compliance.

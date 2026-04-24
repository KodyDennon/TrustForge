# TF-0009: Compatibility Bridges

## Status

Draft.

## Principle

TrustForge should bridge and unify existing systems rather than pretending they do not exist.

## Initial bridge specs

- TrustForge-WebAuthn Bridge
- TrustForge-SPIFFE Bridge
- TrustForge-OAuth Bridge
- TrustForge-GNAP Bridge
- TrustForge-MCP Bridge
- TrustForge-A2A Bridge
- TrustForge-Matrix Bridge
- TrustForge-TLS Bridge
- TrustForge-DID Bridge
- TrustForge-Webhook Bridge
- TrustForge-gRPC Bridge
- TrustForge-Service-Mesh Bridge

## Example mappings

WebAuthn credential -> human proof input.

SPIFFE SVID -> workload identity proof.

OAuth/GNAP token -> delegated grant input.

DID document -> portable identity document.

mTLS certificate -> transport or service identity proof.

MCP tool call -> TrustForge action.

A2A agent card -> actor metadata.

Matrix event -> message/proof carrier.

Webhook signature -> TrustForge proof/capability wrapper.

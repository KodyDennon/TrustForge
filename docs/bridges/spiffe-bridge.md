# SPIFFE Bridge

## Status

Draft.

## Purpose

Project SPIFFE / SPIRE identity (SVIDs) into TrustForge so workload-based
deployments can stay on their existing identity backbone while gaining
TrustForge proof events, capability scoping, and revocation. The bridge
does not replace SPIFFE — TrustForge consumes SVIDs as a foreign trust
root, just as it consumes WebAuthn or DID identifiers elsewhere.

The reference implementations live at:

- TS: `tools/tf-types-ts/src/core/bridge-spiffe.ts`
- Rust: `crates/tf-types/src/bridge_spiffe.rs`

## Source identity object

The bridge accepts a SPIFFE SVID in three forms:

1. **X.509 SVID** — an `spiffe://<trust_domain>/<workload>` URI carried in
   a peer X.509 certificate's SAN extension.
2. **JWT SVID** — a signed JWT whose `sub` claim is a SPIFFE ID.
3. **Federation bundle** — a SPIFFE trust bundle describing the public
   keys for a foreign trust domain. Federations expand the set of trust
   domains TrustForge will accept SVIDs from.

## Actor mapping

A SPIFFE ID `spiffe://example.com/payments` projects to:

```
tf:actor:service:example.com/payments
```

The trust domain is the SPIFFE trust domain; the local path becomes the
service name. The bridge MUST refuse SVIDs whose trust domain is not in
the operator-configured allowlist.

## Trust level mapping

| SVID source                | Default trust level |
| -------------------------- | ------------------- |
| Local SPIRE agent (T1 root) | T2                  |
| Federated trust bundle     | T2                  |
| Self-asserted (no chain)   | T1                  |

Operators may upgrade individual SPIFFE IDs to T3 via the agent-contract
`trust_overrides` block.

## Capability mapping

SPIFFE itself does not carry capability claims. A workload that wants to
expose actions to TrustForge MUST also provide an `agent-contract.yaml`;
the SVID becomes the actor identity, and the agent-contract becomes the
capability surface.

## Proof events

The bridge emits two stub event kinds the daemon can promote to full
proof events:

- `bridge.spiffe.svid_accepted` — a new SVID has been projected into
  TrustForge. Carries `spiffe_id`, `trust_domain`, `expires_at`, and the
  derived `actor_id`.
- `bridge.spiffe.svid_rejected` — a SVID failed validation. Reasons
  include unknown trust domain, expired cert, signature mismatch.

## Revocation behavior

A revoked SVID surfaces through the SPIFFE federation bundle's CRL
checks; the bridge consults the CRL on every projection. SPIFFE does not
provide instantaneous revocation, so TrustForge layers its own
`RevocationIndex` on top: the daemon's policy may refuse a still-valid
SVID if its derived `actor_id` is in the local revocation set.

## Envoy / Istio / Linkerd integration

When TrustForge runs behind a service mesh, the bridge can also consume
the mesh's projected identity headers:

- Envoy XFCC (`x-forwarded-client-cert`) — parsed for `URI=spiffe://…`.
- Istio AuthN headers — `x-istio-attributes` source-principal.
- Linkerd `l5d-client-id` — already SPIFFE-shaped.

These integrations live in `bridge-service-mesh.ts` and project the same
way as direct SVIDs but at trust level T1 unless the operator opts in to
trusting the mesh (T2).

## Conformance tests

`conformance/bridge-vectors.yaml` contains three SPIFFE cases verified
by both the TS and Rust runners:

- `spiffe.parse-x509-svid` — extracts a SPIFFE ID from a SAN URI.
- `spiffe.federation-bundle-accepts` — a federated bundle promotes a
  foreign SVID to T2.
- `spiffe.expired-svid-rejects` — a cert past its `notAfter` is dropped
  at the bridge layer regardless of TrustForge policy.

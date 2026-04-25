# TLS / DID / Matrix Bridge

## Status

Draft.

## Purpose

Three loosely-related transport-layer identity bridges:

- **TLS / mTLS** — accept the peer's X.509 certificate as a transport
  binding; the cert's subject becomes a foreign trust root.
- **DID** — accept W3C DID Core 1.0 documents as actor identifiers,
  with the DID's verification methods serving as TrustForge keys.
- **Matrix** — federate over the Matrix protocol, projecting room and
  user events into the TrustForge proof log.

The reference implementations live at:

- TS: `bridge-tls.ts`, `bridge-did.ts`, `bridge-matrix.ts`.
- Rust: `bridge_tls.rs`, `bridge_did.rs`, `bridge_matrix.rs`.

## TLS / mTLS

### Source identity

A peer X.509 certificate plus the connection's TLS exporter material
(RFC 5705). The bridge captures:

- subject + issuer DNs
- SAN URIs and DNS names
- `notBefore` / `notAfter`
- the negotiated TLS exporter key (binds the session to this peer)

### Actor mapping

```
tf:actor:service:<dns_name>/<sha256-fp[..16]>
```

`dns_name` is the first SAN DNS entry; the fingerprint comes from
`sha256(der(cert))`. If the cert carries a SPIFFE URI SAN, the SPIFFE
bridge takes precedence and produces the SPIFFE-shaped actor instead.

### Trust level

| Source                                  | Trust level |
| --------------------------------------- | ----------- |
| Cert chain validates to operator root   | T2          |
| Self-signed (certificate exporter only) | T1          |

### Proof events

- `bridge.tls.handshake_accepted`
- `bridge.tls.handshake_rejected`
- `bridge.tls.exporter_bound` — records the exporter key digest so
  later session-bound proof events can verify the binding.

### Optional extensions

The TLS bridge has hooks for OCSP / CRL freshness checks and
post-handshake re-authentication, but those are profile-gated and not
required for the home / constrained profiles.

## DID

### Source identity

A DID document fetched via the DID method's resolver, plus a DID
authentication assertion (a signed challenge tying the DID to the
current session).

### Actor mapping

```
tf:actor:human:did/<did-method>:<did-suffix>
tf:actor:agent:did/<did-method>:<did-suffix>
```

The actor type is derived from the DID document's `service`
endpoints — a service entry of type `Agent` projects to `agent`,
otherwise `human`.

### Trust level

| Source                                          | Trust level |
| ----------------------------------------------- | ----------- |
| `did:key`, `did:web` w/ HTTPS chain valid       | T2          |
| `did:web` w/ self-signed                        | T1          |
| `did:ion`, `did:ethr` w/ chain anchor verified  | T2          |
| `did:peer`, `did:dht`                           | T1          |

### Proof events

- `bridge.did.document_resolved`
- `bridge.did.authentication_verified`
- `bridge.did.authentication_failed`

## Matrix

### Source identity

A Matrix federation event signed by the originating homeserver. The
bridge projects the homeserver's signing key as a foreign trust root
and the event's `sender` MXID as the actor.

### Actor mapping

```
tf:actor:human:matrix/<homeserver>/<localpart>
```

Rooms project as ephemeral trust domains; events ride as encrypted
TrustForge packets bound to the room's key state.

### Trust level

| Source                                  | Trust level |
| --------------------------------------- | ----------- |
| Homeserver listed in trust-overlay      | T2          |
| Homeserver discovered via federation    | T1          |
| Cross-signed device key validated       | T3          |

### Proof events

- `bridge.matrix.event_received`
- `bridge.matrix.cross_sig_verified`
- `bridge.matrix.event_rejected`

## Revocation behavior

| Bridge | Revocation source                                      |
| ------ | ------------------------------------------------------ |
| TLS    | OCSP, CRL, operator's `RevocationIndex`                |
| DID    | DID document deactivation events, `RevocationIndex`    |
| Matrix | Cross-signing key rotation + homeserver demotion       |

All three bridges also consult the local TrustForge revocation set on
every projection.

## Conformance tests

`conformance/bridge-vectors.yaml` covers:

- `tls.subject-projection`
- `tls.exporter-bound-session`
- `did.web.authentication-verified`
- `matrix.event-from-trusted-homeserver`

# WebAuthn Bridge

## Status

Draft.

## Purpose

Accept WebAuthn / FIDO2 attestations as TrustForge actor authority for
human users. A user with a hardware authenticator (YubiKey, Apple
Passkey, Windows Hello) can sign approval requests and authenticate
sessions without TrustForge issuing or rotating its own per-user keys.

The reference implementations live at:

- TS: `tools/tf-types-ts/src/core/bridge-webauthn.ts` plus the
  attestation verifier in `webauthn-attestation.ts`.
- Rust: `crates/tf-types/src/bridge_webauthn.rs` plus
  `webauthn_attestation.rs`.

## Source identity object

The bridge accepts the standard WebAuthn registration response:

```
{
  attestationObject: <CBOR>,
  clientDataJSON:    <UTF-8 JSON>,
  // Plus the `credential.id`, `credential.publicKey` extracted by the
  // browser's WebAuthn API.
}
```

The `attestationObject` is parsed for the `fmt`, `authData`, and
`attStmt` fields. TrustForge supports three attestation formats:

- `none` — self-attestation; trust level T1.
- `packed` — RFC 8809 packed attestation with attestation certificate;
  trust level T2 if the cert chain validates against an operator-
  configured FIDO Metadata Service root.
- `fido-u2f` — legacy U2F format; T1 by default.

## Actor mapping

A WebAuthn credential projects to:

```
tf:actor:human:<trust_domain>/<rpId>:<credentialId>
```

The `trust_domain` comes from the operator-configured federation; the
`rpId` is the WebAuthn relying-party id; the `credentialId` is the
base64url credential id. The bridge stores the COSE public key as the
actor's primary signing key.

## Trust level mapping

| Attestation format       | Cert chain validates? | Trust level |
| ------------------------ | --------------------- | ----------- |
| `none`                   | n/a                   | T1          |
| `packed` self-attest     | n/a                   | T1          |
| `packed` w/ X5C chain    | yes (FIDO MDS)        | T2          |
| `packed` w/ X5C chain    | no                    | T1          |
| `fido-u2f`               | n/a                   | T1          |

## Capability mapping

WebAuthn carries no capabilities of its own. The user's agent-contract
or a per-session delegation defines what actions the credential is
allowed to authorize.

## Proof events

- `bridge.webauthn.registered` — first sighting of a credential.
- `bridge.webauthn.assertion_verified` — an authentication assertion
  successfully verified, recording credential id, signature counter,
  and challenge.
- `bridge.webauthn.assertion_failed` — counter regression, signature
  failure, or RP-id mismatch.

## Counter / clone-detection

WebAuthn assertions carry a monotonically-increasing signature counter.
The bridge's `verifyAssertion` refuses any assertion whose counter is
not strictly greater than the last value recorded for the credential.
A counter regression usually indicates a cloned authenticator; the
daemon emits `bridge.webauthn.assertion_failed` with reason
`counter-regression` and the operator's policy decides next steps
(typically: revoke the credential, force re-registration).

## Revocation behavior

Revoking a WebAuthn credential adds an entry to TrustForge's
`RevocationIndex` keyed by the credential's actor URI. Subsequent
assertions are rejected at the bridge layer before any policy check.
The bridge also honours FIDO Metadata Service status updates: a
credential whose authenticator is reported `STATUS_REVOKED` is treated
as revoked even without an explicit operator action.

## Conformance tests

`conformance/bridge-vectors.yaml` contains two WebAuthn cases:

- `webauthn.packed-self-attest-ed25519` — registers an ed25519 packed
  self-attestation; the bridge accepts at T1.
- `webauthn.packed-rsa-with-chain` — registers a packed attestation
  with an RS256 attestation cert chain; the bridge validates the chain
  via WebCrypto on TS and `@peculiar/x509` semantics on both sides.

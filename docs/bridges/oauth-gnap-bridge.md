# OAuth / OIDC / GNAP Bridge

## Status

Draft.

## Purpose

Accept OAuth 2.x access tokens, OpenID Connect ID tokens, and GNAP
(Grant Negotiation and Authorization Protocol) access tokens as
delegated authority into TrustForge. The token issuer is the trust
root; TrustForge does not need its own copy of every user account.

The reference implementations live at:

- TS: `tools/tf-types-ts/src/core/bridge-oauth.ts` and
  `bridge-gnap.ts`.
- Rust: `crates/tf-types/src/bridge_oauth.rs` and `bridge_gnap.rs`.

## Source identity object

### OAuth / OIDC

A signed JWT or RFC 9068 JWT-Profile access token. The bridge requires:

- `iss` (issuer) — must be in the operator-configured allowlist.
- `sub` (subject) — the user/client identifier.
- `aud` (audience) — must match the deployment's TrustForge daemon.
- `exp`, `iat`, `nbf` — checked against the daemon's clock.
- Either `scope` (space-separated) or `scopes` (array) — projected into
  capabilities.

For OIDC ID tokens, additional claims (`email`, `name`, `groups`) are
preserved on the projected actor identity but never used as authority.

### GNAP

A GNAP grant response (RFC TBD) containing an `access_token.value` and
`subject.sub_ids` array. The bridge consumes the `value` (an opaque
bearer token) plus the issuer-signed introspection record.

## Actor mapping

```
tf:actor:human:<iss-host>/<sub>     // OIDC user
tf:actor:service:<iss-host>/<client_id>   // OAuth M2M / GNAP service
```

`iss-host` is the host portion of the `iss` claim. The bridge refuses
issuers whose host is not registered in the trust-overlay or
federation-attestation set.

## Trust level mapping

| Token kind                              | Trust level |
| --------------------------------------- | ----------- |
| OIDC ID token, ed25519 / EdDSA signed   | T2          |
| OIDC ID token, RS256 / ES256 signed     | T2          |
| OAuth bearer w/ JWT introspection       | T2          |
| OAuth bearer w/ opaque introspection    | T1          |
| GNAP grant w/ subject identity          | T2          |
| GNAP grant w/o subject identity         | T1          |

## Capability mapping

OAuth `scope` / `scopes` and GNAP `access_token.access[].actions` are
projected to TrustForge action names by:

- lowercasing
- replacing `:` and `/` with `.`
- prepending `oauth.` (or `gnap.`) if the result has no dot

Operators may override the projection via the bridge config's
`scope_to_action_map`. Unrecognised scopes are emitted as
`oauth.<scope>` actions with risk class `R2` and approval `conditional`.

## Proof events

- `bridge.oauth.token_accepted` — captures `iss`, `sub`, `jti`,
  derived `actor_id`, scope set.
- `bridge.oauth.token_rejected` — reasons: signature, expired,
  audience mismatch, untrusted issuer.
- `bridge.gnap.grant_introspected` — successful GNAP introspection.

## Revocation behavior

Two layers:

1. **Issuer-side** — OAuth introspection (RFC 7662) can report
   `active: false` for revoked tokens. The bridge re-introspects on
   every projection unless the cache TTL is set; cache TTL must be
   ≤ token's `exp`.
2. **TrustForge-side** — operators may add the derived `actor_id` to
   the local `RevocationIndex`. The bridge consults both before
   accepting any subsequent introspection.

## Conformance tests

`conformance/bridge-vectors.yaml` covers:

- `oauth.jwt-rs256-accepted` — an RS256-signed JWT with valid issuer
  certificate is accepted at T2.
- `oauth.expired-rejected` — an `exp` in the past is rejected.
- `oauth.audience-mismatch-rejected` — `aud` not matching the daemon
  is rejected.
- `gnap.grant-introspect-accepted` — an introspection-active grant
  projects to a service actor.

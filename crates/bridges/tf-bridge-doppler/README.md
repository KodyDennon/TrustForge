# tf-bridge-doppler

TrustForge identity bridge for DOPPLER. Translate DOPPLER credentials, roles, and policies into cryptographic TrustForge actors and capabilities.

Part of [TrustForge](https://github.com/KodyDennon/TrustForge) — the open-source trust fabric for
AI-native software, devices, and verifiable action. The Rust crates and
the TypeScript packages (`@trustforge-protocol/*`) are mirrored
reference implementations kept in lockstep by a cross-language
conformance suite.

## Install

```sh
cargo add tf-bridge-doppler
```

## Overview

TrustForge bridge for Doppler.

Doppler issues *service tokens* (`dp.st.<env>.<random>`) and
*service-account tokens* that are scoped to a single project + config
(environment). The bridge:

1. Calls `GET /v3/me` against the Doppler API with the bearer token
   to verify the token is live and to learn its workplace + slug.
2. Calls `GET /v3/configs/config` to learn which project/config the
   token is bound to (service tokens are project-scoped at issue
   time).
3. Translates the verified token into a TrustForge `ActorIdentity`
   keyed by `<workplace>/<project>/<config>/<token-slug>`.
4. Translates each Doppler secret name into a `vault.kv.read` style
   capability targeted at `doppler://<project>/<config>/<secret>`.

Test note: Doppler's `me` endpoint returns plain JSON, so we point
the verifier at a `wiremock` instance for tests.

## Links

- API docs: [docs.rs/tf-bridge-doppler](https://docs.rs/tf-bridge-doppler)
- Source: [crates/bridges/tf-bridge-doppler](https://github.com/KodyDennon/TrustForge/tree/main/crates/bridges/tf-bridge-doppler)
- Specs & conformance vectors: [KodyDennon/TrustForge](https://github.com/KodyDennon/TrustForge)
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.

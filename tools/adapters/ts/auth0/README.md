# @trustforge-protocol/auth0

TrustForge authentication and policy enforcement adapter for Auth0. Seamlessly integrate zero-trust verifiable actions into your Auth0 application.

## Install

```sh
bun add @trustforge-protocol/auth0
# or
npm install @trustforge-protocol/auth0
```

## Usage

```ts
import { trustforgeAuth0 } from "@trustforge-protocol/auth0";
```

Every gated request is decided by `tf-daemon /v1/decide` (`enforce` or
`observe-only` mode) and stamped with a proof id. See the source for the
full option set and framework wiring.

## Links

- Source: [tools/adapters/ts/auth0](https://github.com/KodyDennon/TrustForge/tree/main/tools/adapters/ts/auth0)
- Project: [TrustForge](https://github.com/KodyDennon/TrustForge) — specs, schemas, and the conformance suite
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.

# @trustforge-protocol/logto

TrustForge authentication and policy enforcement adapter for Logto. Seamlessly integrate zero-trust verifiable actions into your Logto application.

## Install

```sh
bun add @trustforge-protocol/logto
# or
npm install @trustforge-protocol/logto
```

## Usage

```ts
import { trustforgeLogto } from "@trustforge-protocol/logto";
```

Every gated request is decided by `tf-daemon /v1/decide` (`enforce` or
`observe-only` mode) and stamped with a proof id. See the source for the
full option set and framework wiring.

## Links

- Source: [tools/adapters/ts/logto](https://github.com/KodyDennon/TrustForge/tree/main/tools/adapters/ts/logto)
- Project: [TrustForge](https://github.com/KodyDennon/TrustForge) — specs, schemas, and the conformance suite
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.

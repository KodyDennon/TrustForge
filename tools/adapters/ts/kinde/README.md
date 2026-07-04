# @trustforge-protocol/kinde

TrustForge authentication and policy enforcement adapter for Kinde. Seamlessly integrate zero-trust verifiable actions into your Kinde application.

## Install

```sh
bun add @trustforge-protocol/kinde
# or
npm install @trustforge-protocol/kinde
```

## Usage

```ts
import { trustforgeKinde } from "@trustforge-protocol/kinde";
```

Every gated request is decided by `tf-daemon /v1/decide` (`enforce` or
`observe-only` mode) and stamped with a proof id. See the source for the
full option set and framework wiring.

## Links

- Source: [tools/adapters/ts/kinde](https://github.com/KodyDennon/TrustForge/tree/main/tools/adapters/ts/kinde)
- Project: [TrustForge](https://github.com/KodyDennon/TrustForge) — specs, schemas, and the conformance suite
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.

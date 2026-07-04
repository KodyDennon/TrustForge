# @trustforge-protocol/h3

TrustForge authentication and policy enforcement adapter for H3. Seamlessly integrate zero-trust verifiable actions into your H3 application.

## Install

```sh
bun add @trustforge-protocol/h3
# or
npm install @trustforge-protocol/h3
```

## Usage

```ts
import { trustforgeHandler, tfRequire } from "@trustforge-protocol/h3";
```

Every gated request is decided by `tf-daemon /v1/decide` (`enforce` or
`observe-only` mode) and stamped with a proof id. See the source for the
full option set and framework wiring.

## Links

- Source: [tools/adapters/ts/h3](https://github.com/KodyDennon/TrustForge/tree/main/tools/adapters/ts/h3)
- Project: [TrustForge](https://github.com/KodyDennon/TrustForge) — specs, schemas, and the conformance suite
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.

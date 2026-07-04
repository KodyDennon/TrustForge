# @trustforge-protocol/koa

TrustForge authentication and policy enforcement adapter for Koa. Seamlessly integrate zero-trust verifiable actions into your Koa application.

## Install

```sh
bun add @trustforge-protocol/koa
# or
npm install @trustforge-protocol/koa
```

## Usage

```ts
import { trustforge, tfRequire } from "@trustforge-protocol/koa";
```

Every gated request is decided by `tf-daemon /v1/decide` (`enforce` or
`observe-only` mode) and stamped with a proof id. See the source for the
full option set and framework wiring.

## Links

- Source: [tools/adapters/ts/koa](https://github.com/KodyDennon/TrustForge/tree/main/tools/adapters/ts/koa)
- Project: [TrustForge](https://github.com/KodyDennon/TrustForge) — specs, schemas, and the conformance suite
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.

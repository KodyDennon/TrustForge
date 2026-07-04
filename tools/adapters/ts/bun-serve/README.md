# @trustforge-protocol/bun-serve

TrustForge authentication and policy enforcement adapter for Bun serve. Seamlessly integrate zero-trust verifiable actions into your Bun serve application.

## Install

```sh
bun add @trustforge-protocol/bun-serve
# or
npm install @trustforge-protocol/bun-serve
```

## Usage

```ts
import { withTrustforge } from "@trustforge-protocol/bun-serve";
```

Every gated request is decided by `tf-daemon /v1/decide` (`enforce` or
`observe-only` mode) and stamped with a proof id. See the source for the
full option set and framework wiring.

## Links

- Source: [tools/adapters/ts/bun-serve](https://github.com/KodyDennon/TrustForge/tree/main/tools/adapters/ts/bun-serve)
- Project: [TrustForge](https://github.com/KodyDennon/TrustForge) — specs, schemas, and the conformance suite
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.

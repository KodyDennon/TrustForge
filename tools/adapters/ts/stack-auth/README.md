# @trustforge-protocol/stack-auth

TrustForge authentication and policy enforcement adapter for Stack auth. Seamlessly integrate zero-trust verifiable actions into your Stack auth application.

## Install

```sh
bun add @trustforge-protocol/stack-auth
# or
npm install @trustforge-protocol/stack-auth
```

## Usage

```ts
import { trustforgeStackAuth } from "@trustforge-protocol/stack-auth";
```

Every gated request is decided by `tf-daemon /v1/decide` (`enforce` or
`observe-only` mode) and stamped with a proof id. See the source for the
full option set and framework wiring.

## Links

- Source: [tools/adapters/ts/stack-auth](https://github.com/KodyDennon/TrustForge/tree/main/tools/adapters/ts/stack-auth)
- Project: [TrustForge](https://github.com/KodyDennon/TrustForge) — specs, schemas, and the conformance suite
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.

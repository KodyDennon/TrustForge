# @trustforge-protocol/test-utils

TrustForge authentication and policy enforcement adapter for Test utils. Seamlessly integrate zero-trust verifiable actions into your Test utils application.

## Install

```sh
bun add @trustforge-protocol/test-utils
# or
npm install @trustforge-protocol/test-utils
```

## Usage

```ts
import { startMockDaemon, defaultAllow } from "@trustforge-protocol/test-utils";
```

Every gated request is decided by `tf-daemon /v1/decide` (`enforce` or
`observe-only` mode) and stamped with a proof id. See the source for the
full option set and framework wiring.

## Links

- Source: [tools/adapters/ts/test-utils](https://github.com/KodyDennon/TrustForge/tree/main/tools/adapters/ts/test-utils)
- Project: [TrustForge](https://github.com/KodyDennon/TrustForge) — specs, schemas, and the conformance suite
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.

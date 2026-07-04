# @trustforge-protocol/workos

TrustForge authentication and policy enforcement adapter for Workos. Seamlessly integrate zero-trust verifiable actions into your Workos application.

## Install

```sh
bun add @trustforge-protocol/workos
# or
npm install @trustforge-protocol/workos
```

## Usage

```ts
import { trustforgeWorkOS } from "@trustforge-protocol/workos";
```

Every gated request is decided by `tf-daemon /v1/decide` (`enforce` or
`observe-only` mode) and stamped with a proof id. See the source for the
full option set and framework wiring.

## Links

- Source: [tools/adapters/ts/workos](https://github.com/KodyDennon/TrustForge/tree/main/tools/adapters/ts/workos)
- Project: [TrustForge](https://github.com/KodyDennon/TrustForge) — specs, schemas, and the conformance suite
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.

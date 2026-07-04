# @trustforge-protocol/firebase-auth

TrustForge authentication and policy enforcement adapter for Firebase auth. Seamlessly integrate zero-trust verifiable actions into your Firebase auth application.

## Install

```sh
bun add @trustforge-protocol/firebase-auth
# or
npm install @trustforge-protocol/firebase-auth
```

## Usage

```ts
import { trustforgeFirebase } from "@trustforge-protocol/firebase-auth";
```

Every gated request is decided by `tf-daemon /v1/decide` (`enforce` or
`observe-only` mode) and stamped with a proof id. See the source for the
full option set and framework wiring.

## Links

- Source: [tools/adapters/ts/firebase-auth](https://github.com/KodyDennon/TrustForge/tree/main/tools/adapters/ts/firebase-auth)
- Project: [TrustForge](https://github.com/KodyDennon/TrustForge) — specs, schemas, and the conformance suite
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.

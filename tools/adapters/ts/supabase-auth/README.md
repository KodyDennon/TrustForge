# @trustforge-protocol/supabase-auth

TrustForge authentication and policy enforcement adapter for Supabase auth. Seamlessly integrate zero-trust verifiable actions into your Supabase auth application.

## Install

```sh
bun add @trustforge-protocol/supabase-auth
# or
npm install @trustforge-protocol/supabase-auth
```

## Usage

```ts
import { trustforgeSupabase } from "@trustforge-protocol/supabase-auth";
```

Every gated request is decided by `tf-daemon /v1/decide` (`enforce` or
`observe-only` mode) and stamped with a proof id. See the source for the
full option set and framework wiring.

## Links

- Source: [tools/adapters/ts/supabase-auth](https://github.com/KodyDennon/TrustForge/tree/main/tools/adapters/ts/supabase-auth)
- Project: [TrustForge](https://github.com/KodyDennon/TrustForge) — specs, schemas, and the conformance suite
- Issues: [KodyDennon/TrustForge/issues](https://github.com/KodyDennon/TrustForge/issues)

## Status

Draft — experimental. Apache-2.0.

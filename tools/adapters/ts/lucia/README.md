# @trustforge-protocol/lucia

Lucia v3 session-validation hook that projects every validated session into a
TrustForge actor + capabilities.

## Status

Draft. Part of TrustForge Phase D. Not production ready.

## Install

```bash
bun add @trustforge-protocol/lucia @trustforge-protocol/sdk lucia
```

## Usage

```ts
import { Lucia } from "lucia";
import { trustforgeForLucia } from "@trustforge-protocol/lucia";

const lucia = new Lucia(adapter, {
  /* ... */
});
export const tfLucia = trustforgeForLucia(lucia, {
  daemonUrl: "http://127.0.0.1:7616",
});

// In your route handler:
const result = await tfLucia.validateSession(sessionId);
if (result.tfActor) {
  // result.tfActor / result.tfCapabilities / result.tfTrustLevel are populated
}
```

## Per-route enforcement

```ts
const requireRead = tfLucia.tfRequire("fs.read", "/etc/passwd");
const verdict = await requireRead(result);
if (!verdict.allowed) throw new Error(verdict.reason);
```

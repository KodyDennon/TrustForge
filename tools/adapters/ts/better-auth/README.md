# @trustforge/better-auth

Better Auth plugin that hooks into the `session.fetch` callback and projects
every resolved Better Auth session into a TrustForge actor + capabilities.

## Status

Draft. Part of TrustForge Phase D (TS auth-library bridges). Not production
ready until the underlying TF specs and `@trustforge/sdk` are stabilized.

## Install

```bash
bun add @trustforge/better-auth @trustforge/sdk better-auth
```

## Usage

```ts
import { betterAuth } from "better-auth";
import { trustforgePlugin } from "@trustforge/better-auth";

export const auth = betterAuth({
  // ... your existing better-auth config ...
  plugins: [
    trustforgePlugin({
      daemonUrl: "http://127.0.0.1:7616",
      adminToken: process.env.TF_ADMIN_TOKEN,
    }),
  ],
});
```

After Better Auth resolves a session, the request/handler context will carry:

| Field             | Meaning                                                |
| ----------------- | ------------------------------------------------------ |
| `tfActor`         | The TrustForge actor URI the session resolved to.     |
| `tfCredentialId`  | Daemon-side credential id for this session.           |
| `tfTrustLevel`    | T0–T7 trust level returned by the daemon.             |
| `tfCapabilities`  | (Reserved.) Per-decide capabilities array.            |

### Per-route enforcement

```ts
const requireFsRead = auth.plugins[0].tfRequire("fs.read", "/etc/passwd");

app.get("/secret", async (ctx) => {
  const verdict = await requireFsRead(ctx);
  if (!verdict.allowed) return ctx.json({ error: verdict.reason }, 403);
  // ... allowed ...
});
```

## Proof events

The plugin emits a `bridge.better_auth.session_resolved` log line on every
successful import. The signed proof event itself is recorded by the daemon
when `/v1/credentials/import` is called.

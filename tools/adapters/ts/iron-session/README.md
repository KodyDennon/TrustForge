# @trustforge/iron-session

Wraps `iron-session`'s `getIronSession` so every read of the cookie-backed
session also projects the session into a TrustForge actor + capabilities.

## Status

Draft. Part of TrustForge Phase D. Not production ready.

## Install

```bash
bun add @trustforge/iron-session @trustforge/sdk iron-session
```

## Usage

```ts
import { getIronSession } from "iron-session";
import { trustforgeForIronSession } from "@trustforge/iron-session";

const sessionOptions = {
  cookieName: "myapp_session",
  password: process.env.SESSION_SECRET!,
};

export const getSession = trustforgeForIronSession(getIronSession, {
  daemonUrl: "http://127.0.0.1:7616",
  sessionOptions,
  identityField: "userId",
});

// In a handler:
const session = await getSession(req, res);
if (session.tfActor) { /* allowed user */ }
```

## Per-route enforcement

```ts
import { tfRequireIron } from "@trustforge/iron-session";
const requireWrite = tfRequireIron(
  { daemonUrl: "http://127.0.0.1:7616" },
  "fs.write",
);
const verdict = await requireWrite(session);
```

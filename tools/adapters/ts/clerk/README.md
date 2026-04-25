# @trustforge/clerk

Clerk integration for TrustForge. Captures the resolved Clerk session id from
`auth().sessionId` and projects it into a TrustForge actor + capabilities.

Two surfaces are exported:

| Helper             | For                                              |
| ------------------ | ------------------------------------------------ |
| `withTrustForge`   | Wrap `clerkMiddleware()` in Next.js (App Router) |
| `trustforgeClerk`  | Express middleware after `ClerkExpressRequireAuth()` |

## Install

```bash
bun add @trustforge/clerk @trustforge/sdk @clerk/nextjs # or @clerk/clerk-sdk-node
```

## Next.js

```ts
// middleware.ts
import { clerkMiddleware } from "@clerk/nextjs/server";
import { withTrustForge } from "@trustforge/clerk";

export default withTrustForge(clerkMiddleware(), {
  daemonUrl: "http://127.0.0.1:7616",
  adminToken: process.env.TF_ADMIN_TOKEN,
});
```

## Express

```ts
import express from "express";
import { ClerkExpressRequireAuth } from "@clerk/clerk-sdk-node";
import { trustforgeClerk } from "@trustforge/clerk";

const app = express();
app.use(ClerkExpressRequireAuth());
app.use(trustforgeClerk({ daemonUrl: "http://127.0.0.1:7616" }));
```

After both middlewares run, `req.tfActor`, `req.tfCredentialId`,
`req.tfTrustLevel`, and `req.tfCapabilities` are populated.

## Per-route enforcement

```ts
import { tfRequireClerk } from "@trustforge/clerk";
const requireShell = tfRequireClerk(
  { daemonUrl: "http://127.0.0.1:7616" },
  "shell.exec",
);

app.post("/admin/exec", async (req, res) => {
  const verdict = await requireShell(req);
  if (!verdict.allowed) return res.status(403).json({ error: verdict.reason });
  /* ... */
});
```

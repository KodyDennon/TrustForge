# @trustforge/hono

Hono middleware for TrustForge. Gates every request through `tf-daemon /v1/decide`.
Tested against Bun (Hono's default runtime); also works on Cloudflare Workers,
Deno, and Node via Hono's own runtime adapters.

## Install

```sh
bun add @trustforge/hono hono
```

## Usage

```ts
import { Hono } from "hono";
import { trustforgeMiddleware, tfRequire } from "@trustforge/hono";

const app = new Hono();

app.use(
  "*",
  trustforgeMiddleware({
    daemonUrl: "http://127.0.0.1:7616",
    adminToken: process.env.TF_ADMIN_TOKEN,
    mode: "enforce",
    profile: "home",
  }),
);

app.get("/public", (c) =>
  c.json({ actor: c.get("tfActor"), proof: c.get("tfProofId") }),
);

app.post(
  "/billing/charge",
  tfRequire("billing.charge", { daemonUrl: "http://127.0.0.1:7616" }),
  (c) => c.json({ ok: true }),
);

export default app;
```

`c.get("tfActor")`, `c.get("tfDecision")`, `c.get("tfProofId")` are populated on
every allowed request.

## Status

Draft — experimental.

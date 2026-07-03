# @trustforge-protocol/fastify

Fastify 4 / 5 plugin for TrustForge. Gates every request via `tf-daemon /v1/decide`.

## Install

```sh
bun add @trustforge-protocol/fastify fastify
# or
npm install @trustforge-protocol/fastify fastify
```

## Usage

```ts
import Fastify from "fastify";
import { fastifyTrustForge } from "@trustforge-protocol/fastify";

const app = Fastify();

await app.register(fastifyTrustForge, {
  daemonUrl: "http://127.0.0.1:7616",
  adminToken: process.env.TF_ADMIN_TOKEN,
  mode: "enforce", // "observe-only" to record-only
  profile: "home",
  // gateGlobally: false, // disable global preHandler if you only want per-route gating
});

app.get("/public", async (req) => ({
  actor: req.tfActor,
  proof: req.tfProofId,
}));

app.post(
  "/billing/charge",
  { preHandler: app.tfRequire("billing.charge") },
  async () => ({ ok: true }),
);

await app.listen({ port: 3000 });
```

`req.tfActor`, `req.tfDecision`, and `req.tfProofId` are available on every
allowed request. The proof id is also surfaced as `x-tf-proof-id` on the response.

## Status

Draft — experimental.

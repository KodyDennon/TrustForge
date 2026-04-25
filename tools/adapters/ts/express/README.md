# @trustforge/express

Express 4 / 5 middleware for TrustForge. Gates every request through
`tf-daemon /v1/decide`.

## Install

```sh
bun add @trustforge/express express
# or
npm install @trustforge/express express
```

## Usage

```ts
import express from "express";
import { tfExpress, tfRequire } from "@trustforge/express";

const app = express();

app.use(
  tfExpress({
    daemonUrl: "http://127.0.0.1:7616",
    adminToken: process.env.TF_ADMIN_TOKEN,
    mode: "enforce", // or "observe-only"
    profile: "home",
  }),
);

// Default (action = "http.request").
app.get("/public", (req, res) => {
  res.json({ actor: req.tfActor, proof: req.tfProofId });
});

// Action-pinned route guard.
app.post("/billing/charge", tfRequire("billing.charge"), (_req, res) => {
  res.json({ ok: true });
});
```

`req.tfActor`, `req.tfDecision`, and `req.tfProofId` are populated on every
allowed request. The proof id is also exposed as the `x-tf-proof-id` response
header for downstream tracing.

## Modes

- `enforce` (default): deny → 403, approval-required → 202 + `Location:`.
- `observe-only`: always forwards but still records decisions / proofs.

## Status

Draft — experimental.

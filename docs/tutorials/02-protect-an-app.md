# 02 — Protect an Express app

Goal: wire `@trustforge/express` (the adapter under
`tools/adapters/`) into a small Node.js Express app so that one
route is gated by a TrustForge policy decision. About 25 minutes.

By the end you will have:

- An Express app exposing a public route and a protected route.
- The protected route calling the daemon's `/v1/decide` endpoint
  via the adapter middleware.
- Proof events emitted for every decision.

This tutorial assumes you have completed
[01 Getting started](01-getting-started.md) and have a daemon
running on `127.0.0.1:8787`.

## Step 1 — Stand up a tiny Express app

Create a new directory `~/tf-tutorial-02` outside the TrustForge
repo (so we can demonstrate cross-package consumption):

```bash
mkdir -p ~/tf-tutorial-02 && cd ~/tf-tutorial-02

bun init -y
bun add express
bun link --link-trustforge   # picks up @trustforge/express from your local checkout
```

(If `bun link --link-trustforge` is not yet a published shortcut
in 0.1.0, install the adapter from the local path:
`bun add file:/path/to/trustforge/tools/adapters/express`.)

Create `index.ts`:

```ts
import express from "express";
import { trustforge } from "@trustforge/express";

const app = express();
app.use(express.json());

const tf = trustforge({
  daemon: "http://127.0.0.1:8787",
  adminToken: process.env.TF_ADMIN_TOKEN!,
  // Adapter actor identity. The adapter authenticates to the
  // daemon under this URI; capabilities are evaluated relative
  // to the *caller*, set on the request below.
  adapter: "tf:actor:service:example.com/tutorial-02-adapter",
});

app.get("/public", (_req, res) => {
  res.json({ ok: true, route: "public" });
});

app.get(
  "/protected/:doc",
  tf.decide({
    action: "doc.read",
    target: (req) => `doc:${req.params.doc}`,
    actor:  (req) => req.headers["x-actor"] as string,
  }),
  (req, res) => {
    res.json({ ok: true, route: "protected", doc: req.params.doc });
  }
);

app.listen(3000, () => console.log("listening on :3000"));
```

The `tf.decide(...)` middleware extracts an actor URI from the
request, calls `/v1/decide`, and either continues or returns
`403` with the daemon's reasons.

## Step 2 — Mint a caller actor

The protected route needs an actor URI to decide *for*. Mint a
caller identity:

```bash
cd /path/to/trustforge
TF_VAULT_PASS=dev-pw \
    bun run tools/tf-cli/src/cli.ts actor create \
    --type human \
    --name alice \
    --domain example.com
```

Result: `tf:actor:human:example.com/alice`.

## Step 3 — Grant the caller a capability

Edit the policy bundle. For this tutorial, use a tiny in-memory
policy file. Create `.tf/policy.yaml`:

```yaml
engine: cedar
schema: |
  entity Action;
  entity Actor;
  entity Target;
rules: |
  permit (
    principal == Actor::"tf:actor:human:example.com/alice",
    action == Action::"doc.read",
    resource
  );
```

Reload the daemon's policy:

```bash
curl -X POST http://127.0.0.1:8787/v1/policy/reload \
    -H "Authorization: Bearer $TF_ADMIN_TOKEN"
```

Or `kill -HUP <daemon-pid>` if you prefer signals.

## Step 4 — Boot the Express app

In a new terminal, with the same `TF_ADMIN_TOKEN` exported:

```bash
cd ~/tf-tutorial-02
bun run index.ts
```

## Step 5 — Hit the public route

```bash
curl -s http://127.0.0.1:3000/public | jq .
# { "ok": true, "route": "public" }
```

No daemon involvement; this is the baseline.

## Step 6 — Hit the protected route as Alice (allowed)

```bash
curl -s http://127.0.0.1:3000/protected/sales-report \
    -H "X-Actor: tf:actor:human:example.com/alice" | jq .
# { "ok": true, "route": "protected", "doc": "sales-report" }
```

In the daemon's log you will see:

```
[info] /v1/decide actor=tf:actor:human:example.com/alice action=doc.read target=doc:sales-report decision=allow latency=2ms
```

And in the ledger, a `pe.action.allowed` event.

## Step 7 — Hit the protected route as Bob (denied)

```bash
curl -s -i http://127.0.0.1:3000/protected/sales-report \
    -H "X-Actor: tf:actor:human:example.com/bob"
# HTTP/1.1 403 Forbidden
# {"ok":false,"reason":"no matching grant","decision":"deny"}
```

Bob has no actor identity and no grant; the daemon returns
`deny`, the middleware translates that to a 403.

## Step 8 — Add a negative capability

Edit `.tf/policy.yaml`:

```yaml
engine: cedar
schema: |
  entity Action;
  entity Actor;
  entity Target;
rules: |
  permit (
    principal == Actor::"tf:actor:human:example.com/alice",
    action == Action::"doc.read",
    resource
  );

  forbid (
    principal,
    action == Action::"doc.read",
    resource == Target::"doc:executive-comp"
  );
```

Reload, then:

```bash
curl -s -i http://127.0.0.1:3000/protected/executive-comp \
    -H "X-Actor: tf:actor:human:example.com/alice"
# HTTP/1.1 403 Forbidden
# {"ok":false,"reason":"forbid rule matched","decision":"deny"}
```

The `forbid` (negative capability) overrides the `permit`. This
is the negative-capability-precedence mitigation in action; a
prompt-injected AI agent that talks Alice's identity into reading
`executive-comp` is denied even though Alice has a positive
grant for `doc.read` on every resource.

## Step 9 — Wire approval-gated routes

Add a third route that requires explicit approval:

```ts
app.post(
  "/protected/:doc/share",
  tf.decide({
    action: "doc.share",
    target: (req) => `doc:${req.params.doc}`,
    actor:  (req) => req.headers["x-actor"] as string,
    onEscalate: "wait",   // adapter polls until approve/deny
  }),
  (req, res) => res.json({ ok: true, action: "shared" })
);
```

Add a Cedar rule for this action that requires approval:

```yaml
permit (
  principal == Actor::"tf:actor:human:example.com/alice",
  action == Action::"doc.share",
  resource
)
when {
  context.approval == true
};
```

Now an attempt to share queues an approval. The operator runs:

```bash
bun run tools/tf-cli/src/cli.ts approval list
bun run tools/tf-cli/src/cli.ts approve <approval-id>
```

The middleware (with `onEscalate: "wait"`) returns once the
approval is granted, denied, or times out.

## What you have learned

- Adapters are thin: they extract actor/action/target from the
  request and call `/v1/decide`.
- Policy is *outside* the application. Changing policy never
  requires redeploying the app.
- Negative capabilities and approval ceremonies are first-class.
  The Express adapter exposes them through `onEscalate`.

## What to read next

- [03 Rust server](03-rust-server.md) — same surface, Axum side.
- [04 Policy authoring](04-policy-authoring.md) — both Cedar and
  Rego, with realistic examples.
- [07 Bridges](07-bridges.md) — turning OAuth tokens, SPIFFE
  SVIDs, or WebAuthn assertions into TrustForge actor URIs.

## Adapter source

The `@trustforge/express` adapter lives in
[`../../tools/adapters/express/`](../../tools/adapters/express/)
(or under `tools/adapters/` more generally). For Remix, see
`tools/adapters/remix/`. For MCP and A2A, see the dedicated
adapters under the same directory.

# `@trustforge-protocol/next`

Next.js adapter for TrustForge. Drop-in support for both **App Router** and
**Pages Router**, on both the **Edge** and **Node** runtimes.

## Install

```bash
bun add @trustforge-protocol/next @trustforge-protocol/sdk
# or: npm install @trustforge-protocol/next @trustforge-protocol/sdk
```

## Edge / Node middleware (`middleware.ts`)

Create `middleware.ts` at your project root:

```ts
import { withTrustForge, recommendedMatcher } from "@trustforge-protocol/next/middleware";

export default withTrustForge({
  daemonUrl: "http://127.0.0.1:8642",
  adminToken: process.env.TF_ADMIN_TOKEN,
  // observe-only logs every request but never blocks. Flip to "enforce"
  // (the default) once you've reviewed traces from your tf-dashboard.
  mode: "observe-only",
  skip: (path) => path.startsWith("/_health") || path.startsWith("/public"),
});

export const config = { matcher: recommendedMatcher };
```

The middleware:
- pulls `Authorization: Bearer ...`, `__Secure-next-auth.session-token`,
  `sess_...` (Clerk), and `auth_...` (Better Auth) credentials automatically;
- calls `POST /v1/decide` against your `tf-daemon`;
- on `allow` / `log-only`, lets the request through with `x-tf-*` headers;
- on `deny`, returns 403 + `WWW-Authenticate: TrustForge`;
- on `approval-required`, returns 202 + `Location: /tf/approval/<id>`;
- on `escalate`, returns 403 with the danger tags in the body.

## App Router route handler (`app/api/.../route.ts`)

```ts
import { tfRequire } from "@trustforge-protocol/next/server";

export const POST = tfRequire("user.create")(async (req) => {
  const body = await req.json();
  // ... do the work
  return Response.json({ ok: true });
});
```

`tfRequire("user.create")` forces the action name; everything else
(host_token extraction, profile, daemon URL) is inherited from the same
options as the middleware.

## Pages Router API route (`pages/api/users.ts`)

```ts
import { tfRequireApi } from "@trustforge-protocol/next/server";
import type { NextApiRequest, NextApiResponse } from "next";

export default tfRequireApi("user.create")(
  async (req: NextApiRequest, res: NextApiResponse) => {
    res.status(200).json({ ok: true });
  },
);
```

## Custom action / credential resolvers

```ts
withTrustForge({
  daemonUrl: "http://127.0.0.1:8642",
  resolveAction: (req) =>
    req.method === "DELETE" ? "data.delete" : "data.read",
  resolveCredential: (req) => ({
    host_token: req.headers.get("x-my-org-token"),
    host_token_kind: "oauth-jwt",
  }),
  resolveContext: (req) => ({
    region: req.headers.get("x-vercel-ip-country") ?? "unknown",
  }),
});
```

## Testing

The adapter accepts a pre-built SDK instance via `tf:`. Pass any object that
satisfies `TrustForgeLike` (i.e. has a `decide(req)` method) and you can
write fast unit tests with no daemon running.

```ts
import { withTrustForge } from "@trustforge-protocol/next/middleware";
const mw = withTrustForge({ tf: { async decide() { return allowFixture; } } });
```

## Profiles

Pass `profile: "home" | "enterprise" | "constrained" | "compliance-evidence"`
and the daemon will load the matching policy bundle. See
`docs/profiles/` in the TrustForge repo.

## Status

Draft. Tracks `TF-0013-decision-protocol` and the Phase C7 entry of the
2026-04-25 implementation plan.

# `@trustforge/sveltekit`

SvelteKit adapter for TrustForge. Wires into the `handle` server hook so
every request flows through `tf-daemon` before reaching your routes.

## Install

```bash
bun add @trustforge/sveltekit @trustforge/sdk
```

## Use it (`src/hooks.server.ts`)

```ts
import { trustforgeHandle } from "@trustforge/sveltekit";
import type { Handle } from "@sveltejs/kit";

export const handle: Handle = trustforgeHandle({
  daemonUrl: "http://127.0.0.1:8642",
  adminToken: process.env.TF_ADMIN_TOKEN,
  // observe-only logs every request but never blocks. Flip to "enforce"
  // (default) once you trust your policy.
  mode: "observe-only",
  skip: (path) => path.startsWith("/_app") || path === "/favicon.ico",
});
```

After this, `event.locals` is populated for every request:

```ts
// in any +server.ts / +page.server.ts
export async function load({ locals }) {
  return {
    actor: locals.tfActor,         // tf:actor:user:example.com/alice
    decision: locals.tfDecision,   // full decision envelope
    proofId: locals.tfProofId,     // proof event hash
  };
}
```

For TypeScript autocompletion, declare the `App.Locals` type in
`src/app.d.ts`:

```ts
declare global {
  namespace App {
    interface Locals {
      tfActor?: string;
      tfDecision?: import("@trustforge/sveltekit").TfDecision;
      tfProofId?: string;
    }
  }
}
export {};
```

## Composing with other handles

Use `sequence()` from `@sveltejs/kit/hooks`:

```ts
import { sequence } from "@sveltejs/kit/hooks";
import { trustforgeHandle } from "@trustforge/sveltekit";
import { authHandle } from "$lib/auth";

export const handle = sequence(
  authHandle,           // resolves session first
  trustforgeHandle({}), // then TF makes the policy decision
);
```

## Custom resolvers

```ts
trustforgeHandle({
  resolveAction: (event) =>
    event.request.method === "DELETE" ? "data.delete" : "data.read",
  resolveCredential: (event) => ({
    host_token: event.cookies.get("my-org-session"),
    host_token_kind: "session-cookie",
  }),
  resolveContext: (event) => ({
    locale: event.request.headers.get("accept-language") ?? "en",
  }),
});
```

## Status

Draft. Tracks Phase C8 of the TrustForge implementation plan.

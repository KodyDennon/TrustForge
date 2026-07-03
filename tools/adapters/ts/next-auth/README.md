# @trustforge-protocol/next-auth

Drop-in NextAuth / Auth.js callbacks that project the resolved JWT / session
into a TrustForge actor + capabilities.

## Status

Draft. Part of TrustForge Phase D. Not production ready.

## Install

```bash
bun add @trustforge-protocol/next-auth @trustforge-protocol/sdk next-auth
```

## Usage

```ts
import NextAuth from "next-auth";
import { trustforgeCallbacks } from "@trustforge-protocol/next-auth";

export const { handlers, auth } = NextAuth({
  providers: [/* ... */],
  callbacks: trustforgeCallbacks({
    daemonUrl: "http://127.0.0.1:7616",
    adminToken: process.env.TF_ADMIN_TOKEN,
  }),
});
```

To merge with your own callbacks:

```ts
import { trustforgeCallbacks } from "@trustforge-protocol/next-auth";

const tf = trustforgeCallbacks({ daemonUrl: "..." });
export const { handlers, auth } = NextAuth({
  callbacks: {
    ...tf,
    async session(args) {
      const s = await tf.session(args);
      // your custom session shaping...
      return s;
    },
  },
});
```

After sign-in the session and JWT carry:

| Field             | Meaning                                        |
| ----------------- | ---------------------------------------------- |
| `tfActor`         | TrustForge actor URI.                          |
| `tfCredentialId`  | Daemon-side credential id for the JWT/session. |
| `tfTrustLevel`    | T0–T7 trust level.                             |
| `tfCapabilities`  | (Reserved.) Per-decide capabilities array.     |

### Per-route enforcement

```ts
import { tfRequire } from "@trustforge-protocol/next-auth";
const requireFsRead = tfRequire({ daemonUrl: "..." }, "fs.read", "/etc/passwd");

export async function GET() {
  const session = await auth();
  const verdict = await requireFsRead(session);
  if (!verdict.allowed) return new Response(verdict.reason, { status: 403 });
  /* ... */
}
```

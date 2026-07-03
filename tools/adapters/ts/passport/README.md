# @trustforge-protocol/passport

Passport strategy that verifies an inbound credential (typically a bearer
token, opaque session id, or signed cookie) against the TrustForge daemon and
surfaces the resolved TF actor as `req.user`.

## Status

Draft. Part of TrustForge Phase D. Not production ready.

## Install

```bash
bun add @trustforge-protocol/passport @trustforge-protocol/sdk passport
```

## Usage

```ts
import passport from "passport";
import { TrustForgeStrategy } from "@trustforge-protocol/passport";

passport.use(
  new TrustForgeStrategy({
    daemonUrl: "http://127.0.0.1:7616",
    source: "auth-bearer", // | "cookie" | "custom"
  }),
);

app.get(
  "/api/me",
  passport.authenticate("trustforge", { session: false }),
  (req, res) => res.json(req.user),
);
```

After authentication, `req.user` contains:

| Field             | Meaning                                |
| ----------------- | -------------------------------------- |
| `tfActor`         | TrustForge actor URI.                  |
| `tfCredentialId`  | Daemon-side credential id.            |
| `tfTrustLevel`    | T0–T7 trust level.                    |
| `tfCapabilities`  | (Reserved.) Per-decide capabilities.  |

## Custom extractors

```ts
new TrustForgeStrategy({
  daemonUrl: "...",
  source: "custom",
  extract: (req) => req.query.token as string,
});
```

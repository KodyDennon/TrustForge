# `@trustforge/nestjs`

NestJS adapter for TrustForge. Ships a `CanActivate` guard, an injectable
service, a `TrustForgeModule.forRoot()` dynamic module, and a
`@TrustForgeRequire("action")` decorator.

## Install

```bash
npm install @trustforge/nestjs @trustforge/sdk reflect-metadata
```

`reflect-metadata` must be imported once at the top of your `main.ts` (this
is a NestJS requirement, not a TrustForge one).

## Wire it up

```ts
// app.module.ts
import { Module } from "@nestjs/common";
import { TrustForgeModule } from "@trustforge/nestjs";

@Module({
  imports: [
    TrustForgeModule.forRoot({
      daemonUrl: "http://127.0.0.1:8642",
      adminToken: process.env.TF_ADMIN_TOKEN,
      mode: "observe-only", // flip to "enforce" once your policy is settled
    }),
  ],
})
export class AppModule {}
```

The module is registered as `global: true`, so any controller in your app
can inject `TrustForgeService` and use `TrustForgeGuard` without re-importing.

## Use the guard + decorator

```ts
import { Controller, Post, UseGuards, Body } from "@nestjs/common";
import { TrustForgeGuard, TrustForgeRequire } from "@trustforge/nestjs";

@Controller("users")
@UseGuards(TrustForgeGuard)
export class UsersController {
  @Post()
  @TrustForgeRequire("user.create")
  create(@Body() body: { email: string }) {
    return { ok: true };
  }
}
```

When the guard runs, it:
1. Reads the action from `@TrustForgeRequire(...)` (or falls back to a
   `${method}.${pathSegment}` default).
2. Pulls credentials from `Authorization: Bearer ...` or session cookies.
3. Calls `tf-daemon /v1/decide`.
4. Throws `HttpException` with status 403 (deny / escalate) or 202
   (approval-required) on a non-allow verdict.
5. Decorates `request.tfActor`, `request.tfDecision`, `request.tfProofId`
   on allow/log-only/observe-only.

## Inject the service

```ts
import { Injectable } from "@nestjs/common";
import { TrustForgeService } from "@trustforge/nestjs";

@Injectable()
export class BillingService {
  constructor(private readonly tf: TrustForgeService) {}

  async charge(actor: string, amount: number) {
    const decision = await this.tf.decide({
      actor,
      action: "billing.charge",
      target: `amount:${amount}`,
      context: { amount },
    });
    if (decision.decision !== "allow")
      throw new Error(`denied: ${decision.reason}`);
  }
}
```

## Apply the guard globally

```ts
// main.ts
import { TrustForgeGuardImpl, TrustForgeService } from "@trustforge/nestjs";
const tfService = app.get(TrustForgeService);
app.useGlobalGuards(new TrustForgeGuardImpl(tfService, { mode: "enforce" }));
```

## Status

Draft. Tracks Phase C9 of the implementation plan.

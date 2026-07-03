import { describe, expect, test } from "bun:test";
import {
  TrustForgeGuardImpl,
  TrustForgeHttpException,
  TrustForgeModule,
  TrustForgeRequire,
  TrustForgeService,
  getRequiredAction,
} from "../src/index.ts";
import type {
  NestExecutionContextLike,
  NestHttpReqLike,
  TfDecideRequest,
  TfDecision,
  TrustForgeLike,
} from "../src/types.ts";

function mockClient(
  decisionFor: (req: TfDecideRequest) => TfDecision,
): TrustForgeLike & { calls: TfDecideRequest[] } {
  const calls: TfDecideRequest[] = [];
  return {
    calls,
    async decide(req) {
      calls.push(req);
      return decisionFor(req);
    },
  };
}

function makeContext(opts: {
  method?: string;
  url?: string;
  headers?: Record<string, string>;
  cookies?: Record<string, string>;
  handler?: Function;
  cls?: Function;
}): {
  ctx: NestExecutionContextLike;
  req: NestHttpReqLike;
} {
  const req: NestHttpReqLike = {
    method: opts.method ?? "GET",
    url: opts.url ?? "/api/users",
    originalUrl: opts.url ?? "/api/users",
    headers: opts.headers ?? {},
    cookies: opts.cookies ?? {},
  };
  const ctx: NestExecutionContextLike = {
    switchToHttp() {
      return { getRequest: <T>() => req as unknown as T };
    },
    getHandler: () => opts.handler ?? (() => {}),
    getClass: () => opts.cls ?? (class {}),
  };
  return { ctx, req };
}

const allow: TfDecision = {
  decision: "allow",
  reason: "ok",
  approval_id: null,
  proof_id: "sha256:allow",
  actor_resolved: "tf:actor:user:example.com/alice",
  trust_level: "T2",
  authority_mode: "layered",
  danger_tags: [],
};

const deny: TfDecision = {
  ...allow,
  decision: "deny",
  reason: "policy",
  proof_id: "sha256:deny",
  danger_tags: ["nope"],
};

const approval: TfDecision = {
  ...allow,
  decision: "approval-required",
  reason: "needs review",
  approval_id: "approval-77",
  proof_id: "sha256:approval",
};

describe("@trustforge-protocol/nestjs", () => {
  test("TrustForgeGuard.canActivate(ctx) returns true on allow and decorates request", async () => {
    const tf = mockClient(() => allow);
    const svc = new TrustForgeService({ tf });
    const guard = new TrustForgeGuardImpl(svc, {});

    const { ctx, req } = makeContext({
      method: "GET",
      url: "/api/users/42",
      headers: { authorization: "Bearer eyJsig.tok.x" },
    });
    const ok = await guard.canActivate(ctx);

    expect(ok).toBe(true);
    expect(req.tfActor).toBe("tf:actor:user:example.com/alice");
    expect(req.tfDecision?.decision).toBe("allow");
    expect(req.tfProofId).toBe("sha256:allow");
    expect(tf.calls[0]?.host_token).toBe("eyJsig.tok.x");
    expect(tf.calls[0]?.host_token_kind).toBe("oauth-jwt");
    expect(tf.calls[0]?.action).toBe("get.api");
  });

  test("Guard throws HttpException(403) on deny verdict", async () => {
    const tf = mockClient(() => deny);
    const svc = new TrustForgeService({ tf });
    const guard = new TrustForgeGuardImpl(svc, {});

    const { ctx } = makeContext({ url: "/admin/users", method: "POST" });
    let thrown: TrustForgeHttpException | undefined;
    try {
      await guard.canActivate(ctx);
    } catch (e) {
      if (e instanceof TrustForgeHttpException) thrown = e;
      else throw e;
    }

    expect(thrown).toBeDefined();
    expect(thrown!.getStatus()).toBe(403);
    const resp = thrown!.getResponse();
    expect(resp.decision).toBe("deny");
    expect(resp.danger_tags).toEqual(["nope"]);
  });

  test("Guard throws HttpException(202) on approval-required", async () => {
    const tf = mockClient(() => approval);
    const svc = new TrustForgeService({ tf });
    const guard = new TrustForgeGuardImpl(svc, {});

    const { ctx } = makeContext({ url: "/api/data/9", method: "DELETE" });
    let thrown: TrustForgeHttpException | undefined;
    try {
      await guard.canActivate(ctx);
    } catch (e) {
      if (e instanceof TrustForgeHttpException) thrown = e;
      else throw e;
    }

    expect(thrown).toBeDefined();
    expect(thrown!.getStatus()).toBe(202);
    expect(thrown!.getResponse().approval_id).toBe("approval-77");
  });

  test("@TrustForgeRequire decorator pins the action read by the guard", async () => {
    // Reflect-metadata polyfill — required for the decorator.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const g = globalThis as any;
    if (!g.Reflect?.defineMetadata) {
      const meta = new WeakMap<object, Map<string, unknown>>();
      g.Reflect = {
        defineMetadata(key: string, value: unknown, target: object) {
          let m = meta.get(target);
          if (!m) {
            m = new Map();
            meta.set(target, m);
          }
          m.set(key, value);
        },
        getMetadata(key: string, target: object) {
          return meta.get(target)?.get(key);
        },
      };
    }

    const tf = mockClient(() => allow);
    const svc = new TrustForgeService({ tf });
    const guard = new TrustForgeGuardImpl(svc, {});

    const handler = function createUserHandler() {};
    TrustForgeRequire("user.create")({}, "create", { value: handler });

    const { ctx } = makeContext({
      method: "POST",
      url: "/api/users",
      handler,
    });

    expect(getRequiredAction(ctx)).toBe("user.create");
    await guard.canActivate(ctx);
    expect(tf.calls[0]?.action).toBe("user.create");
  });

  test("observe-only mode returns true even when verdict is deny, but still records decision", async () => {
    const tf = mockClient(() => deny);
    const svc = new TrustForgeService({ tf });
    const guard = new TrustForgeGuardImpl(svc, { mode: "observe-only" });

    const { ctx, req } = makeContext({
      url: "/admin",
      cookies: { session: "sess_clerkish" },
    });
    const ok = await guard.canActivate(ctx);

    expect(ok).toBe(true);
    expect(req.tfDecision?.decision).toBe("deny");
    expect(tf.calls[0]?.host_token).toBe("sess_clerkish");
    expect(tf.calls[0]?.host_token_kind).toBe("clerk-session");
  });

  test("TrustForgeModule.forRoot returns a NestJS DynamicModule descriptor", () => {
    const mod = TrustForgeModule.forRoot({ daemonUrl: "http://x" });
    expect(mod.module).toBe(TrustForgeModule);
    expect(mod.global).toBe(true);
    expect(Array.isArray(mod.providers)).toBe(true);
    expect(mod.providers.length).toBe(3);
    expect(mod.exports.length).toBe(2);
  });
});

import { afterEach, describe, expect, test } from "bun:test";
import { startMockDaemon, type MockDaemonHandle } from "@trustforge/test-utils";
import {
  trustforge,
  tfRequire,
  type KoaContextLike,
  type KoaMiddleware,
} from "../src/index.ts";

let daemon: MockDaemonHandle;

afterEach(async () => {
  await daemon.stop();
});

/** Build a minimal Koa-like ctx for unit-testing the middleware in isolation. */
function makeCtx(init: {
  method?: string;
  url?: string;
  headers?: Record<string, string>;
}): KoaContextLike {
  const headers = init.headers ?? {};
  const ctx: KoaContextLike = {
    request: { headers },
    method: init.method ?? "GET",
    url: init.url ?? "/",
    originalUrl: init.url ?? "/",
    ip: "127.0.0.1",
    state: {},
    status: 404,
    body: undefined,
    set(field: string, value: string) {
      headers[`set-${field.toLowerCase()}`] = value;
    },
    get(field: string) {
      return headers[field.toLowerCase()] ?? "";
    },
  };
  return ctx;
}

async function runChain(
  middleware: KoaMiddleware,
  ctx: KoaContextLike,
  inner?: () => Promise<void>,
): Promise<void> {
  await middleware(ctx, async () => {
    if (inner) await inner();
  });
}

describe("@trustforge/koa", () => {
  test("allow path attaches ctx.state.tfDecision and continues", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const mw = trustforge({
      daemonUrl: daemon.url,
      adminToken: "admin",
      profile: "home",
    });
    const ctx = makeCtx({
      url: "/x",
      headers: { authorization: "Bearer host-token-koa" },
    });
    let inner = false;
    await runChain(mw, ctx, async () => {
      inner = true;
      ctx.status = 200;
      ctx.body = { ok: true };
    });
    expect(inner).toBe(true);
    expect(ctx.status).toBe(200);
    expect(ctx.state.tfActor).toMatch(/^tf:actor:/);
    expect(ctx.state.tfDecision?.decision).toBe("allow");
    expect(ctx.state.tfProofId).toMatch(/^sha256:/);
    expect(daemon.calls()[0]!.host_token).toBe("host-token-koa");
  });

  test("deny path returns 403 with reason + danger_tags", async () => {
    daemon = startMockDaemon({
      adminToken: "admin",
      decide: () => ({
        decision: "deny",
        reason: "blocked",
        approval_id: null,
        proof_id: "sha256:deny-koa",
        actor_resolved: "tf:actor:agent:example.com/x",
        trust_level: "T1",
        authority_mode: "layered",
        danger_tags: ["fs"],
      }),
    });
    const mw = trustforge({ daemonUrl: daemon.url, adminToken: "admin" });
    const ctx = makeCtx({ url: "/y" });
    let inner = false;
    await runChain(mw, ctx, async () => {
      inner = true;
    });
    expect(inner).toBe(false);
    expect(ctx.status).toBe(403);
    expect((ctx.body as { decision: string }).decision).toBe("deny");
    expect((ctx.body as { danger_tags: string[] }).danger_tags).toEqual(["fs"]);
  });

  test("approval-required produces 202 and Location-style header", async () => {
    daemon = startMockDaemon({
      adminToken: "admin",
      decide: () => ({
        decision: "approval-required",
        reason: "human approval",
        approval_id: "appr-koa-1",
        proof_id: "sha256:appr-koa",
        actor_resolved: "tf:actor:agent:example.com/x",
        trust_level: "T2",
        authority_mode: "layered",
        danger_tags: [],
      }),
    });
    const mw = trustforge({ daemonUrl: daemon.url, adminToken: "admin" });
    const ctx = makeCtx({ url: "/z" });
    await runChain(mw, ctx);
    expect(ctx.status).toBe(202);
    expect((ctx.body as { approval_id: string }).approval_id).toBe(
      "appr-koa-1",
    );
  });

  test("observe-only forwards on deny", async () => {
    daemon = startMockDaemon({
      adminToken: "admin",
      decide: () => ({
        decision: "deny",
        reason: "would-be-blocked",
        approval_id: null,
        proof_id: "sha256:obs-koa",
        actor_resolved: "tf:actor:agent:example.com/x",
        trust_level: "T1",
        authority_mode: "layered",
        danger_tags: [],
      }),
    });
    const mw = trustforge({
      daemonUrl: daemon.url,
      adminToken: "admin",
      mode: "observe-only",
    });
    const ctx = makeCtx({ url: "/o" });
    let inner = false;
    await runChain(mw, ctx, async () => {
      inner = true;
      ctx.status = 200;
    });
    expect(inner).toBe(true);
    expect(ctx.status).toBe(200);
    expect(ctx.state.tfProofId).toBe("sha256:obs-koa");
  });

  test("tfRequire pins a custom action", async () => {
    daemon = startMockDaemon({ adminToken: "admin" });
    const mw = tfRequire("billing.charge", {
      daemonUrl: daemon.url,
      adminToken: "admin",
    });
    const ctx = makeCtx({ method: "POST", url: "/billing/charge" });
    await runChain(mw, ctx, async () => {
      ctx.status = 200;
    });
    expect(ctx.status).toBe(200);
    expect(daemon.calls()[0]!.action).toBe("billing.charge");
  });

  test("daemon failure in enforce mode returns 502", async () => {
    daemon = startMockDaemon({ adminToken: "real-token" });
    const mw = trustforge({ daemonUrl: daemon.url, adminToken: "wrong" });
    const ctx = makeCtx({ url: "/x" });
    await runChain(mw, ctx);
    expect(ctx.status).toBe(502);
  });
});
